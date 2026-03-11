#!/usr/bin/env python3
# encoding:utf-8


import json
from _socket import if_nametoindex
from configparser import ConfigParser
from ipaddress import IPv4Address
from pathlib import Path
from threading import get_ident
from time import sleep
from typing import List, Tuple, TYPE_CHECKING

from wirescale.communications.common import check_with_timeout, CONFIG_DIR, CONNECTION_PAIRS
from wirescale.communications.messages import ErrorCodes, ErrorMessages
from wirescale.vpn.commands import ip_addr_show_json, wg_quick_down, wg_quick_up_test, wg_show
from wirescale.vpn.wgconfig import WGConfig

if TYPE_CHECKING:
    from wirescale.vpn.recover import RecoverConfig


def interface_exists(name: str) -> bool:
    try:
        if_nametoindex(name)
        return True
    except OSError:
        return False


def next_interface_with_suffix(name: str) -> Tuple[str, int]:
    if not interface_exists(name):
        return name, 0
    counter = 1
    while interface_exists(name_with_suffix := f'{name}{counter}'):
        counter += 1
    return name_with_suffix, counter


def check_interface(interface: str, allow_suffix: bool) -> Tuple[str, int]:
    if not allow_suffix and interface_exists(interface):
        ErrorMessages.send_paired_error(ErrorMessages.INTERFACE_EXISTS, error_code=ErrorCodes.INTERFACE_EXISTS, always_send_to_remote=False, interface=interface)
    return next_interface_with_suffix(interface)


def check_configfile() -> Path:
    pair = CONNECTION_PAIRS[get_ident()]
    peer = CONFIG_DIR.joinpath(f'{pair.peer_name}.conf')
    if peer.is_file():
        return peer.resolve()
    ErrorMessages.send_paired_error(ErrorMessages.CONFIG_PATH_ERROR, error_code=ErrorCodes.CONFIG_PATH_ERROR, remote_code=ErrorCodes.CONFIG_PATH_ERROR)


def get_local_ip_addresses() -> List[IPv4Address]:
    result = ip_addr_show_json()
    if result.returncode != 0:
        raise RuntimeError(f"Error running 'ip addr show': {result.stderr}")

    addresses = []
    try:
        data = json.loads(result.stdout)
        for interface in data:
            for addr_info in interface.get('addr_info', []):
                addresses.append(IPv4Address(addr_info['local']))
    except json.JSONDecodeError:
        pass  # Handle or log error if needed
    return addresses


def check_behind_nat(ip: IPv4Address) -> bool:
    local_addresses = get_local_ip_addresses()
    return ip not in local_addresses


def check_recover_config(recover: 'RecoverConfig'):
    pair = CONNECTION_PAIRS[get_ident()]
    if pair.running_in_remote and abs(recover.latest_handshake - get_latest_handshake(recover.interface)) > 10:
        ErrorMessages.send_paired_error(ErrorMessages.LATEST_HANDSHAKE_MISMATCH, error_code=ErrorCodes.HANDSHAKE_MISMATCH,
                                        remote_code=ErrorCodes.HANDSHAKE_MISMATCH, interface=recover.interface)
    if not match_interface_port(recover.interface, recover.current_port):
        ErrorMessages.send_paired_error(ErrorMessages.PORT_MISMATCH, interface=recover.interface, port=recover.current_port)
    if not recover.runfile.exists() or not recover.runfile.is_file():
        ErrorMessages.send_paired_error(ErrorMessages.RUNFILE_MISSING, interface=recover.interface)


def _send_config_error(local_message: str):
    pair = CONNECTION_PAIRS[get_ident()]
    remote_error = ErrorMessages.REMOTE_CONFIG_ERROR.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
    ErrorMessages.send_error_message(local_message=local_message, remote_message=remote_error, always_send_to_remote=False)


def check_wgconfig(config: Path) -> WGConfig:
    try:
        wgconfig = WGConfig(config)
    except Exception as error:
        _send_config_error(str(error))
    if wgconfig.addresses is None:
        error_pair = ErrorMessages.MISSING_ADDRESS
    elif wgconfig.allowed_ips is None:
        error_pair = ErrorMessages.MISSING_ALLOWEDIPS
    elif not wgconfig.public_key:
        error_pair = ErrorMessages.BAD_FORMAT_PRIVKEY
    elif wgconfig.has_psk and not wgconfig.generate_wg_pubkey(wgconfig.psk):
        error_pair = ErrorMessages.BAD_FORMAT_PSK
    elif wgconfig.remote_pubkey and not wgconfig.generate_wg_pubkey(wgconfig.remote_pubkey):
        error_pair = ErrorMessages.BAD_FORMAT_PUBKEY
    else:
        return wgconfig
    ErrorMessages.send_paired_error(error_pair, always_send_to_remote=False, config_file=wgconfig.file_path)


def test_wgconfig(wgconfig: WGConfig):
    test_config = ConfigParser(interpolation=None)
    test_config.optionxform = lambda option: option
    interface, peer = 'Interface', 'Peer'
    test_config.add_section(interface)
    test_config.add_section(peer)
    repeatable_fields = ((interface, 'address'), (interface, 'dns'), (peer, 'allowedips'))
    for pair in repeatable_fields:
        for i, value in enumerate(wgconfig.get_field(pair[0], pair[1]), start=1):
            test_config.set(pair[0], f'{pair[1]}{i}_', value)
    test_config.set(interface, 'PrivateKey', wgconfig.private_key)
    test_config.set(interface, 'Table', wgconfig.table) if wgconfig.table else None
    test_config.set(interface, 'MTU', wgconfig.mtu) if wgconfig.mtu else None
    test_config.set(interface, 'FwMark', wgconfig.fwmark) if wgconfig.fwmark else None
    remote_pubkey = wgconfig.remote_pubkey if wgconfig.remote_pubkey else WGConfig.generate_wg_keypair()[1]
    test_config.set(peer, 'PublicKey', remote_pubkey)
    test_config.set(peer, 'PresharedKey', wgconfig.psk) if wgconfig.has_psk else None
    test_config = WGConfig.write_config(test_config, wgconfig.suffix)
    wgconfig.new_config_path.write_text(test_config, encoding='utf-8')
    wgquick = wg_quick_up_test(wgconfig.new_config_path)
    try:
        if wgquick.returncode != 0:
            _send_config_error(wgquick.stderr)
        else:
            wg_quick_down(wgconfig.new_config_path)
    finally:
        wgconfig.new_config_path.unlink(missing_ok=False)


def match_pubkeys(wgconfig: WGConfig, remote_pubkey: str, my_pubkey: str | None):
    pair = CONNECTION_PAIRS[get_ident()]
    error = None
    if wgconfig.remote_pubkey is not None and wgconfig.remote_pubkey != remote_pubkey:
        error = ErrorMessages.PUBKEY_MISMATCH.format(receiver_name=pair.my_name, receiver_ip=pair.my_ip, sender_ip=pair.peer_ip, sender_name=pair.peer_name)
    else:
        wgconfig.remote_pubkey = remote_pubkey
    if my_pubkey is not None and wgconfig.public_key != my_pubkey:
        error = ErrorMessages.PUBKEY_MISMATCH.format(receiver_name=pair.peer_name, receiver_ip=pair.peer_ip, sender_ip=pair.my_ip, sender_name=pair.my_name)
    if error is None:
        return
    ErrorMessages.send_error_message(local_message=error, remote_message=error)


def match_psk(wgconfig: WGConfig, remote_has_psk: bool, remote_psk: str):
    pair = CONNECTION_PAIRS[get_ident()]
    if wgconfig.has_psk != remote_has_psk:
        error = ErrorMessages.PSK_MISMATCH
        if wgconfig.has_psk:
            error = error.format(name_with_psk=pair.my_name, ip_with_psk=pair.my_ip, name_without_psk=pair.peer_name, ip_without_psk=pair.peer_ip)
        elif remote_has_psk:
            error = error.format(name_with_psk=pair.peer_name, ip_with_psk=pair.peer_ip, name_without_psk=pair.my_name, ip_without_psk=pair.my_ip)
        ErrorMessages.send_error_message(local_message=error, remote_message=error)
    if not wgconfig.has_psk:
        wgconfig.psk = remote_psk


def check_addresses_in_allowedips(wgconfig: WGConfig):
    check = all(wgconfig.ip_is_allowed(ip) for ip in wgconfig.remote_addresses)
    if check:
        return
    pair = CONNECTION_PAIRS[get_ident()]
    error = ErrorMessages.ALLOWED_IPS_MISMATCH.format(my_name=pair.my_name, my_ip=pair.my_ip, sender_name=pair.peer_name, sender_ip=pair.peer_ip)
    ErrorMessages.send_error_message(local_message=error, remote_message=error)


def match_interface_port(interface: str, port: int) -> bool:
    def match():
        try:
            real_port = int(wg_show(interface, 'listen-port'))
            return real_port == port
        except:
            ErrorMessages.send_paired_error(ErrorMessages.WG_INTERFACE_MISSING, interface=interface)

    return check_with_timeout(match, timeout=5)


def get_latest_handshake(interface: str) -> int:
    pair = CONNECTION_PAIRS.get(get_ident())
    try:
        handshake = wg_show(interface, 'latest-handshakes')
        return int(handshake.split('\n')[0].split('\t')[1])
    except:
        error = ErrorMessages.WG_INTERFACE_MISSING.local.format(interface=interface)
        remote_error = None
        if pair is not None:
            remote_error = ErrorMessages.WG_INTERFACE_MISSING.remote.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=interface)
        ErrorMessages.send_error_message(local_message=error, remote_message=remote_error)


def check_updated_handshake(interface: str, latest_handshake: int = 0, timeout: int = 20) -> bool:
    sleep_time = 0.5
    while not (updated := get_latest_handshake(interface) != latest_handshake) and timeout > 0:
        timeout -= sleep_time
        sleep(sleep_time)
    return updated
