#!/usr/bin/env python3
# encoding:utf-8


import subprocess
import sys
from _socket import if_nametoindex
from configparser import ConfigParser
from ipaddress import IPv4Address, IPv4Interface
from pathlib import Path
from threading import get_ident
from time import sleep
from typing import Tuple, TYPE_CHECKING

from netifaces import AF_INET, ifaddresses, interfaces

from wirescale.communications.common import check_with_timeout, CONNECTION_PAIRS
from wirescale.communications.messages import ErrorCodes, ErrorMessages
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
    pair = CONNECTION_PAIRS[get_ident()]
    if not allow_suffix and interface_exists(interface):
        error = ErrorMessages.INTERFACE_EXISTS.format(interface=interface)
        remote_error = ErrorMessages.REMOTE_INTERFACE_EXISTS.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=interface)
        ErrorMessages.send_error_message(local_message=error, remote_message=remote_error, error_code=ErrorCodes.INTERFACE_EXISTS, always_send_to_remote=False)
    return next_interface_with_suffix(interface)


def check_configfile() -> Path:
    pair = CONNECTION_PAIRS[get_ident()]
    peer = Path(f'/etc/wirescale/{pair.peer_name}.conf')
    if peer.is_file():
        return peer.resolve()
    error = ErrorMessages.CONFIG_PATH_ERROR.format(peer_name=pair.peer_name)
    remote_error = ErrorMessages.REMOTE_CONFIG_PATH_ERROR.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
    ErrorMessages.send_error_message(local_message=error, remote_message=remote_error, error_code=ErrorCodes.CONFIG_PATH_ERROR, remote_code=ErrorCodes.CONFIG_PATH_ERROR)


def check_behind_nat(ip: IPv4Address) -> bool:
    local_addresses = (IPv4Interface(y[0]['addr'] + '/' + y[0]['netmask']) for x in interfaces() if (y := ifaddresses(x).get(AF_INET)) is not None)
    return ip not in (x.ip for x in local_addresses)


def check_recover_config(recover: 'RecoverConfig'):
    pair = CONNECTION_PAIRS[get_ident()]
    if pair.running_in_remote and abs(recover.latest_handshake - get_latest_handshake(recover.interface)) > 10:
        error = ErrorMessages.LATEST_HANDSHAKE_MISMATCH.format(interface=recover.interface)
        error_remote = ErrorMessages.REMOTE_LATEST_HANDSHAKE_MISMATCH.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=recover.interface)
        ErrorMessages.send_error_message(local_message=error, remote_message=error_remote, error_code=ErrorCodes.HANDSHAKE_MISMATCH,
                                         remote_code=ErrorCodes.HANDSHAKE_MISMATCH, exit_code=None)
        if recover.restart_on_fail:
            error = ErrorMessages.RESTART_UNIT.format(interface=recover.interface)
            ErrorMessages.send_error_message(local_message=error, exit_code=None)
            subprocess.run(['systemctl', 'restart', f'autoremove-{recover.interface}.service'], text=True)
        sys.exit(1)
    if not match_interface_port(recover.interface, recover.current_port):
        error = ErrorMessages.PORT_MISMATCH.format(interface=recover.interface, port=recover.current_port)
        error_remote = ErrorMessages.REMOTE_PORT_MISMATCH.format(peer_name=pair.my_name, peer_ip=pair.my_ip, interface=recover.interface, port=recover.current_port)
        ErrorMessages.send_error_message(local_message=error, remote_message=error_remote)
    if not recover.runfile.exists() or not recover.runfile.is_file():
        error = ErrorMessages.RUNFILE_MISSING.format(interface=recover.interface)
        error_remote = ErrorMessages.REMOTE_RUNFILE_MISSING.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=recover.interface)
        ErrorMessages.send_error_message(local_message=error, remote_message=error_remote)


def check_wgconfig(config: Path) -> WGConfig:
    pair = CONNECTION_PAIRS[get_ident()]
    try:
        wgconfig = WGConfig(config)
    except Exception as error:
        remote_error = ErrorMessages.REMOTE_CONFIG_ERROR.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        ErrorMessages.send_error_message(local_message=str(error), remote_message=remote_error, always_send_to_remote=False)
    if wgconfig.addresses is None:
        error = ErrorMessages.MISSING_ADDRESS.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_MISSING_ADDRESS.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
    elif wgconfig.allowed_ips is None:
        error = ErrorMessages.MISSING_ALLOWEDIPS.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_MISSING_ALLOWEDIPS.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
    elif not wgconfig.public_key:
        error = ErrorMessages.BAD_FORMAT_PRIVKEY.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_BAD_FORMAT_PRIVKEY.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
    elif wgconfig.has_psk and not wgconfig.generate_wg_pubkey(wgconfig.psk):
        error = ErrorMessages.BAD_FORMAT_PSK.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_BAD_FORMAT_PSK.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
    elif wgconfig.remote_pubkey and not wgconfig.generate_wg_pubkey(wgconfig.remote_pubkey):
        error = ErrorMessages.BAD_FORMAT_PUBKEY.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_BAD_FORMAT_PUBKEY.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
    else:
        return wgconfig
    ErrorMessages.send_error_message(local_message=error, remote_message=remote_error, always_send_to_remote=False)


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
    wgquick = subprocess.run(['wg-quick', 'up', str(wgconfig.new_config_path)], capture_output=True, text=True)
    try:
        if wgquick.returncode != 0:
            pair = CONNECTION_PAIRS[get_ident()]
            error = wgquick.stderr
            remote_error = ErrorMessages.REMOTE_CONFIG_ERROR.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
            ErrorMessages.send_error_message(local_message=error, remote_message=remote_error, always_send_to_remote=False)
        else:
            subprocess.run(['wg-quick', 'down', str(wgconfig.new_config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
    check = next((False for ip in wgconfig.remote_addresses if not wgconfig.ip_is_allowed(ip)), True)
    if check:
        return
    pair = CONNECTION_PAIRS[get_ident()]
    error = ErrorMessages.ALLOWED_IPS_MISMATCH.format(my_name=pair.my_name, my_ip=pair.my_ip, sender_name=pair.peer_name, sender_ip=pair.peer_ip)
    ErrorMessages.send_error_message(local_message=error, remote_message=error)


def match_interface_port(interface: str, port: int) -> bool:
    def match():
        pair = CONNECTION_PAIRS[get_ident()]
        try:
            real_port = int(subprocess.run(['wg', 'show', interface, 'listen-port'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip())
            return real_port == port
        except:
            error = ErrorMessages.WG_INTERFACE_MISSING.format(interface=interface)
            remote_error = ErrorMessages.REMOTE_WG_INTERFACE_MISSING.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=interface)
            ErrorMessages.send_error_message(local_message=error, remote_message=remote_error)

    return check_with_timeout(match, timeout=5)


def get_latest_handshake(interface: str) -> int:
    pair = CONNECTION_PAIRS.get(get_ident())
    try:
        handshake = subprocess.run(['wg', 'show', interface, 'latest-handshakes'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
        return int(handshake.split('\n')[0].split('\t')[1])
    except:
        error = ErrorMessages.WG_INTERFACE_MISSING.format(interface=interface)
        remote_error = None
        if pair is not None:
            remote_error = ErrorMessages.REMOTE_WG_INTERFACE_MISSING.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=interface)
        ErrorMessages.send_error_message(local_message=error, remote_message=remote_error)


def check_updated_handshake(interface: str, latest_handshake: int = 0, timeout: int = 10) -> bool:
    sleep_time = 0.5
    while not (updated := get_latest_handshake(interface) != latest_handshake) and timeout > 0:
        timeout -= sleep_time
        sleep(sleep_time)
    return updated
