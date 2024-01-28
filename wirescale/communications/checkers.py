#!/usr/bin/env python3
# encoding:utf-8


import collections
import json
import subprocess
import sys
from _socket import if_nametoindex
from configparser import ConfigParser
from pathlib import Path

from websockets.sync.client import ClientConnection
from websockets.sync.server import ServerConnection

from wirescale.communications.messages import ErrorCodes, ErrorMessages
from wirescale.parsers.args import ConnectionPair
from wirescale.vpn.wgconfig import WGConfig


def interface_exists(name: str) -> bool:
    try:
        if_nametoindex(name)
        return True
    except OSError:
        return False


def next_interface_with_suffix(name: str) -> str:
    if not interface_exists(name):
        return name
    counter = 1
    while interface_exists(name_with_suffix := f'{name}{counter}'):
        counter += 1
    return name_with_suffix


def send_error(websocket: ClientConnection | ServerConnection, message: str, error_code: ErrorCodes, exit_code: int | None = 1):
    error = ErrorMessages.build_error_message(message, error_code)
    websocket.send(json.dumps(error))
    if exit_code is not None:
        sys.exit(exit_code)


def check_interface(pair: ConnectionPair, interface: str, suffix: bool) -> str:
    if not suffix and interface_exists(interface):
        error = ErrorMessages.INTERFACE_EXISTS.format(interface=interface)
        print(error, file=sys.stderr, flush=True)
        if not pair.running_in_remote:
            send_error(pair.local_socket, message=error, error_code=ErrorCodes.INTERFACE_EXISTS)
        else:
            remote_error = ErrorMessages.REMOTE_INTERFACE_EXISTS.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=interface)
            send_error(pair.remote_socket, message=remote_error, error_code=ErrorCodes.REMOTE_INTERFACE_EXISTS)
    return next_interface_with_suffix(interface)


def check_configfile(pair: ConnectionPair, config: str) -> Path:
    config = Path(config)
    if not config.exists():
        error = f"path '{config}' does not exist"
    elif not config.is_file():
        error = f"path '{config}' is not a regular file"
    else:
        return config.resolve()
    print(error, file=sys.stderr, flush=True)
    if not pair.running_in_remote:
        send_error(pair.local_socket, message=error, error_code=ErrorCodes.CONFIG_PATH_ERROR)
    else:
        error_message = ErrorMessages.REMOTE_CONFIG_PATH_ERROR.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        send_error(pair.remote_socket, message=error_message, error_code=ErrorCodes.REMOTE_CONFIG_PATH_ERROR)


def check_wgconfig(pair: ConnectionPair, config: Path) -> WGConfig:
    try:
        wgconfig = WGConfig(config)
    except Exception as e:
        print(e, file=sys.stderr, flush=True)
        if not pair.running_in_remote:
            send_error(pair.local_socket, message=str(e), error_code=ErrorCodes.CONFIG_ERROR)
        else:
            remote_error = ErrorMessages.REMOTE_CONFIG_ERROR.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
            send_error(pair.remote_socket, message=remote_error, error_code=ErrorCodes.REMOTE_CONFIG_ERROR)
    if wgconfig.addresses is None:
        error = ErrorMessages.MISSING_ADDRESS.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_MISSING_ADDRESS.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        error_code = ErrorCodes.MISSING_ADDRESS
        remote_error_code = ErrorCodes.REMOTE_MISSING_ADDRESS
    elif wgconfig.allowed_ips is None:
        error = ErrorMessages.MISSING_ALLOWEDIPS.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_MISSING_ALLOWEDIPS.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        error_code = ErrorCodes.MISSING_ALLOWEDIPS
        remote_error_code = ErrorCodes.REMOTE_MISSING_ALLOWEDIPS
    elif not wgconfig.public_key:
        error = ErrorMessages.BAD_FORMAT_PRIVKEY.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_BAD_FORMAT_PRIVKEY.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        error_code = ErrorCodes.BAD_FORMAT_PRIVKEY
        remote_error_code = ErrorCodes.REMOTE_BAD_FORMAT_PRIVKEY
    elif wgconfig.has_psk and not wgconfig.generate_wg_pubkey(wgconfig.psk):
        error = ErrorMessages.BAD_FORMAT_PSK.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_BAD_FORMAT_PSK.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        error_code = ErrorCodes.BAD_FORMAT_PSK
        remote_error_code = ErrorCodes.REMOTE_BAD_FORMAT_PSK
    elif wgconfig.remote_pubkey and not wgconfig.generate_wg_pubkey(wgconfig.remote_pubkey):
        error = ErrorMessages.BAD_FORMAT_PUBKEY.format(config_file=wgconfig.file_path)
        remote_error = ErrorMessages.REMOTE_BAD_FORMAT_PUBKEY.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        error_code = ErrorCodes.BAD_FORMAT_PUBKEY
        remote_error_code = ErrorCodes.REMOTE_BAD_FORMAT_PUBKEY
    else:
        error = test_wgconfig(wgconfig)
        if error is None:
            return wgconfig
        error_code = ErrorCodes.CONFIG_ERROR
        remote_error = ErrorMessages.REMOTE_CONFIG_ERROR.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_name=pair.peer_name)
        remote_error_code = ErrorCodes.REMOTE_CONFIG_ERROR
    print(error, file=sys.stderr, flush=True)
    if not pair.running_in_remote:
        send_error(pair.local_socket, error, error_code)
    else:
        send_error(pair.remote_socket, remote_error, remote_error_code)


def test_wgconfig(wgconfig: WGConfig) -> str | None:
    res = None
    test_config = ConfigParser()
    test_config.optionxform = lambda option: option
    test_path = Path('/run/wirescale/test.conf')
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
    test_config = WGConfig.write_config(test_config)
    test_path.write_text(test_config, encoding='utf-8')
    wgquick = subprocess.run(['wg-quick', 'up', str(test_path)], capture_output=True, text=True)
    if wgquick.returncode != 0:
        res = wgquick.stderr
    else:
        subprocess.run(['wg-quick', 'down', str(test_path)], capture_output=True, text=True)
    test_path.unlink(missing_ok=False)
    return res


def match_pubkeys(pair: ConnectionPair, wgconfig: WGConfig, remote_pubkey: str, my_pubkey: str | None):
    error = None
    if wgconfig.remote_pubkey is not None and wgconfig.remote_pubkey != remote_pubkey:
        error = ErrorMessages.PUBKEY_MISMATCH.format(receiver_name=pair.my_name, receiver_ip=pair.my_ip, sender_ip=pair.peer_ip, sender_name=pair.peer_name)
    else:
        wgconfig.remote_pubkey = remote_pubkey
    if my_pubkey is not None and wgconfig.public_key != my_pubkey:
        error = ErrorMessages.PUBKEY_MISMATCH.format(receiver_name=pair.peer_name, receiver_ip=pair.peer_ip, sender_ip=pair.my_ip, sender_name=pair.my_name)
    if error is None:
        return
    error_code = ErrorCodes.PUBKEY_MISMATCH
    print(error, file=sys.stderr, flush=True)
    collections.deque((send_error(ws, message=error, error_code=error_code, exit_code=None) for ws in pair.websockets), maxlen=0)
    sys.exit(1)


def match_psk(pair: ConnectionPair, wgconfig: WGConfig, remote_has_psk: bool, remote_psk: str):
    if wgconfig.has_psk != remote_has_psk:
        error_code = ErrorCodes.PSK_MISMATCH
        error = ErrorMessages.PSK_MISMATCH
        if wgconfig.has_psk:
            error = error.format(name_with_psk=pair.my_name, ip_with_psk=pair.my_ip, name_without_psk=pair.peer_name, ip_without_psk=pair.peer_ip)
        elif remote_has_psk:
            error = error.format(name_with_psk=pair.peer_name, ip_with_psk=pair.peer_ip, name_without_psk=pair.my_name, ip_without_psk=pair.my_ip)
        print(error, file=sys.stderr, flush=True)
        send_error(pair.remote_socket, error, error_code)
    if not wgconfig.has_psk:
        wgconfig.psk = remote_psk


def check_addresses_in_allowedips(pair: ConnectionPair, wgconfig: WGConfig):
    check = next((False for ip in wgconfig.remote_addresses if not wgconfig.ip_is_allowed(ip)), True)
    if check:
        return
    error = ErrorMessages.ALLOWED_IPS_MISMATCH.format(my_name=pair.my_name, my_ip=pair.my_ip, sender_name=pair.peer_name, sender_ip=pair.peer_ip)
    error_code = ErrorCodes.ALLOWED_IPS_MISMATCH
    print(error, file=sys.stderr, flush=True)
    collections.deque((send_error(ws, message=error, error_code=error_code, exit_code=None) for ws in pair.websockets), maxlen=0)
    sys.exit(1)
