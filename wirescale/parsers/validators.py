#!/usr/bin/env python3
# encoding:utf-8


import re
import subprocess
from argparse import ArgumentError, ArgumentTypeError
from ipaddress import IPv4Address
from pathlib import Path
from subprocess import DEVNULL, PIPE

from wirescale.communications.common import file_locker
from wirescale.vpn import TSManager


def check_peer(value) -> IPv4Address:
    value = value.strip()
    if not value:
        raise ArgumentTypeError('you provided an empty peer')
    print(f"Checking peer '{value}' is correct. This might take some minutes...")
    with file_locker():
        print(f"Start checking peer '{value}'")
        try:
            ip = IPv4Address(value)
        except Exception:
            ip = TSManager.peer_ip(value)
        if ip == TSManager.my_ip():
            raise ArgumentTypeError('you should not connect to your own machine')
        TSManager.peer(ip)  # Checks the IP belongs to somebody
        TSManager.peer_endpoint(ip)  # Checks an endpoint is available
    return ip


def check_existing_conf(value) -> Path:
    res = Path(f'/run/wirescale/{value}.conf')
    if not res.exists():
        raise ArgumentTypeError(f"file '{res}' does not exist")
    return res.resolve()


def check_existing_wg_interface(value):
    res = subprocess.run(['wg', 'show', value, 'listen-port'], stdout=DEVNULL, stderr=DEVNULL).returncode
    if res != 0:
        raise ArgumentTypeError(f"WireGuard interface '{value}' does not exist")
    return value


def interface_name_validator(value):
    regex = r'([a-zA-Z0-9_=+.-]{1,15})'
    if not re.fullmatch(regex, value):
        error = f"'{value}' is not a valid name for a WireGuard interface"
        raise ArgumentTypeError(error)
    return value


def match_interface_port(interface: str, supplied_port: int):
    from wirescale.parsers.parsers import recover_subparser, port_argument
    if not 0 < supplied_port < 65536:
        recover_subparser.error(str(ArgumentError(port_argument, f'supplied port {supplied_port} is out of range 1-65535')))
    try:
        real_port = int(subprocess.run(['wg', 'show', interface, 'listen-port'], stdout=PIPE, stderr=DEVNULL, text=True).stdout)
    except:
        real_port = -1
    if real_port != supplied_port:
        recover_subparser.error(str(ArgumentError(port_argument, f"WireGuard interface '{interface}' is not listening on supplied port {supplied_port}")))


def get_latest_handshake(interface: str) -> int:
    from wirescale.parsers.parsers import recover_subparser, interface_recover_argument
    handshake = subprocess.run(['wg', 'show', interface, 'latest-handshakes'], stdout=PIPE, stderr=DEVNULL, text=True)
    if handshake.returncode != 0:
        recover_subparser.error(str(ArgumentError(interface_recover_argument, f"WireGuard interface '{interface}' does not exist")))
    return int(handshake.stdout.strip().split('\n')[0].split('\t')[1])
