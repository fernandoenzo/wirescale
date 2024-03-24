#!/usr/bin/env python3
# encoding:utf-8


import json
import os
import re
import subprocess
import sys
from functools import lru_cache
from ipaddress import IPv4Address
from typing import Dict, Tuple

from wirescale.communications.messages import ErrorMessages


class TSManager:
    @classmethod
    def start(cls) -> int:
        status = subprocess.run(['systemctl', 'start', 'tailscaled'], capture_output=True, text=True)
        return status.returncode

    @classmethod
    def stop(cls) -> int:
        status = subprocess.run(['systemctl', 'stop', 'tailscaled'], capture_output=True, text=True)
        return status.returncode

    @classmethod
    def status(cls) -> Dict:
        cls.check_running()
        status = subprocess.run(['tailscale', 'status', '--json'], capture_output=True, text=True)
        return json.loads(status.stdout)

    @classmethod
    def is_running(cls) -> bool:
        is_active = subprocess.run(['systemctl', 'is-active', 'tailscaled.service'], capture_output=True, text=True)
        if is_active.returncode != 0:
            return False
        status = subprocess.run(['tailscale', 'status', '--json'], capture_output=True, text=True)
        status = json.loads(status.stdout)
        return status.get('BackendState', '').lower() == 'running'

    @classmethod
    def check_running(cls):
        if not cls.is_running():
            print(ErrorMessages.TS_STOPPED, file=sys.stderr, flush=True)
            sys.exit(1)

    @classmethod
    @lru_cache(maxsize=None)
    def dns_suffix(cls) -> str:
        return cls.status()['MagicDNSSuffix'].lower()

    @classmethod
    def my_name(cls) -> str:
        return cls.status()['Self']['DNSName'].removesuffix(f'.{cls.dns_suffix()}')

    @classmethod
    @lru_cache(maxsize=None)
    def my_ip(cls) -> IPv4Address:
        cls.check_running()
        ip = subprocess.run(['tailscale', 'ip', '-4'], capture_output=True, text=True).stdout.strip()
        return IPv4Address(ip)

    @classmethod
    def peer(cls, ip: IPv4Address) -> Dict:
        cls.check_running()
        peer = subprocess.run(['tailscale', 'whois', '--json', str(ip)], capture_output=True, text=True)
        if peer.returncode != 0:
            print(ErrorMessages.TS_NO_PEER.format(ip=ip), file=sys.stderr, flush=True)
            sys.exit(1)
        data = json.loads(peer.stdout)
        return cls.status()['Peer'][data['Node']['Key']]

    @classmethod
    def peer_name(cls, ip: IPv4Address) -> str:
        return cls.peer(ip)['DNSName'].removesuffix(f'.{cls.dns_suffix()}')

    @classmethod
    def peer_ip(cls, name: str) -> IPv4Address:
        cls.check_running()
        ip = subprocess.run(['tailscale', 'ip', '-4', name], capture_output=True, text=True)
        if ip.returncode != 0:
            print(ErrorMessages.TS_NO_IP.format(peer_name=name), file=sys.stderr, flush=True)
            sys.exit(1)
        return IPv4Address(ip.stdout.strip())

    @classmethod
    def peer_is_online(cls, ip: IPv4Address) -> bool:
        if not cls.peer(ip)['Online']:
            return False
        check_ping = subprocess.run(['tailscale', 'ping', '-c', '1', str(ip)], capture_output=True, text=True)
        if check_ping.returncode != 0 and 'no reply' in check_ping.stderr.strip().lower():
            return False
        return True

    @classmethod
    def peer_endpoint(cls, ip: IPv4Address) -> Tuple[IPv4Address, int]:
        cls.check_running()
        if not cls.peer_is_online(ip):
            print(ErrorMessages.TS_PEER_OFFLINE.format(peer_name=cls.peer_name(ip), peer_ip=ip), file=sys.stderr, flush=True)
            sys.exit(1)
        force_endpoint = subprocess.run(['tailscale', 'ping', '-c', '30', str(ip)], capture_output=True, text=True)
        if force_endpoint.returncode != 0:
            print(ErrorMessages.TS_NO_ENDPOINT.format(peer_name=cls.peer_name(ip), peer_ip=ip), file=sys.stderr, flush=True)
            sys.exit(1)
        else:
            endpoint = force_endpoint.stdout.split()[-3]
        return IPv4Address(endpoint.split(':')[0]), int(endpoint.split(':')[1])

    @classmethod
    def local_port(cls) -> int:
        cls.check_running()
        try:
            os.setuid(0)
        except PermissionError:
            print(ErrorMessages.SUDO, file=sys.stderr, flush=True)
            sys.exit(1)
        while True:
            result = subprocess.run(['ss', '-lunp4'], capture_output=True, text=True)
            port: int = None
            try:
                generator = (int(match.group(1)) for match in (re.search(r':(\d+)', line) for line in result.stdout.split('\n') if 'tailscale' in line) if match)
                port = next(generator)
                next(generator)
            except StopIteration:
                if port:
                    return port
                print(ErrorMessages.TS_NO_PORT, file=sys.stderr, flush=True)
                sys.exit(1)
