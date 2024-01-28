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
        status = subprocess.run(['tailscale', 'status', '--json'], capture_output=True, text=True)
        if status.returncode != 0:
            print(ErrorMessages.TAILSCALED_STOPPED, file=sys.stderr, flush=True)
            sys.exit(1)
        return json.loads(status.stdout)

    @classmethod
    def is_running(cls) -> bool:
        return cls.status()['BackendState'].lower() == 'running'

    @classmethod
    @lru_cache(maxsize=None)
    def dns_suffix(cls) -> str:
        return cls.status()['MagicDNSSuffix'].lower()

    @classmethod
    def my_name(cls) -> str:
        return cls.status()['Self']['DNSName'].removesuffix(f'.{cls.dns_suffix()}')

    @staticmethod
    @lru_cache(maxsize=None)
    def my_ip() -> IPv4Address:
        ip = subprocess.run(['tailscale', 'ip', '-4'], capture_output=True, text=True).stdout.strip()
        return IPv4Address(ip)

    @classmethod
    def peer(cls, ip: IPv4Address) -> Dict:
        peer = subprocess.run(['tailscale', 'whois', '--json', str(ip)], capture_output=True, text=True)
        if peer.returncode != 0:
            print(f"Error: No peer found matching the IP '{ip}'", file=sys.stderr, flush=True)
            sys.exit(1)
        data = json.loads(peer.stdout)
        return cls.status()['Peer'][data['Node']['Key']]

    @classmethod
    def peer_name(cls, ip: IPv4Address) -> str:
        return cls.peer(ip)['DNSName'].removesuffix(f'.{cls.dns_suffix()}')

    @classmethod
    def peer_ip(cls, name: str) -> IPv4Address:
        ip = subprocess.run(['tailscale', 'ip', '-4', name], capture_output=True, text=True)
        if ip.returncode != 0:
            print(f"Error: No IPv4 found for peer '{name}'", file=sys.stderr, flush=True)
            sys.exit(1)
        return IPv4Address(ip.stdout.strip())

    @classmethod
    def peer_is_online(cls, ip: IPv4Address) -> bool:
        return cls.peer(ip)['Online'] is True

    @classmethod
    def peer_endpoint(cls, ip: IPv4Address) -> Tuple[IPv4Address, int]:
        if not cls.is_running():
            print(ErrorMessages.TAILSCALED_STOPPED, file=sys.stderr, flush=True)
            sys.exit(1)
        if not cls.peer_is_online(ip):
            print(f'Error: Peer {cls.peer_name(ip)} ({ip}) is offline', file=sys.stderr, flush=True)
            sys.exit(1)
        subprocess.run(['tailscale', 'ping', '-c', '30', str(ip)], capture_output=True, text=True)
        if not (endpoint := cls.peer(ip)['CurAddr']):
            print(f'Sorry, it was impossible to find a public endpoint for peer {cls.peer_name(ip)} ({ip})', file=sys.stderr, flush=True)
            sys.exit(1)
        return IPv4Address(endpoint.split(':')[0]), int(endpoint.split(':')[1])

    @classmethod
    def local_port(cls) -> int:
        if os.geteuid() != 0:
            print('Error: This program must be run as a superuser', file=sys.stderr, flush=True)
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
                print('Error: No listening port for Tailscale was found', file=sys.stderr, flush=True)
                sys.exit(1)
