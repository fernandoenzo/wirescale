#!/usr/bin/env python3
# encoding:utf-8


import json
import os
import re
import subprocess
import sys
from contextlib import ExitStack
from functools import lru_cache
from ipaddress import IPv4Address
from threading import get_ident
from time import sleep
from typing import Dict, Tuple, TYPE_CHECKING

from wirescale.communications.common import check_with_timeout, CONNECTION_PAIRS
from wirescale.communications.messages import ErrorCodes, ErrorMessages, Messages
from wirescale.communications.systemd import Systemd

if TYPE_CHECKING:
    from wirescale.communications.connection_pair import ConnectionPair


class TSManager:
    @staticmethod
    def _run_ts(*args) -> subprocess.CompletedProcess:
        return subprocess.run(['tailscale', *args], capture_output=True, text=True)

    @classmethod
    def start(cls) -> bool:
        return Systemd.start('tailscaled.service')

    @classmethod
    def stop(cls) -> bool:
        return Systemd.stop('tailscaled.service')

    @classmethod
    def status(cls) -> Dict:
        cls.check_service_running()
        status = cls._run_ts('status', '--json')
        return json.loads(status.stdout)

    @staticmethod
    def service_is_running() -> bool:
        return Systemd.is_active('tailscaled.service')

    @classmethod
    def state(cls) -> str:
        return cls.status()['BackendState']

    @classmethod
    def check_state(cls, tag: str, state: str = None) -> bool:
        if state is None:
            return cls.state().lower() == tag.lower()
        return state.lower() == tag.lower()

    @classmethod
    def has_state(cls, state: str = None) -> bool:
        return not cls.check_state('NoState', state)

    @classmethod
    def is_logged(cls, state: str = None) -> bool:
        return not cls.check_state('NeedsLogin', state)

    @classmethod
    def is_starting(cls, state: str = None) -> bool:
        return cls.check_state('Starting', state)

    @classmethod
    def is_stopped(cls, state: str = None) -> bool:
        return cls.check_state('Stopped', state)

    @classmethod
    def is_running(cls, state: str = None) -> bool:
        return cls.check_state('Running', state)

    @classmethod
    def check_service_running(cls):
        if not check_with_timeout(cls.service_is_running, timeout=10):
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_SYSTEMD_STOPPED)

    @classmethod
    def check_running(cls):
        cls.check_service_running()
        if not check_with_timeout(cls.has_state, timeout=15):
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_COORD_OFFLINE)
        state = cls.state()
        if not cls.is_logged(state):
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_NO_LOGGED)
        if cls.is_stopped(state):
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_STOPPED)
        while cls.is_starting(state):
            sleep(0.5)
            state = cls.state()
        if not cls.is_running(state):
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_NOT_RUNNING)

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
        ip = cls._run_ts('ip', '-4').stdout.strip()
        return IPv4Address(ip)

    @classmethod
    def peer(cls, ip: IPv4Address) -> Dict:
        cls.check_running()
        peer = cls._run_ts('whois', '--json', str(ip))
        if peer.returncode != 0:
            no_peer = ErrorMessages.TS_NO_PEER.format(ip=ip)
            ErrorMessages.send_error_message(local_message=no_peer)
        data = json.loads(peer.stdout)
        return cls.status()['Peer'][data['Node']['Key']]

    @classmethod
    def peer_name(cls, ip: IPv4Address) -> str:
        return cls.peer(ip)['DNSName'].removesuffix(f'.{cls.dns_suffix()}')

    @classmethod
    def peer_ip(cls, name: str) -> IPv4Address:
        cls.check_running()
        ip = cls._run_ts('ip', '-4', name)
        if ip.returncode != 0:
            no_ip = ErrorMessages.TS_NO_IP.format(peer_name=name)
            ErrorMessages.send_error_message(local_message=no_ip)
        return IPv4Address(ip.stdout.strip())

    @classmethod
    def peer_is_online(cls, ip: IPv4Address, timeout: int = 2) -> bool:
        if not check_with_timeout(cls.has_state, timeout=15):
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_COORD_OFFLINE)
        check_ping = subprocess.run(['tailscale', 'ping', '-c', '1', '--until-direct=false', '--timeout', f'{timeout}s', str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_ping.returncode == 0:
            check_ping = subprocess.run(['ping', '-c', '1', '-W', str(timeout), str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return check_ping.returncode == 0

    @classmethod
    def wait_until_peer_is_online(cls, ip: IPv4Address, timeout: int = None) -> bool:
        single_ping_timeout = 2
        while not (ts_recovered := cls.peer_is_online(ip=ip, timeout=single_ping_timeout)):
            if timeout is not None:
                timeout -= single_ping_timeout
                if timeout <= 0:
                    break
        return ts_recovered

    @classmethod
    def wait_tailscale_restarted(cls, pair: 'ConnectionPair', stack: ExitStack):
        with stack:
            seconds_to_wait = 45
            print(f'Waiting for tailscale to be fully operational again. This could take up to {seconds_to_wait} seconds...', flush=True)
            res = cls.wait_until_peer_is_online(pair.peer_ip, timeout=seconds_to_wait)
            if not res:
                print(ErrorMessages.TS_NOT_RECOVERED.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip), file=sys.stderr, flush=True)
            else:
                print('Tailscale is fully working again!', flush=True)

    @classmethod
    def peer_endpoint(cls, ip: IPv4Address) -> Tuple[IPv4Address, int]:
        cls.check_running()
        pair = CONNECTION_PAIRS.get(get_ident())
        peer_name = pair.peer_name if pair is not None else cls.peer_name(ip)
        checking_endpoint = Messages.CHECKING_ENDPOINT.format(peer_name=peer_name, peer_ip=ip)
        Messages.send_info_message(local_message=checking_endpoint, send_to_local=False)
        if not cls.wait_until_peer_is_online(ip, timeout=25):
            peer_is_offline = ErrorMessages.TS_PEER_OFFLINE.format(peer_name=peer_name, peer_ip=ip)
            ErrorMessages.send_error_message(local_message=peer_is_offline, error_code=ErrorCodes.TS_UNREACHABLE, exit_code=4)
        force_endpoint = cls._run_ts('ping', '-c', '30', str(ip))
        if force_endpoint.returncode != 0:
            no_endpoint = ErrorMessages.TS_NO_ENDPOINT.format(peer_name=peer_name, peer_ip=ip)
            ErrorMessages.send_error_message(local_message=no_endpoint, error_code=ErrorCodes.TS_UNREACHABLE, exit_code=4)
        else:
            reachable = Messages.REACHABLE.format(peer_name=peer_name, peer_ip=ip)
            Messages.send_info_message(local_message=reachable, send_to_local=False)
            endpoint = force_endpoint.stdout.split()[-3]
        # Validate format in case 'tailscale ping' changes its output
        if ':' not in endpoint:
            no_endpoint = ErrorMessages.TS_NO_ENDPOINT.format(peer_name=peer_name, peer_ip=ip)
            ErrorMessages.send_error_message(local_message=no_endpoint, error_code=ErrorCodes.TS_UNREACHABLE, exit_code=4)
        return IPv4Address(endpoint.split(':')[0]), int(endpoint.split(':')[1])

    @classmethod
    def local_port(cls) -> int:
        cls.check_running()
        try:
            os.setuid(0)
        except PermissionError:
            print(ErrorMessages.SUDO, file=sys.stderr, flush=True)
            sys.exit(1)
        timeout = 20
        while timeout > 0:
            result = subprocess.run(['ss', '-lunp4'], capture_output=True, text=True)
            port: int = None
            try:
                generator = (int(match.group(1)) for match in (re.search(r':(\d+)', line) for line in result.stdout.split('\n') if 'tailscale' in line) if match)
                port = next(generator)
                next(generator)
            except StopIteration:
                if port:
                    return port
            timeout -= 0.1
            sleep(0.1)
        ErrorMessages.send_error_message(local_message=ErrorMessages.TS_NO_PORT)
