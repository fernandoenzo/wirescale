#!/usr/bin/env python3
# encoding:utf-8


import json
import os
import random
import re
import subprocess
import sys
import time
import warnings
from collections import namedtuple
from contextlib import ExitStack
from functools import lru_cache
from ipaddress import IPv4Address
from threading import get_ident
from time import sleep
from typing import Dict, Tuple, TYPE_CHECKING

import netifaces
from cryptography.utils import CryptographyDeprecationWarning
from parallel_utils.thread import create_thread

with warnings.catch_warnings(action='ignore', category=CryptographyDeprecationWarning):
    from scapy.all import IP, send, sniff, UDP
from wirescale.communications.common import check_with_timeout, CONNECTION_PAIRS
from wirescale.communications.messages import ErrorCodes, ErrorMessages, Messages
from wirescale.communications.systemd import Systemd

if TYPE_CHECKING:
    from wirescale.communications.connection_pair import ConnectionPair


class TSManager:
    QUEUE_NUM = random.randint(0, 65535)
    PacketInfo = namedtuple('PacketInfo', ['packet', 'timestamp'])
    PORTMAPPING_PACKETS = []

    @classmethod
    def start(cls) -> bool:
        t = create_thread(cls.capture_packets)
        res = Systemd.start('tailscaled.service')
        t.result()
        return res

    @classmethod
    def stop(cls) -> bool:
        return Systemd.stop('tailscaled.service')

    @classmethod
    def status(cls) -> Dict:
        cls.check_service_running()
        status = subprocess.run(['tailscale', 'status', '--json'], capture_output=True, text=True)
        return json.loads(status.stdout)

    @staticmethod
    def service_is_running() -> bool:
        return Systemd.is_active('tailscaled.service')

    @classmethod
    def has_state(cls) -> bool:
        return cls.status()['BackendState'].lower() != 'NoState'.lower()

    @classmethod
    def check_has_state(cls, timeout=15) -> bool:
        return check_with_timeout(cls.has_state, timeout=timeout)

    @classmethod
    def capture_packets(cls):
        packet_handler = lambda pkt: cls.PORTMAPPING_PACKETS.append(cls.PacketInfo(pkt, time.time()))
        sniff(filter="udp and (port 5350 or port 5351)", prn=packet_handler, timeout=10)

    @classmethod
    def retransmit_packets(cls, interface: str, listen_port: int):
        start_time = time.time()
        duration = 62 * 60
        while (time.time() - start_time < duration) and (interface in netifaces.interfaces()):
            real_port = subprocess.run(['wg', 'show', interface, 'listen-port'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
            if (not real_port) or (listen_port != int(real_port)):
                return
            if not cls.PORTMAPPING_PACKETS:
                return
            for i, packet_info in enumerate(cls.PORTMAPPING_PACKETS):
                if i < len(cls.PORTMAPPING_PACKETS) - 1:
                    next_packet_time = cls.PORTMAPPING_PACKETS[i + 1].timestamp
                    delay = next_packet_time - packet_info.timestamp
                else:
                    delay = 0
                original_pkt = packet_info.packet
                new_pkt = IP(src=original_pkt[IP].src, dst=original_pkt[IP].dst) / UDP(sport=original_pkt[UDP].sport, dport=original_pkt[UDP].dport) / original_pkt[UDP].payload
                send(new_pkt, verbose=False)
                if delay > 0:
                    time.sleep(delay)
            time.sleep(15)

    @classmethod
    def block_net(cls):  # To avoid UPnP unmap
        add_iptables = ['iptables', '-I', 'OUTPUT', '-m', 'cgroup', '--path', Systemd.get_slice('tailscaled'), '-j', 'DROP']
        subprocess.run(add_iptables, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def unblock_net(cls):
        remove_iptables = ['iptables', '-D', 'OUTPUT', '-m', 'cgroup', '--path', Systemd.get_slice('tailscaled'), '-j', 'DROP']
        subprocess.run(remove_iptables, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def is_logged(cls) -> bool:
        return cls.status()['BackendState'].lower() != 'NeedsLogin'.lower()

    @classmethod
    def is_starting(cls) -> bool:
        return cls.status()['BackendState'].lower() == 'Starting'.lower()

    @classmethod
    def is_stopped(cls) -> bool:
        return cls.status()['BackendState'].lower() == 'Stopped'.lower()

    @classmethod
    def is_running(cls) -> bool:
        return cls.status()['BackendState'].lower() == 'Running'.lower()

    @classmethod
    def check_service_running(cls):
        if not check_with_timeout(cls.service_is_running, timeout=10):
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_SYSTEMD_STOPPED)

    @classmethod
    def check_running(cls):
        cls.check_service_running()
        sleep_time = 0.5
        if not cls.check_has_state():
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_COORD_OFFLINE)
        if not cls.is_logged():
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_NO_LOGGED)
        if cls.is_stopped():
            ErrorMessages.send_error_message(local_message=ErrorMessages.TS_STOPPED)
        while cls.is_starting():
            sleep(sleep_time)
        if not cls.is_running():
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
        ip = subprocess.run(['tailscale', 'ip', '-4'], capture_output=True, text=True).stdout.strip()
        return IPv4Address(ip)

    @classmethod
    def peer(cls, ip: IPv4Address) -> Dict:
        cls.check_running()
        peer = subprocess.run(['tailscale', 'whois', '--json', str(ip)], capture_output=True, text=True)
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
        ip = subprocess.run(['tailscale', 'ip', '-4', name], capture_output=True, text=True)
        if ip.returncode != 0:
            no_ip = ErrorMessages.TS_NO_IP.format(peer_name=name)
            ErrorMessages.send_error_message(local_message=no_ip)
        return IPv4Address(ip.stdout.strip())

    @classmethod
    def peer_is_online(cls, ip: IPv4Address, timeout: int = 2) -> bool:
        if not cls.check_has_state():
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
        force_endpoint = subprocess.run(['tailscale', 'ping', '-c', '30', str(ip)], capture_output=True, text=True)
        if force_endpoint.returncode != 0:
            no_endpoint = ErrorMessages.TS_NO_ENDPOINT.format(peer_name=peer_name, peer_ip=ip)
            ErrorMessages.send_error_message(local_message=no_endpoint, error_code=ErrorCodes.TS_UNREACHABLE, exit_code=4)
        else:
            reachable = Messages.REACHABLE.format(peer_name=peer_name, peer_ip=ip)
            Messages.send_info_message(local_message=reachable, send_to_local=False)
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
                ErrorMessages.send_error_message(local_message=ErrorMessages.TS_NO_PORT)
