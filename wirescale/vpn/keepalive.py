#!/usr/bin/env python3
# encoding:utf-8


import random
import subprocess
import warnings
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from time import sleep

from cryptography.utils import CryptographyDeprecationWarning
from parallel_utils.thread import create_thread

from wirescale.communications.messages import Messages

with warnings.catch_warnings(action="ignore", category=CryptographyDeprecationWarning):
    from scapy.all import IP, Raw, send, UDP

from wirescale.communications.systemd import Systemd


class KeepAliveConfig:

    def __init__(self, interface: str, remote_ip: IPv4Address, local_port: int, remote_port: int, running_in_remote: bool, start_time: int):
        self.interface: str = interface
        self.remote_ip: IPv4Address = remote_ip
        self.local_port: int = local_port
        self.remote_port: int = remote_port
        self.running_in_remote: bool = running_in_remote
        self.start_time: int = start_time
        self.flag_file_stop = Path(f'/run/wirescale/control/{self.interface}-stop')

    @classmethod
    def create_from_autoremove(cls, interface: str):
        unit = f'autoremove-{interface}'
        systemd = Systemd.create_from_autoremove(unit=unit)
        endpoints = subprocess.run(['wg', 'show', interface, 'endpoints'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout
        endpoint = endpoints.split(systemd.remote_pubkey)[1].split()[0]
        remote_ip = IPv4Address(endpoint.split(':')[0])
        remote_port = int(endpoint.split(':')[1])
        return cls(interface=interface, remote_ip=remote_ip, local_port=systemd.local_port, remote_port=remote_port, running_in_remote=systemd.running_in_remote, start_time=systemd.start_time)

    def wait_until_next_occurrence(self):
        wait_time = (self.start_time - datetime.now().second) % 60
        sleep(wait_time)

    def send_random_data(self, duration: int):
        wait: bool = False

        def flag_after_seconds(seconds: int):
            nonlocal wait
            sleep(seconds)
            wait = True

        def print_size(kb: int):
            mb = kb / 1024
            if mb >= 1:
                return f'{mb:.2f} MiB'
            else:
                return f'{kb} KiB'

        self.wait_until_next_occurrence()
        Messages.send_info_message(local_message=Messages.START_KEEPALIVE, send_to_local=False)
        counter, total_size = 0, 0
        create_thread(flag_after_seconds, duration)
        while not wait:
            size = random.randint(4, 10)
            counter += 1
            total_size += size
            random_data = random.randbytes(size * 1024)
            packet = IP(dst=str(self.remote_ip)) / UDP(sport=self.local_port, dport=self.remote_port) / Raw(load=random_data)
            send(packet, verbose=False)
        print(f'Total of {counter} packages sent with a total size of {print_size(total_size)}', flush=True)
