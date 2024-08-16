#!/usr/bin/env python3
# encoding:utf-8


import logging
import random
import subprocess
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from time import sleep

logging.getLogger("scapy").setLevel(logging.CRITICAL)
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
        self.flag_file_fail = Path(f'/run/wirescale/control/{self.interface}-fail')
        self.flag_file_stop = Path(f'/run/wirescale/control/{self.interface}-stop')

    @classmethod
    def create_from_autoremove(cls, interface: str):
        unit = f'autoremove-{interface}'
        args = Systemd.parse_args(unit=unit)
        running_in_remote = bool(int(args[6]))
        remote_pubkey = args[4]
        local_port = int(subprocess.run(['wg', 'show', interface, 'listen-port'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout.strip())
        endpoints = subprocess.run(['wg', 'show', interface, 'endpoints'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout
        endpoint = endpoints.split(remote_pubkey)[1].split()[0]
        remote_ip = IPv4Address(endpoint.split(':')[0])
        remote_port = int(endpoint.split(':')[1])
        start_time = int(args[7])
        return cls(interface=interface, remote_ip=remote_ip, local_port=local_port, remote_port=remote_port, running_in_remote=running_in_remote, start_time=start_time)

    def wait_until_next_occurrence(self):
        current_second = datetime.now().second
        target_second = (self.start_time if not self.running_in_remote else self.start_time + 10) % 60
        wait_time = (target_second - current_second) % 60
        sleep(wait_time)

    def send_random_data(self):
        self.wait_until_next_occurrence()
        while not (self.flag_file_fail.exists() or self.flag_file_stop.exists()):
            count = random.randint(4, 10)
            random_data = random.randbytes(count * 1024)
            packet = IP(dst=str(self.remote_ip)) / UDP(sport=self.local_port, dport=self.remote_port) / Raw(load=random_data)
            send(packet, verbose=False)
            sleep(20)
        print('Finishing keepalive packet transmission')
