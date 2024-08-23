#!/usr/bin/env python3
# encoding:utf-8


import json
import random
import subprocess
import warnings
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from time import sleep

from cryptography.utils import CryptographyDeprecationWarning
from parallel_utils.thread import create_thread

from wirescale.communications.messages import ErrorMessages, Messages

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
        wait_time = (self.start_time - datetime.now().second) % 60
        sleep(wait_time)

    def get_mtu(self) -> int:
        res = subprocess.run(['ip', '--json', 'link', 'show', self.interface], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8')
        if res.returncode != 0:
            error_message = ErrorMessages.INTERFACE_NOT_FOUND.format(interface=self.interface)
            ErrorMessages.send_error_message(local_message=error_message, send_to_local=False)
        res = json.loads(res.stdout)[0]
        return res['mtu']

    def set_mtu(self, mtu: int):
        command = ['ip', 'link', 'set', 'dev', self.interface, 'mtu', str(mtu)]
        p = subprocess.run(command)
        if p.returncode != 0:
            error_message = ErrorMessages.MTU_NOT_CHANGED.format(interface=self.interface, mtu=mtu)
            ErrorMessages.send_error_message(local_message=error_message, send_to_local=False)

    def send_random_data(self):
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
        total_iterations = 8
        sleep_time = None
        for i in range(1, total_iterations + 1):
            counter, total_size = 0, 0
            if self.flag_file_stop.exists():
                break
            if sleep_time is not None:
                sleep_message = Messages.SLEEP.format(minutes=(sleep_time // 60))
                Messages.send_info_message(local_message=sleep_message, send_to_local=False)
                sleep(sleep_time)
            seconds = 10 if i < total_iterations else (5 * 60)
            create_thread(flag_after_seconds, seconds)
            print(f'Start sending random packets ({i}/{total_iterations})', flush=True)
            while not wait:
                size = random.randint(4, 10)
                counter += 1
                total_size += size
                random_data = random.randbytes(size * 1024)
                packet = IP(dst=str(self.remote_ip)) / UDP(sport=self.local_port, dport=self.remote_port) / Raw(load=random_data)
                send(packet, verbose=False)
            print(f'Total of {counter} packages sent with a total size of {print_size(total_size)} ({i}/{total_iterations})', flush=True)
            wait = False
            sleep_time = (4 + i) * 60

        Messages.send_info_message(local_message=Messages.FINISH_KEEPALIVE, send_to_local=False)
