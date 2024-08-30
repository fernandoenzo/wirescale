#!/usr/bin/env python3
# encoding:utf-8


import subprocess
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path

import netifaces
from parallel_utils.thread import create_thread

from wirescale.communications.messages import Messages
from wirescale.communications.systemd import Systemd
from wirescale.keepalive import ping


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
        ping.STOP.wait(wait_time)

    def check_interface_and_flag(self):
        while not ping.STOP.is_set():
            if self.interface not in netifaces.interfaces() or self.flag_file_stop.exists():
                ping.STOP.set()
            ping.STOP.wait(5)

    @staticmethod
    def stop_after(duration: int):
        ping.STOP.wait(duration)
        ping.STOP.set()

    def start(self, duration: int):
        create_thread(self.stop_after, duration)
        create_thread(self.check_interface_and_flag)
        create_thread(ping.listen_for_pings, src_ip=self.remote_ip, src_port=self.remote_port, dst_port=self.local_port)
        self.wait_until_next_occurrence()
        while not ping.STOP.is_set():
            try:
                ping.send_ping(dest_ip=str(self.remote_ip), dest_port=self.remote_port, src_port=self.local_port)
                ping.send_ping(dest_ip=str(self.remote_ip), dest_port=self.remote_port, src_port=None)
                ping.send_ping(dest_ip=str(self.remote_ip), dest_port=self.remote_port, src_port=None)
            except Exception as e:
                Messages.send_info_message(local_message=str(e), send_to_local=False)
            ping.STOP.wait(5)
