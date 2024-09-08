#!/usr/bin/env python3
# encoding:utf-8


import subprocess
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from ipaddress import IPv4Address
from multiprocessing import Process
from pathlib import Path

import netifaces
from parallel_utils.thread import create_thread

from wirescale.communications.systemd import Systemd
from wirescale.keepalive import ping


class KeepAliveConfig:

    def __init__(self, interface: str, remote_ip: IPv4Address, local_port: int, local_secondary_port: int, local_ext_port: int, remote_port: int,
                 remote_secondary_port: int, running_in_remote: bool, start_time: int):
        self.interface: str = interface
        self.remote_ip: IPv4Address = remote_ip
        self.local_port: int = local_port
        self.local_secondary_port: int = local_secondary_port
        self.local_ext_port: int = local_ext_port
        self.remote_port: int = remote_port
        self.remote_secondary_port: int = remote_secondary_port
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
        return cls(interface=interface, remote_ip=remote_ip, local_port=systemd.local_port, local_secondary_port=systemd.local_secondary_port, local_ext_port=systemd.local_ext_port,
                   remote_port=remote_port, remote_secondary_port=systemd.remote_secondary_port, running_in_remote=systemd.running_in_remote, start_time=systemd.start_time)

    def wait_until_next_occurrence(self):
        wait_time = (self.start_time - datetime.now().second) % 60
        ping.STOP.wait(wait_time)

    def check_interface_and_flag(self):
        while not ping.STOP.is_set():
            if self.interface not in netifaces.interfaces() or self.flag_file_stop.exists():
                ping.STOP.set()
            ping.STOP.wait(5)

    def stop_secondary(self, check_period: int = 20):
        def wg_listening_port(port: int) -> bool:
            output = subprocess.check_output(['wg', 'show', 'all', 'listen-port'], text=True)
            return str(port) in output.split()

        while not ping.STOP.is_set() and ping.HIT_PING and ping.HIT_PONG and not wg_listening_port(self.local_secondary_port):
            ping.HIT_PING, ping.HIT_PONG = False, False
            ping.STOP.wait(check_period)
        ping.STOP.set()

    def launch_secondary(self, duration):
        with open('/dev/null', 'w') as devnull:
            with redirect_stdout(devnull), redirect_stderr(devnull):
                create_thread(self.stop_after, duration)
                create_thread(ping.listen_for_pings, src_ip=self.remote_ip, src_port=self.remote_secondary_port, dst_port=self.local_secondary_port)
                create_thread(ping.send_periodic_ping, dest_ip=str(self.remote_ip), dest_port=self.remote_secondary_port, src_port=self.local_secondary_port)
                ping.STOP.wait(10)
                create_thread(self.stop_secondary)
                ping.STOP.wait()

    @staticmethod
    def stop_after(duration: int):
        ping.STOP.wait(duration)
        ping.STOP.set()

    def start(self, duration: int):
        create_thread(self.stop_after, duration)
        create_thread(self.check_interface_and_flag)
        create_thread(ping.listen_for_pings, src_ip=self.remote_ip, src_port=self.remote_port, dst_port=self.local_port)
        self.wait_until_next_occurrence()
        create_thread(ping.send_periodic_ping, dest_ip=str(self.remote_ip), dest_port=self.remote_port, src_port=self.local_port)
        Process(target=self.launch_secondary, args=[duration], daemon=True).start()
