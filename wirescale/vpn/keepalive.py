#!/usr/bin/env python3
# encoding:utf-8


import random
import socket
import struct
import subprocess
from contextlib import suppress
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from time import sleep

from wirescale.communications.systemd import Systemd


class KeepAliveConfig:

    def __init__(self, interface: str, remote_ip: IPv4Address, local_port: int, remote_port: int, running_in_remote: bool, start_time: int):
        self.interface: str = interface
        self.remote_ip: IPv4Address = remote_ip
        self.local_port: int = local_port
        self.remote_port: int = remote_port
        self.running_in_remote: bool = running_in_remote
        self.start_time: int = start_time
        self.keepalive_port: int = None
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

    @staticmethod
    def checksum(msg):
        s = 0
        for i in range(0, len(msg) - 1, 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w

        if len(msg) % 2:
            s += msg[-1] << 8

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def modify_and_send_packet(self, data):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        ip_header = data[:20]
        udp_header = data[20:28]
        payload = data[28:]
        udp_header = struct.pack('!HHHH', self.local_port, self.remote_port, len(udp_header) + len(payload), 0)
        src_ip = socket.inet_ntoa(ip_header[12:16])
        pseudo_header = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(str(self.remote_ip)),
                                    0, socket.IPPROTO_UDP, len(udp_header) + len(payload))
        udp_checksum = self.checksum(pseudo_header + udp_header + payload)
        udp_header = udp_header[:6] + struct.pack('!H', udp_checksum)
        modified_packet = ip_header + udp_header + payload
        s.sendto(modified_packet, (str(self.remote_ip), 0))

    def run_relay(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))  # Asigna un puerto libre automáticamente
            self.keepalive_port = sock.getsockname()[1]

            while not (self.flag_file_fail.exists() or self.flag_file_stop.exists()):
                with suppress(BaseException):
                    data, addr = sock.recvfrom(65535)
                    self.modify_and_send_packet(data)

    def wait_until_next_occurrence(self):
        current_second = datetime.now().second
        target_second = (self.start_time if not self.running_in_remote else self.start_time + 10) % 60
        wait_time = (target_second - current_second) % 60
        sleep(wait_time)

    def send_random_data(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            self.wait_until_next_occurrence()
            while not (self.flag_file_fail.exists() or self.flag_file_stop.exists()):
                count = random.randint(2, 50)
                random_data = random.randbytes(count * 1024)
                with suppress(BaseException):
                    sock.sendto(random_data, ('127.0.0.1', self.keepalive_port))
                sleep(20)
