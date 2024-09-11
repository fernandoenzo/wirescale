#!/usr/bin/env python3
# encoding:utf-8


import functools
import re
import subprocess
from ipaddress import IPv4Address
from threading import get_ident
from time import sleep
from typing import Tuple, TYPE_CHECKING, Union

from wirescale.communications.common import CONNECTION_PAIRS

if TYPE_CHECKING:
    from wirescale.communications.connection_pair import ConnectionPair
    from wirescale.vpn.recover import RecoverConfig
    from wirescale.vpn.wgconfig import WGConfig


class Systemd:
    def __init__(self):
        self.interface: str = None
        self.suffix: int = None
        self.ts_ip: IPv4Address = None
        self.remote_pubkey: str = None
        self.wg_ip: IPv4Address = None
        self.running_in_remote: bool = None
        self.start_time: int = None
        self.local_port: int = None
        self.local_ext_port: int = None
        self.nat: bool = None
        self.remote_interface: str = None
        self.remote_local_port: int = None
        self.iptables_accept: bool = None
        self.recover_tries: int = None
        self.recreate_tries: int = None

    @classmethod
    def create_from_autoremove(cls, unit: str) -> 'Systemd':
        args = cls.parse_args(unit)
        res = cls()
        res.interface = args[1]
        res.suffix = int(args[2])
        res.ts_ip = IPv4Address(args[3])
        res.remote_pubkey = args[4]
        res.wg_ip = IPv4Address(args[5])
        res.running_in_remote = bool(int(args[6]))
        res.start_time = int(args[7])
        res.local_port = int(args[8])
        res.local_ext_port = int(args[9])
        res.nat = bool(int(args[10]))
        res.remote_interface = args[11]
        res.remote_local_port = int(args[12])
        res.iptables_accept = bool(int(args[13]))
        res.recover_tries = int(args[14])
        res.recreate_tries = int(args[15])
        return res

    @classmethod
    def check_active(cls, unit: str):
        from wirescale.communications.messages import ErrorMessages
        if not cls.is_active(unit):
            pair = CONNECTION_PAIRS.get(get_ident())
            error = ErrorMessages.MISSING_UNIT.format(unit=unit)
            error_remote = None
            if pair is not None:
                error_remote = ErrorMessages.REMOTE_MISSING_UNIT.format(my_name=pair.my_name, my_ip=pair.my_ip, unit=unit)
            ErrorMessages.send_error_message(local_message=error, remote_message=error_remote)

    @staticmethod
    @functools.cache
    def get_slice(unit: str) -> str:
        command = ['systemctl', 'show', '-p', 'ControlGroup', '--value', f'{unit}.service']
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout.strip()

    @staticmethod
    def is_active(unit: str) -> bool:
        is_active = subprocess.run(['systemctl', 'is-active', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        return is_active == 0

    @staticmethod
    def restart(unit: str) -> bool:
        restart = subprocess.run(['systemctl', 'restart', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        return restart == 0

    @staticmethod
    def start(unit: str) -> bool:
        start = subprocess.run(['systemctl', 'start', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        return start == 0

    @staticmethod
    def stop(unit: str) -> bool:
        stop = subprocess.run(['systemctl', 'stop', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        return stop == 0

    @classmethod
    def launch_autoremove(cls, config: Union['WGConfig', 'RecoverConfig'], pair: 'ConnectionPair'):
        from wirescale.communications.messages import Messages
        unit = f'autoremove-{config.interface}.service'
        tries, is_active = 20, True
        while is_active and tries > 0:
            is_active = cls.is_active(unit)
            tries -= 1
            sleep(1)
        subprocess.run(['systemctl', 'stop', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['systemctl', 'reset-failed', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        remote_pubkey: str = config.remote_pubkey_str if hasattr(config, 'remote_pubkey_str') else config.remote_pubkey
        wg_ip: IPv4Address = config.wg_ip if hasattr(config, 'wg_ip') else next(ip for ip in config.remote_addresses)
        running_in_remote: bool = config.running_in_remote if hasattr(config, 'running_in_remote') else pair.running_in_remote
        listen_port: int = config.new_port if hasattr(config, 'new_port') else config.listen_port
        args = [config.interface, str(config.suffix), str(pair.peer_ip), remote_pubkey, str(wg_ip), str(int(running_in_remote)), str(config.start_time), str(listen_port),
                str(config.listen_ext_port), str(int(config.nat)), config.remote_interface, str(config.remote_local_port), str(int(config.iptables_accept)), str(config.recover_tries),
                str(config.recreate_tries)]

        systemd = subprocess.run(['systemd-run', '-u', unit, '/bin/sh', '/run/wirescale/wirescale-autoremove', 'start', *args],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        Messages.send_info_message(local_message=f'Launching autoremove subprocess. {systemd.stdout.strip()}')

    @classmethod
    def parse_args(cls, unit: str) -> Tuple[str, ...]:
        exec_start = subprocess.run(['systemctl', 'show', '-p', 'ExecStart', unit], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
        if not exec_start:
            cls.check_active(unit)
        args = re.search(r'(\sstart.*?);', exec_start).group(1).strip().split()
        return tuple(args)
