#!/usr/bin/env python3
# encoding:utf-8


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
                str(int(config.nat)), config.remote_interface, str(config.remote_local_port), str(int(config.iptables)), str(config.recover_tries), str(config.recreate_tries)]

        systemd = subprocess.run(['systemd-run', '-u', unit, '/bin/sh', '/run/wirescale/wirescale-autoremove', 'autoremove', *args],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        Messages.send_info_message(local_message=f'Launching autoremove subprocess. {systemd.stdout.strip()}')

    @classmethod
    def parse_args(cls, unit: str) -> Tuple[str, ...]:
        exec_start = subprocess.run(['systemctl', 'show', '-p', 'ExecStart', unit], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
        if not exec_start:
            cls.check_active(unit)
        args = re.search(r'(\sautoremove.*?);', exec_start).group(1).strip().split()
        return tuple(args)
