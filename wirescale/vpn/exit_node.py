#!/usr/bin/env python3
# encoding:utf-8


import subprocess
import sys
from ipaddress import ip_network, IPv4Network, IPv6Network
from pathlib import Path
from typing import Set

from wirescale.communications.common import EXIT_NODE_MARK, WIRESCALE_TABLE
from wirescale.communications.messages import Messages
from wirescale.communications.systemd import Systemd
from wirescale.vpn.iptables import IPTABLES


class ExitNode:
    GLOBAL_NETWORK = ip_network('0.0.0.0/0')
    DIRECTORY = Path('/run/wirescale/control/')
    GOOD = '✅'
    BAD = '❌'

    @staticmethod
    def get_fwmark(interface: str) -> int | None:
        command = ['wg', 'show', interface, 'fwmark']
        mark = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout.strip()
        return int(mark, 16) if mark != 'off' else None

    @classmethod
    def get_exit_node(cls):
        try:
            file = next(cls.DIRECTORY.glob('exit-node-*'))
            with file.open() as f:
                has_allowed_ips = f.read().strip() == '1'
            return file.name.split('exit-node-')[-1], has_allowed_ips
        except StopIteration:
            return None, None

    @classmethod
    def set(cls, interface: str):
        node, _ = cls.get_exit_node()
        if interface == node:
            Messages.send_info_message(local_message=f"Warning: Interface '{interface}' is already the exit node")
            sys.exit(0)
        if node is not None:
            cls.remove_exit_node()
        fwmark = cls.get_fwmark(interface) or EXIT_NODE_MARK
        if fwmark == EXIT_NODE_MARK:
            cls.set_fwmark(interface, fwmark)
        save_connmark = IPTABLES.SAVE_CONNMARK.replace('"', '').format(mark=fwmark, interface='{interface}').split()
        save_connmark[-1] = save_connmark[-1].format(interface=interface)
        restore_connmark = IPTABLES.RESTORE_CONNMARK.replace('"', '').split()
        restore_connmark[-1] = restore_connmark[-1].format(interface=interface)
        modified = cls.modify_allowed_ips(interface)
        file = cls.DIRECTORY.joinpath(f'exit-node-{interface}')
        with file.open('w') as f:
            f.write('1\n') if modified else f.write('0\n')
        add_route = ['ip', '-4', 'route', 'add', str(cls.GLOBAL_NETWORK), 'dev', interface, 'table', str(WIRESCALE_TABLE)]
        add_rule_not_fwmark = ['ip', '-4', 'rule', 'add', 'not', 'fwmark', str(fwmark), 'table', str(WIRESCALE_TABLE)]
        add_rule_suppress = ['ip', '-4', 'rule', 'add', 'table', 'main', 'suppress_prefixlength', '0']
        subprocess.run(restore_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(save_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(add_route, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(add_rule_not_fwmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(add_rule_suppress, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Messages.send_info_message(local_message=f"Interface '{interface}' has been enabled as an exit node {cls.GOOD}")

    @staticmethod
    def set_fwmark(interface: str, mark: int | None):
        mark = mark if mark is not None else 0
        command = ['wg', 'set', interface, 'fwmark', str(mark)]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def remove_exit_node(cls):
        node, remove_allowed_ips = cls.get_exit_node()
        if node is None:
            Messages.send_info_message(local_message='Warning: There is currently no active exit node')
            sys.exit(0)
        if remove_allowed_ips:
            cls.modify_allowed_ips(interface=node, remove=True)
        fwmark = cls.get_fwmark(node)
        if fwmark == EXIT_NODE_MARK:
            cls.set_fwmark(node, None)
        save_connmark = IPTABLES.remove_rule(IPTABLES.SAVE_CONNMARK.replace('"', '').format(mark=fwmark, interface='{interface}')).split()
        save_connmark[-1] = save_connmark[-1].format(interface=node)
        restore_connmark = IPTABLES.remove_rule(IPTABLES.RESTORE_CONNMARK.replace('"', '')).split()
        restore_connmark[-1] = restore_connmark[-1].format(interface=node)
        del_route = ['ip', 'route', 'flush', 'table', str(WIRESCALE_TABLE)]
        del_rule_not_fwmark = ['ip', '-4', 'rule', 'del', 'not', 'fwmark', str(fwmark), 'table', str(WIRESCALE_TABLE)]
        del_rule_suppress = ['ip', '-4', 'rule', 'del', 'table', 'main', 'suppress_prefixlength', '0']
        subprocess.run(restore_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(save_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(del_route, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(del_rule_not_fwmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(del_rule_suppress, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.DIRECTORY.joinpath(f'exit-node-{node}').unlink()
        Messages.send_info_message(local_message=f"Interface '{node}' has been deactivated as an exit node {cls.BAD}")

    @staticmethod
    def get_allowed_ips(interface: str) -> Set[IPv4Network | IPv6Network]:
        node = Systemd.create_from_autoremove(f'autoremove-{interface}.service')
        command = ['wg', 'show', interface, 'allowed-ips']
        peers = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout.splitlines()
        peers = [x.split() for x in peers]
        return set(ip_network(network) for peer in peers if peer[0] == node.remote_pubkey for network in peer[1:])

    @classmethod
    def modify_allowed_ips(cls, interface: str, remove: bool = False) -> bool:
        node = Systemd.create_from_autoremove(f'autoremove-{interface}.service')
        all_networks = cls.get_allowed_ips(interface)
        if remove:
            try:
                all_networks.remove(cls.GLOBAL_NETWORK)
            except KeyError:
                return False
        else:
            if cls.GLOBAL_NETWORK in all_networks:
                return False
            all_networks.add(cls.GLOBAL_NETWORK)
        all_networks = ','.join(str(x) for x in all_networks)
        command = ['wg', 'set', interface, 'peer', node.remote_pubkey, 'allowed-ips', all_networks]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
