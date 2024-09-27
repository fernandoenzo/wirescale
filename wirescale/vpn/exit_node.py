#!/usr/bin/env python3
# encoding:utf-8
import collections
import json
import subprocess
import sys
from ipaddress import ip_network, IPv4Network, IPv6Network
from pathlib import Path
from typing import Set

from wirescale.communications.common import EXIT_NODE_MARK, GLOB_MARK, WIRESCALE_TABLE
from wirescale.communications.messages import Messages
from wirescale.communications.systemd import Systemd


class ExitNode:
    GLOBAL_NETWORK = ip_network('0.0.0.0/0')
    DIRECTORY = Path('/run/wirescale/')
    EXIT_FILE = DIRECTORY.joinpath('control/exit-node')
    ADD_ALLOWEDIPS = 'add allowedips'
    EXIT_NODE = 'exit-node'
    NODES = 'nodes'
    SUPPRESS = 'suppress'
    RULES = {
        SUPPRESS: ['ip', '-4', 'rule', 'add', 'pref', '5500', 'table', 'main', 'suppress_prefixlength', '0'],
        NODES: ['ip', '-4', 'rule', 'add', 'pref', '5501', 'fwmark', str(GLOB_MARK), 'table', 'main'],
        EXIT_NODE: ['ip', '-4', 'rule', 'add', 'pref', '6000', 'not', 'fwmark', '{fwmark}', 'table', str(WIRESCALE_TABLE)],
    }
    SAVE_CONNMARK = ['iptables', '-t', 'mangle', '-I', 'POSTROUTING', '-m', 'mark', '--mark', '{mark}', '-p', 'udp', '-j', 'CONNMARK', '--save-mark', '-m', 'comment', '--comment',
                     'wirescale-{interface}']
    RESTORE_CONNMARK = ['iptables', '-t', 'mangle', '-I', 'PREROUTING', '-p', 'udp', '-j', 'CONNMARK', '--restore-mark', '-m', 'comment', '--comment', 'wirescale-{interface}']
    GOOD = '✅'
    BAD = '❌'

    @staticmethod
    def get_fwmark(interface: str) -> int | None:
        command = ['wg', 'show', interface, 'fwmark']
        mark = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout.strip()
        return int(mark, 16) if mark != 'off' else None

    @staticmethod
    def delete_ip_rule(priority: int):
        del_rule = ['ip', '-4', 'rule', 'del', 'priority', str(priority)]
        subprocess.run(del_rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def load_config(cls) -> dict | None:
        if not cls.EXIT_FILE.exists():
            return None
        with cls.EXIT_FILE.open('r') as f:
            return json.loads(f.read())

    @classmethod
    def save_config(cls, config: dict):
        with cls.EXIT_FILE.open('w') as f:
            f.write(json.dumps(config))

    @classmethod
    def set_exit_node(cls, interface: str):
        # Disable any previous exit-node
        config = cls.load_config()
        if config is not None:
            if interface == config[cls.EXIT_NODE]:
                Messages.send_info_message(local_message=f"Warning: Interface '{interface}' is already the exit node")
                sys.exit(0)
            else:
                cls.remove_exit_node()

        # Add 0.0.0.0/0 to AllowedIPs if necessary to the exit node
        modified = cls.modify_allowed_ips(interface)

        # Get or set, if None, a specific fwmark:
        fwmark = cls.get_fwmark(interface) or cls.set_fwmark(interface, EXIT_NODE_MARK) or EXIT_NODE_MARK

        # Create and save a base config structure
        config = {cls.EXIT_NODE: interface, cls.ADD_ALLOWEDIPS: modified, cls.NODES: {}}
        cls.save_config(config)

        # Add the nodes
        cls.add_missing_interfaces()

        # Set iptables connmark rules
        save_connmark = cls.SAVE_CONNMARK.copy()
        save_connmark[8], save_connmark[-1] = str(fwmark), save_connmark[-1].format(interface=interface)
        restore_connmark = cls.RESTORE_CONNMARK.copy()
        restore_connmark[-1] = restore_connmark[-1].format(interface=interface)
        subprocess.run(restore_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(save_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Add a new custom ip routing table
        add_route = ['ip', '-4', 'route', 'add', str(cls.GLOBAL_NETWORK), 'dev', interface, 'table', str(WIRESCALE_TABLE)]
        subprocess.run(add_route, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Add the ip rules
        cls.RULES[cls.EXIT_NODE][8] = str(fwmark)
        subprocess.run(cls.RULES[cls.SUPPRESS], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cls.RULES[cls.NODES], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(cls.RULES[cls.EXIT_NODE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        Messages.send_info_message(local_message=f"Interface '{interface}' has been enabled as an exit node {cls.GOOD}")

    @staticmethod
    def set_fwmark(interface: str, mark: int | None):
        mark = mark if mark is not None else 0
        command = ['wg', 'set', interface, 'fwmark', str(mark)]
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def clean_missing_interfaces(cls):
        config = cls.load_config()
        if config is None:
            return
        active_peers = set(peer.stem for peer in cls.DIRECTORY.glob('*.conf'))
        stored_nodes = set(config[cls.NODES].keys())
        remove = stored_nodes - active_peers
        rules = []
        for node in remove:
            priority = config[cls.NODES][node]
            rules.append(priority) if priority is not None else None
            config[cls.NODES].remove(node)
        for rule in rules:
            cls.delete_ip_rule(rule)
        cls.save_config(config)

    @classmethod
    def add_missing_interfaces(cls):
        config = cls.load_config()
        if config is None:
            return
        active_peers = set(peer.stem for peer in cls.DIRECTORY.glob('*.conf'))
        stored_nodes = set(config[cls.NODES].keys())
        add = active_peers - stored_nodes
        rules = set(config[cls.NODES].values())
        i = 5502
        for peer in add:
            mark = cls.get_fwmark(peer)
            if mark is None:
                cls.set_fwmark(peer, GLOB_MARK)
                config[cls.NODES][peer] = None
            else:
                while i in rules:
                    i += 1
                config[cls.NODES][peer] = i
                add_rule = cls.RULES[cls.NODES].copy()
                add_rule[5] = str(i)
                add_rule[7] = str(mark)
                subprocess.run(add_rule, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.save_config(config)

    @classmethod
    def reload(cls):
        config = cls.load_config()
        if config is None:
            sys.exit(0)
        cls.clean_missing_interfaces()
        cls.add_missing_interfaces()

    @classmethod
    def remove_exit_node(cls):
        config = cls.load_config()
        if config is None:
            Messages.send_info_message(local_message='Warning: There is currently no active exit node')
            sys.exit(0)
        interface = config[cls.EXIT_NODE]
        fwmark = cls.get_fwmark(interface)

        # Remove the fwmark if it was previously added
        cls.set_fwmark(interface, None) if fwmark == EXIT_NODE_MARK else None

        # Remove 0.0.0.0/0 to AllowedIPs if it was explicitly added
        if config[cls.ADD_ALLOWEDIPS]:
            cls.modify_allowed_ips(interface=interface, remove=True)

        # Remove iptables' CONNMARK rules
        save_connmark = cls.SAVE_CONNMARK.copy()
        save_connmark[8], save_connmark[-1] = str(fwmark), save_connmark[-1].format(interface=interface)
        restore_connmark = cls.RESTORE_CONNMARK.copy()
        restore_connmark[-1] = restore_connmark[-1].format(interface=interface)
        save_connmark[3], restore_connmark[3] = '-D', '-D'
        subprocess.run(save_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(restore_connmark, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Flush the custom ip routing table
        del_route = ['ip', 'route', 'flush', 'table', str(WIRESCALE_TABLE)]
        subprocess.run(del_route, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Remove the ip rules
        rules = [5500, 5501, 6000]
        for peer, priority in config[cls.NODES].items():
            cls.set_fwmark(peer, None) if priority is None else rules.append(priority)
        collections.deque((cls.delete_ip_rule(rule) for rule in rules), maxlen=0)

        # Remove the config file
        cls.EXIT_FILE.unlink()
        Messages.send_info_message(local_message=f"Interface '{interface}' has been deactivated as an exit node {cls.BAD}")

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
