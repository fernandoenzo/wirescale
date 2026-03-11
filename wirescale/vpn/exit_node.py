#!/usr/bin/env python3
# encoding: utf-8


import collections
import fcntl
import json
import sys
from contextlib import contextmanager
from ipaddress import ip_network, IPv4Network, IPv6Network
from typing import Dict, List, Optional, Set

from wirescale.communications.common import EXIT_NODE_MARK, GLOB_MARK, RUN_DIR, WIRESCALE_TABLE
from wirescale.communications.messages import Messages
from wirescale.communications.systemd import Systemd
from wirescale.vpn.commands import iptables_run, ip_run, wg_set, wg_show


class ExitNode:
    GLOBAL_NETWORK = ip_network('0.0.0.0/0')
    EXIT_FILE = RUN_DIR.joinpath('control/exit-node')
    LOCKER = RUN_DIR.joinpath('control/exit-node-locker')
    ADD_ALLOWEDIPS = 'add-allowedips'
    EXIT_NODE = 'exit-node'
    NODES = 'nodes'
    SUPPRESS = 'suppress'
    RULES: Dict[str, List[str]] = {
        SUPPRESS: ['ip', '-4', 'rule', 'add', 'pref', '5500', 'table', 'main', 'suppress_prefixlength', '0'],
        NODES: ['ip', '-4', 'rule', 'add', 'pref', '5501', 'fwmark', str(GLOB_MARK), 'table', 'main'],
        EXIT_NODE: ['ip', '-4', 'rule', 'add', 'pref', '6000', 'not', 'fwmark', '{fwmark}', 'table', str(WIRESCALE_TABLE)],
    }
    SAVE_CONNMARK = ['iptables', '-t', 'mangle', '-I', 'POSTROUTING', '-m', 'mark', '--mark', '{mark}', '-p', 'udp', '-j', 'CONNMARK', '--save-mark', '-m', 'comment', '--comment',
                     'wirescale-{interface}']
    RESTORE_CONNMARK = ['iptables', '-t', 'mangle', '-I', 'PREROUTING', '-p', 'udp', '-j', 'CONNMARK', '--restore-mark', '-m', 'comment', '--comment', 'wirescale-{interface}']
    GOOD = '✅'
    BAD = '❌'

    @classmethod
    def load_config(cls) -> Optional[Dict]:
        """Load the exit node configuration from file."""
        if not cls.EXIT_FILE.exists():
            return None
        with cls.EXIT_FILE.open('r') as f:
            return json.load(f)

    @classmethod
    def save_config(cls, config: Dict) -> None:
        """Save the exit node configuration to file."""
        with cls.EXIT_FILE.open('w') as f:
            json.dump(config, f)
        cls.EXIT_FILE.chmod(mode=0o644)

    @classmethod
    def status(cls) -> None:
        config = cls.load_config()
        if config is not None:
            Messages.send_info_message(local_message=config[cls.EXIT_NODE])

    @staticmethod
    def get_fwmark(interface: str) -> Optional[int]:
        """Get the firewall mark for the given interface."""
        mark = wg_show(interface, 'fwmark')
        return int(mark, 16) if mark != 'off' else None

    @staticmethod
    def set_fwmark(interface: str, mark: Optional[int]) -> None:
        """Set the firewall mark for the given interface."""
        mark = mark if mark is not None else 0
        wg_set(interface, 'fwmark', str(mark))

    @staticmethod
    def get_allowed_ips(interface: str) -> Set[IPv4Network | IPv6Network]:
        """Get the allowed IPs for the given interface."""
        node = Systemd.create_from_autoremove(f'autoremove-{interface}.service')
        peers = wg_show(interface, 'allowed-ips').splitlines()
        peers = [x.split() for x in peers]
        return {ip_network(network) for peer in peers if peer[0] == node.remote_pubkey for network in peer[1:]}

    @classmethod
    def modify_allowed_ips(cls, interface: str, remove: bool = False) -> bool:
        """Modify the allowed IPs for the given interface."""
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
        wg_set(interface, 'peer', node.remote_pubkey, 'allowed-ips', all_networks)
        return True

    @classmethod
    def _iptables_connmark(cls, interface: str, fwmark: int, action: str = '-I') -> None:
        """Add or remove iptables CONNMARK rules for the exit node."""
        save = [x.format(mark=fwmark, interface=interface) for x in cls.SAVE_CONNMARK]
        restore = [x.format(interface=interface) for x in cls.RESTORE_CONNMARK]
        if action != '-I':
            save[3], restore[3] = action, action
        first, second = (restore, save) if action == '-I' else (save, restore)
        iptables_run(first)
        iptables_run(second)

    @classmethod
    def add_custom_routing_table(cls, interface: str) -> None:
        """Add a custom routing table for the exit node."""
        ip_run('-4', 'route', 'add', str(cls.GLOBAL_NETWORK), 'dev', interface, 'table', str(WIRESCALE_TABLE))

    @classmethod
    def flush_custom_routing_table(cls) -> None:
        """Flush the custom routing table."""
        ip_run('route', 'flush', 'table', str(WIRESCALE_TABLE))

    @classmethod
    def add_ip_rules(cls, fwmark: int) -> None:
        """Add IP rules for the exit node."""
        cls.RULES[cls.EXIT_NODE][8] = str(fwmark)
        for rule in cls.RULES:
            ip_run(*cls.RULES[rule][1:])

    @staticmethod
    def remove_ip_rule(priority: int) -> None:
        """Delete an IP rule with the given priority."""
        ip_run('-4', 'rule', 'del', 'priority', str(priority))

    @classmethod
    def remove_all_ip_rules(cls, config: Dict) -> None:
        """Remove IP rules for the exit node."""
        rules = [5500, 5501, 6000]
        for peer, priority in config[cls.NODES].items():
            cls.set_fwmark(peer, None) if priority is None else rules.append(priority)
        collections.deque((cls.remove_ip_rule(rule) for rule in rules), maxlen=0)

    @classmethod
    def add_missing_interfaces(cls) -> None:
        """Add configurations for new interfaces."""
        config = cls.load_config()
        if config is None:
            return
        active_peers = set(peer.stem for peer in RUN_DIR.glob('*.conf') if peer.stem != config[cls.EXIT_NODE])
        stored_nodes = set(config[cls.NODES].keys())
        add = active_peers - stored_nodes
        if not add:
            return
        rules = set(config[cls.NODES].values())
        rules.discard(None)
        min_priority = 5502
        max_priority = (max(rules) if rules else min_priority) + len(add) + 1
        gen = (x for x in range(min_priority, max_priority))
        gen = (i for i in gen if i not in rules)
        for peer in add:
            mark = cls.get_fwmark(peer)
            if mark is None:
                cls.set_fwmark(peer, GLOB_MARK)
                config[cls.NODES][peer] = None
            else:
                i = next(gen)
                config[cls.NODES][peer] = i
                add_rule = cls.RULES[cls.NODES].copy()
                add_rule[5] = str(i)
                add_rule[7] = str(mark)
                ip_run(*add_rule[1:])
        cls.save_config(config)

    @classmethod
    def clean_missing_interfaces(cls) -> None:
        """Remove configurations for interfaces that no longer exist."""
        config = cls.load_config()
        if config is None:
            return
        active_peers = set(peer.stem for peer in RUN_DIR.glob('*.conf'))
        stored_nodes = set(config[cls.NODES].keys())
        remove = stored_nodes - active_peers
        if not remove:
            return
        rules = set()
        for node in remove:
            priority = config[cls.NODES][node]
            if priority is not None:
                config[cls.NODES].pop(node, None)
                rules.add(priority)
        collections.deque((cls.remove_ip_rule(rule) for rule in rules), maxlen=0)
        cls.save_config(config)

    @classmethod
    def sync(cls) -> None:
        """Sync state between peers and config file"""
        config = cls.load_config()
        if config is None:
            sys.exit(0)
        cls.clean_missing_interfaces()
        cls.add_missing_interfaces()

    @classmethod
    def set_exit_node(cls, interface: str) -> None:
        """Set up the given interface as the exit node."""
        config = cls.load_config()
        if config is not None:
            if interface == config[cls.EXIT_NODE]:
                Messages.send_info_message(local_message=f"Warning: Interface '{interface}' is already the exit node")
                sys.exit(0)
            else:
                cls.remove_exit_node()

        modified = cls.modify_allowed_ips(interface)
        fwmark = cls.get_fwmark(interface) or cls.set_fwmark(interface, EXIT_NODE_MARK) or EXIT_NODE_MARK

        config = {cls.EXIT_NODE: interface, cls.ADD_ALLOWEDIPS: modified, cls.NODES: {}}
        cls.save_config(config)

        cls.add_missing_interfaces()

        cls._iptables_connmark(interface, fwmark)
        cls.add_custom_routing_table(interface)
        cls.add_ip_rules(fwmark)

        Messages.send_info_message(local_message=f"Interface '{interface}' has been enabled as an exit node {cls.GOOD}")

    @classmethod
    def remove_exit_node(cls) -> None:
        """Remove the current exit node configuration."""
        config = cls.load_config()
        if config is None:
            Messages.send_info_message(local_message='Warning: There is currently no active exit node')
            sys.exit(0)
        interface = config[cls.EXIT_NODE]
        fwmark = cls.get_fwmark(interface)

        if fwmark == EXIT_NODE_MARK:
            cls.set_fwmark(interface, None)

        if config[cls.ADD_ALLOWEDIPS]:
            cls.modify_allowed_ips(interface=interface, remove=True)

        cls._iptables_connmark(interface, fwmark, action='-D')
        cls.flush_custom_routing_table()
        cls.remove_all_ip_rules(config)

        cls.EXIT_FILE.unlink()
        Messages.send_info_message(local_message=f"Interface '{interface}' has been deactivated as an exit node {cls.BAD}")

    @classmethod
    @contextmanager
    def locker(cls):
        with cls.LOCKER.open(mode='w') as lockfile:
            fcntl.flock(lockfile, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lockfile, fcntl.LOCK_UN)
