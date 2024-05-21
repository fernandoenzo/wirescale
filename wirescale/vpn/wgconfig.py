#!/usr/bin/env python3
# encoding:utf-8


import collections
import re
import subprocess
import sys
from configparser import ConfigParser
from contextlib import ExitStack
from datetime import datetime
from io import StringIO
from ipaddress import ip_address, ip_network, IPv4Address, IPv4Network, IPv6Address, IPv6Network
from pathlib import Path
from subprocess import CompletedProcess, STDOUT
from threading import get_ident
from typing import Dict, FrozenSet, Tuple

from parallel_utils.thread import create_thread

from wirescale.communications.common import CONNECTION_PAIRS, file_locker, subprocess_run_tmpfile
from wirescale.communications.messages import ErrorMessages, Messages
from wirescale.vpn.tsmanager import TSManager


class WGConfig:
    repeatable_fields = frozenset(('address', 'dns', 'preup', 'postup', 'predown', 'postdown', 'allowedips'))
    configfile = Path('/run/wirescale/%i.conf')

    def __init__(self, file_path: Path | str):
        self.interface: str = None
        self.file_path: Path = file_path if isinstance(file_path, Path) else Path(file_path)
        self.config: ConfigParser = ConfigParser(interpolation=None)
        self.config.optionxform = lambda option: option
        self.counters: Dict = {}
        self.read_config()
        self.addresses = self.get_addresses()
        self.remote_addresses: FrozenSet[IPv4Address | IPv6Address] = None
        self.private_key = self.get_field('Interface', 'PrivateKey') or self.generate_wg_privkey()
        self.listen_port = TSManager.local_port()
        self.endpoint: Tuple[IPv4Address, int] = None
        self.table = self.get_field('Interface', 'Table')
        self.mtu = self.get_field('Interface', 'MTU')
        self.nat: bool = None
        self.fwmark = self.get_field('Interface', 'FwMark')
        self.allowed_ips = self.get_allowed_ips()
        self.public_key = self.generate_wg_pubkey(self.private_key)
        self.remote_interface: str = None
        self.remote_local_port: int = None
        self.remote_pubkey: str = self.get_field('Peer', 'PublicKey')
        self.psk = self.get_field('Peer', 'PresharedKey')
        self.has_psk: bool = self.psk is not None
        self.psk = self.psk or self.generate_wg_psk()
        self.start_time: int = datetime.now().second
        self.suffix: int = None

    def read_config(self):
        with open(self.file_path, 'r') as f:
            text = f.read()
        for field in self.repeatable_fields:
            field = field.lower()
            suffix = [1]  # We use a list so that the value is preserved between calls to the replace function

            def replace(match):
                old_str = match.group(0)
                result = f'{old_str}{suffix[0]}_'
                suffix[0] += 1
                return result

            text = re.sub(field, replace, text, flags=re.IGNORECASE)
            self.counters[field] = suffix[0] - 1
        self.config.read_string(text)

    def get_field(self, section_name: str, field: str) -> str | Tuple[str, ...] | None:
        field = field.lower()
        section = next(section for section in self.config.sections() if section.lower() == section_name.lower())
        if field not in self.repeatable_fields:
            return next((value for (name, value) in self.config.items(section) if name.lower() == field), None)
        return tuple(value for (name, value) in self.config.items(section) if name.lower().startswith(field))

    def get_addresses(self) -> FrozenSet[IPv4Address | IPv6Address] | None:
        lines: Tuple[str, ...] = self.get_field('interface', 'address')
        if not lines:
            return None
        return frozenset(ip_address(addr.strip()) for line in lines for addr in line.replace(',', ' ').split())

    def get_allowed_ips(self) -> FrozenSet[IPv4Network | IPv6Network] | None:
        lines: Tuple[str, ...] = self.get_field('peer', 'allowedips')
        if not lines:
            return None
        return frozenset(ip_network(addr.strip(), strict=False) for line in lines for addr in line.replace(',', ' ').split())

    def ip_is_allowed(self, ip: IPv4Address | IPv6Address) -> bool:
        return next((True for network in self.allowed_ips if ip in network), False)

    def add_script(self, action: str, script: str, first_place=False):
        interface = next(section for section in self.config.sections() if section.lower() == 'interface')
        if first_place:
            same_actions = [(name, value) for (name, value) in self.config.items(interface) if name.lower().startswith(action.lower())]
            collections.deque((self.config.remove_option(interface, name) for (name, _) in same_actions), maxlen=0)
        self.counters[action.lower()] += 1
        self.config.set(interface, f'{action}{self.counters[action.lower()]}_', script)
        if first_place:
            collections.deque((self.config.set(interface, name, value) for (name, value) in same_actions), maxlen=0)

    def add_iptables(self):
        port = TSManager.local_port()
        postup_input_interface = 'iptables -I INPUT -i %i -j ACCEPT'
        postup_input_port = f'iptables -I INPUT -p udp --dport {port} -j ACCEPT'
        postdown_input_interface = 'iptables -D INPUT -i %i -j ACCEPT || true'
        postdown_input_port = f'iptables -D INPUT -p udp --dport {port} -j ACCEPT || true'
        self.add_script('postup', postup_input_interface)
        self.add_script('postup', postup_input_port)
        self.add_script('postdown', postdown_input_interface, first_place=True)
        self.add_script('postdown', postdown_input_port, first_place=True)

    def first_handshake(self):
        handshake = (rf"""/bin/sh -c 'count=0; while [ $count -le 14 ]; do handshake=$(wg show %i latest-handshakes | awk -v pubkey="{self.remote_pubkey}" '\''$1 == pubkey {{print $2}}'\''); """
                     "if [ $handshake -eq 0 ]; then sleep 0.5; count=$((count+1)); else exit 0; fi; done; exit 1'")
        self.add_script('postup', handshake, first_place=True)

    def autoremove_interface(self):
        pair = CONNECTION_PAIRS[get_ident()]
        running_in_remote = int(pair.running_in_remote)
        nat = int(self.nat)
        subprocess.run(['systemctl', 'reset-failed', f'autoremove-{self.interface}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        systemd = subprocess.run(['systemd-run', '-u', f'autoremove-{self.interface}', '/bin/sh', '/run/wirescale/wirescale-autoremove', 'autoremove',
                                  self.interface, str(pair.peer_ip), self.remote_pubkey, next(str(ip) for ip in self.remote_addresses), str(running_in_remote),
                                  str(self.start_time), str(self.listen_port), str(nat), self.remote_interface, str(self.remote_local_port)],
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        Messages.send_info_message(local_message=f'Launching autoremove subprocess. {systemd.stdout.strip()}')

    def autoremove_configfile(self):
        remove_configfile = f'rm -f {self.configfile}'
        self.add_script('postdown', remove_configfile, first_place=True)

    def set_metric(self, metric: int):
        metric = (r'/bin/bash -c "ip route | grep -w %i | while read -r line ; do sudo ip route del $line; if [[ ${line##* } == metric ]]; then line=${line% *}; line=${line% *}; fi; '
                  fr'sudo ip route add $line metric {metric}; done"')
        self.add_script('postup', metric, first_place=True)

    @staticmethod
    def generate_wg_privkey() -> str:
        return subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()

    @staticmethod
    def generate_wg_pubkey(privkey: str) -> str:
        return subprocess.run(['wg', 'pubkey'], input=privkey, capture_output=True, text=True).stdout.strip()

    @classmethod
    def generate_wg_keypair(cls) -> Tuple[str, str]:
        private = cls.generate_wg_privkey()
        public = cls.generate_wg_pubkey(private)
        return private, public

    @staticmethod
    def generate_wg_psk() -> str:
        return subprocess.run(['wg', 'genpsk'], capture_output=True, text=True).stdout.strip()

    def generate_new_config(self):
        new_config = ConfigParser(interpolation=None)
        new_config.optionxform = lambda option: option
        interface, peer, allowedips = 'Interface', 'Peer', 'AllowedIPs'
        new_config.add_section(interface)
        new_config.add_section(peer)
        # self.add_iptables()
        # self.first_handshake()
        self.autoremove_configfile()
        repeatable_fields = [field for field in self.repeatable_fields if field != allowedips]
        for field in repeatable_fields:
            for i, value in enumerate(self.get_field(interface, field), start=1):
                new_config.set(interface, f'{field}{i}_', value)
        new_config.set(interface, 'ListenPort', str(self.listen_port))
        new_config.set(interface, 'PrivateKey', self.private_key)
        new_config.set(interface, 'Table', self.table) if self.table else None
        new_config.set(interface, 'MTU', self.mtu) if self.mtu else None
        new_config.set(interface, 'FwMark', self.fwmark) if self.fwmark else None
        new_config.set(peer, 'PublicKey', self.remote_pubkey)
        new_config.set(peer, 'PresharedKey', self.psk)
        new_config.set(peer, 'Endpoint', f'{self.endpoint[0]}:{self.endpoint[1]}')
        new_config.set(peer, 'PersistentKeepalive', '10')
        for i, value in enumerate(self.get_field(peer, allowedips), start=1):
            new_config.set(peer, f'{allowedips}{i}_', value)
        new_config = self.write_config(new_config, self.suffix)
        self.new_config_path.write_text(new_config, encoding='utf-8')

    @property
    def new_config_path(self):
        return Path('/run/wirescale/').joinpath(f'{self.interface}.conf')

    @classmethod
    def write_config(cls, config: ConfigParser, suffix: int = None):
        string_io = StringIO()
        config.write(string_io)
        text = string_io.getvalue()

        def replace(match):
            old_str = match.group(0)
            result = re.sub(r'\d+_', '', old_str, flags=re.IGNORECASE)
            return result

        for field in cls.repeatable_fields:
            text = re.sub(rf'{field}\d+_', replace, text, flags=re.IGNORECASE)

        if suffix is not None:
            text = text.replace('%s', str(suffix))

        return text

    def upgrade(self) -> CompletedProcess[str]:
        from wirescale.communications.checkers import check_updated_handshake
        pair = CONNECTION_PAIRS[get_ident()]
        stack = ExitStack()
        stack.enter_context(file_locker())
        Messages.send_info_message(local_message='Stopping tailscale...')
        TSManager.stop()
        Messages.send_info_message(local_message=f"Setting up WireGuard interface '{self.interface}'...")
        wgquick = subprocess_run_tmpfile(['wg-quick', 'up', str(self.new_config_path)], stderr=STDOUT)
        Messages.send_info_message(local_message='Starting tailscale...')
        TSManager.start()
        if wgquick.returncode == 0:
            updated = check_updated_handshake(self.interface)
            if not updated:
                error = ErrorMessages.HANDSHAKE_FAILED.format(interface=self.interface)
                ErrorMessages.send_error_message(local_message=error)
            self.autoremove_interface()
            wgquick_messages = wgquick.stdout.split('\n')
            systemd_messages = [m for m in wgquick_messages if "running as unit" in m.lower()]
            collections.deque((Messages.send_info_message(local_message=m) for m in systemd_messages), maxlen=0)
            success = Messages.SUCCESS.format(interface=self.interface)
            Messages.send_info_message(local_message=success, send_to_local=False)
        else:
            self.new_config_path.unlink()
            final_error = Messages.add_id(pair.id, ErrorMessages.FINAL_ERROR)
            print(final_error, file=sys.stderr, flush=True)
        create_thread(TSManager.wait_tailscale_restarted, pair, stack)
        return wgquick
