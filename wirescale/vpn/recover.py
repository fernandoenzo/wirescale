#!/usr/bin/env python3
# encoding:utf-8


import base64
import os
import re
from contextlib import ExitStack
from ipaddress import IPv4Address
from pathlib import Path
from threading import get_ident

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from parallel_utils.thread import create_thread

from wirescale.communications.checkers import check_configfile, check_updated_handshake
from wirescale.communications.common import BytesStrConverter, CONNECTION_PAIRS, file_locker
from wirescale.communications.connection_pair import ConnectionPair
from wirescale.communications.messages import ActionCodes, ErrorCodes, ErrorMessages, Messages
from wirescale.communications.systemd import Systemd
from wirescale.vpn.commands import iptables_run, wg_set, wg_show
from wirescale.vpn.tsmanager import TSManager
from wirescale.vpn.vpn_config import VPNConfig


class RecoverConfig(VPNConfig):

    def __init__(self, interface: str, iptables_accept: bool, iptables_forward: bool, iptables_masquerade: bool, running_in_remote: bool, latest_handshake: int,
                 current_port: int, recover_tries: int, recreate_tries: int, remote_interface: str, remote_local_port: int, suffix: int, wg_ip: IPv4Address):
        super().__init__()
        self.current_port: int = current_port
        self.derived_key: bytes = None
        self.chacha: ChaCha20Poly1305 = None
        self.config_file: Path = None
        self.interface: str = interface
        self.iptables_accept: bool = iptables_accept
        self.iptables_forward: bool = iptables_forward
        self.iptables_masquerade: bool = iptables_masquerade
        self.running_in_remote: bool = running_in_remote
        self.latest_handshake: int = latest_handshake
        self.nonce: bytes = os.urandom(12)
        self.new_port: int = TSManager.local_port()
        self.private_key: X25519PrivateKey = None
        self.recover_tries: int = recover_tries
        self.recreate_tries: int = recreate_tries
        self.remote_interface: str = remote_interface
        self.remote_local_port: int = remote_local_port
        self.remote_pubkey: X25519PublicKey = None
        self.remote_pubkey_str: str = None
        self.psk: bytes = None
        self.shared_key: bytes = None
        self.suffix: int = suffix
        self.wg_ip: IPv4Address = wg_ip

    @property
    def autoremove_pubkey(self) -> str:
        return self.remote_pubkey_str

    @property
    def autoremove_wg_ip(self) -> IPv4Address:
        return self.wg_ip

    @property
    def autoremove_listen_port(self) -> int:
        return self.new_port

    @classmethod
    def create_from_autoremove(cls, interface: str, latest_handshake: int):
        pair = CONNECTION_PAIRS.get(get_ident())
        unit = f'autoremove-{interface}'
        systemd = Systemd.create_from_autoremove(unit=unit)
        pair = pair or ConnectionPair(caller=TSManager.my_ip(), receiver=systemd.ts_ip)
        if systemd.ts_ip != pair.peer_ip:
            ErrorMessages.send_paired_error(ErrorMessages.IP_MISMATCH, interface=interface, autoremove_ip=systemd.ts_ip)
        recover = RecoverConfig(interface=interface, latest_handshake=latest_handshake, running_in_remote=systemd.running_in_remote, iptables_accept=systemd.iptables_accept,
                                iptables_forward=systemd.iptables_forward, iptables_masquerade=systemd.iptables_masquerade, wg_ip=systemd.wg_ip, current_port=systemd.local_port,
                                recover_tries=systemd.recover_tries, recreate_tries=systemd.recreate_tries, remote_interface=systemd.remote_interface, remote_local_port=systemd.remote_local_port,
                                suffix=systemd.suffix)
        recover.config_file = check_configfile()
        recover.load_keys()
        with file_locker():
            recover.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        return recover

    def fix_iptables(self):
        iptables = 'iptables -{action} INPUT -p udp --dport {port} -j ACCEPT -m comment --comment "wirescale-{interface}"'
        add_iptables = iptables.format(action='I', port=self.new_port, interface=self.interface).split()
        remove_iptables = iptables.format(action='D', port=self.current_port, interface=self.interface).split()
        iptables_run(remove_iptables)
        iptables_run(add_iptables)

    def modify_wgconfig(self):
        with open(self.config_path, 'r') as f:
            text = f.read()
        dport = '--dport {port}'
        listen_port = 'ListenPort = {port}'
        orig_listen_port = listen_port.format(port=self.current_port)
        new_listen_port = listen_port.format(port=self.new_port)
        orig_dport = dport.format(port=self.current_port)
        new_dport = dport.format(port=self.new_port)
        text = re.sub(rf'^{orig_listen_port}', new_listen_port, text, flags=re.IGNORECASE | re.MULTILINE)
        text = re.sub(orig_dport, new_dport, text, flags=re.IGNORECASE)
        with open(self.config_path, 'w') as f:
            f.write(text)

    def load_keys(self):
        privkey = wg_show(self.interface, 'private-key')
        pubkey_psk = wg_show(self.interface, 'preshared-keys')
        pubkey, psk = pubkey_psk.split('\n')[0].split('\t')
        self.remote_pubkey_str = pubkey.strip()
        privkey = base64.urlsafe_b64decode(privkey)
        pubkey = base64.urlsafe_b64decode(pubkey)
        self.psk = base64.urlsafe_b64decode(psk)
        self.private_key = X25519PrivateKey.from_private_bytes(privkey)
        self.remote_pubkey = X25519PublicKey.from_public_bytes(pubkey)
        self.shared_key = self.private_key.exchange(self.remote_pubkey)
        self.derived_key = HKDF(algorithm=hashes.SHA384(), length=32, salt=self.psk, info=None).derive(self.shared_key)
        self.chacha = ChaCha20Poly1305(self.derived_key)

    def encrypt(self, data: str) -> str:
        data = BytesStrConverter.str_to_bytes(data)
        encrypted = self.chacha.encrypt(nonce=self.nonce, data=data, associated_data=None)
        encrypted = BytesStrConverter.raw_bytes_to_str64(encrypted)
        return encrypted

    def decrypt(self, data: str) -> str:
        data = BytesStrConverter.str64_to_raw_bytes(data)
        decrypted = self.chacha.decrypt(nonce=self.nonce, data=data, associated_data=None)
        decrypted = BytesStrConverter.bytes_to_str(decrypted)
        return decrypted

    def recover(self):
        self.modify_wgconfig()
        if self.iptables_accept:
            self.fix_iptables()
        pair = CONNECTION_PAIRS[get_ident()]
        stack = ExitStack()
        stack.enter_context(file_locker())
        Messages.send_info_message(local_message='Stopping tailscale...')
        TSManager.stop()
        Messages.send_info_message(local_message=f"Modifying WireGuard interface '{self.interface}'...")
        wg_set(self.interface, 'listen-port', str(self.new_port))
        wg_set(self.interface, 'peer', self.remote_pubkey_str, 'endpoint', f'{self.endpoint[0]}:{self.endpoint[1]}')
        Messages.send_info_message(local_message='Starting tailscale...')
        TSManager.start()
        create_thread(TSManager.wait_tailscale_restarted, pair, stack)
        Messages.send_info_message(local_message=f"Checking latest handshake of interface '{self.interface}' after changing the endpoint...")
        updated = check_updated_handshake(self.interface, self.latest_handshake)
        if not updated:
            self.undo_recover()
            error = ErrorMessages.HANDSHAKE_FAILED_RECOVER.format(interface=self.interface)
            ErrorMessages.send_error_message(local_message=error, error_code=ErrorCodes.TS_UNREACHABLE)
        if pair.running_in_remote:
            Systemd.stop(f'autoremove-{self.interface}.service')
        success_message = Messages.RECOVER_SUCCESS.format(interface=self.interface)
        Messages.send_info_message(local_message=success_message, code=ActionCodes.SUCCESS)
        create_thread(Systemd.launch_autoremove, config=self, pair=pair)

    def undo_recover(self):
        self.new_port, self.current_port = self.current_port, self.new_port
        self.modify_wgconfig()
        if self.iptables_accept:
            self.fix_iptables()
        wg_set(self.interface, 'listen-port', str(self.new_port))
        wg_set(self.interface, 'peer', self.remote_pubkey_str, 'endpoint', f'{self.endpoint[0]}:{self.endpoint[1]}')
