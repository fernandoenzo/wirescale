#!/usr/bin/env python3
# encoding:utf-8


import base64
import os
import re
import subprocess
import time
from contextlib import ExitStack
from ipaddress import IPv4Address
from pathlib import Path
from threading import get_ident
from time import sleep
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from parallel_utils.thread import create_thread

from wirescale.communications import CONNECTION_PAIRS, ErrorMessages, Messages, RawBytesStrConverter
from wirescale.communications.common import file_locker, wait_tailscale_restarted
from wirescale.parsers.validators import get_latest_handshake
from wirescale.vpn import TSManager


class RecoverConfig:

    def __init__(self, interface: str, latest_handshake: int, current_port: int, remote_interface: str, remote_port: int):
        self.current_port: int = current_port
        self.derived_key: bytes = None
        self.endpoint: Tuple[IPv4Address, int] = None
        self.chacha: ChaCha20Poly1305 = None
        self.interface: str = interface
        self.latest_handshake: int = latest_handshake
        self.nonce: bytes = os.urandom(12)
        self.new_port: int = TSManager.local_port()
        self.private_key: X25519PrivateKey = None
        self.remote_interface: str = remote_interface
        self.remote_port: int = remote_port
        self.remote_pubkey: X25519PublicKey = None
        self.runfile = Path(f'/run/wirescale/{interface}.conf')
        self.psk: bytes = None
        self.shared_key: bytes = None
        self.load_keys()

    def fix_iptables(self):
        iptables = 'iptables -{action} INPUT -p udp --dport {port} -j ACCEPT'
        add_iptables = iptables.format(action='I', port=self.new_port).split()
        remove_iptables = iptables.format(action='D', port=self.current_port).split()
        subprocess.run(remove_iptables, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(add_iptables, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def modify_wgconfig(self):
        with open(self.runfile, 'r') as f:
            text = f.read()
        dport = '--dport {port}'
        listen_port = 'ListenPort = {port}'
        orig_listen_port = listen_port.format(port=self.current_port)
        new_listen_port = listen_port.format(port=self.new_port)
        orig_dport = dport.format(port=self.current_port)
        new_dport = dport.format(port=self.new_port)
        text = re.sub(rf'^{orig_listen_port}', new_listen_port, text, flags=re.IGNORECASE | re.MULTILINE)
        text = re.sub(orig_dport, new_dport, text, flags=re.IGNORECASE)
        with open(self.runfile, 'w') as f:
            f.write(text)

    def load_keys(self):
        privkey = subprocess.run(['wg', 'show', self.interface, 'private-key'], capture_output=True, encoding='utf-8', text=True).stdout.strip()
        pubkey_psk = subprocess.run(['wg', 'show', self.interface, 'preshared-keys'], capture_output=True, encoding='utf-8', text=True).stdout.strip()
        pubkey, psk = pubkey_psk.split('\n')[0].split('\t')
        privkey = base64.urlsafe_b64decode(privkey)
        pubkey = base64.urlsafe_b64decode(pubkey)
        self.psk = base64.urlsafe_b64decode(psk)
        self.private_key = X25519PrivateKey.from_private_bytes(privkey)
        self.remote_pubkey = X25519PublicKey.from_public_bytes(pubkey)
        self.shared_key = self.private_key.exchange(self.remote_pubkey)
        self.derived_key = HKDF(algorithm=hashes.SHA384(), length=32, salt=self.psk, info=None).derive(self.shared_key)
        self.chacha = ChaCha20Poly1305(self.derived_key)

    def encrypt(self, data: str) -> str:
        data = RawBytesStrConverter.str_to_bytes(data)
        encrypted = self.chacha.encrypt(nonce=self.nonce, data=data, associated_data=None)
        encrypted = RawBytesStrConverter.raw_bytes_to_str64(encrypted)
        return encrypted

    def decrypt(self, data: str) -> str:
        data = RawBytesStrConverter.str64_to_raw_bytes(data)
        decrypted = self.chacha.decrypt(nonce=self.nonce, data=data, associated_data=None)
        decrypted = RawBytesStrConverter.bytes_to_str(decrypted)
        return decrypted

    def check_updated_handshake(self, timeout: int = 10) -> bool:
        t1 = time.time()
        while (time.time() - t1) < timeout:
            if get_latest_handshake(self.interface) != self.latest_handshake:
                return True
            sleep(0.5)
        return False

    def recover(self) -> bool:
        self.modify_wgconfig()
        self.fix_iptables()
        pair = CONNECTION_PAIRS[get_ident()]
        stack = ExitStack()
        stack.enter_context(file_locker())
        Messages.send_info_message(local_message='Stopping tailscale...')
        TSManager.stop()
        Messages.send_info_message(local_message=f"Modifying WireGuard interface '{self.interface}'...")
        subprocess.run(['wg', 'set', self.interface, 'listen-port', str(self.new_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['wg', 'set', self.interface, 'peer', self.remote_pubkey, 'endpoint', f'{self.endpoint[0]}:{self.endpoint[1]}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Messages.send_info_message(local_message='Starting tailscale...')
        TSManager.start()
        create_thread(wait_tailscale_restarted, pair, stack)
        Messages.send_info_message(local_message=f"Checking latest handshake of interface '{self.interface}' after changing the endpoint...")
        updated = self.check_updated_handshake()
        if not updated:
            error = ErrorMessages.HANDSHAKE_FAILED.format(interface=self.interface)
            ErrorMessages.send_error_message(local_message=error)
        create_thread(self.autoremove_interface)
        # Subprocess run systemd con el nuevo endpoint
        # IMPORTANTE
        # IMPORTANTE
        # IMPORTANTE
        return updated

    def autoremove_interface(self):
        pair = CONNECTION_PAIRS[get_ident()]
        running_in_remote = int(pair.running_in_remote)
        subprocess.run(['systemctl', 'reset-failed', f'autoremove-{self.interface}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        systemd = subprocess.run(['systemd-run', '-u', f'autoremove-{self.interface}', '/bin/sh', '/run/wirescale/wirescale-autoremove', 'autoremove',
                                  self.interface, str(pair.peer_ip), self.remote_pubkey, next(str(ip) for ip in self.remote_addresses), str(running_in_remote), str(self.start_time),
                                  self.remote_interface, str(self.remote_local_port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        Messages.send_info_message(local_message=f'Launching autoremove subprocess. {systemd.stdout}')
