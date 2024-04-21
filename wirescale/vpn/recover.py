#!/usr/bin/env python3
# encoding:utf-8


import base64
import os
import re
import subprocess
import time
from contextlib import ExitStack
from datetime import datetime
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

from wirescale.communications import ActionCodes, BytesStrConverter, check_recover_config, CONNECTION_PAIRS, ErrorMessages, Messages
from wirescale.communications.checkers import get_latest_handshake
from wirescale.communications.common import file_locker, wait_tailscale_restarted
from wirescale.parsers.args import ConnectionPair
from wirescale.vpn import TSManager


class RecoverConfig:

    def __init__(self, interface: str, is_remote: int, latest_handshake: int, current_port: int, remote_interface: str, remote_port: int, wg_ip: IPv4Address):
        self.current_port: int = current_port
        self.derived_key: bytes = None
        self.endpoint: Tuple[IPv4Address, int] = None
        self.chacha: ChaCha20Poly1305 = None
        self.interface: str = interface
        self.is_remote: int = is_remote
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
        self.start_time: int = datetime.now().second
        self.wg_ip: IPv4Address = wg_ip

    @classmethod
    def create_from_autoremove(cls, interface: str, latest_handshake: int):
        pair = CONNECTION_PAIRS.get(get_ident())
        exec_start = subprocess.run(['systemctl', 'show', '-p', 'ExecStart', f'autoremove-{interface}'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip()
        if not exec_start:
            error = ErrorMessages.MISSING_AUTOREMOVE.format(interface=interface)
            error_remote = None
            if pair is not None:
                error_remote = ErrorMessages.REMOTE_MISSING_AUTOREMOVE.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=interface)
            ErrorMessages.send_error_message(local_message=error, remote_message=error_remote)
        args = re.search(r'(\sautoremove.*?);', exec_start).group(1).strip().split()
        autoremove_ip_receiver = IPv4Address(args[2])
        pair = pair or ConnectionPair(caller=TSManager.my_ip(), receiver=autoremove_ip_receiver)
        if autoremove_ip_receiver != pair.peer_ip:
            error = ErrorMessages.IP_MISMATCH.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip, interface=interface, autoremove_ip=autoremove_ip_receiver)
            error_remote = ErrorMessages.REMOTE_IP_MISMATCH.format(my_name=pair.my_name, my_ip=pair.my_ip, peer_ip=pair.peer_ip, interface=interface)
            ErrorMessages.send_error_message(local_message=error, remote_message=error_remote)
        recover = RecoverConfig(interface=interface, latest_handshake=latest_handshake, is_remote=args[5], wg_ip=IPv4Address(args[4]), current_port=int(args[7]), remote_interface=args[8],
                                remote_port=int(args[9]))
        check_recover_config(recover)
        recover.load_keys()
        with file_locker():
            recover.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        return recover

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
        privkey = subprocess.run(['wg', 'show', self.interface, 'private-key'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout.strip()
        pubkey_psk = subprocess.run(['wg', 'show', self.interface, 'preshared-keys'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding='utf-8').stdout.strip()
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
        data = BytesStrConverter.str_to_bytes(data)
        encrypted = self.chacha.encrypt(nonce=self.nonce, data=data, associated_data=None)
        encrypted = BytesStrConverter.raw_bytes_to_str64(encrypted)
        return encrypted

    def decrypt(self, data: str) -> str:
        data = BytesStrConverter.str64_to_raw_bytes(data)
        decrypted = self.chacha.decrypt(nonce=self.nonce, data=data, associated_data=None)
        decrypted = BytesStrConverter.bytes_to_str(decrypted)
        return decrypted

    def check_updated_handshake(self, timeout: int = 10) -> bool:
        t1 = time.time()
        while (time.time() - t1) < timeout:
            if get_latest_handshake(self.interface) != self.latest_handshake:
                return True
            sleep(0.5)
        return False

    def recover(self):
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
        if pair.running_in_remote:
            subprocess.run(['systemctl', 'stop', f'autoremove-{self.interface}.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        success_message = Messages.RECOVER_SUCCES.format(interface=self.interface)
        Messages.send_info_message(local_message=success_message, code=ActionCodes.SUCCESS)
        create_thread(self.autoremove_interface, pair)

    def autoremove_interface(self, pair: ConnectionPair):
        sleep(20)
        subprocess.run(['systemctl', 'reset-failed', f'autoremove-{self.interface}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        systemd = subprocess.run(['systemd-run', '-u', f'autoremove-{self.interface}', '/bin/sh', '/run/wirescale/wirescale-autoremove', 'autoremove',
                                  self.interface, str(pair.peer_ip), self.remote_pubkey, self.wg_ip, str(self.is_remote), str(self.start_time),
                                  int(self.new_port), self.remote_interface, str(self.remote_port)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        Messages.send_info_message(local_message=f'Launching autoremove subprocess. {systemd.stdout.strip()}')
