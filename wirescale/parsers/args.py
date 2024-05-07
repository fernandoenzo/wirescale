#!/usr/bin/env python3
# encoding:utf-8


from functools import cached_property
from ipaddress import IPv4Address
from pathlib import Path
from threading import get_ident

from websockets.sync.client import ClientConnection
from websockets.sync.server import ServerConnection

from wirescale.communications.checkers import get_latest_handshake
from wirescale.communications.common import CONNECTION_PAIRS, file_locker
from wirescale.parsers import top_parser
from wirescale.vpn.tsmanager import TSManager


class ConnectionPair:
    def __init__(self, caller: IPv4Address, receiver: IPv4Address):
        self.caller = caller
        self.receiver = receiver
        with file_locker():
            self.caller_name, self.receiver_name
        self.tcp_socket: ClientConnection | ServerConnection = None
        self.unix_socket: ServerConnection = None
        CONNECTION_PAIRS[get_ident()] = self

    def __eq__(self, other):
        if self is not other:
            return False
        if self.caller is not other.caller:
            return False
        if self.receiver is not other.receiver:
            return False
        if self.tcp_socket is not other.tcp_socket:
            return False
        if self.unix_socket is not other.unix_socket:
            return False
        return True

    def close_sockets(self):
        if self.local_socket is not None:
            self.local_socket.close()
        if self.remote_socket is not None:
            self.remote_socket.close()

    @cached_property
    def my_ip(self) -> IPv4Address:
        return TSManager.my_ip()

    @cached_property
    def my_name(self) -> str:
        return TSManager.my_name()

    @cached_property
    def peer_ip(self) -> IPv4Address:
        return self.caller if self.running_in_remote else self.receiver

    @cached_property
    def peer_name(self) -> str:
        return TSManager.peer_name(self.peer_ip)

    @cached_property
    def caller_name(self) -> str:
        return self.peer_name if self.running_in_remote else self.my_name

    @cached_property
    def receiver_name(self) -> str:
        return self.my_name if self.running_in_remote else self.peer_name

    @cached_property
    def running_in_remote(self) -> bool:
        return self.receiver == self.my_ip

    @property
    def remote_socket(self):
        return self.tcp_socket

    @property
    def local_socket(self):
        return self.unix_socket

    @cached_property
    def websockets(self):
        return (self.remote_socket,) if self.running_in_remote else (self.remote_socket, self.local_socket)


class ARGS:
    AUTOREMOVE: bool = None
    CONFIGFILE: str = None
    DAEMON: bool = None
    DOWN: Path = None
    INTERFACE: str = None
    LATEST_HANDSHAKE: int = None
    PAIR: ConnectionPair = None
    PORT: int = None
    RECOVER: bool = None
    START: bool = None
    STOP: bool = None
    SUFFIX: bool = None
    UPGRADE: bool = None


def parse_args():
    args = vars(top_parser.parse_args())
    ARGS.DAEMON = args.get('opt') == 'daemon'
    ARGS.UPGRADE = args.get('opt') == 'upgrade'
    ARGS.DOWN = args.get('opt') == 'down'
    ARGS.RECOVER = args.get('opt') == 'recover'
    ARGS.START = args.get('command') == 'start'
    ARGS.STOP = args.get('command') == 'stop'
    ARGS.SUFFIX = not args.get('no_suffix')
    ARGS.AUTOREMOVE = not args.get('disable_autoremove')
    if ARGS.UPGRADE:
        peer_ip = args.get('peer')
        ARGS.PAIR = ConnectionPair(caller=TSManager.my_ip(), receiver=peer_ip)
        ARGS.CONFIGFILE = args.get('config') if args.get('config') is not None and args.get('config').split() else f'/etc/wirescale/{ARGS.PAIR.peer_name}.conf'
        ARGS.INTERFACE = args.get('interface') or ARGS.PAIR.peer_name
    if ARGS.RECOVER:
        ARGS.INTERFACE = args.get('interface')
        ARGS.LATEST_HANDSHAKE = get_latest_handshake(ARGS.INTERFACE)
    elif ARGS.DOWN:
        ARGS.CONFIGFILE = args.get('interface')
