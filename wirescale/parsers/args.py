#!/usr/bin/env python3
# encoding:utf-8


from functools import cached_property
from ipaddress import IPv4Address
from pathlib import Path
from threading import get_ident

from websockets.sync.client import ClientConnection
from websockets.sync.server import ServerConnection

from wirescale.communications.common import CONNECTION_PAIRS, file_locker
from wirescale.parsers.parsers import top_parser


class ConnectionPair:
    def __init__(self, caller: IPv4Address, receiver: IPv4Address):
        self.caller = caller
        self.receiver = receiver
        with file_locker() as _:
            self.caller_name, self.receiver_name
        self.tcp_socket: ClientConnection | ServerConnection = None
        self.unix_socket: ServerConnection = None
        CONNECTION_PAIRS[get_ident()] = self

    @cached_property
    def my_ip(self) -> IPv4Address:
        from wirescale.vpn import TSManager
        return TSManager.my_ip()

    @cached_property
    def my_name(self) -> str:
        from wirescale.vpn import TSManager
        return TSManager.my_name()

    @cached_property
    def peer_ip(self) -> IPv4Address:
        return self.caller if self.running_in_remote else self.receiver

    @cached_property
    def peer_name(self) -> str:
        from wirescale.vpn import TSManager
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
    PAIR: ConnectionPair = None
    START: bool = None
    STOP: bool = None
    SUFFIX: bool = None
    UPGRADE: bool = None


def parse_args():
    from wirescale.vpn import TSManager
    args = vars(top_parser.parse_args())
    ARGS.DAEMON = args.get('opt') == 'daemon'
    ARGS.UPGRADE = args.get('opt') == 'upgrade'
    ARGS.DOWN = args.get('opt') == 'down'
    ARGS.START = args.get('command') == 'start'
    ARGS.STOP = args.get('command') == 'stop'
    ARGS.SUFFIX = not args.get('no_suffix')
    ARGS.AUTOREMOVE = not args.get('disable_autoremove')
    if ARGS.UPGRADE:
        peer_ip = args.get('peer')
        ARGS.PAIR = ConnectionPair(caller=TSManager.my_ip(), receiver=peer_ip)
        ARGS.CONFIGFILE = args.get('config') if args.get('config') is not None and args.get('config').split() else f'/etc/wirescale/{ARGS.PAIR.peer_name}.conf'
        ARGS.INTERFACE = args.get('interface') or ARGS.PAIR.peer_name
    elif ARGS.DOWN:
        ARGS.CONFIGFILE = args.get('interface')
