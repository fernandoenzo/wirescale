#!/usr/bin/env python3
# encoding:utf-8


import json
import socket
import sys
from contextlib import suppress
from ipaddress import IPv4Address
from pathlib import Path
from threading import active_count, get_ident
from time import sleep

from parallel_utils.thread import StaticMonitor
from websockets.sync.server import ServerConnection, WebSocketServer, unix_serve

from wirescale.communications import Messages, SHUTDOWN, TCPServer
from wirescale.communications.checkers import check_configfile, check_interface, check_wgconfig, send_error
from wirescale.communications.common import CONNECTION_PAIRS, SOCKET_PATH
from wirescale.communications.messages import ActionCodes, ErrorCodes, ErrorMessages, MessageFields
from wirescale.communications.tcp_client import TCPClient
from wirescale.communications.udp_server import UDPServer
from wirescale.parsers.args import ConnectionPair
from wirescale.vpn import TSManager


class UnixServer:
    SYSTEMD_SOCKET_FD: int = None
    SOCKET: socket.socket = None
    SERVER: WebSocketServer = None

    @classmethod
    def set_socket(cls):
        if cls.SOCKET is not None:
            return
        fd_dir = Path('/proc/self/fd')
        fd_dir = [int(fd.name) for fd in fd_dir.iterdir() if fd.is_socket() and int(fd.name) not in (0, 1, 2)]
        for fd in fd_dir:
            with suppress(Exception):
                s = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
                if s.getsockname() == str(SOCKET_PATH):
                    cls.SYSTEMD_SOCKET_FD = fd
                    cls.SOCKET = s
                    return
                s.close()
        print(f"Error: No file descriptor found for the UNIX socket located at '{SOCKET_PATH}'", file=sys.stderr, flush=True)
        sys.exit(1)

    @classmethod
    def run_server(cls):
        UDPServer.occupy_port_41641()
        cls.set_socket()
        cls.SERVER = unix_serve(sock=cls.SOCKET, handler=cls.handler)
        with cls.SERVER:
            cls.SERVER.serve_forever()

    @classmethod
    def handler(cls, websocket: ServerConnection):
        with websocket:
            cls.discard_connections(websocket)
            message: dict = json.loads(websocket.recv())
            if code := message[MessageFields.CODE]:
                match code:
                    case ActionCodes.STOP:
                        cls.stop()
                    case ActionCodes.UPGRADE:
                        with StaticMonitor.synchronized(uid=ActionCodes.UPGRADE):
                            cls.discard_connections(websocket)
                            cls.upgrade(websocket, message)

    @staticmethod
    def discard_connections(websocket: ServerConnection):
        if SHUTDOWN.is_set():
            send_error(websocket, ErrorMessages.CLOSED, ErrorCodes.CLOSED)

    @classmethod
    def stop(cls):
        SHUTDOWN.set()
        TCPServer.SERVER.shutdown()
        cls.SERVER.shutdown()
        print(Messages.SHUTDOWN_SET, flush=True)
        while active_count() > 3:
            sleep(0)
            with StaticMonitor.synchronized(uid=ActionCodes.UPGRADE):
                pass
        UDPServer.UDPDummy.close()

    @staticmethod
    def upgrade(websocket: ServerConnection, message: dict):
        try:
            pair = ConnectionPair(caller=TSManager.my_ip(), receiver=IPv4Address(message[MessageFields.PEER_IP]))
            pair.unix_socket = websocket
            interface = check_interface(interface=message[MessageFields.INTERFACE], suffix=message[MessageFields.SUFFIX])
            config = check_configfile(config=message[MessageFields.CONFIG])
            wgconfig = check_wgconfig(config, interface)
            wgconfig.endpoint = TSManager.peer_endpoint(pair.peer_ip)
            wgconfig.autoremove = message[MessageFields.AUTOREMOVE]
            TCPClient.upgrade(wgconfig=wgconfig)
        finally:
            CONNECTION_PAIRS.pop(get_ident(), None)
