#!/usr/bin/env python3
# encoding:utf-8


import json
import socket
import sys
from contextlib import ExitStack, suppress
from ipaddress import IPv4Address
from pathlib import Path

from parallel_utils.thread import StaticMonitor
from websockets.sync.server import ServerConnection, unix_serve, WebSocketServer

from wirescale.communications import TCPServer, SHUTDOWN
from wirescale.communications.checkers import check_interface, check_configfile, check_wgconfig, send_error
from wirescale.communications.messages import ActionCodes, ErrorCodes, MessageFields, ErrorMessages
from wirescale.communications.tcp_client import TCPClient
from wirescale.parsers import ARGS
from wirescale.parsers.args import ConnectionPair
from wirescale.vpn import TSManager


class UnixServer:
    SOCKET_PATH = Path('/run/wirescale/wirescaled.sock').resolve()
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
                if s.getsockname() == str(cls.SOCKET_PATH):
                    cls.SYSTEMD_SOCKET_FD = fd
                    cls.SOCKET = s
                    return
                s.close()
        print(f'Error: No file descriptor found for the UNIX socket located at "{cls.SOCKET_PATH}"', file=sys.stderr, flush=True)
        sys.exit(1)

    @classmethod
    def run_server(cls):
        cls.set_socket()
        cls.SERVER = unix_serve(sock=cls.SOCKET, handler=cls.handler)
        with ExitStack() as stack:
            stack.enter_context(cls.SERVER)
            cls.SERVER.serve_forever()

    @classmethod
    def handler(cls, websocket: ServerConnection):
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
        cls.SERVER.shutdown()
        TCPServer.SERVER.shutdown()
        print('The server has been set to shut down', flush=True)

    @staticmethod
    def upgrade(websocket: ServerConnection, message: dict):
        pair = ConnectionPair(caller=TSManager.my_ip(), receiver=IPv4Address(message[MessageFields.PEER_IP]))
        pair.unix_socket = websocket
        interface = check_interface(pair, interface=message[MessageFields.INTERFACE], suffix=ARGS.SUFFIX)
        config = check_configfile(pair, config=message[MessageFields.CONFIG])
        wgconfig = check_wgconfig(pair, config)
        wgconfig.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        wgconfig.autoremove = message[MessageFields.AUTOREMOVE]
        wgconfig.interface = interface
        TCPClient.upgrade(pair=pair, wgconfig=wgconfig)
