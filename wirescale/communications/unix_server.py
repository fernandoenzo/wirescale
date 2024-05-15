#!/usr/bin/env python3
# encoding:utf-8


import json
import socket
import sys
from contextlib import ExitStack, suppress
from ipaddress import IPv4Address
from pathlib import Path
from threading import active_count, get_ident
from time import sleep

from parallel_utils.thread import StaticMonitor
from websockets import ConnectionClosed
from websockets.sync.server import ServerConnection, unix_serve, WebSocketServer

from wirescale.communications.checkers import check_configfile, check_interface, check_recover_config, check_wgconfig
from wirescale.communications.common import CONNECTION_PAIRS, Semaphores, SHUTDOWN, SOCKET_PATH
from wirescale.communications.messages import ActionCodes, ErrorCodes, ErrorMessages, MessageFields, Messages
from wirescale.communications.tcp_client import TCPClient
from wirescale.communications.tcp_server import TCPServer
from wirescale.communications.udp_server import UDPServer
from wirescale.parsers.args import ConnectionPair
from wirescale.vpn.recover import RecoverConfig
from wirescale.vpn.tsmanager import TSManager
from wirescale.vpn.watch import ACTIVE_SOCKETS


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
            with suppress(BaseException):
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
                try:
                    match code:
                        case ActionCodes.STOP:
                            cls.stop()
                        case ActionCodes.UPGRADE | ActionCodes.RECOVER:
                            pair = ConnectionPair(caller=TSManager.my_ip(), receiver=IPv4Address(message[MessageFields.PEER_IP]))
                            pair.unix_socket = websocket
                            pair.id  # Sets the token property
                            if code == ActionCodes.UPGRADE:
                                enqueueing = Messages.ENQUEUEING_TO.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                                start_processing = Messages.START_PROCESSING_TO.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                                next_message = Messages.NEXT_UPGRADE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                                exclusive_message = Messages.EXCLUSIVE_SEMAPHORE_UPGRADE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                                action = lambda: cls.upgrade(message, stack)
                            elif code == ActionCodes.RECOVER:
                                interface = message[MessageFields.INTERFACE]
                                enqueueing = Messages.ENQUEUEING_RECOVER.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip, interface=interface)
                                start_processing = Messages.START_PROCESSING_RECOVER.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip, interface=interface)
                                next_message = Messages.NEXT_RECOVER.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip, interface=interface)
                                exclusive_message = Messages.EXCLUSIVE_SEMAPHORE_RECOVER.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip, interface=interface)
                                action = lambda: cls.recover(message, stack)
                            Messages.send_info_message(local_message=enqueueing)
                            with ExitStack() as stack:
                                stack.enter_context(StaticMonitor.synchronized(uid=Semaphores.CLIENT))
                                cls.discard_connections(websocket)
                                Messages.send_info_message(local_message=next_message)
                                ACTIVE_SOCKETS.client_thread = get_ident()
                                ACTIVE_SOCKETS.waiter_switched.wait()
                                stack.enter_context(StaticMonitor.synchronized(uid=Semaphores.EXCLUSIVE))
                                cls.discard_connections(websocket)
                                ACTIVE_SOCKETS.exclusive_socket = pair
                                Messages.send_info_message(local_message=exclusive_message)
                                Messages.send_info_message(local_message=start_processing)
                                action()

                finally:
                    Messages.send_info_message(local_message=Messages.END_SESSION, send_to_local=False)
                    CONNECTION_PAIRS.pop(get_ident(), None)

    @staticmethod
    def discard_connections(websocket: ServerConnection):
        if SHUTDOWN.is_set():
            error = ErrorMessages.build_error_message(ErrorMessages.CLOSED, ErrorCodes.CLOSED)
            try:
                websocket.send(json.dumps(error))
            except ConnectionClosed:
                pass
            ConnectionPair.close_socket(websocket)
            sys.exit(1)

    @classmethod
    def stop(cls):
        SHUTDOWN.set()
        TCPServer.SERVER.shutdown()
        cls.SERVER.shutdown()
        print(Messages.SHUTDOWN_SET, flush=True)
        while active_count() > 3:
            sleep(1)
        UDPServer.UDPDummy.close()

    @staticmethod
    def upgrade(message: dict, stack: ExitStack):
        interface, suffix = message[MessageFields.INTERFACE], message[MessageFields.SUFFIX]
        wg_interface, _ = check_interface(interface=interface, suffix=suffix)
        config = check_configfile(config=message[MessageFields.CONFIG])
        wgconfig = check_wgconfig(config, wg_interface)
        TCPClient.upgrade(wgconfig=wgconfig, interface=interface, stack=stack, suffix=suffix)

    @staticmethod
    def recover(message: dict, stack: ExitStack):
        interface = message[MessageFields.INTERFACE]
        latest_handshake = message[MessageFields.LATEST_HANDSHAKE]
        recover = RecoverConfig.create_from_autoremove(interface=interface, latest_handshake=latest_handshake)
        check_recover_config(recover)
        TCPClient.recover(recover=recover, stack=stack)
