#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from contextlib import suppress
from functools import cached_property
from ipaddress import IPv4Address
from threading import get_ident
from typing import Iterator

from parallel_utils.thread import create_thread
from websockets import ConnectionClosed, ConnectionClosedError, ConnectionClosedOK, Data
from websockets.sync.client import ClientConnection
from websockets.sync.connection import Connection
from websockets.sync.server import ServerConnection

from wirescale.communications.common import CONNECTION_PAIRS, file_locker
from wirescale.communications.messages import ErrorCodes, ErrorMessages, Messages
from wirescale.vpn.tsmanager import TSManager


class ConnectionPair:
    def __init__(self, caller: IPv4Address, receiver: IPv4Address):
        self.caller = caller
        self.receiver = receiver
        with file_locker():
            self.caller_name, self.receiver_name
        self.check_running = False
        self.closing = False
        self.tcp_socket: ClientConnection | ServerConnection = None
        self.unix_socket: ServerConnection = None
        self.token: str = None
        CONNECTION_PAIRS[get_ident()] = self

    def __eq__(self, other):
        if self is not other:
            return False
        if self.token != other.token:
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

    def __iter__(self) -> Iterator[Data]:
        while True:
            try:
                yield self.remote_socket.recv(15)
            except TimeoutError:
                create_thread(self.check_broken_connection)
            except ConnectionClosedError:
                error = ErrorMessages.CONNECTION_LOST.format(peer_name=self.peer_name, peer_ip=self.peer_ip)
                ErrorMessages.send_error_message(local_message=error, error_code=ErrorCodes.TS_UNREACHABLE)
            except ConnectionClosedOK:
                return

    def check_broken_connection(self):
        if self.closing or self.check_running:
            return
        try:
            self.check_running = True
            with file_locker():
                checking_message = Messages.CHECKING_CONNECTION.format(peer_name=self.peer_name, peer_ip=self.peer_ip)
                checking_message = Messages.add_id(self.id, checking_message)
                Messages.send_info_message(local_message=checking_message, send_to_local=False)
                is_online = TSManager.wait_until_peer_is_online(ip=self.peer_ip, timeout=30)
            if not is_online:
                self.closing = True
                closing_message = Messages.add_id(self.id, ErrorMessages.CLOSING_SOCKET)
                ErrorMessages.send_error_message(local_message=closing_message, send_to_local=False, exit_code=None)
                create_thread(self.close_socket, self.remote_socket)
            else:
                message_ok = Messages.CONNECTION_OK.format(peer_name=self.peer_name, peer_ip=self.peer_ip)
                message_ok = Messages.add_id(self.id, message_ok)
                Messages.send_info_message(local_message=message_ok, send_to_local=False)
        finally:
            self.check_running = False

    def close_sockets(self):
        if self.local_socket is not None:
            create_thread(self.close_socket, self.local_socket)
        if self.remote_socket is not None:
            create_thread(self.close_socket, self.remote_socket)

    @staticmethod
    def close_socket(socket: Connection):
        with suppress(BaseException):
            socket.close()

    @cached_property
    def id(self) -> str:
        if self.token is None:
            self.token: str = str(self.local_socket.id)
        return self.token[-6:]

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

    def send_to_local(self, message):
        try:
            self.local_socket.send(message)
        except ConnectionClosed:
            socket_error = Messages.add_id(self.id, ErrorMessages.SOCKET_ERROR)
            print(socket_error, file=sys.stderr, flush=True)
            if self.remote_socket is not None:
                socket_remote_error = ErrorMessages.SOCKET_REMOTE_ERROR.format(peer_name=self.my_name, peer_ip=self.my_ip)
                socket_remote_error = Messages.add_id(self.id, socket_remote_error)
                error_message = ErrorMessages.build_error_message(socket_remote_error, ErrorCodes.GENERIC)
                try:
                    self.remote_socket.send(json.dumps(error_message))
                except ConnectionClosed:
                    remote_is_closed = ErrorMessages.SOCKET_REMOTE_ERROR.format(peer_name=self.peer_name, peer_ip=self.peer_ip)
                    remote_is_closed = Messages.add_id(self.id, remote_is_closed)
                    print(remote_is_closed, file=sys.stderr, flush=True)
            self.close_sockets()
            sys.exit(1)

    def send_to_remote(self, message, ack_timeout: int = None):
        try:
            self.remote_socket.send(message)
            if ack_timeout is not None:
                p = self.remote_socket.ping()
                return p.wait(timeout=ack_timeout)
        except ConnectionClosed:
            error = ErrorMessages.SOCKET_REMOTE_ERROR.format(peer_name=self.peer_name, peer_ip=self.peer_ip)
            error = Messages.add_id(self.id, error)
            print(error, file=sys.stderr, flush=True)
            if not self.running_in_remote:
                error_message = ErrorMessages.build_error_message(error, ErrorCodes.GENERIC)
                try:
                    self.local_socket.send(json.dumps(error_message))
                except ConnectionClosed:
                    socket_error = Messages.add_id(self.id, ErrorMessages.SOCKET_ERROR)
                    print(socket_error, file=sys.stderr, flush=True)
            self.close_sockets()
            sys.exit(1)

    @property
    def remote_socket(self):
        return self.tcp_socket

    @property
    def local_socket(self):
        return self.unix_socket

    @cached_property
    def websockets(self):
        return (self.remote_socket,) if self.running_in_remote else (self.remote_socket, self.local_socket)
