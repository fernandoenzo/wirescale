#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from contextlib import ExitStack
from ipaddress import IPv4Address
from threading import get_ident

from parallel_utils.thread import StaticMonitor
from websockets.sync.client import ClientConnection, connect

from wirescale.communications.common import CONNECTION_PAIRS, Semaphores, TCP_PORT
from wirescale.communications.messages import ActionCodes, ErrorCodes, ErrorMessages, MessageFields, Messages, TCPMessages
from wirescale.communications.operations import VPNOperation
from wirescale.vpn.watch import ACTIVE_SOCKETS


class TCPClient:

    @staticmethod
    def connect(uri: IPv4Address) -> ClientConnection:
        for i in range(3):
            try:
                return connect(uri=f'ws://{uri}:{TCP_PORT}')
            except TimeoutError:
                if i == 2:
                    return None

    @classmethod
    def _establish_connection(cls, pair):
        try:
            pair.tcp_socket = cls.connect(uri=pair.peer_ip)
            if pair.tcp_socket is None:
                peer_is_offline = ErrorMessages.TS_PEER_OFFLINE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                ErrorMessages.send_error_message(local_message=peer_is_offline, error_code=ErrorCodes.TS_UNREACHABLE)
        except ConnectionRefusedError:
            error = ErrorMessages.REMOTE_MISSING_WIRESCALE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            ErrorMessages.send_error_message(local_message=error)

    @staticmethod
    def _send_go_or_fail(pair, config):
        sent = TCPMessages.send_go(config)
        if not sent:
            error = ErrorMessages.CONNECTION_LOST.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            ErrorMessages.send_error_message(local_message=error, error_code=ErrorCodes.TS_UNREACHABLE)

    @classmethod
    def run(cls, operation: VPNOperation, stack: ExitStack):
        pair = CONNECTION_PAIRS[get_ident()]
        cls._establish_connection(pair)
        with pair.remote_socket:
            TCPMessages.send_token()
            TCPMessages.send_hello()
            for message in pair:
                message = json.loads(message)
                if error_code := message[MessageFields.ERROR_CODE]:
                    ErrorMessages.send_error_message(local_message=message[MessageFields.ERROR_MESSAGE], error_code=error_code)
                elif code := message[MessageFields.CODE]:
                    match code:
                        case ActionCodes.ACK:
                            stack.enter_context(StaticMonitor.synchronized(uid=Semaphores.WAIT_IF_SWITCHED))
                            ACTIVE_SOCKETS.client_thread = None
                            ACTIVE_SOCKETS.exclusive_socket = pair
                            operation.on_ack(pair, stack)
                        case ActionCodes.INFO:
                            Messages.send_info_message(local_message=message[MessageFields.MESSAGE])
                        case action if action == operation.response_code:
                            operation.on_response(message, pair)
                            cls._send_go_or_fail(pair, operation.config)
                            operation.execute()
                            sys.exit(0)
