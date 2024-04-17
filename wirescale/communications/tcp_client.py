#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from ipaddress import ip_address, IPv4Address
from threading import get_ident

from websockets.sync.client import ClientConnection, connect

from wirescale.communications import ErrorMessages, Messages
from wirescale.communications.checkers import check_addresses_in_allowedips, match_pubkeys
from wirescale.communications.common import CONNECTION_PAIRS, TCP_PORT
from wirescale.communications.messages import ActionCodes, MessageFields, TCPMessages, UnixMessages
from wirescale.vpn.recover import RecoverConfig
from wirescale.vpn.wgconfig import WGConfig


class TCPClient:

    @staticmethod
    def connect(uri: IPv4Address) -> ClientConnection:
        return connect(uri=f'ws://{uri}:{TCP_PORT}')

    @classmethod
    def upgrade(cls, wgconfig: WGConfig):
        pair = CONNECTION_PAIRS[get_ident()]
        try:
            pair.tcp_socket = cls.connect(uri=pair.peer_ip)
        except ConnectionRefusedError:
            error = ErrorMessages.REMOTE_MISSING_WIRESCALE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            ErrorMessages.send_error_message(local_message=error)
        with pair.remote_socket:
            upgrade_message = TCPMessages.build_upgrade(wgconfig)
            pair.remote_socket.send(json.dumps(upgrade_message))
            for message in pair.remote_socket:
                message = json.loads(message)
                if error_code := message[MessageFields.ERROR_CODE]:
                    match error_code:
                        case _:
                            ErrorMessages.send_error_message(local_message=message[MessageFields.ERROR_MESSAGE], error_code=error_code)
                elif code := message[MessageFields.CODE]:
                    match code:
                        case ActionCodes.INFO:
                            Messages.send_info_message(local_message=message[MessageFields.MESSAGE])
                        case ActionCodes.UPGRADE_RESPONSE:
                            match_pubkeys(wgconfig, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=None)
                            wgconfig.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
                            check_addresses_in_allowedips(wgconfig)
                            wgconfig.start_time = message[MessageFields.START_TIME]
                            wgconfig.remote_local_port = message[MessageFields.PORT]
                            wgconfig.remote_interface = message[MessageFields.INTERFACE]
                            wgconfig.generate_new_config()
                            pair.remote_socket.send(json.dumps(TCPMessages.build_go()))
                            wgquick = wgconfig.upgrade()
                            pair.local_socket.send(json.dumps(UnixMessages.build_upgrade_result(wgquick, wgconfig.interface)))
                            pair.remote_socket.close()
                            pair.local_socket.close()
                            sys.exit(wgquick.returncode)

    @classmethod
    def recover(cls, recover: RecoverConfig):
        pair = CONNECTION_PAIRS[get_ident()]
        try:
            pair.tcp_socket = cls.connect(uri=pair.peer_ip)
        except ConnectionRefusedError:
            error = ErrorMessages.REMOTE_MISSING_WIRESCALE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            ErrorMessages.send_error_message(local_message=error)
        with pair.remote_socket:
            recover_message = TCPMessages.build_recover(recover)
            pair.remote_socket.send(json.dumps(recover_message))
            for message in pair.remote_socket:
                message = json.loads(message)
                if error_code := message[MessageFields.ERROR_CODE]:
                    match error_code:
                        case _:
                            ErrorMessages.send_error_message(local_message=message[MessageFields.ERROR_MESSAGE], error_code=error_code)
                elif code := message[MessageFields.CODE]:
                    match code:
                        case ActionCodes.INFO:
                            Messages.send_info_message(local_message=message[MessageFields.MESSAGE])
                        case ActionCodes.UPGRADE_RESPONSE:
                            match_pubkeys(wgconfig, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=None)
