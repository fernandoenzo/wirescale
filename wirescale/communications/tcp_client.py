#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from ipaddress import IPv4Address, ip_address
from threading import get_ident

from websockets.sync.client import ClientConnection, connect

from wirescale.communications import ErrorCodes, ErrorMessages
from wirescale.communications.checkers import check_addresses_in_allowedips, match_pubkeys
from wirescale.communications.common import CONNECTION_PAIRS, TCP_PORT
from wirescale.communications.messages import ActionCodes, MessageFields, TCPMessages, UnixMessages
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
            print(error, file=sys.stderr, flush=True)
            ErrorMessages.send_error_message(pair.local_socket, error_message=error, error_code=ErrorCodes.REMOTE_MISSING_WIRESCALE)
        with pair.remote_socket:
            upgrade_message = TCPMessages.build_upgrade(wgconfig)
            pair.remote_socket.send(json.dumps(upgrade_message))
            for message in pair.remote_socket:
                message = json.loads(message)
                if message[MessageFields.ERROR_CODE]:
                    pair.remote_socket.close()
                    print(message[MessageFields.ERROR_MESSAGE], file=sys.stderr, flush=True)
                    pair.local_socket.send(json.dumps(message))
                    sys.exit(1)
                elif code := message[MessageFields.CODE]:
                    match code:
                        case ActionCodes.INFO:
                            print(message[MessageFields.MESSAGE], flush=True)
                            pair.local_socket.send(json.dumps(message))
                        case ActionCodes.UPGRADE_RESPONSE:
                            match_pubkeys(wgconfig, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=None)
                            wgconfig.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
                            check_addresses_in_allowedips(wgconfig)
                            wgconfig.generate_new_config()
                            pair.remote_socket.send(json.dumps(TCPMessages.build_upgrade_go()))
                            wgquick = wgconfig.upgrade()
                            pair.local_socket.send(json.dumps(UnixMessages.build_upgrade_result(wgquick, wgconfig.interface)))
                            pair.remote_socket.close()
                            pair.local_socket.close()
                            sys.exit(wgquick.returncode)
