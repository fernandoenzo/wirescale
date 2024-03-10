#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from ipaddress import IPv4Address, ip_address
from threading import get_ident

from websockets.sync.client import ClientConnection, connect

from wirescale.communications import ErrorMessages, ErrorCodes
from wirescale.communications.checkers import match_pubkeys, check_addresses_in_allowedips, send_error
from wirescale.communications.common import TCP_PORT, CONNECTION_PAIRS
from wirescale.communications.messages import TCPMessages, ActionCodes, MessageFields, UnixMessages
from wirescale.vpn.wgconfig import WGConfig


class TCPClient:
    CLIENT: ClientConnection = None

    @classmethod
    def connect(cls, uri: IPv4Address):
        if cls.CLIENT is None:
            cls.CLIENT = connect(uri=f'ws://{uri}:{TCP_PORT}')

    @classmethod
    def upgrade(cls, wgconfig: WGConfig):
        pair = CONNECTION_PAIRS[get_ident()]
        try:
            cls.connect(uri=pair.peer_ip)
        except ConnectionRefusedError:
            error = ErrorMessages.REMOTE_MISSING_WIRESCALE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            print(error, file=sys.stderr, flush=True)
            send_error(pair.local_socket, message=error, error_code=ErrorCodes.REMOTE_MISSING_WIRESCALE)
        pair.tcp_socket = cls.CLIENT
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
                        case ActionCodes.UPGRADE_RESPONSE:
                            match_pubkeys(wgconfig, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=None)
                            wgconfig.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
                            check_addresses_in_allowedips(wgconfig)
                            wgconfig.generate_new_config()
                            pair.remote_socket.send(json.dumps(TCPMessages.build_upgrade_go()))
                            wgquick = wgconfig.upgrade()
                            pair.local_socket.send(json.dumps(UnixMessages.build_upgrade_go(wgquick)))
                            pair.remote_socket.close()
                            pair.local_socket.close()
                            sys.exit(wgquick.returncode)
