#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from ipaddress import IPv4Address, ip_address
from threading import get_ident

from parallel_utils.thread import StaticMonitor
from websockets.sync.server import ServerConnection, serve, WebSocketServer

from wirescale.communications import ErrorCodes, ActionCodes, ErrorMessages, TCPMessages, MessageFields
from wirescale.communications import SHUTDOWN
from wirescale.communications.checkers import send_error, check_configfile, check_interface, check_wgconfig, match_pubkeys, match_psk, check_addresses_in_allowedips
from wirescale.communications.common import TCP_PORT, CONNECTION_PAIRS
from wirescale.parsers import ARGS
from wirescale.parsers.args import ConnectionPair
from wirescale.vpn import TSManager


class TCPServer:
    SERVER: WebSocketServer = None

    @classmethod
    def set_server(cls):
        if cls.SERVER is None:
            cls.SERVER = serve(cls.handler, str(TSManager.my_ip()), TCP_PORT)

    @classmethod
    def run_server(cls):
        cls.set_server()
        with cls.SERVER:
            cls.SERVER.serve_forever()

    @classmethod
    def handler(cls, websocket: ServerConnection):
        try:
            with websocket:
                pair = ConnectionPair(caller=IPv4Address(websocket.remote_address[0]), receiver=TSManager.my_ip())
                pair.tcp_socket = websocket
                if SHUTDOWN.is_set():
                    remote_error = ErrorMessages.REMOTE_CLOSED.format(my_name=pair.my_name, my_ip=pair.my_ip)
                    send_error(pair.remote_socket, remote_error, ErrorCodes.REMOTE_CLOSED)
                message: dict = json.loads(pair.remote_socket.recv())
                if message[MessageFields.CODE] == ActionCodes.UPGRADE:
                    with StaticMonitor.synchronized(uid=ActionCodes.UPGRADE):
                        cls.upgrade(message)
        finally:
            CONNECTION_PAIRS.pop(get_ident(), None)

    @classmethod
    def upgrade(cls, message: dict):
        pair = CONNECTION_PAIRS[get_ident()]
        interface = check_interface(interface=pair.peer_name, suffix=ARGS.SUFFIX)
        config = check_configfile(config=f'/etc/wirescale/{pair.peer_name}.conf')
        wgconfig = check_wgconfig(config)
        wgconfig.autoremove = True
        wgconfig.interface = interface
        wgconfig.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        wgconfig.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
        match_pubkeys(wgconfig, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=message[MessageFields.REMOTE_PUBKEY])
        match_psk(wgconfig, remote_has_psk=message[MessageFields.HAS_PSK], remote_psk=message[MessageFields.PSK])
        check_addresses_in_allowedips(wgconfig)
        wgconfig.generate_new_config()
        upgrade_response = TCPMessages.build_upgrade_response(wgconfig)
        pair.remote_socket.send(json.dumps(upgrade_response))
        for message in pair.remote_socket:
            message = json.loads(message)
            if message[MessageFields.ERROR_CODE]:
                print(message[MessageFields.ERROR_MESSAGE], file=sys.stderr, flush=True)
                pair.remote_socket.close()
                sys.exit(1)
            elif code := message[MessageFields.CODE]:
                match code:
                    case ActionCodes.UPGRADE_GO:
                        wgquick = wgconfig.upgrade()
                        pair.remote_socket.close()
                        sys.exit(wgquick.returncode)
