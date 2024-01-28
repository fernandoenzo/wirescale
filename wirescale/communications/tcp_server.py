#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from contextlib import ExitStack
from ipaddress import IPv4Address, ip_address

from parallel_utils.thread import StaticMonitor
from websockets.sync.server import ServerConnection, serve, WebSocketServer

from wirescale.communications import ErrorCodes, ActionCodes, ErrorMessages, TCPMessages, MessageFields
from wirescale.communications import SHUTDOWN
from wirescale.communications.checkers import send_error, check_configfile, check_interface, check_wgconfig, match_pubkeys, match_psk, check_addresses_in_allowedips
from wirescale.communications.common import TCP_PORT
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
        with ExitStack() as stack:
            stack.enter_context(cls.SERVER)
            cls.SERVER.serve_forever()

    @classmethod
    def handler(cls, websocket: ServerConnection):
        pair = ConnectionPair(caller=IPv4Address(websocket.remote_address[0]), receiver=TSManager.my_ip())
        pair.tcp_socket = websocket
        if SHUTDOWN.is_set():
            remote_error = ErrorMessages.REMOTE_CLOSED.format(my_name=pair.my_name, my_ip=pair.my_ip)
            send_error(pair.remote_socket, remote_error, ErrorCodes.REMOTE_CLOSED)
        message: dict = json.loads(pair.remote_socket.recv())
        if message[MessageFields.CODE] == ActionCodes.UPGRADE:
            with StaticMonitor.synchronized(uid=ActionCodes.UPGRADE_RESPONSE):
                cls.upgrade(pair, message)

    @classmethod
    def upgrade(cls, pair: ConnectionPair, message: dict):
        interface = check_interface(pair, interface=pair.peer_name, suffix=ARGS.SUFFIX)
        config = check_configfile(pair, config=f'/etc/wirescale/{pair.peer_name}.conf')
        wgconfig = check_wgconfig(pair, config)
        wgconfig.autoremove = True
        wgconfig.interface = interface
        wgconfig.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        wgconfig.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
        match_pubkeys(pair, wgconfig, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=message[MessageFields.REMOTE_PUBKEY])
        match_psk(pair, wgconfig, remote_has_psk=message[MessageFields.HAS_PSK], remote_psk=message[MessageFields.PSK])
        check_addresses_in_allowedips(pair, wgconfig)
        wgconfig.generate_new_config()
        upgrade_response = TCPMessages.build_upgrade_response(wgconfig)
        pair.remote_socket.send(json.dumps(upgrade_response))
        for message in pair.remote_socket:
            message = json.loads(message)
            if message[MessageFields.ERROR_CODE]:
                print(message[MessageFields.ERROR_MESSAGE], file=sys.stderr, flush=True)
                sys.exit(1)
            elif code := message[MessageFields.CODE]:
                match code:
                    case ActionCodes.UPGRADE_GO:
                        wgquick = wgconfig.upgrade()
                        pair.remote_socket.close()
                        sys.exit(wgquick.returncode)
