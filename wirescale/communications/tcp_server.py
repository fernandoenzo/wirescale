#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from ipaddress import ip_address, IPv4Address
from threading import get_ident

from parallel_utils.thread import StaticMonitor
from websockets.sync.server import serve, ServerConnection, WebSocketServer

from wirescale.communications import ActionCodes, ErrorMessages, MessageFields, Messages, TCPMessages
from wirescale.communications import SHUTDOWN
from wirescale.communications.checkers import check_addresses_in_allowedips, check_configfile, check_interface, check_wgconfig, match_psk, match_pubkeys
from wirescale.communications.common import CONNECTION_PAIRS, file_locker, TCP_PORT
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
        with websocket:
            pair = ConnectionPair(caller=IPv4Address(websocket.remote_address[0]), receiver=TSManager.my_ip())
            pair.tcp_socket = websocket
            try:
                cls.discard_connections()
                enqueueing = Messages.ENQUEUEING_FROM.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                enqueueing_remote = Messages.ENQUEUEING_REMOTE.format(sender_name=pair.my_name, sender_ip=pair.my_ip)
                Messages.send_info_message(local_message=enqueueing, remote_message=enqueueing_remote)
                with StaticMonitor.synchronized(uid=ActionCodes.UPGRADE), websocket:
                    cls.discard_connections()
                    start_processing = Messages.START_PROCESSING_FROM.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                    start_processing_remote = Messages.START_PROCESSING_REMOTE.format(sender_name=pair.my_name, sender_ip=pair.my_ip)
                    message: dict = json.loads(pair.remote_socket.recv())
                    match message[MessageFields.CODE]:
                        case ActionCodes.UPGRADE:
                            Messages.send_info_message(local_message=start_processing.format(action='upgrade'), remote_message=start_processing_remote.format(action='upgrade'))
                            cls.upgrade(message)
                        case ActionCodes.RECOVER:
                            Messages.send_info_message(local_message=start_processing.format(action='recover'), remote_message=start_processing_remote.format(action='recover'))
                            cls.recover(message)

            finally:
                CONNECTION_PAIRS.pop(get_ident(), None)

    @staticmethod
    def discard_connections():
        if SHUTDOWN.is_set():
            pair = CONNECTION_PAIRS[get_ident()]
            remote_error = ErrorMessages.REMOTE_CLOSED.format(my_name=pair.my_name, my_ip=pair.my_ip)
            ErrorMessages.send_error_message(remote_message=remote_error)

    @classmethod
    def upgrade(cls, message: dict):
        pair = CONNECTION_PAIRS[get_ident()]
        interface = check_interface(interface=pair.peer_name, suffix=ARGS.SUFFIX)
        config = check_configfile(config=f'/etc/wirescale/{pair.peer_name}.conf')
        wgconfig = check_wgconfig(config, interface)
        wgconfig.autoremove = ARGS.AUTOREMOVE
        with file_locker():
            wgconfig.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        wgconfig.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
        wgconfig.remote_local_port = message[MessageFields.PORT]
        wgconfig.remote_interface = message[MessageFields.INTERFACE]
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
                    case ActionCodes.INFO:
                        print(message[MessageFields.MESSAGE], flush=True)
                    case ActionCodes.GO:
                        wgquick = wgconfig.upgrade()
                        pair.remote_socket.close()
                        sys.exit(wgquick.returncode)

    @classmethod
    def recover(cls, message: dict):
        pair = CONNECTION_PAIRS[get_ident()]
        recover = TCPMessages.process_recover(message)
        with file_locker():
            recover.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        pair.remote_socket.send(json.dumps(TCPMessages.build_go()))
        recover.recover()
        pair.remote_socket.close()
        sys.exit(0)
