#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from contextlib import ExitStack
from ipaddress import ip_address, IPv4Address
from threading import get_ident

from parallel_utils.thread import StaticMonitor
from websockets.sync.server import serve, ServerConnection, WebSocketServer

from wirescale.communications.checkers import check_addresses_in_allowedips, check_behind_nat, check_configfile, check_interface, check_wgconfig, match_psk, match_pubkeys, test_wgconfig
from wirescale.communications.common import CONNECTION_PAIRS, file_locker, Semaphores, SHUTDOWN, TCP_PORT
from wirescale.communications.connection_pair import ConnectionPair
from wirescale.communications.messages import ActionCodes, ErrorMessages, MessageFields, Messages, TCPMessages
from wirescale.parsers.args import ARGS
from wirescale.vpn.tsmanager import TSManager
from wirescale.vpn.watch import ACTIVE_SOCKETS


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
                message_token = json.loads(pair.tcp_socket.recv())
                pair.token = message_token[MessageFields.TOKEN]
                cls.discard_connections()
                enqueueing = Messages.ENQUEUEING_FROM.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                enqueueing_remote = Messages.ENQUEUEING_REMOTE.format(sender_name=pair.my_name, sender_ip=pair.my_ip)
                Messages.send_info_message(local_message=enqueueing, remote_message=enqueueing_remote)
                Messages.process_version(message_token)
                with ExitStack() as stack:
                    stack.enter_context(StaticMonitor.synchronized(uid=Semaphores.SERVER))
                    cls.discard_connections()
                    next_message = Messages.NEXT_INCOMING.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                    Messages.send_info_message(local_message=next_message)
                    ACTIVE_SOCKETS.server_thread = get_ident()
                    ACTIVE_SOCKETS.waiter_switched.wait()
                    stack.enter_context(StaticMonitor.synchronized(uid=Semaphores.EXCLUSIVE))
                    cls.discard_connections()
                    ACTIVE_SOCKETS.exclusive_socket = pair
                    ACTIVE_SOCKETS.waiter_server_switched.set()
                    exclusive_message = Messages.EXCLUSIVE_SEMAPHORE_REMOTE.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                    Messages.send_info_message(local_message=exclusive_message)
                    stack.enter_context(StaticMonitor.synchronized(uid=Semaphores.WAIT_IF_SWITCHED))
                    ACTIVE_SOCKETS.server_thread = None
                    cls.discard_connections()
                    ACTIVE_SOCKETS.exclusive_socket = pair
                    start_processing = Messages.START_PROCESSING_FROM.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
                    start_processing_remote = Messages.START_PROCESSING_REMOTE.format(sender_name=pair.my_name, sender_ip=pair.my_ip)
                    for message in pair:
                        message = json.loads(message)
                        match message[MessageFields.CODE]:
                            case ActionCodes.HELLO:
                                TCPMessages.send_ack()
                            case ActionCodes.UPGRADE:
                                Messages.send_info_message(local_message=start_processing.format(action='upgrade'), remote_message=start_processing_remote.format(action='upgrade'))
                                cls.upgrade(message)
                            case ActionCodes.RECOVER:
                                interface = message[MessageFields.INTERFACE]
                                start_processing = start_processing.format(action='recover') + f" for interface '{interface}'"
                                start_processing_remote = start_processing_remote.format(action='recover') + f" for their local interface '{interface}'"
                                Messages.send_info_message(local_message=start_processing, remote_message=start_processing_remote)
                                cls.recover(message)

            finally:
                pair.close_sockets()
                Messages.send_info_message(local_message=Messages.END_SESSION)
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
        config = check_configfile()
        wgconfig = check_wgconfig(config)
        wgconfig.interface = wgconfig.interface or pair.peer_name
        wgconfig.allow_suffix = wgconfig.allow_suffix if wgconfig.allow_suffix is not None else ARGS.ALLOW_SUFFIX if ARGS.ALLOW_SUFFIX is not None else False
        wgconfig.interface, wgconfig.suffix = check_interface(interface=wgconfig.interface, allow_suffix=wgconfig.allow_suffix)
        expected_interface = message[MessageFields.EXPECTED_INTERFACE]
        if expected_interface is not None and wgconfig.interface != expected_interface:
            error = ErrorMessages.INTERFACE_MISMATCH.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            remote_error = ErrorMessages.REMOTE_INTERFACE_MISMATCH.format(my_name=pair.my_name, my_ip=pair.my_ip, interface=expected_interface)
            ErrorMessages.send_error_message(local_message=error, remote_message=remote_error)
        test_wgconfig(wgconfig)
        wgconfig.iptables = wgconfig.iptables if wgconfig.iptables is not None else ARGS.IPTABLES if ARGS.IPTABLES is not None else False
        with file_locker():
            wgconfig.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        wgconfig.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
        wgconfig.remote_local_port = message[MessageFields.PORT]
        wgconfig.remote_interface = message[MessageFields.INTERFACE]
        match_pubkeys(wgconfig, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=message[MessageFields.REMOTE_PUBKEY])
        match_psk(wgconfig, remote_has_psk=message[MessageFields.HAS_PSK], remote_psk=message[MessageFields.PSK])
        check_addresses_in_allowedips(wgconfig)
        wgconfig.generate_new_config()
        wgconfig.nat = check_behind_nat(IPv4Address(message[MessageFields.PUBLIC_IP]))
        wgconfig.recover_tries = wgconfig.recover_tries if wgconfig.recover_tries is not None else ARGS.RECOVER_TRIES if ARGS.RECOVER_TRIES is not None else 3
        wgconfig.recreate_tries = wgconfig.recreate_tries if wgconfig.recreate_tries is not None else ARGS.RECREATE_TRIES if ARGS.RECREATE_TRIES is not None else 0
        TCPMessages.send_upgrade_response(wgconfig)
        for message in pair:
            message = json.loads(message)
            ErrorMessages.process_error_message(message)
            match message[MessageFields.CODE]:
                case ActionCodes.INFO:
                    print(message[MessageFields.MESSAGE], flush=True)
                case ActionCodes.GO:
                    wgconfig.nat = message[MessageFields.NAT]
                    wgconfig.upgrade()
                    sys.exit(0)

    @classmethod
    def recover(cls, message: dict):
        pair = CONNECTION_PAIRS[get_ident()]
        recover = TCPMessages.process_recover(message)
        TCPMessages.send_recover_response(recover)
        for message in pair:
            message = json.loads(message)
            ErrorMessages.process_error_message(message)
            match message[MessageFields.CODE]:
                case ActionCodes.INFO:
                    print(message[MessageFields.MESSAGE], flush=True)
                case ActionCodes.GO:
                    recover.nat = message[MessageFields.NAT]
                    recover.recover()
                    sys.exit(0)
