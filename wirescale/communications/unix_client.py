#!/usr/bin/env python3
# encoding:utf-8


import json
import sys

from websockets import ConnectionClosedOK
from websockets.sync.client import unix_connect

from wirescale.communications.common import SOCKET_PATH
from wirescale.communications.messages import ActionCodes, ErrorCodes, ErrorMessages, MessageFields, Messages, UnixMessages
from wirescale.parsers.args import ARGS
from wirescale.vpn.recover import RecoverConfig


class UnixClient:

    @classmethod
    def connect(cls):
        try:
            print(Messages.CONNECTING_UNIX, flush=True)
            ARGS.PAIR.unix_socket = unix_connect(path=str(SOCKET_PATH))
            print(Messages.CONNECTED_UNIX, flush=True)
        except:
            print(ErrorMessages.UNIX_SOCKET, file=sys.stderr, flush=True)
            sys.exit(2)

    @classmethod
    def stop(cls):
        cls.connect()
        with ARGS.PAIR.local_socket:
            ARGS.PAIR.send_to_local(json.dumps(UnixMessages.STOP_MESSAGE))
            try:
                message: dict = json.loads(ARGS.PAIR.local_socket.recv(timeout=40))
                if message[MessageFields.ERROR_CODE] == ErrorCodes.CLOSED:
                    print(message[MessageFields.ERROR_MESSAGE], file=sys.stderr, flush=True)
                    sys.exit(1)
            except TimeoutError:
                print('Error: The UNIX server is not responding to the stop request', file=sys.stderr, flush=True)
                sys.exit(1)
            except ConnectionClosedOK:
                print('Connection has been successfully closed', flush=True)

    @classmethod
    def upgrade(cls):
        cls.connect()
        pair = ARGS.PAIR
        with pair.local_socket:
            message: dict = UnixMessages.build_upgrade_option()
            pair.send_to_local(json.dumps(message))
            for message in pair.local_socket:
                message = json.loads(message)
                ErrorMessages.process_error_message(message)
                match message[MessageFields.CODE]:
                    case ActionCodes.INFO:
                        print(message[MessageFields.MESSAGE], flush=True)
                    case ActionCodes.SUCCESS:
                        print(message[MessageFields.MESSAGE], flush=True)
                        pair.close_sockets()
                        sys.exit(0)

    @classmethod
    def recover(cls):
        recover = RecoverConfig.create_from_autoremove(interface=ARGS.INTERFACE, latest_handshake=ARGS.LATEST_HANDSHAKE)
        cls.connect()
        pair = ARGS.PAIR
        with pair.local_socket:
            message: dict = UnixMessages.build_recover(recover)
            pair.send_to_local(json.dumps(message))
            for message in pair.local_socket:
                message = json.loads(message)
                ErrorMessages.process_error_message(message)
                match message[MessageFields.CODE]:
                    case ActionCodes.INFO:
                        print(message[MessageFields.MESSAGE], flush=True)
                    case ActionCodes.SUCCESS:
                        print(message[MessageFields.MESSAGE], flush=True)
                        pair.close_sockets()
                        sys.exit(0)
