#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from argparse import ArgumentError

from websockets import ConnectionClosedOK
from websockets.sync.client import ClientConnection, unix_connect

from wirescale.communications import ActionCodes, ErrorCodes, ErrorMessages, MessageFields, Messages, UnixMessages
from wirescale.communications.common import SOCKET_PATH
from wirescale.parsers import ARGS, upgrade_subparser
from wirescale.parsers.parsers import config_argument, interface_argument


class UnixClient:
    CLIENT: ClientConnection = None

    @classmethod
    def connect(cls):
        if cls.CLIENT is None:
            try:
                print(Messages.CONNECTING_UNIX, flush=True)
                cls.CLIENT = unix_connect(path=str(SOCKET_PATH))
                print(Messages.CONNECTED_UNIX, flush=True)
            except:
                print(ErrorMessages.UNIX_SOCKET, file=sys.stderr, flush=True)
                sys.exit(1)

    @classmethod
    def stop(cls):
        cls.connect()
        with cls.CLIENT:
            cls.CLIENT.send(json.dumps(UnixMessages.STOP_MESSAGE))
            try:
                message: dict = json.loads(cls.CLIENT.recv(timeout=40))
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
        with cls.CLIENT:
            message: dict = UnixMessages.build_upgrade_option(ARGS)
            cls.CLIENT.send(json.dumps(message))
            for message in cls.CLIENT:
                message = json.loads(message)
                if error_code := message[MessageFields.ERROR_CODE]:
                    cls.CLIENT.close()
                    error = message[MessageFields.ERROR_MESSAGE]
                    match error_code:
                        case ErrorCodes.INTERFACE_EXISTS:
                            upgrade_subparser.error(str(ArgumentError(interface_argument, error)))
                        case ErrorCodes.CONFIG_PATH_ERROR:
                            upgrade_subparser.error(str(ArgumentError(config_argument, error)))
                        case ErrorCodes.FINAL_ERROR:
                            print(error, file=sys.stderr, flush=True)
                            print(ErrorMessages.FINAL_ERROR, file=sys.stderr, flush=True)
                            sys.exit(1)
                        case _:
                            print(error, file=sys.stderr, flush=True)
                            sys.exit(1)
                elif code := message[MessageFields.CODE]:
                    match code:
                        case ActionCodes.INFO:
                            print(message[MessageFields.MESSAGE], flush=True)
                        case ActionCodes.SUCCESS:
                            print(Messages.SUCCESS.format(interface=message[MessageFields.INTERFACE]), flush=True)
                            cls.CLIENT.close()
                            sys.exit(0)
