#!/usr/bin/env python3
# encoding:utf-8


import json
import sys
from argparse import ArgumentError

from websockets import ConnectionClosedOK
from websockets.sync.client import ClientConnection, unix_connect

from wirescale.communications import UnixMessages, ErrorCodes, MessageFields, ActionCodes, ErrorMessages
from wirescale.communications.common import SOCKET_PATH
from wirescale.parsers import upgrade_subparser, ARGS
from wirescale.parsers.parsers import config_argument, interface_argument


class UnixClient:
    CLIENT: ClientConnection = None

    @classmethod
    def connect(cls):
        if cls.CLIENT is None:
            cls.CLIENT = unix_connect(path=str(SOCKET_PATH))

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
        try:
            cls.connect()
        except:
            print(ErrorMessages.UNIX_SOCKET, file=sys.stderr, flush=True)
            sys.exit(1)
        with cls.CLIENT:
            message: dict = UnixMessages.build_upgrade(ARGS)
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
                        case _:
                            print(error, file=sys.stderr, flush=True)
                            sys.exit(1)
                elif code := message[MessageFields.CODE]:
                    match code:
                        case ActionCodes.UPGRADE_GO:
                            print(f"Success! Now you have a new working P2P connection through interface {ARGS.INTERFACE}", flush=True)
                            cls.CLIENT.close()
                            sys.exit(0)
