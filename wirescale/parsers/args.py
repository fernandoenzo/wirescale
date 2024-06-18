#!/usr/bin/env python3
# encoding:utf-8


from pathlib import Path

from wirescale.communications.checkers import get_latest_handshake
from wirescale.communications.connection_pair import ConnectionPair
from wirescale.parsers import top_parser
from wirescale.vpn.tsmanager import TSManager


class ARGS:
    ALLOW_SUFFIX: bool = None
    CONFIGFILE: str = None
    DAEMON: bool = None
    DOWN: Path = None
    INTERFACE: str = None
    IPTABLES: bool = None
    LATEST_HANDSHAKE: int = None
    PAIR: ConnectionPair = None
    RECOVER: bool = None
    RECOVER_TRIES: int = None
    RECREATE_TRIES: int = None
    EXPECTED_INTERFACE: str = None
    START: bool = None
    STOP: bool = None
    SUFFIX_NUMBER: int = None
    UPGRADE: bool = None


def parse_args():
    args = vars(top_parser.parse_args())
    ARGS.DAEMON = args.get('opt') == 'daemon'
    ARGS.UPGRADE = args.get('opt') == 'upgrade'
    ARGS.DOWN = args.get('opt') == 'down'
    ARGS.RECOVER = args.get('opt') == 'recover'
    ARGS.START = args.get('command') == 'start'
    ARGS.STOP = args.get('command') == 'stop'
    ARGS.IPTABLES = args.get('iptables')
    ARGS.ALLOW_SUFFIX = args.get('suffix')
    if ARGS.UPGRADE:
        peer_ip = args.get('peer')
        ARGS.PAIR = ConnectionPair(caller=TSManager.my_ip(), receiver=peer_ip)
        ARGS.INTERFACE = args.get('interface')
        ARGS.EXPECTED_INTERFACE = args.get('remote_interface')
        ARGS.RECOVER_TRIES = args.get('recover_tries')
        ARGS.RECREATE_TRIES = args.get('recreate_tries')
        ARGS.SUFFIX_NUMBER = args.get('suffix_number')
        if ARGS.SUFFIX_NUMBER is not None:
            ARGS.ALLOW_SUFFIX = False
    if ARGS.RECOVER:
        ARGS.INTERFACE = args.get('interface')
        ARGS.LATEST_HANDSHAKE = get_latest_handshake(ARGS.INTERFACE)
    elif ARGS.DOWN:
        ARGS.CONFIGFILE = args.get('interface')
