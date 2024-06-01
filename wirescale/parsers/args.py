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
    START: bool = None
    STOP: bool = None
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
        ARGS.CONFIGFILE = args.get('config') if args.get('config') is not None and args.get('config').split() else f'/etc/wirescale/{ARGS.PAIR.peer_name}.conf'
        ARGS.INTERFACE = args.get('interface')
    if ARGS.RECOVER:
        ARGS.INTERFACE = args.get('interface')
        ARGS.LATEST_HANDSHAKE = get_latest_handshake(ARGS.INTERFACE)
    elif ARGS.DOWN:
        ARGS.CONFIGFILE = args.get('interface')
