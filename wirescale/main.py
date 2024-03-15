#!/usr/bin/env python3
# encoding:utf-8


import os
import subprocess
import sys

from parallel_utils.thread import create_thread

from wirescale.communications import TCPServer, UnixClient, UnixServer
from wirescale.parsers import ARGS, parse_args, top_parser

sys.tracebacklimit = 0

os.umask(0o177)  # chmod 600


def main():
    parse_args()
    if ARGS.DAEMON:
        systemd_exec_pid = int(os.environ.get('SYSTEMD_EXEC_PID', default=-1))
        if os.geteuid() != 0 or systemd_exec_pid is None or os.getpgid(systemd_exec_pid) != os.getpgid(os.getpid()):
            print('Error: Wirescale daemon must be launched as root via systemd', file=sys.stderr, flush=True)
            sys.exit(1)
        if ARGS.START:
            systemd_envvars = ('LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES')
            if next((True for e in systemd_envvars if e not in os.environ), False):
                print('Error: Wirescale needs a UNIX socket supplied by systemd', file=sys.stderr, flush=True)
                sys.exit(1)
            create_thread(TCPServer.run_server)
            create_thread(UnixServer.run_server)
        elif ARGS.STOP:
            UnixClient.stop()
    elif ARGS.UPGRADE:
        UnixClient.upgrade()
    elif ARGS.DOWN:
        subprocess.run(['wg-quick', 'down', str(ARGS.CONFIGFILE)], text=True)
    else:
        top_parser.print_help()
