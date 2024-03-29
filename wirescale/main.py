#!/usr/bin/env python3
# encoding:utf-8


import os
import shutil
import subprocess
import sys
from pathlib import Path

from parallel_utils.thread import create_thread

from wirescale.__main__ import SCRIPT_PATH
from wirescale.communications import ErrorMessages, TCPServer, UnixClient, UnixServer
from wirescale.parsers import ARGS, parse_args, top_parser

sys.tracebacklimit = 0

os.umask(0o177)  # chmod 600


def check_root():
    try:
        os.setuid(0)
    except PermissionError:
        print(ErrorMessages.ROOT_SYSTEMD, file=sys.stderr, flush=True)
        sys.exit(1)


def copy_script():
    script_file = Path('/run/wirescale/wirescale-autoremove')
    script_file.unlink(missing_ok=True)
    shutil.copy(SCRIPT_PATH.joinpath('wirescale-autoremove'), script_file)
    script_file.chmod(0o744)


def main():
    parse_args()
    if ARGS.DAEMON:
        check_root()
        systemd_exec_pid = int(os.environ.get('SYSTEMD_EXEC_PID', default=-1))
        if ARGS.START:
            if systemd_exec_pid == -1 or os.getpgid(systemd_exec_pid) != os.getpgid(os.getpid()):
                systemd = subprocess.run(['systemctl', 'start', 'wirescaled.service'], text=True)
                sys.exit(systemd.returncode)
            systemd_envvars = ('LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES')
            if next((True for e in systemd_envvars if e not in os.environ), False):
                print('Error: Wirescale needs a UNIX socket supplied by systemd', file=sys.stderr, flush=True)
                sys.exit(1)
            copy_script()
            create_thread(TCPServer.run_server)
            create_thread(UnixServer.run_server)
        elif ARGS.STOP:
            if systemd_exec_pid == -1 or os.getpgid(systemd_exec_pid) != os.getpgid(os.getpid()):
                systemd = subprocess.run(['systemctl', 'stop', 'wirescaled.service'], text=True)
                sys.exit(systemd.returncode)
            UnixClient.stop()
    elif ARGS.UPGRADE:
        UnixClient.upgrade()
    elif ARGS.DOWN:
        subprocess.run(['wg-quick', 'down', str(ARGS.CONFIGFILE)], text=True)
    else:
        top_parser.print_help()
