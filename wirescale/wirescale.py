#!/usr/bin/env python3
# encoding:utf-8

import os
import shutil
import subprocess
import sys
from pathlib import Path

from parallel_utils.thread import create_thread

from wirescale.__main__ import SCRIPT_PATH
from wirescale.communications.messages import ErrorMessages
from wirescale.communications.systemd import Systemd
from wirescale.communications.tcp_server import TCPServer
from wirescale.communications.udp_server import UDPServer
from wirescale.communications.unix_client import UnixClient
from wirescale.communications.unix_server import UnixServer
from wirescale.parsers import top_parser
from wirescale.parsers.args import ARGS, parse_args
from wirescale.vpn.watch import ACTIVE_SOCKETS

sys.tracebacklimit = 0

os.umask(0o177)  # chmod 600


def check_root(systemd=False):
    try:
        os.setuid(0)
    except PermissionError:
        if systemd:
            print(ErrorMessages.ROOT_SYSTEMD, file=sys.stderr, flush=True)
        else:
            print(ErrorMessages.SUDO, file=sys.stderr, flush=True)
        sys.exit(1)


def copy_script():
    script_file = Path('/run/wirescale/wirescale-autoremove')
    script_file.unlink(missing_ok=True)
    shutil.copy(SCRIPT_PATH.joinpath('wirescale-autoremove'), script_file)
    script_file.chmod(0o744)


def main():
    parse_args()
    if ARGS.DAEMON:
        check_root(systemd=True)
        unit = 'wirescaled.service'
        systemd_exec_pid = int(os.environ.get('SYSTEMD_EXEC_PID', default=-1))
        if ARGS.START:
            if systemd_exec_pid == -1 or os.getpgid(systemd_exec_pid) != os.getpgid(os.getpid()):
                systemd = subprocess.run(['systemctl', 'start', unit], text=True)
                sys.exit(systemd.returncode)
            systemd_envvars = ('LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES')
            if next((True for e in systemd_envvars if e not in os.environ), False):
                print('Error: Wirescale needs a UNIX socket supplied by systemd', file=sys.stderr, flush=True)
                sys.exit(1)
            copy_script()
            UDPServer.occupy_port_41641()
            tcp_thread = create_thread(TCPServer.run_server)
            unix_thread = create_thread(UnixServer.run_server)
            watch_thread = create_thread(ACTIVE_SOCKETS.watch)
            tcp_thread.result(), unix_thread.result(), watch_thread.result()
        elif ARGS.STOP:
            if systemd_exec_pid == -1 or os.getpgid(systemd_exec_pid) != os.getpgid(os.getpid()):
                if Systemd.is_active(unit):
                    systemd = subprocess.run(['systemctl', 'stop', 'wirescaled.service'], text=True)
                    sys.exit(systemd.returncode)
                sys.exit(0)
            UnixClient.stop()
    elif ARGS.UPGRADE:
        UnixClient.upgrade()
    elif ARGS.RECOVER:
        check_root()
        main_pid = subprocess.run(['systemctl', 'show', '-p', 'MainPID', f'autoremove-{ARGS.INTERFACE}.service'], capture_output=True, text=True).stdout.strip()
        main_pid = int(main_pid.replace('MainPID=', ''))
        systemd_exec_pid = int(os.environ.get('SYSTEMD_EXEC_PID', default=-1))
        if main_pid == 0 or systemd_exec_pid == -1 or main_pid != os.getpgid(os.getpid()) or os.getpgid(systemd_exec_pid) != os.getpgid(os.getpid()):
            ErrorMessages.send_error_message(local_message=ErrorMessages.RECOVER_SYSTEMD)
        UnixClient.recover()
    elif ARGS.DOWN:
        subprocess.run(['wg-quick', 'down', str(ARGS.CONFIGFILE)], text=True)
    else:
        top_parser.print_help()
