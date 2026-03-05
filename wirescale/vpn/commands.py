#!/usr/bin/env python3
# encoding:utf-8


import subprocess
from pathlib import Path
from subprocess import CompletedProcess, DEVNULL, PIPE, STDOUT
from typing import List

from wirescale.communications.common import subprocess_run_tmpfile

_SILENT = dict(stdout=DEVNULL, stderr=DEVNULL)
_CAPTURE = dict(stdout=PIPE, stderr=DEVNULL, text=True)


# --- wg commands ---

def wg_show(interface: str, field: str) -> str:
    return subprocess.run(['wg', 'show', interface, field], **_CAPTURE).stdout.strip()


def wg_show_rc(interface: str, field: str) -> int:
    return subprocess.run(['wg', 'show', interface, field], **_SILENT).returncode


def wg_set(interface: str, *args: str) -> None:
    subprocess.run(['wg', 'set', interface, *args], **_SILENT)


def wg_genkey() -> str:
    return subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()


def wg_pubkey(privkey: str) -> str:
    return subprocess.run(['wg', 'pubkey'], input=privkey, capture_output=True, text=True).stdout.strip()


def wg_genpsk() -> str:
    return subprocess.run(['wg', 'genpsk'], capture_output=True, text=True).stdout.strip()


# --- wg-quick commands ---

def wg_quick_up(config_path: Path) -> CompletedProcess:
    return subprocess_run_tmpfile(['wg-quick', 'up', str(config_path)], stderr=STDOUT)


def wg_quick_up_test(config_path: Path) -> CompletedProcess:
    return subprocess.run(['wg-quick', 'up', str(config_path)], capture_output=True, text=True)


def wg_quick_down(config_path: Path, silent: bool = True) -> None:
    if silent:
        subprocess.run(['wg-quick', 'down', str(config_path)], **_SILENT)
    else:
        subprocess.run(['wg-quick', 'down', str(config_path)], text=True)


# --- iptables commands ---

def iptables_run(args: List[str]) -> None:
    subprocess.run(args, **_SILENT)


# --- ip commands ---

def ip_addr_show_json() -> CompletedProcess:
    return subprocess.run(['ip', '-j', 'addr', 'show'], capture_output=True, text=True)


def ip_run(*args: str) -> None:
    subprocess.run(['ip', *args], **_SILENT)


# --- sysctl commands ---

def sysctl_set(key: str, value: str) -> None:
    subprocess.run(['sysctl', '-w', f'{key}={value}'], **_SILENT)
