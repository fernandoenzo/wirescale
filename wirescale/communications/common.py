# encoding:utf-8


import base64
import collections
import fcntl
import subprocess
from contextlib import contextmanager, ExitStack
from enum import auto, IntEnum
from ipaddress import IPv4Address
from pathlib import Path
from tempfile import TemporaryFile
from threading import Event
from time import sleep
from typing import Dict, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from wirescale.communications.connection_pair import ConnectionPair
    from wirescale.vpn.recover import RecoverConfig
    from wirescale.vpn.wgconfig import WGConfig

CONNECTION_PAIRS: Dict[int, 'ConnectionPair'] = {}
SHUTDOWN = Event()
SOCKET_PATH = Path('/run/wirescale/wirescaled.sock').resolve()
TCP_PORT = 41642


class Semaphores(IntEnum):
    CLIENT = auto()
    EXCLUSIVE = auto()
    SERVER = auto()
    WAIT_IF_SWITCHED = auto()


def subprocess_run_tmpfile(*args, **kwargs) -> subprocess.CompletedProcess[str]:
    kwargs['encoding'] = kwargs.get('encoding', 'utf-8')
    collections.deque((kwargs.pop(field, None) for field in ('capture_output', 'text', 'universal_newlines')), maxlen=0)
    streams = ('stdout', 'stderr')
    streams_are_set = {stream: kwargs.get(stream, None) is not None for stream in streams}
    with ExitStack() as stack:
        kwargs.update({stream: kwargs[stream] if streams_are_set[stream] else stack.enter_context(TemporaryFile(mode='w+', encoding=kwargs['encoding'])) for stream in streams})
        p = subprocess.run(*args, **kwargs)
        p.stdout, p.stderr = ((kwargs[stream].flush(), kwargs[stream].seek(0), kwargs[stream].read())[2] if not streams_are_set[stream] else getattr(p, stream) for stream in streams)
    return p


class BytesStrConverter:

    @classmethod
    def raw_bytes_to_str64(cls, data: bytes) -> str:
        data = base64.urlsafe_b64encode(data)
        return cls.bytes_to_str(data)

    @classmethod
    def str64_to_raw_bytes(cls, data: str) -> bytes:
        data = cls.str_to_bytes(data)
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def str_to_bytes(data: str) -> bytes:
        return data.encode('utf-8')

    @staticmethod
    def bytes_to_str(data: bytes) -> str:
        return data.decode('utf-8')


@contextmanager
def file_locker():
    lockfile = Path('/run/wirescale/control/locker').open(mode='w')
    fcntl.flock(lockfile, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(lockfile, fcntl.LOCK_UN)
        lockfile.close()


def systemd_autoremove(config: Union['WGConfig', 'RecoverConfig'], pair: 'ConnectionPair'):
    from wirescale.communications.messages import Messages
    unit = f'autoremove-{config.interface}.service'
    tries, is_active = 20, 0
    while is_active == 0 and tries > 0:
        is_active = subprocess.run(['systemctl', 'is-active', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
        tries -= 1
        sleep(1)
    subprocess.run(['systemctl', 'stop', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['systemctl', 'reset-failed', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    remote_pubkey: str = config.remote_pubkey_str if hasattr(config, 'remote_pubkey_str') else config.remote_pubkey
    wg_ip: IPv4Address = config.wg_ip if hasattr(config, 'wg_ip') else next(ip for ip in config.remote_addresses)
    running_in_remote: bool = config.running_in_remote if hasattr(config, 'running_in_remote') else pair.running_in_remote
    listen_port: int = config.new_port if hasattr(config, 'new_port') else config.listen_port
    config_file: Path = config.config_file if hasattr(config, 'config_file') else config.file_path

    args = [config.interface, str(pair.peer_ip), remote_pubkey, str(wg_ip), str(int(running_in_remote)), str(config.start_time), str(listen_port), str(int(config.nat)),
            config.remote_interface, str(config.remote_local_port), str(int(config.iptables)), config_file.as_uri()]

    systemd = subprocess.run(['systemd-run', '-u', unit, '/bin/sh', '/run/wirescale/wirescale-autoremove', 'autoremove', *args],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    Messages.send_info_message(local_message=f'Launching autoremove subprocess. {systemd.stdout.strip()}')
