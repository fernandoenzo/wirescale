# encoding:utf-8


import base64
import collections
import fcntl
import subprocess
from contextlib import contextmanager, ExitStack
from enum import auto, IntEnum
from pathlib import Path
from tempfile import TemporaryFile
from threading import Event
from time import sleep
from typing import Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from wirescale.communications.connection_pair import ConnectionPair

CONNECTION_PAIRS: Dict[int, 'ConnectionPair'] = {}
SHUTDOWN = Event()
SOCKET_PATH = Path('/run/wirescale/wirescaled.sock').resolve()
TCP_PORT = 41642


class Semaphores(IntEnum):
    CLIENT = auto()
    EXCLUSIVE = auto()
    SERVER = auto()
    WAIT_IF_SWITCHED = auto()


def check_with_timeout(func, timeout, sleep_time=0.5, *args, **kwargs) -> bool:
    while not (check := func(*args, **kwargs)) and timeout > 0:
        timeout -= sleep_time
        sleep(0.5)
    return check


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
