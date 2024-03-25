# encoding:utf-8


import collections
import fcntl
from contextlib import ExitStack, contextmanager
from pathlib import Path
from subprocess import CompletedProcess, run
from tempfile import TemporaryFile
from threading import Event
from typing import Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from wirescale.parsers.args import ConnectionPair

SHUTDOWN = Event()
TCP_PORT = 41642
SOCKET_PATH = Path('/run/wirescale/wirescaled.sock').resolve()
CONNECTION_PAIRS: Dict[int, 'ConnectionPair'] = {}


def subprocess_run_tmpfile(*args, **kwargs) -> CompletedProcess[str]:
    kwargs['encoding'] = kwargs.get('encoding', 'utf-8')
    collections.deque((kwargs.pop(field, None) for field in ('capture_output', 'text', 'universal_newlines')), maxlen=0)
    streams = ('stdout', 'stderr')
    streams_are_set = {stream: kwargs.get(stream, None) is not None for stream in streams}
    with ExitStack() as stack:
        kwargs.update({stream: kwargs[stream] if streams_are_set[stream] else stack.enter_context(TemporaryFile(mode='w+', encoding=kwargs['encoding'])) for stream in streams})
        p = run(*args, **kwargs)
        p.stdout, p.stderr = ((kwargs[stream].flush(), kwargs[stream].seek(0), kwargs[stream].read())[2] if not streams_are_set[stream] else getattr(p, stream) for stream in streams)
    return p


@contextmanager
def file_locker():
    lockfile = Path('/run/wirescale/control/locker').open(mode='w')
    fcntl.flock(lockfile, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(lockfile, fcntl.LOCK_UN)
        lockfile.close()
