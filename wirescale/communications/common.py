# encoding:utf-8


from pathlib import Path
from threading import Event
from typing import Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from wirescale.parsers.args import ConnectionPair

SHUTDOWN = Event()
TCP_PORT = 41642
SOCKET_PATH = Path('/run/wirescale/wirescaled.sock').resolve()
CONNECTION_PAIRS: Dict[int, 'ConnectionPair'] = {}
