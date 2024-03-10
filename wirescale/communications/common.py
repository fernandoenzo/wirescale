# encoding:utf-8


from pathlib import Path
from threading import Event

SHUTDOWN = Event()
TCP_PORT = 41642
SOCKET_PATH = Path('/run/wirescale/wirescaled.sock').resolve()
