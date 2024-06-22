# encoding:utf-8


from threading import Event
from time import sleep
from typing import TYPE_CHECKING

from parallel_utils.thread import create_thread, StaticMonitor

from wirescale.communications.common import CONNECTION_PAIRS, Semaphores, SHUTDOWN
from wirescale.communications.messages import Messages

if TYPE_CHECKING:
    from wirescale.communications.connection_pair import ConnectionPair


class ActiveSockets:
    def __init__(self):
        self._client: 'ConnectionPair' = None
        self._client_thread: int = None
        self._server_thread: int = None
        self._server: 'ConnectionPair' = None
        self.exclusive_socket: 'ConnectionPair' = None
        self.waiter_server_switched, self.waiter_switched = Event(), Event()
        self.waiter_server_switched.set()
        self.waiter_switched.set()

    def client_exists(self) -> bool:
        if CONNECTION_PAIRS.get(self._client_thread) != self._client:
            self._client, self._client_thread = None, None
        return self._client is not None

    def client_is_running(self) -> bool:
        return self.client_exists() and self.exclusive_socket == self._client

    @property
    def client_thread(self) -> int:
        return self._client_thread

    @client_thread.setter
    def client_thread(self, new_client_thread):
        self._client_thread = new_client_thread
        self._client = CONNECTION_PAIRS.get(new_client_thread)

    def needs_switch(self, counter: int) -> bool:
        if not self.client_exists() or not self.server_exists():
            return False
        if self.server_is_running():
            return False
        if self.client_is_running():
            if counter > 1 and self._server.peer_ip == self._client.peer_ip:
                return True
            return self._server.peer_ip < self._client.my_ip
        return False

    def capture_semaphore(self):
        self.waiter_server_switched.wait()
        StaticMonitor.lock_code(uid=Semaphores.EXCLUSIVE)
        self.waiter_switched.set()

    def server_exists(self) -> bool:
        if CONNECTION_PAIRS.get(self._server_thread) != self._server:
            self._server, self._server_thread = None, None
        return self._server is not None

    def server_is_running(self) -> bool:
        return self.server_exists() and self.exclusive_socket == self._server

    @property
    def server_thread(self) -> int:
        return self._server_thread

    @server_thread.setter
    def server_thread(self, new_server_thread):
        self._server_thread = new_server_thread
        self._server = CONNECTION_PAIRS.get(new_server_thread)

    def watch(self):
        server, client = None, None
        counter = 0
        while True:
            if SHUTDOWN.is_set() and not (self.server_exists() and self.client_exists()):
                return
            if self._server != server or self._client != client or None in (self._server, self._client):
                server, client = self._server, self._client
                counter = 0
            else:
                if self.waiter_switched.is_set():
                    counter += 1
                    if self.needs_switch(counter):
                        print(Messages.DEADLOCK, flush=True)
                        self.waiter_server_switched.clear()
                        self.waiter_switched.clear()
                        StaticMonitor.unlock_code(uid=Semaphores.EXCLUSIVE)
                        create_thread(self.capture_semaphore)
            sleep(15)


ACTIVE_SOCKETS = ActiveSockets()
