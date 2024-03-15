#!/usr/bin/env python3
# encoding:utf-8


from socket import AF_INET, SOCK_DGRAM, socket
from time import sleep

from wirescale.vpn import TSManager


class UDPServer:
    UDPDummy: socket = None

    @classmethod
    def occupy_port_41641(cls):
        if cls.UDPDummy is not None:
            return
        if TSManager.local_port() != 41641:
            return
        TSManager.stop()
        cls.UDPDummy = socket(AF_INET, SOCK_DGRAM)
        cls.UDPDummy.bind(('localhost', 41641))
        TSManager.start()
        while not TSManager.is_running():
            sleep(0.5)
