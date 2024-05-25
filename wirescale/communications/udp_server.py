#!/usr/bin/env python3
# encoding:utf-8


import sys
from socket import AF_INET, SOCK_DGRAM, socket
from time import sleep

from wirescale.vpn.tsmanager import TSManager


class UDPServer:
    UDPDummy: socket = None

    @classmethod
    def occupy_port_41641(cls):
        TSManager.start()
        if TSManager.local_port() == 41641:
            TSManager.stop()
        try:
            cls.UDPDummy = socket(AF_INET, SOCK_DGRAM)
            cls.UDPDummy.bind(('localhost', 41641))
        except:
            print("Couldn't occupy port 41641", file=sys.stderr, flush=True)
        TSManager.start()
        while not TSManager.is_running():
            sleep(0.5)
