#!/usr/bin/env python3
# encoding:utf-8


import ipaddress
import os
import struct
import time
import warnings
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from threading import Event
from typing import Tuple

from cryptography.utils import CryptographyDeprecationWarning

from wirescale.communications.messages import Messages

with warnings.catch_warnings(action='ignore', category=CryptographyDeprecationWarning):
    from scapy.all import IP, UDP, RandShort, Raw, sniff, send

MAGIC = b'WS\xf0\x9f\x96\xa7'  # 'WS🖧'
MAGIC_LEN = len(MAGIC)
KEY_LEN = 32
NONCE_LEN = 24
IPV6_PREFIX = b'\x00' * 10 + b'\xff' * 2
SENT_PINGS = {}
STOP = Event()
HIT_PING = False
HIT_PONG = False


class MessageType:
    PING = 0x01
    PONG = 0x02


@dataclass
class Ping:
    tx_id: bytes
    padding: int


@dataclass
class Pong:
    tx_id: bytes
    src: Tuple[str, int]  # (IP, port)


def create_disco_wrapper(sender_key: bytes, nonce: bytes, payload: bytes) -> bytes:
    return MAGIC + sender_key + nonce + payload


def parse_disco_wrapper(data: bytes) -> Tuple[bytes, bytes, bytes]:
    if not data.startswith(MAGIC):
        raise ValueError('Invalid magic bytes')
    key_end = MAGIC_LEN + KEY_LEN
    nonce_end = key_end + NONCE_LEN
    return data[MAGIC_LEN:key_end], data[key_end:nonce_end], data[nonce_end:]


def create_ping(tx_id: bytes, padding: int) -> bytes:
    result = bytearray([MessageType.PING, 0])  # type and version
    result.extend(tx_id)
    result.extend(b'\x00' * padding)
    return bytes(result)


def create_pong(tx_id: bytes, src: Tuple[str, int]) -> bytes:
    result = bytearray([MessageType.PONG, 0])  # type and version
    result.extend(tx_id)
    ip = ipaddress.ip_address(src[0]).packed
    if len(ip) == 4:
        ip = IPV6_PREFIX + ip  # IPv4-mapped IPv6 address
    result.extend(ip)
    result.extend(struct.pack('>H', src[1]))
    return bytes(result)


def parse_ping(payload: bytes) -> Ping:
    if len(payload) < 14:  # 1 (type) + 1 (version) + 12 (tx_id)
        raise ValueError('Short message')
    return Ping(tx_id=payload[2:14], padding=len(payload) - 14)


def parse_pong(payload: bytes) -> Pong:
    if len(payload) < 32:  # 1 (type) + 1 (version) + 12 (tx_id) + 16 (IP) + 2 (port)
        raise ValueError('Short message')
    tx_id = payload[2:14]
    ip = payload[14:30]
    ip = ip[len(IPV6_PREFIX):] if ip.startswith(IPV6_PREFIX) else ip
    ip = ipaddress.ip_address(ip).compressed
    port = struct.unpack('>H', payload[30:32])[0]
    return Pong(tx_id, (ip, port))


def generate_tx_id() -> bytes:
    return os.urandom(12)


def handle_pong(payload):
    try:
        pong = parse_pong(payload)
        send_time = SENT_PINGS[pong.tx_id.hex()]
        rtt = time.time() - send_time
        global HIT_PING
        HIT_PING = True
        Messages.send_info_message(local_message=f'Received pong with TX ID: {pong.tx_id.hex()}, RTT: {rtt:.6f} seconds', send_to_local=False)
    except Exception as e:
        Messages.send_info_message(local_message=f'Error processing pong: {e}', send_to_local=False)


def send_ping(dest_ip: str, dest_port: int, src_port: int | None):
    sender_key = os.urandom(KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    tx_id = generate_tx_id()
    ping_payload = create_ping(tx_id, padding=20)
    ping_message = create_disco_wrapper(sender_key, nonce, ping_payload)
    sport = src_port if src_port is not None else RandShort()
    pkt = IP(dst=dest_ip) / UDP(sport=sport, dport=dest_port) / Raw(load=ping_message)
    Messages.send_info_message(local_message=f'Sending ping to {dest_ip}:{dest_port} from port {src_port} with TX ID: {tx_id.hex()}', send_to_local=False)
    send_time = time.time()
    SENT_PINGS[tx_id.hex()] = send_time
    send(pkt, verbose=False)


def send_periodic_ping(dest_ip: str, dest_port: int, src_port: int | None, period: int = 5):
    while not STOP.is_set():
        try:
            send_ping(dest_ip, dest_port, src_port)
        except Exception as e:
            Messages.send_info_message(local_message=str(e), send_to_local=False)
        STOP.wait(period)


def handle_packet(packet):
    if UDP in packet and Raw in packet:
        try:
            data = packet[Raw].load
            if data.startswith(MAGIC):
                _, _, payload = parse_disco_wrapper(data)
                if payload[0] == MessageType.PING:
                    ping = parse_ping(payload)
                    Messages.send_info_message(local_message=f'Received ping with TX ID: {ping.tx_id.hex()}', send_to_local=False)

                    # Send pong
                    global HIT_PONG
                    HIT_PONG = True
                    pong_payload = create_pong(ping.tx_id, (packet[IP].src, packet[UDP].sport))
                    pong_message = create_disco_wrapper(os.urandom(KEY_LEN), os.urandom(NONCE_LEN), pong_payload)
                    pong_pkt = IP(dst=packet[IP].src) / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / Raw(load=pong_message)
                    send(pong_pkt, verbose=False)
                    Messages.send_info_message(local_message=f'Sent pong to {packet[IP].src}:{packet[UDP].sport} from port {packet[UDP].dport} with TX ID: {ping.tx_id.hex()}',
                                               send_to_local=False)

                elif payload[0] == MessageType.PONG:
                    handle_pong(payload)

        except Exception as e:
            Messages.send_info_message(local_message=f'Error processing packet: {e}', send_to_local=False)


def clear_orphaned_pings():
    while not STOP.is_set():
        for ping in SENT_PINGS:
            rtt = time.time() - SENT_PINGS[ping]
            if rtt >= 3:
                Messages.send_info_message(local_message=f'No response received with TX ID: {ping}', send_to_local=False)
                del SENT_PINGS[ping]
        STOP.wait(5)


def listen_for_pings(src_ip: IPv4Address | IPv6Address, src_port: int, dst_port: int):
    Messages.send_info_message(local_message=f'Listening for pings on port {dst_port} coming from {src_ip}:{src_port}', send_to_local=False)
    sniff(filter=f'src {src_ip} and udp src port {src_port} and udp dst port {dst_port}', prn=handle_packet, stop_filter=lambda x: STOP.is_set())
