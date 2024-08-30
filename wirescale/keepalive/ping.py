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
    from scapy.all import IP, UDP, RandShort, Raw, sniff, send, sr1

MAGIC = b'WS\xf0\x9f\x96\xa7'  # 'WS🖧'
MAGIC_LEN = len(MAGIC)
KEY_LEN = 32
NONCE_LEN = 24
IPV6_PREFIX = b'\x00' * 10 + b'\xff' * 2
STOP = Event()


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


def handle_pong(packet, send_time):
    if UDP in packet and Raw in packet:
        try:
            data = packet[Raw].load
            if data.startswith(MAGIC):
                _, _, payload = parse_disco_wrapper(data)
                if payload[0] == MessageType.PONG:
                    pong = parse_pong(payload)
                    rtt = time.time() - send_time
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

    if src_port is not None:
        Messages.send_info_message(local_message=f'Sending ping to {dest_ip}:{dest_port} from port {src_port} with TX ID: {tx_id.hex()}', send_to_local=False)
        send_time = time.time()
        response = sr1(pkt, timeout=2, verbose=False)
        if response:
            handle_pong(response, send_time)
        else:
            Messages.send_info_message(local_message=f'No response received with TX ID: {tx_id.hex()}', send_to_local=False)

    else:
        send(pkt, verbose=False)


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
                    pong_payload = create_pong(ping.tx_id, (packet[IP].src, packet[UDP].sport))
                    pong_message = create_disco_wrapper(os.urandom(KEY_LEN), os.urandom(NONCE_LEN), pong_payload)
                    pong_pkt = IP(dst=packet[IP].src) / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / Raw(load=pong_message)
                    send(pong_pkt, verbose=False)
                    Messages.send_info_message(local_message=f'Sent pong to {packet[IP].src}:{packet[UDP].sport} from port {packet[UDP].dport} with TX ID: {ping.tx_id.hex()}',
                                               send_to_local=False)
        except Exception as e:
            Messages.send_info_message(local_message=f'Error processing packet: {e}', send_to_local=False)


def listen_for_pings(src_ip: IPv4Address | IPv6Address, src_port: int, dst_port: int):
    Messages.send_info_message(local_message=f'Listening for pings on port {dst_port} coming from {src_ip}', send_to_local=False)
    sniff(filter=f'src {src_ip} and udp dst port {dst_port}', prn=handle_packet, stop_filter=lambda x: STOP.is_set())
