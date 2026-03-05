#!/usr/bin/env python3
# encoding:utf-8


from abc import ABC, abstractmethod
from contextlib import ExitStack
from ipaddress import ip_address, IPv4Address
from typing import TYPE_CHECKING

from wirescale.communications.checkers import check_addresses_in_allowedips, check_behind_nat, check_interface, match_pubkeys
from wirescale.communications.common import file_locker
from wirescale.communications.messages import ActionCodes, MessageFields, TCPMessages
from wirescale.vpn.tsmanager import TSManager

if TYPE_CHECKING:
    from wirescale.communications.connection_pair import ConnectionPair
    from wirescale.vpn.vpn_config import VPNConfig


class VPNOperation(ABC):
    """Abstract base class for upgrade and recover operations.

    Encapsulates the per-operation logic that differs between upgrade and
    recover flows, allowing TCPClient.run() to drive both with a single
    message loop.
    """

    @property
    @abstractmethod
    def config(self) -> 'VPNConfig':
        """The VPNConfig (WGConfig or RecoverConfig) for this operation."""

    @property
    @abstractmethod
    def response_code(self) -> str:
        """The ActionCode expected for the response message."""

    @abstractmethod
    def on_ack(self, pair: 'ConnectionPair', stack: ExitStack) -> None:
        """Called when ACK is received: prepare config and send the request."""

    @abstractmethod
    def on_response(self, message: dict, pair: 'ConnectionPair') -> None:
        """Called when the response message is received: process it."""

    @abstractmethod
    def execute(self) -> None:
        """Run the final VPN action (upgrade or recover)."""


class UpgradeOperation(VPNOperation):
    def __init__(self, wgconfig, interface: str, suffix_number: int):
        from wirescale.vpn.wgconfig import WGConfig
        self._config: WGConfig = wgconfig
        self._interface: str = interface
        self._suffix_number: int = suffix_number

    @property
    def config(self):
        return self._config

    @property
    def response_code(self) -> str:
        return ActionCodes.UPGRADE_RESPONSE

    def on_ack(self, pair: 'ConnectionPair', stack: ExitStack) -> None:
        with file_locker():
            self._config.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        self._config.interface, self._config.suffix = check_interface(interface=self._interface, allow_suffix=self._config.allow_suffix)
        if self._suffix_number is not None:
            self._config.suffix = self._suffix_number
        self._config.listen_port = TSManager.local_port()
        TCPMessages.send_upgrade(self._config)

    def on_response(self, message: dict, pair: 'ConnectionPair') -> None:
        match_pubkeys(self._config, remote_pubkey=message[MessageFields.PUBKEY], my_pubkey=None)
        self._config.remote_addresses = frozenset(ip_address(ip) for ip in message[MessageFields.ADDRESSES])
        check_addresses_in_allowedips(self._config)
        self._config.listen_ext_port = message[MessageFields.EXPOSED_PORT]
        self._config.start_time = message[MessageFields.START_TIME]
        self._config.remote_local_port = message[MessageFields.PORT]
        self._config.remote_interface = message[MessageFields.INTERFACE]
        self._config.generate_new_config()
        self._config.nat = message[MessageFields.NAT] and check_behind_nat(IPv4Address(message[MessageFields.PUBLIC_IP]))

    def execute(self) -> None:
        self._config.upgrade()


class RecoverOperation(VPNOperation):
    def __init__(self, recover):
        from wirescale.vpn.recover import RecoverConfig
        self._config: RecoverConfig = recover

    @property
    def config(self):
        return self._config

    @property
    def response_code(self) -> str:
        return ActionCodes.RECOVER_RESPONSE

    def on_ack(self, pair: 'ConnectionPair', stack: ExitStack) -> None:
        with file_locker():
            self._config.endpoint = TSManager.peer_endpoint(pair.peer_ip)
        self._config.new_port = TSManager.local_port()
        TCPMessages.send_recover(self._config)

    def on_response(self, message: dict, pair: 'ConnectionPair') -> None:
        TCPMessages.process_recover_response(message, self._config)

    def execute(self) -> None:
        self._config.recover()
