#!/usr/bin/env python3
# encoding:utf-8


from abc import ABC, abstractmethod
from datetime import datetime
from ipaddress import IPv4Address
from typing import Optional, Tuple

from wirescale.communications.common import RUN_DIR


class VPNConfig(ABC):
    """Base class for WGConfig and RecoverConfig, providing the shared fields
    used by Systemd.launch_autoremove and the unified properties that
    eliminate the hasattr() checks."""

    def __init__(self):
        self.endpoint: Tuple[IPv4Address, int] = None
        self.interface: str = None
        self.iptables_accept: bool = None
        self.iptables_forward: bool = None
        self.iptables_masquerade: bool = None
        self.listen_ext_port: int = None
        self.nat: bool = None
        self.recover_tries: int = None
        self.recreate_tries: int = None
        self.remote_interface: str = None
        self.remote_local_port: int = None
        self.running_in_remote: Optional[bool] = None
        self.start_time: int = datetime.now().second
        self.suffix: int = None

    @property
    def config_path(self):
        return RUN_DIR.joinpath(f'{self.interface}.conf')

    @property
    @abstractmethod
    def autoremove_pubkey(self) -> str:
        """The remote public key string for the autoremove unit."""

    @property
    @abstractmethod
    def autoremove_wg_ip(self) -> IPv4Address:
        """The WireGuard IP address for the autoremove unit."""

    @property
    @abstractmethod
    def autoremove_listen_port(self) -> int:
        """The listen port for the autoremove unit."""
