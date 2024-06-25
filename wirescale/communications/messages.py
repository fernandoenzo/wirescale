#!/usr/bin/env python3
# encoding:utf-8


import json
import os
import sys
from argparse import ArgumentError
from enum import auto, StrEnum, unique
from ipaddress import IPv4Address
from threading import get_ident
from typing import TYPE_CHECKING, Union

from wirescale.communications.common import BytesStrConverter, CONNECTION_PAIRS
from wirescale.version import VERSION

if TYPE_CHECKING:
    from wirescale.vpn.recover import RecoverConfig
    from wirescale.vpn.wgconfig import WGConfig


@unique
class MessageFields(StrEnum):
    ADDRESSES = auto()
    ALLOW_SUFFIX = auto()
    CODE = auto()
    ENCRYPTED = auto()
    ERROR_CODE = auto()
    ERROR_MESSAGE = auto()
    EXPECTED_INTERFACE = auto()
    HAS_PSK = auto()
    INTERFACE = auto()
    IPTABLES = auto()
    LATEST_HANDSHAKE = auto()
    MESSAGE = auto()
    NAT = auto()
    NONCE = auto()
    PEER_IP = auto()
    PUBLIC_IP = auto()
    PORT = auto()
    PSK = auto()
    PUBKEY = auto()
    RECOVER_TRIES = auto()
    RECREATE_TRIES = auto()
    REMOTE_INTERFACE = auto()
    REMOTE_PORT = auto()
    REMOTE_PUBKEY = auto()
    RESTART_ON_FAIL = auto()
    START_TIME = auto()
    SUFFIX_NUMBER = auto()
    TOKEN = auto()
    VERSION = auto()
    WG_IP = auto()


@unique
class ActionCodes(StrEnum):
    ACK = auto()
    GO = auto()
    HELLO = auto()
    INFO = auto()
    RECOVER = auto()
    RECOVER_RESPONSE = auto()
    STOP = auto()
    SUCCESS = auto()
    TOKEN = auto()
    UPGRADE = auto()
    UPGRADE_RESPONSE = auto()


@unique
class ErrorCodes(StrEnum):
    CLOSED = auto()
    CONFIG_PATH_ERROR = auto()
    GENERIC = auto()
    HANDSHAKE_MISMATCH = auto()
    INTERFACE_EXISTS = auto()
    TS_UNREACHABLE = auto()


class UnixMessages:
    STOP_MESSAGE = {MessageFields.CODE: ActionCodes.STOP, MessageFields.ERROR_CODE: None}

    @staticmethod
    def send_upgrade_option():
        from wirescale.parsers.args import ARGS
        res = {
            MessageFields.CODE: ActionCodes.UPGRADE,
            MessageFields.ERROR_CODE: None,
            MessageFields.ALLOW_SUFFIX: ARGS.ALLOW_SUFFIX,
            MessageFields.EXPECTED_INTERFACE: ARGS.EXPECTED_INTERFACE,
            MessageFields.INTERFACE: ARGS.INTERFACE,
            MessageFields.IPTABLES: ARGS.IPTABLES,
            MessageFields.PEER_IP: str(ARGS.PAIR.peer_ip),
            MessageFields.RECOVER_TRIES: ARGS.RECOVER_TRIES,
            MessageFields.RECREATE_TRIES: ARGS.RECREATE_TRIES,
            MessageFields.SUFFIX_NUMBER: ARGS.SUFFIX_NUMBER,
        }
        ARGS.PAIR.send_to_local(json.dumps(res))

    @staticmethod
    def send_recover(recover: 'RecoverConfig'):
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.RECOVER,
            MessageFields.ERROR_CODE: None,
            MessageFields.INTERFACE: recover.interface,
            MessageFields.LATEST_HANDSHAKE: recover.latest_handshake,
            MessageFields.PEER_IP: str(CONNECTION_PAIRS[get_ident()].peer_ip),
        }
        pair.send_to_local(json.dumps(res))


class TCPMessages:

    @staticmethod
    def send_ack():
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.ACK,
            MessageFields.ERROR_CODE: None
        }
        pair.send_to_remote(json.dumps(res))

    @staticmethod
    def send_hello():
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.HELLO,
            MessageFields.ERROR_CODE: None
        }
        pair.send_to_remote(json.dumps(res))

    @staticmethod
    def send_token():
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.TOKEN,
            MessageFields.ERROR_CODE: None,
            MessageFields.TOKEN: pair.token,
            MessageFields.VERSION: VERSION,
        }
        pair.send_to_remote(json.dumps(res))

    @staticmethod
    def send_upgrade(wgconfig: 'WGConfig'):
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.UPGRADE,
            MessageFields.ERROR_CODE: None,
            MessageFields.ADDRESSES: [str(ip) for ip in wgconfig.addresses],
            MessageFields.EXPECTED_INTERFACE: wgconfig.expected_interface,
            MessageFields.HAS_PSK: wgconfig.has_psk,
            MessageFields.INTERFACE: wgconfig.interface,
            MessageFields.PORT: wgconfig.listen_port,
            MessageFields.PSK: wgconfig.psk if not wgconfig.has_psk else None,
            MessageFields.PUBLIC_IP: str(wgconfig.endpoint[0]),
            MessageFields.PUBKEY: wgconfig.public_key,
            MessageFields.REMOTE_PUBKEY: wgconfig.remote_pubkey,
        }
        pair.send_to_remote(json.dumps(res))

    @staticmethod
    def send_upgrade_response(wgconfig):
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.UPGRADE_RESPONSE,
            MessageFields.ERROR_CODE: None,
            MessageFields.ADDRESSES: [str(ip) for ip in wgconfig.addresses],
            MessageFields.INTERFACE: wgconfig.interface,
            MessageFields.NAT: wgconfig.nat,
            MessageFields.PORT: wgconfig.listen_port,
            MessageFields.PUBLIC_IP: str(wgconfig.endpoint[0]),
            MessageFields.PUBKEY: wgconfig.public_key,
            MessageFields.START_TIME: wgconfig.start_time,
        }
        pair.send_to_remote(json.dumps(res))

    @staticmethod
    def send_go(config: Union['WGConfig', 'RecoverConfig']) -> bool:
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.GO,
            MessageFields.NAT: config.nat,
            MessageFields.ERROR_CODE: None,
        }
        return pair.send_to_remote(json.dumps(res), ack_timeout=7)

    @staticmethod
    def send_recover(recover: 'RecoverConfig'):
        pair = CONNECTION_PAIRS[get_ident()]
        res = {
            MessageFields.CODE: ActionCodes.RECOVER,
            MessageFields.ERROR_CODE: None,
            MessageFields.INTERFACE: recover.remote_interface,
            MessageFields.NONCE: BytesStrConverter.raw_bytes_to_str64(recover.nonce),
        }
        encrypted = {
            MessageFields.LATEST_HANDSHAKE: recover.latest_handshake,
            MessageFields.PORT: recover.remote_local_port,
            MessageFields.PUBLIC_IP: str(recover.endpoint[0]),
            MessageFields.REMOTE_INTERFACE: recover.interface,
            MessageFields.REMOTE_PORT: recover.new_port,
            MessageFields.RESTART_ON_FAIL: recover.restart_on_fail,
        }
        encrypted = json.dumps(encrypted)
        res[MessageFields.ENCRYPTED] = recover.encrypt(encrypted)
        pair.send_to_remote(json.dumps(res))

    @staticmethod
    def send_recover_response(recover: 'RecoverConfig'):
        pair = CONNECTION_PAIRS[get_ident()]
        recover.nonce = os.urandom(12)
        res = {
            MessageFields.CODE: ActionCodes.RECOVER_RESPONSE,
            MessageFields.ERROR_CODE: None,
            MessageFields.NONCE: BytesStrConverter.raw_bytes_to_str64(recover.nonce),
        }
        encrypted = {
            MessageFields.NAT: recover.nat,
            MessageFields.PUBLIC_IP: str(recover.endpoint[0]),
            MessageFields.REMOTE_PORT: recover.new_port,
            MessageFields.START_TIME: recover.start_time,
        }
        encrypted = json.dumps(encrypted)
        res[MessageFields.ENCRYPTED] = recover.encrypt(encrypted)
        pair.send_to_remote(json.dumps(res))

    @staticmethod
    def process_recover(message: dict) -> 'RecoverConfig':
        from wirescale.communications.checkers import check_behind_nat, check_recover_config
        from wirescale.vpn.recover import RecoverConfig
        pair = CONNECTION_PAIRS[get_ident()]
        interface = message[MessageFields.INTERFACE]
        recover = RecoverConfig.create_from_autoremove(interface=interface, latest_handshake=None)
        recover.nonce = BytesStrConverter.str64_to_raw_bytes(message[MessageFields.NONCE])
        try:
            decrypted = recover.decrypt(data=message[MessageFields.ENCRYPTED])
        except:
            error = ErrorMessages.CANT_DECRYPT.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            error_remote = ErrorMessages.REMOTE_CANT_DECRYPT.format(my_name=pair.my_name, my_ip=pair.my_ip)
            ErrorMessages.send_error_message(local_message=error, remote_message=error_remote)
        decrypted = json.loads(decrypted)
        message.update(decrypted)
        recover.current_port = message[MessageFields.PORT]
        recover.latest_handshake = message[MessageFields.LATEST_HANDSHAKE]
        recover.remote_local_port = message[MessageFields.REMOTE_PORT]
        recover.remote_interface = message[MessageFields.REMOTE_INTERFACE]
        recover.restart_on_fail = message[MessageFields.RESTART_ON_FAIL]
        check_recover_config(recover)
        recover.nat = check_behind_nat(IPv4Address(message[MessageFields.PUBLIC_IP]))
        return recover

    @staticmethod
    def process_recover_response(message: dict, recover: 'RecoverConfig'):
        from wirescale.communications.checkers import check_behind_nat
        pair = CONNECTION_PAIRS[get_ident()]
        recover.nonce = BytesStrConverter.str64_to_raw_bytes(message[MessageFields.NONCE])
        try:
            decrypted = recover.decrypt(data=message[MessageFields.ENCRYPTED])
        except:
            error = ErrorMessages.CANT_DECRYPT.format(peer_name=pair.peer_name, peer_ip=pair.peer_ip)
            error_remote = ErrorMessages.REMOTE_CANT_DECRYPT.format(my_name=pair.my_name, my_ip=pair.my_ip)
            ErrorMessages.send_error_message(local_message=error, remote_message=error_remote)
        decrypted = json.loads(decrypted)
        message.update(decrypted)
        recover.remote_local_port = message[MessageFields.REMOTE_PORT]
        recover.start_time = message[MessageFields.START_TIME]
        recover.nat = message[MessageFields.NAT] and check_behind_nat(IPv4Address(message[MessageFields.PUBLIC_IP]))


class Messages:
    CHECKING_CONNECTION = "Checking whether the connection with peer '{peer_name}' ({peer_ip}) is broken..."
    CHECKING_ENDPOINT = "Checking that an endpoint is available for peer '{peer_name}' ({peer_ip})..."
    CONNECTED_UNIX = 'Connection to local UNIX socket established'
    CONNECTING_UNIX = 'Connecting to local UNIX socket...'
    CONNECTION_OK = "Connection with peer '{peer_name}' ({peer_ip}) is fine"
    DEADLOCK = 'Potential deadlock situation identified. Taking actions to avoid it'
    END_SESSION = "Session finished"
    ENQUEUEING_FROM = "Enqueueing request coming from peer '{peer_name}' ({peer_ip})..."
    ENQUEUEING_REMOTE = "Remote peer '{sender_name}' ({sender_ip}) has enqueued our request"
    ENQUEUEING_TO = "Enqueueing upgrade request to peer '{peer_name}' ({peer_ip})..."
    ENQUEUEING_RECOVER = "Enqueueing recover request to peer '{peer_name}' ({peer_ip}) for interface '{interface}'..."
    EXCLUSIVE_SEMAPHORE_RECOVER = "The recover request to peer '{peer_name}' ({peer_ip}) for interface '{interface}' has acquired the exclusive semaphore"
    EXCLUSIVE_SEMAPHORE_REMOTE = "Request coming from peer '{peer_name}' ({peer_ip}) has acquired the exclusive semaphore"
    EXCLUSIVE_SEMAPHORE_UPGRADE = "The upgrade request for the peer '{peer_name}' ({peer_ip}) has acquired the exclusive semaphore"
    NEW_UNIX_INCOMING = 'New local UNIX connection incoming'
    NEXT_INCOMING = "Request coming from peer '{peer_name}' ({peer_ip}) is the next one in the processing queue"
    NEXT_RECOVER = "The recover request to peer '{peer_name}' ({peer_ip}) for interface '{interface}' is the next one in the processing queue"
    NEXT_UPGRADE = "The upgrade request for the peer '{peer_name}' ({peer_ip}) is the next one in the processing queue"
    REACHABLE = "Peer '{peer_name}' ({peer_ip}) is reachable"
    RECOVER_SUCCES = "Success! WireGuard connection through interface '{interface}' is working again"
    SHUTDOWN_SET = 'The server has been set to shut down'
    START_PROCESSING_FROM = "Starting to process the {{action}} request coming from peer '{peer_name}' ({peer_ip})"
    START_PROCESSING_REMOTE = "Remote peer '{sender_name}' ({sender_ip}) has started to process our {{action}} request"
    START_PROCESSING_TO = "Starting to process the upgrade request for the peer '{peer_name}' ({peer_ip})"
    START_PROCESSING_RECOVER = "Starting to process the recover request for the peer '{peer_name}' ({peer_ip}) for interface '{interface}'"
    SUCCESS = "Success! Now you have a new working P2P connection through interface '{interface}'"
    VERSION_MISMATCH = "Warning: Your wirescale version doesn't match the remote peer's one ({local_version} ≠ {remote_version}). Errors may occur"

    @staticmethod
    def add_id(uid: str, message: str) -> str:
        if message.startswith(uid):
            return message
        return f'{uid} - {message}'

    @staticmethod
    def build_info_message(info_message: str, code: ActionCodes = ActionCodes.INFO) -> dict:
        res = {
            MessageFields.CODE: code,
            MessageFields.ERROR_CODE: None,
            MessageFields.MESSAGE: info_message
        }
        return res

    @classmethod
    def process_version(cls, message: dict):
        remote_version = message[MessageFields.VERSION]
        if remote_version != VERSION:
            local_message = cls.VERSION_MISMATCH.format(local_version=VERSION, remote_version=remote_version)
            remote_message = cls.VERSION_MISMATCH.format(local_version=remote_version, remote_version=VERSION)
            cls.send_info_message(local_message=local_message, remote_message=remote_message)

    @classmethod
    def send_info_message(cls, local_message: str = None, remote_message: str = None, code: ActionCodes = ActionCodes.INFO, send_to_local: bool = True, always_send_to_remote: bool = True):
        pair = CONNECTION_PAIRS.get(get_ident())
        if pair is not None and pair.token is not None:
            local_message = cls.add_id(pair.id, local_message) if local_message is not None else None
            remote_message = cls.add_id(pair.id, remote_message) if remote_message is not None else None
        if local_message is not None:
            print(local_message, flush=True)
        if pair is not None:
            if pair.local_socket is not None and local_message is not None and not pair.running_in_remote and send_to_local:
                local_message = cls.build_info_message(local_message, code)
                pair.send_to_local(json.dumps(local_message))
            if pair.remote_socket is not None and remote_message is not None and (pair.running_in_remote or always_send_to_remote):
                remote_message = cls.build_info_message(remote_message, code)
                pair.send_to_remote(json.dumps(remote_message))


class ErrorMessages:
    ALLOWED_IPS_MISMATCH = "Error: IPs from the 'Address' field of '{sender_name}' ({sender_ip}) are not fully covered in the 'AllowedIPs' field of '{my_name}' ({my_ip})"
    BAD_FORMAT_PRIVKEY = "Error: The private key has not the correct length or format in file '{config_file}'"
    BAD_FORMAT_PSK = "Error: The pre-shared key has not the correct length or format in file '{config_file}'"
    BAD_FORMAT_PUBKEY = "Error: The public key has not the correct length or format in file '{config_file}'"
    BAD_WS_CONFIG = "Error: Invalid value for the '{field}' field in the 'Wirescale' section of file '{config_file}'"
    CANT_DECRYPT = "Error: Couldn't decrypt the recover message sent by remote peer '{peer_name}' ({peer_ip})"
    CLOSED = 'Error: Wirescale is shutting down and is no longer accepting new requests'
    CLOSING_SOCKET = "Error: Connection is broken. Closing socket"
    CONFIG_PATH_ERROR = "Error: Cannot locate a configuration file for peer '{peer_name}' in '/etc/wirescale/'"
    CONNECTION_LOST = "Error: Connection with remote peer '{peer_name}' ({peer_ip}) has been lost. Aborting pending operations"
    FINAL_ERROR = 'Something went wrong and, finally, it was not possible to establish the P2P connection'
    HANDSHAKE_FAILED = "Error: Handshake with interface '{interface}' failed"
    HANDSHAKE_FAILED_RECOVER = "Error: Handshake with interface '{interface}' failed after changing its endpoint"
    INTERFACE_EXISTS = "Error: A network interface '{interface}' already exists"
    INTERFACE_MISMATCH = "Error: Remote peer '{peer_name}' ({peer_ip}) expects a network interface name that does not match the one we are assigning"
    IP_MISMATCH = "Error: Remote peer '{peer_name}' ({peer_ip}) IP address mismatch with the 'autoremove-{interface}' systemd unit's registered IP ({autoremove_ip})"
    LATEST_HANDSHAKE_MISMATCH = "Error: The latest handshake of interface '{interface}' has been updated since the recover request was made. Discarding request"
    MISSING_ADDRESS = "Error: 'Address' option missing in 'Interface' section of file '{config_file}'"
    MISSING_ALLOWEDIPS = "Error: 'AllowedIPs' option missing in 'Peer' section of file '{config_file}'"
    MISSING_UNIT = "Error: systemd unit '{unit}' is not active"
    PORT_MISMATCH = "Error: WireGuard interface '{interface}' is not listening on port {port}"
    PSK_MISMATCH = ("Error: Peer '{name_without_psk}' ({ip_without_psk}) does not have a pre-shared key for '{name_with_psk}' ({ip_with_psk}), but '{name_with_psk}' has one configured for "
                    "'{name_without_psk}'. Ensure key consistency.")
    PUBKEY_MISMATCH = "Error: The public key provided by '{sender_name}' ({sender_ip}) is inconsistent with the one that '{receiver_name}' ({receiver_ip}) has on record for this peer."
    RECOVER_SYSTEMD = "Error: The 'recover' option can only be invoked by the Wirescale shell script"
    REMOTE_BAD_FORMAT_PRIVKEY = "Error: The private key has not the correct length or format in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_BAD_FORMAT_PSK = "Error: The pre-shared key has not the correct length or format in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_BAD_FORMAT_PUBKEY = "Error: The public key has not the correct length or format in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_BAD_WS_CONFIG = "Error: Invalid value for the '{field}' field in the 'Wirescale' section in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_CANT_DECRYPT = "Error: Remote peer '{my_name}' ({my_ip}) couldn't decrypt our recover message"
    REMOTE_CLOSED = "Error: Wirescale instance at '{my_name}' ({my_ip}) has been set to stop receiving requests"
    REMOTE_CONFIG_ERROR = "Error: Remote peer '{my_name}' ({my_ip}) has a syntax error in its configuration file for '{peer_name}'"
    REMOTE_CONFIG_PATH_ERROR = "Error: Remote peer '{my_name}' ({my_ip}) cannot locate a configuration file for peer '{peer_name}'"
    REMOTE_INTERFACE_EXISTS = "Error: A network interface '{interface}' already exists in remote peer '{my_name}' ({my_ip})"
    REMOTE_INTERFACE_MISMATCH = "Error: Remote peer '{my_name}' ({my_ip}) is not assigning the expected name '{interface}' to its network interface"
    REMOTE_IP_MISMATCH = "Error: Remote peer '{my_name}' ({my_ip}) has registered a different IP address in its 'autoremove-{interface}' systemd unit than ours ({peer_ip})"
    REMOTE_LATEST_HANDSHAKE_MISMATCH = ("Error: The latest handshake of remote interface '{interface}' from remote peer '{my_name}' ({my_ip}) has been updated since the recover "
                                        "request was made. Discarding request.")
    REMOTE_MISSING_ADDRESS = "Error: 'Address' option missing in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_MISSING_ALLOWEDIPS = "Error: 'AllowedIPs' option missing in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_MISSING_UNIT = "Error: systemd unit '{unit}' is not active in remote peer '{my_name}' ({my_ip})"
    REMOTE_MISSING_WIRESCALE = "Error: Remote peer '{peer_name}' ({peer_ip}) does not have Wirescale running"
    REMOTE_PORT_MISMATCH = "Error: WireGuard interface '{interface}' is not listening on local port {port} in remote peer '{peer_name}' ({peer_ip})"
    REMOTE_RUNFILE_MISSING = "Error: File '/run/wirescale/{interface}.conf' does not exist or is not a regular file in remote peer '{my_name}' ({my_ip})"
    REMOTE_WG_INTERFACE_MISSING = "Error: Remote peer '{my_name}' ({my_ip}) does not have a WireGuard interface named '{interface}'"
    RESTART_UNIT = "Restarting systemd unit 'autoremove-{interface}'"
    RUNFILE_MISSING = "Error: File '/run/wirescale/{interface}.conf' does not exist or is not a regular file"
    ROOT_SYSTEMD = "Error: Wirescale daemon must be managed by root's systemd"
    SOCKET_REMOTE_ERROR = "Error: Remote peer '{peer_name}' ({peer_ip}) has closed the connection. Aborting pending operations"
    SOCKET_ERROR = "Error: The program has been closed. Aborting pending operations"
    SUDO = 'Error: This program must be run as a superuser'
    TS_COORD_OFFLINE = "Error: Tailscale has no state; the coordination server may not be reachable"
    TS_PEER_OFFLINE = "Error: Peer '{peer_name}' ({peer_ip}) is offline"
    TS_SYSTEMD_STOPPED = "Error: 'tailscaled.service' is stopped. Start the service with systemd"
    TS_STOPPED = "Error: Tailscale is stopped. Run 'sudo tailscale up'"
    TS_NO_ENDPOINT = "Sorry, it was impossible to find a public endpoint for peer '{peer_name}' ({peer_ip})"
    TS_NO_IP = "Error: No IPv4 found for peer '{peer_name}'"
    TS_NO_LOGGED = 'Error: Tailscale is logged out'
    TS_NO_PEER = "Error: No peer found matching the IP '{peer_ip}'"
    TS_NO_PORT = 'Error: No listening port for Tailscale was found'
    TS_NOT_RECOVERED = "Error: Either this tailscale instance or '{peer_name}' ({peer_ip}) one has not fully recovered and cannot reestablish the connection"
    TS_NOT_RUNNING = 'Error: Tailscale is not running'
    UNIX_SOCKET = "Error: Couldn't connect to the local UNIX socket"
    WG_INTERFACE_MISSING = "Error: WireGuard interface '{interface}' does not exist"

    @staticmethod
    def build_error_message(error_message: str, error_code: ErrorCodes = ErrorCodes.GENERIC) -> dict:
        res = {
            MessageFields.CODE: None,
            MessageFields.ERROR_CODE: error_code,
            MessageFields.ERROR_MESSAGE: error_message
        }
        return res

    @classmethod
    def process_error_message(cls, message: dict):
        from wirescale.parsers.parsers import interface_argument, upgrade_subparser
        pair = CONNECTION_PAIRS[get_ident()]
        if error_code := message[MessageFields.ERROR_CODE]:
            text = message[MessageFields.ERROR_MESSAGE]
            if pair.running_in_remote or pair.tcp_socket is not None:  # TCP Server or Unix Server
                cls.send_error_message(local_message=text, error_code=error_code)
            else:  # Unix Client
                pair.close_sockets()
                match error_code:
                    case ErrorCodes.INTERFACE_EXISTS:
                        upgrade_subparser.error(str(ArgumentError(interface_argument, text[16:])))  # exit code 2
                    case ErrorCodes.CONFIG_PATH_ERROR:
                        cls.send_error_message(local_message=text, send_to_local=False, exit_code=3)
                    case ErrorCodes.TS_UNREACHABLE:
                        cls.send_error_message(local_message=text, send_to_local=False, exit_code=4)
                    case ErrorCodes.HANDSHAKE_MISMATCH:
                        cls.send_error_message(local_message=text, send_to_local=False, exit_code=5)
                    case _:
                        cls.send_error_message(local_message=text, send_to_local=False, exit_code=1)

    @classmethod
    def send_error_message(cls, local_message: str = None, remote_message: str = None, error_code: ErrorCodes = ErrorCodes.GENERIC, remote_code: ErrorCodes = ErrorCodes.GENERIC,
                           send_to_local: bool = True, always_send_to_remote: bool = True, exit_code: int | None = 1):
        pair = CONNECTION_PAIRS.get(get_ident())
        if pair is not None and pair.token is not None:
            local_message = Messages.add_id(pair.id, local_message) if local_message is not None else None
            remote_message = Messages.add_id(pair.id, remote_message) if remote_message is not None else None
        if local_message is not None:
            print(local_message, file=sys.stderr, flush=True)
        if pair is not None:
            if pair.local_socket is not None and local_message is not None and not pair.running_in_remote and send_to_local:
                local_message = cls.build_error_message(local_message, error_code)
                pair.send_to_local(json.dumps(local_message))
            if pair.remote_socket is not None and remote_message is not None and (pair.running_in_remote or always_send_to_remote):
                remote_message = cls.build_error_message(remote_message, remote_code)
                pair.send_to_remote(json.dumps(remote_message))
            pair.close_sockets()
        if exit_code is not None:
            sys.exit(exit_code)
