#!/usr/bin/env python3
# encoding:utf-8


import json
import os
import sys
from enum import auto, IntEnum, StrEnum, unique
from subprocess import CompletedProcess
from threading import get_ident
from typing import TYPE_CHECKING

from wirescale.communications.checkers import check_recover_config
from wirescale.communications.common import BytesStrConverter, CONNECTION_PAIRS

if TYPE_CHECKING:
    from wirescale.vpn.recover import RecoverConfig
    from wirescale.vpn.wgconfig import WGConfig


@unique
class MessageFields(StrEnum):
    ADDRESSES = auto()
    AUTOREMOVE = auto()
    CODE = auto()
    CONFIG = auto()
    ENCRYPTED = auto()
    ERROR_CODE = auto()
    ERROR_MESSAGE = auto()
    HAS_PSK = auto()
    INTERFACE = auto()
    LATEST_HANDSHAKE = auto()
    MESSAGE = auto()
    NONCE = auto()
    PEER_IP = auto()
    PORT = auto()
    PSK = auto()
    PUBKEY = auto()
    REMOTE_INTERFACE = auto()
    REMOTE_PORT = auto()
    REMOTE_PUBKEY = auto()
    START_TIME = auto()
    SUFFIX = auto()
    WG_IP = auto()


class ActionCodes(IntEnum):
    ACK = auto()
    GO = auto()
    INFO = auto()
    RECOVER = auto()
    RECOVER_RESPONSE = auto()
    STOP = auto()
    SUCCESS = auto()
    UPGRADE = auto()
    UPGRADE_RESPONSE = auto()


class ErrorCodes(IntEnum):
    CLOSED = auto()
    CONFIG_PATH_ERROR = auto()
    FINAL_ERROR = auto()
    GENERIC = auto()
    HANDSHAKE_MISMATCH = auto()
    INTERFACE_EXISTS = auto()
    TS_UNREACHABLE = auto()


class UnixMessages:
    STOP_MESSAGE = {MessageFields.CODE: ActionCodes.STOP, MessageFields.ERROR_CODE: None}

    @staticmethod
    def build_upgrade_option(args) -> dict:
        res = {
            MessageFields.CODE: ActionCodes.UPGRADE,
            MessageFields.ERROR_CODE: None,
            MessageFields.AUTOREMOVE: args.AUTOREMOVE,
            MessageFields.CONFIG: args.CONFIGFILE,
            MessageFields.INTERFACE: args.INTERFACE,
            MessageFields.PEER_IP: str(args.PAIR.peer_ip),
            MessageFields.SUFFIX: args.SUFFIX,
        }
        return res

    @staticmethod
    def build_upgrade_result(wgquick: CompletedProcess[str], interface: str) -> dict:
        res = {}
        if wgquick.returncode == 0:
            res[MessageFields.CODE] = ActionCodes.SUCCESS
            res[MessageFields.ERROR_CODE] = None
            res[MessageFields.INTERFACE] = interface
        else:
            res[MessageFields.CODE] = None
            res[MessageFields.ERROR_CODE] = ErrorCodes.FINAL_ERROR
            res[MessageFields.ERROR_MESSAGE] = wgquick.stdout.strip()
        return res

    @staticmethod
    def build_recover(recover: 'RecoverConfig') -> dict:
        res = {
            MessageFields.CODE: ActionCodes.RECOVER,
            MessageFields.ERROR_CODE: None,
            MessageFields.INTERFACE: recover.interface,
            MessageFields.LATEST_HANDSHAKE: recover.latest_handshake,
            MessageFields.PEER_IP: str(CONNECTION_PAIRS[get_ident()].peer_ip),
        }
        return res


class TCPMessages:

    @staticmethod
    def build_upgrade(wgconfig: 'WGConfig') -> dict:
        res = {
            MessageFields.CODE: ActionCodes.UPGRADE,
            MessageFields.ERROR_CODE: None,
            MessageFields.ADDRESSES: [str(ip) for ip in wgconfig.addresses],
            MessageFields.HAS_PSK: wgconfig.has_psk,
            MessageFields.INTERFACE: wgconfig.interface,
            MessageFields.PORT: wgconfig.listen_port,
            MessageFields.PSK: wgconfig.psk if not wgconfig.has_psk else None,
            MessageFields.PUBKEY: wgconfig.public_key,
            MessageFields.REMOTE_PUBKEY: wgconfig.remote_pubkey,
        }
        return res

    @staticmethod
    def build_upgrade_response(wgconfig) -> dict:
        res = {
            MessageFields.CODE: ActionCodes.UPGRADE_RESPONSE,
            MessageFields.ERROR_CODE: None,
            MessageFields.ADDRESSES: [str(ip) for ip in wgconfig.addresses],
            MessageFields.INTERFACE: wgconfig.interface,
            MessageFields.PORT: wgconfig.listen_port,
            MessageFields.PUBKEY: wgconfig.public_key,
            MessageFields.START_TIME: wgconfig.start_time,
        }
        return res

    @staticmethod
    def build_go() -> dict:
        res = {
            MessageFields.CODE: ActionCodes.GO,
            MessageFields.ERROR_CODE: None,
        }
        return res

    @staticmethod
    def build_recover(recover: 'RecoverConfig') -> dict:
        res = {
            MessageFields.CODE: ActionCodes.RECOVER,
            MessageFields.ERROR_CODE: None,
            MessageFields.INTERFACE: recover.remote_interface,
            MessageFields.NONCE: BytesStrConverter.raw_bytes_to_str64(recover.nonce),
        }
        encrypted = {
            MessageFields.LATEST_HANDSHAKE: recover.latest_handshake,
            MessageFields.PORT: recover.remote_port,
            MessageFields.REMOTE_INTERFACE: recover.interface,
            MessageFields.REMOTE_PORT: recover.new_port,
        }
        encrypted = json.dumps(encrypted)
        res[MessageFields.ENCRYPTED] = recover.encrypt(encrypted)
        return res

    @staticmethod
    def build_recover_response(recover: 'RecoverConfig') -> dict:
        recover.nonce = os.urandom(12)
        res = {
            MessageFields.CODE: ActionCodes.RECOVER_RESPONSE,
            MessageFields.ERROR_CODE: None,
            MessageFields.NONCE: BytesStrConverter.raw_bytes_to_str64(recover.nonce),
        }
        encrypted = {
            MessageFields.REMOTE_PORT: recover.new_port,
            MessageFields.START_TIME: recover.start_time,
        }
        encrypted = json.dumps(encrypted)
        res[MessageFields.ENCRYPTED] = recover.encrypt(encrypted)
        return res

    @staticmethod
    def process_recover(message: dict) -> 'RecoverConfig':
        pair = CONNECTION_PAIRS[get_ident()]
        interface = message[MessageFields.INTERFACE]
        latest_handshake = message[MessageFields.LATEST_HANDSHAKE]
        recover = RecoverConfig.create_from_autoremove(interface=interface, latest_handshake=latest_handshake)
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
        recover.remote_port = message[MessageFields.REMOTE_PORT]
        recover.remote_interface = message[MessageFields.REMOTE_INTERFACE]
        check_recover_config(recover)
        return recover

    @staticmethod
    def process_recover_response(message: dict, recover: 'RecoverConfig'):
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
        recover.remote_port = message[MessageFields.REMOTE_PORT]
        recover.start_time = message[MessageFields.START_TIME]


class Messages:
    CHECKING_ENDPOINT = "Checking that an endpoint is available for peer '{peer_name}' ({peer_ip})..."
    CONNECTING_UNIX = 'Connecting to local UNIX socket...'
    CONNECTED_UNIX = 'Connection to local UNIX socket established'
    ENQUEUEING_FROM = "Enqueueing upgrade request coming from peer '{peer_name}' ({peer_ip})..."
    ENQUEUEING_REMOTE = "Remote peer '{sender_name}' ({sender_ip}) has enqueued our upgrade request"
    ENQUEUEING_TO = "Enqueueing upgrade request to peer '{peer_name}' ({peer_ip})..."
    ENQUEUEING_RECOVER = "Enqueueing recover request to peer '{peer_name}' ({peer_ip}) for interface '{interface}'..."
    NEW_UNIX_INCOMING = 'New local UNIX connection incoming'
    REACHABLE = "Peer '{peer_name}' ({peer_ip}) is reachable"
    RECOVER_SUCCES = "Success! WireGuard connection through interface '{interface}' is working again"
    SHUTDOWN_SET = 'The server has been set to shut down'
    START_PROCESSING_FROM = "Starting to process the {action} request coming from peer '{peer_name}' ({peer_ip})"
    START_PROCESSING_REMOTE = "Remote peer '{sender_name}' ({sender_ip}) has started to process our {action} request"
    START_PROCESSING_TO = "Starting to process the upgrade request for the peer '{peer_name}' ({peer_ip})"
    START_PROCESSING_RECOVER = "Starting to process the recover request for the peer '{peer_name}' ({peer_ip}) for interface '{interface}'"
    SUCCESS = "Success! Now you have a new working P2P connection through interface '{interface}'"

    @staticmethod
    def build_info_message(info_message: str, code: ActionCodes = ActionCodes.INFO) -> dict:
        res = {
            MessageFields.CODE: code,
            MessageFields.ERROR_CODE: None,
            MessageFields.MESSAGE: info_message
        }
        return res

    @classmethod
    def send_info_message(cls, local_message: str, remote_message: str = None, code: ActionCodes = ActionCodes.INFO, always_send_to_remote: bool = True):
        pair = CONNECTION_PAIRS.get(get_ident())
        if local_message is not None:
            print(local_message, flush=True)
        if pair is not None:
            if pair.local_socket is not None and local_message is not None:
                local_message = cls.build_info_message(local_message, code)
                pair.local_socket.send(json.dumps(local_message))
            if pair.remote_socket is not None and remote_message is not None and (always_send_to_remote or pair.running_in_remote):
                remote_message = cls.build_info_message(remote_message, code)
                pair.remote_socket.send(json.dumps(remote_message))


class ErrorMessages:
    ALLOWED_IPS_MISMATCH = "Error: IPs from the 'Address' field of '{sender_name}' ({sender_ip}) are not fully covered in the 'AllowedIPs' field of '{my_name}' ({my_ip})"
    BAD_FORMAT_PRIVKEY = "Error: The private key has not the correct length or format in file '{config_file}'"
    BAD_FORMAT_PSK = "Error: The pre-shared key has not the correct length or format in file '{config_file}'"
    BAD_FORMAT_PUBKEY = "Error: The public key has not the correct length or format in file '{config_file}'"
    CANT_DECRYPT = "Error: Couldn't decrypt the recover message sent by remote peer '{peer_name}' ({peer_ip})"
    CLOSED = 'Error: Wirescale is shutting down and is no longer accepting new requests'
    FINAL_ERROR = 'Something went wrong and, finally, it was not possible to establish the P2P connection'
    HANDSHAKE_FAILED = "Handshake with interface '{interface}' failed after changing its endpoint. Interface will be removed"
    INTERFACE_EXISTS = "Error: A network interface '{interface}' already exists and Wirescale was started with the --no-suffix option"
    IP_MISMATCH = "Error: Remote peer '{peer_name}' ({peer_ip}) IP address mismatch with the 'autoremove-{interface}' systemd unit's registered IP ({autoremove_ip})"
    LATEST_HANDSHAKE_MISMATCH = "Error: The latest handshake of interface '{interface}' has been updated since the recover request was made. Discarding request"
    MISSING_ADDRESS = "Error: 'Address' option missing in 'Interface' section of file '{config_file}'"
    MISSING_ALLOWEDIPS = "Error: 'AllowedIPs' option missing in 'Peer' section of file '{config_file}'"
    MISSING_AUTOREMOVE = "Error: systemd unit 'autoremove-{interface}' is not active"
    PORT_MISMATCH = "Error: WireGuard interface '{interface}' is not listening on port {port}"
    PSK_MISMATCH = ("Error: Peer '{name_without_psk}' ({ip_without_psk}) does not have a pre-shared key for '{name_with_psk}' ({ip_with_psk}), but '{name_with_psk}' has one configured for "
                    "'{name_without_psk}'. Ensure key consistency.")
    PUBKEY_MISMATCH = "Error: The public key provided by '{sender_name}' ({sender_ip}) is inconsistent with the one that '{receiver_name}' ({receiver_ip}) has on record for this peer."
    RECOVER_SYSTEMD = "Error: The 'recover' option can only be invoked by the Wirescale shell script"
    REMOTE_BAD_FORMAT_PRIVKEY = "Error: The private key has not the correct length or format in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_BAD_FORMAT_PSK = "Error: The pre-shared key has not the correct length or format in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_BAD_FORMAT_PUBKEY = "Error: The public key has not the correct length or format in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_CANT_DECRYPT = "Error: Remote peer '{my_name}' ({my_ip}) couldn't decrypt our recover message"
    REMOTE_CLOSED = "Error: Wirescale instance at '{my_name}' ({my_ip}) has been set to stop receiving requests"
    REMOTE_CONFIG_ERROR = "Error: Remote peer '{my_name}' ({my_ip}) has a syntax error in its configuration file for '{peer_name}'"
    REMOTE_CONFIG_PATH_ERROR = "Error: Remote peer '{my_name}' ({my_ip}) cannot locate a configuration file for '{peer_name}'"
    REMOTE_INTERFACE_EXISTS = "Error: A network interface '{interface}' already exists on peer '{my_name}' ({my_ip}) and its Wirescale was started with the --no-suffix option"
    REMOTE_IP_MISMATCH = "Error: Remote peer '{my_name}' ({my_ip}) has registered a different IP address in its 'autoremove-{interface}' systemd unit than ours ({peer_ip})"
    REMOTE_LATEST_HANDSHAKE_MISMATCH = ("Error: The latest handshake of remote interface '{interface}' from remote peer '{my_name}' ({my_ip}) has been updated since the recover "
                                        "request was made. Discarding request.")
    REMOTE_MISSING_ADDRESS = "Error: 'Address' option missing in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_MISSING_ALLOWEDIPS = "Error: 'AllowedIPs' option missing in remote peer '{my_name}' ({my_ip}) configuration file for '{peer_name}'"
    REMOTE_MISSING_AUTOREMOVE = "Error: systemd unit 'autoremove-{interface}' is not active in remote peer '{my_name}' ({my_ip})"
    REMOTE_MISSING_WIRESCALE = "Error: Remote peer '{peer_name}' ({peer_ip}) does not have Wirescale running"
    REMOTE_PORT_MISMATCH = "Error: WireGuard interface '{interface}' is not listening on local port {port} in remote peer '{peer_name}' ({peer_ip})"
    REMOTE_RUNFILE_MISSING = "Error: File '/run/wirescale/{interface}.conf' does not exist or is not a regular file in remote peer '{my_name}' ({my_ip})"
    REMOTE_TAILSCALED_STOPPED = "Error: Tailscaled service is not running in remote peer `{peer_name}` ({peer_ip})"
    REMOTE_WG_INTERFACE_MISSING = "Error: Remote peer '{peer_name}' ({peer_ip}) does not have a WireGuard interface named '{interface}'"
    RUNFILE_MISSING = "Error: File '/run/wirescale/{interface}.conf' does not exist or is not a regular file"
    ROOT_SYSTEMD = "Error: Wirescale daemon must be managed by root's systemd"
    SUDO = 'Error: This program must be run as a superuser'
    TS_PEER_OFFLINE = "Error: Peer '{peer_name}' ({peer_ip}) is offline"
    TS_SYSTEMD_STOPPED = "Error: 'tailscaled.service' is stopped. Start the service with systemd"
    TS_STOPPED = "Error: Tailscale is stopped. Run 'sudo tailscale up'"
    TS_NO_ENDPOINT = "Sorry, it was impossible to find a public endpoint for peer `{peer_name}` ({peer_ip})"
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
    def send_error_message(cls, local_message: str = None, remote_message: str = None, error_code: ErrorCodes = ErrorCodes.GENERIC, always_send_to_remote: bool = True, exit_code: int | None = 1):
        pair = CONNECTION_PAIRS.get(get_ident())
        if local_message is not None:
            print(local_message, file=sys.stderr, flush=True)
        if pair is not None:
            if pair.local_socket is not None and local_message is not None:
                local_message = cls.build_error_message(local_message, error_code)
                pair.local_socket.send(json.dumps(local_message))
            if pair.remote_socket is not None and remote_message is not None and (always_send_to_remote or pair.running_in_remote):
                remote_message = cls.build_error_message(remote_message, error_code)
                pair.remote_socket.send(json.dumps(remote_message))
            pair.close_sockets()
        if exit_code is not None:
            sys.exit(exit_code)
