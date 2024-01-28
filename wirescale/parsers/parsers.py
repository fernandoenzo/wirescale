#!/usr/bin/env python3
# encoding:utf-8


from argparse import ArgumentParser

from wirescale.parsers.utils import CustomArgumentFormatter
from wirescale.parsers.validators import check_peer, interface_name_validator
from wirescale.version import version_msg

top_parser = ArgumentParser(prog='wirescale', description='Upgrade your existing Tailscale connection by transitioning to pure WireGuard', formatter_class=CustomArgumentFormatter)
subparsers = top_parser.add_subparsers(dest='opt')

daemon_subparser = subparsers.add_parser('daemon', help='options for systemd to manage the daemon', description='Options for systemd to manage the daemon', formatter_class=CustomArgumentFormatter)
group = daemon_subparser.add_mutually_exclusive_group(required=True)
group.add_argument('--start', help="start the daemon if it's not already running", action='store_true', required=False)
group.add_argument('--stop', help="stop the deaemon if it's running", action='store_true', required=False)
daemon_subparser.add_argument('--no-suffix', action='store_true',
                              help='disables the default behavior of appending a numeric suffix to interface names when they already exist')

upgrade_subparser = subparsers.add_parser('upgrade', help='duplicates a Tailscale connection with pure WireGuard', formatter_class=CustomArgumentFormatter)
upgrade_subparser.add_argument('peer', type=check_peer, help='either the IP address or the Tailscale name of the peer you want to connect to')
config_argument = upgrade_subparser.add_argument('--config', '-c', metavar='wgconf',
                                                 help='path to a WireGuard config template.\n'
                                                      'Defaults to /etc/wirescale/{peername}.conf\n')
upgrade_subparser.add_argument('--disable-autoremove', action='store_true',
                               help='prevents automatic removal of the WireGuard interface if connection is permanently lost')
interface_argument = upgrade_subparser.add_argument('--interface', '-i', metavar='iface', type=interface_name_validator,
                                                    help='interface name that WireGuard will set up. Defaults to {peername}')

top_parser.add_argument('--version', '-v', help='print version information and exit', action='version', version=version_msg)
