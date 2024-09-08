#!/usr/bin/env python3
# encoding:utf-8


from argparse import ArgumentParser, BooleanOptionalAction

from wirescale.parsers.utils import CustomArgumentFormatter
from wirescale.parsers.validators import check_existing_conf, check_existing_conf_and_systemd, check_peer, check_positive, interface_name_validator
from wirescale.version import version_msg

top_parser = ArgumentParser(prog='wirescale', description='Upgrade your existing Tailscale connection by transitioning to pure WireGuard', formatter_class=CustomArgumentFormatter)
subparsers = top_parser.add_subparsers(dest='opt')

daemon_subparser = subparsers.add_parser('daemon', help='commands for systemd to manage the daemon', description='Commands for systemd to manage the daemon', formatter_class=CustomArgumentFormatter)
order_subparser = daemon_subparser.add_subparsers(dest='command', required=True)
order_subparser.add_parser('start', help="start the daemon. Must be run by systemd", add_help=False)
order_subparser.add_parser('stop', help="stop the daemon. Must be run with sudo", add_help=False)
daemon_subparser.add_argument('--iptables', action=BooleanOptionalAction,
                              help='add iptables rules that allow incoming traffic through new network interfaces. Use this only if the connection is unstable.\n'
                                   'Disabled by default')
daemon_subparser.add_argument('--suffix', action=BooleanOptionalAction,
                              help='add numeric suffix to new interfaces with existing names.\n'
                                   'Disabled by default')

down_subparser = subparsers.add_parser('down', help='deactivates a WireGuard interface set up by wirescale', formatter_class=CustomArgumentFormatter)
down_subparser.add_argument('interface', type=check_existing_conf, help="shortcut for 'wg-quick down /run/wirescale/{interface}.conf'")

upgrade_subparser = subparsers.add_parser('upgrade', help='duplicates a Tailscale connection with pure WireGuard', formatter_class=CustomArgumentFormatter)
upgrade_subparser.add_argument('peer', type=check_peer, help='either the Tailscale IP address or the name of the peer you want to connect to')
upgrade_subparser.add_argument('--iptables', action=BooleanOptionalAction,
                               help='add iptables rules that allow incoming traffic through the new network interface. Use this only if the connection is unstable.\n'
                                    'Disabled by default')
upgrade_subparser.add_argument('--suffix', action=BooleanOptionalAction,
                               help='add numeric suffix to new interfaces with existing names.\n'
                                    'Disabled by default')
upgrade_subparser.add_argument('--suffix-number', type=check_positive, metavar='N',
                               help='append this numeric suffix to the interface name.\n'
                                    'Intended for internal use only')
interface_argument = upgrade_subparser.add_argument('--interface', '-i', metavar='iface', type=interface_name_validator,
                                                    help='interface name that WireGuard will set up. Defaults to {peername}')
upgrade_subparser.add_argument('--remote-interface', metavar='r_iface',
                               help='expected remote interface name. If the remote peer does not use this interface name, the connection attempt will be aborted.\n'
                                    'Intended for internal use only')
upgrade_subparser.add_argument('--recover-tries', type=int, metavar='N',
                               help='number of automatic recovery attempts if the connection drops, before the network interface is brought down. '
                                    'Negative values indicate unlimited attempts.\nDefault is 3')
upgrade_subparser.add_argument('--recreate-tries', type=int, metavar='N',
                               help='number of tries to create a new tunnel if the network interface was brought down after failing at recovering it. '
                                    'Negative values indicate unlimited retries.\nDefault is 0')

recover_subparser = subparsers.add_parser('recover', formatter_class=CustomArgumentFormatter,
                                          help='recover a dropped connection by forcing a new hole punching.\nIntended for internal use only')
recover_subparser.add_argument('interface', type=check_existing_conf_and_systemd, help='local WireGuard interface to recover')

top_parser.add_argument('--version', '-v', help='print version information and exit', action='version', version=version_msg)
