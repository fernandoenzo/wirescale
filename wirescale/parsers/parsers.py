#!/usr/bin/env python3
# encoding:utf-8


from argparse import ArgumentParser, BooleanOptionalAction

from wirescale.parsers.utils import CustomArgumentFormatter
from wirescale.parsers.validators import check_existing_conf, check_existing_conf_and_systemd, check_peer, interface_name_validator
from wirescale.version import version_msg

top_parser = ArgumentParser(prog='wirescale', description='Upgrade your existing Tailscale connection by transitioning to pure WireGuard', formatter_class=CustomArgumentFormatter)
subparsers = top_parser.add_subparsers(dest='opt')

daemon_subparser = subparsers.add_parser('daemon', help='commands for systemd to manage the daemon', description='Commands for systemd to manage the daemon', formatter_class=CustomArgumentFormatter)
order_subparser = daemon_subparser.add_subparsers(dest='command', required=True)
order_subparser.add_parser('start', help="start the daemon. Must be run by systemd", add_help=False)
order_subparser.add_parser('stop', help="stop the daemon. Must be run with sudo", add_help=False)
daemon_subparser.add_argument('--no-suffix', action='store_true', help='prevent numeric suffix addition to existing interface names during new ones setup')

down_subparser = subparsers.add_parser('down', help='deactivates a WireGuard interface set up by wirescale', formatter_class=CustomArgumentFormatter)
down_subparser.add_argument('interface', type=check_existing_conf, help="shortcut for 'wg-quick down /run/wirescale/{interface}.conf'")

upgrade_subparser = subparsers.add_parser('upgrade', help='duplicates a Tailscale connection with pure WireGuard', formatter_class=CustomArgumentFormatter)
upgrade_subparser.add_argument('peer', type=check_peer, help='either the Tailscale IP address or the name of the peer you want to connect to')
config_argument = upgrade_subparser.add_argument('--config', '-c', metavar='wgconf',
                                                 help='path to a WireGuard config template.\n'
                                                      'Defaults to /etc/wirescale/{peername}.conf\n')
upgrade_subparser.add_argument('--suffix', action=BooleanOptionalAction, default=True,
                               help='add numeric suffix to new interfaces with existing names.\n'
                                    'Enabled by default')
interface_argument = upgrade_subparser.add_argument('--interface', '-i', metavar='iface', type=interface_name_validator,
                                                    help='interface name that WireGuard will set up. Defaults to {peername}')

recover_subparser = subparsers.add_parser('recover', help='recover a dropped connection by forcing a new hole punching', formatter_class=CustomArgumentFormatter)
recover_subparser.add_argument('interface', type=check_existing_conf_and_systemd, help='local WireGuard interface to recover')

top_parser.add_argument('--version', '-v', help='print version information and exit', action='version', version=version_msg)
