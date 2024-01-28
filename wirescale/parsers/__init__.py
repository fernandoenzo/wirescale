#!/usr/bin/env python3
# encoding:utf-8


from wirescale.parsers.args import ARGS, parse_args
from wirescale.parsers.parsers import top_parser, subparsers, daemon_subparser, upgrade_subparser
from wirescale.parsers.utils import sort_argparse_help

sort_argparse_help(top_parser)
sort_argparse_help(subparsers)
sort_argparse_help(daemon_subparser)
sort_argparse_help(upgrade_subparser)
