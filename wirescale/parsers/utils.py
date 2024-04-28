#!/usr/bin/env python3
# encoding:utf-8


import textwrap
from argparse import _SubParsersAction, ArgumentParser, RawTextHelpFormatter
from typing import Union


class CustomArgumentFormatter(RawTextHelpFormatter):
    # https://stackoverflow.com/a/65891304
    """Formats argument help which maintains line length restrictions as well as appends default value if present."""

    def _split_lines(self, text, width):
        text = super()._split_lines(text, width)
        new_text = []

        # loop through all the lines to create the correct wrapping for each line segment.
        for line in text:
            if not line:
                # this would be a new line.
                new_text.append(line)
                continue

            # wrap the line's help segment which preserves new lines but ensures line lengths are
            # honored
            new_text.extend(textwrap.wrap(line, width))

        return new_text


def sort_argparse_help(parser: Union[ArgumentParser, _SubParsersAction]):
    if isinstance(parser, _SubParsersAction):
        parser._choices_actions.sort(key=lambda x: x.dest)
    else:
        for g in parser._action_groups:
            g._group_actions.sort(key=lambda x: x.dest)
