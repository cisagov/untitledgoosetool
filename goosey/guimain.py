#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Guimain!
This module makes a nice GUI."""

"""Modifications made by the Cybersecurity and Infrastructure Agency (CISA)
 and are excluded from US domestic copyright under 17 USC 107. No domestic or international rights reserved."""

import sys
from itertools import chain

from copy import deepcopy

from gooey.util.functional import compact

from gooey.gui import cli as gooey_gui_cli
from goosey.main import main as gooseymain

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

try:
    from gooey import Gooey, GooeyParser
except ModuleNotFoundError as e:
    print("No Gooey module found, running in terminal mode.")
    def Gooey(*args, **kwargs):
        def wrapper(func):
            return func
        return wrapper

def __buildCliString(target, cmd, positional, optional, suppress_gooey_flag=False):
    positionals = deepcopy(positional)
    if positionals:
        positionals.insert(0, "--")

    cmd_string = ' '.join(compact(chain(optional, positionals)))

    if cmd != '::gooey/default':
        cmd_string = u'{} {}'.format(cmd, cmd_string)

    ignore_flag = '' if suppress_gooey_flag else '--ignore-gooey'

    if sys.platform == 'win32':
        return u'{}.exe {} {}'.format(target, ignore_flag, cmd_string)
    else:
        return u'{} {} {}'.format(target, ignore_flag, cmd_string)

setattr(gooey_gui_cli, "buildCliString", __buildCliString)

@Gooey(navigation='TABBED', 
    default_size=(1000, 800),
    program_name="Untitled Goose Tool",
    show_stop_warning=True,
    force_stop_is_error=True,
    show_success_modal=True,
    use_cmd_args=True,
    body_bg_color='#282828',
    header_bg_color='#181818',
    footer_bg_color='#181818',
    option_label_color='#d6d6d6',
    richtext_controls=True)

def main():  
    gooseymain()

if __name__ == '__main__':
    main()
