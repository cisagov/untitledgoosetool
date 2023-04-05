#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Guimain!
This module makes a nice GUI.
"""

from goosey.main import main as gooseymain

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.1.0"

try:
    from gooey import Gooey, GooeyParser
except ModuleNotFoundError as e:
    print("No Gooey module found, running in terminal mode.")
    def Gooey(*args, **kwargs):
        def wrapper(func):
            return func
        return wrapper

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
