#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Main!
"""

import argparse
import sys

from goosey.auth import Authentication
from goosey.graze import getargs as getgrazeargs
from goosey.honk import getargs as gethonkargs
from goosey.d4iot import getargs as getd4iotargs
from goosey.messagetrace import getargs as getmsgtrcargs
from goosey.csv import getargs as getcsvargs

GOOSEY_HELP = '''Untitled Goose Tool: Goosey

To get started, use one of the subcommands. Each command has a help feature (goosey <command> -h).

1. Authenticate to Azure AD
goosey auth

1a (optional). Gather UAL time bound info
goosey graze

2. Gather all information
goosey honk

2a (optional but highly encouraged). Create csv files mapping GUIDs to text
goosey csv

3. Gather message trace information
goosey messagetrace
'''

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

def main():
    # Primary argument parser
    parser = argparse.ArgumentParser(add_help=True, description=GOOSEY_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # Add subparsers for modules
    subparsers = parser.add_subparsers(dest='command')

    # Construct Goosey Authentication module options
    auth = Authentication()
    auth_parser = subparsers.add_parser('auth', help='Authenticate to Azure AD Graph, Microsoft Graph')
    auth.get_sub_argparse(auth_parser)

    # Construct Goosey Graze module options
    graze_parser = subparsers.add_parser('graze', help='Get UAL timebounds for optimal runtime and efficiency.')
    getgrazeargs(graze_parser)

    # Construct Goosey Honk module options
    honk_parser = subparsers.add_parser('honk', help='Gather Azure, Azure AD, and M365 information')
    gethonkargs(honk_parser)

    # Construct Goosey MessageTrace module options
    messagetrace_parser = subparsers.add_parser('messagetrace', help='Submit and export message trace reports')
    getmsgtrcargs(messagetrace_parser)

    # Construct Goosey d4iot module options
    d4iot_parser = subparsers.add_parser('d4iot', help='Gather d4iot information')
    getd4iotargs(d4iot_parser)

    # Construct Goosey csv module options
    csv_parser = subparsers.add_parser('csv', help='Create CSVs converting GUIDs to text')
    getcsvargs(csv_parser)

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    if args.command == 'auth':
        auth.parse_args(args)
        if args.revoke:
            auth.revoke_tokens(args)
        if args.d4iot:
            auth.d4iot_auth()
        else:
            auth.ugt_auth()
    elif args.command == 'honk':
        from goosey.honk import main as honkmain
        honkmain(args)
    elif args.command == 'graze':
        from goosey.graze import main as grazemain
        grazemain(args)
    elif args.command == 'messagetrace':
        from goosey.messagetrace import main as messagetracemain
        messagetracemain(args)
    elif args.command == 'd4iot':
        from goosey.d4iot import main as d4iotmain
        d4iotmain(args)
    elif args.command == 'csv':
        from goosey.csv import main as csvmain
        csvmain(args)
if __name__ == '__main__':
    main()
