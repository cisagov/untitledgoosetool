#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: D4IOT!
This module performs data collection of Microsoft's Defender for IOT.
"""

import aiohttp
import argparse
import asyncio
import configparser
import json
import os
import sys
import time
import warnings
import getpass

from goosey.datadumper import DataDumper
from goosey.d4iot_dumper import DefenderIoTDumper
from goosey.utils import *

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

warnings.simplefilter('ignore')

logger = None
data_calls = {}
encryption_pw = None

def getargs(d4iot_parser) -> None:
    """Helper function to build arguments for argparse

    :param d4iot_parser: parser which will perform command line argument parsing
    :type d4iot_parser: argparse.ArgumentParser
    :return: None
    :rtype: None
    """
    d4iot_parser.add_argument('-a',
                               '--authfile',
                               action='store',
                               help='File to read credentials from obtained by goosey auth',
                               default='.d4iot_auth')
    d4iot_parser.add_argument('-c',
                               '--config',
                               action='store',
                               help='Path to config file',
                               default='.d4iot_conf')
    d4iot_parser.add_argument('-ac',
                               '--auth',
                               action='store',
                               help='Path to config file',
                               default='.auth_d4iot')
    d4iot_parser.add_argument('--output-dir',
                               action='store',
                               help='Output directory for output files',
                               default='output')
    d4iot_parser.add_argument('--reports-dir',
                               action='store',
                               help='Output directory for output files',
                               default='reports')
    d4iot_parser.add_argument('--debug',
                               action='store_true',
                               help='Debug output',
                               default=False)
    d4iot_parser.add_argument('--dry-run',
                               action='store_true',
                               help='Dry run (do not do any API calls)',
                               default=False)

def _get_section_dict(config, s):
    try:
        return dict([(x[0], x[1].lower()=='true') for x in config.items(s)])
    except Exception as e:
        logger.warning(f'Error getting section dictionary from config: {str(e)}')
    return {}

def parse_config(configfile, args, auth=False):
    global data_calls
    config = configparser.ConfigParser()
    config.read(configfile)

    if not auth:
        sections = ['d4iot']
    else:
        sections = ['auth']

    for section in sections:
        d = _get_section_dict(config, section)
        data_calls[section] = {}
        for key in d:
            if d[key]:
                data_calls[section][key] = True

    if not auth:
        logger.debug(json.dumps(data_calls, indent=2))
    return config


async def run(args, config, auth, auth_un_pw=None):
    """Main async run loop

    :param args: argparse object with populated namespace
    :type args: Namespace argparse object
    :param auth: All auth credentials
    :type auth: dict
    :return: None
    :rtype: None
    """
    global data_calls, logger

    session = aiohttp.ClientSession(trust_env=True)
    sessionid = None
    csrftoken = None

    for key in auth['sensor']:
        if 'csrftoken' in key:
            csrftoken = auth['sensor']['csrftoken']
        if 'sessionId' in key:
            sessionid = auth['sensor']['sessionId']

    maindumper = DataDumper(args.output_dir, args.reports_dir, csrftoken, sessionid, session, args.debug)

    if args.dry_run:
        d4iot_dumper = maindumper
    else:
        d4iot_dumper = DefenderIoTDumper(args.output_dir, args.reports_dir, maindumper.ahsession, csrftoken, sessionid, config, auth_un_pw, args.debug)

    async with maindumper.ahsession as ahsession:
        tasks = []
        tasks.extend(d4iot_dumper.data_dump(data_calls['d4iot']))
        await asyncio.gather(*tasks)

def main(args=None) -> None:
    global logger, encryption_pw

    parser = argparse.ArgumentParser(add_help=True, description='Goosey', formatter_class=argparse.RawDescriptionHelpFormatter)

    getargs(parser)

    if args is None:
        args = parser.parse_args()

    logger = setup_logger(__name__, args.debug)

    auth_un_pw, auth = get_authfile(authfile=args.auth, ugt_authfile=args.authfile, logger=logger)

    check_output_dir(args.output_dir, logger)
    check_output_dir(args.reports_dir, logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}d4iot', logger)
    config = parse_config(args.config, args)

    logger.info("Goosey beginning to honk.")
    seconds = time.perf_counter()
    asyncio.run(run(args, config, auth, auth_un_pw))
    elapsed = time.perf_counter() - seconds
    logger.info("Goosey executed in {0:0.2f} seconds.".format(elapsed))

def d4iot(authfile=".d4iot_auth",
          config=".d4iot_conf",
          auth=".auth_d4iot",
          output_dir="output",
          reports_dir="reports",
          debug=False,
          dry_run=False):
    """
    Gather d4iot Information

    Args:
       authfile: File to read credentials from obtained by goosey auth
       config: Path to config file
       auth: Path to d4iot creds used for auth
       output_dir: Output directory for output files
       reports_dir: Output directory for report files
       debug: Debug output
       dry_run: Dry run (do not do any API calls)
    """
    args = dict2obj(locals())
    main(args)

if __name__ == "__main__":
    main()
