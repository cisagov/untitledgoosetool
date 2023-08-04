#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Honk!
This module performs data collection of various data sources from an Azure/M365 environment.
"""

from mimetypes import init
import aiohttp
import argparse
import asyncio
import configparser
import getpass
import json
import os
import pyAesCrypt
import sys
import time
import warnings

from goosey.azure_ad_datadumper import AzureAdDataDumper
from goosey.azure_dumper import AzureDataDumper
from goosey.datadumper import DataDumper
from goosey.m365_datadumper import M365DataDumper
from goosey.mde_datadumper import MDEDataDumper
from goosey.utils import *

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

warnings.simplefilter('ignore')

logger = None
data_calls = {}
encryption_pw = None

def getargs(honk_parser) -> None:
    """Helper function to build arguments for argparse

    :param honk_parser: parser which will perform command line argument parsing
    :type honk_parser: argparse.ArgumentParser
    :return: None
    :rtype: None
    """
    honk_parser.add_argument('-a',
                               '--authfile',
                               action='store',
                               help='File to store the authentication tokens and cookies (default: .ugt_auth)',
                               default='.ugt_auth')
    honk_parser.add_argument('-c',
                               '--config',
                               action='store',
                               help='Path to config file (default: .conf)',
                               default='.conf')
    honk_parser.add_argument('-ac',
                               '--auth',
                               action='store',
                               help='File to store the credentials used for authentication (default: .auth)',
                               default='.auth')
    honk_parser.add_argument('--output-dir',
                               action='store',
                               help='Directory for storing the results (default: output)',
                               default='output')
    honk_parser.add_argument('--reports-dir',
                               action='store',
                               help='Directory for storing debugging/informational logs (default: reports)',
                               default='reports')                               
    honk_parser.add_argument('--debug',
                               action='store_true',
                               help='Enable debug logging',
                               default=False)
    honk_parser.add_argument('--dry-run',
                               action='store_true',
                               help='Dry run (do not do any API calls)',
                               default=False)
    honk_parser.add_argument('--azure',
                                action='store_true',
                                help='Set all of the Azure calls to true',
                                default=False)
    honk_parser.add_argument('--ad',
                                action='store_true',
                                help='Set all of the Azure AD calls to true',
                                default=False)   
    honk_parser.add_argument('--m365',
                                action='store_true',
                                help='Set all of the M365 calls to true',
                                default=False)
    honk_parser.add_argument('--mde',
                                action='store_true',
                                help='Set all of the MDE calls to true',
                                default=False)

async def run(args, config, auth, init_sections, auth_un_pw=None):
    """Main async run loop

    :param args: argparse object with populated namespace
    :type args: Namespace argparse object
    :param auth: All token auth credentials
    :type auth: dict
    :return: None
    :rtype: None
    """
    global data_calls, logger

    session = aiohttp.ClientSession()

    msft_graph_auth = {}
    msft_graph_app_auth = {}

    for key in auth['mfa']:
        if 'graph.microsoft.com' in key or 'graph.microsoft.us' in key:
            msft_graph_auth = auth['mfa'][key]        

    for key in auth['app_auth']:
        if 'graph.microsoft.com' in key or 'graph.microsoft.us' in key:
            msft_graph_app_auth = auth['app_auth'][key]
        if 'management.azure.com' in key or 'management.azure.us' in key:
            mgmt_app_auth = auth['app_auth'][key]
        if 'api.securitycenter.microsoft.com' in key or 'api-gcc.securitycenter.microsoft.us' in key or 'api-gov.securitycenter.microsoft.us' in key:
            msft_security_center_auth = auth['app_auth'][key]
        if 'api.security.microsoft.com' in key or 'api-gcc.security.microsoft.us' in key or 'api-gov.security.microsoft.us' in key:
            msft_security_auth = auth['app_auth'][key]

    maindumper = DataDumper(args.output_dir, args.reports_dir, msft_graph_auth, msft_graph_app_auth, session, args.debug)
    
    m365, azuread, azure, mde = False, False, False, False

    if args.dry_run:
        m365dumper = maindumper 
        azureaddumper = maindumper
        azure_dumper = maindumper
        mdedumper = maindumper

    else:
        if 'm365' in init_sections:
            m365dumper = M365DataDumper(args.output_dir, args.reports_dir, msft_graph_auth, msft_graph_app_auth, maindumper.ahsession, config, args.debug)
            m365 = True
        if 'azuread' in init_sections:
            azureaddumper = AzureAdDataDumper(args.output_dir, args.reports_dir, msft_graph_auth, msft_graph_app_auth, maindumper.ahsession, config, args.debug)
            azuread = True
        if 'azure' in init_sections:
            azure_dumper = AzureDataDumper(args.output_dir, args.reports_dir, maindumper.ahsession, mgmt_app_auth, config, auth_un_pw, args.debug)
            azure = True
        if 'mde' in init_sections:
            mdedumper = MDEDataDumper(args.output_dir, args.reports_dir, msft_graph_auth, msft_security_center_auth, msft_security_auth, maindumper.ahsession, config, args.debug)
            mde = True

    async with maindumper.ahsession as ahsession:
        tasks = []
        if m365:
            tasks.extend(m365dumper.data_dump(data_calls['m365']))
        if azuread:
            tasks.extend(azureaddumper.data_dump(data_calls['azuread']))
        if azure:
            tasks.extend(azure_dumper.data_dump(data_calls['azure']))
        if mde:
            tasks.extend(mdedumper.data_dump(data_calls['mde']))

        await asyncio.gather(*tasks)

def _get_section_dict(config, s):
    try:
        return dict([(x[0], x[1].lower()=='true') for x in config.items(s)])
    except Exception as e:
        logger.warning(f'Error getting section dictionary from config: {str(e)}')
    return {}

def parse_config(configfile, args, auth=None):
    global data_calls
    config = configparser.ConfigParser()
    config.read(configfile)

    if not auth:
        sections = ['azure', 'm365', 'azuread', 'mde']
    else:
        sections = ['auth']    

    init_sections = []
    for section in sections:
        d = _get_section_dict(config, section)
        data_calls[section] = {}
        for key in d:
            if d[key]:
                data_calls[section][key] = True
                init_sections.append(section)
    
    if args.azure:
        for item in [x.replace('dump_', '') for x in dir(AzureDataDumper) if x.startswith('dump_')]:
            data_calls['azure'][item] = True
    if args.ad:
        for item in [x.replace('dump_', '') for x in dir(AzureAdDataDumper) if x.startswith('dump_')]:
            data_calls['azuread'][item] = True
    if args.m365:
        for item in [x.replace('dump_', '') for x in dir(M365DataDumper) if x.startswith('dump_')]:
            data_calls['m365'][item] = True
    if args.mde:
        for item in [x.replace('dump_', '') for x in dir(MDEDataDumper) if x.startswith('dump_')]:
            data_calls['mde'][item] = True

    logger.debug(json.dumps(data_calls, indent=2))
    return config, init_sections
        
def main(args=None, gui=False) -> None:
    global logger
    global encryption_pw
    parser = argparse.ArgumentParser(add_help=True, description='Goosey', formatter_class=argparse.RawDescriptionHelpFormatter)

    getargs(parser)

    if args is None:
        args = parser.parse_args()

    if gui:
        logger = setup_logger(__name__, args.debug, formatter='gui')
    else:
        logger = setup_logger(__name__, args.debug)

    auth = {}

    encrypted_auth = False
    encrypted_authfile = False

    dir_path = os.path.dirname(os.path.realpath(args.auth))
    encrypted_auth = os.path.join(dir_path, args.auth + '.aes')

    dir_path = os.path.dirname(os.path.realpath(args.authfile))
    encrypted_authfile = os.path.join(dir_path, args.authfile + '.aes')

    encrypted = False
    encrypted_ugtauth = False

    if os.path.isfile(encrypted_auth):
        encrypted = True
        if encryption_pw is None:
            encryption_pw = getpass.getpass("Please type the password for file encryption: ")

        pyAesCrypt.decryptFile(encrypted_auth, args.auth, encryption_pw)
        os.remove(encrypted_auth)
        logger.debug("Decrypted the " + args.auth + " file!")

    try:
        if os.path.isfile(args.auth):
            logger.info("Reading in auth: {}".format(args.auth))
            with open(args.auth, 'r') as infile:
                auth_un_pw, _ = parse_config(args.auth, args, auth=True)
        else:
            auth_un_pw = None
    except Exception as e:
        logger.error("{}".format(str(e)))
        raise e      

    if encrypted:
        if os.path.isfile(args.auth):
            pyAesCrypt.encryptFile(args.auth, encrypted_auth, encryption_pw)
            os.remove(args.auth)
            logger.debug("Encrypted the " + args.auth + " file!")              

    if os.path.isfile(encrypted_authfile):
        encrypted_ugtauth = True
        if encryption_pw is None:
            encryption_pw = getpass.getpass("Please type the password for file encryption: ")

        pyAesCrypt.decryptFile(encrypted_authfile, args.authfile, encryption_pw)
        os.remove(encrypted_authfile)
        logger.debug("Decrypted the " + args.authfile + " file!")

    if not os.path.isfile(args.authfile):
        logger.warning("{} auth file missing. Please auth first. Exiting.".format(args.authfile))
        sys.exit(1)

    try:
        logger.info("Reading in authfile: {}".format(args.authfile))
        with open(args.authfile, 'r') as infile:
            auth = json.loads(infile.read())
    except Exception as e:
        logger.error("{}".format(str(e)))
        raise e    

    if encrypted_ugtauth:
        if os.path.isfile(args.authfile):
            pyAesCrypt.encryptFile(args.authfile, encrypted_authfile, encryption_pw)
            os.remove(args.authfile)
            logger.debug("Encrypted the " + args.authfile + " file!")    
  
    check_output_dir(args.output_dir, logger)
    check_output_dir(args.reports_dir, logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}azure', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}m365', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}azuread', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}mde', logger)
    config, init_sections = parse_config(args.config, args)

    logger.info("Goosey beginning to honk.")
    seconds = time.perf_counter()
    try:
        asyncio.run(run(args, config, auth, init_sections, auth_un_pw=auth_un_pw))
    except RuntimeError as e:
        sys.exit(1)
    elapsed = time.perf_counter() - seconds
    logger.info("Goosey executed in {0:0.2f} seconds.".format(elapsed))

if __name__ == "__main__":
    main()

