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
import json
import os
import sys
import time
import warnings
from multiprocessing import Process

from goosey.entra_id_datadumper import EntraIdDataDumper
from goosey.azure_dumper import AzureDataDumper
from goosey.datadumper import DataDumper
from goosey.m365_datadumper import M365DataDumper
from goosey.mde_datadumper import MDEDataDumper
from goosey.utils import *
from goosey.auth import auth as gooseyauth

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

warnings.simplefilter('ignore')

logger = None
data_calls = {}

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

    # Set name of current task
    asyncio.current_task().set_name("honk_run")

    session = aiohttp.ClientSession(trust_env=True)

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
        if 'outlook.office365.com' in key or 'outlook.office365.us' in key:
            o365_app_auth = auth['app_auth'][key]

    maindumper = DataDumper(args.output_dir, args.reports_dir, msft_graph_auth, msft_graph_app_auth, session, args.debug)

    m365, entraid, azure, mde = False, False, False, False

    if args.dry_run:
        m365dumper = maindumper
        entraiddumper = maindumper
        azure_dumper = maindumper
        mdedumper = maindumper

    else:
        if 'm365' in init_sections:
            m365dumper = M365DataDumper(args.output_dir, args.reports_dir, msft_graph_auth, msft_graph_app_auth, maindumper.ahsession, config, args.debug, o365_app_auth)
            m365 = True
        if 'entraid' in init_sections:
            entraiddumper = EntraIdDataDumper(args.output_dir, args.reports_dir, msft_graph_auth, msft_graph_app_auth, maindumper.ahsession, config, args.debug)
            entraid = True
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
        if entraid:
            tasks.extend(entraiddumper.data_dump(data_calls['entraid']))
        if azure:
            tasks.extend(azure_dumper.data_dump(data_calls['azure']))
        if mde:
            tasks.extend(mdedumper.data_dump(data_calls['mde']))

        honk_results = await asyncio.gather(*tasks)
        error_occured = False
        for class_name, func_name, err in honk_results:
            if err:
                logger.error(f"[{class_name}] {func_name[5:]}: Failed with error {err}")
                error_occured = True
            else:
                logger.info(f"[{class_name}] {func_name[5:]}: Success")
        if error_occured:
            sys.exit(1)

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
        sections = ['azure', 'm365', 'entraid', 'mde']
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
    if args.entraid:
        for item in [x.replace('dump_', '') for x in dir(EntraIdDataDumper) if x.startswith('dump_')]:
            data_calls['entraid'][item] = True
    if args.m365:
        for item in [x.replace('dump_', '') for x in dir(M365DataDumper) if x.startswith('dump_')]:
            data_calls['m365'][item] = True
    if args.mde:
        for item in [x.replace('dump_', '') for x in dir(MDEDataDumper) if x.startswith('dump_')]:
            data_calls['mde'][item] = True

    logger.debug(json.dumps(data_calls, indent=2))
    return config, init_sections

def honk(authfile=".ugt_auth",
         config=".conf",
         auth=".auth",
         output_dir="output",
         reports_dir="reports",
         debug=False,
         dry_run=False,
         azure=False,
         entraid=False,
         m365=False,
         mde=False,
         encryption_pw=None):
    """
    Untitled Goose Tool Information Gathering

    Args:
        authfile: File to store the authentication tokens and cookies
        config: Path to config file
        auth: File to store the credentials used for authentication
        output_dir: Directory for storing the results
        reports_dir: Directory for storing debugging/informational logs
        debug: Enable debug logging
        dry_run: Dry run (do not do any API calls)
        azure: Set all of the Azure calls to true
        entraid: Set all of the Entra ID calls to true
        m365: Set all of the M365 calls to true
        mde: Set all of the MDE calls to true
        encryption_pw: Password for the auth file encryption. SHOULD ONLY BE USED WITH AUTOHONK
    """
    global logger
    args = dict2obj(locals())

    logger = setup_logger(__name__, args.debug)

    auth_un_pw, auth = get_authfile(authfile=args.auth, ugt_authfile=args.authfile, logger=logger, encryption_pw=encryption_pw)

    check_output_dir(args.output_dir, logger)
    check_output_dir(args.reports_dir, logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}azure', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}m365', logger)
    check_output_dir(f'{args.output_dir}{os.path.sep}entraid', logger)
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

def autohonk(authfile=".ugt_auth",
         config=".conf",
         auth=".auth",
         output_dir="output",
         reports_dir="reports",
         debug=False,
         azure=False,
         entraid=False,
         m365=False,
         mde=False,
         insecure=False):
    """
    Untitled Goose Tool Information Gathering. With auto authentication!
    This will never stop until you tell it to.

    Args:
        authfile: File to store the authentication tokens and cookies
        config: Path to config file
        auth: File to store the credentials used for authentication
        output_dir: Directory for storing the results
        reports_dir: Directory for storing debugging/informational logs
        debug: Enable debug logging
        dry_run: Dry run (do not do any API calls)
        azure: Set all of the Azure calls to true
        entraid: Set all of the Entra ID calls to true
        m365: Set all of the M365 calls to true
        mde: Set all of the MDE calls to true
        insecure: Disable secure authentication handling (file encryption)
    """
    # auth and honk in a loop
    encryption_pw = None
    if not insecure:
        encryption_pw = getpass.getpass("Please type the password for file encryption: ")
    auth_dict = {
        "authfile": authfile,
        "config": config,
        "auth": auth,
        "debug": debug,
        "encryption_pw": encryption_pw
    }
    honk_dict = {
        "authfile": authfile,
        "config": config,
        "auth": auth,
        "output_dir": output_dir,
        "reports_dir": reports_dir,
        "debug": debug,
        "azure": azure,
        "entraid": entraid,
        "m365": m365,
        "mde": mde,
        "encryption_pw": encryption_pw
    }
    # Endless loop to keep authing and honking
    while True:
        auth_process = Process(target=gooseyauth, kwargs=auth_dict)
        auth_process.start()
        auth_process.join()

        honk_process = Process(target=honk, kwargs=honk_dict)
        seconds = time.perf_counter()

        honk_process.start()
        honk_process.join()

        elapsed = time.perf_counter() - seconds
        if elapsed <= 5:
            break


