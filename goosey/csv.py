#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Csv!
This module converts GUIDs to human readable text.
"""

import argparse
from ast import parse
import warnings
import csv

from tkinter import E
from goosey.utils import *

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

warnings.simplefilter('ignore')

logger = None
data_calls = {}

def getargs(csv_parser) -> None:
    csv_parser.add_argument('-o',
                               '--output_dir',
                               action='store',
                               help='The directory where the goose files are located',
                               default='output/azuread/')
    csv_parser.add_argument('-r',
                               '--result_dir',
                               action='store',
                               help='Directory for storing the results (default: output/csvs)',
                               default='output/csvs/')
    csv_parser.add_argument('--debug',
                               action='store_true',
                               help='Debug output',
                               default=False)

def create_file_filter_dict():
    file_filter_dict = {
        'users.json': ['id', 'userPrincipalName'],
        'applications.json': ['id', 'displayName'],
        'conditionalAccess_policies.json': ['id', 'displayName'],
        'conditionalAccess_namedLocations.json': ['id', 'displayName'],
        'devices.json': ['id', 'displayName'],
        'directoryRoles.json': ['id', 'displayName'],
        'groups.json': ['id', 'displayName'],
        'roleManagement_directory_roleDefinitions.json': ['id', 'displayName'],
        'servicePrincipals.json': ['id', 'displayName']

    }
    return file_filter_dict

def recurse_output_dir(output_dir, result_dir, file_filter_dict):
    for f in os.listdir(output_dir):
        path = os.path.join(output_dir, f)
        if os.path.isfile(path):
            if f in file_filter_dict.keys():
                fields = file_filter_dict[f]
                parse_file(f, path, fields, result_dir)

def parse_file(input_file_name, input_file_path, fields, result_dir):
    file = input_file_name.split('.')[0] + ".csv"
    output_file = os.path.join(result_dir, file)
    logger.debug("Creating %s GUID to Text csv.." % (input_file_name.split('.')[0]))
    with open(output_file, "w+") as w:
        writer = csv.writer(w)
        writer.writerow(fields)
        with open(input_file_path, "r") as f:
            for line in f:
                line = json.loads(line)
                row = [line[fields[0]], line[fields[1]]]
                writer.writerow(row)
    logger.debug("Finished creating %s GUID to Text csv.." % (input_file_name.split('.')[0]))

def main(args=None, gui=False) -> None:
    global logger
    parser = argparse.ArgumentParser(add_help=True, description='Goosey', formatter_class=argparse.RawDescriptionHelpFormatter)
    if args is None:
        args = parser.parse_args()

    if gui:
        logger = setup_logger(__name__, args.debug, formatter='gui')
    else:
        logger = setup_logger(__name__, args.debug)

    
    logger.info("Creating CSV files started...")
    check_output_dir(args.result_dir, logger)
    file_filter_dict = create_file_filter_dict()
    recurse_output_dir(args.output_dir, args.result_dir, file_filter_dict)
    logger.info("Finished created CSV files.")


if __name__ == "__main__":
    main()