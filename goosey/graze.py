#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Graze!
This module performs data collection time bound extraction of UAL thresholds.
"""

import argparse
import configparser
import fnmatch
import getpass
import json 
import os
import pyAesCrypt
import random 
import re
import requests
import sys
import time
import warnings

from datetime import datetime, timedelta
from goosey.utils import *
from urllib.parse import unquote

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

warnings.simplefilter('ignore')

logger = None
THRESHOLD = 1000
a_THRESHOLD = THRESHOLD
TIMEOUT = 60
DEFAULT_TIME_JUMP = 1800
ZERO_RETRIES = 20
LATENCY_TH = 30000
url = None

call_cnt = 0
auth = None
config = None

encryption_pw = None

def getargs(graze_parser) -> None:
    """Helper function to build arguments for argparse

    :param graze_parser: parser which will perform command line argument parsing
    :type graze_parser: argparse.ArgumentParser
    :return: None
    :rtype: None
    """
    graze_parser.add_argument('-a',
                               '--authfile',
                               action='store',
                               help='File to store the authentication tokens and cookies (default: .ugt_auth)',
                               default='.ugt_auth')
    graze_parser.add_argument('-c',
                               '--config',
                               action='store',
                               help='Path to config file (default: .conf)',
                               default='.conf')
    graze_parser.add_argument('-o',
                               '--output-dir',
                               action='store',
                               help='Output directory for honk outputs',
                               default='output')
    graze_parser.add_argument('-d',
                               '--debug',
                               action='store_true',
                               help='Enable debug logging',
                               default=False)
    graze_parser.add_argument('-e',
                               '--endpoint',
                               action='store',
                               help='Endpoint for UAL. Can change to localhost for testing if hosting local server.',
                               default="https://security.microsoft.com/api/UnifiedAuditLog")

def check(start, end):
    global auth, call_cnt, url
    forceCount = 0
    call_cnt += 1
    sessionId = random.randint(1337, 9999999)
    startDate = start.strftime("%Y-%m-%d %H:%M:%S -0000")
    endDate = end.strftime("%Y-%m-%d %H:%M:%S -0000")
    bound = f'[{startDate} - {endDate}]'
    payload = {'newSession': True, 'optin': True, 'sessionId': sessionId, 'startDate': startDate, 'endDate': endDate, 'ipAddresses': ''}
    payload = json.dumps(payload)

    headers = {
    'x-clientside-xhr-queue': "psws-exo",
    'sec-ch-ua-mobile': "?0",
    'x-clientpage': "auditlogresults@auditlogsearch",
    'content-type': "application/json;charset=UTF-8",
    'accept': "application/json, text/plain, */*",
    'x-xsrf-token': unquote(auth['xsrf']),
    'dnt': "1",
    'sec-gpc': "1",
    'cache-control': "no-cache",
    'Cookie': 's.SessID='+ auth['sessionId'] + '; sccauth=' + auth['sccauth'] + ';',
    }

    try:
        response = requests.request("POST", url, data=payload, headers=headers, timeout=TIMEOUT)
    except requests.Timeout as e:
        logger.warning(f'=======> Timed out. Perhaps try lowering bounds?')
        return False, a_THRESHOLD
    except Exception as e:
        logger.warning(f'=======> Other requests exception occurred: {str(e)}. Sleeping to stabilize...')
        time.sleep(10)
        return False, -1

    if response.status_code == 200:
        try:
            d = json.loads(response.text)
            if len(d) == 0:
                if int(response.headers['Content-Length']) >= 2:
                    resheaders = response.headers['X-PerfTrace'].split(',')
                    latencypat = "*ActionExecution*"
                    latencymat = fnmatch.filter(resheaders, latencypat)
                    num = re.findall('[\\d]*[.][\\d]+', str(latencymat))
                    latencyv = float(num[0])
                    if latencyv > LATENCY_TH:
                        forceCount = a_THRESHOLD  
                    return False, forceCount
                else:
                    logger.warning(f'=======> {bound} has 0 results: {response.text} {json.dumps(response.headers.__dict__, indent=2)}')
                    return False, 0
            if forceCount > 0:
                resCount = forceCount
            else:
                resCount = d[0]['ResultCount']
            
            if resCount == 0:
                return False, 0

            if not type(resCount) is int:
                logger.debug(f'Type of resCount is not int: {resCount}')
                time.sleep(60)
                return False, -1
            
            if resCount < a_THRESHOLD - 1:
                logger.debug(f'=======> {bound} : {resCount} results (within {a_THRESHOLD}): {json.dumps(response.headers.__dict__, indent=2)}')
                return True, resCount
            else:
                logger.debug(f'=======> {bound} : {resCount} results (outside {a_THRESHOLD}): {json.dumps(response.headers.__dict__, indent=2)}')
                return False, resCount
        except Exception as e:
            logger.debug(f'\t[-] Error decoding JSON: {str(e)}, {response.text[:100]}')
            sys.exit(1)
    elif response.status_code == 429:
        # Throttling, sleep for a bit
        logger.debug(f'\t[-] Requests being throttled, sleeping for one minute before retrying...')
        time.sleep(60)
        return False, -1
    else:
        logger.debug(f'\t[-] Did not get 200 code returned: {response.status_code}')
        logger.debug(str(response.text))
        logger.debug("Please re-auth if it is an authentication or login time-out error code.")
        sys.exit(1)

    return False, 0

def linear_strategy(start_ts, end_ts, cnt):
    # Calculate units of time per count with the assumption that log data is linear
    # Multiplier to try to fall within threshold as opposed to right at threshold
    MULTIPLIER = 0.95
    ts_per_res = (end_ts - start_ts)/cnt
    logger.debug(f'-------> [Linear] {ts_per_res} timestamp ticks per result, {ts_per_res*a_THRESHOLD} timestamp ticks for threshold of {a_THRESHOLD}')
    return datetime.fromtimestamp(start_ts + int(ts_per_res*a_THRESHOLD*MULTIPLIER))

def naive_log_strategy(start_ts, end_ts, cnt):
    new_end_ts = start_ts + ((end_ts - start_ts)/2)
    return datetime.fromtimestamp(new_end_ts)

def find_single_threshold(start, end):
    global a_THRESHOLD
    done = False
    start_ts = start.timestamp()
    startDate = start.strftime("%Y-%m-%d %H:%M:%S")
    endDate = end.strftime("%Y-%m-%d %H:%M:%S")
    bound = f'[{startDate} -> {endDate}]'
    logger.debug(f'[+] Searching {bound}')
    retry_counter = 0
    while not done:
        a_THRESHOLD = THRESHOLD
        diff = (end - start).total_seconds()
        print(f'Time difference: {diff}')
        if diff <= 1.99:
            a_THRESHOLD = THRESHOLD * 2
            print(f'New Threshold set: {a_THRESHOLD}')
        endDate = end.strftime("%Y-%m-%d %H:%M:%S")
        bound = f'[{startDate} -> {endDate}]'
        logger.debug(f'===> Trying to find a bounding for {bound}')
        r, cnt = check(start, end)
        if r:
            return (start, end, cnt)
        elif cnt == 0:
            if retry_counter < ZERO_RETRIES:
                retry_counter += 1 # do nothing and just retry again with same time frame
                logger.debug(f'===> Got 0 results returned from server, retry number {retry_counter} of {ZERO_RETRIES}')
            else:
                return (start, end, cnt) # 0 cnt means 0 results, need to expand timeframe. Return 0 for now
        elif cnt >= a_THRESHOLD:
            retry_counter = 0
            end = naive_log_strategy(start.timestamp(), end.timestamp(), cnt)
            # Threshold returns means timeout, need to reduce timeframe. For now, use naive strategy for logarithmic
        elif cnt == -1:
            pass # Throttling, sleep for a bit in func then resume
        else:
            retry_counter = 0
            end = linear_strategy(start.timestamp(), end.timestamp(),  cnt)

def find_bounds(start, end, output=None):
    bounds = []
    rolling_end = end
    while start < end:
        (ns, ne, c) = find_single_threshold(start, rolling_end)
        start = ne
        bounds.append((ns, ne, c))
        with open(output, 'a') as f:
            s = ns.strftime("%Y-%m-%d %H:%M:%S")
            e = ne.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f'{s},{e},{c}\n')
        if c == 0:
            rolling_end = datetime.fromtimestamp(ne.timestamp() + DEFAULT_TIME_JUMP)
        else:
            rolling_end = datetime.fromtimestamp(ne.timestamp() + int(a_THRESHOLD/c)*(ne.timestamp() - ns.timestamp()))
        if rolling_end > end:
            rolling_end = end
    return bounds
      
def main(args=None) -> None:
    global logger, auth, url, config, encryption_pw

    parser = argparse.ArgumentParser(add_help=True, description='Goosey', formatter_class=argparse.RawDescriptionHelpFormatter)
    
    getargs(parser)

    if args is None:
        args = parser.parse_args()

    logger = setup_logger(__name__, args.debug)
  
    config = configparser.ConfigParser()
    config.read(args.config)

    auth = {}

    exo_us_government = config_get(config, 'config', 'exo_us_government', logger).lower()

    encrypted_ugtauth = False

    dir_path = os.path.dirname(os.path.realpath(args.authfile))
    encrypted_authfile = os.path.join(dir_path, '.ugt_auth.aes')

    if os.path.isfile(encrypted_authfile):
        encrypted_ugtauth = True
        if encryption_pw is None:
            encryption_pw = getpass.getpass("Please type the password for file encryption: ")

        pyAesCrypt.decryptFile(encrypted_authfile, args.authfile, encryption_pw)
        os.remove(encrypted_authfile)
        logger.debug("Decrypted the .ugt_auth file!")

    if not os.path.isfile(args.authfile):
        logger.warning("{} auth file missing. Please auth first. Exiting.".format(args.authfile))
        sys.exit(1)

    try:
        logger.info("Reading in authfile: {}".format(args.authfile))
        with open(args.authfile, 'r') as infile:
            if exo_us_government == 'false':
                auth = json.loads(infile.read())['mfa']["['https://graph.microsoft.com/.default']"]
            elif exo_us_government == 'true':
                auth = json.loads(infile.read())['mfa']["['https://graph.microsoft.us/.default']"]
    except Exception as e:
        logger.error("{}".format(str(e)))
        raise e
        sys.exit(1)

    if encrypted_ugtauth:
        if os.path.isfile(args.authfile):
            pyAesCrypt.encryptFile(args.authfile, encrypted_authfile, encryption_pw)
            os.remove(args.authfile)
            logger.debug("Encrypted the .ugt_auth file!")    

    url = args.endpoint

    check_output_dir(f'{args.output_dir}{os.path.sep}m365', logger)
    output_file = f'{args.output_dir}{os.path.sep}m365{os.path.sep}.ual_bounds'

    yday_end = get_end_time_yesterday()

    start = None
    if os.path.isfile(output_file):
        logger.info(f"Output file {output_file} exists. Starting from last bound.")
        try:
            start = datetime.strptime(open(output_file, 'r').readlines()[-1].split(',')[1], "%Y-%m-%d %H:%M:%S")
        except Exception as e:
            logger.warning(f"Error pulling latest time from bounds file: {str(e)} Starting from default.")
            start = yday_end - timedelta(days=364)
    else:
        start = yday_end - timedelta(days=364)

    logger.info(f"Goosey beginning to graze: {start} -> {yday_end}")
    seconds = time.perf_counter()
    bounds = find_bounds(start, yday_end, output_file)
    elapsed = time.perf_counter() - seconds
    logger.info("Goosey graze executed in {0:0.2f} seconds.".format(elapsed))

    total = sum([b[2] for b in bounds])
    logger.info(f'{call_cnt} requests were made. Total sum of events: {total}')

if __name__ == "__main__":
    main()
