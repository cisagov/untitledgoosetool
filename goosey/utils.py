#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Utils!
"""

import asyncio
import configparser
import darkdetect
import json
import logging
import os
import sys

from colored import stylize, attr, fg
from datetime import datetime, timedelta, date
from tracemalloc import start
from logging import handlers

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

if sys.platform == 'win32':
    import msvcrt
else:
    import fcntl

# Custom logging from https://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
class CustomFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""

    blue = "\x1b[34;21m"
    grey = "\x1b[38;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    # Until we import a fancier library like colorama or clrprint, opt for no colors on non-posix terminals
    if os.name != 'posix':
        blue = ""
        grey = ""
        yellow = ""
        red = ""
        bold_red = ""
        reset = ""
    
    format = "%(asctime)s - %(module)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: blue + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class GuiFormatter(logging.Formatter):
    """Logging Formatter to add colors and count warning / errors"""
    
    format = "%(asctime)s - %(module)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"

    DARK_FORMATS = {
        logging.DEBUG: stylize(format, fg('light_blue')),
        logging.INFO: stylize(format, fg('light_gray')),
        logging.WARNING: stylize(format, fg('yellow')),
        logging.ERROR: stylize(format, fg('light_red')),
        logging.CRITICAL: stylize(format, fg('light_red') + attr('bold'))
    }

    LIGHT_FORMATS = {
        logging.DEBUG: stylize(format, fg('blue')),
        logging.INFO: stylize(format, fg('dark_gray')),
        logging.WARNING: stylize(format, fg('dark_green')),
        logging.ERROR: stylize(format, fg('red')),
        logging.CRITICAL: stylize(format, fg('red') + attr('bold'))
    }

    def format(self, record):
        if darkdetect.isDark():
            log_fmt = self.DARK_FORMATS.get(record.levelno)
        else:
            log_fmt = self.LIGHT_FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

class LogLevelFilter(logging.Filter):
    def __init__(self, level):
        self.level = level

    def filter(self, record):
        return record.levelno == self.level

def setup_logger(name, debug, formatter='cli') -> None:
    """Helper function to set up logger.

    :param name: Logger name to grab
    :type name: str
    :param debug: Flag indicating if debug mode is set.
    :type debug: bool
    :param formatter: Custom formatter to use.
    :type formatter: str
    :return: None
    :rtype: None
    """
    debug_log = "debug.log"
    error_log = "error.log"

    logger = logging.getLogger(name)
    file_formatter = logging.Formatter('%(asctime)s  %(name)s  %(levelname)s  %(message)s')

    debug_fh = logging.handlers.WatchedFileHandler(debug_log)   
    debug_fh.setFormatter(file_formatter)
    debug_fh.addFilter(LogLevelFilter(logging.DEBUG))
    debug_fh.setLevel(logging.DEBUG)

    error_fh = logging.handlers.WatchedFileHandler(error_log)   
    error_fh.setFormatter(file_formatter)
    error_fh.addFilter(LogLevelFilter(logging.ERROR))
    error_fh.setLevel(logging.ERROR)

    logger.addHandler(debug_fh)
    logger.addHandler(error_fh)
    

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    # create console handler with a higher log level
    ch = logging.StreamHandler()

    if debug:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)

    if formatter == 'cli':
        ch.setFormatter(CustomFormatter())
    elif formatter == 'gui':
        ch.setFormatter(GuiFormatter())
    logger.addHandler(ch)

    return logger

def build_date_range(start_date, end_date):
    res = []
    res.append(start_date)

    while start_date != end_date:
        res.append((datetime.strptime(start_date,"%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d"))
        start_date = (datetime.strptime(start_date,"%Y-%m-%d") + timedelta(days=1)).strftime("%Y-%m-%d")
    
    return res

def build_date_tuples(chunk_size=26, start_date=None, end_date=None):
    """Helper function to chunk last 364 days into 14 chunks
    
    :return: A list of the checkpoint dates when chunking the last 364 days.
    :rtype: List
    """

    ret = []
    
    if start_date and end_date:
        start_date = datetime.strptime(start_date,"%Y-%m-%d")
        diff = end_date - start_date
        if diff.days > 26:
            ret.append(end_date.strftime("%Y-%m-%d"))
            while end_date.date() > start_date.date():
                ret.append((end_date - timedelta(days=26)).strftime("%Y-%m-%d"))
                end_date = end_date - timedelta(days=26)
        else:
            ret.append(end_date.strftime("%Y-%m-%d"))
            ret.append(start_date.strftime("%Y-%m-%d"))
    else:
        for i in range(0, 365, chunk_size):
            ret.append((datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d"))
    return ret[::-1]

def findkeys(node, kv):
    if isinstance(node, list):
        for i in node:
            for x in findkeys(i, kv):
                yield x
    elif isinstance(node, dict):
        if kv in node:
            yield node[kv]
        for j in node.values():
            for x in findkeys(j, kv):
                yield x

def search_results(values, lookup):
    for k in values:
        if any(lookup in str(s) for s in k.values()):
            return k
    return None

def config_get(conf, section: str, option: str, logger=None, default=None):
    """Helper function for getting config options from a configparser.

    :param conf: configparser item after reading a config file or string.
    :type conf: configparser.ConfigParser
    :param section: section in config file
    :type section: str
    :param option: option item in config file
    :type option: str
    :param logger: logging context
    :type logger: logger
    :param default: default to return
    :type default: any
    :return: config item based on section and option
    :rtype: any
    """
    r = None
    try:
        r = conf.get(section, option)
    except configparser.NoSectionError as e:
        err = f"Missing section in config file: {section}. Proceeding."
        if logger:
            logger.warning(err)  
        else:
            print(err)
    except configparser.NoOptionError as e:
        if option:
            err = f"Missing option in config file: {option}. Proceeding."
            logger.warning(err) if logger else print(err)
    except Exception as e:
        err = f"Unknown exception while parsing config file: {str(e)}"
        logger.warning(err) if logger else print(err)
    return r

def check_output_dir(output_dir, logger):
    if not os.path.exists(output_dir):
        logger.info(f'Output directory "{output_dir}" does not exist. Attempting to create.')
        try:
            os.makedirs(output_dir)
        except Exception as e:
            logger.error(f'Error while attempting to create output directory {output_dir}: {str(e)}')
            raise
    elif not os.path.isdir(output_dir):
        logger.error(f'{output_dir} exists but is not a directory or you do not have permissions to access. Exiting.')
        sys.exit(1)

async def get_nextlink(url, outfile, session, logger, auth):
    retries = 50
    while url:
        try:
            if '$skiptoken' in url:
                skiptoken = url.split('skiptoken=')[1]
            elif '$skip' in url:
                skiptoken = url.split('skip=')[1]
            if not skiptoken == '50':
                logger.debug('Getting nextLink %s' % (skiptoken))

            header = {'Authorization': '%s %s' % (auth['token_type'], auth['access_token'])}
            async with session.get(url, headers=header, raise_for_status=True, timeout=600) as r2:
                result2 = await r2.json()
                if 'value' in result2:
                    finalvalue = result2['value']
                elif 'value' not in result2:
                    finalvalue = result2
                if not skiptoken == '50':
                    logger.debug('Received nextLink %s' % (skiptoken))

                with open(outfile, 'a+', encoding='utf-8') as f:
                    f.write("\n".join([json.dumps(x) for x in finalvalue]) + '\n')
                    f.flush()
                    os.fsync(f)
                if '@odata.nextLink' in result2:
                    url = result2['@odata.nextLink']
                    retries = 50
                else:
                    url = None
        except asyncio.TimeoutError:
            logger.error('TimeoutError has occurred on {}'.format(skiptoken))
        except Exception as e:
            if retries == 0:
                logger.info('Error. No more retries on {}.'.format(skiptoken))
                url = None 
            else:
                logger.info('Error. Retrying {} up to {} more times'.format(skiptoken, retries))
                try:
                    if e.status:
                        if e.status == 429:
                            logger.info('Sleeping for 60 seconds because of API throttle limit was exceeded.')
                            await asyncio.sleep(60)
                        elif e.status == 401:
                            logger.error('Unauthorized message received. Exiting calls.')
                            logger.error("Check auth to make sure it's not expired.")
                            return                            
                        else:
                            logger.info('Error: {}'.format(str(e)))
                        retries -= 1
                except AttributeError as a:
                    logger.error('Error on nextLink retrieval {}: {}'.format(skiptoken, str(e)))



async def helper_single_object(object, params, failurefile=None, retries=5) -> None:
        url, auth, logger, output_dir, session = params[0], params[1], params[2], params[3], params[4]

        if 'token_type' not in auth or 'access_token' not in auth:
            logger.error(f"Missing token_type and access_token from auth. Did you auth correctly? (Skipping {object})")
            return
        url += object
        if '/' in object:
            temp = object.split('/')
            name = '_'.join(temp)
            object = temp[-1]
        elif '/' not in object:
            name = object

        try:
            header = {'Authorization': '%s %s' % (auth['token_type'], auth['access_token'])}
            logger.info('Dumping %s information...' % (object))
            outfile = os.path.join(output_dir, name + '.json')

            async with session.get(url, headers=header, raise_for_status=True) as r:
                result = await r.json()
                nexturl = None

                if 'value' not in result:
                    if '@odata.context' in result:
                        if '@odata.type' in result:
                            result['value'].pop('@odata.type')
                            with open(outfile, 'w', encoding='utf-8') as f:
                                f.write(json.dumps(result) + '\n')
                    elif 'error' in result:
                        if result['error']['code'] == 'InvalidAuthenticationToken':
                            return
                        elif result['error']['code'] == 'Unauthorized':
                            logger.error("Error with authentication token: " + result['error']['message'])
                            logger.error("Please re-auth.")
                            return
                        else:
                            logger.error("Error: " + result['error']['message'])
                    else:
                        logger.debug("Error with result: {}".format(str(result)))
                        return
                if 'value' in result:
                    if result['value']:
                        with open(outfile, 'w', encoding='utf-8') as f:
                            for x in result['value']:
                                if '@odata.type' in x:
                                    x.pop('@odata.type')
                                f.write(json.dumps(x) + '\n')
                    elif not result['value']:
                        logger.debug('%s has no information (size is 0). No output file.' % (outfile))
                        with open(failurefile, 'a+', encoding='utf-8') as f:
                            f.write('No output file: ' + name + ' - ' + str((datetime.now())) + '\n')
                if '@odata.nextLink' in result:
                    nexturl = result['@odata.nextLink']
                    await get_nextlink(nexturl, outfile, session, logger, auth)
        except Exception as e:
            try:
                if e.status:
                    if e.status == 429:
                        logger.info('Sleeping for 60 seconds because of API throttle limit was exceeded.')
                        await asyncio.sleep(60)
                        retries -= 1
                    elif e.status == 401:
                        logger.error('Unauthorized message received. Exiting calls.')
                        logger.error("Check auth to make sure it's not expired.")
                        return
                    elif e.status == 400:
                        logger.error('Error received on ' + str(object) + ': '  + str(e))
                        with open(failurefile, 'a+', encoding='utf-8') as f:
                            f.write('Error: ' + name + ' - ' + str((datetime.now())) + '\n')
                        return
            except AttributeError as a:
                logger.error('Error on nextLink retrieval: {}'.format(str(e)))

        logger.info('Finished dumping %s information.' % (object))

class Lock:
    def __init__(self, fh):
        self.fh = fh 
        
    def acquire(self):
        if self.fh != None:
            try:
                if sys.platform == 'win32':
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    print("Acquired lock")
            except (IOError, BlockingIOError, PermissionError) as e:
                raise

    def release(self):
        if self.fh != None:
            try:
                if sys.platform == 'win32':
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self.fh, fcntl.LOCK_UN)
                    print("released lock")
            except (IOError, BlockingIOError, PermissionError) as e:
                raise

    def __del__(self):
        if self.fh != None:
            self.fh.close()

def get_end_time_yesterday():
    yesterday = date.today() - timedelta(days=1)
    return datetime.combine(yesterday, datetime.max.time())

def get_authfile(fn, auth_type='app_auth', uri='https://graph.microsoft.com/', logger=logging):
    if not os.path.isfile(fn):
        logger.warning("{} auth file missing. Please auth first. Exiting.".format(fn))
        sys.exit(1)

    auth = {}
    try:
        with open(fn, 'r') as infile:
            if auth_type == 'sdk_auth':
                auth = json.loads(infile.read())[auth_type]
            else:
                auth = json.loads(infile.read())[auth_type][uri]
    except Exception as e:
        logger.error("{}".format(str(e)))
        raise e

    return auth