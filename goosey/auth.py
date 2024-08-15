#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Auth!
This module handles authentication to Entra ID, Azure, M365, and D4IoT environments.
"""

import argparse
import atexit
import configparser
import copy
import getpass
import io
import json
import msal
import os
import requests
import sys
import time

from collections import namedtuple
from goosey.utils import *

green = "\x1b[1;32m"
bold_red = "\x1b[31;1m"

class Authentication():
    """
    Authentication class for Untitled Goose Tool
    """
    def __init__(self, debug=False):
        self.resource_uri = 'https://graph.microsoft.com/.default'
        self.tokendata = {}
        self.logger = None
        self.d4iot = False
        self.encryption_pw = None

    def get_authority_url(self):
        """
        Returns the authority URL for the commercial or government tenant specified,
        or the common one if no tenant was specified.
        """
        if self.us_government == 'false':
            if self.tenant is not None:
                return 'https://login.microsoftonline.com/{}'.format(self.tenant)
            return 'https://login.microsoftonline.com/common'
        else:
            if self.tenant is not None:
                return 'https://login.microsoftonline.us/{}'.format(self.tenant)
            return 'https://login.microsoftonline.us/common'

    def get_d4iot_sensor_uri(self):
        """
        Returns the d4iot sensor URI.
        """
        return "https://" + self.d4iot_sensor_ip

    def get_mfa_resource_uri(self):
        """
        Returns the MFA Graph API resource URI for a commercial or government tenant.
        """
        if self.us_government == 'false':
            return ['https://graph.microsoft.com/.default']
        elif self.us_government == 'true':
            return ['https://graph.microsoft.us/.default']

    def get_app_resource_uri(self):
        """
        Returns the application resource URI for a commercial or government tenant.
        """
        if self.us_government == 'false':
            if self.mde_gcc == 'false' and self.mde_gcc_high == 'false':
                return ['https://graph.microsoft.com/.default', 'https://outlook.office365.com/.default', 'https://api.securitycenter.microsoft.com/.default', 'https://management.azure.com/.default', 'https://api.security.microsoft.com/.default']
            elif self.mde_gcc == 'true':
                return ['https://graph.microsoft.com/.default', 'https://api.securitycenter.microsoft.com/.default', 'https://api-gcc.securitycenter.microsoft.us', 'https://api-gcc.security.microsoft.us']
            elif self.mde_gcc_high == 'true':
                return ['https://graph.microsoft.com/.default', 'https://api.securitycenter.microsoft.com/.default', 'https://api-gov.securitycenter.microsoft.us', 'https://api-gov.security.microsoft.us']
        elif self.us_government == 'true':
            if self.mde_gcc == 'true':
                return ['https://graph.microsoft.us/.default', 'https://management.azure.us/.default', 'https://api-gcc.securitycenter.microsoft.us', 'https://api-gcc.security.microsoft.us']
            elif self.mde_gcc_high =='true':
                return ['https://graph.microsoft.us/.default', 'https://management.azure.us/.default', 'https://api-gov.securitycenter.microsoft.us', 'https://api-gov.security.microsoft.us']

    def authenticate_as_app(self, resource_uri):
        """
        Authenticate with an application id + client secret (password credentials assigned to serviceprinicpal)
        """
        authority_uri = self.get_authority_url()
        self.logger.debug(f"App Authentication authority uri: {str(authority_uri)}")
        self.logger.debug(f"App authentication resource uri: {str(resource_uri)}")
        context = msal.ConfidentialClientApplication(client_id=self.app_client_id, client_credential=self.client_secret, authority=authority_uri)
        self.tokendata = context.acquire_token_for_client(scopes=[resource_uri])
        if 'error' in self.tokendata:
            if self.tokendata['error'] == 'invalid_client':
                self.logger.error("There was an issue with your application auth: " + self.tokendata['error_description'])
                sys.exit(1)
            else:
                self.logger.error("There was an issue with your application auth: " + self.tokendata['error_description'])
        if 'expires_in' in self.tokendata:
            expiration_time = time.time() + self.tokendata['expires_in']
            self.tokendata['expires_on'] = expiration_time
        return self.tokendata

    @staticmethod
    def get_sub_argparse(auth_parser):
        """
        Get an argparse subparser for authentication
        """
        auth_parser.add_argument('-a',
                                 '--authfile',
                                 action='store',
                                 help='File to store the authentication tokens and cookies (default: .ugt_auth)',
                                 default='.ugt_auth')
        auth_parser.add_argument('--d4iot-authfile',
                                 action='store',
                                 help='File to store the authentication cookies for D4IoT (default: .d4iot_auth)',
                                 default='.d4iot_auth')
        auth_parser.add_argument('-c',
                                 '--config',
                                 action='store',
                                 help='Path to config file (default: .conf)',
                                 default='.conf')
        auth_parser.add_argument('-ac',
                                 '--auth',
                                 action='store',
                                 help='File to store the credentials used for authentication (default: .auth)',
                                 default='.auth')
        auth_parser.add_argument('--d4iot-auth',
                                 action='store',
                                 help='File to store the D4IoT credentials used for authentication (default: .auth_d4iot)',
                                 default='.auth_d4iot')
        auth_parser.add_argument('--d4iot-config',
                                 action='store',
                                 help='Path to D4IoT config file (default: .d4iot_conf)',
                                 default='.d4iot_conf')
        auth_parser.add_argument('--debug',
                                 action='store_true',
                                 help='Enable debug logging')
        auth_parser.add_argument('--d4iot',
                                 action='store_true',
                                 help='Run the authentication portion for d4iot',
                                 default=False)
        auth_parser.add_argument('--insecure',
                                 action='store_true',
                                 help='Disable secure authentication handling (file encryption)')
        return auth_parser


    def parse_config(self, configfile):
        config = configparser.ConfigParser()
        config.read(configfile)
        if not self.d4iot:
            self.tenant = config_get(config, 'config', 'tenant', self.logger)
            self.us_government = config_get(config, 'config', 'us_government', self.logger).lower()
            self.mde_gcc = config_get(config, 'config', 'mde_gcc', self.logger).lower()
            self.mde_gcc_high = config_get(config, 'config', 'mde_gcc_high', self.logger).lower()
            self.exo_us_government = config_get(config, 'config', 'exo_us_government', self.logger).lower()
            self.subscriptions = config_get(config, 'config', 'subscriptionid', self.logger)

            if self.us_government == '' or self.mde_gcc == '' or self.mde_gcc_high == '' or self.tenant == '' or self.exo_us_government == '' or self.subscriptions == '':
                self.logger.error("Empty contents within .conf file. Please edit and try again.")
                sys.exit(1)
        else:
            self.d4iot_sensor_ip = config_get(config, 'config', 'd4iot_sensor_ip', self.logger)
            self.d4iot_mgmt_ip = config_get(config, 'config', 'd4iot_mgmt_ip', self.logger)

        return config

    def parse_auth(self, authstr=None):
        self.authconfig = configparser.ConfigParser()
        auth_dict = {}
        if authstr:
            self.authconfig.read_string(authstr)
        self.username = ""
        if self.d4iot:
            if config_get(self.authconfig, 'auth', 'username', self.logger):
                self.username = config_get(self.authconfig, 'auth', 'username', self.logger)
            else:
                self.username = getpass.getpass("Please type your username: ")
        auth_dict["username"] = self.username
        self.password = ""
        if self.d4iot:
            if config_get(self.authconfig, 'auth', 'password', self.logger):
                self.password = config_get(self.authconfig, 'auth', 'password', self.logger)
            else:
                self.password = getpass.getpass("Please type your password: ")
        auth_dict["password"] = self.password
        if self.d4iot:
            if config_get(self.authconfig, 'auth', 'd4iot_sensor_token', self.logger):
                self.d4iot_sensor_token = config_get(self.authconfig, 'auth', 'd4iot_sensor_token', self.logger)
            else:
                self.d4iot_sensor_token = getpass.getpass("Please type your D4IOT sensor token: ")
            auth_dict["d4iot_sensor_token"] = self.d4iot_sensor_token
            if config_get(self.authconfig, 'auth', 'd4iot_mgmt_token', self.logger):
                self.d4iot_mgmt_token = config_get(self.authconfig, 'auth', 'd4iot_mgmt_token', self.logger)
            else:
                self.d4iot_mgmt_token = getpass.getpass("Please type your D4IOT management console token: ")
            auth_dict["d4iot_mgmt_token"] = self.d4iot_mgmt_token
        else:
            if config_get(self.authconfig, 'auth', 'appid', self.logger):
                self.app_client_id = config_get(self.authconfig, 'auth', 'appid', self.logger)
            else:
                self.app_client_id = getpass.getpass("Please type your application client id: ")
            auth_dict["appid"] = self.app_client_id
            if config_get(self.authconfig, 'auth', 'clientsecret', self.logger):
                self.client_secret = config_get(self.authconfig, 'auth', 'clientsecret', self.logger)
            else:
                self.client_secret = getpass.getpass("Please type your client secret: ")
            auth_dict["clientsecret"] = self.client_secret
        self.authconfig["auth"] = auth_dict

    def _read_current_tokens(self, filepath: str):
        tokens = {}
        tokens_str = read_auth(filepath, logger=self.logger, encryption_pw=self.encryption_pw)
        if tokens_str:
            tokens = json.loads(tokens_str)
        return tokens

    def _write_current_tokens(self, filepath: str, tokens: dict):
        writestr = json.dumps(tokens, indent=2, sort_keys=True)
        write_auth(filepath, writestr, logger=self.logger, encryption_pw=self.encryption_pw, insecure=self.insecure)

    def d4iot_auth(self):
        custom_auth_dict = self._read_current_tokens(self.d4iot_authfile)

        if 'sensor' not in custom_auth_dict:
            custom_auth_dict['sensor'] = {}

        url = self.get_d4iot_sensor_uri()

        self.logger.info("Authenticating to Defender for IoT sensor at %s" % (url))
        if self.d4iot:
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
                }
            response = requests.request("GET", url, headers=headers, verify=False)
            mid_csrf = response.cookies['csrftoken']

            url2 = url + "/api/authentication/login"

            headers2 = {
            'Accept': 'application/json, text/plain, */*',
            'Cookie': 'csrftoken=' + mid_csrf,
            'Origin': url,
            'Referrer': url + '/login',
            'X-CSRFToken': mid_csrf
            }

            payload ={
            "username": self.username,
            "password": self.password
            }

            response2 = requests.post(url2, headers=headers2, json=payload, verify=False)

            self.tokendata['csrftoken'] = response2.cookies['csrftoken']
            self.tokendata['sessionId'] = response2.cookies['sessionid']
            self.logger.info('Obtained d4iot cookies.')

            if self.tokendata:
                custom_auth_dict['sensor'] = copy.copy(self.tokendata)

            self.logger.info(green + "Authentication complete." + green)
            self._write_current_tokens(self.d4iot_authfile, custom_auth_dict)

    def ugt_auth(self):

        custom_auth_dict = self._read_current_tokens(self.authfile)

        self._write_current_tokens(self.authfile, custom_auth_dict)

        if 'mfa' not in custom_auth_dict:
            custom_auth_dict['mfa'] = {}
        if 'app_auth' not in custom_auth_dict:
            custom_auth_dict['app_auth'] = {}
        if 'sdk_auth' not in custom_auth_dict:
            custom_auth_dict['sdk_auth'] = {}

        custom_auth_dict['sdk_auth']['tenant_id'] = self.tenant
        custom_auth_dict['sdk_auth']['app_id'] = self.app_client_id
        custom_auth_dict['sdk_auth']['client_secret'] = self.client_secret
        custom_auth_dict['sdk_auth']['subscriptionid'] = self.subscriptions

        uri = str(self.get_mfa_resource_uri())

        if self.tokendata:
            custom_auth_dict['mfa'][uri] = copy.copy(self.tokendata)
            custom_auth_dict['mfa'][uri]['tenantId'] = self.tenant
            if 'expiresOn' in custom_auth_dict['mfa'][uri]:
                expiretime = time.mktime(time.strptime(custom_auth_dict['mfa'][uri]['expiresOn'].split('.')[0], '%Y-%m-%d %H:%M:%S'))
                custom_auth_dict['mfa'][uri]['expireTime'] = expiretime

            # Clear out our token data
            self.tokendata = None

        resource_uri = self.get_app_resource_uri()
        for uri in resource_uri:
            try:
                if self.client_secret and self.app_client_id:
                    self.authenticate_as_app(uri)
            except Exception as e:
                self.logger.error(f"Error authenticating as app: {str(e)}")

            if self.tokendata:
                custom_auth_dict['app_auth'][uri] = copy.copy(self.tokendata)
                custom_auth_dict['app_auth'][uri]['tenantId'] = self.tenant
                if 'expiresOn' in custom_auth_dict['app_auth'][uri]:
                    expiretime = time.mktime(time.strptime(custom_auth_dict['app_auth'][uri]['expiresOn'].split('.')[0], '%Y-%m-%d %H:%M:%S'))
                    custom_auth_dict['app_auth'][uri]['expireTime'] = expiretime
        self._write_current_tokens(self.authfile, custom_auth_dict)

    def parse_args(self, args):
        self.debug = args.debug
        self.logger = setup_logger(__name__, self.debug)
        self.authfile = args.authfile
        self.auth = args.auth
        self.insecure = args.insecure
        self.encryption_pw = args.encryption_pw
        if args.d4iot:
            self.d4iot = True
            self.config = args.d4iot_config
            self.d4iot_authfile = args.d4iot_authfile
            self.auth = args.d4iot_auth
        else:
            self.config = args.config

        if not self.insecure:
            if self.encryption_pw is None:
                self.encryption_pw = getpass.getpass("Please type the password for file encryption: ")
        auth_config_str = read_auth(self.auth, logger=self.logger, encryption_pw=self.encryption_pw)

        # Read in authconfig or prompt for user info
        self.parse_auth(auth_config_str)

        authio = io.StringIO()
        self.authconfig.write(authio)
        authio.seek(0)
        auth_config_str = authio.getvalue()

        write_auth(self.auth, auth_config_str, logger=self.logger, encryption_pw=self.encryption_pw, insecure=self.insecure)

        self.parse_config(self.config)

def check_app_auth_token(auth_data, logger):
    expiry_time = auth_data['expires_on']
    if time.time() > expiry_time:
        logger.warning("Authentication expired. Please re-authenticate before proceeding.")
        sys.exit(1)
    return False

def main():
    parser = argparse.ArgumentParser(add_help=True, description='Untitled Goose Tool Authentication', formatter_class=argparse.RawDescriptionHelpFormatter)
    auth = Authentication(debug=True)
    auth.get_sub_argparse(parser)
    args = parser.parse_args()
    auth.parse_args(args)
    if args.revoke:
        auth.revoke_tokens(args)
    if args.d4iot:
        auth.d4iot_auth()
    else:
        auth.ugt_auth()

def auth(authfile=".ugt_auth",
         d4iot_authfile=".d4iot_auth",
         config=".conf",
         auth=".auth",
         d4iot_auth=".auth_d4iot",
         d4iot_config=".d4iot_conf",
         debug=False,
         d4iot=False,
         insecure=False,
         encryption_pw=None):
    """
    Untitled Goose Tool Authentication

    Args:
        authfile: File to store the authentication tokens and cookies
        d4iot_authfile: File to store the authentication cookies for D4IoT
        config: Path to config file
        auth: File to store the credentials used for authentication
        d4iot_auth: File to store the D4IoT credentials used for authentication
        debug: Enable debug logging
        d4iot: Run the authentication portion for d4iot
        insecure: Disable secure authentication handling (file encryption)
        encryption_pw: password used for auth file encryption. SHOULD ONLY BE USED WITH AUTOHONK
    """
    args = dict2obj(locals())
    auth = Authentication(debug=debug)
    auth.parse_args(args)
    if args.d4iot:
        auth.d4iot_auth()
    else:
        auth.ugt_auth()


if __name__ == '__main__':
    main()
