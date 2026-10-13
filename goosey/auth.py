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
        self.tokendata = {}
        self.logger = None
        self.d4iot = False
        self.encryption_pw = None

    def get_authority_url(self):
        """
        Returns the authority URL for the commercial or government tenant specified,
        or the common one if no tenant was specified.
        """
        endpoint = self.endpoints_dict["authority_api"]
        tenant = "common"
        if self.tenant:
            tenant = self.tenant
        return f'{endpoint}/{tenant}'

    def get_d4iot_sensor_uri(self):
        """
        Returns the d4iot sensor URI.
        """
        return "https://" + self.d4iot_sensor_ip

    def get_app_resource_uri(self):
        """
        Returns the application resource URI for a commercial or government tenant.
        """
        app_resource_uris = {}
        for key in self.endpoints_dict.keys():
            if key in ["blob_api", "authority_api"]:
                continue
            if key == "cloudapp_defender":
                app_resource_uris[key] = "05a65629-4c1b-48c1-a78b-804c4abdd4af/.default"
            else:
                app_resource_uris[key] = self.endpoints_dict[key] + "/.default"
        return app_resource_uris

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

    def parse_config(self, configfile):
        config = configparser.ConfigParser()
        config.read(configfile)
        if not self.d4iot:
            self.tenant = config_get(config, 'config', 'tenant', self.logger)
            self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
            self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
            self.subscriptions = config_get(config, 'config', 'subscriptionid', self.logger)
            self.endpoints_dict = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
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

        resource_uri = self.get_app_resource_uri()
        for key, uri in resource_uri.items():
            try:
                if self.client_secret and self.app_client_id:
                    self.authenticate_as_app(uri)
            except Exception as e:
                self.logger.error(f"Error authenticating as app: {str(e)}")

            if self.tokendata:
                custom_auth_dict['app_auth'][key] = copy.copy(self.tokendata)
                custom_auth_dict['app_auth'][key]['tenantId'] = self.tenant
                if 'expiresOn' in custom_auth_dict['app_auth'][key]:
                    expiretime = time.mktime(time.strptime(custom_auth_dict['app_auth'][key]['expiresOn'].split('.')[0], '%Y-%m-%d %H:%M:%S'))
                    custom_auth_dict['app_auth'][key]['expireTime'] = expiretime
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
