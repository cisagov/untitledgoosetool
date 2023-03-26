#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Auth!
This module handles authentication to an Azure AD, Azure, and M365 environment.
"""

import adal
import argparse
import atexit
import configparser
import copy
import json
import msal
import sys
import time

from goosey.utils import *
from seleniumwire import webdriver
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.0.0"

green = "\x1b[1;32m"

class Authentication():
    """
    Authentication class for Untitled Goose Tool
    """
    def __init__(self, debug=False):
        self.client_id = '1b730954-1685-4b74-9bfd-dac224a7b894'
        self.resource_uri = 'https://graph.microsoft.com/.default'
        self.tokendata = {}
        self.headless = False
        self.logger = None
        self.d4iot = False

    def get_webdriver_browser(self):
        browser = None
        try:
            opts = FirefoxOptions()
            # opts.accept_insecure_certs = True
            # desired_capabilities = DesiredCapabilities.FIREFOX.copy()
            # desired_capabilities['acceptInsecureCerts'] = True
            if self.headless:
                opts.add_argument("--headless")
            # profile = webdriver.FirefoxProfile()
            # profile.accept_untrusted_certs = True      , firefox_profile=profile 
            browser = webdriver.Firefox(options=opts)

        except Exception as e:
            self.logger.error(f'Error getting Firefox webdriver: {str(e)}. Exiting.')
            sys.exit(1)
        return browser

    def get_authority_url(self):
        """
        Returns the authority URL for the tenant specified, or the
        common one if no tenant was specified
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
        return "https://" + self.d4iot_sensor_ip

    def get_mfa_resource_uri(self):

        if self.us_government == 'false':
            return 'https://graph.microsoft.com/.default'
        elif self.us_government == 'true':
            return 'https://graph.microsoft.us/.default'

    def get_app_resource_uri(self):

        if self.us_government == 'false':
            return ['https://graph.microsoft.com/.default', 'https://api.securitycenter.microsoft.com/.default', 'https://management.azure.com/.default']
        elif self.us_government == 'true':
            return 'https://graph.microsoft.us/.default'

    def authenticate_device_code(self):
        """
        Authenticate the end-user using device auth.
        """
        authority_host_uri = self.get_authority_url()

        context = msal.ConfidentialClientApplication(client_id=self.client_id, client_credential=self.client_secret, authority=authority_host_uri)
        code = context.acquire_user_code(self.resource_uri, self.client_id)
        self.logger.info(code['message'])
        self.tokendata = context.acquire_token_with_device_code(self.resource_uri, code, self.client_id)
        return self.tokendata

    def authenticate_device_code_selenium(self, cache=None):
        """
        Authenticate the end-user using device auth through Selenium.
        """

        # TODO: Check that all required args are present

        authority_host_uri = self.get_authority_url()
        self.logger.debug(f"Device code selenium authority uri: {str(authority_host_uri)}")
        resource_uri = self.get_mfa_resource_uri()
        self.logger.debug(f"Device code selenium resource uri: {str(resource_uri)}")
        cache = msal.SerializableTokenCache()
        context = msal.PublicClientApplication(client_id=self.client_id,  authority=authority_host_uri, token_cache=cache)
        code = context.initiate_device_flow(scopes=[resource_uri])
        self.logger.info('Attempting to automatically auth via device code. You may have to accept MFA prompts.')

        one_time_code = code['message'].split(' ')[16]

        CODEFIELD = (By.ID, "otc")
        EMAILFIELD = (By.ID, "i0116")
        PASSWORDFIELD = (By.ID, "i0118")
        NEXTBUTTON = (By.ID, "idSIButton9")

        browser = self.get_webdriver_browser()

        try:
            if browser:
                if self.us_government == 'false':
                    browser.get("https://microsoft.com/devicelogin")
                elif self.us_government == 'true':
                    browser.get("https://login.microsoftonline.us/common/oauth2/deviceauth")

            WebDriverWait(browser, 10).until(EC.element_to_be_clickable(CODEFIELD)).send_keys(one_time_code)

            WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

            WebDriverWait(browser, 10).until(EC.element_to_be_clickable(EMAILFIELD)).send_keys(self.username)

            WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'usernameError')))
                browser.quit()
                sys.exit("Incorrect username. Please correct it and try again.")  
            except Exception as e:
                pass                  
                
            WebDriverWait(browser, 15).until(EC.element_to_be_clickable(PASSWORDFIELD)).send_keys(self.password)

            WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()
            
            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'passwordError')))
                browser.quit()
                sys.exit("Incorrect password. Please correct it and try again.")  
            except Exception as e:
                pass    
            
            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'idDiv_SAASDS_Title')))
                browser.quit()
                sys.exit("Declined MFA. Please correct it and try again.")  
            except Exception as e:
                pass    

            try:
                WebDriverWait(browser, 10).until(EC.presence_of_element_located((By.ID, 'ChangePasswordDescription')))
                browser.quit()
                sys.exit("Password reset required. Change your password and try again.")
            except Exception as e:
                pass
           
            if EC.text_to_be_present_in_element((By.ID, "appConfirmTitle"), "Are you trying to sign to Azure Active Directory PowerShell?"):
                WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

            # Wait for MFA
            WebDriverWait(browser, 30).until(EC.text_to_be_present_in_element((By.ID, "message"), "You have signed in to the Azure Active Directory PowerShell application on your device. You may now close this window."))
           

        except Exception as e:
            return False

        if browser:
            try:
                browser.quit()
            except Exception as e:
                pass

        token_data_to_add = context.acquire_token_by_device_flow(code)

        if not self.tokendata:
            self.tokendata = {}

        for key in token_data_to_add:
            self.tokendata[key] = token_data_to_add[key]
        
        atexit.register(lambda:open("token_cache.bin", "w").write(cache.serialize()) if cache.has_state_changed else None)

        return self.tokendata

    def authenticate_as_app(self, resource_uri):
        """
        Authenticate with an APP id + secret (password credentials assigned to serviceprinicpal)
        """
        authority_uri = self.get_authority_url()
        self.logger.debug(f"App Authentication authority uri: {str(authority_uri)}")
        self.logger.debug(f"App authentication resource uri: {str(resource_uri)}")
        context = msal.ConfidentialClientApplication(client_id=self.app_client_id, client_credential=self.client_secret, authority=authority_uri)
        self.tokendata = context.acquire_token_for_client(resource_uri)
        if 'expires_in' in self.tokendata:
            expiration_time = time.time() + self.tokendata['expires_in']
        self.tokendata['expires_on'] = expiration_time
        return self.tokendata

    def authenticate_mfa_interactive(self):
        """
        Authenticate via username, password, and MFA to get session ID and sccauth cookies.
        """

        if self.auth_device_selenium:
            self.authenticate_device_code_selenium()

        result = False

        EMAILFIELD = (By.ID, "i0116")
        PASSWORDFIELD = (By.ID, "i0118")
        NEXTBUTTON = (By.ID, "idSIButton9")

        browser = self.get_webdriver_browser()
        if self.m365 == 'true':
            try:
                if browser:
                    if self.us_government == 'false':
                        browser.get("https://login.microsoftonline.com")
                    elif self.us_government == 'true':
                        browser.get("https://login.microsoftonline.us")

                    WebDriverWait(browser, 10).until(EC.element_to_be_clickable(EMAILFIELD)).send_keys(self.username)
                    # Click Next
                    WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'usernameError')))
                        browser.quit()
                        sys.exit("Incorrect username. Please correct it and try again.")  
                    except Exception as e:
                        pass     

                    # find password input field and insert password as well
                    WebDriverWait(browser, 10).until(EC.element_to_be_clickable(PASSWORDFIELD)).send_keys(self.password)
                    # Click Login 
                    WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'passwordError')))
                        browser.quit()
                        sys.exit("Incorrect password. Please correct it and try again.")  
                    except Exception as e:
                        pass    
                
                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'ChangePasswordDescription')))
                        browser.quit()
                        sys.exit("Password reset required. Change your password and try again.")
                    except Exception as e:
                        pass

                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'idDiv_SAASDS_Title')))
                        browser.quit()
                        sys.exit("Declined MFA. Please correct it and try again.") 
                    except Exception as e:
                        pass    

                    # Switch to second window
                    browser.execute_script("window.open('');")
                    browser.switch_to.window(browser.window_handles[1])
                    if self.exo_us_government == 'false':
                        browser.get("https://outlook.office365.com/ecp")
                        try:
                            WebDriverWait(browser, 10).until(EC.url_to_be('https://outlook.office365.com/ecp'))
                        except Exception as e:
                            pass
                    elif self.exo_us_government == 'true':
                        browser.get("https://outlook.office365.us/ecp")
                        try:
                            WebDriverWait(browser, 10).until(EC.url_to_be('https://outlook.office365.us/ecp'))
                        except Exception as e:
                            pass
                    time.sleep(1)

                    if self.msgtrc == 'true':
                        print("Msgtrc = true")
                        browser.execute_script("window.open('');")
                        browser.switch_to.window(browser.window_handles[2])
                        if self.exo_us_government == 'false':
                            browser.get("https://admin.exchange.microsoft.com/")
                            try:
                                WebDriverWait(browser, 10).until(EC.url_to_be('https://admin.exchange.microsoft.com/#/'))
                                browser.get("https://admin.exchange.microsoft.com/#/messagetrace")
                                WebDriverWait(browser, 10).until(EC.url_to_be('https://admin.exchange.microsoft.com/#/messagetrace'))
                            except Exception as e:
                                pass
                        elif self.exo_us_government == 'true':
                            browser.get("http://admin.exchange.office365.us/#/messagetrace")
                            try:
                                WebDriverWait(browser, 10).until(EC.url_to_be('https://admin.exchange.microsoft.us/#/'))
                            except Exception as e:
                                pass
                        time.sleep(1)
                    else:
                        browser.execute_script("window.open('');")
                        browser.switch_to.window(browser.window_handles[2])
                        if self.exo_us_government == 'false':
                            browser.get("https://admin.exchange.microsoft.com")
                            try:
                                WebDriverWait(browser, 10).until(EC.url_to_be('https://admin.exchange.microsoft.com'))
                            except Exception as e:
                                pass
                        elif self.exo_us_government == 'true':
                            browser.get("http://admin.exchange.office365.us/")
                            try:
                                WebDriverWait(browser, 10).until(EC.url_to_be('https://admin.exchange.microsoft.us'))
                            except Exception as e:
                                pass
                        time.sleep(1)

                    """ if self.get_csp:
                        self.logger.info('Acquiring auth for admin.microsoft.com since CSP data pull is enabled.')
                        browser.execute_script("window.open('');")
                        browser.switch_to.window(browser.window_handles[3])
                        if self.exo_us_government == 'false':
                            browser.get("https://admin.microsoft.com")
                        try:
                            WebDriverWait(browser, 10).until(EC.url_to_be('https://admin.microsoft.com'))
                        except Exception as e:
                            pass
                        if self.exo_us_government == 'true':
                            browser.get("https://admin.microsoft.us")
                        try:
                            WebDriverWait(browser, 10).until(EC.url_to_be('https://admin.microsoft.us'))
                        except Exception as e:
                            pass
                        time.sleep(1)
                    else:
                        self.logger.info("Skipping auth for admin.microsoft.com since CSP data pull is disabled.")
                    """

                    # Switch back to first window
                    browser.switch_to.window(browser.window_handles[0])

                    # Stay signed in
                    try:
                        WebDriverWait(browser, 20).until(EC.element_to_be_clickable(NEXTBUTTON)).click()
                    except Exception as e:
                        pass

                    if self.exo_us_government == 'false':
                        browser.get("https://security.microsoft.com/auditlogsearch")
                        try:
                            WebDriverWait(browser, 10).until(EC.url_to_be('https://security.microsoft.com/auditlogsearch'))
                        except Exception as e:
                            pass
                    elif self.exo_us_government == 'true':
                        browser.get("https://security.microsoft.us/auditlogsearch")
                        try:
                            WebDriverWait(browser, 10).until(EC.url_to_be('https://security.microsoft.us/auditlogsearch'))
                        except Exception as e:
                            pass

                    self.tokendata['sessionId'] = browser.get_cookie('s.SessID').get('value')
                    self.tokendata['sccauth'] = browser.get_cookie('sccauth').get('value')
                    self.tokendata['xsrf'] = browser.get_cookie('XSRF-TOKEN').get('value')
                    self.logger.info('Obtained audit log cookies.')

                    """ if self.get_csp:
                        browser.switch_to.window(browser.window_handles[3])

                        self.tokendata['RootAuthToken'] = browser.get_cookie('RootAuthToken').get('value')
                        self.tokendata['userIndex'] = browser.get_cookie('UserIndex').get('value')
                        self.tokendata['OIDCAuth'] = browser.get_cookie('OIDCAuthCookie').get('value')
                        self.tokendata['s.LoginUserTenantId'] = browser.get_cookie('s.LoginUserTenantId').get('value')
                    """

                    if self.msgtrc == 'false':
                        browser.switch_to.window(browser.window_handles[2])
                        self.tokendata['.AspNet.Cookies'] = browser.get_cookie('.AspNet.Cookies').get('value')
                    elif self.msgtrc == 'true':
                        browser.switch_to.window(browser.window_handles[2])

                        self.tokendata['.AspNet.Cookies'] = browser.get_cookie('.AspNet.Cookies').get('value')

                        for request in browser.requests:
                            if request.url == "https://admin.exchange.microsoft.com/beta/UserProfile":
                                self.tokendata['validationkey'] = request.headers['validationkey']                    

                    browser.switch_to.window(browser.window_handles[1])

                    done = False
                    while not done:
                        if not EC.text_to_be_present_in_element((By.ID, "message"), "Manage your Exchange Online mailboxes and messaging configurations in the New Exchange admin center."):
                            inp = input("Could not load page. Would you like to wait another 10 seconds? (y/n)")
                            if inp.lower() == 'y':
                                self.logger.info('Waiting 10 more seconds for web page to load...')
                                time.sleep(10)
                            else:
                                self.logger.info('No longer waiting for exchange cookies. Closing.')
                                done = True
                        else:
                            self.tokendata['msExchEcpCanary'] = browser.get_cookie('msExchEcpCanary').get('value')
                            self.tokendata['OpenIdConnect.token.v1'] = browser.get_cookie('OpenIdConnect.token.v1').get('value')
                            self.logger.info('Exchange cookies acquired.')
                            done = True
                    result = True
                else:
                    result = False
            except Exception as e:
                self.logger.warning(f"Exception happened during auth: {str(e)}")
                result = False

            if browser:
                try:
                    browser.quit()
                except Exception as e:
                    pass
        else:
            self.logger.info("m365 auth set to False. Not gathering Exchange cookies.")
        return result

    @staticmethod
    def get_sub_argparse(auth_parser):
        """
        Get an argparse subparser for authentication
        """
        auth_parser.add_argument('-a',
                                 '--authfile',
                                 action='store',
                                 help='File to store the credentials (default: .ugt_auth)',
                                 default='.ugt_auth')
        auth_parser.add_argument('--d4iot-authfile',
                                 action='store',
                                 help='File to store the credentials for defender for iOt(default: .d4iot_auth)',
                                 default='.d4iot_auth')
        auth_parser.add_argument('-c',
                                 '--config',
                                 action='store',
                                 help='Path to config file with auth credentials',
                                 default='.conf')
        auth_parser.add_argument('--d4iot-config',
                                 action='store',
                                 help='Path to config file with d4iot auth credentials',
                                 default='.d4iot_conf')
        auth_parser.add_argument('--revoke',
                                 action='store_true',
                                 help='Revoke sessions for user with credentials in tokenfile (default to .ugt_auth)',
                                 default=False)
        auth_parser.add_argument('--interactive',
                                 action='store_true',
                                 help='Interactive mode for Selenium. Default to false (headless).',
                                 default=False)
        auth_parser.add_argument('--debug',
                                 action='store_true',
                                 help='Enable debug logging to disk')
        auth_parser.add_argument('--d4iot',
                                 action='store_true',
                                 help='Run the authentication portion for d4iot',
                                 default=False)
        return auth_parser


    def parse_config(self, configfile):
        config = configparser.ConfigParser()
        config.read(configfile)
        self.username = config_get(config, 'auth', 'username', self.logger)
        self.password = config_get(config, 'auth', 'password', self.logger)
        self.app_client_id = config_get(config, 'auth', 'appid', self.logger)
        self.client_secret = config_get(config, 'auth', 'clientsecret', self.logger)
        self.tenant = config_get(config, 'auth', 'tenant', self.logger)

        if self.d4iot:
            self.d4iot_sensor_token = config_get(config, 'auth', 'd4iot_sensor_token', self.logger)
            self.d4iot_mgmt_token = config_get(config, 'auth', 'd4iot_mgmt_token', self.logger)
            self.d4iot_sensor_ip = config_get(config, 'auth', 'd4iot_sensor_ip', self.logger)
            self.d4iot_mgmt_ip = config_get(config, 'auth', 'd4iot_mgmt_ip', self.logger)

        else:
            self.us_government = config_get(config, 'auth', 'us_government', self.logger).lower()
            self.exo_us_government = config_get(config, 'auth', 'exo_us_government', self.logger).lower()
            self.msgtrc = config_get(config, 'auth', 'msgtrace', self.logger).lower()
            self.subscriptions = config_get(config, 'auth', 'subscriptionid', self.logger)
            self.m365 = config_get(config, 'auth', 'm365', self.logger).lower()

        """# Get CSP to know if we need to auth to admin.microsoft.com
        self.get_csp = config_get(config, 'azuread', 'csp', self.logger).lower() == 'true'
        """

        # TODO: Read other options in config file and see what resource URIs we need
        return config

    def _read_current_tokens(self, authfile: str):
        tokens = {} 

        try:
            tokens = json.loads(open(authfile, 'r').read())
        except Exception as e:
            self.logger.info(f"Could not read current authfile: {str(e)}\nThis is normal if this is your first time running auth.")

        return tokens

    def d4iot_auth(self):
        if self.username and self.password:
            self.auth_device_selenium = True 

        custom_auth_dict = self._read_current_tokens(self.d4iot_authfile)

        if 'sensor' not in custom_auth_dict:
            custom_auth_dict['sensor'] = {}


        USERNAMEFIELD = (By.ID, "TextField3")
        PASSWORDFIELD = (By.ID, "TextField6")
        NEXTBUTTON = (By.ID, "id__9")
        
        url = self.get_d4iot_sensor_uri()

        self.logger.debug("Authenticating to Defender for IoT sensor at %s" % (url))
        browser = self.get_webdriver_browser()
        if self.d4iot:
            try:
                if browser:
                    browser.get(url)
                    try:
                        WebDriverWait(browser, 10).until(EC.url_to_be(url))

                    except Exception as e:
                        pass
                    
                    WebDriverWait(browser, 1).until(EC.element_to_be_clickable(USERNAMEFIELD)).send_keys(self.username)
                    
                    WebDriverWait(browser, 1).until(EC.element_to_be_clickable(PASSWORDFIELD)).send_keys(self.password)

                    WebDriverWait(browser, 1).until(EC.element_to_be_clickable(NEXTBUTTON)).click()
                    # Click Next
                    
                    time.sleep(2)
                    self.tokendata['sessionId'] = browser.get_cookie('sessionid').get('value')
                    self.tokendata['csrftoken'] = browser.get_cookie('csrftoken').get('value')
                    self.logger.info('Obtained d4iot cookies.')

                    if self.tokendata:
                        custom_auth_dict['sensor'] = copy.copy(self.tokendata)

                    try:
                        with open(self.d4iot_authfile, 'w') as outfile:
                            json.dump(custom_auth_dict, outfile, indent=2, sort_keys=True)
                    except Exception as e:
                        self.logger.error(f"Error writing auth to file: {str(e)}")
                    self.logger.info(green + "Authentication complete." + green)
            except Exception as e:
                print(e)


    def ugt_auth(self):

        custom_auth_dict = self._read_current_tokens(self.authfile)

        if 'mfa' not in custom_auth_dict:
            custom_auth_dict['mfa'] = {}
        if 'app_auth' not in custom_auth_dict:
            custom_auth_dict['app_auth'] = {}
        if 'sdk_auth' not in custom_auth_dict:
            custom_auth_dict['sdk_auth'] = {}
        

        if self.username and self.password:
            self.auth_device_selenium = True 

            self.authenticate_mfa_interactive()
       
        custom_auth_dict['sdk_auth']['tenant_id'] = self.tenant 
        custom_auth_dict['sdk_auth']['app_id'] = self.app_client_id
        custom_auth_dict['sdk_auth']['client_secret'] = self.client_secret         
        custom_auth_dict['sdk_auth']['subscriptionid'] = self.subscriptions 


        uri = self.get_mfa_resource_uri()

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

            try:
                with open(self.authfile, 'w') as outfile:
                    json.dump(custom_auth_dict, outfile, indent=2, sort_keys=True)
            except Exception as e:
                self.logger.error(f"Error writing auth to file: {str(e)}")

    def revoke_tokens(self, args) -> None:

        self.parse_authfile(args.authfile)

        try:
            with open(args.authfile, 'r') as infile:
                authfile = json.loads(infile.read())
        except Exception as e:
            raise e

        if not 'oid' in authfile:
            self.logger.error("Error: no oid param in auth file.")
            return

        URL = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/UserDetailsMenuBlade/Profile/userId/{}".format(authfile['oid'])
        EMAILFIELD = (By.ID, "i0116")
        PASSWORDFIELD = (By.ID, "i0118")
        NEXTBUTTON = (By.ID, "idSIButton9")
        REVOKEBUTTON = (By.XPATH, "//div[@title='Revoke sessions']")
        YESBUTTON = (By.XPATH, "//div[@title='Yes'][@role='button']")

        browser = self.get_webdriver_browser()

        browser.get(URL)

        WebDriverWait(browser, 10).until(EC.element_to_be_clickable(EMAILFIELD)).send_keys(self.username)

        WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

        WebDriverWait(browser, 10).until(EC.element_to_be_clickable(PASSWORDFIELD)).send_keys(self.password)

        WebDriverWait(browser, 10).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

        # Stay signed in
        WebDriverWait(browser, 20).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

        WebDriverWait(browser, 20).until(EC.element_to_be_clickable(REVOKEBUTTON))
        time.sleep(1)
        WebDriverWait(browser, 20).until(EC.element_to_be_clickable(REVOKEBUTTON)).click()

        WebDriverWait(browser, 20).until(EC.element_to_be_clickable(YESBUTTON)).click()

        if browser:
            browser.quit()

    def authenticate_with_refresh(self, config, oldtokendata):
        """
        Authenticate with a refresh token, refreshes the refresh token
        and obtains an access token
        """
        self.us_government = config_get(config, 'auth', 'us_government', self.logger).lower()
        authority_uri = self.get_authority_url()

        context = adal.AuthenticationContext(authority_uri, api_version=None, proxies=None, verify_ssl=True)
        resource_uri = self.get_resource_uri()
        try:
            newtokendata = context.acquire_token_with_refresh_token(oldtokendata['refreshToken'], self.client_id, resource_uri)
        except Exception as e:
            if self.logger:
                self.logger.warning("Error with acquiring context token.")
            else:
                self.logger.error("Error with acquiring context token.")
            return self.tokendata
        # Overwrite fields
        for ikey, ivalue in newtokendata.items():
            self.tokendata[ikey] = ivalue
        return self.tokendata

    def parse_args(self, args):
        self.authfile = args.authfile
        self.debug = args.debug
        if args.d4iot:
            self.d4iot = True
            self.config = args.d4iot_config
            self.d4iot_authfile = args.d4iot_authfile
        else:
            self.config = args.config
        self.headless = not args.interactive
        self.parse_config(self.config)
        self.logger = setup_logger(__name__, self.debug)

def check_app_auth_token(auth_data, logger):
    expiry_time = auth_data['expires_on']
    if time.time() > expiry_time:
        logger.warning("Authentication expired. Please re-authenticate before proceeding.")
        return True
    return False


def check_token(config, auth_data: dict, logger, EXPIRY_THRESHOLD_SECONDS=300):
    """Token refresher

    :param auth_data: Authentication data from auth file
    :type auth_data: dict
    :return: Updated authentication tokens
    :rrtype: dict
    """

    logger.info("Checking auth token for expiry")

    if auth_data == {}:
        logger.info("No MFA tokens (was M365 set to False?) detected, proceeding.")
    else:
        if not 'exp' in auth_data['id_token_claims']:
            logger.debug('No expireTime set in auth_data, returning')
            return auth_data 
        
        if time.time() > auth_data['id_token_claims']['exp']:
            logger.debug("Auth token within expiry threshold. Attempting to refresh...")
            auth = Authentication()
            auth.tokendata = auth_data
            auth.tenant = auth_data['tenantId']
            auth.us_government = config['auth']['us_government'].lower()
            authority_host_uri = auth.get_authority_url()
            cache = msal.SerializableTokenCache()
            if os.path.exists("token_cache.bin"):
                cache.deserialize(open("token_cache.bin", "r").read())
            
            context = msal.PublicClientApplication(client_id=auth.client_id,  authority=authority_host_uri, token_cache=cache)
            accounts = context.get_accounts()
            token_data_to_add = context.acquire_token_silent(scopes=[auth.resource_uri], account=accounts[0])

            if 'access_token' in token_data_to_add:
                if token_data_to_add.get('access_token') == '':
                    logger.warning("Error refreshing token, attempt re-auth!")
                    return auth_data
                logger.info('Refreshed token successfully.')
                for ikey, ivalue in token_data_to_add.items():
                    auth_data[ikey] = ivalue
                return auth_data
            elif time.time() >  auth_data['id_token_claims']['exp']:
                logger.warning('Access token is expired, but no access to refresh token!')
                return auth_data

        else:
            logger.info("Auth token is not within expiry threshold, proceeding.")
    return auth_data    

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

if __name__ == '__main__':
    main()