#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: Auth!
This module handles authentication to Azure AD, Azure, M365, and D4IoT environments.
"""

import adal
import argparse
import atexit
import configparser
import copy
import getpass
import json
import msal
import os
import pyAesCrypt
import sys
import time

from goosey.utils import *
from selenium.webdriver import FirefoxOptions
from selenium.webdriver.common.by import By
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from seleniumwire import webdriver

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

green = "\x1b[1;32m"

class Authentication():
    """
    Authentication class for Untitled Goose Tool
    """
    def __init__(self, debug=False):
        self.resource_uri = 'https://graph.microsoft.com/.default'
        self.tokendata = {}
        self.headless = False
        self.logger = None
        self.d4iot = False
        self.encryption_pw = None

    def get_webdriver_browser(self):
        """
        Initializes and returns the browser object.
        """
        browser = None

        try:
            opts = FirefoxOptions()
            options = {
                'request_storage': 'memory'
            }
            if self.headless:
                opts.add_argument("--headless")
            browser = webdriver.Firefox(options=opts,seleniumwire_options=options)
        except Exception as e:
            self.logger.error(f'Error getting Firefox webdriver: {str(e)}. Exiting.')
            sys.exit(1)
            
        return browser

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
                return ['https://graph.microsoft.com/.default', 'https://api.securitycenter.microsoft.com/.default', 'https://management.azure.com/.default', 'https://api.security.microsoft.com/.default']
            elif self.mde_gcc == 'true':
                return ['https://graph.microsoft.com/.default', 'https://api.securitycenter.microsoft.com/.default', 'https://api-gcc.securitycenter.microsoft.us', 'https://api-gcc.security.microsoft.us']
            elif self.mde_gcc_high == 'true':
                return ['https://graph.microsoft.com/.default', 'https://api.securitycenter.microsoft.com/.default', 'https://api-gov.securitycenter.microsoft.us', 'https://api-gov.security.microsoft.us']
        elif self.us_government == 'true':
            if self.mde_gcc == 'true':
                return ['https://graph.microsoft.us/.default', 'https://management.azure.us/.default', 'https://api-gcc.securitycenter.microsoft.us', 'https://api-gcc.security.microsoft.us']
            elif self.mde_gcc_high =='true':
                return ['https://graph.microsoft.us/.default', 'https://management.azure.us/.default', 'https://api-gov.securitycenter.microsoft.us', 'https://api-gov.security.microsoft.us']

    def authenticate_device_code_selenium(self):
        """
        Authenticate the end-user using device authentication through Selenium.
        """
        authority_host_uri = self.get_authority_url()
        self.logger.debug(f"Device code selenium authority uri: {str(authority_host_uri)}")
        resource_uri = self.get_mfa_resource_uri()
        self.logger.debug(f"Device code selenium resource uri: {str(resource_uri)}")

        context = msal.PublicClientApplication(client_id=self.app_client_id, authority=authority_host_uri)
        code = context.initiate_device_flow(scopes=resource_uri)

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

            WebDriverWait(browser, 60).until(EC.element_to_be_clickable(CODEFIELD)).send_keys(one_time_code)

            WebDriverWait(browser, 60).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

            self.logger.debug("Device code authentication - Device code entered.")

            WebDriverWait(browser, 60).until(EC.element_to_be_clickable(EMAILFIELD)).send_keys(self.username)

            WebDriverWait(browser, 60).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

            self.logger.debug("Device code authentication - Username entered.")

            time.sleep(1)

            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'usernameError')))
                browser.quit()
                sys.exit("Device code authentication - Incorrect username. Please correct it and try again.")  
            except Exception as e:
                pass                            

            WebDriverWait(browser, 60).until(EC.element_to_be_clickable(PASSWORDFIELD)).send_keys(self.password)

            WebDriverWait(browser, 60).until(EC.element_to_be_clickable(NEXTBUTTON)).click()
           
            self.logger.debug("Device code authentication - Password entered.")

            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'passwordError')))
                browser.quit()
                sys.exit("Device code authentication - Incorrect password. Please correct it and try again.")  
            except Exception as e:
                pass    
            
            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'idDiv_SAASDS_Title')))
                browser.quit()
                sys.exit("Device code authentication - Declined MFA. Please correct it and try again.")  
            except Exception as e:
                pass    

            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'ChangePasswordDescription')))
                browser.quit()
                sys.exit("Device code authentication - Password reset required. Change your password and try again.")
            except Exception as e:
                pass

            try:
                if "Your organization needs more information to keep your account secure" in browser.find_element(By.ID, "ProofUpDescription").text:
                    browser.quit()
                    sys.exit("Device code authentication - Your organization needs more information to keep your account secure. Manually fix this problem and try again.")
            except Exception as e:
                pass

            try:
                if "Your sign-in was successful but does not meet the criteria to access this resource" in browser.find_element(By.ID, "ErrorDescription").text:
                    browser.quit()
                    sys.exit("Device code authentication - Your sign-in was successful but does not meet the criteria to access this resource. For example, you might be signing in from a browser, app, or location that is restricted by your admin. Make sure to meet your conditional access policies and try again.")
            except Exception as e:
                pass

            try:
                if "Your account is at risk" in browser.find_element(By.ID, "landingTitle").text:
                    browser.quit()
                    sys.exit("Device code authentication - Your account is at risk. Please investigate this issue and try again.")
            except Exception as e:
                pass

            try:
                if "Approve sign in request" in browser.find_element(By.ID, "idDiv_SAOTCAS_Title").text:
                    self.logger.debug("Device code authentication - Push notification MFA detected.")

                    if browser.find_element(By.ID, "idRichContext_DisplaySign"):
                        self.logger.debug("Device code authentication - Number matching MFA detected.")
                        mfa_code = browser.find_element(By.ID, "idRichContext_DisplaySign").text
                        self.logger.info("Device code authentication - Your MFA code is: " + str(mfa_code))
                        time.sleep(10)

                    time.sleep(20)

                    if "Approve sign in request" in browser.find_element(By.ID, "idDiv_SAOTCAS_Title").text:
                        self.logger.info("Device code authentication - The MFA request was not approved in time.")
                        browser.quit()
                        sys.exit(1)                        
            except Exception as e:
                pass

            try:
                if "Enter code" in browser.find_element(By.ID, "idDiv_SAOTCC_Title").text:
                    self.logger.debug("Device code authentication - OTP MFA detected.")

                    if browser.find_element(By.ID, "idTxtBx_SAOTCC_OTC"):
                        OTP = (By.ID, "idTxtBx_SAOTCC_OTC")
                        OTP_code = getpass.getpass("Device code authentication - Please type your OTP code: ")
                        verify = (By.ID, "idSubmit_SAOTCC_Continue")

                        WebDriverWait(browser, 60).until(EC.element_to_be_clickable(OTP)).send_keys(OTP_code)
                        WebDriverWait(browser, 60).until(EC.element_to_be_clickable(verify)).click()
                    
                    if browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC"):
                        errormsg = browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC").text
                        self.logger.error("Device code authentication - OTP error message: " + errormsg)
                        browser.quit()
                        sys.exit("Device code authentication - MFA failed. Please see OTP error message and try again.")                    
            except Exception as e:
                pass

            try:
                if "Verify your identity" in browser.find_element(By.ID, "idDiv_SAOTCS_Title").text:
                    self.logger.debug("Device code authentication - Other MFA detected.")

                    if "Text" in browser.find_element(By.ID, "idDiv_SAOTCS_Proofs_Section").text:
                        self.logger.debug("Device code authentication - Text option found.")
                        sms = (By.ID, "idDiv_SAOTCS_Proofs_Section")
                        WebDriverWait(browser, 60).until(EC.element_to_be_clickable(sms)).click()
                        self.logger.debug("Device code authentication - SMS OTP requested.")
                        time.sleep(10)

                        if "Enter code" in browser.find_element(By.ID, "idDiv_SAOTCC_Title").text:
                            self.logger.debug("Device code authentication - SMS OTP MFA detected.")

                            if browser.find_element(By.ID, "idTxtBx_SAOTCC_OTC"):
                                OTP = (By.ID, "idTxtBx_SAOTCC_OTC")
                                OTP_code = getpass.getpass("Device code authentication - Please type your OTP code: ")
                                verify = (By.ID, "idSubmit_SAOTCC_Continue")

                                WebDriverWait(browser, 60).until(EC.element_to_be_clickable(OTP)).send_keys(OTP_code)
                                WebDriverWait(browser, 60).until(EC.element_to_be_clickable(verify)).click()
                            
                            if browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC"):
                                errormsg = browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC").text
                                self.logger.error("Device code authentication - OTP error message: " + errormsg)
                                browser.quit()
                                sys.exit("Device code authentication - MFA failed. Please see OTP error message and try again.")                          
            except Exception as e:
                pass

            try:
                WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'ChangePasswordDescription')))
                browser.quit()
                sys.exit("Device code authentication - Password reset required. Change your password and try again.")
            except Exception as e:
                pass

            # Wait for AAD PowerShell prompt
            WebDriverWait(browser, 60).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

            WebDriverWait(browser, 60).until(EC.text_to_be_present_in_element((By.ID, "message"), "You may now close this window."))
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
        
        self.logger.info('Device code authentication complete.')

        return self.tokendata

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

    def authenticate_mfa_interactive(self):
        """
        Authenticate via username, password, and MFA to get session ID and cookies.
        """

        if self.auth_device_selenium:
            self.authenticate_device_code_selenium()

        result = False

        EMAILFIELD = (By.ID, "i0116")
        PASSWORDFIELD = (By.ID, "i0118")
        NEXTBUTTON = (By.ID, "idSIButton9")

        browser = self.get_webdriver_browser()

        if self.m365 == 'true':
            self.logger.debug("M365 authentication set to True. Pulling authentication information.")
            self.logger.info('Attempting to automatically auth as an user. You may have to accept MFA prompts.')
            try:
                if browser:
                    if self.us_government == 'false':
                        browser.get("https://login.microsoftonline.com")
                    elif self.us_government == 'true':
                        browser.get("https://login.microsoftonline.us")

                    WebDriverWait(browser, 60).until(EC.element_to_be_clickable(EMAILFIELD)).send_keys(self.username)
                    
                    WebDriverWait(browser, 60).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

                    self.logger.debug("M365 user authentication - Username entered.")
                    time.sleep(1)

                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'usernameError')))
                        browser.quit()
                        sys.exit("M365 user authentication - Incorrect username. Please correct it and try again.")  
                    except Exception as e:
                        pass     

                    WebDriverWait(browser, 60).until(EC.element_to_be_clickable(PASSWORDFIELD)).send_keys(self.password)
                    
                    WebDriverWait(browser, 60).until(EC.element_to_be_clickable(NEXTBUTTON)).click()

                    self.logger.debug("M365 user authentication - Password entered.")

                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'passwordError')))
                        browser.quit()
                        sys.exit("M365 user authentication - Incorrect password. Please correct it and try again.")  
                    except Exception as e:
                        pass    
                
                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'ChangePasswordDescription')))
                        browser.quit()
                        sys.exit("M365 user authentication - Password reset required. Change your password and try again.")
                    except Exception as e:
                        pass

                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'idDiv_SAASDS_Title')))
                        browser.quit()
                        sys.exit("M365 user authentication - Declined MFA. Please correct it and try again.") 
                    except Exception as e:
                        pass

                    try:
                        if "Your organization needs more information to keep your account secure" in browser.find_element(By.ID, "ProofUpDescription").text:
                            browser.quit()
                            sys.exit("M365 user authentication - Your organization needs more information to keep your account secure. Manually fix this problem and try again.")
                    except Exception as e:
                        pass

                    try:
                        if "Your sign-in was successful but does not meet the criteria to access this resource" in browser.find_element(By.ID, "ErrorDescription").text:
                            browser.quit()
                            sys.exit("M365 user authentication - Your sign-in was successful but does not meet the criteria to access this resource. For example, you might be signing in from a browser, app, or location that is restricted by your admin. Make sure to meet your conditional access policies and try again.")
                    except Exception as e:
                        pass

                    try:
                        if "Your account is at risk" in browser.find_element(By.ID, "landingTitle").text:
                            browser.quit()
                            sys.exit("M365 user authentication - Your account is at risk. Please investigate this issue and try again.")
                    except Exception as e:
                        pass

                    try:
                        if "Approve sign in request" in browser.find_element(By.ID, "idDiv_SAOTCAS_Title").text:
                            self.logger.debug("M365 user authentication - Push notification MFA detected.")

                            if browser.find_element(By.ID, "idRichContext_DisplaySign"):
                                self.logger.debug("M365 user authentication - Number matching MFA detected.")
                                mfa_code = browser.find_element(By.ID, "idRichContext_DisplaySign").text
                                self.logger.info("M365 user authentication - Your MFA code is: " + str(mfa_code))
                                time.sleep(10)

                            time.sleep(20)

                            if "Approve sign in request" in browser.find_element(By.ID, "idDiv_SAOTCAS_Title").text:
                                self.logger.info("M365 user authentication - The MFA request was not approved in time.")
                                browser.quit()
                                sys.exit(1)                        
                    except Exception as e:
                        pass

                    try:
                        if "Enter code" in browser.find_element(By.ID, "idDiv_SAOTCC_Title").text:
                            self.logger.debug("M365 user authentication - OTP MFA detected.")

                            if browser.find_element(By.ID, "idTxtBx_SAOTCC_OTC"):
                                OTP = (By.ID, "idTxtBx_SAOTCC_OTC")
                                OTP_code = getpass.getpass("M365 user authentication - Please type your OTP code: ")
                                verify = (By.ID, "idSubmit_SAOTCC_Continue")

                                WebDriverWait(browser, 60).until(EC.element_to_be_clickable(OTP)).send_keys(OTP_code)
                                WebDriverWait(browser, 60).until(EC.element_to_be_clickable(verify)).click()
                            
                            if browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC"):
                                errormsg = browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC").text
                                self.logger.error("M365 user authentication - OTP error message: " + errormsg)
                                browser.quit()
                                sys.exit("M365 user authentication - MFA failed. Please see OTP error message and try again.")                    
                    except Exception as e:
                        pass

                    try:
                        if "Verify your identity" in browser.find_element(By.ID, "idDiv_SAOTCS_Title").text:
                            self.logger.debug("M365 user authentication - Other MFA detected.")

                            if "Text" in browser.find_element(By.ID, "idDiv_SAOTCS_Proofs_Section").text:
                                self.logger.debug("M365 user authentication - Text option found.")
                                sms = (By.ID, "idDiv_SAOTCS_Proofs_Section")
                                WebDriverWait(browser, 60).until(EC.element_to_be_clickable(sms)).click()
                                self.logger.debug("M365 user authentication - SMS OTP requested.")
                                time.sleep(10)

                                if "Enter code" in browser.find_element(By.ID, "idDiv_SAOTCC_Title").text:
                                    self.logger.debug("M365 user authentication - SMS OTP MFA detected.")

                                    if browser.find_element(By.ID, "idTxtBx_SAOTCC_OTC"):
                                        OTP = (By.ID, "idTxtBx_SAOTCC_OTC")
                                        OTP_code = getpass.getpass("M365 user authentication - Please type your OTP code: ")
                                        verify = (By.ID, "idSubmit_SAOTCC_Continue")

                                        WebDriverWait(browser, 60).until(EC.element_to_be_clickable(OTP)).send_keys(OTP_code)
                                        WebDriverWait(browser, 60).until(EC.element_to_be_clickable(verify)).click()
                                    
                                    if browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC"):
                                        errormsg = browser.find_element(By.ID, "idDiv_SAOTCC_ErrorMsg_OTC").text
                                        self.logger.error("M365 user authentication - OTP error message: " + errormsg)
                                        browser.quit()
                                        sys.exit("M365 user authentication - MFA failed. Please see OTP error message and try again.")                          
                    except Exception as e:
                        pass

                    time.sleep(5)

                    try:
                        WebDriverWait(browser, 3).until(EC.presence_of_element_located((By.ID, 'ChangePasswordDescription')))
                        browser.quit()
                        sys.exit("Device code authentication - Password reset required. Change your password and try again.")
                    except Exception as e:
                        pass                    

                    time.sleep(5)

                    # Switch to second tab
                    browser.execute_script("window.open('');")
                    browser.switch_to.window(browser.window_handles[1])
                    self.logger.debug("Opening second tab: Exchange Control Panel")
                    if self.exo_us_government == 'false':
                        browser.get("https://outlook.office365.com/ecp")
                        try:
                            WebDriverWait(browser, 20).until(EC.url_matches('https://outlook.office365.com/ecp'))
                        except Exception as e:
                            pass
                    elif self.exo_us_government == 'true':
                        browser.get("https://outlook.office365.us/ecp")
                        try:
                            WebDriverWait(browser, 20).until(EC.url_matches('https://outlook.office365.us/ecp'))
                        except Exception as e:
                            pass
                    self.logger.debug("Completed loading second window!")
                    time.sleep(1)

                    # Switch to third tab
                    browser.execute_script("window.open('');")
                    browser.switch_to.window(browser.window_handles[2])
                    self.logger.debug("Opening third tab: Admin Exchange Portal")
                    if self.exo_us_government == 'false':
                        browser.get("https://admin.exchange.microsoft.com/#/messagetrace")
                        try:
                            WebDriverWait(browser, 20).until((EC.url_matches('https://admin.exchange.microsoft.com/#/messagetrace')))
                        except Exception as e:
                            pass
                    elif self.exo_us_government == 'true':
                        browser.get("http://admin.exchange.office365.us/#/messagetrace")
                        try:
                            WebDriverWait(browser, 20).until((EC.url_matches('https://admin.exchange.microsoft.us/#/messagetrace')))
                        except Exception as e:
                            pass
                    self.logger.debug("Completed loading third window!")
                    time.sleep(1)

                    # Switch back to first tab
                    browser.switch_to.window(browser.window_handles[0])
                    self.logger.debug("Switching back to first tab: Audit Log Search.")
                    if self.exo_us_government == 'false':
                        browser.get("https://security.microsoft.com/auditlogsearch")
                        try:
                            WebDriverWait(browser, 20).until(EC.url_matches('https://security.microsoft.com/auditlogsearch'))
                        except Exception as e:
                            pass
                    elif self.exo_us_government == 'true':
                        browser.get("https://security.microsoft.us/auditlogsearch")
                        try:
                            WebDriverWait(browser, 20).until(EC.url_matches('https://security.microsoft.us/auditlogsearch'))
                        except Exception as e:
                            pass
                    try:
                        cookie_str = 'Session ID cookie - security.microsoft.com/auditlogsearch'
                        if browser.get_cookie('s.SessID').get('value'):
                            self.tokendata['sessionId'] = browser.get_cookie('s.SessID').get('value')
                    except Exception as e:
                        self.logger.error("Error obtaining " + cookie_str + ": " + str(e))
                    try:                            
                        cookie_str = 'sccauth cookie - security.microsoft.com/auditlogsearch'    
                        if browser.get_cookie('sccauth').get('value'):
                            self.tokendata['sccauth'] = browser.get_cookie('sccauth').get('value')
                    except Exception as e:
                        self.logger.error("Error obtaining " + cookie_str + ": " + str(e))
                    try:
                        cookie_str = 'XSRF-TOKEN - security.microsoft.com/auditlogsearch'        
                        if browser.get_cookie('XSRF-TOKEN').get('value'):
                            self.tokendata['xsrf'] = browser.get_cookie('XSRF-TOKEN').get('value')
                    except Exception as e:
                        self.logger.error("Error obtaining " + cookie_str + ": " + str(e))
                    
                    self.logger.info('First tab: Obtained audit log cookies.')

                    browser.switch_to.window(browser.window_handles[2])

                    try:
                        cookie_str = '.AspNet cookie - admin.exchange.microsoft.com'
                        if browser.get_cookie('.AspNet.Cookies').get('value'):
                            self.tokendata['.AspNet.Cookies'] = browser.get_cookie('.AspNet.Cookies').get('value')
                    except Exception as e:
                        self.logger.error("Error obtaining " + cookie_str + ": " + str(e))

                    try:
                        validkey = None
                        while validkey == None:
                            count = 0
                            for request in browser.requests:
                                count += 1
                                if request.headers['validationkey']:
                                    self.logger.debug("Validationkey found! It took " + str(count) + " requests.")
                                    validkey = request.headers['validationkey']
                                    break
                        self.tokendata['validationkey'] = validkey
                    except Exception as e:
                        self.logger.error("Error obtaining validationkey: " + str(e))

                    self.logger.info("Third tab: Obtained Exchange cookies.")               

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
                            try:
                                cookie_str = 'msExchEcpCanary cookie - outlook.office365.com/ecp'
                                if browser.get_cookie('msExchEcpCanary').get('value'):
                                    self.tokendata['msExchEcpCanary'] = browser.get_cookie('msExchEcpCanary').get('value')
                            except Exception as e:
                                self.logger.error("Error obtaining " + cookie_str + ": " + str(e))
                            try:
                                cookie_str = 'OpenIdConnect.token.v1 cookie - outlook.office365.com/ecp'
                                if browser.get_cookie('OpenIdConnect.token.v1').get('value'):
                                    self.tokendata['OpenIdConnect.token.v1'] = browser.get_cookie('OpenIdConnect.token.v1').get('value')
                            except Exception as e:
                                self.logger.error("Error obtaining " + cookie_str + ": " + str(e))    
                                                        
                            self.logger.info('Second tab: Exchange Control Panel cookies acquired.')
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

            self.logger.info('User authentication complete.')
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
        auth_parser.add_argument('--revoke',
                                 action='store_true',
                                 help='Revoke sessions for user with authentication tokens and cookies (default: .ugt_auth)',
                                 default=False)
        auth_parser.add_argument('--interactive',
                                 action='store_true',
                                 help='Interactive mode for Selenium. Default to false (headless).',
                                 default=False)
        auth_parser.add_argument('--debug',
                                 action='store_true',
                                 help='Enable debug logging')
        auth_parser.add_argument('--d4iot',
                                 action='store_true',
                                 help='Run the authentication portion for d4iot',
                                 default=False)
        auth_parser.add_argument('--secure',
                                 action='store_true',
                                 help='Enable secure authentication handling (file encryption)')
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
            self.m365 = config_get(config, 'config', 'm365', self.logger).lower()

            if self.us_government == '' or self.mde_gcc == '' or self.mde_gcc_high == '' or self.tenant == '' or self.exo_us_government == '' or self.subscriptions == '' or self.m365 == '':
                self.logger.error("Empty contents within .conf file. Please edit and try again.")
                sys.exit(1)
        else:
            self.d4iot_sensor_ip = config_get(config, 'config', 'd4iot_sensor_ip', self.logger)
            self.d4iot_mgmt_ip = config_get(config, 'config', 'd4iot_mgmt_ip', self.logger)

        return config

    def parse_auth(self, authfile=None):
        if authfile is not None:
            auth = configparser.ConfigParser()
            auth.read(authfile)
            if config_get(auth, 'auth', 'username', self.logger):
                self.username = config_get(auth, 'auth', 'username', self.logger)
            else:
                self.username = getpass.getpass("Please type your username: ")
            if config_get(auth, 'auth', 'password', self.logger):
                self.password = config_get(auth, 'auth', 'password', self.logger)
            else:
                self.password = getpass.getpass("Please type your password: ")
            if not self.d4iot:
                if config_get(auth, 'auth', 'appid', self.logger):
                    self.app_client_id = config_get(auth, 'auth', 'appid', self.logger)
                else:
                    self.app_client_id = getpass.getpass("Please type your application client id: ")
                if config_get(auth, 'auth', 'clientsecret', self.logger):
                    self.client_secret = config_get(auth, 'auth', 'clientsecret', self.logger)
                else:
                    self.client_secret = getpass.getpass("Please type your client secret: ")       

            if self.d4iot:
                if config_get(auth, 'auth', 'd4iot_sensor_token', self.logger):
                    self.d4iot_sensor_token = config_get(auth, 'auth', 'd4iot_sensor_token', self.logger)
                else:
                    self.d4iot_sensor_token = getpass.getpass("Please type your D4IOT sensor token: ")
                if config_get(auth, 'auth', 'd4iot_mgmt_token', self.logger):
                    self.d4iot_mgmt_token = config_get(auth, 'auth', 'd4iot_mgmt_token', self.logger)
                else:
                    self.d4iot_mgmt_token = getpass.getpass("Please type your D4IOT management console token: ")

        else:
            self.username = getpass.getpass("Please type your username: ")
            self.password = getpass.getpass("Please type your password: ")
            if not self.d4iot:
                self.app_client_id = getpass.getpass("Please type your application client id: ")
                self.client_secret = getpass.getpass("Please type your client secret: ")
            else:
                self.d4iot_sensor_token = getpass.getpass("Please type your D4IOT sensor token: ")
                self.d4iot_mgmt_token = getpass.getpass("Please type your D4IOT management console token: ")

    def _read_current_tokens(self, authfile: str):
        tokens = {} 

        try:
            tokens = json.loads(open(authfile, 'r').read())
        except Exception as e:
            self.logger.info(f"Could not read current authfile: {str(e)}\nThis is normal if this is your first time running auth.")

        return tokens

    def d4iot_auth(self):
        if self.secure:
            if self.encryption_pw is None:
                self.encryption_pw = getpass.getpass("Please type the password for file encryption: ")            
            dir_path = os.path.dirname(os.path.realpath(self.d4iot_authfile))
            encrypted_authfile = os.path.join(dir_path, self.d4iot_authfile + '.aes')           
            if os.path.isfile(encrypted_authfile):
                pyAesCrypt.decryptFile(encrypted_authfile, self.d4iot_authfile, self.encryption_pw)
                os.remove(encrypted_authfile)
                self.logger.debug("Decrypted the " + self.d4iot_authfile + " file!")

        if self.username and self.password:
            self.auth_device_selenium = True 

        custom_auth_dict = self._read_current_tokens(self.d4iot_authfile)

        if 'sensor' not in custom_auth_dict:
            custom_auth_dict['sensor'] = {}

        USERNAMEFIELD = (By.ID, "TextField3")
        PASSWORDFIELD = (By.ID, "TextField6")
        NEXTBUTTON = (By.ID, "id__9")
        
        url = self.get_d4iot_sensor_uri()

        self.logger.info("Authenticating to Defender for IoT sensor at %s" % (url))
        browser = self.get_webdriver_browser()
        if self.d4iot:
            try:
                if browser:
                    browser.get(url)
                    try:
                        WebDriverWait(browser, 10).until(EC.url_to_be(url))

                    except Exception as e:
                        pass
                    
                    WebDriverWait(browser, 60).until(EC.element_to_be_clickable(USERNAMEFIELD)).send_keys(self.username)
                    
                    WebDriverWait(browser, 60).until(EC.element_to_be_clickable(PASSWORDFIELD)).send_keys(self.password)

                    WebDriverWait(browser, 60).until(EC.element_to_be_clickable(NEXTBUTTON)).click()
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
            if self.secure:
                if os.path.isfile(self.d4iot_authfile):
                    pyAesCrypt.encryptFile(self.d4iot_authfile, encrypted_authfile, self.encryption_pw)
                    os.remove(self.d4iot_authfile)
                    self.logger.debug("Encrypted the " + self.d4iot_authfile + " file!")  

    def ugt_auth(self):     

        if self.secure:
            if self.encryption_pw is None:
                self.encryption_pw = getpass.getpass("Please type the password for file encryption: ")            
            dir_path = os.path.dirname(os.path.realpath(self.authfile))
            encrypted_authfile = os.path.join(dir_path, self.authfile + '.aes')           
            if os.path.isfile(encrypted_authfile):
                pyAesCrypt.decryptFile(encrypted_authfile, self.authfile, self.encryption_pw)
                os.remove(encrypted_authfile)
                self.logger.debug("Decrypted the " + self.authfile + " file!")

        custom_auth_dict = self._read_current_tokens(self.authfile)

        if self.secure:
            if os.path.isfile(self.authfile):
                pyAesCrypt.encryptFile(self.authfile, encrypted_authfile, self.encryption_pw)
                os.remove(self.authfile)
                self.logger.debug("Encrypted the " + self.authfile + " file!")                  

        if 'mfa' not in custom_auth_dict:
            custom_auth_dict['mfa'] = {}
        if 'app_auth' not in custom_auth_dict:
            custom_auth_dict['app_auth'] = {}
        if 'sdk_auth' not in custom_auth_dict:
            custom_auth_dict['sdk_auth'] = {}
        
        if self.secure:
            dir_path = os.path.dirname(os.path.realpath(self.auth))
            encrypted_auth = os.path.join(dir_path, self.auth + '.aes')  

            if not os.path.isfile(self.auth) or not os.path.isfile(encrypted_auth):
                self.logger.debug("No auth file and no encrypted auth file detected.")         

        if self.username and self.password:
            self.auth_device_selenium = True 
            
            self.authenticate_mfa_interactive()
            
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

        if self.m365 == "True":
            if not custom_auth_dict['mfa'][uri]['access_token']:
                self.logger.error("MFA did not complete successfully. Re-authentication is required.")
                sys.exit(1)

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

        if self.secure:
            if os.path.isfile(self.authfile):
                pyAesCrypt.encryptFile(self.authfile, encrypted_authfile, self.encryption_pw)
                os.remove(self.authfile)
                self.logger.debug("Encrypted the " + self.authfile + " file!")    
        

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

    def parse_args(self, args):
        self.debug = args.debug
        self.logger = setup_logger(__name__, self.debug)
        self.authfile = args.authfile
        self.auth = args.auth
        self.secure = args.secure
        if args.d4iot:
            self.d4iot = True
            self.config = args.d4iot_config
            self.d4iot_authfile = args.d4iot_authfile
            self.auth = args.d4iot_auth
        else:
            self.config = args.config
        self.headless = not args.interactive
        if self.secure:
            dir_path = os.path.dirname(os.path.realpath(self.auth))
            encrypted_auth = os.path.join(dir_path, self.auth + '.aes')             
            if os.path.isfile(encrypted_auth):
                self.encryption_pw = getpass.getpass("Please type the password for file encryption: ")
                pyAesCrypt.decryptFile(encrypted_auth, self.auth, self.encryption_pw)
                os.remove(encrypted_auth)
                self.logger.debug("Decrypted the " + self.auth + " file!")
                
        if os.path.isfile(self.auth):
            self.parse_auth(self.auth)
        else:
            self.logger.debug("No .auth file detected, proceeding with prompting user for username, password, application id, and application client secret inputs.")
            self.parse_auth()
        
        if self.secure:
            if os.path.isfile(self.auth):
                if self.encryption_pw is None:
                    self.encryption_pw = getpass.getpass("Please type the password for file encryption: ")
                pyAesCrypt.encryptFile(self.auth, encrypted_auth, self.encryption_pw)
                os.remove(self.auth)
                self.logger.debug("Encrypted the " + self.auth + " file!")

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

if __name__ == '__main__':
    main()