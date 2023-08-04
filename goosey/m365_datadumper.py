#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: m365_datadumper!
This module has all the telemetry pulls for M365.
"""

import asyncio
import csv
import json
import os
import requests
import subprocess
import sys
import time
import urllib.parse

from aiohttp.client_exceptions import *
from datetime import datetime, timedelta
from goosey.auth import check_app_auth_token
from goosey.datadumper import DataDumper
from goosey.utils import *
from io import StringIO

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

class M365DataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, auth, app_auth, session, config, debug):
        super().__init__(f'{output_dir}{os.path.sep}m365', reports_dir, auth, app_auth, session, debug)
        self.logger = setup_logger(__name__, debug)    
        self.exo_us_government = config_get(config, 'config', 'exo_us_government', self.logger).lower()
        self.inboxfailfile = os.path.join(reports_dir, '_user_inbox_503.json')
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        filters = config_get(config, 'filters', '', logger=self.logger)
        if filters != '' and  filters is not None:
            self.date_range=True
            self.date_start = config_get(config, 'filters', 'date_start')
            if config_get(config, 'filters', 'date_end') != '':
                self.date_end = config_get(config, 'filters', 'date_end')
            else:
                self.date_end = datetime.now().strftime("%Y-%m-%d") +':00:00.000Z'
        else:
            self.date_range=False

        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]

    async def dump_exo_groups(self) -> None:
        """Dumps Exchange Online Role Group and Role Group Members information.

        :return: None
        :rtype: None
        """

        if '.AspNet.Cookies' not in self.auth:
            self.logger.error("Missing .AspNet.Cookies auth cookie. Did you auth correctly? (Skipping dump_exo_groups)")
            return
        
        self.logger.info("Gathering Exchange Online Role Groups...")
        if self.exo_us_government == 'false':
            url = 'https://admin.exchange.microsoft.com/beta/RoleGroup'
        elif self.exo_us_government == 'true':
            url = 'https://admin.exchange.office365.us/beta/RoleGroup'

        headers = {
            'Cookie': '.AspNet.Cookies=' + self.auth['.AspNet.Cookies'] + ';',
            'validationkey': self.auth['validationkey'],
            'Content-Type': 'application/json;charset=UTF-8'
        }

        self.logger.info('Dumping Exchange Online Role Groups...')
        async with self.ahsession.request("GET", url, headers=headers) as r:
            result = await r.json()

            if 'value' not in result:
                if result['error']['message'] == 'Request validation failed with validation key':
                    self.logger.error("Error with validation key: " + result['error']['message'])
                    self.logger.error("Please re-auth.")
                    sys.exit(1)    
                else:
                    self.logger.debug("Error with result: {}".format(str(result)))
                return

            outfile = os.path.join(self.output_dir, "EXO_RoleGroups.json")
            with open(outfile, 'w', encoding="utf-8") as f:
                if 'value' in result:
                    f.write("\n".join([json.dumps(x) for x in result['value']]) + '\n')
            self.logger.info('Finished dumping Exchange Online Role Groups.')
        
        self.logger.info("Gathering Exchange Online Role Group Members...")

        m365_rolegrps = []
        for jsonline in open(outfile, 'r'):
            m365_rolegrps.append(json.loads(jsonline))

        listOfIds = list(findkeys(m365_rolegrps, 'Id'))
        listOfNames = list(findkeys(m365_rolegrps, 'Name'))

        headers = {
            'Cookie': '.AspNet.Cookies=' + self.auth['.AspNet.Cookies'] + ';',
            'validationkey': self.auth['validationkey'],
            'Content-Type': 'application/json;charset=UTF-8'
        }

        self.logger.info('Dumping Exchange Online Role Group Members...')

        for i, j in zip(listOfIds, listOfNames):
            if self.exo_us_government == 'false':
                url = 'https://admin.exchange.microsoft.com/beta/RoleGroup(\'' + i + '\')/ExchangeAdminCenter.GetRoleGroupMembers()'
            elif self.exo_us_government == 'true':
                url = 'https://admin.exchange.office365.us/beta/RoleGroup(\'' + i + '\')/ExchangeAdminCenter.GetRoleGroupMembers()'
            y = {"GroupId": i, "GroupName": j}

            async with self.ahsession.request("GET", url, headers=headers) as r:
                result = await r.json()
                finalvalue = result['value']
                if 'value' not in result:
                    if result['error']['message'] == 'Request validation failed with validation key':
                        self.logger.error("Error with validation key: " + result['error']['message'])
                        self.logger.error("Please re-auth.")
                        sys.exit(1)    
                    else:
                        self.logger.debug("Error with result: {}".format(str(result)))
                    return

                outfile = os.path.join(self.output_dir, "EXO_RoleGroupMembers.json")
                with open(outfile, 'a', encoding="utf-8") as f:
                    if finalvalue:
                        finalvalue.append(y)
                        f.write(json.dumps(finalvalue))
                        f.write("\n")
        
        self.logger.info('Finished dumping Exchange Online Role Groups.') 

    async def dump_exo_mailbox(self) -> None:
        """Dumps Exchange Online mailbox information.

        :return: None
        :rtype: None
        """

        if '.AspNet.Cookies' not in self.auth:
            self.logger.error("Missing .AspNet.Cookies auth cookie. Did you auth correctly? (Skipping dump_exo_mailbox)")
            return

        self.logger.info("Gathering Exchange Online Mailboxes...")
        if self.exo_us_government == 'false':
            url = 'https://admin.exchange.microsoft.com/beta/Recipient'
        elif self.exo_us_government == 'true':
            url = 'https://admin.exchange.office365.us/beta/Recipient'
        headers = {
            'Cookie': '.AspNet.Cookies=' + self.auth['.AspNet.Cookies'] + ';',
            'validationkey': self.auth['validationkey'],
            'Content-Type': 'application/json;charset=UTF-8'
        }

        self.logger.info('Dumping Exchange Online Mailboxes...')
        
        async with self.ahsession.request("GET", url, headers=headers) as r:
            result = await r.json()

            if 'value' not in result:
                if result['error']['message'] == 'Request validation failed with validation key':
                    self.logger.error("Error with validation key: " + result['error']['message'])
                    self.logger.error("Please re-auth.")
                    sys.exit(1)    
                else:
                    self.logger.debug("Error with result: {}".format(str(result)))
                return

            outfile = os.path.join(self.output_dir, "EXO_Mailboxes.json")
            with open(outfile, 'w', encoding='utf-8') as f:
                nexturl = None
                if '@odata.nextLink' in result:
                    nexturl = result['@odata.nextLink']
                if 'value' in result:
                    f.write("\n".join([json.dumps(x) for x in result['value']]) + '\n')

                retries = 5
                while nexturl:
                    try:
                        skiptoken = nexturl.split('skiptoken=')[1]
                        self.logger.debug('Getting nextLink %s' % (skiptoken))

                        async with self.ahsession.get(nexturl, headers=headers, timeout=600) as r2:
                            result2 = await r2.json()

                            if 'value' not in result2:
                                if result2['error']['message'] == 'Request validation failed with validation key':
                                    self.logger.error("Error with validation key: " + result2['error']['message'])
                                    self.logger.error("Please re-auth.")
                                    sys.exit(1)    
                                else:
                                    self.logger.debug("Error with result: {}".format(str(result2)))
                                return

                            self.logger.debug('Received nextLink %s' % (skiptoken))
                            f.write("\n".join([json.dumps(x) for x in result2['value']]) + '\n')
                            f.flush()
                            os.fsync(f)
                            if '@odata.nextLink' in result2:
                                nexturl = result2['@odata.nextLink']
                                retries = 5
                            else:
                                nexturl = None
                    except Exception as e:
                        self.logger.error('Error on nextLink retrieval {}: {}'.format(skiptoken, str(e)))
                        if retries == 0:
                            self.logger.info('Error. No more retries on {}.'.format(skiptoken))
                            nexturl = None 
                        else:
                            self.logger.info('Error. Retrying {} up to {} more times'.format(skiptoken, retries))
                            retries -= 1
                
            self.logger.info('Finished dumping Exchange Online Mailboxes.')

        self.logger.info("Gathering Exchange Online Mailbox CAS Settings...")

        m365_mailboxes = []
        for jsonline in open(outfile, 'r'):
            m365_mailboxes.append(json.loads(jsonline))

        listOfIds = list(findkeys(m365_mailboxes, 'ObjectId'))
        listOfNames = list(findkeys(m365_mailboxes, 'PrimarySmtpAddress'))

        headers = {
            'Cookie': '.AspNet.Cookies=' + self.auth['.AspNet.Cookies'] + ';',
            'validationkey': self.auth['validationkey'],
            'Content-Type': 'application/json;charset=UTF-8'
        }

        self.logger.info('Dumping Exchange Online Mailbox CAS Settings...')

        for i, j in zip(listOfIds, listOfNames):
            if self.exo_us_government == 'false':
                url = 'https://admin.exchange.microsoft.com/beta/Mailbox(' + i + ')?$select=ClientAccessSettings'
            elif self.exo_us_government == 'true':
                url = 'https://admin.exchange.office365.us/beta/Mailbox(' + i + ')?$select=ClientAccessSettings'
            y = {"ObjectId": i, "PrimarySmtpAddress": j}

            async with self.ahsession.request("GET", url, headers=headers) as r:
                result = await r.json()
                
                if 'ClientAccessSettings' not in result:
                    self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                    return
                else:
                    finalvalue = result['ClientAccessSettings']

                outfile = os.path.join(self.output_dir, "EXO_MailboxCASSettings.json")
                with open(outfile, 'a', encoding="utf-8") as f:
                    if finalvalue:
                        finalvalue.update(y)
                        f.write(json.dumps(finalvalue))
                        f.write("\n")
        
        self.logger.info('Finished dumping Exchange Online Mailbox CAS Settings.')
        
        self.logger.info('Dumping Exchange Online Mailbox Permissions and Delegations...')

        for i, j in zip(listOfIds, listOfNames):
            if self.exo_us_government == 'false':
                url = 'https://admin.exchange.microsoft.com/beta/Mailbox(' + i + ')?$expand=FullAccessPermission,%20SendOnBehalfPermission,%20SendAsPermission'
            elif self.exo_us_government == 'true':
                url = 'https://admin.exchange.office365.us/beta/Mailbox(' + i + ')?$expand=FullAccessPermission,%20SendOnBehalfPermission,%20SendAsPermission'
            y = {"PrimarySmtpAddress": j}

            async with self.ahsession.request("GET", url, headers=headers) as r:
                result = await r.json()

                if not result:
                    self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                    return

                outfile = os.path.join(self.output_dir, "EXO_MailboxPermissions.json")
                with open(outfile, 'a', encoding="utf-8") as f:
                    if result:
                        result.update(y)
                        if '@odata.context' in result.keys():
                            del result['@odata.context']
                        f.write(json.dumps(result))
                        f.write("\n")
        
        self.logger.info('Finished dumping Exchange Online Mailbox Permissions and Delegations.')

        self.logger.info('Dumping Exchange Online Mailbox Forwarding...')

        for i, j in zip(listOfIds, listOfNames):
            if self.exo_us_government == 'false':
                url = 'https://admin.exchange.microsoft.com/beta/Mailbox(' + i + ')?$select=ForwardingAddress,DeliverToMailboxAndForward'
            elif self.exo_us_government == 'true':
                url = 'https://admin.exchange.office365.us/beta/Mailbox(' + i + ')?$select=ForwardingAddress,DeliverToMailboxAndForward'
            y = {"ObjectId": i, "PrimarySmtpAddress": j}

            async with self.ahsession.request("GET", url, headers=headers) as r:
                result = await r.json()

                if not result:
                    self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                    return

                outfile = os.path.join(self.output_dir, "EXO_MailboxForwarding.json")
                with open(outfile, 'a', encoding="utf-8") as f:
                    if result:
                        result.update(y)
                        if '@odata.context' in result.keys():
                            del result['@odata.context']
                        f.write(json.dumps(result))
                        f.write("\n")
        
        self.logger.info('Finished dumping Exchange Online Mailbox Forwarding.')

    async def dump_exo_addins(self) -> None:
        """Dumps Exchange Online Add-in data.

        :return: None
        :rtype: None
        """

        if 'msExchEcpCanary' not in self.auth:
            self.logger.error("Missing msExchEcpCanary auth cookie. Did you auth correctly? (Skipping dump_exo_addins)")
            return

        self.logger.info("Gathering Exchange Online Add-ins...")

        if self.exo_us_government == 'false':
            url = 'https://outlook.office365.com/ecp/DDI/DDIService.svc/GetList?schema=OrgClientExtension&msExchEcpCanary=' + self.auth['msExchEcpCanary']
        elif self.exo_us_government == 'true':
            url = 'https://outlook.office365.us/ecp/DDI/DDIService.svc/GetList?schema=OrgClientExtension&msExchEcpCanary=' + self.auth['msExchEcpCanary']

        headers = {
            'Cookie': 'msExchEcpCanary=' + self.auth['msExchEcpCanary'] + '; OpenIdConnect.token.v1=' + self.auth['OpenIdConnect.token.v1'] + ';',
            'Content-Type': 'application/json;charset=UTF-8'
        }

        payload = {"filter":{"Parameters":{"__type":"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel"}},"sort":{"Direction":0,"PropertyName":"DisplayName"}}

        payload = json.dumps(payload)

        self.logger.info('Dumping Exchange Online Add-ins...')
        async with self.ahsession.request("POST", url, headers=headers, data=payload) as r:
            result = await r.json()
            finalvalue = list(findkeys(result, 'Output'))

            outfile = os.path.join(self.output_dir, "EXO_AddIns.json")
            with open(outfile, 'w', encoding="utf-8") as f:
                    f.write(json.dumps(finalvalue))
                    f.write("\n")
            self.logger.info('Finished dumping Exchange Online Add-ins.')
    
    async def dump_exo_inboxrules(self) -> None:

        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error("Missing token_type and access_token from auth. Did you auth correctly? (Skipping dump_exo_inboxrules)")
            return

        if check_app_auth_token(self.app_auth, self.logger):
            return

        outfile = os.path.join(self.output_dir, 'users.json')
        if os.path.exists(outfile):
            data = [json.loads(line) for line in open (outfile, 'r')]
        else:
            await helper_single_object('users', self.call_object, self.failurefile)
            data = [json.loads(line) for line in open (outfile, 'r')]

        statefile = f'{self.output_dir}{os.path.sep}.inbox_state'
        if os.path.isfile(statefile):
            self.logger.debug(f'Save state file exists at {statefile}')
            self.logger.info(f'Inbox rules save state file found. Continuing from last checkpoint.')
            
            with open(statefile, "r") as f:
                save_state_type = f.readline().strip()
                if save_state_type:
                    save_state_start = save_state_type
                    self.logger.info("Save state: {}".format(str(save_state_start)))
            
            i = save_state_start
            self.logger.info("Value of I: {}".format(str(i)))
        else:
            self.logger.debug('No save state file found.')
            i = 0

        listOfIds = list(findkeys(data, 'userPrincipalName'))
        self.logger.info('Dumping inbox rules...')

        for i in range(int(i), len(listOfIds)):
            retries = 50
            while retries > 0:
                try:
                    if "'" in listOfIds[i]:
                        listOfIds[i] = listOfIds[i].replace("'", "%27")
                        self.logger.debug('Converted userprincipal: {}'.format(str(listOfIds[i])))
                    if self.exo_us_government == 'false':
                        url = 'https://graph.microsoft.com/beta/users/' + listOfIds[i] + '/mailFolders/inbox/messageRules'
                    elif self.exo_us_government == 'true':
                        url = 'https://graph.microsoft.us/beta/users/' + listOfIds[i] + '/mailFolders/inbox/messageRules'
                    header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
                    additionalInfo = {"userPrincipalName": listOfIds[i]}
                    async with self.ahsession.request("GET", url, headers=header, raise_for_status=True) as r:
                        result = await r.json()
                        finalvalue = result['value']
                        self.logger.debug('Full result: {}'.format(str(result)))
                        outfile = os.path.join(self.output_dir, "EXO_InboxRules_Graph.json")
                        with open(outfile, 'a', encoding="utf-8") as f:
                            if finalvalue:
                                finalvalue.append(additionalInfo)
                                f.write(json.dumps(finalvalue))
                                f.write("\n")
                        with open(statefile, 'w') as f:
                            f.write(f'{i}')
                    i += 1
                    break
                except Exception as e:
                    if e.status == 429:
                        self.logger.error('Error on json retrieval: {}'.format(str(e)))
                        self.logger.info('Sleeping for 60 seconds because of API throttle limit was exceeded.')
                        await asyncio.sleep(60)
                        retries -= 1
                    elif e.status == 404:
                        self.logger.info('User does not have inbox rules: {}'.format(str(listOfIds[i])))
                        retries = 0
                    elif e.status == 503:
                        self.logger.error('Error on json retrieval: {}'.format(str(e)))
                        self.logger.info('Error on user pull {}'.format(str(listOfIds[i])))
                        with open(self.inboxfailfile, 'a+', encoding='utf-8') as f:
                            f.write(str(listOfIds[i]) + "_" + str(i) + '\n')
                        retries = 0
                    elif e.status == 401:
                        self.logger.error('Error on json retrieval: {}'.format(str(e)))
                        self.logger.info('Unauthorized message received. Exiting calls.')
                        sys.exit("Check auth to make sure it's not expired.")
        self.logger.info('Finished dumping inbox rules.')

    def get_url(self):
        if self.exo_us_government == "false":
            return "https://graph.microsoft.com/beta/"
        elif self.exo_us_government == "true":
            return "https://graph.microsoft.us/beta/"

    async def _ual_timeframe(self, start_date: str, end_date: str, start_time='', end_time='') -> None:
        """Given a start and end date, dumps the unified audit log to a file.

        :param start_date: Start date of UAL retrieval in strftime format %Y-%m-%d
        :type start_date: str
        :param end_date: End date of UAL retrieval in strftime format %Y-%m-%d
        :type end_date: str
        :return: None
        :rtype: None
        """
        self.logger.info("Dumping UAL from date %sT%s to %sT%s" % (start_date, start_time, end_date, end_time))
        postfix = f'{start_date}_{end_date}'
        q_s = start_time.replace(':', '_').replace('.', '_')
        q_e = end_time.replace(':', '_').replace('.', '_')
        postfix += f'_{q_s}_{q_e}' if start_time else ''

        ual_filename = 'ual_%s.csv' % (postfix)
        json_filename = 'ual_%s.json' % (postfix)
        end_ret = ''
        try:
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://security.microsoft.com',
                'Connection': 'keep-alive',
                'Cookie': 's.SessID='+ self.auth['sessionId'] + '; sccauth=' + self.auth['sccauth'] + ';',
                'Upgrade-Insecure-Requests': '1',
                'TE': 'Trailers',
            }
            if self.exo_us_government == 'true':
                headers["Origin"] = 'https://security.microsoft.us'
                url = "https://security.microsoft.us/api/UnifiedAuditLog/Export"
            elif self.exo_us_government == 'false':
                url = "https://security.microsoft.com/api/UnifiedAuditLog/Export"
            
            if start_time:
                end_ret = end_date + 'T' + urllib.parse.quote(end_time)
                payload='XSRF-TOKEN=' + self.auth['xsrf'] + '&startDate=%22'+ start_date + 'T' + urllib.parse.quote(start_time) + '%22&endDate=%22' + end_ret + '%22'
            else:
                end_ret = end_date + 'T04%3A00%3A00.000Z'
                payload='XSRF-TOKEN=' + self.auth['xsrf'] + '&startDate=%22'+ start_date + 'T04%3A00%3A00.000Z%22&endDate=%22' + end_ret + '%22'

            seconds = time.perf_counter()

            done = False
            while not done:
                try:
                    async with self.get_session().request("POST", url, headers=headers, data=payload, timeout=600) as response:
                        if response.status == 440:
                            self.logger.info('Received response code 440. Your auth has expired! Please re-auth and rerun.')
                            sys.exit(1)
                        data = await response.text()
                        data_lines = data.splitlines()
                        n_lines = len(data_lines)
                        if n_lines == 1 or n_lines == 0:
                            self.logger.info('UAL pull came back with no data. Not writing to file.')

                        else:
                            self.logger.info("Writing {} bytes to {}".format(len(data), ual_filename))
                            if n_lines == 50001:
                                end_ret = data_lines[1].split(',')[0]
                                self.logger.info(f"There are exactly 50001 lines in returned data. Last date retrieved is: {end_ret}")
                        
                            csvf = StringIO(data)
                            csvReader = csv.DictReader(csvf)
                            outfile = os.path.join(self.output_dir, json_filename)
                            with open(outfile, 'w', encoding='utf-8') as jsonf:
                                for rows in csvReader:
                                    if rows['AuditData']:
                                        Audit_data = json.loads(rows['AuditData'])
                                        jsonf.write('{}\n'.format(json.dumps(Audit_data)))
                        self.logger.debug('UAL dump (%s%s to %s%s) response code: %d' % (start_date, start_time, end_date, end_time, response.status))
                        done = True
                except asyncio.TimeoutError:
                    self.logger.debug('UAL pull timed out. Retrying again.')
                    done = False
        except ClientPayloadError as e:
            self.logger.error("Dumping UAL encountered an error with time bounds: {}".format(str(e)))
            self.logger.error("Please change the date of the time bounds or save state to a date within the last 364 days.")
            exit(1)
        except KeyError as e:
            self.logger.error("Dumping UAL encountered auth key error: {}".format(str(e)))
            self.logger.error("Do you have the proper auth tokens?")
        except requests.exceptions.ChunkedEncodingError as e:
            self.logger.error("Dumping UAL encountered error: {}".format(str(e)))
            self.logger.error("This is most likely due to a permissions error with your account accessing UAL.")
        return end_ret

    async def dump_ual(self, hourly=False) -> None:
        """Dumps UAL for last year in chunks sequentially due to DOS protection on endpoint.

        :return: None
        :rtype: None
        """
        statefile = f'{self.output_dir}{os.path.sep}.ual_state'
        boundsfile = f'{self.output_dir}{os.path.sep}.ual_bounds'
        if os.path.isfile(boundsfile):
            self.logger.debug(f'UAL Bounds file exists at {boundsfile}')
            last_ind = 0
            if os.path.isfile(statefile):
                self.logger.debug(f'UAL save state file exists at {statefile}')
                last_state = open(statefile, 'r').read()
                try:
                    last_ind = int(last_state)
                except Exception as e:
                    self.logger.debug(f'Last state for statefile not a valid bound index, starting at 0: {last_state}')
                    last_ind = 0
            buf = open(boundsfile, 'r').readlines()
            all_times = [x.strip().split(',')[:2] for x in buf]

            for i in range(last_ind, len(all_times)):
                t = all_times[i]
                s = t[0].split(' ')
                e = t[1].split(' ')
                with open(statefile, 'w') as f:
                    f.write(f'{i}')
                self.logger.debug(f'Bounded UAL timeframes: {s} -> {e}')
                await self._ual_timeframe(s[0], e[0], f'{s[1]}.000Z', f'{e[1]}.000Z')

        elif os.path.isfile(statefile):
            self.logger.debug(f'UAL save state file exists at {statefile}')
            self.logger.info(f'UAL Dump save state file found. Continuing from last checkpoint.')
            last_state = open(statefile, 'r').read()
            if 'T' in last_state:
                self.logger.debug(f'Last state was an hourly pull: {last_state}')
                start = datetime.strptime(last_state, '%Y-%m-%dT%H:%M:%S.000Z')
                now = datetime.now()
                all_hours = [(start.strftime('%Y-%m-%d'), start.strftime('%H:%M:%S.000Z'), start.strftime('%H:59:59.999Z'))]
                self.logger.debug(f"Continuing UAL pull from {last_state}")
                while start < now:
                    start += timedelta(hours=1)
                    all_hours.append((start.strftime('%Y-%m-%d'), start.strftime('%H:%M:%S.000Z'), start.strftime('%H:59:59.999Z')))

                for h in all_hours:
                    with open(statefile, 'w') as f:
                        f.write(f'{h[0]}T{h[1]}')
                    await self._ual_timeframe(h[0], h[0], h[1], h[2])
            else:
                self.logger.debug(f'Last state was a daily pull: {last_state}')
                now = datetime.now()
                with open(statefile, "r") as f:
                    start_date = f.readline().strip()                                
                dates = build_date_tuples(start_date=start_date, end_date=now)
                for i in range(0, len(dates)-1):
                    with open(statefile, 'w') as f:
                        f.write(dates[i])
                    await self._ual_timeframe(dates[i], dates[i+1]) 

        elif self.date_range:
            self.logger.debug(f'UAL Dump using specified date range: {self.date_start} to {self.date_end}')
           
            dates = build_date_range(self.date_start, self.date_end)
            for i in range(0, len(dates)-1):
                with open(statefile, 'w') as f:
                    f.write(dates[i])
                await self._ual_timeframe(dates[i], dates[i+1]) 
            
            return
        else:
            self.logger.debug(f'Save state file does not exist at {statefile}.')

            if hourly:
                dates = build_date_tuples(chunk_size=1)
            else:
                dates = build_date_tuples()


            if not hourly:
                for i in range(0, len(dates)-1):
                    with open(statefile, 'w') as f:
                        f.write(dates[i])
                    await self._ual_timeframe(dates[i], dates[i+1]) 
            else:
                for d in dates:
                    for j in range(24):
                        h = str(j).zfill(2)
                        start_time = h + ':00:00.000Z'
                        end_time = h + ':59:59.999Z'
                        with open(statefile, 'w') as f:
                            f.write(f'{d}T{start_time}')
                        await self._ual_timeframe(d, d, start_time, end_time)

    async def dump_powershell_calls(self) -> None:

        self.logger.info('Starting PowerShell script...')
        main_directory = os.getcwd()
        file_directory = os.path.join(os.path.dirname(self.output_dir), '..', 'scripts')
        file_path = os.path.join(file_directory, "EXO.ps1")
        config_directory = os.path.join(os.path.dirname(self.output_dir), '..', '.conf')
        report_directory = main_directory + os.path.sep + self.reports_dir

        if sys.platform == 'win32':
            subprocess.Popen(["powershell.exe", "-ExecutionPolicy", "Unrestricted", "-File", file_path, "-ExportDir", self.output_dir, "-ReportDir", report_directory], creationflags=subprocess.CREATE_NEW_CONSOLE)
