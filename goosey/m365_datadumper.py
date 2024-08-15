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
import random

from aiohttp.client_exceptions import *
from datetime import datetime, timedelta
from goosey.auth import check_app_auth_token
from goosey.datadumper import DataDumper
from goosey.utils import *
from io import StringIO

class M365DataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, auth, app_auth, session, config, debug, o365_app_auth):
        super().__init__(f'{output_dir}{os.path.sep}m365', reports_dir, auth, app_auth, session, debug)
        self.logger = setup_logger(__name__, debug)
        self.exo_us_government = config_get(config, 'config', 'exo_us_government', self.logger).lower()
        self.inboxfailfile = os.path.join(reports_dir, '_user_inbox_503.json')
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        self.ual_bounds_state = []
        self.o365_app_auth = o365_app_auth
        self.a_THRESHOLD = int(config_get(config, 'variables', 'ual_threshold'))
        self.max_ual_tasks = max(1,int(config_get(config, 'variables', 'max_ual_tasks')))
        self.ual_extra_start = config_get(config, 'variables', 'ual_extra_start')
        self.ual_extra_end = config_get(config, 'variables', 'ual_extra_end')
        self.tenantId = config_get(config, 'config', 'tenant')
        self.ual_tasks = []
        self.ual_results_cache = [] # used to store results in case of cross query interference
        filters = config_get(config, 'filters', 'date_start', logger=self.logger)
        if filters != '' and  filters is not None:
            self.date_range=True
            self.date_start = config_get(config, 'filters', 'date_start')
            if config_get(config, 'filters', 'date_end') != '':
                self.date_end = config_get(config, 'filters', 'date_end')
            else:
                self.date_end = datetime.now().strftime("%Y-%m-%d")
        else:
            self.date_range=False

        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]

    async def run_exo_cmdlet(self, cmdlet, Parameters={}, timeout=120):
        """
        Run an exo powershell cmdlet and return the results
        """
        access_token = self.o365_app_auth["access_token"]
        headers = {
               'Prefer': 'odata.maxpagesize=1000',
               'X-AnchorMailbox': "SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}",
               'Accept': 'application/json',
               'Content-Type': 'application/json',
               'Authorization': f"Bearer {access_token}",
               'X-ResponseFormat': 'json',
               'X-CmdletName': cmdlet,
               'X-ClientApplication': 'ExoManagementModule'
        }

        raw_payload = {
            'CmdletInput': {
                'CmdletName': cmdlet,
                'Parameters': Parameters
            }
        }
        data=json.dumps(raw_payload)
        result = None
        err = None
        # https://learn.microsoft.com/en-us/powershell/module/exchange
        url = "https://outlook.office.com/adminapi/beta/{tenant_id}/InvokeCommand"
        url = url.format(tenant_id=self.tenantId)
        self.logger.debug(raw_payload)

        try:
            async with self.ahsession.request("POST", url=url, headers=headers, data=data, timeout=timeout) as r:
                result = await r.text()
                result = json.loads(result)
                result["status"] = r.status
                if r.status == 401:
                    self.logger.error("Detected 401 unauthorized, exiting.")
                    sys.exit(1)
                elif r.status == 429:
                    error = result['error']
                    message = error['message']
                    seconds = message.split(' ')[-2]
                    self.logger.debug("Sleeping for %s seconds" % (seconds))
                    await asyncio.sleep(int(seconds))
                    err = message
                else:
                    if "error" in result:
                        err = result["error"]["message"]
        except TimeoutError:
            err = "TimeoutError"
        except asyncio.exceptions.TimeoutError:
            err = "TimeoutError"
        except Exception as e:
            self.logger.debug("Exception info", exc_info=1)
            err = str(e)

        if err:
            self.logger.debug(err)

        return result, err

    def load_exo_cmdlet(self, load_file):
        """
        Load previous output from an exo cmdlet.
        Return an array of values
        """
        infile = os.path.join(self.output_dir, load_file)
        if not os.path.isfile(infile):
            self.logger.debug(f"File {infile} does not exist")
            return []
        values = []
        infile_handle = open(infile, "r")
        for line in infile_handle:
            values.append(json.loads(line))
        return values


    async def save_exo_cmdlet(self, cmdlet, save_file, Parameters={}, remove_fields=[], append=False, overwrite_existing=False):
        """
        Run an exo powershell cmdlet and save the results to a file
        """
        outfile = os.path.join(self.output_dir, save_file)
        # Check if the output file exists and if we can overwrite it
        if os.path.isfile(outfile) and not append and not overwrite_existing:
            self.logger.debug(f"File {outfile} already exists. Not performing call to cmdlet")
            return self.load_exo_cmdlet(save_file)

        response, err = await self.run_exo_cmdlet(cmdlet, Parameters)
        if err:
            raise Exception(err)
        response_dict = response
        new_values = []
        if "value" not in response_dict:
            return
        for value in response_dict["value"]:
            for field in remove_fields:
                del value[field]
            new_values.append(value)
        open_flags = "w"
        if append:
            open_flags = "a"
        output_string = ""
        for value in new_values:
            output_string += json.dumps(value) + "\n"
        if output_string != "":
            with open(outfile, open_flags, encoding="utf-8") as f:
                f.write(output_string)

        return new_values

    async def dump_exo_groups(self):
        """
        Dumps Exchange Online Role Group and Role Group Members information.
        """
        roles = await self.save_exo_cmdlet("Get-RoleGroup", "EXO_RoleGroups_PowerShell.json", Parameters={"ResultSize": "Unlimited"})

        append=False
        # Load save state and change the roles array to be only role groups that haven't been searched
        member_save_state_file = os.path.join(self.output_dir, ".EXO_RoleGroupMembers_savestate")
        last_role = load_state(member_save_state_file, is_datetime=False)
        if last_role:
            role_index = next((i for i, item in enumerate(roles) if item["Id"] == last_role), None)
            roles = roles[role_index+1:]
            append=True
        for role in roles:
            await self.save_exo_cmdlet("Get-RoleGroupMember", "EXO_RoleGroupsMembers_PowerShell.json", Parameters={"Identity": role["Id"]}, append=append)
            save_state(member_save_state_file, role["Id"], is_datetime=False)
            append=True

    async def dump_exo_mailbox(self) -> None:
        """
        Dumps Exchange Online Mailbox Information
        """
        self.logger.debug("Starting dumping EXO Mailboxes")
        new_values = await self.save_exo_cmdlet("Get-Mailbox", "EXO_Mailboxes_PowerShell.json", Parameters={"IncludeInactiveMailbox": "True", "ResultSize": "Unlimited"})
        mailboxes = []
        for value in new_values:
            mailboxes.append(value["WindowsEmailAddress"])
        self.logger.debug("Finished dumping EXO Mailboxes")

        self.logger.debug("Starting dumping EXO Mailbox Client Access Settings")
        await self.save_exo_cmdlet("Get-CASMailbox", "EXO_MailboxCAS_Settings_PowerShell.json", Parameters={"ResultSize": "Unlimited"})
        await self.save_exo_cmdlet("Get-CASMailboxPlan", "EXO_Tenant_CAS_Plan_PowerShell.json", Parameters={"ResultSize": "Unlimited"})
        self.logger.debug("Finished dumping EXO Mailboxes Client Access Settings")

        append=False
        # Load save state
        mailbox_save_state_file = os.path.join(self.output_dir, ".EXO_Mailbox_savestate")
        last_mailbox = load_state(mailbox_save_state_file, is_datetime=False)
        if last_mailbox:
            mailbox_index = mailboxes.index(last_mailbox)
            mailboxes = mailboxes[mailbox_index+1:]
            append=True
        # Go through each mailbox and grap permissions, folder permissions, and inbox rules
        self.logger.debug("Starting dumping EXO Mailbox Permissions")
        for mailbox in mailboxes:
            self.logger.debug(f"Dumping Mailbox Info for {mailbox}")
            await self.save_exo_cmdlet("Get-MailboxPermission", "EXO_MailboxPermissions_PowerShell.json", Parameters={"Identity": mailbox}, append=append)
            await self.save_exo_cmdlet("Get-MailboxFolderPermission", "EXO_TopLevelFolderPermissions_PowerShell.json", Parameters={"Identity": mailbox}, append=append)
            await self.save_exo_cmdlet("Get-InboxRule", "EXO_InboxRules_PowerShell.json", Parameters={"Mailbox": mailbox, "IncludeHidden": "True"}, append=append)
            save_state(mailbox_save_state_file, mailbox, is_datetime=False)
            append=True

        self.logger.debug("Finished dumping EXO Mailbox Permissions")

    async def dump_exo_config_info(self) -> None:
        """
        Get EXO config information
        """
        asyncio.gather(
            self.save_exo_cmdlet("Get-MailboxAuditBypassAssociation", "EXO_MailboxAuditStatus_PowerShell.json", Parameters={"ResultSize": "Unlimited"}),
            self.save_exo_cmdlet("Get-AdminAuditLogConfig", "EXO_AdminAuditLogConfig_PowerShell.json"),
            # Below cmdlet is in the previous powershell script but gives an error here
            #self.save_exo_cmdlet("Get-UnifiedAuditLogRetentionPolicy", "EXO_UALRetentionPolicy_PowerShell.json"),
            self.save_exo_cmdlet("Get-OrganizationConfig", "EXO_OrganizationConfig_PowerShell.json"),
            self.save_exo_cmdlet("Get-PerimeterConfig", "EXO_PerimeterConfig_PowerShell.json"),
            self.save_exo_cmdlet("Get-TransportRule", "EXO_TransportRules_PowerShell.json"),
            self.save_exo_cmdlet("Get-TransportConfig", "EXO_TransportConfig_PowerShell.json")
        )

    async def dump_exo_mobile_devices(self) -> None:
        """
        Get information on m365 mobile devices
        """
        devices = await self.save_exo_cmdlet("Get-MobileDevice", "EXO_MobileDevices_PowerShell.json", Parameters={"ResultSize": "Unlimited"})
        await self.save_exo_cmdlet("Get-MobileDeviceMailboxPolicy", "EXO_MobileDeviceMailboxPolicy_PowerShell.json")

        append=False
        # Load save state and change the devices array to be only devices that haven't been searched
        mobile_save_state_file = os.path.join(self.output_dir, ".EXO_MobileDevicesStats_savestate")
        last_device = load_state(mobile_save_state_file, is_datetime=False)
        if last_device:
            device_index = next((i for i, item in enumerate(devices) if item["Guid"] == last_device), None)
            devices = devices[device_index+1:]
            append=True
        for device in devices:
            device = device["Guid"]
            await self.save_exo_cmdlet("Get-MobileDeviceStatistics", "EXO_MobileDeviceStats_PowerShell.json", Parameters={"Identity": device, "ErrorAction": "SilentlyContinue"}, append=append)
            save_state(mobile_save_state_file, device, is_datetime=False)
            append=True

    async def dump_ediscovery_info(self) -> None:
        """
        Get Exchange discovery information
        """
        roles = await self.save_exo_cmdlet("Get-ManagementRoleEntry", "EXO_EDiscovery_Roles_PowerShell.json", Parameters={"Identity": "*\\New-MailboxSearch"})
        roles += await self.save_exo_cmdlet("Get-ManagementRoleEntry", "EXO_EDiscovery_Roles_PowerShell.json", Parameters={"Identity": "*\\Search-Mailbox"}, append=True)
        new_roles = []
        for role in roles:
            new_role = role["Role"]
            if new_role not in new_roles:
                new_roles.append(role["Role"])
        roles=new_roles
        append=False
        # Load save state and change the roles array to be only role groups that haven't been searched
        role_save_state_file = os.path.join(self.output_dir, ".EXO_EDiscovery_savestate")
        last_role = load_state(role_save_state_file, is_datetime=False)
        if last_role:
            self.logger.debug(f"save state role detected. Starting from {last_role}")
            role_index = roles.index(last_role)
            roles = roles[role_index+1:]
            append=True
        # Go through each role and pull cmdlets and assignments associated witht the roles
        for role in roles:
            await self.save_exo_cmdlet("Get-ManagementRoleEntry", "EXO_Ediscovery_RoleCmdlets_PowerShell.json", Parameters={"Identity": f"{role}\\*"}, append=append)
            await self.save_exo_cmdlet("Get-ManagementRoleAssignment", "EXO_Ediscovery_RoleAssignments_PowerShell.json", Parameters={"Role": role, "Delegating": "False"}, append=append)
            save_state(role_save_state_file, role, is_datetime=False)
            append=True



    async def dump_exo_addins(self, timeout=120) -> None:
        """
        Get all of the applications installed for the organization
        """
        await self.save_exo_cmdlet("Get-App", "EXO_AddIns.json", Parameters={"OrganizationApp": "True", "PrivateCatalog": "True"}, remove_fields=["ManifestXml"])

    async def dump_exo_inboxrules(self) -> None:
        """
        Get all the messageRule objects defined for all users' inboxes
        """
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

    def _insert_ual_record(self, record, boundsfile=None):
        """
        Description:
            Add a record to the sorted ual_bounds_state.

        Arguments:
            record: Tuple of (start, end, count, done_status)
            boundsfile: filepath to where to save the bounds data.

        Returns:
            None
        """
        # Unless the time period that logs are being pulled from changes
        # the bounds within a time range will become further segmented and pulling from
        # that time period will go faster. Saving the state of the bounds is difficult though
        # because we have to be careful to account for changing start and end times.

        # This could be an optional situation of the bounds with only one time frame being searched
        # where $ is the begining and ! is the end and - in the middle means it's done_status is true.
        # Notice that the bounds double as time goes on.
        # This is because the shrinking of bounds is done in a binary fashion
        # | $-!$ !$    !$             ! |
        # Here it is after the finished time bounds are removed. Which is done for efficiency
        # |    $ !$    !$             ! |

        # Here is an example with multiple time frames
        # | $  !  $ !$ !$    !

        # Perform insert
        #self.logger.debug(f"Inserting Record {record}")

        if len(self.ual_bounds_state) == 0:
            self.ual_bounds_state.append(record)
            if boundsfile!= None:
                save_state(boundsfile, self.ual_bounds_state, is_datetime=False, time_bounds=True)
            return

        record_inserted = False
        for idx, cur_record in enumerate(self.ual_bounds_state):
            # Situations for an insert here are
            # 1. where a record already exists with that start time and we just shrink the bounds
            # 2. Or it's a completely separate time range
            if record["start"] == cur_record["start"] and record["end"] <= cur_record["end"]:
                #self.logger.debug(f"Current Record {cur_record}")
                cur_record["start"] = record["end"]
                # if the count is less than 0 then it is not accurate
                # if the new record is within a bound then adjust the larger bound.
                if cur_record["count"] >= 0 and record["count"] > 0:
                    cur_record["count"] = max(0,cur_record["count"] - record["count"])

                new_records = [record.copy(), cur_record.copy()]
                if cur_record["count"] == 0 or cur_record["start"] == cur_record["end"]:
                    new_records = [record.copy()]
                    #self.logger.debug("Record overwritten")
                #self.logger.debug(f"New Records {new_records}")
                self.ual_bounds_state = self.ual_bounds_state[:idx] + new_records + self.ual_bounds_state[idx+1:]
                #self.logger.debug(f"Record inserted at index {idx}")
                record_inserted = True
                break
            # Record before existing bounds.
            elif record["start"] < cur_record["start"] and record["end"] <= cur_record["start"]:
                new_records = [record.copy(), cur_record.copy()]
                self.ual_bounds_state = self.ual_bounds_state[:idx] + new_records + self.ual_bounds_state[idx+1:]
                record_inserted = True
                break

        if not record_inserted:
            # Loop in reverse to insert a record at the end of bound ranges
            reversed_bounds = self.ual_bounds_state[::-1]
            for idx, cur_record in enumerate(self.ual_bounds_state[::-1]):
                # Record after existing bounds.
                if record["end"] > cur_record["end"] and record["start"] >= cur_record["end"]:
                    new_records = [record.copy(), cur_record.copy()]
                    reversed_bounds = reversed_bounds[:idx] + new_records + reversed_bounds[idx+1:]
                    self.ual_bounds_state = reversed_bounds[::-1]
                    record_inserted = True
                    break

        # Remove bounds with a done_status == True
        # They no longer matter and their status as being done is tracked in the state file
        self.ual_bounds_state = [r for r in self.ual_bounds_state if not r.get('done_status')]

        self.ual_bounds_state = sorted(self.ual_bounds_state, key=lambda x: x['start'])

        overlap_detected = False
        for idx in range(len(self.ual_bounds_state)-1):
            bound1 = self.ual_bounds_state[idx]
            bound2 = self.ual_bounds_state[idx+1]
            if bound1["end"] > bound2["start"]:
                self.logger.error(f"Overlap detected in bounds state. Terminating, {bound1}, {bound2}")
                sys.exit(1)

        if boundsfile != None:
            save_state(boundsfile, self.ual_bounds_state, is_datetime=False, time_bounds=True)

    def find_bounds_end_size(self, start, end):
        """
        Description:
            find the bounds within a timeframe and return a good end time given the bounds. Also estimates the total number of logs

        Arguments:
            start: starting timestamp
            end: ending timestamp

        Returns:
            A good end time to search
        """
        # Use these to estimate how many logs are within this timeframe
        bound_logs = 0
        total_estimated_logs = 0
        total_time_delta = end - start
        record_time_delta = timedelta(0)

        matching_bounds = []
        for record in self.ual_bounds_state:
            if start <= record["start"] and end >= record["end"]:
                matching_bounds.append(record.copy())
                bound_logs += record["count"]
                record_time_delta += (record["end"] - record["start"])

        if record_time_delta != timedelta(0):
            total_estimated_logs = int(total_time_delta / record_time_delta * bound_logs)

        if len(matching_bounds) == 0:
            matching_bounds = [{"start": start, "end": end}]

        if start < matching_bounds[0]["start"]:
            return matching_bounds[0]["start"], total_estimated_logs



        return matching_bounds[0]["end"], total_estimated_logs

    def get_start_end_results(self, results):
        start = dateutil.parser.parse(json.loads(results[0]["AuditData"])["CreationTime"]).replace(tzinfo=None)
        end = start
        for idx, entry in enumerate(results):
            time = dateutil.parser.parse(json.loads(entry["AuditData"])["CreationTime"]).replace(tzinfo=None)
            start = min(time, start)
            end = max(time, end)

        return start, end

    async def _new_ual_timeframe(self, start, end, retries=5, statefile=None, boundsfile=None, session_results=[], sessionId=None, isolated=False):
        """
        Description:
            Query the ual API to get information about the number of logs

        Arguments:
            start: starting timestamp
            end: ending timestamp
            retries=MAX_RETRIES: number of times to retry
            statefile=None: filepath of statefile
            isolated=False: Boolean for if the timeframe this function/task is dealing with has been isolated to a known good time bound.

        Returns:
        """

        response_count = 0
        session_sizes = {}
        sessionCount = 0
        finalEnd = end
        tries = 0
        total_duplicates = 0
        continuing = False
        # continue the session if this is a created a task
        if isolated and sessionId and session_results:
            continuing = True

        #self.logger.debug(f"start/end before bounds {start}/{end}")
        end, totalResultCount = self.find_bounds_end_size(start, end)
        #self.logger.debug(f"start/end after bounds {start}/{end}")

        while start < finalEnd and tries < retries:
            # Can't have a time period with no time in between
            startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
            endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            if startDate == endDate:
                end += timedelta(seconds=1)
                endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            # continue the session if this is a created task
            if not continuing:
                session_results = []
                sessionId = str(random.randint(1337, 9999999))
            continuing = False
            sessionCount = -1
            session_set = set() # Unique results returned. Used to detect duplicates
            bound = f'[{startDate} - {endDate}]'
            #self.logger.debug(f'===> Trying to find a bounding for {bound}')
            # Inner loop for a session search. Denoted by the sessionId
            status_code = None
            session_timeout = 60
            data_saved = False
            new_task_created = False

            while True:
                startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
                endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
                resultSize = 100
                parameters = {
                     'SessionCommand': "ReturnLargeSet",
                     'ResultSize': str(resultSize),
                     'SessionId': sessionId,
                     'StartDate': startDate,
                     'EndDate': endDate
                }
                # more efficient to use lower ResultSize to find a session.
                # Afterwards use the maximum ResultSize and higher timeout
                if isolated:
                    resultSize = 5000
                    parameters["ResultSize"] = str(resultSize)
                    session_timeout = 300

                first_iteration = False
                response, err = await self.run_exo_cmdlet("Search-UnifiedAuditLog", parameters, timeout=session_timeout)

                if err != None and "TimeoutError" in err:
                    # Timeout usually indicates too many logs. Need to reduce bounds
                    self.logger.debug(f"Encountered Timeout Error {err}")
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)
                    break
                elif err != None:
                    # For other errors increase the tries and half the time
                    tries += 1
                    self.logger.debug(f"Encountered {err}. tries == {tries}/{retries}")
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)
                    break


                if response == None:
                    tries += 1
                    self.logger.debug(f"No Results and no errors. tries == {tries}/{retries}")
                    break
                status_code = response["status"]
                if status_code == 200:
                    # If there are no more results within a session then break
                    # This could indicate that there an error or just that all results have been received
                    response_dict = response
                    if len(response_dict['value']) == 0:
                        tries += 1
                        self.logger.debug(f"No results in response? tries == {tries}/{retries}")
                        break
                    if int(response_dict['value'][0]['ResultCount']) == 0:
                        tries += 1
                        self.logger.debug(f"Too many logs. Couldn't calculate total count. Halving. tries == {tries}/{retries}")
                        new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                        end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)
                        break
                    tries = 0
                    sessionCount = int(response_dict['value'][0]['ResultCount'])
                    totalResultCount = max(sessionCount, totalResultCount)

                    # The ual api will sometimes produce duplicate results.
                    session_oldset = set([json.loads(result["AuditData"])["Id"] for result in session_results])
                    session_newset = set([json.loads(result["AuditData"])["Id"] for result in response_dict['value']])
                    session_set = session_oldset.union(session_newset)
                    old_duplicates = abs(len(session_results) - len(session_oldset))
                    new_duplicates = abs(sessionCount - len(session_newset))
                    total_duplicates = abs(len(session_results) + sessionCount - len(session_set))
                    duplicate_difference = abs(new_duplicates - old_duplicates)
                    # Check if the session has restarted by seeing if the difference in
                    # duplicates is the same as the total amount of new logs or old logs. In this
                    # case we will discard the earlier results and continue with the session.
                    if total_duplicates - old_duplicates == sessionCount \
                       or total_duplicates - new_duplicates == len(session_results):
                        session_results = []
                        session_set = session_newset

                    if len(session_set) != len(session_results) + sessionCount:
                        self.logger.debug(f"Duplicates found. Found {len(session_set)} unique results. Expected {len(session_results)}.")


                    # Check if ual cache is needed. Results need to be within time bounds
                    # and the result size either needs to match the number of logs within that
                    # time range or be equal to the number of logs expected to be pulled
                    response_start, response_end = self.get_start_end_results(response_dict['value'])
                    response_len = len(response_dict['value'])
                    self.logger.debug(f"{response_len} records returned from response")
                    concat_len = len(session_results) + response_len
                    if (concat_len == sessionCount \
                       or (response_len == resultSize and concat_len <= sessionCount)) \
                       and (response_start >= start and response_end <= end):
                        # return results are correct
                        session_results += response_dict['value']
                        # Special case where the session is ignored with existing results are excluded
                        if (response_len == sessionCount):
                            session_results = response_dict['value']
                    else:
                        self.logger.debug("Results returned are wrong. Adding to cache and checking for existing entries in cache")
                        self.logger.debug(f"response start {response_start}, response end {response_end}")
                        self.ual_results_cache.append({"start": response_start,
                                               "end": response_end,
                                               "results": response_dict['value']})
                        entry_found = False
                        for idx, cache_entry in enumerate(self.ual_results_cache):
                            response_len = len(cache_entry["results"])
                            concat_len = len(session_results) + response_len
                            if (concat_len == sessionCount \
                               or (response_len == resultSize and concat_len <= sessionCount)) \
                               and cache_entry["start"] >= start and cache_entry["end"] <= end:
                                self.logger.debug("Cache entry found")
                                session_results += cache_entry['results']
                                self.ual_results_cache.pop(idx)
                                break
                        if not entry_found:
                            self.logger.debug("No Cache entry found. Attempting again")
                            break

                    self._insert_ual_record({"start": start,
                                       "end": end,
                                       "count": sessionCount,
                                       "done_status": False}, boundsfile=boundsfile)

                    # check if within log threshold and the time difference is greater than 2 seconds
                    if sessionCount > self.a_THRESHOLD and end - start >= timedelta(seconds=2):
                        self.logger.debug(f"{sessionCount} results found within bounds. Exceeds result limit {self.a_THRESHOLD}")
                        # half the difference between the start and end time
                        new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                        end = datetime.fromtimestamp(new_end_ts).replace(microsecond=0)

                        break


                    self.logger.debug(f"{len(session_results)}/{sessionCount} records found in session {sessionId}")
                    self.logger.debug(f"Total results {response_count+len(session_results)}/{totalResultCount}")
                    if len(session_results) >= sessionCount:
                        # break out of session loop if all logs collected
                        break
                    elif not isolated:
                        # This is where we will isolate this timeframe as a coroutine task just for this timeframe and then start another task to pull the rest
                        # Can't continue until some of the tasks are done
                        while len(self.ual_tasks) >= self.max_ual_tasks:
                            self.logger.debug("Waiting for ual dumpers to complete before starting more")
                            finished, ual_tasks_l = await asyncio.wait(self.ual_tasks, return_when=asyncio.FIRST_COMPLETED)
                            self.ual_tasks = list(ual_tasks_l)
                        self.ual_tasks.append(asyncio.create_task(self._new_ual_timeframe(start, end, statefile=statefile, isolated=True, session_results=session_results, sessionId=sessionId, boundsfile=boundsfile), name=f"ual_dumper_{start.isoformat()}_{end.isoformat()}"))
                        new_task_created = True
                        response_count += sessionCount
                        break
                elif status_code == 500:
                    self.logger.debug(f'\t[-] Services aren\'t available right now, sleeping for 30 seconds before retrying...')
                    self.logger.debug(str(response))
                    asyncio.sleep(30)
                    tries += 1
                    break
                else:
                    try:
                        self.logger.debug(json.dumps(response, indent=2, sort_keys=True))
                    except:
                        self.logger.debug(response)
                    tries += 1
                    break

            # Check to see if the search was successful and the total results captured matches the ResultCount
            # from the session
            if status_code == 200 and len(session_results) == sessionCount:
                # Remove the duplicates
                new_session_results = []
                response_count += len(session_results)
#                if len(session_set) != len(session_results):
#                    total_duplicates += len(session_results) - len(session_results)
#                    for result in session_results:
#                        result_id = json.loads(result["AuditData"])["Id"]
#                        if result_id in session_set:
#                            session_set.remove(result_id)
#                            new_session_results.append(result)
#                    session_results = new_session_results
                # save output for current session
                if len(session_results) > 0:
                    session_filename = f"ual_{startDate}_{endDate}.json".replace(":", "_")
                    session_filepath = os.path.join(self.output_dir, session_filename)
                    ual_session_output_str = ""
                    for ual_log in session_results:
                        audit_data_dict = json.loads(ual_log["AuditData"])
                        ual_session_output_str += json.dumps(audit_data_dict) + "\n"
                    open(session_filepath, "w").write(ual_session_output_str)

                # Save the latest date pulled to help with restart
                save_state(statefile, end, start=start, is_datetime=False, time_range=True)
                self._insert_ual_record({"start": start,
                                   "end": end,
                                   "count": sessionCount,
                                   "done_status": True}, boundsfile=boundsfile)
                data_saved = True

                self.total_ual_logs_saved += len(session_results)
                elapsed_time = time.perf_counter() - self.ual_seconds
                rate = int(self.total_ual_logs_saved / elapsed_time * 60 * 60)
                self.logger.info(f"Saved {len(session_results)} logs. Current rate is {rate} logs/hours")

            if new_task_created or data_saved:
                start = end
                end = finalEnd
                #self.logger.debug(f"start/end before bounds {start}/{end}")
                end,_ = self.find_bounds_end_size(start, end)
                #self.logger.debug(f"start/end after bounds {start}/{end}")

        if not isolated:
            await asyncio.gather(*self.ual_tasks)

    async def dump_ual(self):
        """Dumps UAL for last year using Search-UnifiedAuditLog api. Previous ual api is currently deprecated.

        https://learn.microsoft.com/en-us/powershell/module/exchange/search-unifiedauditlog?view=exchange-ps

        """
        statefile = f'{self.output_dir}{os.path.sep}.ual_state'
        boundsfile = f'{self.output_dir}{os.path.sep}.ual_bounds'

        # default end time
        end = get_end_time_yesterday()

        # Default start time
        start = end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'UAL Dump using specified date range: {self.date_start} to {self.date_end}')
            start = datetime.strptime(self.date_start,"%Y-%m-%d")
            end = datetime.strptime(self.date_end,"%Y-%m-%d")

        bounds_save_state = load_state(boundsfile, is_datetime=False, time_bounds=True)
        if bounds_save_state != None:
            self.ual_bounds_state = bounds_save_state

        finished_time_ranges = load_state(statefile, is_datetime=False, time_range=True)

        search_time_ranges = []

        # Check if the extra times were set
        if self.ual_extra_start:
            extra_start = datetime.strptime(self.ual_extra_start,"%Y-%m-%d")
            extra_end = get_end_time_yesterday()
            if self.ual_extra_end:
                extra_end = datetime.strptime(self.ual_extra_end,"%Y-%m-%d")

            # Check if overlap in the extra time frame
            if start <= extra_start and extra_start <= end or \
               extra_start <= start and start <= extra_end:
                # overlap at the beginning
                if extra_start <= start:
                    swap = extra_end
                    extra_end = start
                    end = max(swap, end)
                # overlap at the end
                if start <= extra_start:
                    swap = end
                    end = extra_start
                    extra_end = max(swap, extra_end)
            search_time_ranges += find_time_gaps(finished_time_ranges, extra_start, extra_end)

        search_time_ranges += find_time_gaps(finished_time_ranges, start, end)

        self.logger.debug(search_time_ranges)
        # set the start time according to the save state
        tasks = []
        for record in search_time_ranges:
            start, end = record["start"], record["end"]
            start = start.replace(microsecond=0)
            end = end.replace(microsecond=0)
            self.logger.info(f"Goosey collecting ual logs from : {start} -> {end}")
            tasks.append(asyncio.create_task(self._new_ual_timeframe(start, end, statefile=statefile, boundsfile=boundsfile),name=f"ual_bounding_{start.isoformat()}_{end.isoformat()}"))

        self.total_ual_logs_saved = 0
        self.ual_seconds = time.perf_counter()
        await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - self.ual_seconds
        self.logger.info("Goosey executed in {0:0.2f} seconds.".format(elapsed))

