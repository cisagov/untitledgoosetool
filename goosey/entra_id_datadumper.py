#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: entra_id_datadumper!
This module has all the telemetry pulls for Entra ID, formerly known as Azure AD.
"""

import asyncio
import json
import os

from datetime import datetime, timedelta
from goosey.auth import check_app_auth_token
from goosey.datadumper import DataDumper
from goosey.utils import *

class EntraIdDataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, app_auth, session, config, debug):
        super().__init__(f'{output_dir}{os.path.sep}entraid', reports_dir, app_auth, session, debug)
        self.logger = setup_logger(__name__, debug)
        self.THRESHOLD = 300
        self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
        self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
        endpoints = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        self.graph_url = endpoints["graph_api"]
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        filters = config_get(config, 'filters', 'date_start', logger=self.logger)
        if  filters!= '' and filters is not None:
            self.date_range=True
            self.date_start = config_get(config, 'filters', 'date_start')
            if config_get(config, 'filters', 'date_end') != '':
                self.date_end = config_get(config, 'filters', 'date_end')
            else:
                self.date_end = datetime.now().strftime("%Y-%m-%d")
        else:
            self.date_range=False

        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]

    async def dump_signins_adfs(self):
        """
        Dump interactive (adfs) sign in logs
        """
        return await self._dump_signins('adfs')

    async def dump_signins_rt(self):
        """
        Dump non-interactive (rt) sign in logs
        """
        return await self._dump_signins('rt')

    async def dump_signins_sp(self):
        """
        Dump service principal (sp) signin logs
        """
        return await self._dump_signins('sp')

    async def dump_signins_msi(self):
        """
        Dump managed identity (msi) sign in logs
        """
        return await self._dump_signins('msi')

    async def _dump_signins(self, source: str) -> None:
        """Dumps signin based off of signin source type.
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta

        :param source: Sign-in source type
        :type source: str
        :return: None
        :rtype: None
        """
        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error("Missing token_type and access_token from auth. Did you auth correctly? (Skipping _dump_signins)")
            return

        if check_app_auth_token(self.app_auth, self.logger):
            return

        signin_directory = os.path.join(self.output_dir, "signin_" + source)
        if not os.path.exists(signin_directory):
            os.mkdir(signin_directory)

        statefile = f'{self.output_dir}{os.path.sep}.{source}_signin_state'
        if os.path.isfile(statefile):
            self.logger.debug(f'Save state file exists at {statefile}')
            self.logger.info(f'{source} signin dump save state file found. Continuing from last checkpoint.')

            with open(statefile, "r") as f:
                save_state_type = f.readline().strip()
                if save_state_type == "time":
                    save_state_time = f.readline()
                    nexturl = None
                if save_state_type == "skiptoken":
                    nexturl = f.readline()
                    save_state_time = f.readline()

            start = '%sT00:00:00.000000Z' % (datetime.strptime(save_state_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1))
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())
            outfile = os.path.join(signin_directory, source + '_signin_log_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
            end_date = '%sT00:00:00.000000Z' % (datetime.now().strftime("%Y-%m-%d"))

        elif self.date_range:
            self.logger.debug(f'Specified date range found. Pulling signin logs for source {source} between {self.date_start} and {self.date_end}')
            start = self.date_start + 'T00:00:00.000000Z'
            end_date = self.date_end + 'T00:00:00.000000Z'

        else:
            self.logger.debug(f'Save state file does not exist at {statefile}.')
            start = '%sT00:00:00.000000Z' % ((datetime.now() - timedelta(days=29)).strftime("%Y-%m-%d"))
            self.logger.info('Getting signin logs for source %s...' % (source))
            end_date = '%sT00:00:00.000000Z' % (datetime.now().strftime("%Y-%m-%d"))

        while dateutil.parser.parse(start) < dateutil.parser.parse(end_date):
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())
            outfile = os.path.join(signin_directory, source + '_signin_log_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            filters = '(createdDateTime ge %s and createdDateTime lt %s)' % (start, end_time)
            params = {
                'api-version': 'beta',
                '$orderby': 'createdDateTime',
                '$filter': filters,
                'source': source
            }
            url = self.graph_url + "/beta/auditLogs/signIns"
            retries = 5
            for counter in range (retries):
                try:
                    header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
                    async with self.ahsession.get(url, headers=header, params=params, raise_for_status=True, timeout=600) as r:
                        result = await r.json()
                        nexturl = None
                        if '@odata.nextLink' in result:
                            nexturl = result['@odata.nextLink']
                        if 'value' in result:
                            with open(outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x))
                                    f.write("\n")
                                f.flush()
                                os.fsync(f)
                        if 'error' in result:
                            if result['error']['code'] == 'InvalidAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                sys.exit(1)

                        await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
                        with open(statefile, 'w') as f:
                            f.write("time\n")
                            f.write(end_time)
                    break

                except Exception as e:
                    try:
                        if e.status:
                            if e.status == 429:
                                self.logger.info('Sleeping for 60 seconds because of API throttle limit was exceeded.')
                                await asyncio.sleep(60)
                                retries -= 1
                                self.logger.debug('Retries remaining: {}'.format(str(retries)))
                            elif e.status == 401:
                                self.logger.error('401 unauthorized message received. Exiting calls. Please re-auth.')
                                sys.exit(1)
                    except AttributeError as a:
                        self.logger.error('Error on nextLink retrieval: {}'.format(str(e)))

            if os.path.isfile(outfile) and os.stat(outfile).st_size == 0:
                os.remove(outfile)
            start = '%sT00:00:00.000000Z' % ((datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1)).strftime("%Y-%m-%d"))

        self.logger.info('Finished dumping signin logs for source: {}'.format(source))

    async def dump_entraid_audit(self) -> None:
        """Dumps Entra ID Audit logs
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-beta

        :return: None
        :rtype: None
        """

        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error("Missing token_type and access_token from auth. Did you auth correctly? (Skipping dump_entraid_audit)")
            return

        if check_app_auth_token(self.app_auth, self.logger):
            return

        sub_dir = os.path.join(self.output_dir, 'entraid_audit_logs')
        check_output_dir(sub_dir, self.logger)

        url = self.graph_url + "/beta/auditLogs/directoryAudits"

        start_default = '%sT00:00:00.000000Z' % ((datetime.now() - timedelta(days=29)).strftime("%Y-%m-%d"))
        end_date_default = '%sT00:00:00.000000Z' % (datetime.now().strftime("%Y-%m-%d"))
        statefile = f'{self.output_dir}{os.path.sep}.audit_log_state'
        if os.path.isfile(statefile):
            self.logger.debug(f'Save state file exists at {statefile}')
            self.logger.info(f'Audit log dump save state file found. Continuing from last checkpoint.')

            with open(statefile, "r") as f:
                save_state_type = f.readline().strip()
                if save_state_type == "time":
                    save_state_time = f.readline()
                    nexturl = None
                if save_state_type == "skiptoken":
                    nexturl = f.readline()
                    save_state_time = f.readline()

            start = '%sT00:00:00.000000Z' % (datetime.strptime(save_state_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1))
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())
            outfile = os.path.join(sub_dir, 'entraidauditlog_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
            end_date = '%sT00:00:00.000000Z' % (datetime.now().strftime("%Y-%m-%d"))

        elif self.date_range:
            start = self.date_start + 'T00:00:00.000000Z'
            end_date = self.date_end + 'T00:00:00.000000Z'
            self.logger.debug(f'Specified date range found. Pulling audit logs between {self.date_start} and {self.date_end}')

        else:
            self.logger.debug(f'Save state file does not exist at {statefile}.')
            start = start_default
            end_date = end_date_default

        if start < start_default:
            self.logger.debug('Specified start time longer than audit log retention period. Using default of 30 days')
            start = start_default


        self.logger.info('Getting Entra ID audit logs...')
        while start < end_date:
            retries = 5
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())
            outfile = os.path.join(sub_dir, 'entraidauditlog_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            filters = '(activityDateTime ge %s and activityDateTime lt %s)' % (start, end_time)

            params = {
                'api-version': 'beta',
                '$orderby': 'activityDateTime',
                '$filter': filters,
            }

            self.logger.debug(f'Dumping Entra ID audit logs for time frame {start} to {end_time}')

            success = False
            for counter in range (retries):
                try:
                    header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
                    async with self.ahsession.get(url, headers=header, params=params, raise_for_status=True, timeout=600) as r:
                        result = await r.json()
                        nexturl = None
                        if '@odata.nextLink' in result:
                                nexturl = result['@odata.nextLink']
                                await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
                        if 'value' in result:
                            if result['value'] != []:
                                with open(outfile, 'w', encoding='utf-8') as f:
                                    f.write("\n".join([json.dumps(x) for x in result['value']]) + '\n')
                            start = '%sT00:00:00.000000Z' % ((datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1)).strftime("%Y-%m-%d"))
                            # We need to end the retry loop if we successfully dumped the audit log data
                            success = True
                        if 'error' in result:
                            if result['error']['code'] == 'InvalidAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                sys.exit(1)
                            else:
                                self.logger.debug('Error in result: {}'.format(result['error']))
                                self.logger.info('Sleeping for 60 seconds because of API throttle limit was exceeded.')
                                await asyncio.sleep(60)
                                retries -=1

                        with open(statefile, 'w') as f:
                            f.write("time\n")
                            f.write(end_time)

                        if success:
                            break


                except Exception as e:
                    try:
                        if e.status:
                            if e.status == 429:
                                self.logger.info('Sleeping for 60 seconds because of API throttle limit was exceeded.')
                                await asyncio.sleep(60)
                                retries -= 1
                            elif e.status == 401:
                                self.logger.info('401 unauthorized message received. Exiting calls. Please re-auth.')
                                sys.exit(1)
                    except AttributeError as a:
                        self.logger.error('Error on nextLink retrieval: {}'.format(str(e)))


        self.logger.info('Finished dumping Entra ID audit logs.')

    async def dump_entraid_provisioning(self) -> None:
        """Dumps Entra ID provisioning logs
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/provisioningobjectsummary?view=graph-rest-beta

        :return: None
        :rtype: None
        """

        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error("Missing token_type and access_token from auth. Did you auth correctly? (Skipping dump_entraid_provisioning)")
            return

        if check_app_auth_token(self.app_auth, self.logger):
            return

        url = self.graph_url + "/beta/auditLogs/provisioning"

        self.logger.info('Getting Entra ID provisioning logs...')
        outfile = os.path.join(self.output_dir, 'entraidprovisioninglogs.json')

        header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
        async with self.ahsession.get(url, headers=header, timeout=600) as r:
            result = await r.json()
            if 'value' not in result:
                self.logger.debug("Error with result: {}".format(str(result)))
                sys.exit(1)

            nexturl = None
            if '@odata.nextLink' in result:
                nexturl = result['@odata.nextLink']
            if 'value' in result:
                if result['value']:
                    with open(outfile, 'w', encoding='utf-8') as f:
                        f.write("\n".join([json.dumps(x) for x in result['value']]) + '\n')
                elif not result['value']:
                    self.logger.debug('%s has no information (size is 0). No output file.' % (outfile))
                    with open(self.failurefile, 'a+', encoding='utf-8') as f:
                        f.write('No output file: entraidprovisioninglogs - ' + str((datetime.now())) + '\n')
            if '@odata.nextLink' in result:
                nexturl = result['@odata.nextLink']
                await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)

        self.logger.info('Finished dumping Entra ID provisioning logs.')

    def get_url(self):
        return self.graph_url + "/beta/"

    async def helper_multiple_object(self, parent, child, output_dir, identifier='id', caller=""):
        url_parent = self.get_url()

        current_task = asyncio.current_task()
        if "Task" in current_task.get_name():
            task_name = f"{parent}_{child}"
            if caller:
                task_name = f"{caller}_{task_name}"
            current_task.set_name(task_name)

        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error(f"Missing token_type and access_token from auth. Did you auth correctly? (Skipping {parent})")
            return

        parent_list = []
        parent_entry_dict = {}
        header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
        parent_url = url_parent + parent

        async with self.ahsession.get(parent_url, headers=header) as r:
            result = await r.json()
            if 'value' not in result:
                if result['error']['code'] == 'InvalidAuthenticationToken':
                    self.logger.error("Error with authentication token: " + result['error']['message'])
                    self.logger.error("Please re-auth.")
                    asyncio.get_event_loop().stop()
                else:
                    self.logger.debug("Error with result: {}".format(str(result)))
                    return
            nexturl = None
            for entry in result['value']:
                parent_list.append(entry[identifier])
                parent_entry_dict[entry[identifier]] = entry
            if '@odata.nextLink' in result:
                nexturl = result['@odata.nextLink']
            retries = 5
            while nexturl:
                try:
                    skiptoken = nexturl.split('skiptoken=')[1]
                    async with self.ahsession.get(nexturl, headers=header, timeout=600) as r2:
                        result2 = await r2.json()
                        self.logger.debug('Received nextLink %s: %s' % (parent, skiptoken))
                        for entry in result2['value']:
                            parent_list.append(entry[identifier])
                            parent_entry_dict[entry[identifier]] = entry

                        if '@odata.nextLink' in result2:
                            if result2['@odata.nextLink'] == nexturl:
                                self.logger.warning("@odata.nextLink received is same as current. Setting nextLink to None.")
                                nexturl = None
                            else:
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

        self.logger.info('Dumping %s %s information...' % (parent, child))
        child_list = []
        for parent_id in parent_list:
            url2 = url_parent + parent + "/" + parent_id + '/%s' % (child)
            if child == 'appRoleAssignedResources':
                header['ConsistencyLevel'] = 'eventual'
            async with self.ahsession.get(url2, headers=header) as r:
                result = await r.json()
                if 'value' not in result:
                    if child == 'federationConfiguration':
                        continue
                    if result['error']['code'] == 'InvalidAuthenticationToken':
                        self.logger.error("Error with authentication token: " + result['error']['message'])
                        self.logger.error("Please re-auth.")
                        asyncio.get_event_loop().stop()
                    else:
                        self.logger.debug("Error with result: {}".format(str(result)))
                        return

                nexturl = None
                for entry in result['value']:
                    if "@odata.type" in entry.keys():
                        entry.pop("@odata.type")
                    temp = {parent : parent_entry_dict[parent_id]}
                    entry.update(temp)
                    child_list.append(entry)

                if '@odata.nextLink' in result:
                    nexturl = result['@odata.nextLink']
                retries = 5
                while nexturl:
                    try:
                        skiptoken = nexturl.split('skiptoken=')[1]
                        async with self.ahsession.get(nexturl, headers=header, timeout=600) as r2:
                            result2 = await r2.json()
                            self.logger.debug('Received nextLink %s: %s' % (parent, skiptoken))
                            for entry in result2['value']:
                                if "@odata.type" in entry.keys():
                                    entry.pop("@odata.type")
                                temp = {parent: parent_entry_dict[parent_id]}
                                entry.update(temp)
                                child_list.append(entry)

                            if '@odata.nextLink' in result2:
                                if result2['@odata.nextLink'] == nexturl:
                                    self.logger.warning("@odata.nextLink received is same as current. Setting nextLink to None.")
                                    nexturl = None
                                else:
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

        if '/' in child:
            temp = child.split('/')
            child = temp[-1]

        if '/' in parent:
            parent = parent.replace("/", "")

        outfile = os.path.join(output_dir, parent + "_" + child + '.json')
        if child_list:
            with open(outfile, 'w', encoding='utf-8') as f:
                for entry in child_list:
                    f.write(json.dumps(entry, sort_keys=True) + '\n')
        elif not child_list:
            with open(self.failurefile, 'a+', encoding='utf-8') as f:
                f.write('No output file: ' + parent + "_" + child + ' - ' + str((datetime.now())) + '\n')

        self.logger.info('Finished dumping %s %s information.' % (parent, child))

    async def dump_configs(self) -> None:
        """
        Dumps Entra ID configuration files
        """
        sub_dir = os.path.join(self.output_dir, 'entraid_configs')
        check_output_dir(sub_dir, self.logger)

        conf_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        caller_name = asyncio.current_task().get_name()

        await asyncio.gather(
            helper_single_object('applications', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/deleteditems/microsoft.graph.application', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identityGovernance/appConsent/appConsentRequests', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('conditionalAccess/authenticationContextClassReferences', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('conditionalAccess/namedLocations',conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('conditionalAccess/policies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('devices', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directoryRoles', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleDefinitions', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleAssignmentSchedules', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleEligibilitySchedules', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('roleManagement/directory/roleEligibilityScheduleInstances', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('groups', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/deleteditems/microsoft.graph.group', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/identityProviders', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/identityProviders/availableProviderTypes', conf_call_object, self.failurefile, caller=caller_name),
            # not working anymore. Requires APIConnectors.ReadWrite.All
            #helper_single_object('identity/apiConnectors', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directorySettingTemplates', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('domains', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('organization', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('subscribedSkus', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/continuousAccessEvaluationPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identity/events/onSignupStart', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/activityBasedTimeoutPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/defaultAppManagementPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/tokenLifetimePolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/tokenIssuancePolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/authenticationFlowsPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/authenticationMethodsPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/authorizationPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/claimsMappingPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/homeRealmDiscoveryPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/permissionGrantPolicies', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/identitySecurityDefaultsEnforcementPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/accessReviewPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/adminConsentRequestPolicy', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('servicePrincipals', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getRelyingPartyDetailedSummary(period='D30')", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getAzureAdApplicationSignInSummary(period='D30')", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('reports/applicationSignInDetailedSummary', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getCredentialUsageSummary(period='D30')", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/getCredentialUserRegistrationCount", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/credentialUserRegistrationDetails", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object("reports/userCredentialUsageDetails", conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('users', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('contacts', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('oauth2PermissionGrants', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('directory/deletedItems/microsoft.graph.user', conf_call_object, self.failurefile, caller=caller_name),
            helper_single_object('policies/featureRolloutPolicies', conf_call_object, self.failurefile, caller=caller_name),
            self.helper_multiple_object(parent='users', child='appRoleAssignments', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='users', child='appRoleAssignedResources', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='extensionProperties', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='owners', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='tokenIssuancePolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='tokenLifetimePolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='applications', child='federatedIdentityCredentials', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='users', child='registeredDevices', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='directoryRoles', child='members', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='groups', child='appRoleAssignments', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='users', child='authentication/methods', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='domains', child='federationConfiguration', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='appRoleAssignments', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='appRoleAssignedTo', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='owners', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='createdObjects', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='ownedObjects', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='oauth2PermissionGrants', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='memberOf', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='transitiveMemberOf', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='homeRealmDiscoveryPolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='synchronization/jobs', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='claimsMappingPolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='tokenLifetimePolicies', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='servicePrincipals', child='delegatedPermissionClassifications', output_dir=sub_dir, caller=caller_name)
        )

    async def dump_risk_detections(self) -> None:
        """
        Dumps risk detections from identity protection. Requires a minimum of Microsoft Entra ID P1 license and Microsoft Entra Workload ID premium license for full results.
        """
        sub_dir = os.path.join(self.output_dir, 'entraid_riskdetections')
        check_output_dir(sub_dir, self.logger)
        caller_name = asyncio.current_task().get_name()

        ri_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        await asyncio.gather(
            helper_single_object('identityProtection/riskDetections', ri_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identityProtection/servicePrincipalRiskDetections', ri_call_object, self.failurefile, caller=caller_name)
        )

    async def dump_risky_objects(self) -> None:
        """
        Dumps risky users and service principal information. Requires a minimum of Microsoft Entra ID P2 license and Microsoft Entra Workload ID premium license for full results.
        """
        sub_dir = os.path.join(self.output_dir, 'entraid_riskyobjects')
        check_output_dir(sub_dir, self.logger)
        caller_name = asyncio.current_task().get_name()

        ri2_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        await asyncio.gather(
            helper_single_object('identityProtection/riskyUsers', ri2_call_object, self.failurefile, caller=caller_name),
            helper_single_object('identityProtection/riskyServicePrincipals', ri2_call_object, self.failurefile, caller=caller_name),
            self.helper_multiple_object(parent='riskyUsers', child='history', output_dir=sub_dir, caller=caller_name),
            self.helper_multiple_object(parent='identityProtection/riskyServicePrincipals', child='history', output_dir=sub_dir, caller=caller_name)
        )

    async def dump_security(self) -> None:
        """
        Dump security actions, alerts, and scores
        """
        sub_dir = os.path.join(self.output_dir, 'entraid_security')
        check_output_dir(sub_dir, self.logger)
        caller_name = asyncio.current_task().get_name()

        sec_call_object = [self.get_url(), self.app_auth, self.logger, sub_dir, self.get_session()]
        await asyncio.gather(
            helper_single_object('security/securityActions', sec_call_object, self.failurefile, caller=caller_name),
            helper_single_object('security/alerts', sec_call_object, self.failurefile, caller=caller_name),
            helper_single_object('security/secureScores', sec_call_object, self.failurefile, caller=caller_name)
        )
