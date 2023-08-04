#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: azure_ad_datadumper!
This module has all the telemetry pulls for Azure AD.
"""

import asyncio
import json
import os

from datetime import datetime, timedelta
from goosey.auth import check_app_auth_token
from goosey.datadumper import DataDumper
from goosey.utils import *

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

class AzureAdDataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, auth, app_auth, session, config, debug):
        super().__init__(f'{output_dir}{os.path.sep}azuread', reports_dir, auth, app_auth, session, debug)
        self.logger = setup_logger(__name__, debug)
        self.THRESHOLD = 300
        self.us_government = config_get(config, 'config', 'us_government', self.logger).lower()
        self.exo_us_government = config_get(config, 'config', 'exo_us_government', self.logger).lower()
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        filters = config_get(config, 'filters', 'date_start', logger=self.logger)
        if  filters!= '' and filters is not None:
            self.date_range=True
            self.date_start = config_get(config, 'filters', 'date_start')
            if config_get(config, 'filters', 'date_end') != '':
                self.date_end = config_get(config, 'filters', 'date_end')
            else:
                self.date_end = datetime.now().strftime("%Y-%m-%d") +':00:00.000Z'
        else:
            self.date_range=False
        
        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]

    async def dump_signins_adfs(self):
        return await self._dump_signins('adfs')

    async def dump_signins_rt(self):
        return await self._dump_signins('rt')

    async def dump_signins_sp(self):
        return await self._dump_signins('sp')

    async def dump_signins_msi(self):
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

        signin_directory = os.path.join(self.output_dir, source)
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

        while start != end_date:
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())            
            outfile = os.path.join(signin_directory, source + '_signin_log_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            filters = '(createdDateTime ge %s and createdDateTime lt %s)' % (start, end_time)
            params = {
                'api-version': 'beta',
                '$orderby': 'createdDateTime',
                '$filter': filters,
                'source': source
            }
            if self.us_government == 'false':
                url = 'https://graph.microsoft.com/beta/auditLogs/signIns'
            elif self.us_government == 'true':
                url = 'https://graph.microsoft.us/beta/auditLogs/signIns'
            retries = 50
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

    async def dump_azuread_audit(self) -> None:
        """Dumps Azure AD Audit logs.
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-beta

        :return: None
        :rtype: None
        """

        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error("Missing token_type and access_token from auth. Did you auth correctly? (Skipping dump_azuread_audit)")
            return

        if check_app_auth_token(self.app_auth, self.logger):
            return
        
        sub_dir = os.path.join(self.output_dir, 'azure_audit_logs')
        check_output_dir(sub_dir, self.logger)
        
        if self.us_government == 'false':
            url = 'https://graph.microsoft.com/beta/auditLogs/directoryAudits'
        elif self.us_government == 'true':
            url = 'https://graph.microsoft.us/beta/auditLogs/directoryAudits'
        
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
            outfile = os.path.join(sub_dir, 'azureadauditlog_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.auth)
            end_date = '%sT00:00:00.000000Z' % (datetime.now().strftime("%Y-%m-%d"))

        elif self.date_range:
            self.logger.debug(f'Specified date range found. Pulling audit logs between {self.date_start} and {self.date_end}')
            start = self.date_start + 'T00:00:00.000000Z'
            end_date = self.date_end + 'T00:00:00.000000Z'

        else:
            self.logger.debug(f'Save state file does not exist at {statefile}.')
            start = '%sT00:00:00.000000Z' % ((datetime.now() - timedelta(days=29)).strftime("%Y-%m-%d"))
            self.logger.info('Getting AzureAD audit logs...')
            end_date = '%sT00:00:00.000000Z' % (datetime.now().strftime("%Y-%m-%d"))
        while start < end_date:
            retries = 5
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())            
            outfile = os.path.join(sub_dir, 'azureadauditlog_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            filters = '(activityDateTime ge %s and activityDateTime lt %s)' % (start, end_time)

            params = {
                'api-version': 'beta',
                '$orderby': 'activityDateTime',
                '$filter': filters,
            }

            self.logger.debug(f'Dumping AzureAD audit logs for time frame {start} to {end_time}')

            success = False
            for counter in range (retries):
                try:
                    header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
                    async with self.ahsession.get(url, headers=header, params=params, raise_for_status=True, timeout=600) as r:
                        result = await r.json()
                        nexturl = None
                        if '@odata.nextLink' in result:
                                nexturl = result['@odata.nextLink']
                                await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.auth)
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
                            

        self.logger.info('Finished dumping AzureAD audit logs.')

    async def dump_azuread_provisioning(self) -> None:
        """Dumps Azure AD provisioning logs.
        API Reference: https://docs.microsoft.com/en-us/graph/api/resources/provisioningobjectsummary?view=graph-rest-beta

        :return: None
        :rtype: None
        """

        if 'token_type' not in self.app_auth or 'access_token' not in self.app_auth:
            self.logger.error("Missing token_type and access_token from auth. Did you auth correctly? (Skipping dump_azuread_provisioning)")
            return
        
        if check_app_auth_token(self.app_auth, self.logger):
            return

        if self.us_government == 'false':
            url = 'https://graph.microsoft.com/beta/auditLogs/provisioning'
        elif self.us_government == 'true':
            url = 'https://graph.microsoft.us/beta/auditLogs/provisioning'
            
        self.logger.info('Getting AzureAD provisioning logs...')
        outfile = os.path.join(self.output_dir, 'azureadprovisioninglogs.json')  

        header = {'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token'])}
        async with self.ahsession.get(url, headers=header, timeout=600) as r:
            result = await r.json()
            if 'value' not in result:
                self.logger.debug("Error with result: {}".format(str(result)))
                sys.exit(1)
            with open(outfile, 'w', encoding='utf-8') as f:
                nexturl = None
                if '@odata.nextLink' in result:
                    nexturl = result['@odata.nextLink']
                if 'value' in result:
                    f.write("\n".join([json.dumps(x) for x in result['value']]) + '\n')

                await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)

        self.logger.info('Finished dumping AzureAD provisioning logs.')
   
    def get_url(self):
        if self.us_government == "false":
            return "https://graph.microsoft.com/beta/"
        elif self.us_government == "true":
            return "https://graph.microsoft.us/beta/"

    async def helper_multiple_object(self, parent, child,identifier='id'): 
        url_parent = self.get_url()

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

        outfile = os.path.join(self.output_dir, parent + "_" + child + '.json')
        if child_list:
            with open(outfile, 'w', encoding='utf-8') as f:
                for entry in child_list:
                    f.write(json.dumps(entry, sort_keys=True) + '\n')
        elif not child_list:
            with open(self.failurefile, 'a+', encoding='utf-8') as f:
                f.write('No output file: ' + parent + "_" + child + ' - ' + str((datetime.now())) + '\n')

        self.logger.info('Finished dumping %s %s information.' % (parent, child))
    
    async def dump_applications(self) -> None:
        await asyncio.gather(
            helper_single_object('applications', self.call_object, self.failurefile),
            helper_single_object('directory/deleteditems/microsoft.graph.application', self.call_object, self.failurefile),
            helper_single_object('identityGovernance/appConsent/appConsentRequests', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='applications', child='extensionProperties'),
            self.helper_multiple_object(parent='applications', child='owners'),
            self.helper_multiple_object(parent='applications', child='tokenIssuancePolicies'),
            self.helper_multiple_object(parent='applications', child='tokenLifetimePolicies'),
            self.helper_multiple_object(parent='applications', child='federatedIdentityCredentials')
        )

    async def dump_conditional_access(self) -> None:
        await asyncio.gather(
            helper_single_object('conditionalAccess/authenticationContextClassReferences', self.call_object, self.failurefile),
            helper_single_object('conditionalAccess/namedLocations',self.call_object, self.failurefile),
            helper_single_object('conditionalAccess/policies', self.call_object, self.failurefile)
        )

    async def dump_devices(self) -> None:
        await asyncio.gather(
            helper_single_object('devices', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='users', child='registeredDevices')
        )

    async def dump_directory_roles(self) -> None:
        await asyncio.gather(
            helper_single_object('directoryRoles', self.call_object, self.failurefile),
            helper_single_object('roleManagement/directory/roleDefinitions', self.call_object, self.failurefile),
            helper_single_object('roleManagement/directory/roleAssignmentSchedules', self.call_object, self.failurefile),
            helper_single_object('roleManagement/directory/roleEligibilitySchedules', self.call_object, self.failurefile),
            helper_single_object('roleManagement/directory/roleEligibilityScheduleInstances', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='directoryRoles', child='members')
        )

    async def dump_groups(self) -> None:
        await asyncio.gather(
            helper_single_object('groups', self.call_object, self.failurefile),
            helper_single_object('directory/deleteditems/microsoft.graph.group', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='groups', child='appRoleAssignments')
        )

    async def dump_identity_provider(self) -> None:
        await asyncio.gather(
            helper_single_object('identity/identityProviders', self.call_object, self.failurefile),
            helper_single_object('identity/identityProviders/availableProviderTypes', self.call_object, self.failurefile),
            helper_single_object('identity/apiConnectors', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='users', child='authentication/methods')
        )       

    async def dump_organization(self) -> None:
        await asyncio.gather(
            helper_single_object('directorySettingTemplates', self.call_object, self.failurefile),
            helper_single_object('directory/federationConfigurations/graph.samlOrWsFedExternalDomainFederation', self.call_object, self.failurefile),
            helper_single_object('domains', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='domains', child='federationConfiguration'),
            helper_single_object('organization', self.call_object, self.failurefile),
            helper_single_object('subscribedSkus', self.call_object, self.failurefile)
        )

    async def dump_policies(self) -> None:
        await asyncio.gather(
            helper_single_object('identity/continuousAccessEvaluationPolicy', self.call_object, self.failurefile),
            helper_single_object('identity/events/onSignupStart', self.call_object, self.failurefile),
            helper_single_object('policies/activityBasedTimeoutPolicies', self.call_object, self.failurefile),
            helper_single_object('policies/defaultAppManagementPolicy', self.call_object, self.failurefile),
            helper_single_object('policies/tokenLifetimePolicies', self.call_object, self.failurefile),
            helper_single_object('policies/tokenIssuancePolicies', self.call_object, self.failurefile),
            helper_single_object('policies/authenticationFlowsPolicy', self.call_object, self.failurefile),
            helper_single_object('policies/authenticationMethodsPolicy', self.call_object, self.failurefile),
            helper_single_object('policies/authorizationPolicy', self.call_object, self.failurefile),
            helper_single_object('policies/claimsMappingPolicies', self.call_object, self.failurefile),
            helper_single_object('policies/homeRealmDiscoveryPolicies', self.call_object, self.failurefile),
            helper_single_object('policies/permissionGrantPolicies', self.call_object, self.failurefile),
            helper_single_object('policies/identitySecurityDefaultsEnforcementPolicy', self.call_object, self.failurefile),
            helper_single_object('policies/accessReviewPolicy', self.call_object, self.failurefile),
            helper_single_object('policies/adminConsentRequestPolicy', self.call_object, self.failurefile)
        )

    async def dump_risk_detections(self) -> None:
        await asyncio.gather(
            helper_single_object('identityProtection/riskDetections', self.call_object, self.failurefile),
            helper_single_object('identityProtection/servicePrincipalRiskDetections', self.call_object, self.failurefile)
        )

    async def dump_risky_objects(self) -> None:
        await asyncio.gather(
            helper_single_object('identityProtection/riskyUsers', self.call_object, self.failurefile),
            helper_single_object('identityProtection/riskyServicePrincipals', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='riskyUsers', child='history'),
            self.helper_multiple_object(parent='identityProtection/riskyServicePrincipals', child='history')
        )

    async def dump_security(self) -> None:
        await asyncio.gather(
            helper_single_object('security/securityActions', self.call_object, self.failurefile),
            helper_single_object('security/alerts', self.call_object, self.failurefile),
            helper_single_object('security/secureScores', self.call_object, self.failurefile)
        )

    async def dump_service_principals(self) -> None:
        await asyncio.gather(
            helper_single_object('servicePrincipals', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='servicePrincipals', child='appRoleAssignments'),
            self.helper_multiple_object(parent='servicePrincipals', child='appRoleAssignedTo'),
            self.helper_multiple_object(parent='servicePrincipals', child='owners'),
            self.helper_multiple_object(parent='servicePrincipals', child='createdObjects'),
            self.helper_multiple_object(parent='servicePrincipals', child='ownedObjects'),
            self.helper_multiple_object(parent='servicePrincipals', child='oauth2PermissionGrants'),
            self.helper_multiple_object(parent='servicePrincipals', child='memberOf'),
            self.helper_multiple_object(parent='servicePrincipals', child='transitiveMemberOf'),
            self.helper_multiple_object(parent='servicePrincipals', child='homeRealmDiscoveryPolicies'),
            self.helper_multiple_object(parent='servicePrincipals', child='synchronization/jobs'),
            self.helper_multiple_object(parent='servicePrincipals', child='claimsMappingPolicies'),
            self.helper_multiple_object(parent='servicePrincipals', child='tokenLifetimePolicies'),
            self.helper_multiple_object(parent='servicePrincipals', child='delegatedPermissionClassifications')
        )

    async def dump_summaries(self) -> None:
        await asyncio.gather(
            helper_single_object("reports/getRelyingPartyDetailedSummary(period='D30')", self.call_object, self.failurefile),
            helper_single_object("reports/getAzureADApplicationSignInSummary(period='D30')", self.call_object, self.failurefile),
            helper_single_object('reports/applicationSignInDetailedSummary', self.call_object, self.failurefile),
            helper_single_object("reports/getCredentialUsageSummary(period='D30')", self.call_object, self.failurefile),
            helper_single_object("reports/getCredentialUserRegistrationCount", self.call_object, self.failurefile),
            helper_single_object("reports/credentialUserRegistrationDetails", self.call_object, self.failurefile),
            helper_single_object("reports/userCredentialUsageDetails", self.call_object, self.failurefile),
        )

    async def dump_users(self) -> None:
        await asyncio.gather(
            helper_single_object('users', self.call_object, self.failurefile),
            helper_single_object('contacts', self.call_object, self.failurefile),
            helper_single_object('oauth2PermissionGrants', self.call_object, self.failurefile),
            helper_single_object('directory/deletedItems/microsoft.graph.user', self.call_object, self.failurefile),
            self.helper_multiple_object(parent='users', child='appRoleAssignments')
        )
