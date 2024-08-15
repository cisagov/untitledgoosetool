#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: azure_datadumper!
This module has all the telemetry pulls for Azure resources.
"""

import asyncio
import getpass
import json
import os
import pytz

from azure.core.exceptions import *
from azure.identity import AzureAuthorityHosts
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient, ResourceManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.storage.blob import BlobServiceClient
from goosey.datadumper import DataDumper
from goosey.utils import *
from http.client import CONTINUE
from re import S, sub
from typing import NewType, Optional

utc = pytz.UTC

class AzureDataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, session, app_auth, config, auth_un_pw, debug):
        super().__init__(f'{output_dir}{os.path.sep}azure', reports_dir, None, app_auth, session, debug)
        self.logger = setup_logger(__name__, debug)
        if auth_un_pw is not None:
            if auth_un_pw['auth']['appid']:
                self.app_id = auth_un_pw['auth']['appid']
            else:
                self.app_id = input("Please type your application client id: ")
            if auth_un_pw['auth']['clientsecret']:
                self.client_secret = auth_un_pw['auth']['clientsecret']
            else:
                self.client_secret = getpass.getpass("Please type your client secret: ")
        else:
             self.app_id = input("Please type your application client id: ")
             self.client_secret = getpass.getpass("Please type your client secret: ")
        self.tenant = config['config']['tenant']
        self.us_gov = config['config']['us_government']
        if self.us_gov.lower() == "true":
            self.authority = AzureAuthorityHosts.AZURE_GOVERNMENT
        else:
            self.authority = AzureAuthorityHosts.AZURE_PUBLIC_CLOUD

        os.environ.setdefault('AZURE_CLIENT_ID', self.app_id)
        os.environ.setdefault('AZURE_TENANT_ID', self.tenant)
        os.environ.setdefault('AZURE_CLIENT_SECRET', self.client_secret)

        self.logger.debug(f"Authority set to: {str(self.authority)}")

        self.credential = ClientSecretCredential(tenant_id=self.tenant, client_id=self.app_id, client_secret=self.client_secret, authority=self.authority, logging_enable=True)

        if config['config']['subscriptionid'].lower() == "all":
            if self.us_gov.lower() == "true":
                self.subscription_client = SubscriptionClient(self.credential, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default'])
            else:
                self.subscription_client = SubscriptionClient(self.credential)
            subscription_list = self.subscription_client.subscriptions.list()
            self.subscription_id_list = []
            try:
                for sub in subscription_list:
                    sub_directory = os.path.join(self.output_dir, sub.subscription_id)
                    if not os.path.exists(sub_directory):
                        os.makedirs(sub_directory)

                    self.subscription_id_list.append(sub.subscription_id)
            except Exception as e:
                self.logger.error(f"Error getting subscriptions: {str(e)}\nDo you have the right subscription ids in your .conf file?")
                if len(self.subscription_id_list) == 0:
                    self.logger.error(f"Subscription list is empty, you won't get any data back for Azure data calls.")
        else:
            self.subscription_id_list = config['config']['subscriptionid'].split(",")

        self.network_managers, self.compute_clients, self.web_clients, self.storage_clients, \
            self.resource_clients, self.monitor_clients, self.security_clients = [], [], [], [], [], [], []

        for sub_id in self.subscription_id_list:
            sub_id = sub_id.strip()

            if self.us_gov.lower() == "true":
                location = 'USGov Virginia'
                self.network_managers.append(NetworkManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.compute_clients.append(ComputeManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.web_clients.append(WebSiteManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.storage_clients.append(StorageManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.resource_clients.append(ResourceManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                self.monitor_clients.append(MonitorManagementClient(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default']))
                locationclient = SecurityCenter(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default'], asc_location=location)
                self.asclocation = locationclient.locations.list().next().as_dict()
                self.security_clients.append(SecurityCenter(credential=self.credential, subscription_id=sub_id, base_url='https://management.usgovcloudapi.net', credential_scopes=['https://management.usgovcloudapi.net/.default'], asc_location=self.asclocation))
            else:
                location = 'centralus'
                self.network_managers.append(NetworkManagementClient(credential=self.credential, subscription_id=sub_id))
                self.compute_clients.append(ComputeManagementClient(credential=self.credential, subscription_id=sub_id))
                self.web_clients.append(WebSiteManagementClient(credential=self.credential, subscription_id=sub_id))
                self.storage_clients.append(StorageManagementClient(credential=self.credential, subscription_id=sub_id))
                self.resource_clients.append(ResourceManagementClient(credential=self.credential, subscription_id=sub_id))
                self.monitor_clients.append(MonitorManagementClient(credential=self.credential, subscription_id=sub_id))
                locationclient = SecurityCenter(credential=self.credential, subscription_id=sub_id, asc_location=location)
                self.asclocation = locationclient.locations.list().next().as_dict()
                self.security_clients.append(SecurityCenter(credential=self.credential, subscription_id=sub_id, asc_location=self.asclocation))

        filters = config_get(config, 'filters', 'date_start', logger=self.logger)
        self.logger.debug(f"Filters are {filters}")
        if filters != '' and  filters is not None:
            self.date_range = True
            self.date_start = config['filters']['date_start']
            if config['filters']['date_end'] != '':
                self.date_end = config['filters']['date_end']
            else:
                self.date_end = datetime.now().strftime("%Y-%m-%d")
        else:
            self.date_range=False

    async def dump_d4iot_portal_pcap(self) -> None:
        """
        Dump D4IOT portal pcaps from alerts
        """
        header = {
            'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token']),
            'Content-type': 'application/json'
            }

        for subscriptionId in self.subscription_id_list:
            self.logger.info("Getting D4IOT portal pcaps from " + subscriptionId + "...")
            pcap_dir = os.path.join(self.output_dir, subscriptionId, 'd4iot_portal', 'pcaps')
            check_output_dir(pcap_dir, self.logger)

            devgrps_outfile = os.path.join(self.output_dir, subscriptionId, 'd4iot_portal', "portal_device_groups.json")

            locations = []
            if self.us_gov.lower() == "true":
                loc_url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview"
            else:
                loc_url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview"

            async with self.ahsession.request('GET', loc_url, headers=header, ssl=False) as r:
                result = await r.json()
                if not result:
                    self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                    return
                if 'value' in result:
                    for entry in result['value']:
                        locations.append(entry['name'])
                elif 'error' in result:
                    if result['error']['code'] == 'ExpiredAuthenticationToken':
                        self.logger.error("Error with authentication token: " + result['error']['message'])
                        self.logger.error("Please re-auth.")
                        sys.exit(1)

            for location in locations:
                device_grps = []
                if self.us_gov.lower() == "true":
                    devgrp_url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups?api-version=2021-02-01-preview"
                else:
                    devgrp_url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups?api-version=2021-02-01-preview"

                async with self.ahsession.request('GET', devgrp_url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        for entry in result['value']:
                            device_grps.append(entry['name'])
                        with open(devgrps_outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x) + "\n")
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            sys.exit(1)

                alert_ids = []
                for val in device_grps:
                    if self.us_gov.lower() == "true":
                        url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups/" + val + "/alerts?api-version=2021-07-01-preview"
                    else:
                        url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups/" + val + "/alerts?api-version=2021-07-01-preview"

                    async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                        result = await r.json()
                        # nexturl = None
                        # if '@odata.nextLink' in result:
                        #     nexturl = result['@odata.nextLink']
                        if 'value' in result:
                            for x in result['value']:
                                createdAt = dateutil.parser.parse(x["systemData"]["createdAt"]).replace(tzinfo=None)
                                # Check for date time range
                                if self.date_range:
                                    start = dateutil.parser.parse(self.date_start).replace(tzinfo=None)
                                    end = dateutil.parser.parse(self.date_end).replace(tzinfo=None)
                                    if start <= createdAt and createdAt <= end:
                                        alert_ids.append(x['id'])
                                else:
                                    alert_ids.append(x['id'])
                        elif 'error' in result:
                            if result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                sys.exit(1)

            for id in alert_ids:
                if self.us_gov.lower() == "true":
                    availability_url =  "https://management.azure.us" + id + "/pcapAvailability?api-version=2021-07-01-preview"
                else:
                    availability_url =  "https://management.azure.com" + id + "/pcapAvailability?api-version=2021-07-01-preview"
                i = id.split("/")[-1]
                outfile = os.path.join(pcap_dir, "pcap_" + str(i) + ".pcap")
                async with self.ahsession.request('POST', availability_url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'error' in result:
                        if result['error']['code'] == 'NotFound':
                            self.logger.debug("Resource not found. Exiting.")
                            return
                        elif result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            sys.exit(1)

                    if 'status' in result:
                        if result['status'] == 'Done':
                            self.logger.info("PCAP downloaded for alert id %s." % (i))
                            download_url = result['downloadUrl']
                            async with self.ahsession.request('GET', download_url,  ssl=False, allow_redirects=True) as r:
                                output = await r.read()
                                with open(outfile, 'wb') as f:
                                    f.write(output)

                        elif result['status'] == 'Available':
                            if 'error' in result:
                                if result['error']['code'] == 'PCAP_NOT_FOUND':
                                    self.logger.debug("PCAP not found for alert id %s. Proceeding" % (i))
                                    continue
                            else:
                                self.logger.debug("PCAP available for alert id %s." % (i))

                            if self.us_gov.lower() == "true":
                                request_url = "https://management.azure.us" + id + "/pcapRequest?api-version=2021-07-01-preview"
                            else:
                                request_url = "https://management.azure.com" + id + "/pcapRequest?api-version=2021-07-01-preview"

                            status = None

                            while status != "Done":
                                 async with self.ahsession.request('POST', request_url, headers=header, ssl=False) as r:
                                    result = await r.json()
                                    if 'error' in result:
                                        self.logger.error("Error: " + result['error']['message'])
                                    else:
                                        status = result['status']
                                    await asyncio.sleep(5)

                            download_url = result['downloadUrl']
                            async with self.ahsession.request('GET', download_url,  ssl=False, allow_redirects=True) as r:
                                output = await r.read()
                                with open(outfile, 'wb') as f:
                                    f.write(output)
                                self.logger.info("PCAP downloaded for alert id %s." % (i))


                        elif result['status'] == "UnsupportedAlert":
                             self.logger.debug("PCAP not available for alert id %s. Proceeding" % (i))
                        elif result['status'] == "DisconnectedSensor":
                            self.logger.error("Sensor is disconnected. Stopping PCAP pull.")
                            return
                        else:
                            self.logger.debug(result)
            self.logger.info("Getting D4IOT portal pcaps from " + subscriptionId + "...")

    async def _dump_portal_alerts(self) -> None:
        """
        Dump d4iot portal alerts
        """
        header = {
            'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token']),
            'Content-type': 'application/json'
            }

        for subscriptionId in self.subscription_id_list:

            self.logger.info("Getting D4IOT portal alerts from " + subscriptionId + "...")

            new_outfile = os.path.join(self.output_dir, subscriptionId, "d4iot_portal")
            check_output_dir(new_outfile, self.logger)

            devgrps_outfile = os.path.join(new_outfile, "portal_device_groups.json")
            outfile = os.path.join(new_outfile, "portal_alerts.json")

            if os.path.exists(devgrps_outfile) and os.path.exists(outfile):
                self.logger.debug("D4IOT portal alerts files exists.. Proceeding without pulling.")
            else:
                locations = []
                if self.us_gov.lower() == "true":
                    loc_url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview"
                else:
                    loc_url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview"

                async with self.ahsession.request('GET', loc_url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        for entry in result['value']:
                            locations.append(entry['name'])
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            os._exit(1)

                for location in locations:
                    device_grps = []
                    if self.us_gov.lower() == "true":
                        devgrp_url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups?api-version=2021-02-01-preview"
                    else:
                        devgrp_url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups?api-version=2021-02-01-preview"

                    async with self.ahsession.request('GET', devgrp_url, headers=header, ssl=False) as r:
                        result = await r.json()
                        if 'value' in result:
                            for entry in result['value']:
                                device_grps.append(entry['name'])
                            with open(devgrps_outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x) + "\n")
                                f.flush()
                                os.fsync(f)
                        elif 'error' in result:
                            if result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                os._exit(1)

                for val in device_grps:
                    if self.us_gov.lower() == "true":
                        url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups/" + val + "/alerts?api-version=2021-07-01-preview"
                    else:
                        url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/deviceGroups/" + val + "/alerts?api-version=2021-07-01-preview"

                    async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                        result = await r.json()
                        nexturl = None
                        if '@odata.nextLink' in result:
                            nexturl = result['@odata.nextLink']
                        if 'value' in result:
                            with open(outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x) + "\n")
                                f.flush()
                                os.fsync(f)
                        elif 'error' in result:
                            if result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                os._exit(1)
                        await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
                self.logger.info("Finished getting D4IOT portal alerts from " + subscriptionId + ".")

    async def _dump_portal_defendersettings(self) -> None:
        """
        Dump d4iot portal defender settings
        """
        header = {
            'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token']),
            'Content-type': 'application/json'
            }

        for subscriptionId in self.subscription_id_list:
            self.logger.info("Getting D4IOT portal defender settings from " + subscriptionId + "...")

            new_outfile = os.path.join(self.output_dir, subscriptionId, "d4iot_portal")
            check_output_dir(new_outfile, self.logger)

            outfile = os.path.join(new_outfile, "portal_defender_settings.json")
            if os.path.exists(outfile):
                self.logger.debug("D4IOT portal defender settings file exists.. Proceeding without pulling.")
            else:
                if self.us_gov.lower() == "true":
                    url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/defenderSettings?api-version=2021-02-01-preview"
                else:
                    url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/defenderSettings?api-version=2021-02-01-preview"

                async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        with open(outfile, 'w', encoding='utf-8') as f:
                            for x in result['value']:
                                f.write(json.dumps(x) + "\n")
                            f.flush()
                            os.fsync(f)
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            os._exit(1)

                self.logger.info("Finished getting D4IOT portal defender settings from " + subscriptionId + ".")

    async def _dump_portal_sensors(self) -> None:
        """
        Dump d4iot portal sensors
        """
        header = {
            'Authorization': '%s %s' % (self.app_auth['token_type'], self.app_auth['access_token']),
            'Content-type': 'application/json'
            }

        for subscriptionId in self.subscription_id_list:
            self.logger.info("Getting D4IOT portal sensors from " + subscriptionId + "...")

            new_outfile = os.path.join(self.output_dir, subscriptionId, "d4iot_portal")
            check_output_dir(new_outfile, self.logger)

            sites_outfile = os.path.join(new_outfile, "portal_sites.json")
            outfile = os.path.join(new_outfile, "portal_sensors.json")
            onsite_outfile = os.path.join(new_outfile, "portal_onpremise_sensors.json")

            locations = []
            if self.us_gov.lower() == "true":
                loc_url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview"
            else:
                loc_url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations?api-version=2021-09-01-preview"
            async with self.ahsession.request('GET', loc_url, headers=header, ssl=False) as r:
                result = await r.json()
                if 'value' in result:
                    for entry in result['value']:
                        locations.append(entry['name'])
                elif 'error' in result:
                    if result['error']['code'] == 'ExpiredAuthenticationToken':
                        self.logger.error("Error with authentication token: " + result['error']['message'])
                        self.logger.error("Please re-auth.")
                        os._exit(1)

            for location in locations:
                sites = []
                if self.us_gov.lower() == "true":
                    sites_url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/sites?api-version=2021-09-01-preview"
                else:
                    sites_url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/sites?api-version=2021-09-01-preview"

                async with self.ahsession.request('GET', sites_url, headers=header, ssl=False) as r:
                    result = await r.json()
                    if 'value' in result:
                        for entry in result['value']:
                            sites.append(entry['name'])
                        with open(sites_outfile, 'a+', encoding='utf-8') as f:
                            for x in result['value']:
                                f.write(json.dumps(x) + "\n")
                            f.flush()
                            os.fsync(f)
                    elif 'error' in result:
                        if result['error']['code'] == 'ExpiredAuthenticationToken':
                            self.logger.error("Error with authentication token: " + result['error']['message'])
                            self.logger.error("Please re-auth.")
                            os._exit(1)

                for val in sites:
                    if self.us_gov.lower() == "true":
                        url = "https://management.azure.us/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/sites/" + val + "/sensors?api-version=2021-09-01-preview"
                    else:
                        url = "https://management.azure.com/subscriptions/" + subscriptionId + "/providers/Microsoft.IoTSecurity/locations/" + location + "/sites/" + val + "/sensors?api-version=2021-09-01-preview"
                    async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
                        result = await r.json()
                        nexturl = None
                        if '@odata.nextLink' in result:
                            nexturl = result['@odata.nextLink']
                        if 'value' in result:
                            with open(outfile, 'a+', encoding='utf-8') as f:
                                for x in result['value']:
                                    f.write(json.dumps(x) + "\n")
                                f.flush()
                                os.fsync(f)
                        elif 'error' in result:
                            if result['error']['code'] == 'ExpiredAuthenticationToken':
                                self.logger.error("Error with authentication token: " + result['error']['message'])
                                self.logger.error("Please re-auth.")
                                os._exit(1)
                        await get_nextlink(nexturl, outfile, self.ahsession, self.logger, self.app_auth)
            self.logger.info("Finished getting D4IOT portal sensors settings from " + subscriptionId + ".")

    async def dump_d4iot_portal_configs(self) -> None:
        """
        Dump D4IOT portal configs
        """
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self._dump_portal_alerts(), name="dump_portal_alerts")
            tg.create_task(self._dump_portal_defendersettings(), name="dump_portal_defendersettings")
            tg.create_task(self._dump_portal_sensors(), name="dump_portal_sensors")

    async def _dump_diagnostic_settings(self) -> None:
        """
        Dump Monitor Management Client diagnostic settings
        """
        for i in range(0, len(self.subscription_id_list)):
            sub_id = self.subscription_id_list[i]
            resource_client = self.resource_clients[i]
            monitor_client = self.monitor_clients[i]
            config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
            check_output_dir(config_dir, self.logger)
            output = os.path.join(config_dir, "diagnostic_settings.json")
            if os.path.exists(output):
                self.logger.debug("Diagnostic settings file exists.. Proceeding without pulling.")
            else:
                self.logger.info("Getting diagnostic settings configurations from " + sub_id + "...")
                for event in resource_client.resources.list(filter=None):
                    if event:
                        resource_id = event.as_dict()['id']
                        try:
                            for entry in monitor_client.diagnostic_settings.list(resource_id):
                                with open(output, 'a+', encoding='utf-8') as f:
                                    temp = {'resource': str(resource_id)}
                                    info = entry.as_dict()
                                    info.update(temp)
                                    f.write(json.dumps(info, sort_keys=True) + '\n')

                        except HttpResponseError as e:
                            continue
                    await asyncio.sleep(0) # make it blocking so that other coroutines can continue
                self.logger.info("Finished geting diagnostic settings from " + sub_id + ".")

    async def _dump_vm_config(self) -> None:
        """
        returns all of the vm configurations
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                compute_client = self.compute_clients[i]
                sub_id = self.subscription_id_list[i]

                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "vm_configs.json")
                if os.path.exists(output):
                    self.logger.debug("VM Configuration file exists.. Proceeding without pulling.")
                else:
                    self.logger.info("Getting virtual machine configurations from " + sub_id + "...")
                    for vm in compute_client.virtual_machines.list_all():
                        with open(output, 'a+', encoding='utf-8') as f:
                            general_view = vm.id.split("/")
                            resource_group = general_view[4]
                            vm_name = general_view[-1]
                            config = compute_client.virtual_machines.get(resource_group,vm_name, expand='instanceView').as_dict()
                            if config:
                                f.write(json.dumps(config))
                                f.write("\n")
                                f.flush()
                                os.fsync(f)
                        await asyncio.sleep(0) # make it blocking so that other coroutines can continue

                    self.logger.info("Finished geting virtual machine configurations from " + sub_id + ".")
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def _dump_container_config(self) -> None:
        """
        Returns all of the app container configs
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                web_client = self.web_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "container_configs.json")
                if os.path.exists(output):
                    self.logger.debug("Container Configuration file exists.. Proceeding without pulling.")
                else:
                    self.logger.info("Getting Azure web app container configurations for" + sub_id + "...")
                    for site in web_client.web_apps.list():
                        with open(output, 'a+', encoding='utf-8') as f:
                            general_view = site.id.split("/")
                            resource_group = general_view[4]
                            name = general_view[-1]
                            for config in web_client.web_apps.list_configurations(resource_group_name=resource_group, name=name):
                                if config:
                                    f.write(json.dumps(config.as_dict()))
                                    f.write("\n")
                                    f.flush()
                                    os.fsync(f)
                        await asyncio.sleep(0) # make it blocking so that other coroutines can continue

                    self.logger.info('Finished getting all web app Azure Container Configs for ' + sub_id + '.')
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def dump_all_azure_subscriptions(self) -> None:
        """
        Returns all azure subscriptions
        :return:
        :rtype:
        """
        output = os.path.join(self.output_dir, "subscriptions.json")
        if os.path.exists(output):
            self.logger.debug("All subscriptions file exists... Proceeding without pulling")
        else:
            try:
                self.logger.info("Getting Azure Subscriptions...")
                for event in self.subscription_client.subscriptions.list():
                    with open(output, 'a+', encoding='utf-8') as f:
                        f.write(json.dumps(event.as_dict()))
                        f.write("\n")
                        f.flush()
                        os.fsync(f)
                    await asyncio.sleep(0) # make it blocking so that other coroutines can continue
                self.logger.info('Finished getting all Azure Subscriptions.')
            except Exception as e:
                self.logger.error(f"Error getting subscriptions: {str(e)}\nDo you have the right credentials in your .conf file?")

    async def _dump_file_shares(self) -> None:
        """
        Dumps all the files shares in azure for each of the storage accounts
        :return:
        :rtype:
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                storage_client = self.storage_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "file_share_list.json")
                if os.path.exists(output):
                    self.logger.debug("File share file exists.. Proceeding without pulling.")
                else:
                    for account in storage_client.storage_accounts.list():
                        self.logger.info("Dumping file shares for " + sub_id + "...")
                        if account:
                            general_view = account.id.split("/")
                            resource_group = general_view[4]
                            name = general_view[-1]
                            for fs in storage_client.file_shares.list(resource_group_name=resource_group, account_name=name):
                                if fs:
                                    with open(output, 'a+', encoding='utf-8') as f:
                                        f.write(json.dumps(fs.as_dict()))
                                        f.write("\n")
                                        f.flush()
                                        os.fsync(f)
                        await asyncio.sleep(0) # make it blocking so that other coroutines can continue

                    self.logger.info('Finished dumping all file shares for' + sub_id + '.')
                    await asyncio.sleep(0) # make it blocking so that other coroutines can continue
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def _dump_all_resources(self) -> None:
        """
        Dumps all the resources in the azure account
        :return:
        :rtype:
        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                resource_client = self.resource_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "all_resources_list.json")
                if os.path.exists(output):
                    self.logger.debug("All resources file exists.. Proceeding without pulling.")
                else:
                    self.logger.info("Dumping list of all resources for" + sub_id + "...")
                    for event in resource_client.resources.list(filter=None):
                        if event:
                            with open(output, 'a+', encoding='utf-8') as f:
                                f.write(json.dumps(event.as_dict()))
                                f.write("\n")
                                f.flush()
                                os.fsync(f)

                    self.logger.info('Finished getting all azure resources information for ' + sub_id + '.')
                    await asyncio.sleep(0) # make it blocking so that other coroutines can continue
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def _dump_storage_accounts(self) -> None:
        """
        Lists all the storage accounts
        :return:
        :rtype:

        """
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                storage_client = self.storage_clients[i]
                config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
                check_output_dir(config_dir, self.logger)
                output = os.path.join(config_dir, "azure_storage_accounts.json")
                if os.path.exists(output):
                    self.logger.debug("Storage account file exists.. Proceeding without pulling.")
                else:
                    for element in storage_client.storage_accounts.list():
                        if element:
                            with open(output, 'a+', encoding='utf-8') as f:
                                f.write(json.dumps(element.as_dict()))
                                f.write("\n")
                                f.flush()
                                os.fsync(f)
                self.logger.info('Finished getting all Azure storage account information for ' + sub_id + '.')
                await asyncio.sleep(0) # make it blocking so that other coroutines can continue
            except HttpResponseError:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def auxillary_activity_log(self, start, end, i, statefile=None):
        sub_id = self.subscription_id_list[i]
        monitor_client = self.monitor_clients[i]
        self.logger.info('Dumping Azure Activity Log for ' + sub_id +'...')

        sub_directory = os.path.join(self.output_dir, sub_id, "Activity Log")
        if not os.path.exists(sub_directory):
            os.mkdir(sub_directory)

        if statefile is None:
            statefile = os.path.join(self.output_dir, sub_id, '.activity_log_state')
        start_datetime = dateutil.parser.parse(start).replace(tzinfo=None)
        end_datetime = dateutil.parser.parse(end).replace(tzinfo=None)
        while start_datetime < end_datetime:
            end_time = '%sT23:59:59.999999Z' % (datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date())

            filters = 'eventTimestamp ge %s' % (start) + ' and eventTimestamp le %s' % (end_time)
            outfile = os.path.join(sub_directory, 'azure_activity_log_' + str(datetime.strptime(end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date()) + '.json')
            self.logger.debug(f'Dumping Azure Activity logs for time frame {start} to {end_time}')
            activity_log = monitor_client.activity_logs

            with open(outfile, 'w', encoding='utf-8') as f:
                for event in activity_log.list(filter=filters):
                    f.write(json.dumps(event.as_dict()))
                    f.write("\n")
                    f.flush()
                    os.fsync(f)
            with open(statefile, 'w') as f:
                f.write(end_time)
            await asyncio.sleep(0) # make it blocking so that other coroutines can continue

            start = '%sT00:00:00.000000Z' % ((datetime.strptime(start, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1)).strftime("%Y-%m-%d"))
            start_datetime = dateutil.parser.parse(start).replace(tzinfo=None)

    async def dump_activity_log(self) -> None:
        """
        Dumps activity log from azure
        :return:
        :rtype:
        """
        save_state = False
        sub_statefile = os.path.join(self.output_dir, '.sub_savestate')

        # default start_date and final_time
        start_date = '%sT00:00:00.000000Z' % ((datetime.now(utc) - timedelta(days=89)).strftime("%Y-%m-%d"))
        final_time = '%sT00:00:00.000000Z' % ((datetime.now(utc)).strftime("%Y-%m-%d"))

        if os.path.isfile(sub_statefile):
            self.logger.debug(f'Subscription save state file exists at {sub_statefile}')
            statefile=""

            with open(sub_statefile, "r") as f:
                subscription_id_num = f.readline().strip()
                subscription_id_num = int(subscription_id_num)
                subscript_id = self.subscription_id_list[subscription_id_num]
                statefile = os.path.join(self.output_dir, subscript_id, '.activity_log_state')
                self.logger.debug(statefile)

            if os.path.isfile(statefile):
                self.logger.info(f'Activity log save state file found. Continuing from last checkpoint.')
                with open(statefile, 'r') as reader:
                    save_state_end_time = reader.readline().strip()
                    start_time_saved_sub = '%sT00:00:00.000000Z' % (datetime.strptime(save_state_end_time, ("%Y-%m-%dT%H:%M:%S.%fZ")).date() + timedelta(days=1))
                save_state = True
            else:
                self.logger.info(f'Activity log save state file not found. Starting a fresh pull.')
                subscription_id_num = 0
                save_state = False

            end_time_saved_sub = '%sT00:00:00.000000Z' % ((datetime.now(utc)).strftime("%Y-%m-%d"))
        else:
            subscription_id_num = 0
            save_state = False
            statefile = os.path.join(self.output_dir, self.subscription_id_list[subscription_id_num], '.activity_log_state')

        if self.date_range:
            self.logger.debug(f'Date Range exists {self.date_start} - {self.date_end}')
            self.date_start  = self.date_start + 'T00:00:00.000000Z'
            self.date_end  = self.date_end + 'T00:00:00.000000Z'
            subscription_id_num = 0
            statefile = os.path.join(self.output_dir, self.subscription_id_list[subscription_id_num], '.activity_log_state')


        for i in range(subscription_id_num, len(self.subscription_id_list)):
            with open(sub_statefile, 'w') as f:
                f.write(f'{i}')
            try:
                if save_state:
                    self.logger.debug(f'Using Saved State {start_time_saved_sub} - {end_time_saved_sub}')
                    await self.auxillary_activity_log(start_time_saved_sub, end_time_saved_sub, i, statefile)
                    save_state = False
                elif self.date_range:
                    self.logger.debug(f'Using Date Range {self.date_start} - {self.date_end}')
                    await self.auxillary_activity_log(self.date_start, self.date_end, i, statefile)
                else:
                    self.logger.debug(f'No state. Using {start_date} - {final_time}')
                    await self.auxillary_activity_log(start_date, final_time, i, statefile)

            except HttpResponseError as e:
                print(e)
                self.logger.debug("Caught HTTP Response Error on subscription " + self.subscription_id_list[i])
                continue

    async def auxillary_storage_log_pull(self, container_name, log_type):
        for i in range(0, len(self.subscription_id_list)):
            try:
                sub_id = self.subscription_id_list[i]
                storage_client = self.storage_clients[i]

                output_dir =  os.path.join(self.output_dir, sub_id, log_type + "_logs/")
                check_output_dir(output_dir, self.logger)

                self.logger.info("Dumping " + log_type + " logs from blob storage...")
                storage_accounts = []
                for element in storage_client.storage_accounts.list():
                    storage_accounts.append(element.as_dict()['name'])

                for account in storage_accounts:

                    if self.us_gov.lower() == "true":
                        url = "https://" + account + "blob.core.usgovcloudapi.net/"
                        blob_service_client = BlobServiceClient(account_url=url, credential=self.credential)
                    else:
                        url = "https://" + account + ".blob.core.windows.net/"
                        blob_service_client = BlobServiceClient(account_url=url, credential=self.credential)
                    try:
                        container_client = blob_service_client.get_container_client(container=container_name)
                        counter = 0
                        start_date = utc.localize((datetime.now() - timedelta(days=90)))
                        end_date = utc.localize(datetime.now())
                        if self.date_range:
                            start_date = dateutil.parser.parse(self.date_start)
                            end_date = dateutil.parser.parse(self.date_end)
                        for blob in container_client.list_blobs():
                            if start_date <= blob.last_modified and blob.last_modified <= end_date:
                                downloader = container_client.download_blob(blob)
                                output = os.path.join(output_dir, "log_" + str(counter) + ".json")
                                if log_type == "nsg_flow":
                                    data = json.loads(downloader.readall().decode(("utf-8")))
                                    with open(output, 'a+', encoding='utf-8') as f:
                                        for record in data['records']:
                                            f.write(json.dumps(record))
                                            f.write("\n")
                                else:
                                    data = downloader.readall().decode(("utf-8"))
                                    lines = data.split("\n")
                                    with open(output, 'a+', encoding='utf-8') as f:
                                        for entry in lines:
                                            f.write(entry)
                                counter+=1


                    except HttpResponseError as e:
                        self.logger.debug(log_type + " log not present in " + account + " continuing.")
                        await asyncio.sleep(0) # make it blocking so that other coroutines can continue
                        continue
                    await asyncio.sleep(0) # make it blocking so that other coroutines can continue
                    self.logger.info("Finished dumping " + log_type + " logs from blob storage.")

            except HttpResponseError as e:
                self.logger.debug("Caught HTTP Response Error on subscription " + sub_id)
                continue

    async def dump_key_vault_log(self):
        """
        Dump insights audit events for key_vault
        """
        await self.auxillary_storage_log_pull("insights-logs-auditevent", "key_vault")

    async def dump_nsg_flow_logs(self):
        """
        Dump insights network security group flow events
        """
        await self.auxillary_storage_log_pull("insights-logs-networksecuritygroupflowevent", "nsg_flow")

    async def dump_bastion_logs(self):
        """
        Dump insights bastion audit logs
        """
        await self.auxillary_storage_log_pull("insights-logs-bastionauditlogs", "bastion")

    async def auxillary_list_all(self, func, sub_id, ops, args: Optional[str] = None) -> None:
        try:
            name = str(func.__class__)
            name = name.strip("\'<>").split(".")[-1]
            if 'Operations' in name:
                name = name.replace('Operations', "")

            config_dir = os.path.join(self.output_dir, sub_id, 'azure_configs')
            check_output_dir(config_dir, self.logger)
            output = os.path.join(config_dir, name + ".json")

            if os.path.exists(output):
                    self.logger.debug(name + " file exists.. Proceeding without pulling.")
            else:
                self.logger.info("Dumping Azure " + name + "...")
                if args:
                    func = getattr(func, ops)(scope=args)
                elif not args:
                    func = getattr(func, ops)()

                for element in func:
                    if element:
                        with open(output, 'a+', encoding='utf-8') as f:
                            f.write(json.dumps(element.as_dict()))
                            f.write("\n")
                            f.flush()
                            os.fsync(f)

                self.logger.info("Finished dumping Azure " + name)
        except HttpResponseError as e:
            self.logger.debug("Caught HTTP Response Error on subscription " + sub_id + " for " + name)
            self.logger.debug('Error: {}'.format(str(e)))

    async def dump_configs(self) -> None:
        """
        Dump Azure configuration information
        """
        for i in range(0, len(self.subscription_id_list)):
            sub_id = self.subscription_id_list[i]
            security_client = self.security_clients[i]
            network_manager = self.network_managers[i]
            scope = "/subscriptions/" + sub_id
            if self.us_gov.lower() == "false":
                await asyncio.gather(
                    self.auxillary_list_all(security_client.settings, sub_id, "list"),
                    self.auxillary_list_all(security_client.security_solutions, sub_id, "list")
                )

            await asyncio.gather(
                self.auxillary_list_all(security_client.alerts, sub_id, "list"),
                self.auxillary_list_all(security_client.allowed_connections, sub_id, "list"),
                self.auxillary_list_all(security_client.applications, sub_id, "list"),
                self.auxillary_list_all(security_client.assessments, sub_id, "list", scope),
                self.auxillary_list_all(security_client.auto_provisioning_settings, sub_id, "list"),
                self.auxillary_list_all(security_client.automations, sub_id, "list"),
                self.auxillary_list_all(security_client.compliance_results, sub_id, "list", scope),
                self.auxillary_list_all(security_client.compliances, sub_id, "list", scope),
                self.auxillary_list_all(security_client.discovered_security_solutions, sub_id, "list"),
                self.auxillary_list_all(security_client.external_security_solutions, sub_id, "list"),
                self.auxillary_list_all(security_client.governance_rules, sub_id, "list", scope),
                self.auxillary_list_all(security_client.information_protection_policies, sub_id, "list", scope),
                self.auxillary_list_all(security_client.jit_network_access_policies, sub_id, "list"),
                self.auxillary_list_all(security_client.locations, sub_id, "list"),
                self.auxillary_list_all(security_client.secure_score_controls, sub_id, "list"),
                self.auxillary_list_all(security_client.secure_scores, sub_id, "list"),
                self.auxillary_list_all(security_client.security_contacts, sub_id, "list"),
                self.auxillary_list_all(security_client.sub_assessments, sub_id, "list_all", scope),
                self.auxillary_list_all(security_client.tasks, sub_id, "list"),
                self.auxillary_list_all(security_client.topology, sub_id, "list"),
                self.auxillary_list_all(security_client.workspace_settings, sub_id, "list"),
                self.auxillary_list_all(network_manager.application_gateways, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.application_security_groups, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.azure_firewall_fqdn_tags, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.azure_firewalls, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.bastion_hosts, sub_id, "list"),
                self.auxillary_list_all(network_manager.custom_ip_prefixes, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.ddos_protection_plans, sub_id, "list"),
                self.auxillary_list_all(network_manager.dscp_configuration, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.express_route_circuits, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.express_route_ports, sub_id, "list"),
                self.auxillary_list_all(network_manager.firewall_policies, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.ip_allocations, sub_id, "list"),
                self.auxillary_list_all(network_manager.ip_groups, sub_id, "list"),
                self.auxillary_list_all(network_manager.load_balancers, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.nat_gateways, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.network_interfaces, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.network_managers, sub_id, "list_by_subscription"),
                self.auxillary_list_all(network_manager.network_profiles, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.network_security_groups, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.network_security_perimeters, sub_id, "list_by_subscription"),
                self.auxillary_list_all(network_manager.network_virtual_appliances, sub_id, "list"),
                self.auxillary_list_all(network_manager.network_watchers, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.p2_svpn_gateways, sub_id, "list"),
                self.auxillary_list_all(network_manager.private_endpoints, sub_id, "list_by_subscription"),
                self.auxillary_list_all(network_manager.private_link_services, sub_id, "list_by_subscription"),
                self.auxillary_list_all(network_manager.public_ip_addresses, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.public_ip_prefixes, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.route_filters, sub_id, "list"),
                self.auxillary_list_all(network_manager.route_tables, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.security_partner_providers, sub_id, "list"),
                self.auxillary_list_all(network_manager.service_endpoint_policies, sub_id, "list"),
                self.auxillary_list_all(network_manager.subscription_network_manager_connections, sub_id, "list"),
                self.auxillary_list_all(network_manager.virtual_hubs, sub_id, "list"),
                self.auxillary_list_all(network_manager.virtual_network_taps, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.virtual_networks, sub_id, "list_all"),
                self.auxillary_list_all(network_manager.virtual_routers, sub_id, "list"),
                self.auxillary_list_all(network_manager.virtual_wans, sub_id, "list"),
                self.auxillary_list_all(network_manager.vpn_gateways, sub_id, "list"),
                self.auxillary_list_all(network_manager.vpn_server_configurations, sub_id, "list"),
                self.auxillary_list_all(network_manager.vpn_sites, sub_id, "list"),
                self.auxillary_list_all(network_manager.web_application_firewall_policies, sub_id, "list_all")
            )

            await asyncio.gather(
                self._dump_container_config(),
                self._dump_vm_config(),
                self._dump_all_resources(),
                self._dump_diagnostic_settings(),
                self._dump_file_shares(),
                self._dump_storage_accounts()
            )
