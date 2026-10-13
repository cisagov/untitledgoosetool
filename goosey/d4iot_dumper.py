#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: d4iot_dumper!
This module has all the telemetry pulls for Defender for IoT.
"""
import getpass
import json
import os

from goosey.datadumper import DataDumper
from goosey.utils import *

class DefenderIoTDumper(DataDumper):
    def __init__(self, output_dir, reports_dir, session, csrftoken, sessionid, config, auth_un_pw, debug):
        super().__init__(f'{output_dir}{os.path.sep}d4iot', reports_dir, csrftoken, sessionid, session, debug)
        self.logger = setup_logger(__name__, debug)
        if auth_un_pw is not None:
            if auth_un_pw['auth']['d4iot_sensor_token']:
                self.sensor_token = auth_un_pw['auth']['d4iot_sensor_token']
            else:
                self.sensor_token = getpass.getpass("Please type your D4IOT sensor token. If you don't have a D4IOT sensor, you can leave it blank (hit Enter to continue): ")
            if auth_un_pw['auth']['d4iot_mgmt_token']:
                self.mgmt_token = auth_un_pw['auth']['d4iot_mgmt_token']
            else:
                self.mgmt_token = getpass.getpass("Please type your D4IOT management console token. If you don't have a D4IOT management console, you can leave it blank (hit Enter to continue): ")
        else:
            self.sensor_token = getpass.getpass("Please type your D4IOT sensor token. If you don't have a D4IOT sensor, you can leave it blank (hit Enter to continue): ")
            self.mgmt_token = getpass.getpass("Please type your D4IOT management console token. If you don't have a D4IOT management console, you can leave it blank (hit Enter to continue): ")

        self.sensor_ip = config_get(config, 'config', 'd4iot_sensor_ip', self.logger)
        self.mgmt_ip = config_get(config, 'config', 'd4iot_mgmt_ip', self.logger)

        self.csrftoken = csrftoken
        self.sessionid = sessionid

    async def helper_multiple_object_sensor(self, parent, child, identifier='id'):
        if not self.csrftoken or not self.sessionid:
            self.logger.error(f"Missing csrftoken and sessionid from auth. Did you auth correctly?")
            return

        base_url = "https://" + str(self.sensor_ip)
        parent_url = base_url + parent
        parent_header = {'Authorization': '%s' % (self.sensor_token)}

        self.logger.info('Dumping alert information...')
        parent_list = []
        async with self.ahsession.request('GET', parent_url, headers=parent_header, ssl=False) as r:
            result = await r.json()
            if not result:
                self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                return

            for entry in result:
                parent_list.append(entry[identifier])

        child_header = {"Cookie": "csrftoken=" + self.csrftoken + "; sessionid=" + self.sessionid}
        outpath = os.path.join(self.output_dir, 'sensor_alert_pcaps')
        check_output_dir(outpath, self.logger)

        for id in parent_list:
            child_url = base_url + child + str(id)
            outfile = os.path.join(outpath, "alert_" + str(id) + ".pcap")

            async with self.ahsession.request('GET', child_url, headers=child_header, ssl=False, allow_redirects=True) as r:
                output = await r.read()
                with open(outfile, 'wb') as f:
                    f.write(output)

    async def helper_single_object_sensor(self, url, object) -> None:
        if not self.sensor_token:
            self.logger.error(f"Missing sensor api token. Acquire the token from the portal to proceed")
            return
        header = {'Authorization': '%s' % (self.sensor_token)}
        self.logger.info('Dumping %s information...' % (object))
        sensor_output_dir = os.path.join(self.output_dir, 'sensor')
        check_output_dir(sensor_output_dir, self.logger)

        async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
            result = await r.json()
            outfile = os.path.join(sensor_output_dir, object + '.json')

            if not result:
                self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                return
            if type(result) ==list:
                with open(outfile, 'w+', encoding='utf-8') as f:
                    for entry in result:
                        f.write(json.dumps(entry) + "\n")
            elif type(result) == dict:
                with open(outfile, 'w+', encoding='utf-8') as f:
                    f.write(json.dumps(result) + "\n")

        self.logger.info("Finished dumping %s information." % (object))

    async def dump_sensor_devices(self) -> None:
        """
        Dump sensor devices
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/devices"
        object = 'devices'
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_alerts(self) -> None:
        """
        Dump sensor alerts
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/alerts"
        object = 'alerts'
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_device_connections(self) -> None:
        """
        Collect all device connections
        https://learn.microsoft.com/en-us/azure/defender-for-iot/organizations/api/sensor-inventory-apis?tabs=connections-request%2Cconnections-device-request%2Ccves-request%2Ccves-ip-request%2Cdevices-request
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/devices/connections"
        object = 'device_connections'
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_device_cves(self) -> None:
        """
        Dummp sensor device known cves
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/devices/cves"
        object = 'devices_cves'
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_events(self) -> None:
        """
        Dump sensor events
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/events"
        object = 'events'
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_device_vuln(self) -> None:
        """
        Dump sensor device known vulnerabilities
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/reports/vulnerabilities/devices"
        object = 'device_vulnerabilities'
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_security_vuln(self) -> None:
        """
        Dump sensor security vulnerabilities
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/reports/vulnerabilities/security"
        object = "security_vulnerabilities"
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_operational_vuln(self) -> None:
        """
        Dump sensor operation vulnerabilities
        """
        url = "https://" + str(self.sensor_ip) + "/api/v1/reports/vulnerabilities/operational"
        object = 'operational_vulnerabilities'
        await self.helper_single_object_sensor(url, object)

    async def dump_sensor_pcap(self) -> None:
        """
        Dump sensor pcap
        """
        parent = "/api/v1/alerts"
        child = "/api/alert/filtered-pcap/"
        await self.helper_multiple_object_sensor(parent, child)


    async def helper_single_object_mgmt(self, url, object) -> None:
        if not self.mgmt_token:
            self.logger.error(f"Missing management console api token. Acquire the token from the portal to proceed")
            return
        header = {'Authorization': '%s' % (self.mgmt_token)}
        mgmt_output_dir = os.path.join(self.output_dir, 'mgmt_console')
        check_output_dir(mgmt_output_dir, self.logger)
        self.logger.info('Dumping %s from the management console...' % (object))
        async with self.ahsession.request('GET', url, headers=header, ssl=False) as r:
            result = await r.json()

            if not result:
                self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                return

            outfile = os.path.join(mgmt_output_dir, object + '.json')
            with open(outfile, 'w+', encoding='utf-8') as f:
                for entry in result:
                    f.write(json.dumps(entry) + "\n")

    async def dump_mgmt_devices(self) -> None:
        """
        Dump management devices
        """
        url = "https://" + self.mgmt_ip + "/external/v1/devices"
        object = "mgmt_devices"
        await self.helper_single_object_mgmt(url,object)

    async def dump_mgmt_alerts(self) -> None:
        """
        Dump management alerts
        """
        url = "https://" + self.mgmt_ip + "/external/v1/alerts"
        object = "mgmt_alerts"
        await self.helper_single_object_mgmt(url,object)

    async def dump_mgmt_sensor_info(self) -> None:
        """
        Dump management sensor information
        """
        url = "https://" + self.mgmt_ip + "/external/v3/integration/sensors"
        object = "sensor_info"
        await self.helper_single_object_mgmt(url,object)

    async def dump_mgmt_pcap(self) -> None:
        """
        Dump management sensor pcap captured
        """
        parent = "v1/alerts"
        child = 'v2/alerts/pcap'
        await self.helper_multiple_object_mgmt(parent,child)


    async def helper_multiple_object_mgmt(self, parent, child,identifier='id'):
        url_parent ="https://" + self.mgmt_ip + "/external/"

        if not self.mgmt_token:
            self.logger.error(f"Missing management console api token. Acquire the token from the portal to proceed")
            return
        parent_list = []
        header = {'Authorization': '%s' % (self.mgmt_token)}
        parent_url = url_parent + parent
        outpath = os.path.join(self.output_dir, 'mgmt_console_alert_pcaps')
        check_output_dir(outpath, self.logger)

        async with self.ahsession.request('GET', parent_url, headers=header, ssl=False) as r:
            result = await r.json()
            if not result:
                self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                return

            for entry in result:
                parent_list.append(entry[identifier])

        self.logger.info('Dumping %s %s information...' % (parent, child))
        for parent_id in parent_list:
            url2 = url_parent + child + "/" + str(parent_id)
            async with self.ahsession.request('GET', url2, headers=header, ssl=False) as r:
                result = await r.json()
                if not result or 'error' in result:
                    self.logger.debug("Error with result. Please check your auth: {}".format(str(result)))
                    return

                download_url = result['downloadUrl']
                token = result['token']

                outfile = os.path.join(outpath, "alert_" + str(parent_id) + ".pcap")
                pcap_token_header = {'Authorization': '%s' % (token)}
                splits = download_url.split('/')
                splits[2] = self.sensor_ip
                download_url_ip = "/".join(splits)
                async with self.ahsession.request('GET', download_url_ip, headers=pcap_token_header, ssl=False, allow_redirects=True) as r:
                    output = await r.read()
                    with open(outfile, 'wb') as f:
                        f.write(output)

        self.logger.info('Finished dumping %s %s information.' % (parent, child))
