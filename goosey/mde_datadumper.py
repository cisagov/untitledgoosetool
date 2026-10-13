#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: mde_datadumper!
This module has all the telemetry pulls for MDE.
"""

from datetime import datetime, timedelta
import itertools
from goosey.auth import check_app_auth_token
from goosey.datadumper import DataDumper
from goosey.utils import *
import pytz

utc=pytz.UTC

end_29_days_ago = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=29)
today_date = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)

class MDEDataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, app_auth, app_auth2, app_auth3, app_auth4, session, config, debug):
        super().__init__(f'{output_dir}{os.path.sep}mde', reports_dir, app_auth, session, debug)
        self.app_auth2 = app_auth2
        self.app_auth3 = app_auth3
        self.app_auth4 = app_auth4
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        self.logger = setup_logger(__name__, debug)
        self.gcc = config_get(config, 'config', 'gcc', self.logger).lower() == "true"
        self.gcc_high = config_get(config, 'config', 'gcc_high', self.logger).lower() == "true"
        self.endpoints = get_endpoints(gcc=self.gcc, gcc_high=self.gcc_high)
        self.mde_url = self.endpoints["securitycenter_api"] + "/"
        self.identity_url = self.endpoints["security_api"]
        self.call_object = [self.mde_url, self.app_auth, self.logger, self.output_dir, self.get_session()]
        self.graph_call_object = [self.endpoints["graph_api"] + "/v1.0/", self.app_auth3, self.logger, self.output_dir, self.get_session()]
        self.mde_THRESHOLD = int(config_get(config, 'variables', 'mde_threshold'))
        self.mde_query_mode = config_get(config, 'variables', 'mde_query_mode')
        filters = config_get(config, 'filters', 'date_start', logger=self.logger)
        self.logger.debug(f"Filters are {filters}")
        if filters != '' and  filters is not None:
            self.date_range=True
            self.date_start = config['filters']['date_start']
            if config['filters']['date_end'] != '':
                self.date_end = config['filters']['date_end']
            else:
                self.date_end = datetime.now().strftime("%Y-%m-%d")
        else:
            self.date_range=False

    def get_url(self):
        if self.mde_gcc == "true":
            return "https://api-gcc.securitycenter.microsoft.us"
        elif self.mde_gcc_high == "true":
            return "https://api-gov.securitycenter.microsoft.us"
        else:
            return "https://api.securitycenter.windows.com/"

    async def dump_machines(self) -> None:
        """
        Dump machines with mde
        """
        await helper_single_object("api/machines", self.call_object, self.failurefile)

    async def dump_alerts(self) -> None:
        """
        Dump alerts
        """
        await helper_single_object("api/alerts", self.call_object, self.failurefile)

    async def dump_indicators(self) -> None:
        """
        Dump indicators
        """
        await helper_single_object("api/indicators", self.call_object, self.failurefile)

    async def dump_investigations(self) -> None:
        """
        Dump investigations
        """
        await helper_single_object("api/investigations", self.call_object, self.failurefile)

    async def dump_library_files(self) -> None:
        """
        Dump library files
        """
        await helper_single_object("api/libraryfiles", self.call_object, self.failurefile)

    async def dump_machine_vulns(self) -> None:
        """
        Dump known machine vulnerabilities
        """
        await helper_single_object("api/vulnerabilities/machinesVulnerabilities", self.call_object, self.failurefile)

    async def dump_software(self) -> None:
        """
        Dump known installed software
        """
        await helper_single_object("api/Software", self.call_object, self.failurefile)

    async def dump_recommendations(self) -> None:
        """
        Dump mde recommendations
        """
        await helper_single_object("api/recommendations", self.call_object, self.failurefile)

    async def dump_incidents(self) -> None:
        """Dump microsoft defender incidents
        https://learn.microsoft.com/en-us/graph/api/security-list-incidents
        """
        await helper_single_object("security/incidents?$expand=alerts", self.graph_call_object, self.failurefile)

    async def dump_cloudappactivity(self) -> None:
        """Dump microsoft defender for cloud app activity
        https://learn.microsoft.com/en-us/defender-cloud-apps/api-activities-list
        """
        caa_output_dir = os.path.join(self.output_dir, "cloud_app_activity")
        statefile = os.path.join(caa_output_dir, ".caa_savestate")
        check_output_dir(caa_output_dir, self.logger)
        app_auth = self.app_auth4
        err = None
        header = {
            'Authorization': '%s %s' % (app_auth['token_type'], app_auth['access_token']),
            'Content-Type': 'application/json'
        }
        url = self.endpoints["cloudapp_defender"] + "/api/v1/archived_activities/"
        unique_ids = set()

        # default end time. Now
        default_end = utc.localize(datetime.now())

        # defult start tiem
        default_start = (default_end - timedelta(days=364))

        if self.date_range:
            default_start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            default_end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        saved_end = load_state(statefile)
        if saved_end:
            default_start = saved_end
        # Filters need to be in epoch time
        start = default_start.timestamp() * 1000
        last_date = start
        end = default_end.timestamp() * 1000
        self.logger.debug(f"Dumping cloud app activity logs from {default_start} to {default_end}")
        # Total Count is not accurate. Changes on each pull. Is more of an estimate
        tries = 0
        retries = 3
        while last_date < end and tries < retries and err == None:
            total_count = 0
            skip = 0
            has_data = True
            start = last_date
            while has_data and tries < retries:
                data = json.dumps({"skip": skip, "sortField": "date", "sortDirection": "asc", "filters": {"date": {"range": [{"start": start, "end": end}]}}})
                async with self.ahsession.request("POST", url=url, headers=header, data=data) as r:
                    result = await r.json()
                    if r.status == 401:
                        self.logger.error("Detected 401 unauthorized, exiting.")
                        sys.exit(1)
                    elif r.status == 403:
                        err = "Insufficient role based permissions"
                        self.logger.error(err)
                        return err
                    elif r.status == 429:
                        error = result['error']
                        message = error['message']
                        seconds = message.split(' ')[-2]
                        self.logger.debug("Sleeping for %s seconds" % (seconds))
                        await asyncio.sleep(int(seconds))
                        err = message
                        tries += 1
                        result = None
                    elif r.status == 200:
                        tries = 0
                        has_data = result["hasNext"]
                        skip += len(result["data"])
                        total_count = max(total_count, result["total"])
                        first_date = 0
                        if len(result["data"]) > 0:
                            first_date = result["data"][0]["timestamp"]
                            last_date = result["data"][0]["timestamp"]
                        for log in result["data"]:
                            if log["timestamp"] < first_date:
                                first_date = log["timestamp"]
                            if log["timestamp"] > last_date:
                                last_date = log["timestamp"]
                            unique_ids.add(log["_id"])
                        self.logger.debug(f"Total pulled {skip}/{total_count}")
                        #self.logger.debug(f"Unique Count {len(unique_ids)}")
                        output_file = os.path.join(caa_output_dir, f"cloudappactivity_{first_date}-{last_date}.json")
                        with open(output_file, 'a', encoding='utf-8') as f:
                            for x in result["data"]:
                                f.write(json.dumps(x) + '\n')
                        if len(result["data"]) > 0:
                            last_date += 1000
                            save_state(statefile, datetime.fromtimestamp(last_date/1000))
                    else:
                        print(r.status)
                        if "error" in result:
                            err = result["error"]["message"]
                            self.logger.error(err)
                        else:
                            print(type(result))
                            self.logger.debug(result)
            if total_count == 0:
                break
        if tries >= retries:
            return err

    async def check_machines(self):
        check_app_auth_token(self.app_auth, self.logger)
        outfile = os.path.join(self.output_dir, 'api_machines.json')
        data = []
        if os.path.exists(outfile):
            with open(outfile, 'r') as f:
                for line in f:
                    data.append(json.loads(line))
        else:
            await helper_single_object('api/machines', self.call_object)
            with open(outfile, 'r') as f:
                for line in f:
                    data.append(json.loads(line))
        return data

    async def _dump_mde_tables_helper(self, tables=[]) -> None:
        """
        Helper Function for dumping mde tables
        """

        # default end time. Now
        default_end = utc.localize(datetime.now())

        # defult start tiem
        default_start = default_end - timedelta(days=364)

        if self.date_range:
            self.logger.debug(f'MDE Dump using specified date range: {self.date_start} to {self.date_end}')
            default_start = utc.localize(datetime.strptime(self.date_start,"%Y-%m-%d"))
            default_end = utc.localize(datetime.strptime(self.date_end,"%Y-%m-%d"))

        tasks = []
        for table in tables:
            start = default_start
            end = default_end
            # Set the output directory for the mde table logs
            mde_log_dir = os.path.join(self.output_dir, table)
            base_query = table

            check_output_dir(mde_log_dir, self.logger)

            statefile = os.path.join(mde_log_dir, f".{table}.savestate")
            outfile_start = os.path.join(mde_log_dir, f"{table}_")
            saved_end = load_state(statefile)
            if saved_end:
                start = max(saved_end, start)
            # Use asyncio to use asyncronous coroutines to help ensure we get data before it rolls off
            self.logger.debug(f"Generating table dump task for table: {table}, start: {start}, end: {end}")
            caller_name = asyncio.current_task().get_name()
            tasks.append(asyncio.create_task(self._dump_table(base_query, start, end, statefile=statefile, outfile_start=outfile_start), name=f"{caller_name}_{table}"))

        await asyncio.gather(*tasks)

    async def dump_advanced_hunting_alerts(self) -> None:
        """Dumps the results from alerts and alert evidence tables.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """

        tables = ['AlertInfo', 'AlertEvidence']
        await self._dump_mde_tables_helper(tables=tables)

    async def dump_advanced_hunting_devices(self) -> None:
        """Dumps the results from microsoft defender for endpoint tables.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """

        tables = ['DeviceEvents', 'DeviceFileCertificateInfo', 'DeviceLogonEvents', 'DeviceRegistryEvents', 'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents', 'DeviceImageLoadEvents', 'DeviceInfo', 'DeviceNetworkInfo']
        await self._dump_mde_tables_helper(tables=tables)

    async def dump_advanced_hunting_identity(self) -> None:
        """Dumps the results from microsoft defender for identity tables.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """

        tables = ['IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents', 'IdentityInfo', 'AADSignInEventsBeta', 'AADSpnSignInEventsBeta']
        await self._dump_mde_tables_helper(tables=tables)

    async def dump_advanced_hunting_cloud_apps(self) -> None:
        """Dumps the results from microsoft defender for cloud apps tables.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = ['CloudAppEvents', 'CloudAuditEvents', 'CloudProcessEvents', 'BehaviorEntities', 'BehaviorInfo']
        await self._dump_mde_tables_helper(tables=tables)

    async def dump_advanced_hunting_email_url(self) -> None:
        """Dumps the results from microsoft xdr email and url click event tables.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = ['EmailAttachmentInfo', 'EmailEvents', 'EmailPostDeliveryEvents', 'EmailUrlInfo', 'UrlClickEvents']
        await self._dump_mde_tables_helper(tables=tables)

    async def dump_advanced_vulnerability_management(self) -> None:
        """Dumps the results from microsoft defender vulnerability management tables.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = ['DeviceBaselineComplianceAssessment', 'DeviceBaselineComplianceAssessmentKB', 'DeviceBaselineComplianceProfiles', 'DeviceTvmBrowserExtensions', 'DeviceTvmBrowserExtensionsKB', 'DeviceTvmCertificateInfo', 'DeviceTvmHardwareFirmware', 'DeviceTvmInfoGathering', 'DeviceTvmInfoGatheringKB', 'DeviceTvmSecureConfigurationAssessment', 'DeviceTvmSecureConfigurationAssessmentKB', 'DeviceTvmSoftwareEvidenceBeta', 'DeviceTvmSoftwareInventory', 'DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSoftwareVulnerabilitiesKB']
        await self._dump_mde_tables_helper(tables=tables)

    async def dump_advanced_hunting_exposure(self) -> None:
        """Dumps the results from microsoft security exposure management.
        API Reference: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables
        """
        tables = ['ExposureGraphEdges', 'ExposureGraphNodes']
        await self._dump_mde_tables_helper(tables=tables)

    async def run_mde_query(self, query, start, end, bounds, summarize=False):
        """
        Run an advanced query or hunt and return the result
        """

        # errors from the query that will cause the dumper to sleep
        sleep_errors = ["Server disconnected", "Cannot connect", "WinError 10054"]
        # errors from the query that will cause the dumper to cut the tim in half
        slice_errors = ['exceeded the allowed limits', 'exceeded the allowed result size']

        app_auth = self.app_auth3
        header = {
            'Authorization': '%s %s' % (app_auth['token_type'], app_auth['access_token']),
            'Content-Type': 'application/json'
        }
        # Apply time filters
        full_query = query

        if start and not end:
            full_query += f"|where Timestamp > datetime({start})"
        elif end and not start:
            full_query += f"|where Timestamp < datetime({end})"
        elif end and start:
            full_query += f"|where Timestamp between(datetime({start})..datetime({end}))"

        if summarize:
            full_query += f"| summarize Count=count(), FirstEvent=min(Timestamp), LastEvent=max(Timestamp)"

        self.logger.debug(full_query)
        payload = {"Query": full_query}
        data=json.dumps(payload)
        splits = full_query.split('|where Timestamp')
        result = None
        err = None
        url = self.endpoints["graph_api"] + "/v1.0/security/runHuntingQuery"
        try:
            async with self.ahsession.request("POST", url=url, headers=header, data=data) as r:
                result = await r.json()
                #self.logger.debug(r.status)
                #self.logger.debug(result)
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
                    result = None
                else:
                    if "error" in result:
                        err = result["error"]["message"]
                    if "results" in result:
                        result = result["results"]
                    else:
                        result = None

        except Exception as e:
            self.logger.error('Error on retrieval: {}'.format(str(e)))
            err = str(e)

        # Insert a new record into the bounds.
        count = None
        done_status = False
        if summarize and result:
            count = result[0]["Count"]
        elif result:
            count = len(result)
        if count != None:
            done_status = count < self.mde_THRESHOLD
        bounds = self._insert_mde_record({"count": count,
                  "start": start,
                  "end": end,
                  "done_status": done_status}, bounds)

        # Checking errors and if the time should be cut
        if err:
            self.logger.debug(err)
        if err is TimeoutError or \
           err and any(e in err for e in slice_errors) or \
           (count and count >= self.mde_THRESHOLD):
           new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
           end = datetime.fromtimestamp(new_end_ts, utc)
        elif err and any(e in err for e in sleep_errors):
            await asyncio.sleep(int(60))

        return result, err, end, bounds


    def _insert_mde_record(self, record, bounds):
        """
        Description:
            Add a record to the sorted  bounds_state.

        Arguments:
            record: Tuple of (start, end, count, done_status)
            bounds: Time Bounds Dictionary

        Returns:
            bounds. The updated time bounds dictionary
        """
        # Perform insert
        #self.logger.debug(f"Inserting Record {record}")

        if len(bounds) == 0:
            bounds.append(record)
            return bounds
        done_idx = 0
        for idx, cur_record in enumerate(bounds):
            # Only situation for an insert here should be where a record already exists with that start
            # time and we just shrink the bounds
            if record["start"] == cur_record["start"] and record["end"] <= cur_record["end"]:
                cur_record["start"] = record["end"]
                # if the count is less than 0 then it is not accurate
                if cur_record["count"] != None and cur_record["count"] >= 0 \
                   and record["count"] != None and record["count"] > 0:
                    cur_record["count"] = max(0,cur_record["count"] - record["count"])

                new_records = [record.copy(), cur_record.copy()]
                if (cur_record["count"] != None and cur_record["count"] == 0) or cur_record["start"] == cur_record["end"]:
                    record["end"] = cur_record["end"]
                    new_records = [record.copy()]
                bounds = bounds[done_idx:idx] + new_records + bounds[idx+1:]
                #self.logger.debug(f"Record inserted at index {idx}")
                break
        idx = 0
        while idx < len(bounds):
            if bounds[idx]["done_status"] == False:
                break
            idx += 1
        return bounds[idx:]



    async def _dump_table(self, base_query, start, end, statefile, outfile_start, retries=3):
        """
        Description:
            Query the mde table and pull logs for the timeframe

        Arguments:
            base_query: what to start with for the query
            start: starting timestamp
            end: ending timestamp
            stattefile: Path to the statefile
            outfile_start: where to place the logs
            retries: number of retries to attempt when there's an error
        """
        totalResultCount = 0
        totalResultEnd = start
        totalSavedResults = 0
        origStart = start
        finalEnd = end
        tries = 0
        # final record is so that it will stop when it gets to the last record
        # and we don't have to worry about the list being empty or changing the logic for
        # an edge case
        final_record = {"count": None,
                        "start": end,
                        "end": end + timedelta(1000),
                        "done_status": False}
        bounds = [final_record]
        # initial query loop to set a baseline
        summary = None
        while start < finalEnd and tries < retries*2:
            # Narrow down until we have a valid timeframe
            summary, err, new_end, bounds = await self.run_mde_query(base_query, start, end, bounds, summarize=True)
            # If there are no results then we want to get to a timeframe that does contain results
            if err:
                tries += 1
            elif summary != None and summary[0]["Count"] == 0:
                tries = 0
                # Check if there are no results in the whole time range. If so we return
                if origStart == start and finalEnd == end:
                    self.logger.debug(f"No logs for {base_query} from {start} to {end}")
                    save_state(statefile, end)
                    return
                # Otherwise it just means this lower time segment has no logs and we remove it and continue
                start = end
                end = finalEnd
                bounds = [final_record]
                continue
            elif summary != None and summary[0]["Count"] > 0:
                tries = 0
                totalResultCount = summary[0]["Count"]
                totalResultEnd = end
                start = dateutil.parser.parse(summary[0]["FirstEvent"])
                # Need to make sure the start of each entry in the bounds matches the first start time
                bounds[0]["start"] = start
                break
            end = new_end


        while start < finalEnd and tries < retries:
            startDate = start.strftime("%Y-%m-%dT%H:%M:%S")
            endDate = end.strftime("%Y-%m-%dT%H:%M:%S")
            session_set = set() # Unique results returned. Used to detect duplicates
            bound = f'[{startDate} - {endDate}]'

            # Run a search to get a summary of the timeframe. Faster and provides more info
            if bounds[0]["count"] == None or \
               (bounds[0]["count"] >= self.mde_THRESHOLD and end <= bounds[0]["end"]):
                summary, err, end, bounds = await self.run_mde_query(base_query, start, end, bounds,  summarize=True)
                if err:
                    tries += 1
                    continue
                tries = 0
                if summary[0]["Count"] >= self.mde_THRESHOLD:
                    continue
                if summary[0]["Count"] == 0:
                    end = bounds[0]["end"]
                    start = bounds[0]["start"]
                    continue

            results, err, end, bounds = await self.run_mde_query(base_query, start, end, bounds)
            if err:
                tries += 1
                continue
            if len(results) >= 0:
                if start >= totalResultEnd:
                    totalResultCount += len(results)
                self.logger.debug('Size of table: %s' % len(results))
                #self.logger.debug('Size of table: %s' % result['Stats']['dataset_statistics'][0]['table_row_count'])
                session_filename = outfile_start + f"{startDate}_{endDate}.json".replace(":", "_")
                with open(session_filename, 'a', encoding='utf-8') as f:
                    for x in results:
                        f.write(json.dumps(x) + '\n')

                save_state(statefile, end)

                tries = 0
                end = bounds[0]["end"]
                start = bounds[0]["start"]
                if bounds[0]["count"] != None and bounds[0]["count"] >= self.mde_THRESHOLD:
                    new_end_ts = start.timestamp() + ((end.timestamp() - start.timestamp())/2)
                    end = datetime.fromtimestamp(new_end_ts, utc)

                totalSavedResults += len(results)
                self.logger.debug(f"Total results {totalSavedResults}/{totalResultCount}")
                continue
