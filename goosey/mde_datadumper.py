#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: mde_datadumper!
This module has all the telemetry pulls for MDE.
"""

from datetime import datetime, timedelta
from goosey.auth import check_app_auth_token
from goosey.datadumper import DataDumper
from goosey.utils import *

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

end_29_days_ago = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=29)
today_date = datetime.today().replace(hour=0, minute=0, second=0, microsecond=0)

class MDEDataDumper(DataDumper):

    def __init__(self, output_dir, reports_dir, auth, app_auth, app_auth2, session, config, debug):
        super().__init__(f'{output_dir}{os.path.sep}mde', reports_dir, auth, app_auth, session, debug)
        self.app_auth2 = app_auth2
        self.failurefile = os.path.join(reports_dir, '_no_results.json')
        self.logger = setup_logger(__name__, debug)
        self.us_government = config_get(config, 'config', 'us_government', self.logger).lower()
        self.mde_gcc = config_get(config, 'config', 'mde_gcc', self.logger).lower()
        self.mde_gcc_high = config_get(config, 'config', 'mde_gcc_high', self.logger).lower()        
        self.exo_us_government = config_get(config, 'config', 'exo_us_government', self.logger).lower()
        self.call_object = [self.get_url(), self.app_auth, self.logger, self.output_dir, self.get_session()]
    
    def get_url(self):
        if self.mde_gcc == "true":
            return "https://api-gcc.securitycenter.microsoft.us"
        elif self.mde_gcc_high == "true":
            return "https://api-gov.securitycenter.microsoft.us"
        else:
            return "https://api-us.securitycenter.windows.com/"
    
    def get_identity_url(self):
        if self.mde_gcc == "true":
            return "https://api-gcc.security.microsoft.us"
        elif self.mde_gcc_high == "true":
            return "https://api-gov.security.microsoft.us"
        else:
            return "https://api.security.microsoft.com/"

    async def dump_machines(self) -> None:
        await helper_single_object("api/machines", self.call_object, self.failurefile)

    async def dump_alerts(self) -> None:
        await helper_single_object("api/alerts", self.call_object, self.failurefile)

    async def dump_indicators(self) -> None:
        await helper_single_object("api/indicators", self.call_object, self.failurefile)

    async def dump_investigations(self) -> None:
        await helper_single_object("api/investigations", self.call_object, self.failurefile)

    async def dump_library_files(self) -> None:
        await helper_single_object("api/libraryfiles", self.call_object, self.failurefile)
    
    async def dump_machine_vulns(self) -> None:
        await helper_single_object("api/vulnerabilities/machinesVulnerabilities", self.call_object, self.failurefile)

    async def dump_software(self) -> None:
        await helper_single_object("api/Software", self.call_object, self.failurefile)

    async def dump_recommendations(self) -> None:
        await helper_single_object("api/recommendations", self.call_object, self.failurefile)
    
    
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

    async def dump_advanced_hunting_query(self) -> None:
        """Dumps the results from advanced hunting queries.
        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-api?view=o365-worldwide
        """
        data = await self.check_machines()

        machine_statefile = os.path.join(self.output_dir, '.machine_savestate')
        if os.path.isfile(machine_statefile):
            self.logger.debug(f'Machine save state file exists at {machine_statefile}')
            with open(machine_statefile, "r") as f:
                machine = f.readline().strip()
                i = machine
        else:
            self.logger.debug(f'Machine save state file does not exist at {machine_statefile}. Starting a full pull.')
            i = 0

        listOfIds = list(findkeys(data, 'id'))
        tables = ['DeviceEvents', 'DeviceLogonEvents', 'DeviceRegistryEvents', 'DeviceProcessEvents', 'DeviceNetworkEvents', 'DeviceFileEvents', 'DeviceImageLoadEvents']        

        for i in range(int(i),len(listOfIds)):
            machine_dir = os.path.join(self.output_dir,'Machine ' + str(listOfIds[i]))
            check_output_dir(machine_dir, self.logger)

            with open(machine_statefile, 'w') as f:
                f.write(f'{i}')

            table_statefile = os.path.join(machine_dir, '.table_savestate')
            if os.path.isfile(table_statefile):
                self.logger.debug(f'Table save state file exists at {table_statefile}')
                with open(table_statefile, "r") as f:
                    table_id = f.readline().strip()
                    j = table_id
            else:
                self.logger.debug(f'Table save state file does not exist at {table_statefile}. Starting a full pull.')
                j = 0  

            for j in range(int(j),len(tables)):
                with open(table_statefile, 'w') as f:
                    f.write(f'{j}')
                                
                payload = {"Query": tables[j] + " |where DeviceId=='" + listOfIds[i] + "'"}
 

                outfile = os.path.join(machine_dir, str(tables[j]) + ".json")
                boundsfile = os.path.join(machine_dir, str(tables[j]) + ".bounds")
                bounds_statefile = os.path.join(machine_dir, "." + str(tables[j]) + "_bounds_savestate")
                time_statefile = os.path.join(machine_dir, "." + str(tables[j]) + "_savestate")

                params = [self.get_url(), self.app_auth, self.logger, self.get_session(), payload, outfile, boundsfile, time_statefile, bounds_statefile]

                await self.post_single_object(object='api/advancedqueries/run', params=params, table_name=tables[j], guid=listOfIds[i])

                check_app_auth_token(self.app_auth, self.logger)

                self.logger.info('Finished dumping %s table for device %s.' % (tables[j], listOfIds[i]))             

            self.logger.debug(f'Removing table save state file: {table_statefile}.')
            os.remove(table_statefile)

            if len(os.listdir(machine_dir)) == 0:
                self.logger.info('No data found, removing %s directory.' %(listOfIds[i]))
                os.rmdir(machine_dir)        

    async def dump_advanced_identity_hunting_query(self) -> None:
        """Dumps the results from advanced hunting API queries.
        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-advanced-hunting?view=o365-worldwide
        """

        check_app_auth_token(self.app_auth2, self.logger)

        id_tables = ['IdentityDirectoryEvents', 'IdentityLogonEvents', 'IdentityQueryEvents']
        
        id_table_statefile = os.path.join(self.output_dir, '.id_table_savestate')
        if os.path.isfile(id_table_statefile):
            self.logger.debug(f'Identity table save state file exists at {id_table_statefile}')
            with open(id_table_statefile, "r") as f:
                id_table_id = f.readline().strip()
                j = id_table_id
        else:
            self.logger.debug(f'Identity table save state file does not exist at {id_table_statefile}. Starting a full pull.')
            j = 0

        for j in range(int(j),len(id_tables)):
            with open(id_table_statefile, 'w') as f:
                f.write(f'{j}')

            id_payload = {"Query": id_tables[j]}

            id_outfile = os.path.join(self.output_dir, str(id_tables[j]) + ".json")
            id_boundsfile = os.path.join(self.output_dir, str(id_tables[j]) + ".bounds")
            id_bounds_statefile = os.path.join(self.output_dir, "." + str(id_tables[j]) + "_bounds_savestate")
            id_time_statefile = os.path.join(self.output_dir, "." + str(id_tables[j]) + "_savestate")

            params = [self.get_identity_url(), self.app_auth2, self.logger, self.get_session(), id_payload, id_outfile, id_boundsfile, id_time_statefile, id_bounds_statefile]

            await self.post_single_object(object='api/advancedhunting/run', params=params, table_name=id_tables[j])

            check_app_auth_token(self.app_auth2, self.logger)

            self.logger.info('Finished dumping %s table.' % (id_tables[j]))         

    async def check_time_query(self, params, force_slice, splits, shift):
        _, _, logger, _, _, _ = params[0], params[1], params[2], params[3], params[4], params[5]

        if force_slice:
            slice=True

            splits_2 = splits[1].split('datetime(')

            end = splits_2[1].split(')')[0]
            end_date = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")

            start = splits_2[2].split(')')[0]
            start_date = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")

            if shift:
                slice=False

                shift_int = (start_date - end_date)
                end_date = start_date

                if (start_date + shift_int) > today_date:
                    start_date = today_date
                else:
                    start_date = start_date + shift_int
                    start_date = start_date.replace(microsecond=0)

                interval_slice = shift_int

                if interval_slice == timedelta(seconds=0):
                    interval_slice = timedelta(seconds=1)
        else:
            slice=False

            interval_slice = (today_date - end_29_days_ago)/2

            end_date = end_29_days_ago
            start_date = end_29_days_ago + interval_slice

        if slice:
            start_date = (start_date.timestamp() + ((end_date.timestamp() - start_date.timestamp())/2))
            start_date = datetime.fromtimestamp(start_date)
            start_date = start_date.replace(microsecond=0)

            interval_slice = (start_date - end_date)

            if interval_slice == timedelta(seconds=0):
                interval_slice = timedelta(seconds=1)         

        return end_date, start_date, interval_slice

    async def test_time_query(self, params, url, header, query, session, outfile, end_date, start_date, interval_slice, boundsfile, time_statefile):
        _, _, logger, _, _, _ = params[0], params[1], params[2], params[3], params[4], params[5]

        retries = 500
        while retries > 0:
            while end_date >= end_29_days_ago:
                if not (end_date == start_date):
                    params[4]['Query'] = query + "|where Timestamp between(datetime(%s)..datetime(%s))" % (str(end_date), str(start_date))
                    logger.debug(params[4]['Query'])
                    full_query = str(params[4]['Query'])
                    payload = {"Query": full_query}
                    data=json.dumps(payload)
                    splits = full_query.split('|where Timestamp')
                    try:
                        async with session.request("POST", url=url, headers=header, data=data) as r:
                            result = await r.json()
                            if r.status == 401:
                                logger.error("Detected 401 unauthorized, exiting.")
                                sys.exit(0)
                            if r.status == 429:
                                error = result['error']
                                message= error['message']
                                seconds = message.split(' ')[-2]
                                logger.debug("Sleeping for %s seconds" % (seconds))
                                await asyncio.sleep(int(seconds))
                                retries -= 1
                            if 'Results' in result:
                                    if result['Results']:
                                        with open(boundsfile, 'a', encoding='utf-8') as f:
                                            f.write(str(full_query) + "\n")
                                        with open(time_statefile, 'w') as f:
                                            f.write(str(full_query))
                                        end_date = start_date
                                        if (start_date + interval_slice) > today_date:
                                            if end_date > today_date:
                                                break
                                            else:
                                                start_date = today_date
                                        elif start_date == today_date:
                                            break
                                        else:
                                            start_date = start_date + interval_slice
                                            start_date = start_date.replace(microsecond=0)
                                            if start_date >= today_date:
                                                break
                                        logger.debug("Value of start_date after success: " + str(start_date))
                                        logger.debug("Value of end_date after success: " + str(end_date))
                                        break
                                    elif not result['Results']:
                                        if result['Stats']['dataset_statistics'][0]['table_size'] == 0:                                        
                                            logger.debug('%s has no information (size is 0). No output file.' % (outfile))
                                            shift = True
                                            force_slice = True
                                            with open(time_statefile, 'w') as f:
                                                f.write(str(full_query))
                                            end_date, start_date, interval_slice = await self.check_time_query(params=params, force_slice=force_slice, splits=splits, shift=shift)
                                            if end_date == today_date:
                                                return
                                            logger.debug("Values of end_date: %s, start_date: %s, interval_slice: %s" %(end_date, start_date, interval_slice))
                                
                            if 'error' in result:
                                error = result['error']
                                if ((error['code'] == 'BadRequest' and 'exceeded the allowed result size' in error['message']) or (error['code'] == 'BadRequest' and 'exceeded the allowed limits' in error['message'])):
                                    message = error['message']
                                    if len(splits)>1:
                                        force_slice = True
                                        shift = False
                                    else:
                                        force_slice = False
                                        shift = False
                                    logger.debug('Received error %s from request. Continuing with time slicing' % (message))
                                    end_date, start_date, interval_slice = await self.check_time_query(params=params, force_slice=force_slice, splits=splits, shift=shift)
                                break
                    
                    except Exception as e:
                        logger.error('Error on retrieval: {}'.format(str(e)))
                else:
                    logger.debug('Start and end dates are the same! Exiting...')
                    retries = 0
                    break

    async def gather_events(self, params, failurefile=None) -> None:
        url, auth, logger, session, payload, outfile, boundsfile, time_statefile, bounds_statefile = params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8]
        if 'token_type' not in auth or 'access_token' not in auth:
            logger.error(f"Missing token_type and access_token from auth. Did you auth correctly? (Skipping {object})")
            return
              
        header = {
            'Authorization': '%s %s' % (auth['token_type'], auth['access_token']),
            'Content-Type': 'application/json'    
        }

        if os.path.isfile(bounds_statefile):
            self.logger.debug(f'Bounds save state file exists at {bounds_statefile}')
            with open(bounds_statefile, "r") as f:
                bounds_id = f.readline().strip()
                k = bounds_id
        else:
            self.logger.debug(f'Bounds save state file does not exist at {bounds_statefile}. Starting a full pull.')
            k = 0       

        try:
            if os.path.isfile(boundsfile):
                self.logger.debug(f'Bounds file exists at {boundsfile}')
                with open(boundsfile, "r") as f:
                    bounds = [bound.rstrip() for bound in f]
                for k in range(int(k),len(bounds)):
                    bound = bounds[k]
                    bound_data = json.dumps(bound)
                    final_bound = json.loads(bound_data)
                    tpayload = {'Query': final_bound}
                    tdata=json.dumps(tpayload)
                    logger.debug(str(tdata))
                    retry = 5
                    while retry > 0:
                        async with session.request("POST", url, headers=header, data=tdata) as r:
                            result = await r.json()
                            logger.debug("Request status: " + str(r.status))
                            if r.status == 401:
                                logger.error("Detected 401 unauthorized, exiting.")
                                sys.exit(0)
                            if r.status == 429:
                                error = result['error']
                                message= error['message']
                                seconds = message.split(' ')[-2]
                                logger.debug("Sleeping for %s seconds" % (seconds))
                                await asyncio.sleep(int(seconds))
                                retry -=1
                            else:
                                if 'Results' in result:
                                    if result['Results']:
                                        logger.debug('Size of table: %s' % result['Stats']['dataset_statistics'][0]['table_row_count'])
                                        with open(outfile, 'a', encoding='utf-8') as f:
                                            for x in result['Results']:
                                                f.write(json.dumps(x) + '\n')
                                        with open(bounds_statefile, 'w') as f:
                                            f.write(f'{k}')
                                        retry = 0
                                    elif not result['Results']:
                                        logger.debug('%s has no information (size is 0). No output file.' % (outfile))
                                        retry = 0
        except Exception as e:
            logger.error('Error on retrieval: {}'.format(str(e)))    

    async def post_single_object(self, object, params, table_name, guid=None, failurefile=None) -> None:
        """Posts single queries for dump_advanced_hunting_query.
        API Reference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-advanced-query-api?view=o365-worldwide
        """
        url, auth, logger, session, payload, outfile, boundsfile, time_statefile, bounds_statefile = params[0], params[1], params[2], params[3], params[4], params[5], params[6], params[7], params[8]

        if 'token_type' not in auth or 'access_token' not in auth:
            logger.error(f"Missing token_type and access_token from auth. Did you auth correctly? (Skipping {object})")
            return
        
        url += object
        bounds_only = False

        header = {
            'Authorization': '%s %s' % (auth['token_type'], auth['access_token']),
            'Content-Type': 'application/json'    
        }

        if os.path.isfile(time_statefile):
            self.logger.debug(f'Time save state file exists at {time_statefile}')
            with open(time_statefile, "r") as f:
                lastquery = f.readline().strip()
                split1 = lastquery.split('datetime(')
                end = split1[1].split(')')[0]
                end_date = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
                start = split1[2].split(')')[0]
                start_date = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
                interval_slice = (start_date - end_date)
                save_state = True
                if start_date == today_date:
                    bounds_only = True
                    params = [url, auth, logger, session, payload, outfile, boundsfile, time_statefile, bounds_statefile]
                    await self.gather_events(params=params)
                    self.logger.debug(f'Removing bounds save state file: {bounds_statefile}.')
                    os.remove(bounds_statefile)
        else:
            self.logger.debug(f'Time save state file does not exist at {time_statefile}. Starting a full pull.')
            save_state = False       

        if not bounds_only:
            try:
                retries = 10
                while retries > 0:
                    async with session.request("POST", url, headers=header, data=json.dumps(payload)) as r:
                        result = await r.json()
                        if r.status == 401:
                            logger.error("Detected 401 unauthorized, exiting.")
                            sys.exit(0)
                        elif r.status == 429:
                            error = result['error']
                            message= error['message']
                            seconds = message.split(' ')[-2]
                            logger.debug("Sleeping for %s seconds" % (seconds))
                            await asyncio.sleep(int(seconds))
                            logger.debug(f'Retries remaining: {retries}')
                            retries -=1
                        else:
                            if 'Results' in result:
                                if result['Results']:
                                    logger.debug('Size of table: %s' % result['Stats']['dataset_statistics'][0]['table_row_count'])
                                    with open(outfile, 'a', encoding='utf-8') as f:
                                        for x in result['Results']:
                                            f.write(json.dumps(x) + '\n')
                                    retries = 0
                                elif not result['Results']:
                                    logger.debug('%s has no information (size is 0). No output file.' % (outfile))
                                    if guid:
                                        with open(self.failurefile, 'a+', encoding='utf-8') as f:
                                            f.write('No output file: ' + guid + '_' + table_name + ' - ' + str((datetime.now())) + '\n')
                                    else:
                                        with open(self.failurefile, 'a+', encoding='utf-8') as f:
                                            f.write('No output file: ' + table_name + ' - ' + str((datetime.now())) + '\n')                                                                          
                                    retries = 0
                                    break
                            if 'error' in result:
                                error = result['error']
                                if ((error['code'] == 'BadRequest' and 'exceeded the allowed result size' in error['message']) or (error['code'] == 'BadRequest' and 'exceeded the allowed limits' in error['message'])):
                                    message = error['message']
                                    logger.debug('Received error %s from request. Continuing with time slicing' % (message))

                                    splits = params[4]['Query'].split('|where Timestamp')

                                    if len(splits)>1:
                                        force_slice = True
                                    else:
                                        force_slice = False

                                    shift = False
                                    if not save_state:
                                        end_date, start_date, interval_slice = await self.check_time_query(params=params, splits=splits, force_slice=force_slice, shift=shift)

                                    logger.debug("Values of end_date: %s, start_date: %s, interval_slice: %s" %(end_date, start_date, interval_slice))

                                    if start_date == today_date:
                                        return
                                    await self.test_time_query(params=params, url=url, header=header, query=splits[0], session=session, outfile=outfile, end_date=end_date, start_date=start_date, interval_slice=interval_slice, boundsfile=boundsfile, time_statefile=time_statefile)
                                    
                                    retries -=1
                                elif 'Server disconnected' in error['message']:
                                    await asyncio.sleep(int(60))
                                    retries -= 1
                                elif 'Cannot connect' in error['message']:
                                    await asyncio.sleep(int(60))
                                    retries -= 1
                                elif 'WinError 10054' in error['message']:
                                    await asyncio.sleep(int(60))
                                    retries -= 1
                                                                                         
            except Exception as e:
                logger.error('Error on retrieval: {}'.format(str(e)))
            
            if os.path.isfile(time_statefile):
                self.logger.debug(f'Time save state file exists at {time_statefile}')
                with open(time_statefile, "r") as f:
                    lastquery = f.readline().strip()
                    split1 = lastquery.split('datetime(')
                    end = split1[1].split(')')[0]
                    end_date = datetime.strptime(end, "%Y-%m-%d %H:%M:%S")
                    start = split1[2].split(')')[0]
                    start_date = datetime.strptime(start, "%Y-%m-%d %H:%M:%S")
                    interval_slice = (start_date - end_date)
                    save_state = True
                    if start_date == today_date:
                        bounds_only = True
                        params = [url, auth, logger, session, payload, outfile, boundsfile, time_statefile, bounds_statefile]
                        await self.gather_events(params=params)
                        self.logger.debug(f'Removing bounds save state file: {bounds_statefile}.')
                        os.remove(bounds_statefile)    