#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: generate_conf
This script creates a blank configuration file to use.
"""

from goosey.azure_ad_datadumper import AzureAdDataDumper
from goosey.d4iot_dumper import DefenderIoTDumper
from goosey.m365_datadumper import M365DataDumper
from goosey.azure_dumper import AzureDataDumper
from goosey.mde_datadumper import MDEDataDumper

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

def main():
    auth_s = '[auth]\nusername=\npassword=\nappid=\nclientsecret=\n\n'

    with open('.auth', 'w') as f:
        f.write(auth_s)

    s = '[config]\ntenant=\nus_government=\nmde_gcc=\nmde_gcc_high=\nexo_us_government=\nsubscriptionid=\nm365=\n\n'
    
    s += '[filters]\ndate_start=\ndate_end=\n\n'

    s += '[azure]\n'
    s += '\n'.join([x.lstrip().replace('dump_', '') + '=False' for x in dir(AzureDataDumper) if x.startswith('dump_')])
    s += '\n\n'

    s += '[azuread]\n'
    s += '\n'.join([x.lstrip().replace('dump_', '') + '=False' for x in dir(AzureAdDataDumper) if x.startswith('dump_')])
    s += '\n\n'

    s += '[m365]\n'
    s += '\n'.join([x.lstrip().replace('dump_', '') + '=False' for x in dir(M365DataDumper) if x.startswith('dump_')])
    s += '\n\n'

    s += '[mde]\n'
    s += '\n'.join([x.lstrip().replace('dump_', '') + '=False' for x in dir(MDEDataDumper) if x.startswith('dump_')])
    s += '\n\n'

    s += '[msgtrc]\nsetemailaddress=\ndirection=\nnotifyaddress=\noriginalclientip=\nrecipientaddress=\nreporttitle=\nreporttype=\nsenderaddress=\n\n'

    with open('.conf', 'w') as f:
        f.write(s)

    d4iotauth_s = '[auth]\nusername=\npassword=\nd4iot_sensor_token=\nd4iot_mgmt_token=\n\n'

    with open('.auth_d4iot', 'w') as f:
        f.write(d4iotauth_s)    
    d4iot_s = '[config]\n'
    d4iot_s += 'd4iot_sensor_ip=\nd4iot_mgmt_ip=\n\n'
    d4iot_s += '[d4iot]\n'
    d4iot_s += '\n'.join([x.lstrip().replace('dump_', '') + '=False' for x in dir(DefenderIoTDumper) if x.startswith('dump_')])
    d4iot_s += '\n\n'
    
    with open('.d4iot_conf', 'w') as f:
        f.write(d4iot_s)

if __name__ == "__main__":
    main()
