#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Untitled Goose Tool: generate_conf
This script creates a blank configuration file to use.
"""
import configparser
import fire
from docstring_parser import parse
from docstring_parser.common import DocstringStyle
from goosey.utils import *

from goosey.entra_id_datadumper import EntraIdDataDumper
from goosey.d4iot_dumper import DefenderIoTDumper
from goosey.m365_datadumper import M365DataDumper
from goosey.azure_dumper import AzureDataDumper
from goosey.mde_datadumper import MDEDataDumper

def genconfstring(args, docstring_params, section_name, prefix, config_dict={}):
    conf_s = f"[{section_name}]\n"
    for arg_key in args.keys():
        if arg_key.startswith(prefix):
            var_name = arg_key[len(prefix):]
            val = args[arg_key]
            if val == None and section_name in config_dict and var_name in config_dict[section_name]:
                val = config_dict[section_name][var_name]
            if val == None:
                val = ""
            if arg_key in docstring_params:
                desc = docstring_params[arg_key]
                conf_s += f"# {desc}\n"
            conf_s += f"{var_name}={val}\n"
    conf_s += "\n"
    return conf_s

"""
TODO: Add support for these options in the future
        prompt_needed: Option to prompt for needed fields during generation
        prompt_all: Option to prompt for all fields
        collection_level: Level of log collection. 0 will pull nothing. 1 will pull the important stuff. 2 will pull everything
"""

def genconf(outpath_auth=".auth",
            outpath_conf=".conf",
            auth_appid=None,
            auth_clientsecret=None,
            #prompt_needed=False,
            #prompt_all=False,
            #collection_level=0,
            config_tenant=None,
            config_us_government=False,
            config_mde_gcc=False,
            config_mde_gcc_high=False,
            config_exo_us_government=False,
            config_subscriptionid="All",
            filters_date_start=None,
            filters_date_end=None,
            variable_ual_threshold=5000,
            variable_max_ual_tasks=5,
            variable_ual_extra_start=None,
            variable_ual_extra_end=None,
            variable_mde_threshold=10000,
            variable_mde_query_mode="table",
            azure=False,
            entraid=False,
            m365=False,
            mde=False,
            outpath_d4iotauth=".auth_d4iot",
            outpath_d4iotconf=".d4iot_conf",
            d4iotauth_username=None,
            d4iotauth_password=None,
            d4iotauth_sensor_token=None,
            d4iotauth_mgmt_token=None,
            d4iotconf_d4iot_sensor_ip=None,
            d4iotconf_d4iot_mgmt_ip=None,
            d4iot=False,
            dict_config={},
            d4iot_dict_config={},
            new=False):
    """
    Generate Configuration Files for Goose

    Args:
        outpath_auth: Path to output the auth config
        outpath_conf: Path to output the goose config
        auth_appid: The application ID of your service principal
        auth_clientsecret: The client secret value of your service principal (not the secret ID)
        config_tenant: The tenant ID of your AAD tenant
        config_us_government: If you have a GCC High tenant
        config_mde_gcc: If you have a GCC tenant with MDE
        config_mde_gcc_high: If you have a GCC High tenant with MDE
        config_exo_us_government: If your M365 tenant is a government tenant
        config_subscriptionid: If you want to check all of your Azure subscriptions, set this to All, otherwise enter your Azure subscription ID. For multiple IDs, separate it with commas, no spaces
        filters_date_start: Format should be YYYY-MM-DD. If not set will default to the earliest date for log retention
        filters_date_end: Format should be YYYY-MM-DD. Will default to the present day
        variable_ual_threshold: Threshold used for ual API requests. Specifies the maximum results pulled per session. Can be between 100 - 50000. The api is optimized to return results faster the larger the threshold, but the whole session has to be repeated if an error occurs as the results are not returned sorted. We recommend 5000 as the threshold, but this can be toggled with
        variable_max_ual_tasks: Maximum number of ual coroutines/tasks to have running asynchronously. Minimum value is 1.
        variable_ual_extra_start: Start date for an extra time frame for ual to search. Reason for this is because ual takes the longest to pull and while you don't want the oldest data to roll off, you may want to look at another timeframe and do not want to wait for ual to get there and pull the logs. Format should be YYY-MM-DD
        variable_ual_extra_end: End date for an extra time frame for ual to search. Reason for this is because ual takes the longest to pull and while you don't want the oldest data to roll off, you may want to look at another timeframe and do not want to wait for ual to get there and pull the logs. Format should be YYY-MM-DD
        variable_mde_threshold: Threshold for how many logs to pull per query. Usually want to try to max this out as KQL queries are rate limited.
        variable_mde_query_mode: can be either 'table' or 'machine'. 'table' will pull directly from the mde tables without filtering. While 'machine' will filter by 'machine' with large tenants 'machine' will likely be prefered as time bounding on the entire table will likely cause issues.
        azure: Enable all azure log collection
        entraid: Enable all entraid log collection
        m365: Enable all m365 log collection
        mde: Enable all mde log collection
        outpath_d4iotauth: Path to output the d4iot auth config
        outpath_d4iotconf: Path to output the d4iot goose config
        d4iotauth_username: Username for your D4IoT sensor login page
        d4iotauth_password: Password for your D4IoT sensor login page
        d4iotauth_sensor_token: Enter your D4IoT sensor API token
        d4iotauth_mgmt_token: Enter your D4IoT management console API token
        d4iotconf_d4iot_sensor_ip: Enter your D4IoT sensor IP
        d4iotconf_d4iot_mgmt_ip: Enter your D4IoT management console IP
        d4iot: Enable all d4iot log collection
        dict_config: dictionary of config values you want to set. Will only update valid config parameters. e.g. {"azure": {"activity_log": True}}
        d4iot_dict_config: dictionary of config values you want to set. Will only update valid config parameters. e.g. {"d4iot": {"mgmt_alerts": True}}
        new: Overwrite the existing config. Default will not overwrite existing config, but will update config info if out of date
    """
    # Grab arguments as a dictionary object
    args = locals()
    # parse the docstring for arguments so they can be used as comments
    docstring = parse(genconf.__doc__)

    # Generate dictionary of descriptions for each parameter
    docstring_params = {}
    for param in docstring.params:
        docstring_params[param.arg_name] = param.description

    # Generate the auth conf
    auth_s = genconfstring(args, docstring_params, "auth", "auth_")
    with open(outpath_auth, 'w') as f:
        f.write(auth_s)

    if not new:
        old_config = configparser.ConfigParser()
        old_config.read('.conf')
        old_dict_config = old_config._sections
        # merge in dict_config from parameters
        for key in old_dict_config.keys():
            if key in dict_config:
                old_dict_config[key].update(dict_config[key])
        dict_config = old_dict_config

    # Generate the main config
    conf_s = genconfstring(args, docstring_params, "config", "config_", dict_config)
    conf_s += genconfstring(args, docstring_params, "filters", "filters_", dict_config)
    conf_s += genconfstring(args, docstring_params, "variables", "variable_", dict_config)
    dumpers = {"azure": AzureDataDumper,
               "entraid": EntraIdDataDumper,
               "m365": M365DataDumper,
               "mde": MDEDataDumper}
    # Go through each data dumper and generate the config values for each dump method
    for section_name, section_func in dumpers.items():
        func_args = {}
        dumper_docstrings = {}
        for func_name in [x for x in dir(section_func) if x.startswith('dump_')]:
            func_args[func_name] = args[section_name]
            docs = parse(section_func.__dict__[func_name].__doc__)
            if docs.short_description:
                dumper_docstrings[func_name] = docs.short_description
        conf_s += genconfstring(func_args, dumper_docstrings, section_name, "dump_", dict_config)

    with open(outpath_conf, 'w') as f:
        f.write(conf_s)

    # Generate the d4iot auth conf
    d4iot_auth_s = genconfstring(args, docstring_params, "auth", "d4iotauth_")
    with open(outpath_d4iotauth, 'w') as f:
        f.write(d4iot_auth_s)

    if not new:
        old_config = configparser.ConfigParser()
        old_config.read('.d4iot_conf')
        old_dict_config = old_config._sections
        # merge in dict_config from parameters
        for key in old_dict_config.keys():
            if key in d4iot_dict_config:
                old_dict_config[key].update(d4iot_dict_config[key])
        d4iot_dict_config = old_dict_config

    # Generate the main d4iot config
    d4iot_conf_s = genconfstring(args, docstring_params, "config", "d4iotconf_", d4iot_dict_config)
    dumpers = {"d4iot": DefenderIoTDumper}
    # Go through each data dumper and generate the config values for each dump method
    for section_name, section_func in dumpers.items():
        func_args = {}
        dumper_docstrings = {}
        for func_name in [x for x in dir(section_func) if x.startswith('dump_')]:
            func_args[func_name] = args[section_name]
            docs = parse(section_func.__dict__[func_name].__doc__)
            if docs.short_description:
                dumper_docstrings[func_name] = docs.short_description
        d4iot_conf_s += genconfstring(func_args, dumper_docstrings, section_name, "dump_", d4iot_dict_config)

    with open(outpath_d4iotconf, 'w') as f:
        f.write(d4iot_conf_s)

if __name__ == "__main__":
    fire.Fire(genconf)
