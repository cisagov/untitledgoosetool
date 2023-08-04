#!/usr/bin/env python
# -*- coding: utf-8 -*-

from goosey.utils import *

__author__ = "Claire Casalnova, Jordan Eberst, Wellington Lee, Victoria Wallace"
__version__ = "1.2.5"

class DataDumper(object):
    def __init__(self, output_dir: str, reports_dir: str, auth: dict, app_auth: dict, session, debug):
        self.output_dir = output_dir
        self.reports_dir = reports_dir
        self.ahsession = session
        self.auth = auth 
        self.app_auth = app_auth
        self.logger = setup_logger(__name__, debug)

    def get_session(self):
        return self.ahsession

    def data_dump(self, calls) -> list:
        """

        :param calls: function calls to make mapped to params
        :type calls: dict
        """
        tasks = []
        self.logger.debug("Called data_dump in DataDumper")
        for key in calls:
            try:
                func = getattr(self, 'dump_' + key)
            except Exception as e:
                self.logger.debug("Did not find %s in dumper" % (key))
                continue
            self.logger.debug("Calling %s" % (func))
            tasks.append(func())
        return tasks

    def __getattr__(self, attr):
        self.logger.info("[DRY RUN] Calling %s" % (attr))
        async def default(*args, **kwargs):
            return attr
        return default