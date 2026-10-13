#!/usr/bin/env python
# -*- coding: utf-8 -*-

from goosey.utils import *

class DataDumper(object):
    def __init__(self, output_dir: str, reports_dir: str, app_auth: dict, session, debug):
        self.output_dir = output_dir
        self.reports_dir = reports_dir
        self.ahsession = session
        self.app_auth = app_auth
        self.logger = setup_logger(__name__, debug)

    def get_session(self):
        return self.ahsession

    def data_dump(self, calls, dumper_name) -> list:
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
            tasks.append(asyncio.create_task(self.func_wrapper(func), name=f"{dumper_name}_{key}"))
        return tasks

    async def func_wrapper(self, func):
        error = None
        try:
            error = await func()
        except Exception as e:
            self.logger.debug(f"{func.__name__} Failed with error {e}", exc_info=1)
            error = e
        return self.__class__.__name__, func.__name__, error

    def __getattr__(self, attr):
        self.logger.info("[DRY RUN] Calling %s" % (attr))
        async def default(*args, **kwargs):
            return attr
        return default
