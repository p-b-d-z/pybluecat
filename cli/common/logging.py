#!/usr/bin/env python3
import inspect
import os
import re
from enum import Enum

from cli.common.terminal import (
    blue,
    green,
    red,
    reset,
    yellow,
)


def get_caller_module(filepath):
    pattern = r'([^\\/]*)\.[^\\/.]*$'
    result = re.search(pattern, filepath)
    return result.group(1)


def validate_log_level(log_level):
    if log_level not in LogLevel.values():
        raise ValueError(f'Invalid log level: {log_level}')


# Simple ENUM for the logging levels
class LogLevel(Enum):
    INFO = 'INFO'
    DEBUG = 'DEBUG'
    ERROR = 'ERROR'
    NONE = 'NONE'
    WARN = 'WARN'

    @classmethod
    def values(cls):
        return [item.value for item in cls]


class Logger:
    """
    Simple helper class for handling logging output. Prints to the console, so not doing anything with logs. The
    There are five logging levels:
        - ERROR: for error output - highest severity, minimal output
        - WARN: for warning output - medium severity, includes error output
        - INFO: for informative and brief output - low severity through highest severity logs are included
        - DEBUG: super verbose, should only be used for debugging issues - includes all log levels
    """

    initial_log_level = os.getenv('LOG_LEVEL', 'NONE').upper().strip()
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance.log_level = LogLevel(cls.initial_log_level)
        return cls._instance

    def set_log_level(self, log_level):
        validate_log_level(log_level)
        # pylint: disable=attribute-defined-outside-init
        self.log_level = LogLevel(log_level)  # noqa Ignore IDE warnings, __new__ handles __init__

    def info(self, info_str):
        """
        INFO is included under all contexts.

        Printed under the following log levels:
            - ERROR (higher severity)
            - INFO (self)
            - DEBUG (always)
            - WARN (higher severity)

        :param info_str:
        """
        if self.log_level in [
            LogLevel.ERROR,
            LogLevel.INFO,
            LogLevel.DEBUG,
            LogLevel.WARN,
        ]:
            caller_mod = get_caller_module(inspect.stack()[1].filename)
            caller_func = inspect.stack()[1].function
            print(f'[{caller_mod}.{caller_func}] {blue}INFO{reset} - {info_str}')

    def debug(self, debug_str):
        """
        DEBUG is included under only the DEBUG context.

        :param debug_str:
        """
        if self.log_level == LogLevel.DEBUG:
            caller_mod = get_caller_module(inspect.stack()[1].filename)
            caller_func = inspect.stack()[1].function
            print(f'[{caller_mod}.{caller_func}] {green}DEBUG{reset} - {debug_str}')

    def error(self, error_str):
        """
        ERROR

        Errors will always be printed regardless of log level to ensure that the user is aware of the error.
        :param error_str:
        """
        caller_mod = get_caller_module(inspect.stack()[1].filename)
        caller_func = inspect.stack()[1].function
        print(f'[{caller_mod}.{caller_func}] {red}ERROR{reset} - {error_str}')

    def warn(self, warn_str):
        """
        WARN

        Printed under the following log levels:
            - ERROR (higher severity)
            - WARN (self)
            - DEBUG (always)
        """
        if self.log_level in [LogLevel.WARN, LogLevel.ERROR, LogLevel.DEBUG]:
            caller_mod = get_caller_module(inspect.stack()[1].filename)
            caller_func = inspect.stack()[1].function
            print(f'[{caller_mod}.{caller_func}] {yellow}WARN{reset} - {warn_str}')
