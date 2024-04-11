#!/usr/bin/env python3

"""
"""

import re
from typing import List
import logging
import csv


PII_FIELDS = ("email", "phone", "ssn", "password", "address")


def filter_datum(fields: List[str], redaction: str, message: str, 
                 separator: str=';') -> str:
    """
    Obfuscates the specified field in a log message

    Args:
        fields (list): a list of strings representing all fields to obfuscate
        redaction (str): a string representing by what the field will be
                        obfuscated
        message (str) : a string representing the log line
        separator (str): a string representing by which character is
                        separating all fields in the log line

    Returns:
        str: log message with specified fields
    """
    return re.sub(r'(?:=^|;)(?:' + '|'.join(fields) + r')=[^;]*', lambda 
                  match: match.group(0).split('=')[0] + '=' + redaction, 
                  message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Formats the log record with specified fields obfuscated"""
        message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, message, self.SEPARATOR)

def get_logger():
    """Returns a logging.logger object"""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)

    handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    logger.propagate = False

    return logger
