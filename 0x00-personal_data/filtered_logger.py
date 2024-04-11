#!/usr/bin/env python3

"""
Provides functionality for logging and filtering sensitive information
"""

import re
from typing import List
import logging
import csv
import os
import mysql.connector


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


def get_db():
    """Returns a connector to the MySQL database"""
    # Retrive credentials from env variables or set default
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    # Connect to the MySQL database
    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=db_name
    )


def main():
    """
    Obtains a database connection using get_db and retreives all rows in the users table
    Displays each row under a filtered format
    """
    logger = get_loger()
    db = get_db()

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()

    for row in rows:
        filtered_row = filter_datum(PII_FIELDS, RedactingFormatter.REDACTION, str(row))
        logger.info(filtered_row)


if __name__ == "__main__":
    main()
