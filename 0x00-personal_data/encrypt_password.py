#!/usr/bin/env python3

"""
Provides functions for hashing passwords
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates if the provided password matches the hashed password.

    Args:
        hashed_password (bytes): The hashed password to compare against
        password (str): The password to validate

    Returns:
        bool: True if the password matches the hashed password,
        False otherwise
    """
    # Convert the password provided to bytes
    password_bytes = password.encode('utf-8')

    # Use bcrypt to check if the provided password matches the hashed password
    return bcrypt.checkpw(password_bytes, hashed_password)
