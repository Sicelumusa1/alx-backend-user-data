#!/usr/bin/env python3

"""
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.exc import InvalidRequestError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initilizes a database"""
        self._db = DB()


    def _hash_password(self, password: str) -> bytes:
        """
        Hashes a password with a random salt using bcrypt

        Args:
            password (str): passwort to be hashed

        Returns:
            bytes: A salted hash of the password
        """
        # Generate a salt
        salt = bcrypt.gensalt()

        # Hash the password with the salt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user with the given email and password

        Args:
            email (str): The user's email address
            password (str): The plaintext password to hash

        Returns:
            User: The created User object

        Raises:
            ValueError: If a user with the given email already exists
        """
        try:
            # Check if the user already exists
            existing_user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            # No existing user with the provided email, create a new user
            hashed_password = self._hash_password(password)
            user = self._db.add_user(email, hashed_password.decode('utf-8'))

            return user
