#!/usr/bin/env python3

"""
Module that defines authentication methods
"""

import bcrypt
from db import DB
from user import User
import uuid
from sqlalchemy.exc import InvalidRequestError, IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from typing import Optional


def _hash_password(password: str) -> bytes:
    """
    Hashes a password with a random salt using bcrypt

    Args:
        password (str): password to be hashed

    Returns:
        bytes: A salted hash of the password
    """
    # Generate a salt
    salt = bcrypt.gensalt()

    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def _generate_uuid() -> str:
    """
    Generate a new UUID and return its string representation

    Returns:
        str: A string prepresentation of a UUID
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initilizes a database"""
        self._db = DB()

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
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password.decode('utf-8'))

            return user

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validates if the email and password are valid

        Args:
            email (str): The user's email address
            password (str): The plaintext password to hash

        Returns:
            bool: True if the email exists and the password matches
        """
        try:
            # try to find user by email
            user = self._db.find_user_by(email=email)

            return bcrypt.checkpw(
                password.encode("utf-8"),
                user.hashed_password.encode("utf-8")
            )
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Create a seeion for a user with the given email

        Agrs:
            email (str): email address of the user

        Returns:
            str: generated session ID or None if not found
        """
        try:
            user = self._db.find_user_by(email=email)

            # Generate a new UUID for the session
            session_id = _generate_uuid()
            user.session_id = session_id
            self._db._session.commit()
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Optional[User]:
        """
        Find a user by the given session_id

        Args:
            session_id (str): The session ID to look up

        Returns:
            User: The user associated with the session ID or None if
            not found
        """
        if session_id is None:
            return None

        try:
            # Try to find the user with the given session_id
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            # If no user is found, return None
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy the session for a given user_id

        Args:
            user_id (int): The ID of the user whose session should be
            destroyed

        Returns:
            None
        """
        try:
            user = self._db.find_user_by(id=user_id)

            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            return

    def get_reset_password_token(self, email: str) -> str:
        """
        Get a reset password token for a user with the given email

        Args:
            email (str):Email address to find the user

        Returns:
            str: A UUID reset token

        Raises:
             ValueError: If no user with the give email is found
        """
        try:
            # find user by email
            user = self._db.find_user_by(email=email)

            # Generate uiid for reset token
            reset_token = _generate_uuid()

            # Update the user's reset_token field in the db
            user.reset_token = reset_token

            # Commit the change to the db
            self._db._session.commit()

            return reset_token
        except NoResultFound:
            raise ValueError(f"No user found with email: {email}")

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Update the user's password using a reset token

        Args:
            reset_token (str): token used to identify the user
            password (str): new plaintext password

        Raises:
            ValueError: If no user with the given reset token is found
        """
        try:
            # find user by the reset token
            user = self._db.find_user_by(reset_token=reset_token)

            # Hash the new password
            hashed_password = self._hash_password(password)

            # Update both password and token
            user.hashed_password = hashed_password.decode('utf-8')
            user.reset_token = None

            # Commit the changes to the db
            self._db._session.commit()
        except NoResultFound:
            raise ValueError(f"No user found with reset token: {reset_token}")
