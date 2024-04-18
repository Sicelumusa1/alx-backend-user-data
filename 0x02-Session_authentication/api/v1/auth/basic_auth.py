#!/usr/bin/env python3

"""Defines a class with basic authentication system"""

from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class"""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the Autherization header for Basic Authentication

        Args:
            authorization_header (str): Authorization header

        returns:
            str: The Base64 part of the Authorization header, or None if not found
        """
        if authorization_header is None or not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith('Basic '):
            return None

        return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """
        Decodes the Base64 string base64_authorization_header

        Args:
            base64_authorization_header (str): the string to decode

        Returns:
            str: The decoded value as utf-8 string, or None if not valid
        """
        if base64_authorization_header is None or not isinstance(base64_authorization_header, str):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            # convert bytes to utf-8 string
            decoded_string = decoded_bytes.decode('utf-8')
            return decoded_string
        except:
            # Invalid Base64 string
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """
        Extracts user email and password from the Base64 decoded value

        Args:
            decoded_base64_authorization_header (str): the decoded Base64 string

        Returns:
            Tuple[str, str]: tuple containing the user email and password
        """
        if decoded_base64_authorization_header is None or not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        # Split the decode header on the first occurrence of colon
        parts = decoded_base64_authorization_header.split(':', 1)
        if len(parts) != 2:
            return None, None

        user_email = parts[0]
        user_pwd = parts[1]

        return user_email, user_pwd

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """
        Returns the user instance based on email and password

        Args:
            user_email (str): The email of the user
            user_pwd (str): password ot the user

        Returns:
            TypeVar('User'): the user instance if found, otherwise None
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        # Search for the user in the database
        users = User.search({'email': user_email})
        if not users:
            return None

        # Check if the password matches
        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the User instance for a request

        Args:
            request: The Flask request object

        Returns:
            TypeVar('User'): The User instance if found, otherwise None
        """
        if request is None:
            return None

        # Get the authorization header from request
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None

        # extract the Base64 part of the authentication header
        base64_auth_header = self.extract_base64_authorization_header(auth_header)
        if base64_auth_header is None:
            return None

        # decode the Base64 string
        decoded_auth_header = self.decode_base64_authorization_header(base64_auth_header)
        if decoded_auth_header is None:
            return None

        # Extract the user credentials
        user_email, user_pwd = self.extract_user_credentials(decoded_auth_header)
        if user_email is None or user_pwd is None:
            return None

        # Retrieve the User instance based on the credentials
        return self.user_object_from_credentials(user_email, user_pwd)
