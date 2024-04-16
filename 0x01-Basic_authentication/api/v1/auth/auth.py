#!/usr/bin/env python3

"""Defines a class to manage the API authentication"""

from flask import request
from typing import List, TypeVar


class Auth:
    """A class to manage the API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication id required for the given path

        Args:
            path (str): Path of the request
            excluded_paths (List[str]): List of the paths that are excluded 
            from authentication
        Returns:
            bool: True if authentication is required. False otherwise
        """
        if path is None or not excluded_paths:
            return True

        path = path.rstrip('/')

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path.rstrip('*')):
                    return False
            elif path.startswith(excluded_path.rstrip('/')):
                return False

        return True


    def authorization_header(self, request=None) -> str:
        """
        Get the authentication header from the request

        Args:
            request: Flask request object
        
        Returns:
            str: The authentication header value
        """
        if request is None:
            return None

        # Check if the Authorization header is present in the request
        if 'Authorization' not in request.headers:
            return None

        # Return the value of the Authorization header
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Get the current user based on the request

        Args:
            request: The flask request object
        
        Returns:
            TypeVar('User'): the current user
        """
        return None
