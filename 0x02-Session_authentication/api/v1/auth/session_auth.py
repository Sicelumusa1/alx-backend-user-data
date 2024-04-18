#!/usr/bin/env python3

"""Defines a session authentication class"""

from models.user import User
from api.v1.auth.auth import Auth
import uuid
from typing import TypeVar


class SessionAuth(Auth):
    """Session authentication class"""
    
    # Class attribute to store user-id by session_id
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a session id for a user id

        Args:
            user_id (str): User id for which the session is created

        Returns:
            str: Session id created
        """
        if user_id is None or not isinstance(user_id, str):
            return None

        # Generate a Session ID using uuid module
        session_id = str(uuid.uuid4())

        # Store the user_id by session_id
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns a User ID based on a Session ID

        Args:
            session_id (str): Session Id for which the User Id is retrieved

        Returns:
            str: User Id associated with the Session Id
        """
        if session_id is None or not isinstance(session_id, str):
            return None

        # Retrieve the User Id based on the session Id
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Get the current user based on the session cookie

        Args:
            request: The flask request object

        Returns:
            TypeVar('User'): the current user
        """
        if request is None:
            return None

        session_id = self.session_cookie(request)

        if session_id is None:
            return None

        user_id = self.user_id_for_session_id(session_id)

        if user_id is None:
            return None

        return User.get(user_id)

    def destroy_session(self, request=None):
        """Delete the user session / logout"""
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False

        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return False

        del self.user_id_by_session_id[session_id]
        return True
