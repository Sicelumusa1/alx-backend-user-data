#!/usr/bin/env python3

"""DB module to handle database operations
"""
import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User

# Set the SQLAlchemy logging level to WARNING or ERROR to reduce verbosity
logging.basicConfig()
logging.getLogger('sqlalchemy.engine').setLevel(logging.ERROR)


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Add a new user to the database

        Args:
            email: Email of the user
            hashed_password: Hashed password of the user

        Rerurns:
            User: the created User object
        """
        new_user = User(email=email, hashed_password=hashed_password)
        session = self._session

        session.add(new_user)
        session.commit()

        return new_user

    def find_user_by(self, **kwargs) -> User:
        """
        Find a user by arbitrary keyword arguments

        Args:
            kwargs: arbitrary keyword arguments to filter users by

        Returns:
            User: the first User object that matches the given filter

        Raises:
            NoResultFound: If no user matches the provided filter
            InvalidRequestError: If there is an invalid query due to
                                wrong arguments
        """
        session = self._session

        try:
            user = session.query(User).filter_by(**kwargs).first()
            if user is None:
                raise NoResultFound()
            return user
        except InvalidRequestError as e:
            raise e

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update a user by Id with the given attributes

        Args:
            user_id (int): The id of the user to update
            kwargs: Arbitrary keyword arguments for use attributes

        Returns:
            None

        Raises:
            ValueError: If any Kwargs dont correspond to User attribute
        """
        session = self._session
        user = self.find_user_by(id=user_id)

        for key, value in kwargs.items():
            if not hasattr(user, key):
                raise ValueError(f"Invalid attribute '{key}' for User")
            setattr(user, key, value)
        session.commit()
