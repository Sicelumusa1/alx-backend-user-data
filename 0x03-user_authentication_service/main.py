#!/usr/bin/env python3
"""
Main file
"""
import requests
from requests import Response

BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """Register a new user
    """
    response = requests.post(
        f"{BASE_URL}/users",
        data={"email": email, "password": password}
    )
    assert response.status_code == 201, f"Expected 201, got {response.status_code}"
    data = response.json()
    assert data["message"] == "user created", f"Expected 'user created', got {data[message]}"


def log_in_wrong_password(email: str, password: str) -> None:
    """Attempt to log in with a wrong password"""
    response = requests.post(
        f"{BASE_URL}/sessions",
        data={"email": email, "password": password}
    )
    assert response.status_code == 401, f"Expected 401, got {response.status_code}"
    assert "wrong password" in response.json()["message"], "Expected 'wrong password' message"


def log_in(email: str, password: str) -> str:
    """Login with correct credentials"""
    response = requests.post(
        f"{BASE_URL}/sessions",
        data={"email": email, "password": password}
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    return response.json()["session_id"]


def profile_unlogged() -> None:
    """Access the profile without a session ID"""
    response = requests.get(f"{BASE_URL}/profile")
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"


def profile_logged(session_id: str) -> None:
    """Access the proofile with a valid session ID"""
    response = requests.gett(
        f"{BASE_URL}/profile",
        headers={"Authorization": session_id}
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    data = response.json()


def log_out(session_id: str) -> None:
    """Log out using session ID"""
    response = requests.delete(
        f"{BASE_URL}/sessions",
        headers={"Authorization": session_id}
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "logged out" in response.json()["message"], "Expected 'logged out' message"


def reset_password_token(email: str) -> str:
    """Obtain a reset token for the given email"""
    response = requests.post(
        f"{BASE_URL}/reset_password",
        data={"email": email}
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    return response.json()["reset_password"]


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Update the user's password"""
    response = requests.delete(
        f"{BASE_URL}/sessions", data={
            "email": email,
            "reset_password": reset_password,
            "new_password": new_password
        }
    )
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert response.json()["message"] == "Password updated" "Expected 'password updated' message"


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
