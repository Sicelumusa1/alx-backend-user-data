#!/usr/bin/env python3

"""
Flask app module
"""

from flask import Flask, jsonify, request, abort
from auth import Auth
import bcrypt

AUTH = Auth()

# Create a Flask application instance
app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    """
    Route to return a welcome message in JSON format
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def users():
    """
    A POST endpoint to register a new user

    Expected from data:
        email: user email adddress
        password: user password

    Returns:
        JSON response with a success message if user registration succeeds
    """
    # Get the form data from the request
    email = request.form.get("email")
    password = request.form.get("password")

    # Check if both email and password are provided
    if not email or not password:
        return jsonify({"message": "email and password are required"}), 400
    try:
        # Attemp to register the user using the Auth class
        user = AUTH.register_user(email, password)

        # Return a success message with the registeres email
        return jsonify({"email": user.email, "message": "user created"}), 201
    except ValueError:
        # If a ValueError is raise, it means the user already exists
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    """
    Endpoint for logging in a user

    Expects form data with:
        email: user email address
        password: user password
    """
    # Extract email and password
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        # If either field is missing, respond with a 401 status
        abort(401)

    # validate the login credentials
    if not AUTH.valid_login(email, password):
        # If invalid, respond with a 401 status
        abort(401)

    # If valid, create a new session and set the session ID as aa cookie
    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)

    return response


@app.route("/sessions", methods=["DELETE"])
def logout():
    """
    Endpoint for logging out a user
    """
    session_id = request.cookies.get("session_id")

    if not session_id:
        abort(403)

    user = AUTH.get_user_from_session_id(session_id)

    if not user:
        abort(403)

    AUTH.destroy_session(user.id)

    return redirect("/")


@app.route("/profile", methods=["GET"])
def profile():
    """
    Endpoint for retrieving the user's profile based on session_id
    """
    # Get the session_id from the request's cookies
    session_id = request.cookies.get("session_id")

    user = AUTH.get_user_from_session_id(session_id)

    if user is not None:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)


# Start the Flask app on the specified host and port
if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
