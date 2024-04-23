#!/usr/bin/env python3

"""
Flask app module
"""

from flask import Flask, jsonify, request
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
def register_user():
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
        return jsonify({"message": "email and password are required"}),400
    try:
        # Attemp to register the user using the Auth class
        user = AUTH.register_user(email, password)

        # Return a success message with the registeres email
        return jsonify({"email": user.email, "message": "user created"}), 201
    except ValueError:
        # If a ValueError is raise, it means the user already exists
        return jsonify({"message": "email already registered"}), 400

# Start the Flask app on the specified host and port
if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
