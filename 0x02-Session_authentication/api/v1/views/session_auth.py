#!/usr/bin/env python3

"""
For Session Authentication views
"""

from flask import abort, jsonify, request
from api.v1.views import app_views
from models.user import User
from api.v1.app import auth

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login():
    """handle user login"""

    email = request.form.get('email')
    password = request.form.get('password')

    if  not email:
        return jsonify({"error": "email missing"}), 400

    if  not password:
        return jsonify({"error": "password missing"}), 400

    users = User.search({'email': email})
    if  not users:
        return jsonify({"error": "no user found for this email"}), 404

    user = users[0]

    if not user.is_valid_password(password):
        return jsonify({"error": "wrong password"}), 401

    session_id = auth.create_session(user.id)

    user_json = user.to_json()

    response = jsonify(user_json)
    response.set_cookie(auth.SESSION_NAME, session_id)

    return response
