#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
from api.v1.auth.auth import Auth
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Initialize auth to None
auth = None

# Load and assign the right instance of authentication to auth
auth_type = getenv('AUTH_TYPE')
if auth_type and auth_type == 'custom':
    auth = Auth()

# excluded paths
excluded_paths = ['/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/']


@app.before_request
def before_request():
    """
    Before request handler
    """
    global auth

    # If auth is None or request path is not in excluded path, do nothing
    if auth is None:
        return

    # Check if authentication is required for the request path
    if request.path not in excluded_paths and auth.require_auth(request.path, excluded_paths):
        # Get the authorization header
        auth_header = auth.authorization_header(request)

        # If authorization header is None, raise 401 error
        if auth_header is None:
            abort(401)

        # Check current user
        current_user = auth.current_user(request)

        # If current user is None, raise 403 error
        if current_user is None:
            abort(403)


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """ Unauthorized handler """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """ Forbidden handler """
    return jsonify({"error": "Forbidden"}), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run( debug=True, host=host, port=port)
