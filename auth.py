"""
Authentication utilities for JWT token management and route protection.
This module provides decorators and functions for securing API endpoints.
"""

import jwt
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from models import User, db

# Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30


def create_access_token(user_id):
    """
    Generate JWT access token for a user.
    
    Args:
        user_id (int): The user's database ID
        
    Returns:
        str: Encoded JWT token
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id):
    """
    Generate JWT refresh token for a user.
    
    Args:
        user_id (int): The user's database ID
        
    Returns:
        str: Encoded JWT refresh token
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        'iat': datetime.utcnow(),
        'type': 'refresh'
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token):
    """
    Decode and validate JWT token.
    
    Args:
        token (str): JWT token to decode
        
    Returns:
        dict: Decoded token payload, or None if invalid/expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """
    Decorator to protect routes requiring authentication.
    
    Usage:
        @app.route('/protected')
        @token_required
        def protected_route():
            user = request.current_user
            return jsonify({'message': f'Hello {user.username}'})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Expected format: "Bearer <token>"
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format. Use: Bearer <token>'}), 401
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        # Decode and validate token
        payload = decode_token(token)
        if not payload or payload.get('type') != 'access':
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Get user from database
        user = User.query.get(payload['user_id'])
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or account is inactive'}), 401
        
        # Add user to request context for use in route handler
        request.current_user = user
        
        return f(*args, **kwargs)
    
    return decorated


def optional_token(f):
    """
    Decorator that allows both authenticated and anonymous access.
    If a valid token is provided, user will be available in request.current_user
    
    Usage:
        @app.route('/public')
        @optional_token
        def public_route():
            if request.current_user:
                return jsonify({'message': f'Hello {request.current_user.username}'})
            return jsonify({'message': 'Hello anonymous user'})
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Try to get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                pass
        
        # If token exists, try to decode it
        if token:
            payload = decode_token(token)
            if payload and payload.get('type') == 'access':
                user = User.query.get(payload['user_id'])
                if user and user.is_active:
                    request.current_user = user
        
        # Set current_user to None if not authenticated
        if not hasattr(request, 'current_user'):
            request.current_user = None
        
        return f(*args, **kwargs)
    
    return decorated


def get_current_user():
    """
    Helper function to get the current authenticated user from the request context.
    
    Returns:
        User: Current user object, or None if not authenticated
    """
    return getattr(request, 'current_user', None)


def verify_token(token):
    """
    Verify if a token is valid without using it in a request context.
    
    Args:
        token (str): JWT token to verify
        
    Returns:
        tuple: (is_valid, user_id, error_message)
    """
    payload = decode_token(token)
    if not payload:
        return False, None, 'Invalid or expired token'
    
    if payload.get('type') != 'access':
        return False, None, 'Not an access token'
    
    user_id = payload.get('user_id')
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        return False, None, 'User not found or inactive'
    
    return True, user_id, None
