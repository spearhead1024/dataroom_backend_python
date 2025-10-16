# backend/routes/auth_routes.py - Authentication Endpoints
"""
Authentication routes for user registration, login, token refresh, and profile management.
All authentication-related endpoints are prefixed with /auth
"""

from flask import Blueprint, request, jsonify
from models import db, User
from auth import create_access_token, create_refresh_token, decode_token, token_required
from datetime import datetime
import re

auth_bp = Blueprint('auth', __name__)


# ============ VALIDATION HELPERS ============

def validate_email(email):
    """
    Validate email format using regex.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    """
    Validate password strength.
    
    Requirements:
    - At least 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    
    Args:
        password (str): Password to validate
        
    Returns:
        tuple: (is_valid: bool, message: str)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    return True, "Password is valid"


def validate_username(username):
    """
    Validate username format.
    
    Requirements:
    - 3-30 characters
    - Alphanumeric and underscores only
    - Cannot start with a number
    
    Args:
        username (str): Username to validate
        
    Returns:
        tuple: (is_valid: bool, message: str)
    """
    if len(username) < 3 or len(username) > 30:
        return False, "Username must be between 3 and 30 characters"
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', username):
        return False, "Username must start with a letter and contain only letters, numbers, and underscores"
    
    return True, "Username is valid"


# ============ AUTHENTICATION ENDPOINTS ============

@auth_bp.route('/auth/register', methods=['POST'])
def register():
    """
    Register a new user account.
    
    Request Body:
        {
            "email": "user@example.com",
            "username": "johndoe",
            "password": "SecurePass123",
            "full_name": "John Doe" (optional)
        }
        
    Returns:
        201: User created successfully with tokens
        400: Validation error or user already exists
        500: Server error
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'username', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        email = data['email'].strip().lower()
        username = data['username'].strip()
        password = data['password']
        full_name = data.get('full_name', '').strip()
        
        # Validate email format
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate username
        is_valid_username, username_message = validate_username(username)
        if not is_valid_username:
            return jsonify({'error': username_message}), 400
        
        # Validate password strength
        is_valid_password, password_message = validate_password(password)
        if not is_valid_password:
            return jsonify({'error': password_message}), 400
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email is already registered'}), 400
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username is already taken'}), 400
        
        # Create new user
        user = User(
            email=email,
            username=username,
            full_name=full_name,
            is_verified=False  # Email verification can be added later
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        # Generate authentication tokens
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/login', methods=['POST'])
def login():
    """
    Authenticate user and return tokens.
    
    Request Body:
        {
            "email": "user@example.com",
            "password": "SecurePass123"
        }
        
    Returns:
        200: Login successful with tokens
        400: Missing credentials
        401: Invalid credentials or inactive account
        500: Server error
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        email = data['email'].strip().lower()
        password = data['password']
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        # Verify user exists and password is correct
        if not user or not user.check_password(password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Check if account is active
        if not user.is_active:
            return jsonify({'error': 'Account is deactivated. Please contact support.'}), 401
        
        # Update last login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Generate authentication tokens
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/refresh', methods=['POST'])
def refresh():
    """
    Refresh access token using refresh token.
    
    Request Body:
        {
            "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
        }
        
    Returns:
        200: New access token generated
        400: Missing refresh token
        401: Invalid or expired refresh token
        500: Server error
    """
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token is required'}), 400
        
        # Decode and validate refresh token
        payload = decode_token(refresh_token)
        if not payload or payload.get('type') != 'refresh':
            return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
        # Get user from database
        user = User.query.get(payload['user_id'])
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or account is inactive'}), 401
        
        # Generate new access token
        access_token = create_access_token(user.id)
        
        return jsonify({
            'access_token': access_token
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/me', methods=['GET'])
@token_required
def get_current_user():
    """
    Get current authenticated user's profile.
    
    Headers:
        Authorization: Bearer <access_token>
        
    Returns:
        200: User profile data
        401: Invalid or missing token
        500: Server error
    """
    try:
        user = request.current_user
        return jsonify(user.to_dict()), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/logout', methods=['POST'])
@token_required
def logout():
    """
    Logout user (token is invalidated on client side).
    
    Note: In a production system, you might want to implement token blacklisting.
    
    Headers:
        Authorization: Bearer <access_token>
        
    Returns:
        200: Logout successful
        401: Invalid or missing token
    """
    try:
        # In a more advanced setup, you could:
        # 1. Add token to blacklist/redis
        # 2. Invalidate all user sessions
        # 3. Clear any cached data
        
        return jsonify({'message': 'Logout successful'}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/change-password', methods=['POST'])
@token_required
def change_password():
    """
    Change user's password.
    
    Request Body:
        {
            "current_password": "OldPass123",
            "new_password": "NewSecurePass456"
        }
        
    Headers:
        Authorization: Bearer <access_token>
        
    Returns:
        200: Password changed successfully
        400: Missing fields or validation error
        401: Current password is incorrect
        500: Server error
    """
    try:
        data = request.get_json()
        user = request.current_user
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        # Validate required fields
        if not current_password or not new_password:
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        # Verify current password
        if not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password strength
        is_valid, message = validate_password(new_password)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Check if new password is same as old password
        if current_password == new_password:
            return jsonify({'error': 'New password must be different from current password'}), 400
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'message': 'Password changed successfully'}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/update-profile', methods=['PUT'])
@token_required
def update_profile():
    """
    Update user profile information.
    
    Request Body:
        {
            "full_name": "John Doe Updated",
            "avatar_url": "https://example.com/avatar.jpg" (optional)
        }
        
    Headers:
        Authorization: Bearer <access_token>
        
    Returns:
        200: Profile updated successfully
        400: Validation error
        500: Server error
    """
    try:
        data = request.get_json()
        user = request.current_user
        
        # Update full_name if provided
        if 'full_name' in data:
            full_name = data['full_name'].strip()
            user.full_name = full_name
        
        # Update avatar_url if provided
        if 'avatar_url' in data:
            avatar_url = data['avatar_url'].strip()
            # Basic URL validation
            if avatar_url and not avatar_url.startswith(('http://', 'https://')):
                return jsonify({'error': 'Invalid avatar URL'}), 400
            user.avatar_url = avatar_url
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/verify-token', methods=['POST'])
def verify_token_endpoint():
    """
    Verify if a token is valid (useful for client-side token validation).
    
    Request Body:
        {
            "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
        }
        
    Returns:
        200: Token is valid
        400: Missing token
        401: Invalid or expired token
    """
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'error': 'Token is required'}), 400
        
        from auth import verify_token
        is_valid, user_id, error_message = verify_token(token)
        
        if not is_valid:
            return jsonify({'error': error_message}), 401
        
        return jsonify({
            'valid': True,
            'user_id': user_id
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
