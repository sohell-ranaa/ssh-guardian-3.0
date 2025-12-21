"""
SSH Guardian v3.1 - Authentication Routes
Login, OTP, Logout endpoints with persistent sessions
Updated for v3.1 database schema
"""

from flask import Blueprint, request, jsonify, make_response, render_template
from datetime import datetime, timedelta
import json
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from auth import (
    UserManager, PasswordManager, OTPManager, SessionManager,
    EmailService, AuditLogger, AuthenticationError,
    login_required, permission_required, role_required,
    _parse_permissions
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/login', methods=['POST'])
def login_step1():
    """Step 1: Validate password and check if OTP needed"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Invalid JSON data'}), 400

        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        # Get user
        user = UserManager.get_user_by_email(email)

        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401

        # Check if account is active
        if not user['is_active']:
            return jsonify({'error': 'Account is deactivated'}), 403

        # Check if account is locked
        is_locked, locked_until = UserManager.check_account_locked(user['id'])

        if is_locked:
            minutes_left = int((locked_until - datetime.now()).total_seconds() / 60)
            return jsonify({
                'error': f'Account locked. Try again in {minutes_left} minutes'
            }), 403

        # Verify password
        if not PasswordManager.verify_password(password, user['password_hash']):
            UserManager.record_failed_login(user['id'])
            AuditLogger.log_action(
                user['id'], 'login_failed',
                resource_type='user', resource_id=str(user['id']),
                details={'reason': 'invalid_password'},
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            return jsonify({'error': 'Invalid credentials'}), 401

        # Password correct - check if user has valid existing session (trusted device)
        session_token = request.cookies.get('session_token')

        if session_token:
            session_data = SessionManager.validate_session(session_token)

            # If valid session exists and belongs to same user, skip OTP
            if session_data and session_data['user_id'] == user['id']:
                # Update last login (v3.1: uses last_login_at, last_login_ip)
                UserManager.update_last_login(user['id'], request.remote_addr)

                # Log trusted device login
                AuditLogger.log_action(
                    user['id'], 'login_trusted_device',
                    resource_type='user', resource_id=str(user['id']),
                    details={'role': user['role_name']},
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )

                # Return success without OTP
                return jsonify({
                    'success': True,
                    'skip_otp': True,
                    'message': 'Login successful',
                    'user': {
                        'id': user['id'],
                        'email': user['email'],
                        'full_name': user['full_name'],
                        'role': user['role_name'],
                        'permissions': _parse_permissions(user['permissions'])
                    }
                }), 200

        # No valid session - require OTP verification (v3.1: no ip_address param)
        otp_code = OTPManager.create_otp(user['id'], 'login')

        # Send OTP via email
        email_sent = EmailService.send_otp_email(user['email'], otp_code, user['full_name'])

        # Log login attempt
        AuditLogger.log_action(
            user['id'], 'login_otp_sent',
            resource_type='user', resource_id=str(user['id']),
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )

        return jsonify({
            'success': True,
            'skip_otp': False,
            'message': 'Verification code sent to your email',
            'user_id': user['id'],
            'email_sent': email_sent,
            'otp_for_dev': otp_code if not email_sent else None  # Only for development
        }), 200

    except Exception as e:
        print(f"[Auth] Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Step 2: Verify OTP and create persistent session (30 days)"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        otp_code = data.get('otp_code', '').strip()

        if not user_id or not otp_code:
            return jsonify({'error': 'User ID and OTP are required'}), 400

        # Verify OTP
        if not OTPManager.verify_otp(user_id, otp_code, 'login'):
            AuditLogger.log_action(
                user_id, 'login_otp_failed',
                resource_type='user', resource_id=str(user_id),
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            return jsonify({'error': 'Invalid or expired code'}), 401

        # Get user details
        user = UserManager.get_user_by_id(user_id)

        if not user or not user['is_active']:
            return jsonify({'error': 'User account not found or inactive'}), 403

        # Update last login (v3.1: uses last_login_at, last_login_ip, resets failed attempts)
        UserManager.update_last_login(user_id, request.remote_addr)

        # Create session - always 30 days for persistent login
        session_token, expires_at = SessionManager.create_session(
            user_id,
            request.remote_addr,
            request.user_agent.string
        )

        # Log successful login
        AuditLogger.log_action(
            user_id, 'login_success',
            resource_type='user', resource_id=str(user_id),
            details={'role': user['role_name']},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )

        # Create response with cookie
        response = make_response(jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role_name'],
                'permissions': _parse_permissions(user['permissions'])
            }
        }))

        # Set persistent HTTP-only cookie (30 days)
        response.set_cookie(
            'session_token',
            session_token,
            max_age=30*24*60*60,  # 30 days
            secure=False,  # Set to True in production with HTTPS
            httponly=True,
            samesite='Lax',
            path='/'
        )

        return response, 200

    except Exception as e:
        print(f"[Auth] OTP verification error: {e}")
        return jsonify({'error': 'OTP verification failed'}), 500


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logout and delete session"""
    try:
        session_token = request.cookies.get('session_token')

        if session_token:
            SessionManager.delete_session(session_token)

        # Log logout
        user_id = request.current_user.get('user_id') or request.current_user.get('id')
        AuditLogger.log_action(
            user_id, 'logout',
            resource_type='user', resource_id=str(user_id),
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )

        response = make_response(jsonify({'success': True, 'message': 'Logged out successfully'}))
        response.delete_cookie('session_token', path='/', samesite='Lax')

        return response, 200

    except Exception as e:
        print(f"[Auth] Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    try:
        user = request.current_user

        # v3.1: last_login_at instead of last_login
        last_login = user.get('last_login_at') or user.get('last_login')

        return jsonify({
            'user': {
                'id': user.get('user_id') or user.get('id'),
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role_name'],
                'permissions': _parse_permissions(user['permissions']),
                'last_login': last_login.isoformat() if last_login else None
            }
        }), 200

    except Exception as e:
        print(f"[Auth] Get user error: {e}")
        return jsonify({'error': 'Failed to get user info'}), 500


@auth_bp.route('/check-session', methods=['GET'])
def check_session():
    """Check if session is valid (for frontend to verify auth status)"""
    session_token = request.cookies.get('session_token')

    if not session_token:
        return jsonify({'authenticated': False}), 200

    session_data = SessionManager.validate_session(session_token)

    if not session_data:
        return jsonify({'authenticated': False}), 200

    return jsonify({
        'authenticated': True,
        'user': {
            'id': session_data.get('user_id') or session_data.get('id'),
            'email': session_data['email'],
            'full_name': session_data['full_name'],
            'role': session_data['role_name']
        }
    }), 200
