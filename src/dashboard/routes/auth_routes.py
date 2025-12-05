"""
SSH Guardian v3.0 - Authentication Routes
Login, OTP, Logout endpoints with persistent sessions
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
    login_required, permission_required, role_required
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
            # Don't reveal if user exists
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
            AuditLogger.log_action(user['id'], 'login_failed', details={'reason': 'invalid_password'},
                                  ip_address=request.remote_addr, user_agent=request.user_agent.string)
            return jsonify({'error': 'Invalid credentials'}), 401

        # Password correct - check if user has valid existing session (trusted device)
        session_token = request.cookies.get('session_token')

        if session_token:
            session_data = SessionManager.validate_session(session_token)

            # If valid session exists and belongs to same user, skip OTP
            if session_data and session_data['id'] == user['id']:
                # Reset failed attempts
                UserManager.reset_failed_attempts(user['id'])

                # Update last login
                from dbs.connection import get_connection
                conn = None
                cursor = None
                try:
                    conn = get_connection()
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user['id'],))
                    conn.commit()
                finally:
                    if cursor:
                        cursor.close()
                    if conn:
                        conn.close()

                # Log trusted device login
                AuditLogger.log_action(user['id'], 'login_trusted_device',
                                      details={'role': user['role_name']},
                                      ip_address=request.remote_addr, user_agent=request.user_agent.string)

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
                        'permissions': json.loads(user['permissions']) if isinstance(user['permissions'], str) else user['permissions']
                    }
                }), 200

        # No valid session - require OTP verification
        otp_code = OTPManager.create_otp(user['id'], 'login', request.remote_addr)

        # Send OTP via email
        email_sent = EmailService.send_otp_email(user['email'], otp_code, user['full_name'])

        # Email sending handled by EmailService - no debug output needed

        # Log login attempt
        AuditLogger.log_action(user['id'], 'login_otp_sent',
                              ip_address=request.remote_addr, user_agent=request.user_agent.string)

        return jsonify({
            'success': True,
            'skip_otp': False,
            'message': 'Verification code sent to your email',
            'user_id': user['id'],
            'email_sent': email_sent,
            'otp_for_dev': otp_code if not email_sent else None  # Only for development
        }), 200

    except Exception as e:
        print(f"❌ Login error: {e}")
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
            AuditLogger.log_action(user_id, 'login_otp_failed',
                                  ip_address=request.remote_addr, user_agent=request.user_agent.string)
            return jsonify({'error': 'Invalid or expired code'}), 401

        # Get user details
        user = UserManager.get_user_by_id(user_id)

        if not user or not user['is_active']:
            return jsonify({'error': 'User account not found or inactive'}), 403

        # Reset failed attempts
        UserManager.reset_failed_attempts(user_id)

        # Update last login
        from dbs.connection import get_connection
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET last_login = NOW() WHERE id = %s", (user_id,))
            conn.commit()
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        # Create session - always 30 days for persistent login
        session_token, expires_at = SessionManager.create_session(
            user_id,
            request.remote_addr,
            request.user_agent.string
        )

        # Log successful login
        AuditLogger.log_action(user_id, 'login_success',
                              details={'role': user['role_name']},
                              ip_address=request.remote_addr, user_agent=request.user_agent.string)

        # Create response with cookie
        response = make_response(jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role_name'],
                'permissions': json.loads(user['permissions']) if isinstance(user['permissions'], str) else user['permissions']
            }
        }))

        # Set persistent HTTP-only cookie (30 days)
        response.set_cookie(
            'session_token',
            session_token,
            max_age=30*24*60*60,  # 30 days - persists across browser restarts
            secure=False,  # Set to True in production with HTTPS
            httponly=True,  # Not accessible via JavaScript
            samesite='Lax',
            path='/'
        )

        return response, 200

    except Exception as e:
        print(f"❌ OTP verification error: {e}")
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
        AuditLogger.log_action(request.current_user['id'], 'logout',
                              ip_address=request.remote_addr, user_agent=request.user_agent.string)

        response = make_response(jsonify({'success': True, 'message': 'Logged out successfully'}))
        response.delete_cookie('session_token', path='/', samesite='Lax')

        return response, 200

    except Exception as e:
        print(f"❌ Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route('/me', methods=['GET'])
@login_required
def get_current_user():
    """Get current user info"""
    try:
        user = request.current_user

        return jsonify({
            'user': {
                'id': user['id'],
                'email': user['email'],
                'full_name': user['full_name'],
                'role': user['role_name'],
                'permissions': json.loads(user['permissions']) if isinstance(user['permissions'], str) else user['permissions'],
                'last_login': user['last_login'].isoformat() if user['last_login'] else None
            }
        }), 200

    except Exception as e:
        print(f"❌ Get user error: {e}")
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
            'id': session_data['id'],
            'email': session_data['email'],
            'full_name': session_data['full_name'],
            'role': session_data['role_name']
        }
    }), 200
