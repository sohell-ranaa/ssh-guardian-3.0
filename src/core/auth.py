"""
SSH Guardian v3.0 - Authentication System
RBAC with password + OTP, session management, and email integration
Adapted from v2.0 for v3.0 database schema
"""

import os
import sys
import secrets
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, session
import bcrypt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from dbs.connection import get_connection

# Email configuration (from environment variables)
EMAIL_CONFIG = {
    'smtp_host': os.getenv('SMTP_HOST', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', 587)),
    'smtp_user': os.getenv('SMTP_USER', '').strip('"'),
    'smtp_password': os.getenv('SMTP_PASSWORD', '').strip('"'),
    'from_email': os.getenv('FROM_EMAIL', '').strip('"'),
    'from_name': os.getenv('FROM_NAME', 'SSH Guardian v3.0')
}

# Session configuration
SESSION_DURATION_DAYS = 30  # Remember me for 30 days (persistent across browser sessions)
OTP_VALIDITY_MINUTES = 5
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 30


class AuthenticationError(Exception):
    """Base exception for authentication errors"""
    pass


class EmailService:
    """Email service for sending OTPs and notifications"""

    @staticmethod
    def send_email(to_email, subject, body_html, body_text=None):
        """Send email using SMTP"""
        try:
            if not EMAIL_CONFIG['smtp_user'] or not EMAIL_CONFIG['smtp_password']:
                print(f"⚠️  Email not configured. OTP for {to_email}: Would send email")
                print(f"   Subject: {subject}")
                print(f"   Body: {body_text or 'See HTML body'}")
                return True

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{EMAIL_CONFIG['from_name']} <{EMAIL_CONFIG['from_email']}>"
            msg['To'] = to_email

            if body_text:
                part1 = MIMEText(body_text, 'plain')
                msg.attach(part1)

            part2 = MIMEText(body_html, 'html')
            msg.attach(part2)

            with smtplib.SMTP(EMAIL_CONFIG['smtp_host'], EMAIL_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['smtp_user'], EMAIL_CONFIG['smtp_password'])
                server.send_message(msg)

            return True

        except Exception as e:
            print(f"❌ Email send error: {e}")
            return False

    @staticmethod
    def send_otp_email(to_email, otp_code, full_name):
        """Send OTP email with v3.0 Azure-style branding"""
        subject = "SSH Guardian v3.0 - Your Login Code"

        body_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                       line-height: 1.6; color: #323130; background: #F3F2F1; margin: 0; padding: 20px; }}
                .container {{ max-width: 500px; margin: 0 auto; background: white;
                             border-radius: 4px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header {{ background: #0078D4; color: white; padding: 24px; text-align: center; }}
                .header h1 {{ margin: 0; font-size: 20px; font-weight: 600; }}
                .content {{ padding: 32px 24px; }}
                .otp-code {{ font-size: 32px; font-weight: 600; color: #0078D4;
                            letter-spacing: 8px; text-align: center; padding: 24px;
                            background: #F3F2F1; border-radius: 4px; margin: 24px 0;
                            border: 2px solid #0078D4; }}
                .info {{ color: #605E5C; font-size: 14px; margin: 16px 0; }}
                .warning {{ color: #D13438; font-size: 12px; margin-top: 24px;
                           padding: 12px; background: #FFF4F4; border-radius: 4px; }}
                .footer {{ text-align: center; color: #A19F9D; font-size: 12px;
                          padding: 24px; background: #F3F2F1; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>SSH Guardian v3.0</h1>
                </div>
                <div class="content">
                    <p>Hello <strong>{full_name}</strong>,</p>
                    <p class="info">Your verification code for signing in to SSH Guardian:</p>
                    <div class="otp-code">{otp_code}</div>
                    <p class="info">This code expires in <strong>{OTP_VALIDITY_MINUTES} minutes</strong>.</p>
                    <p class="info">If you didn't request this code, please ignore this email.</p>
                    <div class="warning">
                        ⚠️ Never share this code with anyone. SSH Guardian will never ask for your code.
                    </div>
                </div>
                <div class="footer">
                    <p>SSH Guardian v3.0 - Enterprise SSH Security Platform</p>
                    <p>This is an automated message, please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
        """

        body_text = f"""
        SSH Guardian v3.0 - Your Login Code

        Hello {full_name},

        Your verification code: {otp_code}

        This code expires in {OTP_VALIDITY_MINUTES} minutes.

        If you didn't request this code, please ignore this email.

        SSH Guardian v3.0
        """

        return EmailService.send_email(to_email, subject, body_html, body_text)


class PasswordManager:
    """Password hashing and validation"""

    @staticmethod
    def hash_password(password):
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(password, password_hash):
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

    @staticmethod
    def validate_password_strength(password):
        """Validate password meets security requirements"""
        errors = []

        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            errors.append("Password must contain at least one special character")

        return len(errors) == 0, errors


class OTPManager:
    """OTP generation and validation"""

    @staticmethod
    def generate_otp():
        """Generate 6-digit OTP"""
        return ''.join([str(secrets.randbelow(10)) for _ in range(6)])

    @staticmethod
    def create_otp(user_id, purpose='login', ip_address=None):
        """Create and store OTP"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            otp_code = OTPManager.generate_otp()
            expires_at = datetime.now() + timedelta(minutes=OTP_VALIDITY_MINUTES)

            cursor.execute("""
                INSERT INTO user_otps (user_id, otp_code, purpose, expires_at, ip_address)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, otp_code, purpose, expires_at, ip_address))

            conn.commit()
            return otp_code

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def verify_otp(user_id, otp_code, purpose='login'):
        """Verify OTP is valid and not expired"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM user_otps
                WHERE user_id = %s
                AND otp_code = %s
                AND purpose = %s
                AND expires_at > NOW()
                AND is_used = FALSE
                ORDER BY created_at DESC
                LIMIT 1
            """, (user_id, otp_code, purpose))

            otp = cursor.fetchone()

            if not otp:
                return False

            # Mark as used
            cursor.execute("""
                UPDATE user_otps
                SET is_used = TRUE, used_at = NOW()
                WHERE id = %s
            """, (otp['id'],))

            conn.commit()
            return True

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def cleanup_expired_otps():
        """Delete expired OTPs"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM user_otps
                WHERE expires_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            conn.commit()

        finally:
            cursor.close()
            conn.close()


class SessionManager:
    """Session management with secure cookies - persistent across browser sessions"""

    @staticmethod
    def generate_session_token():
        """Generate secure session token"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def create_session(user_id, ip_address=None, user_agent=None):
        """Create new session - always 30 days for persistent login"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            session_token = SessionManager.generate_session_token()
            # Always use 30 days - persistent across browser restarts
            expires_at = datetime.now() + timedelta(days=SESSION_DURATION_DAYS)

            cursor.execute("""
                INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent, expires_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, session_token, ip_address, user_agent, expires_at))

            conn.commit()

            return session_token, expires_at

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def validate_session(session_token):
        """Validate session token and return user"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT s.*, u.*, r.name as role_name, r.permissions
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                JOIN roles r ON u.role_id = r.id
                WHERE s.session_token = %s
                AND s.expires_at > NOW()
                AND u.is_active = TRUE
            """, (session_token,))

            session_data = cursor.fetchone()

            if session_data:
                # Update last activity
                cursor.execute("""
                    UPDATE user_sessions
                    SET last_activity = NOW()
                    WHERE session_token = %s
                """, (session_token,))
                conn.commit()

            return session_data

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_session(session_token):
        """Delete session (logout)"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM user_sessions
                WHERE session_token = %s
            """, (session_token,))

            conn.commit()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def cleanup_expired_sessions():
        """Delete expired sessions"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM user_sessions
                WHERE expires_at < NOW()
            """)
            conn.commit()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_user_from_session(session_token):
        """Get user data from session token"""
        session_data = SessionManager.validate_session(session_token)
        if not session_data:
            return None

        return {
            'id': session_data['user_id'],
            'email': session_data['email'],
            'full_name': session_data['full_name'],
            'role': session_data['role_name'],
            'permissions': json.loads(session_data['permissions']) if isinstance(session_data['permissions'], str) else session_data['permissions']
        }


class UserManager:
    """User management operations"""

    @staticmethod
    def get_user_by_email(email):
        """Get user by email"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT u.*, r.name as role_name, r.permissions
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.email = %s
            """, (email,))

            return cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_user_by_id(user_id):
        """Get user by ID"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT u.*, r.name as role_name, r.permissions
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.id = %s
            """, (user_id,))

            return cursor.fetchone()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def check_account_locked(user_id):
        """Check if account is locked"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT locked_until FROM users
                WHERE id = %s
            """, (user_id,))

            result = cursor.fetchone()

            if result and result['locked_until']:
                if result['locked_until'] > datetime.now():
                    return True, result['locked_until']
                else:
                    # Unlock account
                    cursor.execute("""
                        UPDATE users
                        SET locked_until = NULL, failed_login_attempts = 0
                        WHERE id = %s
                    """, (user_id,))
                    conn.commit()

            return False, None

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def record_failed_login(user_id):
        """Record failed login attempt"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE users
                SET failed_login_attempts = failed_login_attempts + 1
                WHERE id = %s
            """, (user_id,))

            # Check if should lock
            cursor.execute("""
                SELECT failed_login_attempts FROM users WHERE id = %s
            """, (user_id,))

            result = cursor.fetchone()

            if result and result[0] >= MAX_FAILED_ATTEMPTS:
                locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                cursor.execute("""
                    UPDATE users
                    SET locked_until = %s
                    WHERE id = %s
                """, (locked_until, user_id))

            conn.commit()

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def reset_failed_attempts(user_id):
        """Reset failed login attempts"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE users
                SET failed_login_attempts = 0, locked_until = NULL
                WHERE id = %s
            """, (user_id,))

            conn.commit()

        finally:
            cursor.close()
            conn.close()


class AuditLogger:
    """Audit logging for security actions"""

    @staticmethod
    def log_action(user_id, action, resource_type=None, resource_id=None, details=None,
                   ip_address=None, user_agent=None):
        """Log user action"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            details_json = json.dumps(details) if details else None

            cursor.execute("""
                INSERT INTO audit_logs (user_id, action, resource_type, resource_id,
                                       details, ip_address, user_agent)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, action, resource_type, resource_id, details_json,
                  ip_address, user_agent))

            conn.commit()

        finally:
            cursor.close()
            conn.close()


# Authentication decorators
def login_required(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.cookies.get('session_token')

        if not session_token:
            return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401

        session_data = SessionManager.validate_session(session_token)

        if not session_data:
            return jsonify({'error': 'Invalid or expired session', 'code': 'INVALID_SESSION'}), 401

        # Add user data to request context
        request.current_user = session_data

        return f(*args, **kwargs)

    return decorated_function


def permission_required(permission_name):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_token = request.cookies.get('session_token')

            if not session_token:
                return jsonify({'error': 'Authentication required'}), 401

            session_data = SessionManager.validate_session(session_token)

            if not session_data:
                return jsonify({'error': 'Invalid session'}), 401

            # Check permission
            permissions = json.loads(session_data['permissions']) if isinstance(session_data['permissions'], str) else session_data['permissions']

            if not permissions.get(permission_name, False):
                return jsonify({'error': 'Insufficient permissions'}), 403

            request.current_user = session_data

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def role_required(*role_names):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            session_token = request.cookies.get('session_token')

            if not session_token:
                return jsonify({'error': 'Authentication required'}), 401

            session_data = SessionManager.validate_session(session_token)

            if not session_data:
                return jsonify({'error': 'Invalid session'}), 401

            # Check role
            if session_data['role_name'] not in role_names:
                return jsonify({'error': 'Insufficient permissions'}), 403

            request.current_user = session_data

            return f(*args, **kwargs)

        return decorated_function

    return decorator
