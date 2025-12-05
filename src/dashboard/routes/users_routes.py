"""
Users Routes - API endpoints for user management
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request
import bcrypt

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

users_routes = Blueprint('users', __name__)


@users_routes.route('/list', methods=['GET'])
def list_users():
    """Get all users with their roles"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                u.id, u.email, u.full_name, u.role_id,
                u.is_active, u.is_email_verified,
                u.last_login, u.failed_login_attempts,
                u.locked_until, u.created_at, u.updated_at,
                r.name as role_name, r.description as role_description
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            ORDER BY u.created_at DESC
        """)

        users = cursor.fetchall()

        # Format timestamps
        for user in users:
            if user['last_login']:
                user['last_login'] = user['last_login'].isoformat()
            if user['locked_until']:
                user['locked_until'] = user['locked_until'].isoformat()
            if user['created_at']:
                user['created_at'] = user['created_at'].isoformat()
            if user['updated_at']:
                user['updated_at'] = user['updated_at'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'users': users,
                'total': len(users)
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/roles', methods=['GET'])
def list_roles():
    """Get all available roles"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, name, description, permissions
            FROM roles
            ORDER BY id
        """)

        roles = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'roles': roles
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a specific user"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                u.id, u.email, u.full_name, u.role_id,
                u.is_active, u.is_email_verified,
                u.last_login, u.failed_login_attempts,
                u.locked_until, u.created_at, u.updated_at,
                r.name as role_name, r.description as role_description
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = %s
        """, (user_id,))

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        # Format timestamps
        if user['last_login']:
            user['last_login'] = user['last_login'].isoformat()
        if user['locked_until']:
            user['locked_until'] = user['locked_until'].isoformat()
        if user['created_at']:
            user['created_at'] = user['created_at'].isoformat()
        if user['updated_at']:
            user['updated_at'] = user['updated_at'].isoformat()

        return jsonify({
            'success': True,
            'data': user
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/create', methods=['POST'])
def create_user():
    """Create a new user"""
    try:
        data = request.get_json()

        email = data.get('email', '').strip().lower()
        full_name = data.get('full_name', '').strip()
        password = data.get('password', '')
        role_id = data.get('role_id', 4)  # Default to Viewer
        is_active = data.get('is_active', True)

        if not email or not full_name or not password:
            return jsonify({
                'success': False,
                'error': 'email, full_name, and password are required'
            }), 400

        if len(password) < 8:
            return jsonify({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }), 400

        # Hash password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (email, password_hash, full_name, role_id, is_active, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            """, (email, password_hash, full_name, role_id, is_active))

            conn.commit()
            new_user_id = cursor.lastrowid

            cursor.close()
            conn.close()

            return jsonify({
                'success': True,
                'message': 'User created successfully',
                'data': {
                    'id': new_user_id,
                    'email': email,
                    'full_name': full_name
                }
            })

        except Exception as e:
            conn.rollback()
            cursor.close()
            conn.close()

            if 'Duplicate entry' in str(e):
                return jsonify({
                    'success': False,
                    'error': f'A user with email "{email}" already exists'
                }), 400

            raise e

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update a user"""
    try:
        data = request.get_json()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        # Build update query dynamically
        updates = []
        params = []

        if 'full_name' in data:
            updates.append("full_name = %s")
            params.append(data['full_name'].strip())

        if 'email' in data:
            updates.append("email = %s")
            params.append(data['email'].strip().lower())

        if 'role_id' in data:
            updates.append("role_id = %s")
            params.append(data['role_id'])

        if 'is_active' in data:
            updates.append("is_active = %s")
            params.append(data['is_active'])

        if 'is_email_verified' in data:
            updates.append("is_email_verified = %s")
            params.append(data['is_email_verified'])

        if 'password' in data and data['password']:
            if len(data['password']) < 8:
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Password must be at least 8 characters'
                }), 400
            password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            updates.append("password_hash = %s")
            params.append(password_hash)

        if not updates:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'No fields to update'
            }), 400

        updates.append("updated_at = NOW()")
        params.append(user_id)

        query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"

        try:
            cursor.execute(query, params)
            conn.commit()
        except Exception as e:
            conn.rollback()
            if 'Duplicate entry' in str(e):
                cursor.close()
                conn.close()
                return jsonify({
                    'success': False,
                    'error': 'Email already exists'
                }), 400
            raise e

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'User updated successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/<int:user_id>/toggle-active', methods=['POST'])
def toggle_user_active(user_id):
    """Toggle user active status"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current status
        cursor.execute("SELECT is_active FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        new_status = not user['is_active']

        cursor.execute("""
            UPDATE users SET is_active = %s, updated_at = NOW()
            WHERE id = %s
        """, (new_status, user_id))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': f"User {'activated' if new_status else 'deactivated'} successfully",
            'data': {'is_active': new_status}
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/<int:user_id>/unlock', methods=['POST'])
def unlock_user(user_id):
    """Unlock a locked user account"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET locked_until = NULL, failed_login_attempts = 0, updated_at = NOW()
            WHERE id = %s
        """, (user_id,))

        conn.commit()

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'User account unlocked successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete a user"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Prevent deleting the last super admin
        cursor.execute("""
            SELECT COUNT(*) as count FROM users
            WHERE role_id = 1 AND is_active = TRUE AND id != %s
        """, (user_id,))
        result = cursor.fetchone()

        cursor.execute("SELECT role_id FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if user and user[0] == 1 and result[0] == 0:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Cannot delete the last active Super Admin'
            }), 400

        # Delete user sessions first
        cursor.execute("DELETE FROM user_sessions WHERE user_id = %s", (user_id,))
        cursor.execute("DELETE FROM user_otps WHERE user_id = %s", (user_id,))

        # Delete the user
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))

        if cursor.rowcount == 0:
            conn.rollback()
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@users_routes.route('/<int:user_id>/reset-password', methods=['POST'])
def reset_user_password(user_id):
    """Reset user password (admin action)"""
    try:
        data = request.get_json()
        new_password = data.get('password', '')

        if len(new_password) < 8:
            return jsonify({
                'success': False,
                'error': 'Password must be at least 8 characters'
            }), 400

        password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET password_hash = %s, failed_login_attempts = 0, locked_until = NULL, updated_at = NOW()
            WHERE id = %s
        """, (password_hash, user_id))

        if cursor.rowcount == 0:
            conn.rollback()
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'message': 'Password reset successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
