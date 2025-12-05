"""
Users Routes - API endpoints for user management
With Redis caching for improved performance
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request
import bcrypt

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash

users_routes = Blueprint('users', __name__)

# Cache TTLs
USERS_LIST_TTL = 600         # 10 minutes for user list
USERS_ROLES_TTL = 3600       # 1 hour for roles (static data)
USERS_DETAIL_TTL = 600       # 10 minutes for single user detail


def invalidate_users_cache():
    """Invalidate all users-related caches"""
    cache = get_cache()
    cache.delete_pattern('users')


@users_routes.route('/list', methods=['GET'])
def list_users():
    """Get all users with their roles"""
    conn = None
    cursor = None
    try:
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('users', 'list')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

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

        result_data = {
            'users': users,
            'total': len(users)
        }

        # Cache the result
        cache.set(cache_k, result_data, USERS_LIST_TTL)

        return jsonify({
            'success': True,
            'data': result_data,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/roles', methods=['GET'])
def list_roles():
    """Get all available roles"""
    conn = None
    cursor = None
    try:
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('users', 'roles')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': {'roles': cached},
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, name, description, permissions
            FROM roles
            ORDER BY id
        """)

        roles = cursor.fetchall()

        # Cache the result
        cache.set(cache_k, roles, USERS_ROLES_TTL)

        return jsonify({
            'success': True,
            'data': {
                'roles': roles
            },
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/<int:user_id>', methods=['GET'])
def get_user(user_id):
    """Get a specific user"""
    conn = None
    cursor = None
    try:
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('users', 'detail', str(user_id))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

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

        # Cache the result
        cache.set(cache_k, user, USERS_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': user,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/create', methods=['POST'])
def create_user():
    """Create a new user"""
    conn = None
    cursor = None
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

            # Invalidate cache
            invalidate_users_cache()

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
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    """Update a user"""
    conn = None
    cursor = None
    try:
        data = request.get_json()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cursor.fetchone():
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
                return jsonify({
                    'success': False,
                    'error': 'Password must be at least 8 characters'
                }), 400
            password_hash = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            updates.append("password_hash = %s")
            params.append(password_hash)

        if not updates:
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

            # Invalidate cache
            invalidate_users_cache()
        except Exception as e:
            conn.rollback()
            if 'Duplicate entry' in str(e):
                return jsonify({
                    'success': False,
                    'error': 'Email already exists'
                }), 400
            raise e

        return jsonify({
            'success': True,
            'message': 'User updated successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/<int:user_id>/toggle-active', methods=['POST'])
def toggle_user_active(user_id):
    """Toggle user active status"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current status
        cursor.execute("SELECT is_active FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
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

        # Invalidate cache
        invalidate_users_cache()

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
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/<int:user_id>/unlock', methods=['POST'])
def unlock_user(user_id):
    """Unlock a locked user account"""
    conn = None
    cursor = None
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
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        # Invalidate cache
        invalidate_users_cache()

        return jsonify({
            'success': True,
            'message': 'User account unlocked successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete a user"""
    conn = None
    cursor = None
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
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        conn.commit()

        # Invalidate cache
        invalidate_users_cache()

        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@users_routes.route('/<int:user_id>/reset-password', methods=['POST'])
def reset_user_password(user_id):
    """Reset user password (admin action)"""
    conn = None
    cursor = None
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
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404

        conn.commit()

        # Invalidate cache
        invalidate_users_cache()

        return jsonify({
            'success': True,
            'message': 'Password reset successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
