"""
Settings Routes - API endpoints for system settings management
With Redis caching for improved performance
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash
from auth import AuditLogger

settings_routes = Blueprint('settings', __name__)


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None


# Cache TTLs - OPTIMIZED FOR PERFORMANCE
SETTINGS_LIST_TTL = 1800      # 30 minutes for settings list
SETTINGS_DETAIL_TTL = 1800    # 30 minutes for single setting detail


def invalidate_settings_cache():
    """Invalidate all settings caches"""
    cache = get_cache()
    cache.delete_pattern('settings')


@settings_routes.route('/list', methods=['GET'])
def get_settings():
    """
    Get all settings or filter by category
    Query params:
    - category: Filter by category (optional)
    """
    try:
        category = request.args.get('category', '')

        # Try cache first
        cache = get_cache()
        cache_params = {'category': category}
        cache_k = cache_key_hash('settings', 'list', cache_params)
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if category:
            cursor.execute("""
                SELECT id, setting_key, setting_value, setting_type, category, description, is_sensitive
                FROM system_settings
                WHERE category = %s
                ORDER BY category, setting_key
            """, (category,))
        else:
            cursor.execute("""
                SELECT id, setting_key, setting_value, setting_type, category, description, is_sensitive
                FROM system_settings
                ORDER BY category, setting_key
            """)

        settings = cursor.fetchall()

        # Group by category
        grouped_settings = {}
        for setting in settings:
            cat = setting['category']
            if cat not in grouped_settings:
                grouped_settings[cat] = []
            grouped_settings[cat].append(setting)

        cursor.close()
        conn.close()

        result_data = {
            'settings': settings,
            'grouped': grouped_settings
        }

        # Cache the result
        cache.set(cache_k, result_data, SETTINGS_LIST_TTL)

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


@settings_routes.route('/<int:setting_id>', methods=['GET'])
def get_setting(setting_id):
    """
    Get a specific setting by ID
    """
    try:
        # Try cache first
        cache = get_cache()
        cache_k = cache_key('settings', 'detail', str(setting_id))
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
            SELECT id, setting_key, setting_value, setting_type, category, description, is_sensitive
            FROM system_settings
            WHERE id = %s
        """, (setting_id,))

        setting = cursor.fetchone()

        cursor.close()
        conn.close()

        if not setting:
            return jsonify({
                'success': False,
                'error': 'Setting not found'
            }), 404

        # Cache the result
        cache.set(cache_k, setting, SETTINGS_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': setting,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_routes.route('/<int:setting_id>', methods=['PUT'])
def update_setting(setting_id):
    """
    Update a setting value
    Body params:
    - setting_value: New value for the setting
    """
    try:
        data = request.get_json()
        setting_value = data.get('setting_value')

        if setting_value is None:
            return jsonify({
                'success': False,
                'error': 'setting_value is required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Update the setting
        cursor.execute("""
            UPDATE system_settings
            SET setting_value = %s, updated_at = NOW()
            WHERE id = %s
        """, (str(setting_value), setting_id))

        conn.commit()

        # Get the updated setting
        cursor.execute("""
            SELECT id, setting_key, setting_value, setting_type, category, description
            FROM system_settings
            WHERE id = %s
        """, (setting_id,))

        setting = cursor.fetchone()

        cursor.close()
        conn.close()

        # Invalidate cache after update
        invalidate_settings_cache()

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='setting_updated',
            resource_type='setting',
            resource_id=str(setting_id),
            details={'setting_key': setting['setting_key'] if setting else None, 'new_value': setting_value},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': 'Setting updated successfully',
            'data': setting
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_routes.route('/bulk-update', methods=['POST'])
def bulk_update_settings():
    """
    Update multiple settings at once
    Body params:
    - settings: Array of {id, setting_value} objects
    """
    try:
        data = request.get_json()
        settings = data.get('settings', [])

        if not settings:
            return jsonify({
                'success': False,
                'error': 'settings array is required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        # Update each setting
        for setting in settings:
            setting_id = setting.get('id')
            setting_value = setting.get('setting_value')

            if setting_id and setting_value is not None:
                cursor.execute("""
                    UPDATE system_settings
                    SET setting_value = %s, updated_at = NOW()
                    WHERE id = %s
                """, (str(setting_value), setting_id))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache after bulk update
        invalidate_settings_cache()

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='settings_bulk_updated',
            resource_type='setting',
            resource_id='bulk',
            details={'settings_count': len(settings), 'setting_ids': [s.get('id') for s in settings]},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': f'{len(settings)} settings updated successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_routes.route('/key/<setting_key>', methods=['GET'])
def get_setting_by_key(setting_key):
    """
    Get a setting by its key name
    """
    try:
        cache = get_cache()
        cache_k = cache_key('settings', 'key', setting_key)
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
            SELECT id, setting_key, setting_value, setting_type, category, description
            FROM system_settings
            WHERE setting_key = %s
        """, (setting_key,))

        setting = cursor.fetchone()
        cursor.close()
        conn.close()

        if not setting:
            return jsonify({
                'success': False,
                'error': f'Setting "{setting_key}" not found'
            }), 404

        cache.set(cache_k, setting, SETTINGS_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': setting,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_routes.route('/key/<setting_key>', methods=['PUT'])
def update_setting_by_key(setting_key):
    """
    Update a setting by its key name
    Body params:
    - setting_value: New value for the setting
    """
    try:
        data = request.get_json()
        setting_value = data.get('setting_value')

        if setting_value is None:
            return jsonify({
                'success': False,
                'error': 'setting_value is required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            UPDATE system_settings
            SET setting_value = %s, updated_at = NOW()
            WHERE setting_key = %s
        """, (str(setting_value), setting_key))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': f'Setting "{setting_key}" not found'
            }), 404

        conn.commit()

        cursor.execute("""
            SELECT id, setting_key, setting_value, setting_type, category, description
            FROM system_settings
            WHERE setting_key = %s
        """, (setting_key,))

        setting = cursor.fetchone()
        cursor.close()
        conn.close()

        invalidate_settings_cache()

        # Audit log
        AuditLogger.log_action(
            user_id=get_current_user_id(),
            action='setting_updated',
            resource_type='setting',
            resource_id=setting_key,
            details={'setting_key': setting_key, 'new_value': setting_value},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': f'Setting "{setting_key}" updated successfully',
            'data': setting
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_routes.route('/time', methods=['GET'])
def get_time_settings():
    """
    Get all time-related settings (timezone, format, etc.)
    """
    try:
        cache = get_cache()
        cache_k = cache_key('settings', 'time', 'all')
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
            SELECT setting_key, setting_value
            FROM system_settings
            WHERE setting_key IN ('time_format', 'date_format', 'timezone', 'datetime_format')
        """)

        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert to dictionary
        time_settings = {row['setting_key']: row['setting_value'] for row in rows}

        # Add comprehensive timezone list for frontend
        time_settings['available_timezones'] = [
            # UTC
            'UTC',
            # Americas
            'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
            'America/Phoenix', 'America/Anchorage', 'America/Toronto', 'America/Vancouver',
            'America/Mexico_City', 'America/Bogota', 'America/Lima', 'America/Santiago',
            'America/Sao_Paulo', 'America/Buenos_Aires', 'America/Caracas',
            # Europe
            'Europe/London', 'Europe/Dublin', 'Europe/Paris', 'Europe/Berlin', 'Europe/Rome',
            'Europe/Madrid', 'Europe/Amsterdam', 'Europe/Brussels', 'Europe/Vienna',
            'Europe/Warsaw', 'Europe/Prague', 'Europe/Stockholm', 'Europe/Oslo',
            'Europe/Helsinki', 'Europe/Athens', 'Europe/Moscow', 'Europe/Istanbul',
            # Asia
            'Asia/Dubai', 'Asia/Riyadh', 'Asia/Tehran', 'Asia/Karachi', 'Asia/Kolkata',
            'Asia/Dhaka', 'Asia/Bangkok', 'Asia/Jakarta', 'Asia/Ho_Chi_Minh',
            'Asia/Kuala_Lumpur', 'Asia/Singapore', 'Asia/Hong_Kong', 'Asia/Shanghai',
            'Asia/Taipei', 'Asia/Seoul', 'Asia/Tokyo', 'Asia/Manila',
            # Africa
            'Africa/Cairo', 'Africa/Lagos', 'Africa/Johannesburg', 'Africa/Nairobi',
            # Australia & Pacific
            'Australia/Perth', 'Australia/Adelaide', 'Australia/Sydney', 'Australia/Brisbane',
            'Australia/Melbourne', 'Pacific/Auckland', 'Pacific/Fiji', 'Pacific/Honolulu'
        ]

        time_settings['available_time_formats'] = ['12h', '24h']
        time_settings['available_date_formats'] = ['YYYY-MM-DD', 'DD/MM/YYYY', 'MM/DD/YYYY', 'DD-MM-YYYY']

        cache.set(cache_k, time_settings, SETTINGS_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': time_settings,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@settings_routes.route('/time', methods=['PUT'])
def update_time_settings():
    """
    Update time-related settings
    Body params:
    - time_format: '12h' or '24h'
    - date_format: 'YYYY-MM-DD', 'DD/MM/YYYY', 'MM/DD/YYYY'
    - timezone: Timezone string
    - datetime_format: Full datetime format string
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        valid_keys = ['time_format', 'date_format', 'timezone', 'datetime_format']
        updated = []

        for key in valid_keys:
            if key in data and data[key] is not None:
                cursor.execute("""
                    UPDATE system_settings
                    SET setting_value = %s, updated_at = NOW()
                    WHERE setting_key = %s
                """, (str(data[key]), key))
                if cursor.rowcount > 0:
                    updated.append(key)

        conn.commit()
        cursor.close()
        conn.close()

        invalidate_settings_cache()

        # Audit log
        if updated:
            AuditLogger.log_action(
                user_id=get_current_user_id(),
                action='time_settings_updated',
                resource_type='setting',
                resource_id='time',
                details={'updated_keys': updated, 'new_values': {k: data.get(k) for k in updated}},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

        return jsonify({
            'success': True,
            'message': f'Time settings updated: {", ".join(updated)}',
            'updated': updated
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
