"""
SSH Guardian v3.1 - Settings Routes
API endpoints for system settings management
Simplified and optimized for new database schema
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash, invalidate_on_settings_change
from auth import AuditLogger

settings_routes = Blueprint('settings', __name__)

# Cache TTL from environment (falls back to cache module defaults)
SETTINGS_CACHE_TTL = 300  # 5 minutes


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None


# =============================================================================
# SETTINGS LIST API
# =============================================================================

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
        cache_k = cache_key_hash('settings', 'list', category=category)
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if category:
            cursor.execute("""
                SELECT id, setting_key, setting_value, value_type, category,
                       description, is_sensitive
                FROM system_settings
                WHERE category = %s
                ORDER BY category, setting_key
            """, (category,))
        else:
            cursor.execute("""
                SELECT id, setting_key, setting_value, value_type, category,
                       description, is_sensitive
                FROM system_settings
                ORDER BY category, setting_key
            """)

        settings = cursor.fetchall()
        cursor.close()
        conn.close()

        # Group by category
        grouped = {}
        for setting in settings:
            cat = setting['category']
            if cat not in grouped:
                grouped[cat] = []
            # Map value_type to setting_type for frontend compatibility
            setting['setting_type'] = setting.pop('value_type', 'string')
            grouped[cat].append(setting)

        result = {'settings': settings, 'grouped': grouped}
        cache.set(cache_k, result, SETTINGS_CACHE_TTL)

        return jsonify({'success': True, 'data': result, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# UPDATE SETTINGS APIs
# =============================================================================

@settings_routes.route('/<int:setting_id>', methods=['PUT'])
def update_setting(setting_id):
    """
    Update a setting value by ID
    Body: { "setting_value": "new_value" }
    """
    try:
        data = request.get_json()
        setting_value = data.get('setting_value')

        if setting_value is None:
            return jsonify({'success': False, 'error': 'setting_value is required'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Update the setting
        user_id = get_current_user_id()
        cursor.execute("""
            UPDATE system_settings
            SET setting_value = %s, updated_by_user_id = %s, updated_at = NOW()
            WHERE id = %s
        """, (str(setting_value), user_id, setting_id))

        if cursor.rowcount == 0:
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Setting not found'}), 404

        conn.commit()

        # Get updated setting for response
        cursor.execute("""
            SELECT id, setting_key, setting_value, value_type as setting_type,
                   category, description
            FROM system_settings WHERE id = %s
        """, (setting_id,))
        setting = cursor.fetchone()

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_on_settings_change()

        # Audit log
        AuditLogger.log_action(
            user_id=user_id,
            action='setting_updated',
            resource_type='setting',
            resource_id=str(setting_id),
            details={'setting_key': setting['setting_key'] if setting else None, 'new_value': setting_value},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({'success': True, 'message': 'Setting updated', 'data': setting})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_routes.route('/bulk-update', methods=['POST'])
def bulk_update_settings():
    """
    Update multiple settings at once
    Body: { "settings": [{ "id": 1, "setting_value": "value" }, ...] }
    """
    try:
        data = request.get_json()
        settings = data.get('settings', [])

        if not settings:
            return jsonify({'success': False, 'error': 'settings array is required'}), 400

        conn = get_connection()
        cursor = conn.cursor()
        user_id = get_current_user_id()
        updated_count = 0

        for setting in settings:
            setting_id = setting.get('id')
            setting_value = setting.get('setting_value')

            if setting_id and setting_value is not None:
                cursor.execute("""
                    UPDATE system_settings
                    SET setting_value = %s, updated_by_user_id = %s, updated_at = NOW()
                    WHERE id = %s
                """, (str(setting_value), user_id, setting_id))
                updated_count += cursor.rowcount

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_on_settings_change()

        # Audit log
        AuditLogger.log_action(
            user_id=user_id,
            action='settings_bulk_updated',
            resource_type='setting',
            resource_id='bulk',
            details={'count': updated_count, 'setting_ids': [s.get('id') for s in settings]},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({'success': True, 'message': f'{updated_count} settings updated'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# NAVIGATION SETTINGS
# =============================================================================

# Available landing pages - defined once
AVAILABLE_LANDING_PAGES = [
    {'value': 'overview', 'label': 'Overview (User Guide & Research)'},
    {'value': 'dashboard', 'label': 'Dashboard (Analytics)'},
    {'value': 'events-live', 'label': 'Live Events'}
]


@settings_routes.route('/navigation', methods=['GET'])
def get_navigation_settings():
    """Get navigation settings (default landing page)"""
    try:
        cache = get_cache()
        cache_k = cache_key('settings', 'navigation')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT setting_key, setting_value
            FROM system_settings
            WHERE setting_key = 'default_landing_page'
        """)
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        result = {
            'default_landing_page': row['setting_value'] if row else 'overview',
            'available_landing_pages': AVAILABLE_LANDING_PAGES
        }

        cache.set(cache_k, result, SETTINGS_CACHE_TTL)
        return jsonify({'success': True, 'data': result, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_routes.route('/navigation', methods=['PUT'])
def update_navigation_settings():
    """
    Update navigation settings
    Body: { "default_landing_page": "overview" }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        new_page = data.get('default_landing_page')
        valid_pages = [p['value'] for p in AVAILABLE_LANDING_PAGES]

        if new_page and new_page not in valid_pages:
            return jsonify({
                'success': False,
                'error': f'Invalid landing page. Must be one of: {", ".join(valid_pages)}'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()
        user_id = get_current_user_id()

        # Upsert the setting
        cursor.execute("""
            INSERT INTO system_settings (setting_key, setting_value, value_type, category, description, updated_by_user_id)
            VALUES ('default_landing_page', %s, 'string', 'navigation', 'Default page shown after login', %s)
            ON DUPLICATE KEY UPDATE
                setting_value = VALUES(setting_value),
                updated_by_user_id = VALUES(updated_by_user_id),
                updated_at = NOW()
        """, (new_page, user_id))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_on_settings_change()

        # Audit log
        AuditLogger.log_action(
            user_id=user_id,
            action='navigation_settings_updated',
            resource_type='setting',
            resource_id='navigation',
            details={'default_landing_page': new_page},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({'success': True, 'message': 'Navigation settings updated'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# TIME SETTINGS
# =============================================================================

# Available options - defined once
AVAILABLE_TIMEZONES = [
    'Local', 'UTC',
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

AVAILABLE_TIME_FORMATS = ['12h', '24h']
AVAILABLE_DATE_FORMATS = ['YYYY-MM-DD', 'DD/MM/YYYY', 'MM/DD/YYYY', 'DD-MM-YYYY']

TIME_SETTING_KEYS = ['time_format', 'date_format', 'timezone', 'datetime_format']


@settings_routes.route('/time', methods=['GET'])
def get_time_settings():
    """Get time-related settings (timezone, format)"""
    try:
        cache = get_cache()
        cache_k = cache_key('settings', 'time')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

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

        # Convert to dictionary with defaults
        result = {row['setting_key']: row['setting_value'] for row in rows}

        # Add available options for frontend
        result['available_timezones'] = AVAILABLE_TIMEZONES
        result['available_time_formats'] = AVAILABLE_TIME_FORMATS
        result['available_date_formats'] = AVAILABLE_DATE_FORMATS

        cache.set(cache_k, result, SETTINGS_CACHE_TTL)
        return jsonify({'success': True, 'data': result, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_routes.route('/time', methods=['PUT'])
def update_time_settings():
    """
    Update time-related settings
    Body: { "time_format": "24h", "date_format": "YYYY-MM-DD", "timezone": "UTC" }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        conn = get_connection()
        cursor = conn.cursor()
        user_id = get_current_user_id()
        updated = []

        for key in TIME_SETTING_KEYS:
            if key in data and data[key] is not None:
                cursor.execute("""
                    UPDATE system_settings
                    SET setting_value = %s, updated_by_user_id = %s, updated_at = NOW()
                    WHERE setting_key = %s
                """, (str(data[key]), user_id, key))
                if cursor.rowcount > 0:
                    updated.append(key)

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_on_settings_change()

        # Audit log
        if updated:
            AuditLogger.log_action(
                user_id=user_id,
                action='time_settings_updated',
                resource_type='setting',
                resource_id='time',
                details={'updated': updated, 'values': {k: data.get(k) for k in updated}},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

        return jsonify({
            'success': True,
            'message': f'Time settings updated: {", ".join(updated)}' if updated else 'No changes',
            'updated': updated
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# DATA MANAGEMENT
# =============================================================================

@settings_routes.route('/data-stats', methods=['GET'])
def get_data_stats():
    """Get record counts for clearable data tables"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        stats = {}

        # Get counts for each table
        tables = [
            ('auth_events', 'Event Logs'),
            ('ip_blocks', 'IP Block List'),
            ('blocking_actions', 'Blocking History'),
            ('notifications', 'Notifications'),
            ('agent_log_batches', 'Agent Log Batches')
        ]

        for table_name, label in tables:
            try:
                cursor.execute(f"SELECT COUNT(*) as count FROM {table_name}")
                result = cursor.fetchone()
                stats[table_name] = {
                    'count': result['count'] if result else 0,
                    'label': label
                }
            except Exception:
                stats[table_name] = {'count': 0, 'label': label, 'error': True}

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'data': stats})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_routes.route('/clear-data/<table_name>', methods=['DELETE'])
def clear_data(table_name):
    """
    Clear data from a specific table
    Allowed tables: auth_events, ip_blocks, notifications, agent_log_batches
    """
    try:
        allowed_tables = ['auth_events', 'ip_blocks', 'blocking_actions', 'notifications', 'agent_log_batches']

        if table_name not in allowed_tables:
            return jsonify({
                'success': False,
                'error': f'Table not allowed. Must be one of: {", ".join(allowed_tables)}'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()
        user_id = get_current_user_id()

        # Get count before clearing
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count_before = cursor.fetchone()[0]

        # Clear the table
        cursor.execute(f"DELETE FROM {table_name}")
        conn.commit()

        cursor.close()
        conn.close()

        # Invalidate cache
        invalidate_on_settings_change()

        # Audit log
        AuditLogger.log_action(
            user_id=user_id,
            action='data_cleared',
            resource_type='table',
            resource_id=table_name,
            details={'table': table_name, 'records_cleared': count_before},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        return jsonify({
            'success': True,
            'message': f'Cleared {count_before} records from {table_name}',
            'records_cleared': count_before
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_routes.route('/export-database', methods=['POST'])
def export_database():
    """
    Export full database as SQL dump (structure + data)
    Returns SQL file content
    """
    try:
        import subprocess
        from flask import Response
        from datetime import datetime

        # Get database credentials from connection
        conn = get_connection()
        db_name = conn.database
        conn.close()

        # Generate timestamp for filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'ssh_guardian_full_backup_{timestamp}.sql'

        # Full database export with structure and data
        cmd = [
            'mysqldump',
            '-u', 'root',
            '-p123123',
            '--single-transaction',
            '--routines',
            '--triggers',
            '--skip-lock-tables',
            '--default-character-set=utf8mb4',
            db_name
        ]

        # Execute mysqldump
        result = subprocess.run(cmd, capture_output=True)

        if result.returncode != 0:
            error_msg = result.stderr.decode('utf-8', errors='ignore')
            return jsonify({'success': False, 'error': f'mysqldump failed: {error_msg}'}), 500

        sql_content = result.stdout

        if not sql_content:
            return jsonify({'success': False, 'error': 'Failed to generate database export'}), 500

        # Add header comment
        header = f"""-- ============================================
-- SSH Guardian v3.0 Full Database Export
-- Generated: {datetime.now().isoformat()}
-- Database: {db_name}
-- ============================================

""".encode('utf-8')

        sql_content = header + sql_content

        # Audit log
        user_id = get_current_user_id()
        AuditLogger.log_action(
            user_id=user_id,
            action='database_exported',
            resource_type='database',
            resource_id='full_export',
            details={'database': db_name, 'filename': filename, 'size_bytes': len(sql_content)},
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )

        # Return as downloadable file
        return Response(
            sql_content,
            mimetype='application/octet-stream',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/sql; charset=utf-8'
            }
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
