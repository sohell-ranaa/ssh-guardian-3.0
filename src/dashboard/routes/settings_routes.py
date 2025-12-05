"""
Settings Routes - API endpoints for system settings management
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

settings_routes = Blueprint('settings', __name__)


@settings_routes.route('/list', methods=['GET'])
def get_settings():
    """
    Get all settings or filter by category
    Query params:
    - category: Filter by category (optional)
    """
    try:
        category = request.args.get('category', '')

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

        return jsonify({
            'success': True,
            'data': {
                'settings': settings,
                'grouped': grouped_settings
            }
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

        return jsonify({
            'success': True,
            'data': setting
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

        return jsonify({
            'success': True,
            'message': f'{len(settings)} settings updated successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
