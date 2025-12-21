"""
SSH Guardian v3.0 - Event Actions Routes
API endpoints for Events Live page actionable functions (whitelist, watchlist, notes, reports)
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path
import uuid
from datetime import datetime, timedelta

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection, is_valid_ip
from cache import get_cache, cache_key, cache_key_hash

# Create Blueprint
event_actions_routes = Blueprint('event_actions_routes', __name__, url_prefix='/api/dashboard/event-actions')

# Cache TTLs - OPTIMIZED FOR FRESHNESS (data changes frequently)
EVENT_ACTIONS_TTL = 30      # 30 seconds for event actions data
IP_STATUS_TTL = 30          # 30 seconds for IP status checks


def invalidate_event_actions_cache():
    """Invalidate all event-actions related caches"""
    cache = get_cache()
    cache.delete_pattern('event_actions')


# ============================================================================
# WHITELIST ACTIONS
# ============================================================================

@event_actions_routes.route('/whitelist', methods=['POST'])
def add_to_whitelist():
    """
    Add IP to whitelist

    Request JSON:
    {
        "ip_address": "192.168.1.100",
        "reason": "Trusted server",
        "expires_minutes": 1440  # Optional, default no expiration
    }
    """
    try:
        data = request.get_json()

        if not data or 'ip_address' not in data or 'reason' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required fields: ip_address, reason'
            }), 400

        ip_address = data['ip_address'].strip()
        reason = data['reason'].strip()
        expires_minutes = data.get('expires_minutes')

        # Validate IP format
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check if already whitelisted
            cursor.execute("""
                SELECT id, is_active
                FROM ip_whitelist
                WHERE ip_address_text = %s
            """, (ip_address,))

            existing = cursor.fetchone()

            if existing and existing['is_active']:
                return jsonify({
                    'success': False,
                    'error': 'IP address is already whitelisted'
                }), 400

            # MUTUAL EXCLUSIVITY: Remove from blocklist if exists
            cursor.execute("""
                UPDATE ip_blocks
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))
            removed_from_blocklist = cursor.rowcount > 0

            # MUTUAL EXCLUSIVITY: Remove from watchlist if exists
            cursor.execute("""
                UPDATE ip_watchlist
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))
            removed_from_watchlist = cursor.rowcount > 0

            # Calculate expiration timestamp if provided
            expires_at = None
            if expires_minutes:
                expires_at = datetime.now() + timedelta(minutes=expires_minutes)

            # Add to whitelist
            cursor.execute("""
                INSERT INTO ip_whitelist (
                    ip_address_text,
                    whitelist_reason,
                    whitelist_source,
                    is_active,
                    expires_at,
                    created_by_user_id
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                ip_address,
                reason,
                'manual',
                True,
                expires_at,
                None  # TODO: Get from session
            ))

            whitelist_id = cursor.lastrowid
            conn.commit()

            # Invalidate cache
            invalidate_event_actions_cache()

            # Build message with removals info
            msg = f'IP {ip_address} added to whitelist'
            if removed_from_blocklist:
                msg += ' (removed from blocklist)'
            if removed_from_watchlist:
                msg += ' (removed from watchlist)'

            return jsonify({
                'success': True,
                'whitelist_id': whitelist_id,
                'message': msg,
                'removed_from_blocklist': removed_from_blocklist,
                'removed_from_watchlist': removed_from_watchlist
            }), 201

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error adding to whitelist: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to add IP to whitelist'
        }), 500


@event_actions_routes.route('/whitelist/<ip_address>', methods=['DELETE'])
def remove_from_whitelist(ip_address):
    """Remove IP from whitelist"""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Set is_active to false instead of deleting
            cursor.execute("""
                UPDATE ip_whitelist
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))

            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'error': 'IP not found in whitelist or already removed'
                }), 404

            conn.commit()

            # Invalidate cache
            invalidate_event_actions_cache()

            return jsonify({
                'success': True,
                'message': f'IP {ip_address} removed from whitelist'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error removing from whitelist: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to remove IP from whitelist'
        }), 500


@event_actions_routes.route('/whitelist/check/<ip_address>', methods=['GET'])
def check_whitelist(ip_address):
    """Check if IP is whitelisted"""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        cache = get_cache()
        cache_k = cache_key('event_actions', 'whitelist_check', ip_address)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    id,
                    whitelist_reason,
                    expires_at,
                    created_at
                FROM ip_whitelist
                WHERE ip_address_text = %s
                AND is_active = TRUE
                AND (expires_at IS NULL OR expires_at > NOW())
            """, (ip_address,))

            whitelist_entry = cursor.fetchone()

            if whitelist_entry:
                result = {
                    'success': True,
                    'is_whitelisted': True,
                    'whitelist_info': {
                        'id': whitelist_entry['id'],
                        'reason': whitelist_entry['whitelist_reason'],
                        'expires_at': whitelist_entry['expires_at'].isoformat() if whitelist_entry['expires_at'] else None,
                        'created_at': whitelist_entry['created_at'].isoformat() if whitelist_entry['created_at'] else None
                    },
                    'from_cache': False
                }
            else:
                result = {
                    'success': True,
                    'is_whitelisted': False,
                    'whitelist_info': None,
                    'from_cache': False
                }

            # Cache the result
            cache.set(cache_k, result, EVENT_ACTIONS_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error checking whitelist: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to check whitelist status'
        }), 500


# ============================================================================
# WATCHLIST ACTIONS
# ============================================================================

@event_actions_routes.route('/watchlist', methods=['POST'])
def add_to_watchlist():
    """
    Add IP to watchlist

    Request JSON:
    {
        "ip_address": "192.168.1.100",
        "reason": "Suspicious activity",
        "watch_level": "medium",  # low, medium, high, critical
        "notify_on_activity": true,
        "event_id": 12345  # Optional
    }
    """
    try:
        data = request.get_json()

        required_fields = ['ip_address', 'reason', 'watch_level']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400

        ip_address = data['ip_address'].strip()
        reason = data['reason'].strip()
        watch_level = data['watch_level'].lower()
        notify_on_activity = data.get('notify_on_activity', True)
        event_id = data.get('event_id')

        # Validate IP format
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        # Validate watch level
        valid_levels = ['low', 'medium', 'high', 'critical']
        if watch_level not in valid_levels:
            return jsonify({
                'success': False,
                'error': f'Invalid watch_level. Must be one of: {", ".join(valid_levels)}'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check if already on watchlist
            cursor.execute("""
                SELECT id, is_active
                FROM ip_watchlist
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))

            existing = cursor.fetchone()

            if existing:
                return jsonify({
                    'success': False,
                    'error': 'IP address is already on watchlist'
                }), 400

            # MUTUAL EXCLUSIVITY: Remove from blocklist if exists
            cursor.execute("""
                UPDATE ip_blocks
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))
            removed_from_blocklist = cursor.rowcount > 0

            # MUTUAL EXCLUSIVITY: Remove from whitelist if exists
            cursor.execute("""
                UPDATE ip_whitelist
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))
            removed_from_whitelist = cursor.rowcount > 0

            # Add to watchlist
            cursor.execute("""
                INSERT INTO ip_watchlist (
                    ip_address_text,
                    watch_reason,
                    watch_level,
                    trigger_event_id,
                    is_active,
                    notify_on_activity,
                    created_by_user_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                ip_address,
                reason,
                watch_level,
                event_id,
                True,
                notify_on_activity,
                None  # TODO: Get from session
            ))

            watchlist_id = cursor.lastrowid
            conn.commit()

            # Invalidate cache
            invalidate_event_actions_cache()

            # Build message with removals info
            msg = f'IP {ip_address} added to watchlist with {watch_level} level'
            if removed_from_blocklist:
                msg += ' (removed from blocklist)'
            if removed_from_whitelist:
                msg += ' (removed from whitelist)'

            return jsonify({
                'success': True,
                'watchlist_id': watchlist_id,
                'message': msg,
                'removed_from_blocklist': removed_from_blocklist,
                'removed_from_whitelist': removed_from_whitelist
            }), 201

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error adding to watchlist: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to add IP to watchlist'
        }), 500


@event_actions_routes.route('/watchlist/<ip_address>', methods=['DELETE'])
def remove_from_watchlist(ip_address):
    """Remove IP from watchlist"""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Set is_active to false instead of deleting
            cursor.execute("""
                UPDATE ip_watchlist
                SET is_active = FALSE, updated_at = NOW()
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))

            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'error': 'IP not found in watchlist or already removed'
                }), 404

            conn.commit()

            # Invalidate cache
            invalidate_event_actions_cache()

            return jsonify({
                'success': True,
                'message': f'IP {ip_address} removed from watchlist'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error removing from watchlist: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to remove IP from watchlist'
        }), 500


@event_actions_routes.route('/watchlist/check/<ip_address>', methods=['GET'])
def check_watchlist(ip_address):
    """Check if IP is on watchlist"""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        cache = get_cache()
        cache_k = cache_key('event_actions', 'watchlist_check', ip_address)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    id,
                    watch_reason,
                    watch_level,
                    notify_on_activity,
                    expires_at,
                    created_at
                FROM ip_watchlist
                WHERE ip_address_text = %s
                AND is_active = TRUE
                AND (expires_at IS NULL OR expires_at > NOW())
            """, (ip_address,))

            watchlist_entry = cursor.fetchone()

            if watchlist_entry:
                result = {
                    'success': True,
                    'is_watched': True,
                    'watchlist_info': {
                        'id': watchlist_entry['id'],
                        'reason': watchlist_entry['watch_reason'],
                        'level': watchlist_entry['watch_level'],
                        'notify_on_activity': bool(watchlist_entry['notify_on_activity']),
                        'expires_at': watchlist_entry['expires_at'].isoformat() if watchlist_entry['expires_at'] else None,
                        'created_at': watchlist_entry['created_at'].isoformat() if watchlist_entry['created_at'] else None
                    },
                    'from_cache': False
                }
            else:
                result = {
                    'success': True,
                    'is_watched': False,
                    'watchlist_info': None,
                    'from_cache': False
                }

            # Cache the result
            cache.set(cache_k, result, EVENT_ACTIONS_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error checking watchlist: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to check watchlist status'
        }), 500


# ============================================================================
# NOTES ACTIONS
# ============================================================================

@event_actions_routes.route('/notes', methods=['POST'])
def add_note():
    """
    Add note to event or IP

    Request JSON:
    {
        "note_type": "event",  # or "ip"
        "event_id": 12345,  # Required if note_type is "event"
        "ip_address": "192.168.1.100",  # Required if note_type is "ip"
        "note_content": "This is a suspicious event"
    }
    """
    try:
        data = request.get_json()

        required_fields = ['note_type', 'note_content']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400

        note_type = data['note_type'].lower()
        note_content = data['note_content'].strip()

        # Validate note type
        if note_type not in ['event', 'ip', 'general']:
            return jsonify({
                'success': False,
                'error': 'Invalid note_type. Must be "event" or "ip"'
            }), 400

        # Validate type-specific fields
        event_id = None
        ip_address = None

        if note_type == 'event':
            if 'event_id' not in data:
                return jsonify({
                    'success': False,
                    'error': 'event_id is required for event notes'
                }), 400
            event_id = data['event_id']

        elif note_type == 'ip':
            if 'ip_address' not in data:
                return jsonify({
                    'success': False,
                    'error': 'ip_address is required for IP notes'
                }), 400
            ip_address = data['ip_address'].strip()

            # Validate IP format
            if not is_valid_ip(ip_address):
                return jsonify({
                    'success': False,
                    'error': 'Invalid IP address format'
                }), 400

        # Generate note UUID
        note_uuid = str(uuid.uuid4())

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO event_notes (
                    note_uuid,
                    note_type,
                    event_id,
                    ip_address_text,
                    note_content,
                    created_by_user_id
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                note_uuid,
                note_type,
                event_id,
                ip_address,
                note_content,
                None  # TODO: Get from session
            ))

            note_id = cursor.lastrowid
            conn.commit()

            # Invalidate cache
            invalidate_event_actions_cache()

            return jsonify({
                'success': True,
                'note_id': note_id,
                'note_uuid': note_uuid,
                'message': f'{note_type.capitalize()} note added successfully'
            }), 201

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error adding note: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to add note'
        }), 500


@event_actions_routes.route('/notes/<note_type>/<id_or_ip>', methods=['GET'])
def get_notes(note_type, id_or_ip):
    """Get notes for event or IP"""
    try:
        if note_type not in ['event', 'ip']:
            return jsonify({
                'success': False,
                'error': 'Invalid note_type. Must be "event" or "ip"'
            }), 400

        cache = get_cache()
        cache_k = cache_key('event_actions', 'notes', note_type, id_or_ip)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            if note_type == 'event':
                cursor.execute("""
                    SELECT
                        id,
                        note_uuid,
                        note_content,
                        is_pinned,
                        created_at,
                        updated_at
                    FROM event_notes
                    WHERE note_type = 'event' AND event_id = %s
                    ORDER BY is_pinned DESC, created_at DESC
                """, (id_or_ip,))
            else:  # ip
                # Validate IP format
                if not is_valid_ip(id_or_ip):
                    return jsonify({
                        'success': False,
                        'error': 'Invalid IP address format'
                    }), 400

                cursor.execute("""
                    SELECT
                        id,
                        note_uuid,
                        note_content,
                        is_pinned,
                        created_at,
                        updated_at
                    FROM event_notes
                    WHERE note_type = 'ip' AND ip_address_text = %s
                    ORDER BY is_pinned DESC, created_at DESC
                """, (id_or_ip,))

            notes = cursor.fetchall()

            # Format notes
            formatted_notes = []
            for note in notes:
                formatted_notes.append({
                    'id': note['id'],
                    'note_uuid': note['note_uuid'],
                    'content': note['note_content'],
                    'is_pinned': bool(note['is_pinned']),
                    'created_at': note['created_at'].isoformat() if note['created_at'] else None,
                    'updated_at': note['updated_at'].isoformat() if note['updated_at'] else None
                })

            result = {
                'success': True,
                'notes': formatted_notes,
                'count': len(formatted_notes),
                'from_cache': False
            }

            # Cache the result
            cache.set(cache_k, result, EVENT_ACTIONS_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error getting notes: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve notes'
        }), 500


@event_actions_routes.route('/notes/<int:note_id>', methods=['DELETE'])
def delete_note(note_id):
    """Delete a note"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                DELETE FROM event_notes
                WHERE id = %s
            """, (note_id,))

            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'error': 'Note not found'
                }), 404

            conn.commit()

            # Invalidate cache
            invalidate_event_actions_cache()

            return jsonify({
                'success': True,
                'message': 'Note deleted successfully'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error deleting note: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete note'
        }), 500


# ============================================================================
# REPORT ACTIONS
# ============================================================================

@event_actions_routes.route('/report', methods=['POST'])
def report_ip():
    """
    Report IP (internal tracking)

    Request JSON:
    {
        "ip_address": "192.168.1.100",
        "report_service": "abuseipdb",  # or "manual", "internal"
        "report_categories": ["ssh", "brute-force"],
        "report_comment": "Multiple failed login attempts",
        "event_id": 12345  # Optional
    }
    """
    try:
        data = request.get_json()

        required_fields = ['ip_address', 'report_service']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400

        ip_address = data['ip_address'].strip()
        report_service = data['report_service'].lower()
        report_categories = data.get('report_categories', [])
        report_comment = data.get('report_comment', '')
        event_id = data.get('event_id')

        # Validate IP format
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        # Validate report service
        valid_services = ['abuseipdb', 'manual', 'internal']
        if report_service not in valid_services:
            return jsonify({
                'success': False,
                'error': f'Invalid report_service. Must be one of: {", ".join(valid_services)}'
            }), 400

        # Generate report UUID
        report_uuid = str(uuid.uuid4())

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Convert categories to JSON
            import json
            categories_json = json.dumps(report_categories) if report_categories else None

            cursor.execute("""
                INSERT INTO ip_reports (
                    report_uuid,
                    ip_address_text,
                    report_service,
                    report_categories,
                    report_comment,
                    trigger_event_id,
                    report_status,
                    created_by_user_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                report_uuid,
                ip_address,
                report_service,
                categories_json,
                report_comment,
                event_id,
                'pending',
                None  # TODO: Get from session
            ))

            report_id = cursor.lastrowid
            conn.commit()

            # Invalidate cache
            invalidate_event_actions_cache()

            return jsonify({
                'success': True,
                'report_id': report_id,
                'report_uuid': report_uuid,
                'message': f'IP {ip_address} report submitted to {report_service}'
            }), 201

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error reporting IP: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to submit IP report'
        }), 500


@event_actions_routes.route('/report/<ip_address>/history', methods=['GET'])
def get_report_history(ip_address):
    """Get report history for IP"""
    try:
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        cache = get_cache()
        cache_k = cache_key('event_actions', 'report_history', ip_address)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    id,
                    report_uuid,
                    report_service,
                    report_categories,
                    report_comment,
                    report_status,
                    external_report_id,
                    created_at,
                    updated_at
                FROM ip_reports
                WHERE ip_address_text = %s
                ORDER BY created_at DESC
            """, (ip_address,))

            reports = cursor.fetchall()

            # Format reports
            import json
            formatted_reports = []
            for report in reports:
                formatted_reports.append({
                    'id': report['id'],
                    'report_uuid': report['report_uuid'],
                    'service': report['report_service'],
                    'categories': json.loads(report['report_categories']) if report['report_categories'] else [],
                    'comment': report['report_comment'],
                    'status': report['report_status'],
                    'external_report_id': report['external_report_id'],
                    'created_at': report['created_at'].isoformat() if report['created_at'] else None,
                    'updated_at': report['updated_at'].isoformat() if report['updated_at'] else None
                })

            result = {
                'success': True,
                'reports': formatted_reports,
                'count': len(formatted_reports),
                'from_cache': False
            }

            # Cache the result
            cache.set(cache_k, result, EVENT_ACTIONS_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error getting report history: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve report history'
        }), 500


# ============================================================================
# QUICK INFO
# ============================================================================

@event_actions_routes.route('/ip-status/<ip_address>', methods=['GET'])
def get_ip_status(ip_address):
    """
    Get combined status for an IP address

    Returns:
    {
        "is_blocked": bool,
        "is_whitelisted": bool,
        "is_watched": bool,
        "notes_count": int,
        "reports_count": int
    }
    """
    try:
        if not is_valid_ip(ip_address):
            return jsonify({
                'success': False,
                'error': 'Invalid IP address format'
            }), 400

        cache = get_cache()
        cache_k = cache_key('event_actions', 'ip_status', ip_address)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check if blocked
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM ip_blocks
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))
            is_blocked = cursor.fetchone()['count'] > 0

            # Check if whitelisted (table may not exist)
            is_whitelisted = False
            try:
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM ip_whitelist
                    WHERE ip_address_text = %s
                    AND is_active = TRUE
                    AND (expires_at IS NULL OR expires_at > NOW())
                """, (ip_address,))
                is_whitelisted = cursor.fetchone()['count'] > 0
            except Exception:
                pass  # Table doesn't exist

            # Check if watched (table may not exist)
            is_watched = False
            try:
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM ip_watchlist
                    WHERE ip_address_text = %s
                    AND is_active = TRUE
                    AND (expires_at IS NULL OR expires_at > NOW())
                """, (ip_address,))
                is_watched = cursor.fetchone()['count'] > 0
            except Exception:
                pass  # Table doesn't exist

            # Count notes (table may not exist)
            notes_count = 0
            try:
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM event_notes
                    WHERE note_type = 'ip' AND ip_address_text = %s
                """, (ip_address,))
                notes_count = cursor.fetchone()['count']
            except Exception:
                pass  # Table doesn't exist

            # Count reports (table may not exist)
            reports_count = 0
            try:
                cursor.execute("""
                    SELECT COUNT(*) as count
                    FROM ip_reports
                    WHERE ip_address_text = %s
                """, (ip_address,))
                reports_count = cursor.fetchone()['count']
            except Exception:
                pass  # Table doesn't exist

            result = {
                'success': True,
                'ip_address': ip_address,
                'is_blocked': is_blocked,
                'is_whitelisted': is_whitelisted,
                'is_watched': is_watched,
                'notes_count': notes_count,
                'reports_count': reports_count,
                'from_cache': False
            }

            # Cache the result
            cache.set(cache_k, result, IP_STATUS_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error getting IP status: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve IP status'
        }), 500
