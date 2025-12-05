"""
SSH Guardian v3.0 - Blocking Management Routes
API endpoints for managing IP blocks, rules, and blocking actions with Redis caching
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path
import json

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from blocking_engine import BlockingEngine, block_ip_manual, unblock_ip
from cache import get_cache, cache_key, cache_key_hash

# Create Blueprint
blocking_routes = Blueprint('blocking_routes', __name__, url_prefix='/api/dashboard/blocking')

# Cache TTLs - OPTIMIZED FOR PERFORMANCE (minimum 15 minutes)
BLOCKS_LIST_TTL = 900     # 15 minutes for blocks list
BLOCKS_STATS_TTL = 1800   # 30 minutes for stats
RULES_LIST_TTL = 3600     # 1 hour for rules (less frequently changed)
BLOCK_CHECK_TTL = 900     # 15 minutes for single IP check


def invalidate_blocking_cache():
    """Invalidate all blocking-related caches"""
    cache = get_cache()
    cache.delete_pattern('blocking')


@blocking_routes.route('/blocks/list', methods=['GET'])
def list_blocks():
    """
    Get list of IP blocks with caching

    Query Parameters:
    - limit: Number of blocks (default: 50, max: 500)
    - offset: Offset for pagination (default: 0)
    - is_active: Filter by active status (true/false)
    - block_source: Filter by source (manual, rule_based, etc.)
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        is_active = request.args.get('is_active')
        block_source = request.args.get('block_source')

        # Generate cache key from parameters
        cache = get_cache()
        cache_k = cache_key_hash('blocking', 'blocks_list',
                                 limit=limit, offset=offset,
                                 is_active=is_active, block_source=block_source)

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        where_clauses = []
        params = []

        if is_active is not None:
            where_clauses.append("ib.is_active = %s")
            params.append(is_active.lower() == 'true')

        if block_source:
            where_clauses.append("ib.block_source = %s")
            params.append(block_source)

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get blocks with related data
            query = f"""
                SELECT
                    ib.id,
                    ib.ip_address_text,
                    ib.block_reason,
                    ib.block_source,
                    ib.failed_attempts,
                    ib.threat_level,
                    ib.is_active,
                    ib.blocked_at,
                    ib.unblock_at,
                    ib.auto_unblock,
                    ib.unblock_reason,

                    -- Rule info
                    br.rule_name,

                    -- Trigger event info
                    ae.source_ip_text as trigger_ip,
                    ae.target_username as trigger_username,

                    -- GeoIP info
                    geo.country_name,
                    geo.city,

                    -- Unblock user info
                    u.full_name as unblocked_by

                FROM ip_blocks ib
                LEFT JOIN blocking_rules br ON ib.blocking_rule_id = br.id
                LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                LEFT JOIN ip_geolocation geo ON ib.ip_address_text = geo.ip_address_text
                LEFT JOIN users u ON ib.unblocked_by_user_id = u.id

                WHERE 1=1 {where_sql}

                ORDER BY ib.blocked_at DESC
                LIMIT %s OFFSET %s
            """

            params.extend([limit, offset])
            cursor.execute(query, params)
            blocks = cursor.fetchall()

            # Get total count
            count_query = f"""
                SELECT COUNT(*) as total
                FROM ip_blocks ib
                WHERE 1=1 {where_sql}
            """

            cursor.execute(count_query, params[:-2])
            total = cursor.fetchone()['total']

            # Format response
            formatted_blocks = []
            for block in blocks:
                formatted_block = {
                    'id': block['id'],
                    'ip_address': block['ip_address_text'],
                    'reason': block['block_reason'],
                    'source': block['block_source'],
                    'failed_attempts': block['failed_attempts'],
                    'threat_level': block['threat_level'],
                    'is_active': bool(block['is_active']),
                    'blocked_at': block['blocked_at'].isoformat() if block['blocked_at'] else None,
                    'unblock_at': block['unblock_at'].isoformat() if block['unblock_at'] else None,
                    'auto_unblock': bool(block['auto_unblock']),
                    'unblock_reason': block['unblock_reason'],
                    'rule_name': block['rule_name'],
                    'location': {
                        'country': block['country_name'],
                        'city': block['city']
                    } if block['country_name'] else None,
                    'unblocked_by': block['unblocked_by']
                }
                formatted_blocks.append(formatted_block)

            result = {
                'success': True,
                'blocks': formatted_blocks,
                'pagination': {
                    'total': total,
                    'limit': limit,
                    'offset': offset,
                    'has_more': (offset + limit) < total
                },
                'from_cache': False
            }

            # Cache the result
            cache.set(cache_k, result, BLOCKS_LIST_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching blocks: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch blocks'
        }), 500


@blocking_routes.route('/blocks/manual', methods=['POST'])
def manual_block():
    """
    Manually block an IP address

    Request JSON:
    {
        "ip_address": "192.168.1.100",
        "reason": "Suspicious activity",
        "duration_minutes": 1440  # Optional, default 24 hours
    }
    """
    try:
        data = request.get_json()

        if not data or 'ip_address' not in data or 'reason' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required fields: ip_address, reason'
            }), 400

        ip_address = data['ip_address']
        reason = data['reason']
        duration_minutes = data.get('duration_minutes', 1440)

        # Block the IP
        result = block_ip_manual(
            ip_address=ip_address,
            reason=reason,
            user_id=None,  # TODO: Get from session
            duration_minutes=duration_minutes
        )

        if result['success']:
            # Invalidate cache
            invalidate_blocking_cache()
            return jsonify(result), 201
        else:
            return jsonify(result), 400

    except Exception as e:
        print(f"❌ Error blocking IP: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to block IP'
        }), 500


@blocking_routes.route('/blocks/unblock', methods=['POST'])
def manual_unblock():
    """
    Manually unblock an IP address

    Request JSON:
    {
        "ip_address": "192.168.1.100",
        "reason": "False positive"  # Optional
    }
    """
    try:
        data = request.get_json()

        if not data or 'ip_address' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: ip_address'
            }), 400

        ip_address = data['ip_address']
        reason = data.get('reason', 'Manual unblock')

        # Unblock the IP
        result = unblock_ip(
            ip_address=ip_address,
            unblock_reason=reason,
            unblocked_by_user_id=None  # TODO: Get from session
        )

        if result['success']:
            # Invalidate cache
            invalidate_blocking_cache()
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    except Exception as e:
        print(f"❌ Error unblocking IP: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to unblock IP'
        }), 500


@blocking_routes.route('/blocks/check/<ip_address>', methods=['GET'])
def check_block_status(ip_address):
    """
    Check if an IP is currently blocked with caching

    Returns:
    {
        "is_blocked": bool,
        "block_info": {...} or null
    }
    """
    try:
        cache = get_cache()
        cache_k = cache_key('blocking', 'check', ip_address)

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
                    ip_address_text,
                    block_reason,
                    block_source,
                    blocked_at,
                    unblock_at,
                    auto_unblock
                FROM ip_blocks
                WHERE ip_address_text = %s AND is_active = TRUE
            """, (ip_address,))

            block = cursor.fetchone()

            if block:
                result = {
                    'is_blocked': True,
                    'block_info': {
                        'id': block['id'],
                        'reason': block['block_reason'],
                        'source': block['block_source'],
                        'blocked_at': block['blocked_at'].isoformat() if block['blocked_at'] else None,
                        'unblock_at': block['unblock_at'].isoformat() if block['unblock_at'] else None,
                        'auto_unblock': bool(block['auto_unblock'])
                    },
                    'from_cache': False
                }
            else:
                result = {
                    'is_blocked': False,
                    'block_info': None,
                    'from_cache': False
                }

            # Cache the result
            cache.set(cache_k, result, BLOCK_CHECK_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error checking block status: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to check block status'
        }), 500


@blocking_routes.route('/rules/list', methods=['GET'])
def list_rules():
    """Get list of blocking rules with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('blocking', 'rules_list')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'rules': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    id,
                    rule_name,
                    rule_type,
                    is_enabled,
                    is_system_rule,
                    priority,
                    conditions,
                    block_duration_minutes,
                    auto_unblock,
                    notify_on_trigger,
                    times_triggered,
                    last_triggered_at,
                    ips_blocked_total,
                    description,
                    created_at
                FROM blocking_rules
                ORDER BY priority DESC, created_at DESC
            """)

            rules = cursor.fetchall()

            # Format rules
            formatted_rules = []
            for rule in rules:
                formatted_rule = {
                    'id': rule['id'],
                    'rule_name': rule['rule_name'],
                    'rule_type': rule['rule_type'],
                    'is_enabled': bool(rule['is_enabled']),
                    'is_system_rule': bool(rule['is_system_rule']),
                    'priority': rule['priority'],
                    'conditions': json.loads(rule['conditions']) if isinstance(rule['conditions'], str) else rule['conditions'],
                    'block_duration_minutes': rule['block_duration_minutes'],
                    'auto_unblock': bool(rule['auto_unblock']),
                    'notify_on_trigger': bool(rule['notify_on_trigger']),
                    'times_triggered': rule['times_triggered'],
                    'last_triggered_at': rule['last_triggered_at'].isoformat() if rule['last_triggered_at'] else None,
                    'ips_blocked_total': rule['ips_blocked_total'],
                    'description': rule['description'],
                    'created_at': rule['created_at'].isoformat() if rule['created_at'] else None
                }
                formatted_rules.append(formatted_rule)

            # Cache the result
            cache.set(cache_k, formatted_rules, RULES_LIST_TTL)

            return jsonify({
                'success': True,
                'rules': formatted_rules,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching rules: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch rules'
        }), 500


@blocking_routes.route('/rules/create', methods=['POST'])
def create_rule():
    """
    Create a new blocking rule

    Request JSON:
    {
        "rule_name": "Brute Force Protection",
        "rule_type": "brute_force",
        "conditions": {
            "failed_attempts": 5,
            "time_window_minutes": 10
        },
        "block_duration_minutes": 1440,
        "auto_unblock": true,
        "priority": 50,
        "description": "Block IPs with 5+ failed attempts in 10 minutes"
    }
    """
    try:
        data = request.get_json()

        required_fields = ['rule_name', 'rule_type', 'conditions']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO blocking_rules (
                    rule_name,
                    rule_type,
                    is_enabled,
                    priority,
                    conditions,
                    block_duration_minutes,
                    auto_unblock,
                    notify_on_trigger,
                    description,
                    created_by_user_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, (
                data['rule_name'],
                data['rule_type'],
                data.get('is_enabled', True),
                data.get('priority', 50),
                json.dumps(data['conditions']),
                data.get('block_duration_minutes', 1440),
                data.get('auto_unblock', True),
                data.get('notify_on_trigger', True),
                data.get('description'),
                None  # TODO: Get from session
            ))

            rule_id = cursor.lastrowid
            conn.commit()

            # Invalidate cache
            invalidate_blocking_cache()

            return jsonify({
                'success': True,
                'rule_id': rule_id,
                'message': f'Rule "{data["rule_name"]}" created successfully'
            }), 201

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error creating rule: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to create rule'
        }), 500


@blocking_routes.route('/rules/<int:rule_id>/toggle', methods=['POST'])
def toggle_rule(rule_id):
    """Enable or disable a rule"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Toggle the rule
            cursor.execute("""
                UPDATE blocking_rules
                SET is_enabled = NOT is_enabled
                WHERE id = %s
            """, (rule_id,))

            if cursor.rowcount == 0:
                return jsonify({
                    'success': False,
                    'error': 'Rule not found'
                }), 404

            conn.commit()

            # Invalidate cache
            invalidate_blocking_cache()

            return jsonify({
                'success': True,
                'message': 'Rule status toggled'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error toggling rule: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to toggle rule'
        }), 500


@blocking_routes.route('/rules/<int:rule_id>/update', methods=['PUT'])
def update_rule(rule_id):
    """Update an existing blocking rule"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Check if rule exists
            cursor.execute("SELECT id FROM blocking_rules WHERE id = %s", (rule_id,))
            if not cursor.fetchone():
                return jsonify({
                    'success': False,
                    'error': 'Rule not found'
                }), 404

            # Update the rule
            cursor.execute("""
                UPDATE blocking_rules
                SET
                    rule_name = %s,
                    rule_type = %s,
                    conditions = %s,
                    block_duration_minutes = %s,
                    priority = %s,
                    description = %s,
                    updated_at = NOW()
                WHERE id = %s
            """, (
                data.get('rule_name'),
                data.get('rule_type'),
                json.dumps(data.get('conditions', {})),
                data.get('block_duration_minutes', 1440),
                data.get('priority', 50),
                data.get('description'),
                rule_id
            ))

            conn.commit()

            # Invalidate cache
            invalidate_blocking_cache()

            return jsonify({
                'success': True,
                'message': f'Rule "{data.get("rule_name")}" updated successfully'
            }), 200

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error updating rule: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to update rule'
        }), 500


@blocking_routes.route('/rules/<int:rule_id>/delete', methods=['DELETE'])
def delete_rule(rule_id):
    """Delete a blocking rule (only user-created rules, not system rules)"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get rule info and check if it's a system rule
            cursor.execute("""
                SELECT rule_name, is_system_rule
                FROM blocking_rules
                WHERE id = %s
            """, (rule_id,))
            rule = cursor.fetchone()

            if not rule:
                return jsonify({
                    'success': False,
                    'error': 'Rule not found'
                }), 404

            # Protect system rules from deletion
            if rule['is_system_rule']:
                return jsonify({
                    'success': False,
                    'error': 'System rules cannot be deleted. They are protected default rules.'
                }), 403

            # Delete the rule
            cursor.execute("DELETE FROM blocking_rules WHERE id = %s", (rule_id,))
            conn.commit()

            # Invalidate cache
            invalidate_blocking_cache()

            return jsonify({
                'success': True,
                'message': f'Rule "{rule["rule_name"]}" deleted successfully'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error deleting rule: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to delete rule'
        }), 500


@blocking_routes.route('/stats', methods=['GET'])
def get_stats():
    """Get blocking statistics with caching"""
    try:
        cache = get_cache()
        cache_k = cache_key('blocking', 'stats')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'stats': cached,
                'from_cache': True
            }), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Total blocks
            cursor.execute("SELECT COUNT(*) as total FROM ip_blocks")
            total_blocks = cursor.fetchone()['total']

            # Active blocks
            cursor.execute("SELECT COUNT(*) as total FROM ip_blocks WHERE is_active = TRUE")
            active_blocks = cursor.fetchone()['total']

            # Blocks by source
            cursor.execute("""
                SELECT block_source, COUNT(*) as count
                FROM ip_blocks
                GROUP BY block_source
            """)
            blocks_by_source = {row['block_source']: row['count'] for row in cursor.fetchall()}

            # Recent blocks (24h)
            cursor.execute("""
                SELECT COUNT(*) as count
                FROM ip_blocks
                WHERE blocked_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            """)
            recent_24h = cursor.fetchone()['count']

            # Top blocked IPs
            cursor.execute("""
                SELECT
                    ip_address_text,
                    COUNT(*) as block_count,
                    MAX(blocked_at) as last_blocked
                FROM ip_blocks
                GROUP BY ip_address_text
                ORDER BY block_count DESC
                LIMIT 10
            """)
            top_blocked_ips = cursor.fetchall()

            # Format timestamps
            for ip in top_blocked_ips:
                if ip['last_blocked']:
                    ip['last_blocked'] = ip['last_blocked'].isoformat()

            stats = {
                'total_blocks': total_blocks,
                'active_blocks': active_blocks,
                'blocks_by_source': blocks_by_source,
                'recent_24h': recent_24h,
                'top_blocked_ips': top_blocked_ips
            }

            # Cache the result
            cache.set(cache_k, stats, BLOCKS_STATS_TTL)

            return jsonify({
                'success': True,
                'stats': stats,
                'from_cache': False
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch statistics'
        }), 500
