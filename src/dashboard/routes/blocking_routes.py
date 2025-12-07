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
from auth import AuditLogger


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None

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
    - search: Search by IP address (partial match)
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        is_active = request.args.get('is_active')
        block_source = request.args.get('block_source')
        search = request.args.get('search', '').strip()

        # Generate cache key from parameters
        cache = get_cache()
        cache_k = cache_key_hash('blocking', 'blocks_list',
                                 limit=limit, offset=offset,
                                 is_active=is_active, block_source=block_source,
                                 search=search if search else None)

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

        if search:
            where_clauses.append("ib.ip_address_text LIKE %s")
            params.append(f"%{search}%")

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

                    -- Agent info
                    COALESCE(ag.display_name, ag.hostname, 'Manual Block') as agent_name,

                    -- GeoIP info
                    geo.country_name,
                    geo.city,

                    -- Unblock user info
                    u.full_name as unblocked_by

                FROM ip_blocks ib
                LEFT JOIN blocking_rules br ON ib.blocking_rule_id = br.id
                LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                LEFT JOIN agents ag ON ae.agent_id = ag.id
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
                    'agent_name': block['agent_name'],
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
            user_id=get_current_user_id(),
            duration_minutes=duration_minutes
        )

        if result['success']:
            # Invalidate cache
            invalidate_blocking_cache()

            # Audit log
            AuditLogger.log_action(
                user_id=get_current_user_id(),
                action='ip_blocked',
                resource_type='ip_block',
                resource_id=ip_address,
                details={'ip_address': ip_address, 'reason': reason, 'duration_minutes': duration_minutes},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

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
            unblocked_by_user_id=get_current_user_id()
        )

        if result['success']:
            # Invalidate cache
            invalidate_blocking_cache()

            # Audit log
            AuditLogger.log_action(
                user_id=get_current_user_id(),
                action='ip_unblocked',
                resource_type='ip_block',
                resource_id=ip_address,
                details={'ip_address': ip_address, 'reason': reason},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

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


@blocking_routes.route('/blocks/<int:block_id>', methods=['DELETE'])
def delete_block(block_id):
    """
    Permanently delete a block record

    This removes the block record entirely from the database.
    Use unblock endpoint if you just want to disable the block.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # First get the block info for logging
            cursor.execute("""
                SELECT id, ip_address_text, block_reason
                FROM ip_blocks
                WHERE id = %s
            """, (block_id,))

            block = cursor.fetchone()

            if not block:
                return jsonify({
                    'success': False,
                    'error': 'Block record not found'
                }), 404

            ip_address = block['ip_address_text']

            # Delete the block record
            cursor.execute("DELETE FROM ip_blocks WHERE id = %s", (block_id,))
            conn.commit()

            # Clear cache
            cache = get_cache()
            cache.delete_pattern('blocking')
            cache.delete(cache_key('blocking', 'check', ip_address))

            # Audit log
            AuditLogger.log_action(
                user_id=get_current_user_id(),
                action='block_record_deleted',
                resource_type='ip_block',
                resource_id=ip_address,
                details={'block_id': block_id, 'ip_address': ip_address, 'reason': block.get('block_reason')},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

            print(f"🗑️ Block record deleted: {ip_address} (ID: {block_id})")

            return jsonify({
                'success': True,
                'message': f'Block record for {ip_address} deleted successfully',
                'deleted_id': block_id,
                'ip_address': ip_address
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error deleting block: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete block record'
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


@blocking_routes.route('/watchlist', methods=['GET'])
def list_watchlist():
    """
    Get list of IPs on watchlist

    Query Parameters:
    - search: Search by IP address (partial match)
    - limit: Number of results (default: 50, max: 500)
    - offset: Offset for pagination (default: 0)
    - is_active: Filter by active status (true/false)
    """
    try:
        search = request.args.get('search', '').strip()
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        is_active = request.args.get('is_active')

        where_clauses = []
        params = []

        if search:
            where_clauses.append("ip_address_text LIKE %s")
            params.append(f"%{search}%")

        if is_active is not None:
            where_clauses.append("is_active = %s")
            params.append(is_active.lower() == 'true')

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            query = f"""
                SELECT
                    id,
                    ip_address_text as ip,
                    watch_reason as reason,
                    watch_level,
                    is_active,
                    expires_at,
                    notify_on_activity,
                    created_at as added_at,
                    trigger_event_id
                FROM ip_watchlist
                WHERE 1=1 {where_sql}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """

            params.extend([limit, offset])
            cursor.execute(query, params)
            watchlist = cursor.fetchall()

            # Get total count
            count_query = f"""
                SELECT COUNT(*) as total
                FROM ip_watchlist
                WHERE 1=1 {where_sql}
            """
            cursor.execute(count_query, params[:-2])
            total = cursor.fetchone()['total']

            return jsonify({
                'success': True,
                'watchlist': watchlist,
                'items': watchlist,  # Alias for compatibility
                'pagination': {
                    'total': total,
                    'limit': limit,
                    'offset': offset,
                    'has_more': (offset + limit) < total
                }
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching watchlist: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch watchlist'
        }), 500


@blocking_routes.route('/whitelist', methods=['GET'])
def list_whitelist():
    """
    Get list of whitelisted IPs

    Query Parameters:
    - search: Search by IP address (partial match)
    - limit: Number of results (default: 50, max: 500)
    - offset: Offset for pagination (default: 0)
    - is_active: Filter by active status (true/false)
    """
    try:
        search = request.args.get('search', '').strip()
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        is_active = request.args.get('is_active')

        where_clauses = []
        params = []

        if search:
            where_clauses.append("ip_address_text LIKE %s")
            params.append(f"%{search}%")

        if is_active is not None:
            where_clauses.append("is_active = %s")
            params.append(is_active.lower() == 'true')

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            query = f"""
                SELECT
                    id,
                    ip_address_text as ip,
                    whitelist_reason as reason,
                    whitelist_source as source,
                    is_active,
                    expires_at,
                    created_by_user_id as added_by_user_id,
                    created_at as added_at,
                    ip_range_cidr
                FROM ip_whitelist
                WHERE 1=1 {where_sql}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """

            params.extend([limit, offset])
            cursor.execute(query, params)
            whitelist = cursor.fetchall()

            # Get total count
            count_query = f"""
                SELECT COUNT(*) as total
                FROM ip_whitelist
                WHERE 1=1 {where_sql}
            """
            cursor.execute(count_query, params[:-2])
            total = cursor.fetchone()['total']

            return jsonify({
                'success': True,
                'whitelist': whitelist,
                'items': whitelist,  # Alias for compatibility
                'pagination': {
                    'total': total,
                    'limit': limit,
                    'offset': offset,
                    'has_more': (offset + limit) < total
                }
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Error fetching whitelist: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch whitelist'
        }), 500


@blocking_routes.route('/blocks/pending', methods=['GET'])
def list_pending_blocks():
    """
    Get list of blocks pending approval

    Returns blocks where approval_status = 'pending' and is_active = TRUE
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    ib.id,
                    ib.ip_address_text,
                    ib.block_reason,
                    ib.block_source,
                    ib.threat_level,
                    ib.blocked_at,
                    ib.approval_status,
                    br.rule_name,
                    ae.ml_risk_score,
                    ae.ml_threat_type,
                    geo.country_name,
                    geo.city
                FROM ip_blocks ib
                LEFT JOIN blocking_rules br ON ib.blocking_rule_id = br.id
                LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                LEFT JOIN ip_geolocation geo ON ib.ip_address_text = geo.ip_address_text
                WHERE ib.approval_status = 'pending'
                AND ib.is_active = TRUE
                ORDER BY ib.blocked_at DESC
            """)

            pending_blocks = cursor.fetchall()

            # Format response
            formatted = []
            for block in pending_blocks:
                formatted.append({
                    'id': block['id'],
                    'ip_address': block['ip_address_text'],
                    'reason': block['block_reason'],
                    'source': block['block_source'],
                    'threat_level': block['threat_level'],
                    'blocked_at': block['blocked_at'].isoformat() if block['blocked_at'] else None,
                    'rule_name': block['rule_name'],
                    'ml_risk_score': block['ml_risk_score'],
                    'ml_threat_type': block['ml_threat_type'],
                    'location': {
                        'country': block['country_name'],
                        'city': block['city']
                    } if block['country_name'] else None
                })

            return jsonify({
                'success': True,
                'pending_blocks': formatted,
                'count': len(formatted)
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching pending blocks: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch pending blocks'
        }), 500


@blocking_routes.route('/blocks/<int:block_id>/approve', methods=['POST'])
def approve_block(block_id):
    """
    Approve a pending block

    This sets approval_status to 'approved' and creates UFW commands
    """
    try:
        user_id = get_current_user_id()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get block info
            cursor.execute("""
                SELECT id, ip_address_text, approval_status, is_active
                FROM ip_blocks
                WHERE id = %s
            """, (block_id,))

            block = cursor.fetchone()

            if not block:
                return jsonify({
                    'success': False,
                    'error': 'Block not found'
                }), 404

            if block['approval_status'] != 'pending':
                return jsonify({
                    'success': False,
                    'error': f"Block is already {block['approval_status']}"
                }), 400

            # Update approval status
            cursor.execute("""
                UPDATE ip_blocks
                SET approval_status = 'approved',
                    approved_by = %s,
                    approved_at = NOW()
                WHERE id = %s
            """, (user_id, block_id))

            conn.commit()

            # Create UFW block commands now that it's approved
            try:
                from core.blocking.ufw_sync import create_ufw_block_commands
                ufw_result = create_ufw_block_commands(
                    ip_address=block['ip_address_text'],
                    block_id=block_id
                )
            except Exception as e:
                print(f"UFW sync error: {e}")
                ufw_result = {'commands_created': 0}

            # Invalidate cache
            invalidate_blocking_cache()

            # Audit log
            AuditLogger.log_action(
                user_id=user_id,
                action='block_approved',
                resource_type='ip_block',
                resource_id=block['ip_address_text'],
                details={'block_id': block_id, 'ip_address': block['ip_address_text']},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

            return jsonify({
                'success': True,
                'message': f'Block for {block["ip_address_text"]} approved',
                'ufw_commands_created': ufw_result.get('commands_created', 0)
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error approving block: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to approve block'
        }), 500


@blocking_routes.route('/blocks/<int:block_id>/reject', methods=['POST'])
def reject_block(block_id):
    """
    Reject a pending block

    This sets approval_status to 'rejected' and is_active to FALSE
    """
    try:
        user_id = get_current_user_id()
        data = request.get_json() or {}
        reason = data.get('reason', 'Rejected by administrator')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Get block info
            cursor.execute("""
                SELECT id, ip_address_text, approval_status
                FROM ip_blocks
                WHERE id = %s
            """, (block_id,))

            block = cursor.fetchone()

            if not block:
                return jsonify({
                    'success': False,
                    'error': 'Block not found'
                }), 404

            if block['approval_status'] != 'pending':
                return jsonify({
                    'success': False,
                    'error': f"Block is already {block['approval_status']}"
                }), 400

            # Update to rejected and deactivate
            cursor.execute("""
                UPDATE ip_blocks
                SET approval_status = 'rejected',
                    is_active = FALSE,
                    approved_by = %s,
                    approved_at = NOW(),
                    unblock_reason = %s
                WHERE id = %s
            """, (user_id, reason, block_id))

            conn.commit()

            # Invalidate cache
            invalidate_blocking_cache()

            # Audit log
            AuditLogger.log_action(
                user_id=user_id,
                action='block_rejected',
                resource_type='ip_block',
                resource_id=block['ip_address_text'],
                details={'block_id': block_id, 'ip_address': block['ip_address_text'], 'reason': reason},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

            return jsonify({
                'success': True,
                'message': f'Block for {block["ip_address_text"]} rejected'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error rejecting block: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to reject block'
        }), 500


@blocking_routes.route('/auto-actions/recent', methods=['GET'])
def get_recent_auto_actions():
    """
    Get recent auto-blocked IPs with ML prediction details and UFW status
    """
    try:
        limit = min(int(request.args.get('limit', 20)), 100)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT
                    ib.id,
                    ib.ip_address_text,
                    ib.block_reason,
                    ib.block_source,
                    ib.threat_level,
                    ib.blocked_at,
                    ib.approval_status,
                    br.rule_name,
                    br.rule_type,
                    ae.ml_risk_score,
                    ae.ml_threat_type,
                    ae.ml_confidence,
                    ae.is_anomaly,
                    geo.country_name,
                    geo.city,
                    (SELECT COUNT(*) FROM agent_ufw_commands WHERE params_json LIKE CONCAT('%%', ib.ip_address_text, '%%') AND status = 'pending') as ufw_pending,
                    (SELECT COUNT(*) FROM agent_ufw_commands WHERE params_json LIKE CONCAT('%%', ib.ip_address_text, '%%') AND status = 'completed') as ufw_completed
                FROM ip_blocks ib
                LEFT JOIN blocking_rules br ON ib.blocking_rule_id = br.id
                LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                LEFT JOIN ip_geolocation geo ON ib.ip_address_text = geo.ip_address_text
                WHERE ib.block_source IN ('ml_threshold', 'rule_based', 'anomaly_detection')
                ORDER BY ib.blocked_at DESC
                LIMIT %s
            """, (limit,))

            auto_actions = cursor.fetchall()

            formatted = []
            for action in auto_actions:
                formatted.append({
                    'id': action['id'],
                    'ip_address': action['ip_address_text'],
                    'reason': action['block_reason'],
                    'source': action['block_source'],
                    'threat_level': action['threat_level'],
                    'blocked_at': action['blocked_at'].isoformat() if action['blocked_at'] else None,
                    'approval_status': action['approval_status'],
                    'rule': {
                        'name': action['rule_name'],
                        'type': action['rule_type']
                    } if action['rule_name'] else None,
                    'ml': {
                        'risk_score': action['ml_risk_score'],
                        'threat_type': action['ml_threat_type'],
                        'confidence': float(action['ml_confidence']) if action['ml_confidence'] else None,
                        'is_anomaly': bool(action['is_anomaly']) if action['is_anomaly'] is not None else None
                    },
                    'location': {
                        'country': action['country_name'],
                        'city': action['city']
                    } if action['country_name'] else None,
                    'ufw_status': {
                        'pending': action['ufw_pending'] or 0,
                        'completed': action['ufw_completed'] or 0
                    }
                })

            return jsonify({
                'success': True,
                'auto_actions': formatted,
                'count': len(formatted)
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching auto actions: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch auto actions'
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
