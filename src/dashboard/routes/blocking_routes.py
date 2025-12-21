"""
SSH Guardian v3.1 - Blocking Management Routes
API endpoints for managing IP blocks, rules, and blocking actions
Updated for v3.1 database schema
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
from cache import get_cache, cache_key, cache_key_hash, invalidate_on_block_change
from auth import AuditLogger


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None

# Create Blueprint
blocking_routes = Blueprint('blocking_routes', __name__, url_prefix='/api/dashboard/blocking')

# Cache TTLs
BLOCKS_LIST_TTL = 30
BLOCKS_STATS_TTL = 60
RULES_LIST_TTL = 300
BLOCK_CHECK_TTL = 30


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
    - agent_id: Filter by agent ID (agent-based blocking)
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        is_active = request.args.get('is_active')
        block_source = request.args.get('block_source')
        search = request.args.get('search', '').strip()
        agent_id = request.args.get('agent_id')

        # Generate cache key from parameters
        cache = get_cache()
        cache_k = cache_key_hash('blocking', 'blocks_list',
                                 limit=limit, offset=offset,
                                 is_active=is_active, block_source=block_source,
                                 search=search if search else None,
                                 agent_id=agent_id)

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

        # Agent-based filtering
        if agent_id:
            resolved_agent_id = agent_id
            if isinstance(agent_id, str) and not agent_id.isdigit():
                conn_temp = get_connection()
                cursor_temp = conn_temp.cursor(dictionary=True)
                try:
                    cursor_temp.execute("SELECT id FROM agents WHERE agent_id = %s", (agent_id,))
                    agent_row = cursor_temp.fetchone()
                    if agent_row:
                        resolved_agent_id = agent_row['id']
                    else:
                        resolved_agent_id = -1
                finally:
                    cursor_temp.close()
                    conn_temp.close()
            where_clauses.append("(ib.agent_id = %s OR (ib.trigger_event_id IS NOT NULL AND ae.agent_id = %s))")
            params.extend([resolved_agent_id, resolved_agent_id])

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # v3.1: Get blocks with related data from ip_geolocation (threat intel merged)
            query = f"""
                SELECT
                    ib.id,
                    ib.ip_address_text,
                    ib.block_reason,
                    ib.block_source,
                    ib.failed_attempts,
                    ib.threat_level,
                    ib.risk_score,
                    ib.is_active,
                    ib.blocked_at,
                    ib.unblock_at,
                    ib.auto_unblock,
                    ib.unblocked_at,
                    ib.unblock_reason,
                    ib.agent_id,

                    -- Rule info
                    br.rule_name,

                    -- Trigger event info
                    ae.source_ip_text as trigger_ip,
                    ae.target_username as trigger_username,
                    ae.agent_id as event_agent_id,

                    -- Agent info
                    COALESCE(
                        ag_direct.hostname,
                        ag.hostname,
                        'Manual Block'
                    ) as agent_name,
                    COALESCE(ib.agent_id, ae.agent_id) as resolved_agent_id,

                    -- GeoIP info (v3.1: from ip_geolocation)
                    geo.country_name,
                    geo.city,

                    -- Unblock user info
                    u.full_name as unblocked_by

                FROM ip_blocks ib
                LEFT JOIN blocking_rules br ON ib.blocking_rule_id = br.id
                LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                LEFT JOIN agents ag ON ae.agent_id = ag.id
                LEFT JOIN agents ag_direct ON ib.agent_id = ag_direct.id
                LEFT JOIN ip_geolocation geo ON ib.geo_id = geo.id
                LEFT JOIN users u ON ib.unblocked_by_user_id = u.id

                WHERE 1=1 {where_sql}

                ORDER BY ib.blocked_at DESC
                LIMIT %s OFFSET %s
            """

            params.extend([limit, offset])
            cursor.execute(query, params)
            blocks = cursor.fetchall()

            # Get total count
            if agent_id:
                count_query = f"""
                    SELECT COUNT(*) as total
                    FROM ip_blocks ib
                    LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                    WHERE 1=1 {where_sql}
                """
            else:
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
                    'agent_id': block['resolved_agent_id'],
                    'failed_attempts': block['failed_attempts'],
                    'threat_level': block['threat_level'],
                    'risk_score': block['risk_score'],
                    'is_active': bool(block['is_active']),
                    'blocked_at': block['blocked_at'].isoformat() if block['blocked_at'] else None,
                    'unblock_at': block['unblock_at'].isoformat() if block['unblock_at'] else None,
                    'unblocked_at': block['unblocked_at'].isoformat() if block['unblocked_at'] else None,
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

            cache.set(cache_k, result, BLOCKS_LIST_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching blocks: {e}")
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
        "duration_minutes": 1440,
        "agent_id": 1
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
        agent_id_param = data.get('agent_id')

        # Resolve agent_id
        agent_id = None
        if agent_id_param:
            if isinstance(agent_id_param, str) and not agent_id_param.isdigit():
                conn = get_connection()
                cursor = conn.cursor(dictionary=True)
                try:
                    cursor.execute("SELECT id FROM agents WHERE agent_id = %s", (agent_id_param,))
                    agent_row = cursor.fetchone()
                    if agent_row:
                        agent_id = agent_row['id']
                    else:
                        return jsonify({
                            'success': False,
                            'error': f'Agent not found: {agent_id_param}'
                        }), 400
                finally:
                    cursor.close()
                    conn.close()
            else:
                agent_id = int(agent_id_param) if agent_id_param else None

        # Block the IP
        result = block_ip_manual(
            ip_address=ip_address,
            reason=reason,
            user_id=get_current_user_id(),
            duration_minutes=duration_minutes,
            agent_id=agent_id
        )

        if result['success']:
            invalidate_blocking_cache()

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
        print(f"Error blocking IP: {e}")
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
        "reason": "False positive"
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
            invalidate_blocking_cache()

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
        print(f"Error unblocking IP: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to unblock IP'
        }), 500


@blocking_routes.route('/blocks/check/<ip_address>', methods=['GET'])
def check_block_status(ip_address):
    """Check if an IP is currently blocked"""
    try:
        cache = get_cache()
        cache_k = cache_key('blocking', 'check', ip_address)

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

            cache.set(cache_k, result, BLOCK_CHECK_TTL)

            return jsonify(result), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error checking block status: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to check block status'
        }), 500


@blocking_routes.route('/blocks/<int:block_id>', methods=['DELETE'])
def delete_block(block_id):
    """Permanently delete a block record"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
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

            cursor.execute("DELETE FROM ip_blocks WHERE id = %s", (block_id,))
            conn.commit()

            invalidate_on_block_change()

            AuditLogger.log_action(
                user_id=get_current_user_id(),
                action='block_record_deleted',
                resource_type='ip_block',
                resource_id=ip_address,
                details={'block_id': block_id, 'ip_address': ip_address, 'reason': block.get('block_reason')},
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )

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
        print(f"Error deleting block: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete block record'
        }), 500


@blocking_routes.route('/rules/list', methods=['GET'])
def list_rules():
    """Get list of blocking rules"""
    try:
        cache = get_cache()
        cache_k = cache_key('blocking', 'rules_list')

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
        print(f"Error fetching rules: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch rules'
        }), 500


@blocking_routes.route('/rules/create', methods=['POST'])
def create_rule():
    """Create a new blocking rule"""
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
                get_current_user_id()
            ))

            rule_id = cursor.lastrowid
            conn.commit()

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
        print(f"Error creating rule: {e}")
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

            invalidate_blocking_cache()

            return jsonify({
                'success': True,
                'message': 'Rule status toggled'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error toggling rule: {e}")
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
            cursor.execute("SELECT id FROM blocking_rules WHERE id = %s", (rule_id,))
            if not cursor.fetchone():
                return jsonify({
                    'success': False,
                    'error': 'Rule not found'
                }), 404

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
        print(f"Error updating rule: {e}")
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

            if rule['is_system_rule']:
                return jsonify({
                    'success': False,
                    'error': 'System rules cannot be deleted. They are protected default rules.'
                }), 403

            cursor.execute("DELETE FROM blocking_rules WHERE id = %s", (rule_id,))
            conn.commit()

            invalidate_blocking_cache()

            return jsonify({
                'success': True,
                'message': f'Rule "{rule["rule_name"]}" deleted successfully'
            }), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error deleting rule: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to delete rule'
        }), 500


@blocking_routes.route('/auto-actions/recent', methods=['GET'])
def get_recent_auto_actions():
    """Get recent auto-blocked IPs with ML prediction details and UFW status"""
    try:
        limit = min(int(request.args.get('limit', 20)), 100)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # v3.1: ML data from auth_events_ml, threat data from ip_geolocation
            cursor.execute("""
                SELECT
                    ib.id,
                    ib.ip_address_text,
                    ib.block_reason,
                    ib.block_source,
                    ib.threat_level,
                    ib.risk_score,
                    ib.blocked_at,
                    br.rule_name,
                    br.rule_type,
                    ml.risk_score as ml_risk_score,
                    ml.threat_type as ml_threat_type,
                    ml.confidence as ml_confidence,
                    ml.is_anomaly,
                    geo.country_name,
                    geo.city,
                    (SELECT COUNT(*) FROM agent_ufw_commands WHERE params LIKE CONCAT('%%', ib.ip_address_text, '%%') AND status = 'pending') as ufw_pending,
                    (SELECT COUNT(*) FROM agent_ufw_commands WHERE params LIKE CONCAT('%%', ib.ip_address_text, '%%') AND status = 'completed') as ufw_completed
                FROM ip_blocks ib
                LEFT JOIN blocking_rules br ON ib.blocking_rule_id = br.id
                LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
                LEFT JOIN ip_geolocation geo ON ib.geo_id = geo.id
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
                    'risk_score': action['risk_score'],
                    'blocked_at': action['blocked_at'].isoformat() if action['blocked_at'] else None,
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
    """Get blocking statistics"""
    try:
        cache = get_cache()
        cache_k = cache_key('blocking', 'stats')

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

            # ML-triggered blocks
            cursor.execute("""
                SELECT
                    COUNT(*) as ml_total,
                    SUM(CASE WHEN DATE(blocked_at) = CURDATE() THEN 1 ELSE 0 END) as ml_today,
                    SUM(CASE WHEN blocked_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 ELSE 0 END) as ml_week
                FROM ip_blocks
                WHERE block_source = 'ml_threshold'
            """)
            ml_row = cursor.fetchone()
            ml_stats = {
                'total': int(ml_row['ml_total'] or 0),
                'today': int(ml_row['ml_today'] or 0),
                'this_week': int(ml_row['ml_week'] or 0)
            }

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

            for ip in top_blocked_ips:
                if ip['last_blocked']:
                    ip['last_blocked'] = ip['last_blocked'].isoformat()

            stats = {
                'total_blocks': total_blocks,
                'active_blocks': active_blocks,
                'blocks_by_source': blocks_by_source,
                'recent_24h': recent_24h,
                'ml_stats': ml_stats,
                'top_blocked_ips': top_blocked_ips
            }

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
        print(f"Error fetching stats: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch statistics'
        }), 500


@blocking_routes.route('/blocks/details/<int:block_id>', methods=['GET'])
def get_block_details(block_id):
    """
    Get comprehensive details about a blocked IP including:
    - Block information
    - Threat intelligence data (from ip_geolocation in v3.1)
    - Behavioral analysis
    - ML contribution
    - Related events
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # v3.1: Get block info with ML data from auth_events_ml
            cursor.execute("""
                SELECT
                    ib.id,
                    ib.ip_address_text as ip_address,
                    ib.block_reason,
                    ib.block_source,
                    ib.blocked_at,
                    ib.unblock_at,
                    ib.is_active,
                    ib.trigger_event_id,
                    ib.risk_score,
                    ib.threat_level,
                    COALESCE(ib.agent_id, ae.agent_id) as agent_id,
                    COALESCE(a.hostname, a2.hostname) as agent_hostname,
                    ae.event_type,
                    ae.target_username,
                    ml.risk_score as ml_risk_score,
                    ml.confidence as ml_confidence,
                    ml.threat_type as ml_threat_type
                FROM ip_blocks ib
                LEFT JOIN agents a ON ib.agent_id = a.id
                LEFT JOIN auth_events ae ON ib.trigger_event_id = ae.id
                LEFT JOIN agents a2 ON ae.agent_id = a2.id
                LEFT JOIN auth_events_ml ml ON ae.id = ml.event_id
                WHERE ib.id = %s
            """, (block_id,))

            block = cursor.fetchone()

            if not block:
                return jsonify({
                    'success': False,
                    'error': 'Block not found'
                }), 404

            ip_address = block['ip_address']

            # v3.1: Get threat intelligence data from ip_geolocation (merged table)
            cursor.execute("""
                SELECT
                    country_code,
                    country_name,
                    city,
                    region,
                    isp,
                    asn,
                    asn_org,
                    latitude,
                    longitude,
                    is_proxy,
                    is_vpn,
                    is_tor,
                    is_datacenter,
                    is_hosting,
                    abuseipdb_score,
                    abuseipdb_reports,
                    abuseipdb_last_reported,
                    virustotal_positives,
                    virustotal_total,
                    threat_level,
                    threat_confidence,
                    updated_at
                FROM ip_geolocation
                WHERE ip_address_text = %s
                LIMIT 1
            """, (ip_address,))
            geo_data = cursor.fetchone()

            # Get behavioral analysis
            cursor.execute("""
                SELECT
                    COUNT(*) as total_events,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_attempts,
                    SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful_logins,
                    SUM(CASE WHEN event_type = 'invalid' THEN 1 ELSE 0 END) as invalid_user_attempts,
                    COUNT(DISTINCT target_username) as unique_usernames_targeted,
                    COUNT(DISTINCT agent_id) as unique_agents_targeted,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen
                FROM auth_events
                WHERE source_ip_text = %s
            """, (ip_address,))
            behavioral = cursor.fetchone()

            # Get average ML score from auth_events_ml
            cursor.execute("""
                SELECT
                    AVG(ml.risk_score) as avg_ml_score,
                    MAX(ml.risk_score) as max_ml_score
                FROM auth_events ae
                JOIN auth_events_ml ml ON ae.id = ml.event_id
                WHERE ae.source_ip_text = %s
            """, (ip_address,))
            ml_stats = cursor.fetchone()

            # Get targeted usernames
            cursor.execute("""
                SELECT target_username, COUNT(*) as attempts
                FROM auth_events
                WHERE source_ip_text = %s
                  AND target_username IS NOT NULL
                GROUP BY target_username
                ORDER BY attempts DESC
                LIMIT 10
            """, (ip_address,))
            targeted_users = cursor.fetchall()

            # Get attack timeline (last 24 hours by hour)
            cursor.execute("""
                SELECT
                    DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00') as hour,
                    COUNT(*) as events,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed
                FROM auth_events
                WHERE source_ip_text = %s
                  AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                GROUP BY DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00:00')
                ORDER BY hour
            """, (ip_address,))
            attack_timeline = cursor.fetchall()

            # Get blocking history
            cursor.execute("""
                SELECT
                    ba.id,
                    ba.action_type,
                    ba.action_source,
                    ba.reason,
                    ba.created_at,
                    u.full_name as performed_by,
                    br.rule_name
                FROM blocking_actions ba
                LEFT JOIN users u ON ba.performed_by_user_id = u.id
                LEFT JOIN blocking_rules br ON ba.triggered_by_rule_id = br.id
                WHERE ba.ip_address_text = %s
                ORDER BY ba.created_at DESC
                LIMIT 20
            """, (ip_address,))
            blocking_history = cursor.fetchall()

            def safe_isoformat(dt):
                return dt.isoformat() if dt else None

            # Build ML contribution explanation
            ml_risk = float(block.get('ml_risk_score') or block.get('risk_score') or 0)
            avg_ml = float(ml_stats.get('avg_ml_score') or 0) if ml_stats else 0
            abuse_score = float(geo_data.get('abuseipdb_score') or 0) if geo_data else 0

            ml_contribution = {
                'risk_score': int(ml_risk),
                'confidence': float(block.get('ml_confidence') or 0),
                'threat_type': block.get('ml_threat_type'),
                'decision': 'Block' if ml_risk >= 70 else 'Monitor',
                'contribution_percentage': int(min(100, (ml_risk * 0.4 + avg_ml * 0.3 + abuse_score * 0.3))),
                'factors': []
            }

            if block.get('ml_risk_score') and block['ml_risk_score'] >= 50:
                ml_contribution['factors'].append({
                    'name': 'ML Risk Score',
                    'weight': 0.4
                })
            if behavioral and behavioral.get('failed_attempts') and behavioral['failed_attempts'] >= 5:
                ml_contribution['factors'].append({
                    'name': 'High Failed Attempts',
                    'weight': 0.25
                })
            if behavioral and behavioral.get('unique_usernames_targeted') and behavioral['unique_usernames_targeted'] >= 3:
                ml_contribution['factors'].append({
                    'name': 'Multiple Usernames Targeted',
                    'weight': 0.2
                })
            if geo_data and geo_data.get('abuseipdb_score') and geo_data['abuseipdb_score'] >= 50:
                ml_contribution['factors'].append({
                    'name': 'Bad Reputation (AbuseIPDB)',
                    'weight': 0.15
                })

            # Build justification
            justification = build_blocking_justification(block, geo_data, behavioral, ml_contribution)

            response = {
                'success': True,
                'block': {
                    'id': block['id'],
                    'ip_address': ip_address,
                    'reason': block['block_reason'],
                    'source': block['block_source'],
                    'blocked_at': safe_isoformat(block['blocked_at']),
                    'unblock_at': safe_isoformat(block['unblock_at']),
                    'is_active': bool(block['is_active']),
                    'agent': block['agent_hostname'] or 'Global',
                    'trigger_event_id': block['trigger_event_id']
                },
                'threat_intelligence': {
                    'abuseipdb': {
                        'score': geo_data['abuseipdb_score'] if geo_data else None,
                        'reports': geo_data['abuseipdb_reports'] if geo_data else None,
                        'last_seen': safe_isoformat(geo_data['abuseipdb_last_reported']) if geo_data else None
                    },
                    'virustotal': {
                        'malicious': geo_data['virustotal_positives'] if geo_data else None,
                        'total': geo_data['virustotal_total'] if geo_data else None
                    },
                    'classification': {
                        'is_tor_exit': bool(geo_data['is_tor']) if geo_data else False,
                        'is_proxy': bool(geo_data['is_proxy']) if geo_data else False,
                        'is_vpn': bool(geo_data['is_vpn']) if geo_data else False,
                        'is_datacenter': bool(geo_data['is_datacenter']) if geo_data else False
                    },
                    'overall_threat_level': geo_data['threat_level'] if geo_data else 'UNKNOWN',
                    'threat_confidence': float(geo_data['threat_confidence']) if geo_data and geo_data['threat_confidence'] else 0
                } if geo_data else None,
                'geolocation': {
                    'country': geo_data['country_name'] if geo_data else None,
                    'country_code': geo_data['country_code'] if geo_data else None,
                    'city': geo_data['city'] if geo_data else None,
                    'region': geo_data['region'] if geo_data else None,
                    'isp': geo_data['isp'] if geo_data else None,
                    'asn': geo_data['asn'] if geo_data else None,
                    'coordinates': {
                        'lat': float(geo_data['latitude']) if geo_data and geo_data['latitude'] else None,
                        'lon': float(geo_data['longitude']) if geo_data and geo_data['longitude'] else None
                    }
                } if geo_data else None,
                'behavioral_analysis': {
                    'total_events': behavioral['total_events'] or 0,
                    'failed_attempts': behavioral['failed_attempts'] or 0,
                    'successful_logins': behavioral['successful_logins'] or 0,
                    'invalid_user_attempts': behavioral['invalid_user_attempts'] or 0,
                    'unique_usernames_targeted': behavioral['unique_usernames_targeted'] or 0,
                    'unique_agents_targeted': behavioral['unique_agents_targeted'] or 0,
                    'avg_ml_score': round(float(ml_stats['avg_ml_score'] or 0), 2) if ml_stats else 0,
                    'max_ml_score': round(float(ml_stats['max_ml_score'] or 0), 2) if ml_stats else 0,
                    'first_seen': safe_isoformat(behavioral['first_seen']),
                    'last_seen': safe_isoformat(behavioral['last_seen']),
                    'targeted_users': targeted_users,
                    'attack_timeline': [
                        {'hour': row['hour'], 'events': row['events'], 'failed': row['failed']}
                        for row in attack_timeline
                    ]
                } if behavioral else None,
                'ml_contribution': ml_contribution,
                'justification': justification,
                'blocking_history': [
                    {
                        'id': h['id'],
                        'action_type': h['action_type'],
                        'action_source': h['action_source'],
                        'reason': h['reason'],
                        'performed_by': h['performed_by'],
                        'rule_name': h['rule_name'],
                        'created_at': safe_isoformat(h['created_at'])
                    }
                    for h in blocking_history
                ] if blocking_history else []
            }

            return jsonify(response), 200

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error fetching block details: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Failed to fetch block details'
        }), 500


def build_blocking_justification(block, geo_data, behavioral, ml_contribution):
    """Build a human-readable justification for why an IP was blocked"""
    reasons = []
    factors = []
    ml_factors = []

    source_explanations = {
        'manual': 'Manually blocked by administrator',
        'rule_based': 'Blocked by automated security rule',
        'ml_threshold': 'Blocked due to high ML risk score',
        'api_reputation': 'Blocked due to bad reputation from threat intelligence',
        'anomaly_detection': 'Blocked due to anomalous behavior detection',
        'fail2ban': 'Blocked by Fail2ban intrusion prevention'
    }
    reasons.append(source_explanations.get(block['block_source'], 'Blocked by system'))

    # Threat intelligence factors
    if geo_data:
        if geo_data.get('abuseipdb_score') and geo_data['abuseipdb_score'] >= 50:
            score = geo_data['abuseipdb_score']
            severity = 'critical' if score >= 90 else 'high' if score >= 70 else 'moderate'
            factors.append({
                'type': 'threat_intel',
                'icon': 'shield',
                'title': 'AbuseIPDB Score',
                'description': f'{severity.title()} abuse confidence score ({score}%)',
                'severity': severity,
                'weight': 0.3
            })

        if geo_data.get('virustotal_positives') and geo_data['virustotal_positives'] > 0:
            detections = geo_data['virustotal_positives']
            factors.append({
                'type': 'threat_intel',
                'icon': 'virus',
                'title': 'VirusTotal Detections',
                'description': f'{detections} security vendors flagged this IP as malicious',
                'severity': 'high' if detections >= 5 else 'moderate',
                'weight': 0.25
            })

        if geo_data.get('is_tor'):
            factors.append({
                'type': 'classification',
                'icon': 'tor',
                'title': 'Tor Exit Node',
                'description': 'Traffic originates from Tor anonymization network',
                'severity': 'moderate',
                'weight': 0.15
            })

        if geo_data.get('is_proxy') or geo_data.get('is_vpn'):
            factors.append({
                'type': 'classification',
                'icon': 'vpn',
                'title': 'Proxy/VPN Detected',
                'description': 'IP is associated with proxy or VPN service',
                'severity': 'low',
                'weight': 0.1
            })

    # Behavioral factors
    if behavioral:
        failed = behavioral.get('failed_attempts') or 0
        if failed >= 10:
            factors.append({
                'type': 'behavioral',
                'icon': 'block',
                'title': 'Failed Login Attempts',
                'description': f'{failed} failed authentication attempts detected',
                'severity': 'critical' if failed >= 50 else 'high' if failed >= 20 else 'moderate',
                'weight': 0.25
            })

        unique_users = behavioral.get('unique_usernames_targeted') or 0
        if unique_users >= 3:
            factors.append({
                'type': 'behavioral',
                'icon': 'users',
                'title': 'Multiple Targets',
                'description': f'Attempted access to {unique_users} different user accounts',
                'severity': 'high' if unique_users >= 5 else 'moderate',
                'weight': 0.2
            })

    # ML factors
    if ml_contribution:
        ml_score = ml_contribution.get('risk_score')
        if ml_score and ml_score >= 50:
            ml_factors.append({
                'type': 'ml',
                'icon': 'brain',
                'title': 'ML Risk Assessment',
                'description': f'Machine learning model assessed {ml_score}% risk probability',
                'severity': 'critical' if ml_score >= 80 else 'high' if ml_score >= 60 else 'moderate',
                'weight': 0.35
            })

    total_weight = sum(f['weight'] for f in factors + ml_factors)
    ml_weight = sum(f['weight'] for f in ml_factors)
    ml_contribution_pct = round((ml_weight / total_weight * 100) if total_weight > 0 else 0)

    return {
        'summary': reasons[0] if reasons else 'Blocked by security system',
        'detailed_reason': block['block_reason'],
        'factors': factors,
        'ml_factors': ml_factors,
        'ml_contribution_percentage': ml_contribution_pct,
        'confidence_level': 'high' if total_weight >= 0.7 else 'medium' if total_weight >= 0.4 else 'low'
    }


@blocking_routes.route('/reconcile', methods=['POST'])
def reconcile_ufw_blocks():
    """
    Reconcile ip_blocks with actual UFW rules.
    Compares ip_blocks (is_active=TRUE) with agent_ufw_rules (DENY from IP).
    """
    try:
        from blocking import reconcile_ufw_with_ip_blocks

        data = request.get_json() or {}
        agent_id = data.get('agent_id')

        result = reconcile_ufw_with_ip_blocks(agent_id)

        if result['success']:
            if result['reconciled_count'] > 0:
                invalidate_blocking_cache()

            return jsonify(result), 200
        else:
            return jsonify(result), 500

    except Exception as e:
        print(f"Error in reconciliation endpoint: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@blocking_routes.route('/real-blocks', methods=['GET'])
def get_real_blocks():
    """
    Get blocked IPs directly from UFW rules and fail2ban events.
    This shows the ACTUAL blocked IPs on the system, not from ip_blocks table.
    """
    try:
        agent_id = request.args.get('agent_id', type=int)
        search = request.args.get('search', '').strip()
        limit = min(request.args.get('limit', 200, type=int), 500)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        blocks = []

        # 1. Get UFW DENY rules (blocked IPs)
        ufw_query = """
            SELECT
                r.id,
                r.agent_id,
                r.from_ip AS ip_address,
                r.action,
                r.to_port AS port,
                r.protocol,
                r.rule_index,
                r.created_at AS blocked_at,
                a.hostname AS agent_name,
                'ufw' AS source
            FROM agent_ufw_rules r
            LEFT JOIN agents a ON r.agent_id = a.id
            WHERE r.action = 'DENY'
              AND r.from_ip IS NOT NULL
              AND r.from_ip != ''
              AND r.from_ip != 'Anywhere'
        """
        params = []

        if agent_id:
            ufw_query += " AND r.agent_id = %s"
            params.append(agent_id)

        if search:
            ufw_query += " AND r.from_ip LIKE %s"
            params.append(f"%{search}%")

        ufw_query += " ORDER BY r.created_at DESC"

        cursor.execute(ufw_query, params)
        ufw_blocks = cursor.fetchall()

        for block in ufw_blocks:
            if block.get('blocked_at'):
                block['blocked_at'] = block['blocked_at'].isoformat()
            block['block_type'] = 'UFW DENY'
            block['reason'] = f"UFW Rule #{block.get('rule_index', '?')}"
            blocks.append(block)

        # 2. Get active fail2ban bans (v3.1: event_type instead of action)
        f2b_query = """
            SELECT
                e.id,
                e.agent_id,
                e.ip_address,
                e.jail_name,
                e.event_type,
                e.failures,
                e.bantime_seconds,
                e.timestamp AS blocked_at,
                a.hostname AS agent_name,
                'fail2ban' AS source
            FROM fail2ban_events e
            LEFT JOIN agents a ON e.agent_id = a.id
            WHERE e.event_type = 'ban'
              AND NOT EXISTS (
                  SELECT 1 FROM fail2ban_events u
                  WHERE u.ip_address = e.ip_address
                    AND u.agent_id = e.agent_id
                    AND u.event_type = 'unban'
                    AND u.timestamp > e.timestamp
              )
        """
        f2b_params = []

        if agent_id:
            f2b_query += " AND e.agent_id = %s"
            f2b_params.append(agent_id)

        if search:
            f2b_query += " AND e.ip_address LIKE %s"
            f2b_params.append(f"%{search}%")

        f2b_query += " ORDER BY e.timestamp DESC"

        cursor.execute(f2b_query, f2b_params)
        f2b_blocks = cursor.fetchall()

        for block in f2b_blocks:
            if block.get('blocked_at'):
                block['blocked_at'] = block['blocked_at'].isoformat()
            block['block_type'] = f"Fail2ban ({block.get('jail_name', 'sshd')})"
            block['reason'] = f"{block.get('failures', 0)} failures"
            blocks.append(block)

        cursor.close()
        conn.close()

        # Sort by blocked_at descending and apply limit
        blocks.sort(key=lambda x: x.get('blocked_at', ''), reverse=True)
        blocks = blocks[:limit]

        ufw_count = len([b for b in blocks if b['source'] == 'ufw'])
        f2b_count = len([b for b in blocks if b['source'] == 'fail2ban'])

        return jsonify({
            'success': True,
            'blocks': blocks,
            'total': len(blocks),
            'ufw_count': ufw_count,
            'fail2ban_count': f2b_count
        })

    except Exception as e:
        print(f"Error fetching real blocks: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@blocking_routes.route('/actions/list', methods=['GET'])
def list_blocking_actions():
    """Get blocking actions history"""
    try:
        limit = min(int(request.args.get('limit', 50)), 500)
        offset = int(request.args.get('offset', 0))
        action_type = request.args.get('action_type')
        ip_address = request.args.get('ip_address')

        where_clauses = []
        params = []

        if action_type:
            where_clauses.append("ba.action_type = %s")
            params.append(action_type)

        if ip_address:
            where_clauses.append("ba.ip_address_text LIKE %s")
            params.append(f"%{ip_address}%")

        where_sql = " AND " + " AND ".join(where_clauses) if where_clauses else ""

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute(f"""
                SELECT
                    ba.id,
                    ba.action_uuid,
                    ba.ip_address_text,
                    ba.action_type,
                    ba.action_source,
                    ba.reason,
                    ba.created_at,
                    u.full_name as performed_by,
                    br.rule_name,
                    a.hostname as agent_name
                FROM blocking_actions ba
                LEFT JOIN users u ON ba.performed_by_user_id = u.id
                LEFT JOIN blocking_rules br ON ba.triggered_by_rule_id = br.id
                LEFT JOIN agents a ON ba.agent_id = a.id
                WHERE 1=1 {where_sql}
                ORDER BY ba.created_at DESC
                LIMIT %s OFFSET %s
            """, params + [limit, offset])

            actions = cursor.fetchall()

            # Get total count
            cursor.execute(f"""
                SELECT COUNT(*) as total
                FROM blocking_actions ba
                WHERE 1=1 {where_sql}
            """, params)
            total = cursor.fetchone()['total']

            formatted = []
            for action in actions:
                formatted.append({
                    'id': action['id'],
                    'action_uuid': action['action_uuid'],
                    'ip_address': action['ip_address_text'],
                    'action_type': action['action_type'],
                    'action_source': action['action_source'],
                    'reason': action['reason'],
                    'performed_by': action['performed_by'],
                    'rule_name': action['rule_name'],
                    'agent_name': action['agent_name'],
                    'created_at': action['created_at'].isoformat() if action['created_at'] else None
                })

            return jsonify({
                'success': True,
                'actions': formatted,
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
        print(f"Error fetching blocking actions: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch blocking actions'
        }), 500
