"""
SSH Guardian v3.0 - Fail2ban Dashboard Routes
API endpoints for viewing fail2ban events in the dashboard
"""

import sys
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

fail2ban_routes = Blueprint('fail2ban_routes', __name__)


@fail2ban_routes.route('/stats', methods=['GET'])
def get_fail2ban_stats():
    """
    Get fail2ban statistics for the dashboard.
    Returns counts of bans, unbans, active bans, today's events, and repeat offenders.
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total bans
        cursor.execute("SELECT COUNT(*) as count FROM fail2ban_events WHERE event_type = 'ban'")
        total_bans = cursor.fetchone()['count']

        # Total unbans
        cursor.execute("SELECT COUNT(*) as count FROM fail2ban_events WHERE event_type = 'unban'")
        total_unbans = cursor.fetchone()['count']

        # Active bans - check ip_blocks table for currently active fail2ban blocks
        # This reflects the actual state synced from agents
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM ip_blocks
            WHERE block_source = 'fail2ban'
              AND is_active = TRUE
        """)
        active_bans = cursor.fetchone()['count']

        # Today's events
        cursor.execute("""
            SELECT COUNT(*) as count FROM fail2ban_events
            WHERE DATE(timestamp) = CURDATE()
        """)
        today_events = cursor.fetchone()['count']

        # Repeat offenders (IPs banned more than once)
        cursor.execute("""
            SELECT COUNT(*) as count FROM (
                SELECT ip_address, COUNT(*) as ban_count
                FROM fail2ban_events
                WHERE event_type = 'ban'
                GROUP BY ip_address
                HAVING ban_count > 1
            ) AS repeat_ips
        """)
        repeat_offenders = cursor.fetchone()['count']

        # Escalated to UFW (IPs that were in fail2ban and then blocked via UFW/manual)
        cursor.execute("""
            SELECT COUNT(DISTINCT ib.ip_address_text) as count
            FROM ip_blocks ib
            WHERE ib.block_source IN ('manual', 'rule_based')
              AND ib.is_active = TRUE
              AND EXISTS (
                  SELECT 1 FROM fail2ban_events f
                  WHERE f.ip_address = ib.ip_address_text
                  AND f.event_type = 'ban'
              )
        """)
        escalated_to_ufw = cursor.fetchone()['count']

        return jsonify({
            'success': True,
            'stats': {
                'total_bans': total_bans,
                'total_unbans': total_unbans,
                'active_bans': active_bans,
                'today_events': today_events,
                'repeat_offenders': repeat_offenders,
                'escalated_to_ufw': escalated_to_ufw
            }
        })

    except Exception as e:
        print(f"Error getting fail2ban stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@fail2ban_routes.route('/events', methods=['GET'])
def get_fail2ban_events():
    """
    Get fail2ban events with filtering and pagination.
    Returns unique IPs with ban_count for active bans and history.

    Query params:
    - page: Page number (default 1)
    - page_size: Events per page (default 25)
    - agent_id: Filter by agent ID
    - action: Filter by action (ban/unban)
    - jail: Filter by jail name
    - time_range: 24h, 7d, 30d, all
    - ip: Search by IP address
    """
    conn = None
    cursor = None
    try:
        # Parse parameters
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('page_size', 25))
        agent_id = request.args.get('agent_id')
        action_filter = request.args.get('action')
        jail_filter = request.args.get('jail')
        time_range = request.args.get('time_range', '24h')
        ip_search = request.args.get('ip')

        # Build base where clauses
        where_clauses = []
        params = []

        if agent_id:
            where_clauses.append("f.agent_id = %s")
            params.append(int(agent_id))

        if jail_filter:
            where_clauses.append("f.jail_name = %s")
            params.append(jail_filter)

        if ip_search:
            where_clauses.append("f.ip_address LIKE %s")
            params.append(f"%{ip_search}%")

        # Time range filter
        if time_range == '24h':
            where_clauses.append("f.timestamp >= NOW() - INTERVAL 24 HOUR")
        elif time_range == '7d':
            where_clauses.append("f.timestamp >= NOW() - INTERVAL 7 DAY")
        elif time_range == '30d':
            where_clauses.append("f.timestamp >= NOW() - INTERVAL 30 DAY")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True, buffered=True)
        offset = (page - 1) * page_size

        if action_filter == 'ban':
            # ACTIVE BANS: Unique IPs currently active in ip_blocks with ban count
            where_clauses.append("f.event_type = 'ban'")
            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Count unique active IPs
            count_sql = f"""
                SELECT COUNT(DISTINCT f.ip_address) as total
                FROM fail2ban_events f
                INNER JOIN ip_blocks b ON f.ip_address = b.ip_address_text
                    AND b.block_source = 'fail2ban' AND b.is_active = TRUE
                {where_sql}
            """
            cursor.execute(count_sql, params)
            total = cursor.fetchone()['total']

            # Get unique active bans with count
            events_sql = f"""
                SELECT
                    MAX(f.id) as id,
                    f.ip_address,
                    MAX(f.jail_name) as jail_name,
                    'ban' as event_type,
                    SUM(f.failures) as failures,
                    MAX(f.bantime_seconds) as bantime_seconds,
                    MAX(f.timestamp) as reported_at,
                    MAX(f.created_at) as created_at,
                    COUNT(*) as ban_count,
                    MAX(a.hostname) as agent_hostname,
                    MAX(a.agent_id) as agent_uuid,
                    MAX(f.agent_id) as agent_id
                FROM fail2ban_events f
                LEFT JOIN agents a ON f.agent_id = a.id
                INNER JOIN ip_blocks b ON f.ip_address = b.ip_address_text
                    AND b.block_source = 'fail2ban' AND b.is_active = TRUE
                {where_sql}
                GROUP BY f.ip_address
                ORDER BY MAX(f.timestamp) DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(events_sql, params + [page_size, offset])

        elif action_filter == 'unban':
            # UNBAN HISTORY: Show all unban events (not grouped)
            where_clauses.append("f.event_type = 'unban'")
            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            count_sql = f"SELECT COUNT(*) as total FROM fail2ban_events f {where_sql}"
            cursor.execute(count_sql, params)
            total = cursor.fetchone()['total']

            events_sql = f"""
                SELECT f.id, f.agent_id, f.ip_address, f.jail_name, f.event_type,
                    f.failures, f.bantime_seconds, f.timestamp as reported_at, f.created_at,
                    a.hostname as agent_hostname, a.agent_id as agent_uuid,
                    1 as ban_count
                FROM fail2ban_events f
                LEFT JOIN agents a ON f.agent_id = a.id
                {where_sql}
                ORDER BY f.timestamp DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(events_sql, params + [page_size, offset])

        else:
            # HISTORY (all actions): Unique IPs with total event count
            where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # Count unique IPs
            count_sql = f"SELECT COUNT(DISTINCT f.ip_address) as total FROM fail2ban_events f {where_sql}"
            cursor.execute(count_sql, params)
            total = cursor.fetchone()['total']

            # Get unique IPs with counts
            events_sql = f"""
                SELECT
                    MAX(f.id) as id,
                    f.ip_address,
                    MAX(f.jail_name) as jail_name,
                    MAX(f.event_type) as event_type,
                    SUM(CASE WHEN f.event_type = 'ban' THEN f.failures ELSE 0 END) as failures,
                    MAX(f.bantime_seconds) as bantime_seconds,
                    MAX(f.timestamp) as reported_at,
                    MAX(f.created_at) as created_at,
                    SUM(CASE WHEN f.event_type = 'ban' THEN 1 ELSE 0 END) as ban_count,
                    SUM(CASE WHEN f.event_type = 'unban' THEN 1 ELSE 0 END) as unban_count,
                    MAX(a.hostname) as agent_hostname,
                    MAX(a.agent_id) as agent_uuid,
                    MAX(f.agent_id) as agent_id
                FROM fail2ban_events f
                LEFT JOIN agents a ON f.agent_id = a.id
                {where_sql}
                GROUP BY f.ip_address
                ORDER BY MAX(f.timestamp) DESC
                LIMIT %s OFFSET %s
            """
            cursor.execute(events_sql, params + [page_size, offset])

        events = cursor.fetchall()

        # Convert datetime objects to strings
        for event in events:
            if event.get('reported_at'):
                event['reported_at'] = event['reported_at'].isoformat()
            if event.get('created_at'):
                event['created_at'] = event['created_at'].isoformat()

        return jsonify({
            'success': True,
            'events': events,
            'total': total,
            'page': page,
            'page_size': page_size,
            'pages': max(1, (total + page_size - 1) // page_size)
        })

    except Exception as e:
        print(f"Error getting fail2ban events: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@fail2ban_routes.route('/top-ips', methods=['GET'])
def get_top_banned_ips():
    """
    Get top banned IPs (most frequently banned).
    """
    conn = None
    cursor = None
    try:
        limit = int(request.args.get('limit', 10))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                ip_address,
                COUNT(*) as ban_count,
                MAX(timestamp) as last_ban,
                SUM(failures) as total_failures
            FROM fail2ban_events
            WHERE event_type = 'ban'
            GROUP BY ip_address
            ORDER BY ban_count DESC
            LIMIT %s
        """, (limit,))

        ips = cursor.fetchall()

        # Convert datetime
        for ip in ips:
            if ip['last_ban']:
                ip['last_ban'] = ip['last_ban'].isoformat()

        return jsonify({
            'success': True,
            'ips': ips
        })

    except Exception as e:
        print(f"Error getting top banned IPs: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@fail2ban_routes.route('/jails', methods=['GET'])
def get_jails():
    """
    Get list of unique jail names from fail2ban events.
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT jail_name, COUNT(*) as event_count
            FROM fail2ban_events
            GROUP BY jail_name
            ORDER BY event_count DESC
        """)

        jails = cursor.fetchall()

        return jsonify({
            'success': True,
            'jails': jails
        })

    except Exception as e:
        print(f"Error getting jails: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@fail2ban_routes.route('/unban', methods=['POST'])
def unban_ip():
    """
    Manually unban an IP address.
    Updates ip_blocks to trigger agent-side fail2ban unban.
    """
    conn = None
    cursor = None
    try:
        data = request.json
        ip_address = data.get('ip_address')
        jail = data.get('jail', 'sshd')

        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True, buffered=True)

        # Check if IP is blocked by fail2ban in ip_blocks
        cursor.execute("""
            SELECT id, block_source FROM ip_blocks
            WHERE ip_address_text = %s AND is_active = TRUE
            LIMIT 1
        """, (ip_address,))
        block = cursor.fetchone()

        if block:
            # Mark for agent-side unban
            cursor.execute("""
                UPDATE ip_blocks SET
                    is_active = FALSE,
                    manually_unblocked_at = NOW(),
                    unblock_reason = 'Manual unban from dashboard',
                    fail2ban_sync_status = 'pending'
                WHERE id = %s
            """, (block['id'],))

        # Get agent_id for unban event (from original ban or default agent)
        cursor.execute("""
            SELECT agent_id FROM fail2ban_events
            WHERE ip_address = %s AND event_type = 'ban'
            ORDER BY timestamp DESC LIMIT 1
        """, (ip_address,))
        agent_row = cursor.fetchone()

        if agent_row:
            agent_id = agent_row['agent_id']
        else:
            # Fallback to most recently active agent
            cursor.execute("""
                SELECT id FROM agents WHERE is_active = TRUE
                ORDER BY last_heartbeat DESC LIMIT 1
            """)
            fallback_row = cursor.fetchone()
            agent_id = fallback_row['id'] if fallback_row else None

        # Record the unban event
        cursor.execute("""
            INSERT INTO fail2ban_events (
                agent_id, ip_address, jail_name, event_type,
                failures, bantime_seconds, timestamp
            ) VALUES (%s, %s, %s, 'unban', 0, 0, NOW())
        """, (agent_id, ip_address, jail))

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'Unban queued for {ip_address}',
            'block_found': block is not None
        })

    except Exception as e:
        print(f"Error unbanning IP: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@fail2ban_routes.route('/ban', methods=['POST'])
def manual_ban_ip():
    """
    Manually ban an IP address via fail2ban.
    Creates a ban event record.
    """
    conn = None
    cursor = None
    try:
        data = request.json
        ip_address = data.get('ip_address')
        jail = data.get('jail', 'sshd')
        bantime = data.get('bantime', 3600)  # Default 1 hour
        reason = data.get('reason', 'Manual ban from dashboard')

        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get agent_id - can be passed as numeric ID or string agent_id
        agent_id_param = data.get('agent_id')
        agent_id = None

        if agent_id_param:
            # If it's a string (like "ranaworkspace-0050565e9ee5"), look up the numeric ID
            if isinstance(agent_id_param, str) and not agent_id_param.isdigit():
                cursor.execute("SELECT id FROM agents WHERE agent_id = %s", (agent_id_param,))
                agent_row = cursor.fetchone()
                if agent_row:
                    agent_id = agent_row['id']
            else:
                agent_id = int(agent_id_param) if agent_id_param else None

        # If no agent_id provided or found, get default (most recently active agent)
        if not agent_id:
            cursor.execute("""
                SELECT id FROM agents WHERE is_active = TRUE ORDER BY last_heartbeat DESC LIMIT 1
            """)
            agent = cursor.fetchone()
            if not agent:
                return jsonify({'success': False, 'error': 'No active agent available'}), 400
            agent_id = agent['id']

        # First, create a record in ip_blocks table (so it shows in Blocked IPs list)
        from blocking_engine import block_ip_manual
        block_result = block_ip_manual(
            ip_address=ip_address,
            reason=reason,
            user_id=None,
            duration_minutes=bantime // 60 if bantime > 0 else 1440,
            agent_id=agent_id
        )

        # Also record the ban event in fail2ban_events
        cursor.execute("""
            INSERT INTO fail2ban_events (
                agent_id, ip_address, jail_name, event_type,
                failures, bantime_seconds, timestamp
            ) VALUES (%s, %s, %s, 'ban', 0, %s, NOW())
        """, (agent_id, ip_address, jail, bantime))

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'IP {ip_address} blocked successfully',
            'bantime': bantime,
            'block_id': block_result.get('block_id') if block_result.get('success') else None
        })

    except Exception as e:
        print(f"Error banning IP: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
