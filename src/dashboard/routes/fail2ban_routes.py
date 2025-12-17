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
        cursor.execute("SELECT COUNT(*) as count FROM fail2ban_events WHERE action = 'ban'")
        total_bans = cursor.fetchone()['count']

        # Total unbans
        cursor.execute("SELECT COUNT(*) as count FROM fail2ban_events WHERE action = 'unban'")
        total_unbans = cursor.fetchone()['count']

        # Active bans (IPs that have been banned but not unbanned)
        cursor.execute("""
            SELECT COUNT(DISTINCT b.ip_address) as count
            FROM fail2ban_events b
            WHERE b.action = 'ban'
            AND NOT EXISTS (
                SELECT 1 FROM fail2ban_events u
                WHERE u.ip_address = b.ip_address
                AND u.action = 'unban'
                AND u.reported_at > b.reported_at
            )
            AND b.reported_at >= NOW() - INTERVAL 24 HOUR
        """)
        active_bans = cursor.fetchone()['count']

        # Today's events
        cursor.execute("""
            SELECT COUNT(*) as count FROM fail2ban_events
            WHERE DATE(reported_at) = CURDATE()
        """)
        today_events = cursor.fetchone()['count']

        # Repeat offenders (IPs banned more than once)
        cursor.execute("""
            SELECT COUNT(*) as count FROM (
                SELECT ip_address, COUNT(*) as ban_count
                FROM fail2ban_events
                WHERE action = 'ban'
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
                  AND f.action = 'ban'
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

        # Build query
        where_clauses = []
        params = []

        if agent_id:
            where_clauses.append("f.agent_id = %s")
            params.append(int(agent_id))

        if action_filter:
            where_clauses.append("f.action = %s")
            params.append(action_filter)

        if jail_filter:
            where_clauses.append("f.jail_name = %s")
            params.append(jail_filter)

        if ip_search:
            where_clauses.append("f.ip_address LIKE %s")
            params.append(f"%{ip_search}%")

        # Time range filter
        if time_range == '24h':
            where_clauses.append("f.reported_at >= NOW() - INTERVAL 24 HOUR")
        elif time_range == '7d':
            where_clauses.append("f.reported_at >= NOW() - INTERVAL 7 DAY")
        elif time_range == '30d':
            where_clauses.append("f.reported_at >= NOW() - INTERVAL 30 DAY")
        # 'all' means no time filter

        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get total count
        count_sql = f"""
            SELECT COUNT(*) as total FROM fail2ban_events f
            {where_sql}
        """
        cursor.execute(count_sql, params)
        total = cursor.fetchone()['total']

        # Get events with agent info
        offset = (page - 1) * page_size
        events_sql = f"""
            SELECT
                f.id,
                f.agent_id,
                f.ip_address,
                f.jail_name,
                f.action,
                f.failures,
                f.bantime_seconds,
                f.reported_at,
                f.created_at,
                a.hostname as agent_hostname,
                a.agent_id as agent_uuid
            FROM fail2ban_events f
            LEFT JOIN agents a ON f.agent_id = a.id
            {where_sql}
            ORDER BY f.reported_at DESC
            LIMIT %s OFFSET %s
        """
        cursor.execute(events_sql, params + [page_size, offset])
        events = cursor.fetchall()

        # Convert datetime objects to strings
        for event in events:
            if event['reported_at']:
                event['reported_at'] = event['reported_at'].isoformat()
            if event['created_at']:
                event['created_at'] = event['created_at'].isoformat()

        return jsonify({
            'success': True,
            'events': events,
            'total': total,
            'page': page,
            'page_size': page_size,
            'pages': (total + page_size - 1) // page_size
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
                MAX(reported_at) as last_ban,
                SUM(failures) as total_failures
            FROM fail2ban_events
            WHERE action = 'ban'
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
        cursor = conn.cursor(dictionary=True)

        # Check if IP is blocked by fail2ban in ip_blocks
        cursor.execute("""
            SELECT id, block_source FROM ip_blocks
            WHERE ip_address_text = %s AND is_active = TRUE
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

        # Also record the unban event
        cursor.execute("""
            INSERT INTO fail2ban_events (
                agent_id, ip_address, jail_name, action,
                failures, bantime_seconds, reported_at
            )
            SELECT
                COALESCE(
                    (SELECT agent_id FROM fail2ban_events
                     WHERE ip_address = %s AND action = 'ban'
                     ORDER BY reported_at DESC LIMIT 1),
                    (SELECT id FROM agents WHERE is_active = TRUE ORDER BY last_heartbeat DESC LIMIT 1)
                ),
                %s, %s, 'unban', 0, 0, NOW()
        """, (ip_address, ip_address, jail))

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

        # Get a default agent_id (most recently active agent)
        cursor.execute("""
            SELECT id FROM agents WHERE is_active = TRUE ORDER BY last_heartbeat DESC LIMIT 1
        """)
        agent = cursor.fetchone()
        if not agent:
            return jsonify({'success': False, 'error': 'No active agent available'}), 400
        agent_id = agent['id']

        # Record the ban event
        cursor.execute("""
            INSERT INTO fail2ban_events (
                agent_id, ip_address, jail_name, action,
                failures, bantime_seconds, reported_at
            ) VALUES (%s, %s, %s, 'ban', 0, %s, NOW())
        """, (agent_id, ip_address, jail, bantime))

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'Ban recorded for {ip_address}',
            'bantime': bantime
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
