"""
SSH Guardian v3.0 - Block Events API
Handles IP block/unblock event tracking and history
"""

from flask import Blueprint, request, jsonify
import json
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection

# Import threat intelligence for analysis
try:
    from threat_intel import ThreatIntelligence
except ImportError:
    ThreatIntelligence = None

# Import ML evaluator for threat scoring
try:
    from blocking.fail2ban_ml_evaluator import Fail2banMLEvaluator
except ImportError:
    Fail2banMLEvaluator = None

# Notification helper - defined later in this module
create_notification = None  # Will be defined below

# Create Blueprint
block_events_routes = Blueprint('block_events', __name__, url_prefix='/api/dashboard/block-events')


def get_current_user_id():
    """Get current user ID from request context"""
    if hasattr(request, 'current_user') and request.current_user:
        return request.current_user.get('user_id') or request.current_user.get('id')
    return None


# ============================================================================
# BLOCK EVENTS API
# ============================================================================

@block_events_routes.route('/list', methods=['GET'])
def list_block_events():
    """
    List block/unblock events with filtering and pagination.
    Query params:
        - ip: Filter by IP address (partial match)
        - agent_id: Filter by agent
        - event_type: block, unblock, escalate
        - block_source: fail2ban, ufw, manual, ml, api
        - time_range: 1h, 24h, 7d, 30d, all
        - page: Page number (default 1)
        - page_size: Items per page (default 50)
    """
    conn = None
    cursor = None
    try:
        # Get query params
        ip_filter = request.args.get('ip_filter', request.args.get('ip', '')).strip()
        agent_id = request.args.get('agent_id', type=int)
        event_type = request.args.get('event_type')
        block_source = request.args.get('block_source')
        time_range = request.args.get('time_range', '24h')
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 50, type=int)

        # Limit page size
        page_size = min(page_size, 200)
        offset = (page - 1) * page_size

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query
        where_clauses = []
        params = []

        if ip_filter:
            where_clauses.append("e.ip_address_text LIKE %s")
            params.append(f"%{ip_filter}%")

        if agent_id:
            where_clauses.append("e.agent_id = %s")
            params.append(agent_id)

        if event_type:
            # Handle variations: blocked/block, unblocked/unblock, escalate
            if event_type in ('blocked', 'block'):
                where_clauses.append("e.action_type IN ('blocked', 'block')")
            elif event_type == 'escalate':
                where_clauses.append("e.action_type = 'escalate'")
            elif event_type in ('unblocked', 'unblock'):
                where_clauses.append("e.action_type IN ('unblocked', 'unblock')")
            else:
                where_clauses.append("e.action_type = %s")
                params.append(event_type)

        if block_source:
            # Handle partial source matching (rule -> rule_based, ml -> ml_threshold, etc.)
            if block_source in ('rule', 'rule_based'):
                where_clauses.append("e.action_source LIKE %s")
                params.append('%rule%')
            elif block_source == 'ml':
                where_clauses.append("e.action_source LIKE %s")
                params.append('%ml%')
            else:
                where_clauses.append("e.action_source = %s")
                params.append(block_source)

        # Time range filter
        if time_range and time_range != 'all':
            time_map = {
                '1h': timedelta(hours=1),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7),
                '30d': timedelta(days=30),
                '90d': timedelta(days=90)
            }
            if time_range in time_map:
                cutoff = datetime.now() - time_map[time_range]
                where_clauses.append("e.created_at >= %s")
                params.append(cutoff)

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        # Get total count - using blocking_actions table
        cursor.execute(f"""
            SELECT COUNT(*) as total
            FROM blocking_actions e
            WHERE {where_sql}
        """, params)
        total = cursor.fetchone()['total']

        # Get events with agent info - using blocking_actions table
        # Also try to get agent from ip_blocks if blocking_actions doesn't have it
        cursor.execute(f"""
            SELECT
                e.id,
                e.action_uuid,
                e.ip_address_text as ip_address,
                e.action_type as event_type,
                e.action_source as block_source,
                e.reason,
                e.metadata as threat_data,
                COALESCE(e.agent_id, b.agent_id) as agent_id,
                e.created_at,
                COALESCE(a.hostname, a2.hostname) as agent_hostname,
                COALESCE(a.ip_address, a2.ip_address) as agent_ip
            FROM blocking_actions e
            LEFT JOIN ip_blocks b ON e.ip_block_id = b.id
            LEFT JOIN agents a ON e.agent_id = a.id
            LEFT JOIN agents a2 ON b.agent_id = a2.id
            WHERE {where_sql}
            ORDER BY e.created_at DESC
            LIMIT %s OFFSET %s
        """, params + [page_size, offset])
        events = cursor.fetchall()

        # Format timestamps and parse JSON
        for event in events:
            if event.get('created_at'):
                event['created_at'] = event['created_at'].isoformat()
            if event.get('threat_data') and isinstance(event['threat_data'], str):
                try:
                    event['threat_data'] = json.loads(event['threat_data'])
                except:
                    pass

        return jsonify({
            'success': True,
            'events': events,
            'total': total,
            'page': page,
            'page_size': page_size,
            'pages': (total + page_size - 1) // page_size
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@block_events_routes.route('/ip/<ip_address>', methods=['GET'])
def get_ip_block_history(ip_address):
    """Get complete block/unblock history for a specific IP"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all events for this IP - using blocking_actions table
        cursor.execute("""
            SELECT
                e.id,
                e.action_uuid,
                e.ip_address_text as ip_address,
                e.action_type as event_type,
                e.action_source as block_source,
                e.reason,
                e.metadata as threat_data,
                e.agent_id,
                e.created_at,
                a.hostname as agent_hostname,
                a.ip_address as agent_ip
            FROM blocking_actions e
            LEFT JOIN agents a ON e.agent_id = a.id
            WHERE e.ip_address_text = %s
            ORDER BY e.created_at DESC
            LIMIT 100
        """, (ip_address,))
        events = cursor.fetchall()

        # Get summary stats - using blocking_actions table
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN action_type = 'block' THEN 1 ELSE 0 END) as block_count,
                SUM(CASE WHEN action_type = 'unblock' THEN 1 ELSE 0 END) as unblock_count,
                SUM(CASE WHEN action_type = 'escalate' THEN 1 ELSE 0 END) as escalate_count,
                SUM(CASE WHEN action_source = 'fail2ban' THEN 1 ELSE 0 END) as fail2ban_count,
                SUM(CASE WHEN action_source = 'ufw' THEN 1 ELSE 0 END) as ufw_count,
                MIN(created_at) as first_seen,
                MAX(created_at) as last_seen
            FROM blocking_actions
            WHERE ip_address_text = %s
        """, (ip_address,))
        stats = cursor.fetchone()

        # Get unique agents that blocked this IP - using blocking_actions table
        cursor.execute("""
            SELECT DISTINCT
                a.id, a.hostname, a.ip_address
            FROM blocking_actions e
            JOIN agents a ON e.agent_id = a.id
            WHERE e.ip_address_text = %s
        """, (ip_address,))
        agents = cursor.fetchall()

        # Get unique reasons - using blocking_actions table
        cursor.execute("""
            SELECT DISTINCT reason
            FROM blocking_actions
            WHERE ip_address_text = %s AND reason IS NOT NULL AND reason != ''
        """, (ip_address,))
        reasons = [r['reason'] for r in cursor.fetchall()]

        # Format timestamps
        for event in events:
            if event.get('created_at'):
                event['created_at'] = event['created_at'].isoformat()
            if event.get('threat_data') and isinstance(event['threat_data'], str):
                try:
                    event['threat_data'] = json.loads(event['threat_data'])
                except:
                    pass

        if stats.get('first_seen'):
            stats['first_seen'] = stats['first_seen'].isoformat()
        if stats.get('last_seen'):
            stats['last_seen'] = stats['last_seen'].isoformat()

        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'events': events,
            'stats': stats,
            'agents': agents,
            'reasons': reasons
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@block_events_routes.route('/stats', methods=['GET'])
def get_block_events_stats():
    """Get aggregated statistics for block events"""
    conn = None
    cursor = None
    try:
        time_range = request.args.get('time_range', '24h')
        agent_id = request.args.get('agent_id', type=int)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build time filter
        time_filter = ""
        params = []
        if time_range and time_range != 'all':
            time_map = {
                '1h': timedelta(hours=1),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7),
                '30d': timedelta(days=30)
            }
            if time_range in time_map:
                cutoff = datetime.now() - time_map[time_range]
                time_filter = "AND created_at >= %s"
                params.append(cutoff)

        agent_filter = ""
        if agent_id:
            agent_filter = "AND agent_id = %s"
            params.append(agent_id)

        # Get overall stats - using blocking_actions table
        cursor.execute(f"""
            SELECT
                COUNT(*) as total_events,
                COUNT(DISTINCT ip_address_text) as unique_ips,
                SUM(CASE WHEN action_type = 'block' THEN 1 ELSE 0 END) as total_blocks,
                SUM(CASE WHEN action_type = 'unblock' THEN 1 ELSE 0 END) as total_unblocks,
                SUM(CASE WHEN action_type = 'escalate' THEN 1 ELSE 0 END) as total_escalations,
                SUM(CASE WHEN action_source = 'fail2ban' THEN 1 ELSE 0 END) as fail2ban_events,
                SUM(CASE WHEN action_source = 'ufw' THEN 1 ELSE 0 END) as ufw_events,
                SUM(CASE WHEN action_source = 'manual' THEN 1 ELSE 0 END) as manual_events,
                SUM(CASE WHEN action_source = 'ml' THEN 1 ELSE 0 END) as ml_events
            FROM blocking_actions
            WHERE 1=1 {time_filter} {agent_filter}
        """, params)
        stats = cursor.fetchone()

        # Get top blocked IPs - using blocking_actions table
        cursor.execute(f"""
            SELECT
                ip_address_text as ip_address,
                COUNT(*) as event_count,
                MAX(created_at) as last_event
            FROM blocking_actions
            WHERE action_type = 'block' {time_filter} {agent_filter}
            GROUP BY ip_address_text
            ORDER BY event_count DESC
            LIMIT 10
        """, params)
        top_ips = cursor.fetchall()

        for ip in top_ips:
            if ip.get('last_event'):
                ip['last_event'] = ip['last_event'].isoformat()

        # Get events by hour (for chart) - using blocking_actions table
        cursor.execute(f"""
            SELECT
                DATE_FORMAT(created_at, '%Y-%m-%d %H:00:00') as hour,
                COUNT(*) as count,
                action_type as event_type
            FROM blocking_actions
            WHERE 1=1 {time_filter} {agent_filter}
            GROUP BY hour, action_type
            ORDER BY hour
        """, params)
        hourly_data = cursor.fetchall()

        return jsonify({
            'success': True,
            'stats': stats,
            'top_ips': top_ips,
            'hourly_data': hourly_data
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def log_block_event(
    ip_address: str,
    event_type: str,
    block_source: str,
    agent_id: int = None,
    reason: str = None,
    jail_name: str = None,
    failures: int = 0,
    bantime_seconds: int = 0,
    threat_score: float = None,
    threat_data: dict = None,
    triggered_by: str = None,
    user_id: int = None,
    run_analysis: bool = True
):
    """
    Log a block/unblock event to the database.
    This function is called from fail2ban and UFW action handlers.

    Args:
        run_analysis: If True, trigger async threat analysis and notifications
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        import uuid as uuid_module
        action_uuid = str(uuid_module.uuid4())

        # Build metadata JSON
        metadata = {
            'jail_name': jail_name,
            'failures': failures,
            'bantime_seconds': bantime_seconds,
            'triggered_by': triggered_by
        }
        if threat_data:
            metadata['threat_data'] = threat_data

        cursor.execute("""
            INSERT INTO blocking_actions
                (action_uuid, ip_address_text, agent_id, action_type, action_source, reason,
                 performed_by_user_id, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            action_uuid,
            ip_address,
            agent_id,
            event_type,
            block_source,
            reason,
            user_id,
            json.dumps(metadata)
        ))

        event_id = cursor.lastrowid
        conn.commit()

        # Trigger analysis and notifications for block events
        if run_analysis and event_type in ('block', 'escalate'):
            try:
                _analyze_and_notify_async(event_id, ip_address, event_type, block_source, agent_id)
            except Exception as analysis_error:
                print(f"Warning: Analysis/notification failed for event {event_id}: {analysis_error}")

        return {'success': True, 'event_id': event_id}

    except Exception as e:
        print(f"Error logging block event: {e}")
        return {'success': False, 'error': str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def create_block_notification(
    notification_type: str,
    title: str,
    message: str,
    severity: str = 'info',
    data: dict = None
):
    """
    Create a notification in the notifications table for topbar display.

    Args:
        notification_type: Type of notification (block_event, escalation, etc.)
        title: Short title for the notification
        message: Notification message body
        severity: info, warning, critical
        data: Additional JSON data to store
    """
    import uuid as uuid_module
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Map severity to priority
        priority_map = {
            'info': 'low',
            'warning': 'normal',
            'critical': 'high'
        }
        priority = priority_map.get(severity, 'normal')

        cursor.execute("""
            INSERT INTO notifications (
                notification_uuid,
                trigger_type,
                trigger_block_id,
                message_title,
                message_body,
                message_format,
                priority,
                status,
                is_read,
                created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, FALSE, NOW())
        """, (
            str(uuid_module.uuid4()),
            notification_type,
            data.get('event_id') if data else None,
            title,
            message,
            'text',
            priority,
            'sent'
        ))
        conn.commit()

        # Invalidate notification cache
        try:
            from cache import get_cache
            cache = get_cache()
            cache.delete_pattern('notif_pane')
        except:
            pass

        return {'success': True}

    except Exception as e:
        print(f"Error creating notification: {e}")
        return {'success': False, 'error': str(e)}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def _analyze_and_notify_async(event_id: int, ip_address: str, event_type: str,
                               block_source: str, agent_id: int = None):
    """
    Perform threat analysis and send notifications for a block event.
    Called asynchronously after logging the event.
    """
    import threading

    def analyze():
        try:
            analysis_result = analyze_block_event_internal(event_id, ip_address, agent_id)

            # Create topbar notification
            threat_level = 'info'
            threat_score = analysis_result.get('threat_score', 0) or 0
            if threat_score >= 75:
                threat_level = 'critical'
            elif threat_score >= 50:
                threat_level = 'warning'

            # Determine icon based on event type
            icon = '🚫' if event_type == 'block' else ('⬆️' if event_type == 'escalate' else '✅')

            title = f"{icon} IP {event_type.capitalize()}ed: {ip_address}"
            message = f"Source: {block_source.upper()}"
            if threat_score:
                message += f" | Threat Score: {threat_score}"
            if analysis_result.get('risk_level') and analysis_result['risk_level'] != 'unknown':
                message += f" | Risk: {analysis_result['risk_level'].upper()}"

            try:
                create_block_notification(
                    notification_type='block_event',
                    title=title,
                    message=message,
                    severity=threat_level,
                    data={
                        'event_id': event_id,
                        'ip_address': ip_address,
                        'event_type': event_type,
                        'block_source': block_source,
                        'agent_id': agent_id,
                        'threat_score': threat_score
                    }
                )
            except Exception as notif_err:
                print(f"Warning: Failed to create notification: {notif_err}")

            # Check if auto-escalation is needed
            if analysis_result.get('should_escalate') and block_source == 'fail2ban':
                print(f"Auto-escalation triggered for {ip_address} (threat score: {threat_score})")
                # Create escalation notification
                try:
                    create_block_notification(
                        notification_type='escalation_recommendation',
                        title=f"⚠️ Escalation Recommended: {ip_address}",
                        message=f"High threat score ({threat_score}) - consider permanent UFW block",
                        severity='warning',
                        data={
                            'event_id': event_id,
                            'ip_address': ip_address,
                            'threat_score': threat_score,
                            'agent_id': agent_id
                        }
                    )
                except:
                    pass

        except Exception as e:
            print(f"Error in async analysis: {e}")

    # Run in background thread
    thread = threading.Thread(target=analyze, daemon=True)
    thread.start()


def analyze_block_event_internal(event_id: int, ip_address: str, agent_id: int = None) -> dict:
    """
    Internal function to analyze an IP using ML and threat intelligence.
    Updates the block event with analysis results.
    """
    result = {
        'event_id': event_id,
        'ip_address': ip_address,
        'threat_score': None,
        'threat_data': None,
        'should_escalate': False,
        'risk_level': 'unknown'
    }

    conn = None
    cursor = None

    try:
        # Run ML evaluation if available
        ml_result = None
        if Fail2banMLEvaluator:
            try:
                evaluator = Fail2banMLEvaluator()
                ml_result = evaluator.evaluate_ban(ip_address, agent_id=agent_id)
                if ml_result:
                    result['threat_score'] = ml_result.get('threat_score', 0)
                    result['risk_level'] = ml_result.get('risk_level', 'unknown')
                    result['should_escalate'] = ml_result.get('recommended_action') == 'escalate_to_ufw'
                    result['ml_factors'] = ml_result.get('factors', [])
            except Exception as ml_err:
                print(f"ML evaluation error: {ml_err}")

        # Run threat intelligence lookup if available
        threat_result = None
        if ThreatIntelligence:
            try:
                threat_intel = ThreatIntelligence()
                threat_result = threat_intel.lookup_ip_threat(ip_address)
                if threat_result:
                    result['threat_data'] = {
                        'abuseipdb_score': threat_result.get('abuseipdb_confidence_score'),
                        'is_tor': threat_result.get('is_tor_exit'),
                        'is_vpn': threat_result.get('is_vpn'),
                        'is_proxy': threat_result.get('is_proxy'),
                        'country_code': threat_result.get('country_code'),
                        'isp': threat_result.get('isp')
                    }
                    # Use AbuseIPDB score if ML didn't provide one
                    if not result['threat_score'] and threat_result.get('abuseipdb_confidence_score'):
                        result['threat_score'] = threat_result['abuseipdb_confidence_score']
            except Exception as threat_err:
                print(f"Threat intel error: {threat_err}")

        # Update the block event with analysis results in metadata
        if result['threat_score'] is not None or result['threat_data']:
            conn = get_connection()
            cursor = conn.cursor()

            # Get existing metadata and merge with threat data
            cursor.execute("SELECT metadata FROM blocking_actions WHERE id = %s", (event_id,))
            row = cursor.fetchone()
            existing_metadata = {}
            if row and row[0]:
                try:
                    existing_metadata = json.loads(row[0]) if isinstance(row[0], str) else row[0]
                except:
                    pass
            existing_metadata['threat_score'] = result['threat_score']
            if result['threat_data']:
                existing_metadata['threat_data'] = result['threat_data']

            cursor.execute("""
                UPDATE blocking_actions
                SET metadata = %s
                WHERE id = %s
            """, (
                json.dumps(existing_metadata),
                event_id
            ))
            conn.commit()

    except Exception as e:
        print(f"Error analyzing block event: {e}")
        result['error'] = str(e)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return result


@block_events_routes.route('/analyze/<int:event_id>', methods=['POST'])
def analyze_block_event(event_id):
    """
    Manually trigger analysis for a specific block event.
    Useful for re-analyzing or analyzing events that missed auto-analysis.
    """
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get the event from blocking_actions
        cursor.execute("""
            SELECT ip_address_text as ip_address, agent_id, action_type as event_type, action_source as block_source
            FROM blocking_actions
            WHERE id = %s
        """, (event_id,))
        event = cursor.fetchone()

        if not event:
            return jsonify({'success': False, 'error': 'Event not found'}), 404

        # Run analysis
        result = analyze_block_event_internal(
            event_id,
            event['ip_address'],
            event.get('agent_id')
        )

        return jsonify({
            'success': True,
            'event_id': event_id,
            'analysis': result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@block_events_routes.route('/analyze-ip/<ip_address>', methods=['POST'])
def analyze_ip(ip_address):
    """
    Analyze an IP address using ML and threat intelligence.
    Returns analysis results without creating a block event.
    """
    try:
        result = {
            'ip_address': ip_address,
            'threat_score': None,
            'threat_data': None,
            'risk_level': 'unknown',
            'recommendation': None,
            'factors': []
        }

        # Run ML evaluation
        if Fail2banMLEvaluator:
            try:
                evaluator = Fail2banMLEvaluator()
                ml_result = evaluator.evaluate_ban(ip_address)
                if ml_result:
                    result['threat_score'] = ml_result.get('threat_score', 0)
                    result['risk_level'] = ml_result.get('risk_level', 'unknown')
                    result['recommendation'] = ml_result.get('recommended_action')
                    result['factors'] = ml_result.get('factors', [])
            except Exception as ml_err:
                result['ml_error'] = str(ml_err)

        # Run threat intelligence lookup
        if ThreatIntelligence:
            try:
                threat_intel = ThreatIntelligence()
                threat_result = threat_intel.lookup_ip_threat(ip_address)
                if threat_result:
                    result['threat_data'] = {
                        'abuseipdb_score': threat_result.get('abuseipdb_confidence_score'),
                        'abuseipdb_reports': threat_result.get('abuseipdb_total_reports'),
                        'is_tor': threat_result.get('is_tor_exit'),
                        'is_vpn': threat_result.get('is_vpn'),
                        'is_proxy': threat_result.get('is_proxy'),
                        'is_datacenter': threat_result.get('is_datacenter'),
                        'country_code': threat_result.get('country_code'),
                        'country_name': threat_result.get('country_name'),
                        'isp': threat_result.get('isp'),
                        'domain': threat_result.get('domain')
                    }
                    # Use AbuseIPDB score if ML didn't provide one
                    if not result['threat_score'] and threat_result.get('abuseipdb_confidence_score'):
                        result['threat_score'] = threat_result['abuseipdb_confidence_score']
            except Exception as threat_err:
                result['threat_intel_error'] = str(threat_err)

        # Determine recommendation based on score
        score = result.get('threat_score', 0) or 0
        if score >= 75:
            result['risk_level'] = 'critical'
            result['recommendation'] = 'Block permanently via UFW'
        elif score >= 50:
            result['risk_level'] = 'high'
            result['recommendation'] = 'Extended fail2ban ban recommended'
        elif score >= 25:
            result['risk_level'] = 'medium'
            result['recommendation'] = 'Standard fail2ban ban'
        else:
            result['risk_level'] = 'low'
            result['recommendation'] = 'Monitor only'

        return jsonify({
            'success': True,
            'analysis': result
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# REAL-TIME NOTIFICATIONS API
# ============================================================================

@block_events_routes.route('/notifications/unread', methods=['GET'])
def get_unread_notifications():
    """
    Get unread notifications for real-time polling.
    Returns newest notifications first.
    """
    try:
        limit = min(int(request.args.get('limit', 10)), 50)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Query only pending notifications (unread)
        cursor.execute("""
            SELECT * FROM notifications
            WHERE status = 'pending'
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))

        notifications = cursor.fetchall()

        # Format for frontend - map actual DB columns
        result = []
        for n in notifications:
            # Get column values from actual schema
            uuid_val = str(n.get('id', ''))
            title = n.get('subject', 'Notification')
            body = n.get('message', '')
            channel = n.get('channel', 'dashboard')
            status = n.get('status', 'pending')

            # Skip empty or test notifications
            if not title or title == 'Notification' or '🧪 Test' in title:
                continue

            item = {
                'uuid': uuid_val,
                'notification_type': 'auto_block' if 'block' in title.lower() else 'alert',
                'title': title,
                'severity': 'critical' if 'attack' in title.lower() else 'warning',
                'is_read': status != 'pending',
                'created_at': n['created_at'].isoformat() if n.get('created_at') else None,
                'message': body[:200] if body else title,  # Truncate long messages
                'data': {}
            }

            result.append(item)

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'notifications': result,
            'count': len(result)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@block_events_routes.route('/notifications/<notification_id>/read', methods=['POST'])
def mark_notification_read(notification_id):
    """Mark a notification as read (status = 'sent')."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Update by id
        cursor.execute("""
            UPDATE notifications SET status = 'sent'
            WHERE id = %s
        """, (notification_id,))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@block_events_routes.route('/notifications/mark-all-read', methods=['POST'])
def mark_all_notifications_read():
    """Mark all notifications as read."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("UPDATE notifications SET status = 'sent' WHERE status = 'pending'")

        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'marked_count': affected})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# SECURITY ALERTS API
# ============================================================================

@block_events_routes.route('/alerts/list', methods=['GET'])
def list_security_alerts():
    """
    List security alerts (non-blocking events) with filtering and pagination.
    Query params:
        - ip: Filter by IP address (partial match)
        - alert_type: Filter by alert type
        - is_acknowledged: Filter by acknowledged status (true/false)
        - time_range: 1h, 24h, 7d, 30d, 90d
        - page: Page number (default 1)
        - page_size: Items per page (default 50)
    """
    try:
        # Get query params
        ip_filter = request.args.get('ip', '').strip()
        alert_type = request.args.get('alert_type')
        is_acknowledged = request.args.get('is_acknowledged')
        time_range = request.args.get('time_range', '7d')
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 50, type=int)

        # Convert string to bool
        if is_acknowledged == 'true':
            is_acknowledged = True
        elif is_acknowledged == 'false':
            is_acknowledged = False
        else:
            is_acknowledged = None

        # Import and use alert_operations
        from blocking.alert_operations import get_alerts

        result = get_alerts(
            page=page,
            page_size=min(page_size, 200),
            alert_type=alert_type,
            is_acknowledged=is_acknowledged,
            ip_filter=ip_filter,
            time_range=time_range
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'alerts': []}), 500


@block_events_routes.route('/alerts/stats', methods=['GET'])
def get_alert_stats():
    """Get security alert statistics."""
    try:
        time_range = request.args.get('time_range', '24h')

        from blocking.alert_operations import get_alert_stats as fetch_alert_stats
        result = fetch_alert_stats(time_range=time_range)

        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@block_events_routes.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Mark an alert as acknowledged."""
    try:
        data = request.get_json() or {}
        action_taken = data.get('action_taken', 'acknowledged')
        user_id = get_current_user_id()

        from blocking.alert_operations import acknowledge_alert as ack_alert
        result = ack_alert(alert_id, user_id=user_id, action_taken=action_taken)

        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@block_events_routes.route('/alerts/<int:alert_id>/escalate', methods=['POST'])
def escalate_alert(alert_id):
    """Escalate an alert to a block."""
    try:
        data = request.get_json() or {}
        duration_minutes = data.get('duration_minutes', 1440)  # Default 24 hours
        user_id = get_current_user_id()

        from blocking.alert_operations import escalate_alert_to_block
        result = escalate_alert_to_block(alert_id, user_id=user_id, duration_minutes=duration_minutes)

        return jsonify(result)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@block_events_routes.route('/alerts/unacknowledged-count', methods=['GET'])
def get_unacknowledged_alert_count():
    """Get count of unacknowledged security alerts."""
    try:
        from blocking.alert_operations import get_unacknowledged_count
        count = get_unacknowledged_count()

        return jsonify({'success': True, 'count': count})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e), 'count': 0}), 500


# Expose log function for other modules
__all__ = ['log_block_event', 'analyze_block_event_internal']
