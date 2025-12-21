"""
SSH Guardian v3.0 - Security Alert Operations
Handles creating and managing security alerts (non-blocking events)
Uses the notifications table with is_security_alert=TRUE
"""

import sys
import uuid
import json
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection
from core.notification_dispatcher import NotificationDispatcher


def create_security_alert(
    ip_address: str,
    alert_type: str,
    title: str,
    description: str = None,
    severity: str = 'medium',
    username: str = None,
    agent_id: int = None,
    event_id: int = None,
    ml_score: int = 0,
    ml_factors: list = None,
    geo_data: dict = None
) -> dict:
    """
    Create a security alert for non-blocking suspicious activity.
    Uses the notifications table with is_security_alert=TRUE.

    Args:
        ip_address: Source IP address
        alert_type: Type of alert (unusual_time, new_location, new_ip, behavioral_anomaly, etc.)
        title: Short title for the alert
        description: Detailed description
        severity: low, medium, high, critical
        username: Associated username if applicable
        agent_id: Agent ID where event occurred
        event_id: Related auth_event ID
        ml_score: ML risk score (0-100)
        ml_factors: List of ML risk factors
        geo_data: Geographic data about the login

    Returns:
        dict with success status and alert_id
    """
    try:
        # Map severity to priority for notifications table
        severity_to_priority = {
            'low': 'low',
            'medium': 'normal',
            'high': 'high',
            'critical': 'critical'
        }
        priority = severity_to_priority.get(severity, 'normal')

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO notifications (
                    channel,
                    subject,
                    message,
                    status,
                    ip_address,
                    username,
                    ml_score,
                    ml_factors,
                    geo_data,
                    agent_id,
                    is_security_alert,
                    is_acknowledged
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE, FALSE)
            """, (
                alert_type,  # Use channel as alert_type
                title,       # subject = title
                description or title,  # message = description
                'pending',   # status
                ip_address,
                username,
                ml_score,
                json.dumps(ml_factors) if ml_factors else None,
                json.dumps(geo_data) if geo_data else None,
                agent_id
            ))

            alert_id = cursor.lastrowid
            conn.commit()

            print(f"  Security Alert: {title} (IP: {ip_address}, Type: {alert_type})")

            # Dispatch notification to configured channels (Telegram, Email, etc.)
            try:
                dispatcher = NotificationDispatcher()

                # Build notification message
                location_info = ""
                if geo_data:
                    city = geo_data.get('city', '')
                    country = geo_data.get('country_name', geo_data.get('country', ''))
                    location_info = f"\nLocation: {country}, {city}" if city else f"\nLocation: {country}"

                factors_info = ""
                if ml_factors:
                    factors_info = "\n\nFactors:\n" + "\n".join(f"• {f}" for f in ml_factors)

                message = f"""🚨 <b>{title}</b>

User: {username or 'N/A'}
IP: {ip_address}{location_info}
Anomaly Score: {ml_score}/100
Type: {alert_type}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{factors_info}

This login deviates from the user's learned patterns."""

                # Send via Telegram
                telegram_config = dispatcher._get_telegram_config()
                if telegram_config:
                    sent = dispatcher.send_telegram(message, telegram_config)
                    if sent:
                        # Update notification status to 'sent'
                        conn2 = get_connection()
                        cursor2 = conn2.cursor()
                        cursor2.execute("UPDATE notifications SET status = 'sent', channel = 'telegram', sent_at = NOW() WHERE id = %s", (alert_id,))
                        conn2.commit()
                        cursor2.close()
                        conn2.close()
                        print(f"    → Telegram notification sent for alert {alert_id}")
                else:
                    print(f"    → Telegram not configured, alert saved to database only")

            except Exception as dispatch_err:
                print(f"    → Warning: Failed to dispatch notification: {dispatch_err}")

            return {
                'success': True,
                'alert_id': alert_id,
                'message': f'Security alert created: {title}'
            }

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"Error creating security alert: {e}")
        return {
            'success': False,
            'alert_id': None,
            'message': f'Failed to create alert: {str(e)}'
        }


def get_alerts(
    page: int = 1,
    page_size: int = 50,
    alert_type: str = None,
    severity: str = None,
    is_acknowledged: bool = None,
    ip_filter: str = None,
    time_range: str = '7d'
) -> dict:
    """Get security alerts with filtering and pagination."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        where_clauses = ["n.is_security_alert = TRUE"]
        params = []

        if alert_type:
            where_clauses.append("n.channel = %s")
            params.append(alert_type)

        # Map severity to filter (channel stores alert_type, not severity in our case)
        # We'll filter by subject containing severity indicators if needed

        if is_acknowledged is not None:
            where_clauses.append("n.is_acknowledged = %s")
            params.append(is_acknowledged)

        if ip_filter:
            where_clauses.append("n.ip_address LIKE %s")
            params.append(f"%{ip_filter}%")

        # Time range
        time_map = {
            '1h': 'INTERVAL 1 HOUR',
            '24h': 'INTERVAL 24 HOUR',
            '7d': 'INTERVAL 7 DAY',
            '30d': 'INTERVAL 30 DAY',
            '90d': 'INTERVAL 90 DAY'
        }
        if time_range in time_map:
            where_clauses.append(f"n.created_at >= NOW() - {time_map[time_range]}")

        where_sql = " AND ".join(where_clauses)
        offset = (page - 1) * page_size

        # Get total (use n alias for consistency with main query)
        cursor.execute(f"SELECT COUNT(*) as total FROM notifications n WHERE {where_sql}", params)
        total = cursor.fetchone()['total']

        # Get alerts
        cursor.execute(f"""
            SELECT
                n.id,
                n.channel as alert_type,
                n.subject as title,
                n.message as description,
                n.status,
                n.ip_address,
                n.username,
                n.ml_score,
                n.ml_factors,
                n.geo_data,
                n.agent_id,
                n.is_acknowledged,
                n.acknowledged_by,
                n.acknowledged_at,
                n.action_taken,
                n.created_at,
                a.hostname as agent_hostname
            FROM notifications n
            LEFT JOIN agents a ON n.agent_id = a.id
            WHERE {where_sql}
            ORDER BY n.created_at DESC
            LIMIT %s OFFSET %s
        """, params + [page_size, offset])

        alerts = cursor.fetchall()

        # Format
        for alert in alerts:
            if alert.get('created_at'):
                alert['created_at'] = alert['created_at'].isoformat()
            if alert.get('acknowledged_at'):
                alert['acknowledged_at'] = alert['acknowledged_at'].isoformat()
            if alert.get('ml_factors') and isinstance(alert['ml_factors'], str):
                try:
                    alert['ml_factors'] = json.loads(alert['ml_factors'])
                except:
                    pass
            if alert.get('geo_data') and isinstance(alert['geo_data'], str):
                try:
                    alert['geo_data'] = json.loads(alert['geo_data'])
                except:
                    pass

        cursor.close()
        conn.close()

        return {
            'success': True,
            'alerts': alerts,
            'total': total,
            'page': page,
            'page_size': page_size,
            'pages': (total + page_size - 1) // page_size
        }

    except Exception as e:
        return {'success': False, 'error': str(e), 'alerts': []}


def acknowledge_alert(alert_id: int, user_id: int = None, action_taken: str = 'acknowledged') -> dict:
    """Mark an alert as acknowledged."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE notifications
            SET is_acknowledged = TRUE,
                acknowledged_by = %s,
                acknowledged_at = NOW(),
                action_taken = %s,
                status = 'sent'
            WHERE id = %s AND is_security_alert = TRUE
        """, (user_id, action_taken, alert_id))

        conn.commit()
        cursor.close()
        conn.close()

        return {'success': True, 'message': 'Alert acknowledged'}

    except Exception as e:
        return {'success': False, 'error': str(e)}


def escalate_alert_to_block(alert_id: int, user_id: int = None, duration_minutes: int = 1440) -> dict:
    """Escalate an alert to a block."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get alert info
        cursor.execute("""
            SELECT id, ip_address, subject as title, channel as alert_type
            FROM notifications
            WHERE id = %s AND is_security_alert = TRUE
        """, (alert_id,))
        alert = cursor.fetchone()

        if not alert:
            return {'success': False, 'error': 'Alert not found'}

        cursor.close()
        conn.close()

        # Import and call block_ip
        from .ip_operations import block_ip

        result = block_ip(
            ip_address=alert['ip_address'],
            block_reason=f"Escalated from alert: {alert['title']}",
            block_source='manual',
            block_duration_minutes=duration_minutes,
            created_by_user_id=user_id
        )

        if result.get('success'):
            # Update alert
            acknowledge_alert(alert_id, user_id, 'escalated_to_block')

        return result

    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_alert_stats(time_range: str = '24h') -> dict:
    """Get alert statistics."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        time_map = {
            '1h': 'INTERVAL 1 HOUR',
            '24h': 'INTERVAL 24 HOUR',
            '7d': 'INTERVAL 7 DAY',
            '30d': 'INTERVAL 30 DAY'
        }
        time_filter = f"created_at >= NOW() - {time_map.get(time_range, 'INTERVAL 24 HOUR')}"

        cursor.execute(f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN ml_score >= 80 THEN 1 ELSE 0 END) as critical_count,
                SUM(CASE WHEN ml_score >= 60 AND ml_score < 80 THEN 1 ELSE 0 END) as high_count,
                SUM(CASE WHEN ml_score >= 40 AND ml_score < 60 THEN 1 ELSE 0 END) as medium_count,
                SUM(CASE WHEN ml_score < 40 THEN 1 ELSE 0 END) as low_count,
                SUM(CASE WHEN is_acknowledged = FALSE THEN 1 ELSE 0 END) as unacknowledged,
                COUNT(DISTINCT ip_address) as unique_ips
            FROM notifications
            WHERE is_security_alert = TRUE AND {time_filter}
        """)

        stats = cursor.fetchone()

        # By type
        cursor.execute(f"""
            SELECT channel as alert_type, COUNT(*) as count
            FROM notifications
            WHERE is_security_alert = TRUE AND {time_filter}
            GROUP BY channel
            ORDER BY count DESC
        """)
        by_type = cursor.fetchall()

        cursor.close()
        conn.close()

        return {
            'success': True,
            'stats': stats,
            'by_type': by_type
        }

    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_unacknowledged_count() -> int:
    """Get count of unacknowledged security alerts."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT COUNT(*) as count
            FROM notifications
            WHERE is_security_alert = TRUE AND is_acknowledged = FALSE
        """)
        result = cursor.fetchone()

        cursor.close()
        conn.close()

        return result['count'] if result else 0

    except Exception:
        return 0
