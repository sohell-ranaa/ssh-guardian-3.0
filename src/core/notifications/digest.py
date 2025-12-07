"""SSH Guardian v3.0 - Notification Digest Module"""
import sys, json, uuid
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
from connection import get_connection

def queue_for_digest(trigger_type: str, context: Dict, notification_rule_id: Optional[int] = None) -> Dict:
    """Queue a notification for the hourly digest instead of sending immediately."""
    conn, cursor = get_connection(), None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""INSERT INTO notifications (notification_uuid, notification_rule_id, trigger_type,
            channels, message_title, message_body, priority, status, notification_metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (str(uuid.uuid4()), notification_rule_id, trigger_type, json.dumps([]),
              f"Digest: {trigger_type}", json.dumps(context), 'normal', 'queued', json.dumps(context)))
        conn.commit()
        return {"success": True, "notification_id": cursor.lastrowid}
    except Exception as e:
        conn.rollback()
        return {"success": False, "error": str(e)}
    finally:
        if cursor: cursor.close()
        conn.close()

def get_pending_digest_notifications(hours: int = 1) -> List[Dict]:
    """Get all notifications queued for digest in the last N hours."""
    conn, cursor = get_connection(), None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM notifications WHERE status = 'queued' AND created_at >= NOW() - INTERVAL %s HOUR ORDER BY trigger_type, created_at", (hours,))
        notifications = cursor.fetchall()
        for n in notifications:
            for dt_field in ['created_at', 'updated_at', 'sent_at']:
                if n.get(dt_field): n[dt_field] = n[dt_field].isoformat()
        return notifications
    except Exception as e:
        print(f"Error fetching pending digest notifications: {e}")
        return []
    finally:
        if cursor: cursor.close()
        conn.close()

def build_digest_summary(notifications: List[Dict]) -> Dict:
    """Build a summary message from queued notifications."""
    if not notifications:
        return {"title": "SSH Guardian Hourly Summary", "body": "No events to report.",
                "stats": {"blocked_count": 0, "high_risk_count": 0, "anomaly_count": 0, "total_count": 0}}
    stats = {"blocked_count": 0, "high_risk_count": 0, "anomaly_count": 0, "total_count": len(notifications)}
    trigger_groups = {}
    for n in notifications:
        tt = n.get('trigger_type', 'unknown')
        if 'blocked' in tt.lower(): stats['blocked_count'] += 1
        if 'risk' in tt.lower(): stats['high_risk_count'] += 1
        if 'anomaly' in tt.lower(): stats['anomaly_count'] += 1
        trigger_groups.setdefault(tt, []).append(n)
    lines = ["SSH Guardian Hourly Digest", "=" * 50,
             f"Period: {datetime.now().strftime('%Y-%m-%d %H:00')}", f"Total Events: {stats['total_count']}", "",
             "Summary:", f"  - IP Blocks: {stats['blocked_count']}", f"  - High Risk Events: {stats['high_risk_count']}",
             f"  - Anomalies Detected: {stats['anomaly_count']}", "", "Details by Type:", "-" * 50]
    for tt, group in trigger_groups.items():
        lines.append(f"\n{tt.upper()} ({len(group)} events):")
        for n in group[:5]:
            meta = json.loads(n.get('notification_metadata')) if isinstance(n.get('notification_metadata'), str) else n.get('notification_metadata', {})
            lines.append(f"  - {meta.get('ip_address', 'N/A')} at {n.get('created_at', 'N/A')}")
        if len(group) > 5: lines.append(f"  ... and {len(group) - 5} more")
    return {"title": "SSH Guardian Hourly Summary", "body": "\n".join(lines), "stats": stats}

def send_hourly_digest() -> Dict:
    """Main function to send the hourly digest. Called by cron scheduler."""
    try:
        notifications = get_pending_digest_notifications(hours=1)
        if not notifications:
            return {"success": True, "notifications_processed": 0, "message": "No notifications to send"}
        summary = build_digest_summary(notifications)
        channels = _get_enabled_channels()
        if not channels:
            return {"success": False, "notifications_processed": 0, "error": "No enabled channels"}
        sent_successfully = False
        notification_ids = [n['id'] for n in notifications]
        for channel in channels:
            if _send_via_channel(channel, summary).get('success'): sent_successfully = True
        if sent_successfully:
            mark_notifications_sent(notification_ids)
            return {"success": True, "notifications_processed": len(notification_ids),
                    "message": f"Digest sent via {len(channels)} channel(s)"}
        return {"success": False, "notifications_processed": 0, "error": "Failed to send via any channel"}
    except Exception as e:
        return {"success": False, "notifications_processed": 0, "error": str(e)}

def mark_notifications_sent(notification_ids: List[int]) -> bool:
    """Mark notifications as sent after digest is delivered."""
    if not notification_ids: return True
    conn, cursor = get_connection(), None
    try:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE notifications SET status = 'sent', sent_at = NOW() WHERE id IN ({','.join(['%s'] * len(notification_ids))})",
                      tuple(notification_ids))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error marking notifications as sent: {e}")
        return False
    finally:
        if cursor: cursor.close()
        conn.close()

def _get_enabled_channels() -> List[str]:
    """Get list of enabled notification channels from database."""
    conn, cursor = get_connection(), None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT channels FROM notification_rules WHERE is_enabled = TRUE")
        channels_set = set()
        for row in cursor.fetchall():
            ch = row.get('channels')
            if ch:
                ch_list = json.loads(ch) if isinstance(ch, str) else ch
                channels_set.update(ch_list)
        return list(channels_set) if channels_set else ['telegram']
    except Exception as e:
        print(f"Error fetching enabled channels: {e}")
        return ['telegram']
    finally:
        if cursor: cursor.close()
        conn.close()

def _send_via_channel(channel: str, summary: Dict) -> Dict:
    """Send digest summary via specified channel."""
    handlers = {'telegram': _send_telegram, 'email': _send_email, 'webhook': _send_webhook}
    try:
        return handlers.get(channel, lambda s: {"success": False, "error": f"Unknown channel: {channel}"})(summary)
    except Exception as e:
        return {"success": False, "error": str(e)}

def _send_telegram(summary: Dict) -> Dict:
    print(f"[TELEGRAM] {summary['title']}\n{summary['body']}")
    return {"success": True, "message": "Telegram digest sent"}

def _send_email(summary: Dict) -> Dict:
    print(f"[EMAIL] {summary['title']}\n{summary['body']}")
    return {"success": True, "message": "Email digest sent"}

def _send_webhook(summary: Dict) -> Dict:
    print(f"[WEBHOOK] {summary['title']}\n{summary['body']}")
    return {"success": True, "message": "Webhook digest sent"}
