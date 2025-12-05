"""
SSH Guardian v3.0 - Event Actions Optimized Queries
Optimized database queries for event actions feature to reduce round-trips and improve performance
"""

from typing import Dict, List, Any, Optional, Tuple
import uuid


def check_ip_status_batched(cursor, ip_address: str) -> Dict[str, Any]:
    """
    Single optimized query that checks IP status across multiple tables.

    Combines multiple separate queries into one using CASE WHEN and subqueries:
    - Block status (ip_blocks)
    - Whitelist status (ip_whitelist)
    - Watchlist status (ip_watchlist)
    - Notes count (event_notes)
    - Reports count (ip_reports)
    - Event statistics (auth_events)

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address to check

    Returns:
        Dict containing all IP status information
    """

    cursor.execute("""
        SELECT
            -- Block status
            (SELECT COUNT(*) > 0 FROM ip_blocks
             WHERE ip_address_text = %s AND is_active = 1) as is_blocked,

            -- Whitelist status
            (SELECT COUNT(*) > 0 FROM ip_whitelist
             WHERE ip_address_text = %s AND is_active = 1) as is_whitelisted,

            -- Watchlist status and level
            (SELECT COUNT(*) > 0 FROM ip_watchlist
             WHERE ip_address_text = %s AND is_active = 1) as is_watched,
            (SELECT watch_level FROM ip_watchlist
             WHERE ip_address_text = %s AND is_active = 1
             ORDER BY created_at DESC LIMIT 1) as watch_level,

            -- Notes count
            (SELECT COUNT(*) FROM event_notes
             WHERE ip_address_text = %s) as notes_count,

            -- Reports count
            (SELECT COUNT(*) FROM ip_reports
             WHERE ip_address_text = %s) as reports_count,

            -- Event statistics
            (SELECT MAX(timestamp) FROM auth_events
             WHERE source_ip_text = %s) as last_seen,
            (SELECT COUNT(*) FROM auth_events
             WHERE source_ip_text = %s) as total_events,
            (SELECT COUNT(*) FROM auth_events
             WHERE source_ip_text = %s AND event_type = 'failed') as failed_events
    """, (ip_address, ip_address, ip_address, ip_address, ip_address,
          ip_address, ip_address, ip_address, ip_address))

    result = cursor.fetchone() or {}

    return {
        'is_blocked': bool(result.get('is_blocked', 0)),
        'is_whitelisted': bool(result.get('is_whitelisted', 0)),
        'is_watched': bool(result.get('is_watched', 0)),
        'watch_level': result.get('watch_level'),
        'notes_count': int(result.get('notes_count', 0)),
        'reports_count': int(result.get('reports_count', 0)),
        'last_seen': result.get('last_seen').isoformat() if result.get('last_seen') else None,
        'total_events': int(result.get('total_events', 0)),
        'failed_events': int(result.get('failed_events', 0))
    }


def get_ip_notes_paginated(
    cursor,
    ip_address: str,
    limit: int = 20,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Get notes for an IP address with pagination.

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address to get notes for
        limit: Maximum number of notes to return
        offset: Number of notes to skip

    Returns:
        List of note dictionaries
    """

    cursor.execute("""
        SELECT
            note_uuid,
            note_type,
            note_content,
            is_pinned,
            created_at,
            created_by_user_id
        FROM event_notes
        WHERE ip_address_text = %s
        ORDER BY is_pinned DESC, created_at DESC
        LIMIT %s OFFSET %s
    """, (ip_address, limit, offset))

    notes = cursor.fetchall()

    formatted_notes = []
    for note in notes:
        formatted_notes.append({
            'note_uuid': note['note_uuid'],
            'note_type': note['note_type'],
            'note_content': note['note_content'],
            'is_pinned': bool(note['is_pinned']),
            'created_at': note['created_at'].isoformat() if note['created_at'] else None,
            'created_by_user_id': note['created_by_user_id']
        })

    return formatted_notes


def get_event_notes_paginated(
    cursor,
    event_id: int,
    limit: int = 20,
    offset: int = 0
) -> List[Dict[str, Any]]:
    """
    Get notes for a specific event with pagination.

    Args:
        cursor: Database cursor (dictionary=True)
        event_id: Event ID to get notes for
        limit: Maximum number of notes to return
        offset: Number of notes to skip

    Returns:
        List of note dictionaries
    """

    cursor.execute("""
        SELECT
            note_uuid,
            note_type,
            note_content,
            is_pinned,
            created_at,
            created_by_user_id
        FROM event_notes
        WHERE event_id = %s
        ORDER BY is_pinned DESC, created_at DESC
        LIMIT %s OFFSET %s
    """, (event_id, limit, offset))

    notes = cursor.fetchall()

    formatted_notes = []
    for note in notes:
        formatted_notes.append({
            'note_uuid': note['note_uuid'],
            'note_type': note['note_type'],
            'note_content': note['note_content'],
            'is_pinned': bool(note['is_pinned']),
            'created_at': note['created_at'].isoformat() if note['created_at'] else None,
            'created_by_user_id': note['created_by_user_id']
        })

    return formatted_notes


def get_ip_report_history(
    cursor,
    ip_address: str,
    limit: int = 10
) -> List[Dict[str, Any]]:
    """
    Get report history for an IP address.

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address to get reports for
        limit: Maximum number of reports to return

    Returns:
        List of report dictionaries
    """

    cursor.execute("""
        SELECT
            report_uuid,
            report_service,
            report_status,
            report_categories,
            report_comment,
            external_report_id,
            created_at,
            created_by_user_id
        FROM ip_reports
        WHERE ip_address_text = %s
        ORDER BY created_at DESC
        LIMIT %s
    """, (ip_address, limit))

    reports = cursor.fetchall()

    formatted_reports = []
    for report in reports:
        formatted_reports.append({
            'report_uuid': report['report_uuid'],
            'report_service': report['report_service'],
            'report_status': report['report_status'],
            'report_categories': report['report_categories'],
            'report_comment': report['report_comment'],
            'external_report_id': report['external_report_id'],
            'created_at': report['created_at'].isoformat() if report['created_at'] else None,
            'created_by_user_id': report['created_by_user_id']
        })

    return formatted_reports


def add_to_whitelist(
    cursor,
    ip_address: str,
    reason: str,
    expires_at: Optional[str] = None,
    user_id: Optional[int] = None
) -> int:
    """
    Add an IP address to the whitelist.
    Handles duplicate entries by updating if exists.

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address to whitelist
        reason: Reason for whitelisting
        expires_at: Optional expiration timestamp
        user_id: Optional user ID who created the entry

    Returns:
        whitelist_id: ID of the whitelist entry
    """

    # Use INSERT ... ON DUPLICATE KEY UPDATE to handle duplicates
    cursor.execute("""
        INSERT INTO ip_whitelist (
            ip_address_text,
            whitelist_reason,
            whitelist_source,
            is_active,
            expires_at,
            created_by_user_id
        ) VALUES (%s, %s, 'manual', TRUE, %s, %s)
        ON DUPLICATE KEY UPDATE
            whitelist_reason = VALUES(whitelist_reason),
            is_active = TRUE,
            expires_at = VALUES(expires_at),
            created_by_user_id = VALUES(created_by_user_id),
            updated_at = CURRENT_TIMESTAMP
    """, (ip_address, reason, expires_at, user_id))

    whitelist_id = cursor.lastrowid

    # If lastrowid is 0, it means we updated an existing record, get its ID
    if whitelist_id == 0:
        cursor.execute("""
            SELECT id FROM ip_whitelist WHERE ip_address_text = %s
        """, (ip_address,))
        result = cursor.fetchone()
        whitelist_id = result['id'] if result else None

    return whitelist_id


def add_to_watchlist(
    cursor,
    ip_address: str,
    reason: str,
    watch_level: str,
    event_id: Optional[int] = None,
    notify: bool = True,
    user_id: Optional[int] = None
) -> int:
    """
    Add an IP address to the watchlist.

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address to watch
        reason: Reason for watching
        watch_level: Watch level (low, medium, high, critical)
        event_id: Optional triggering event ID
        notify: Whether to notify on activity
        user_id: Optional user ID who created the entry

    Returns:
        watchlist_id: ID of the watchlist entry
    """

    cursor.execute("""
        INSERT INTO ip_watchlist (
            ip_address_text,
            watch_reason,
            watch_level,
            trigger_event_id,
            is_active,
            notify_on_activity,
            created_by_user_id
        ) VALUES (%s, %s, %s, %s, TRUE, %s, %s)
    """, (ip_address, reason, watch_level, event_id, notify, user_id))

    return cursor.lastrowid


def add_note(
    cursor,
    note_type: str,
    content: str,
    event_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_id: Optional[int] = None
) -> Tuple[int, str]:
    """
    Add a note for an event or IP address.

    Args:
        cursor: Database cursor (dictionary=True)
        note_type: Type of note ('event', 'ip', 'general')
        content: Note content
        event_id: Optional event ID
        ip_address: Optional IP address
        user_id: Optional user ID who created the note

    Returns:
        Tuple of (note_id, note_uuid)
    """

    note_uuid = str(uuid.uuid4())

    cursor.execute("""
        INSERT INTO event_notes (
            note_uuid,
            note_type,
            event_id,
            ip_address_text,
            note_content,
            is_pinned,
            created_by_user_id
        ) VALUES (%s, %s, %s, %s, %s, FALSE, %s)
    """, (note_uuid, note_type, event_id, ip_address, content, user_id))

    note_id = cursor.lastrowid

    return note_id, note_uuid


def create_report_entry(
    cursor,
    ip_address: str,
    service: str,
    categories: Optional[List[str]] = None,
    comment: Optional[str] = None,
    event_id: Optional[int] = None,
    user_id: Optional[int] = None
) -> Tuple[int, str]:
    """
    Create a report entry for an IP address.

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address being reported
        service: Report service ('abuseipdb', 'manual', 'internal')
        categories: Optional list of abuse categories
        comment: Optional comment for the report
        event_id: Optional triggering event ID
        user_id: Optional user ID who created the report

    Returns:
        Tuple of (report_id, report_uuid)
    """

    report_uuid = str(uuid.uuid4())

    # Convert categories list to JSON if provided
    import json
    categories_json = json.dumps(categories) if categories else None

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
        ) VALUES (%s, %s, %s, %s, %s, %s, 'pending', %s)
    """, (report_uuid, ip_address, service, categories_json, comment, event_id, user_id))

    report_id = cursor.lastrowid

    return report_id, report_uuid


def get_whitelist_status(cursor, ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Check if an IP address is whitelisted.
    Includes CIDR range check for subnet whitelisting.

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address to check

    Returns:
        Whitelist entry dict if found, None otherwise
    """

    # First check for exact match
    cursor.execute("""
        SELECT
            id,
            ip_address_text,
            ip_range_cidr,
            whitelist_reason,
            whitelist_source,
            is_active,
            expires_at,
            created_at
        FROM ip_whitelist
        WHERE ip_address_text = %s
          AND is_active = 1
          AND (expires_at IS NULL OR expires_at > NOW())
        LIMIT 1
    """, (ip_address,))

    result = cursor.fetchone()

    if result:
        return {
            'id': result['id'],
            'ip_address_text': result['ip_address_text'],
            'ip_range_cidr': result['ip_range_cidr'],
            'whitelist_reason': result['whitelist_reason'],
            'whitelist_source': result['whitelist_source'],
            'is_active': bool(result['is_active']),
            'expires_at': result['expires_at'].isoformat() if result['expires_at'] else None,
            'created_at': result['created_at'].isoformat() if result['created_at'] else None
        }

    # TODO: Add CIDR range check if needed
    # This would require additional logic to check if IP falls within any CIDR ranges

    return None


def get_watchlist_status(cursor, ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Check if an IP address is on the watchlist.

    Args:
        cursor: Database cursor (dictionary=True)
        ip_address: IP address to check

    Returns:
        Watchlist entry dict with watch_level if found, None otherwise
    """

    cursor.execute("""
        SELECT
            id,
            ip_address_text,
            watch_reason,
            watch_level,
            trigger_event_id,
            is_active,
            notify_on_activity,
            expires_at,
            created_at
        FROM ip_watchlist
        WHERE ip_address_text = %s
          AND is_active = 1
          AND (expires_at IS NULL OR expires_at > NOW())
        ORDER BY created_at DESC
        LIMIT 1
    """, (ip_address,))

    result = cursor.fetchone()

    if result:
        return {
            'id': result['id'],
            'ip_address_text': result['ip_address_text'],
            'watch_reason': result['watch_reason'],
            'watch_level': result['watch_level'],
            'trigger_event_id': result['trigger_event_id'],
            'is_active': bool(result['is_active']),
            'notify_on_activity': bool(result['notify_on_activity']),
            'expires_at': result['expires_at'].isoformat() if result['expires_at'] else None,
            'created_at': result['created_at'].isoformat() if result['created_at'] else None
        }

    return None
