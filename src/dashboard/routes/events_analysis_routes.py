"""
Events Analysis Routes - API endpoints for auth events analysis
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

events_analysis_routes = Blueprint('events_analysis', __name__)


@events_analysis_routes.route('/list', methods=['GET'])
def get_events_list():
    """
    Get paginated list of auth events
    Query params:
    - page: Page number (default: 1)
    - limit: Items per page (default: 20)
    - sort: Sort field (default: timestamp)
    - order: Sort order (asc/desc, default: desc)
    - search: Search IP or username
    - event_type: Filter by event type (failed/successful/invalid)
    - risk_level: Filter by risk level (high/medium/low)
    - anomaly: Filter by anomaly status (true/false)
    """
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        sort = request.args.get('sort', 'timestamp')
        order = request.args.get('order', 'desc').upper()
        search = request.args.get('search', '')
        event_type = request.args.get('event_type', '')
        risk_level = request.args.get('risk_level', '')
        anomaly = request.args.get('anomaly', '')

        # Validate parameters
        if order not in ['ASC', 'DESC']:
            order = 'DESC'

        allowed_sort_fields = ['timestamp', 'source_ip_text', 'ml_risk_score',
                               'event_type', 'target_username']
        if sort not in allowed_sort_fields:
            sort = 'timestamp'

        offset = (page - 1) * limit

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build WHERE clause
        where_conditions = []
        params = []

        if search:
            where_conditions.append("(e.source_ip_text LIKE %s OR e.target_username LIKE %s)")
            params.append(f"%{search}%")
            params.append(f"%{search}%")

        if event_type:
            where_conditions.append("e.event_type = %s")
            params.append(event_type)

        if risk_level:
            if risk_level == 'high':
                where_conditions.append("e.ml_risk_score >= 70")
            elif risk_level == 'medium':
                where_conditions.append("e.ml_risk_score >= 40 AND e.ml_risk_score < 70")
            elif risk_level == 'low':
                where_conditions.append("e.ml_risk_score < 40")

        if anomaly:
            if anomaly.lower() == 'true':
                where_conditions.append("e.is_anomaly = 1")
            elif anomaly.lower() == 'false':
                where_conditions.append("e.is_anomaly = 0")

        where_clause = ""
        if where_conditions:
            where_clause = "WHERE " + " AND ".join(where_conditions)

        # Get total count
        count_query = f"""
            SELECT COUNT(*) as total
            FROM auth_events e
            {where_clause}
        """
        cursor.execute(count_query, params)
        total_count = cursor.fetchone()['total']

        # Get data with pagination
        query = f"""
            SELECT
                e.id,
                e.event_uuid,
                e.timestamp,
                e.event_type,
                e.auth_method,
                e.source_ip_text,
                e.source_port,
                e.target_server,
                e.target_port,
                e.target_username,
                e.failure_reason,
                e.ml_risk_score,
                e.ml_threat_type,
                e.is_anomaly,
                e.anomaly_reasons,
                e.was_blocked,
                e.created_at,
                g.country_name,
                g.country_code,
                g.city
            FROM auth_events e
            LEFT JOIN ip_geolocation g ON e.geo_id = g.id
            {where_clause}
            ORDER BY e.{sort} {order}
            LIMIT %s OFFSET %s
        """

        query_params = params + [limit, offset]
        cursor.execute(query, query_params)
        events = cursor.fetchall()

        # Format dates and parse JSON fields
        for event in events:
            if event.get('timestamp'):
                event['timestamp'] = event['timestamp'].isoformat()
            if event.get('created_at'):
                event['created_at'] = event['created_at'].isoformat()

            # Parse anomaly_reasons if it's a JSON string
            if event.get('anomaly_reasons') and isinstance(event['anomaly_reasons'], str):
                import json
                try:
                    event['anomaly_reasons'] = json.loads(event['anomaly_reasons'])
                except:
                    pass

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': events,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'pages': (total_count + limit - 1) // limit
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@events_analysis_routes.route('/summary', methods=['GET'])
def get_events_summary():
    """
    Get overall events summary statistics
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get overall statistics
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful_count,
                SUM(CASE WHEN event_type = 'invalid' THEN 1 ELSE 0 END) as invalid_count,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomaly_count,
                SUM(CASE WHEN was_blocked = 1 THEN 1 ELSE 0 END) as blocked_count,
                AVG(ml_risk_score) as avg_risk_score,
                MAX(ml_risk_score) as max_risk_score,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                COUNT(DISTINCT target_username) as unique_usernames
            FROM auth_events
        """)
        summary = cursor.fetchone()

        # Get risk level distribution
        cursor.execute("""
            SELECT
                CASE
                    WHEN ml_risk_score >= 70 THEN 'high'
                    WHEN ml_risk_score >= 40 THEN 'medium'
                    ELSE 'low'
                END as risk_level,
                COUNT(*) as count
            FROM auth_events
            WHERE ml_risk_score IS NOT NULL
            GROUP BY risk_level
        """)
        risk_distribution = {row['risk_level']: row['count'] for row in cursor.fetchall()}

        # Get events by type
        cursor.execute("""
            SELECT
                event_type,
                COUNT(*) as count
            FROM auth_events
            GROUP BY event_type
        """)
        events_by_type = {row['event_type']: row['count'] for row in cursor.fetchall()}

        # Get top failure reasons
        cursor.execute("""
            SELECT
                failure_reason,
                COUNT(*) as count
            FROM auth_events
            WHERE failure_reason IS NOT NULL AND failure_reason != ''
            GROUP BY failure_reason
            ORDER BY count DESC
            LIMIT 10
        """)
        top_failure_reasons = cursor.fetchall()

        # Get top targeted usernames
        cursor.execute("""
            SELECT
                target_username,
                COUNT(*) as count,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_count
            FROM auth_events
            WHERE target_username IS NOT NULL
            GROUP BY target_username
            ORDER BY count DESC
            LIMIT 10
        """)
        top_usernames = cursor.fetchall()

        # Get authentication methods distribution
        cursor.execute("""
            SELECT
                auth_method,
                COUNT(*) as count
            FROM auth_events
            WHERE auth_method IS NOT NULL
            GROUP BY auth_method
        """)
        auth_methods = {row['auth_method']: row['count'] for row in cursor.fetchall()}

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'summary': summary,
                'risk_distribution': risk_distribution,
                'events_by_type': events_by_type,
                'top_failure_reasons': top_failure_reasons,
                'top_usernames': top_usernames,
                'auth_methods': auth_methods
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@events_analysis_routes.route('/timeline', methods=['GET'])
def get_events_timeline():
    """
    Get time-series data for events
    Query params:
    - interval: Time interval (hour/day/week, default: day)
    - days: Number of days back (default: 7)
    """
    try:
        interval = request.args.get('interval', 'day')
        days = int(request.args.get('days', 7))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build time grouping based on interval
        if interval == 'hour':
            time_format = '%Y-%m-%d %H:00:00'
            group_by = "DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00')"
        elif interval == 'week':
            time_format = '%Y-%u'
            group_by = "DATE_FORMAT(timestamp, '%Y-%u')"
        else:  # day
            time_format = '%Y-%m-%d'
            group_by = "DATE(timestamp)"

        # Get events timeline
        query = f"""
            SELECT
                {group_by} as time_period,
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful,
                SUM(CASE WHEN event_type = 'invalid' THEN 1 ELSE 0 END) as invalid,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                AVG(ml_risk_score) as avg_risk_score
            FROM auth_events
            WHERE timestamp >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY time_period
            ORDER BY time_period ASC
        """

        cursor.execute(query, (days,))
        timeline = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'timeline': timeline,
                'interval': interval,
                'days': days
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@events_analysis_routes.route('/<int:event_id>', methods=['GET'])
def get_event_detail(event_id):
    """
    Get detailed information for a specific event
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get event details
        cursor.execute("""
            SELECT
                e.id,
                e.event_uuid,
                e.timestamp,
                e.processed_at,
                e.source_type,
                e.agent_id,
                e.event_type,
                e.auth_method,
                e.source_ip_text,
                e.source_port,
                e.target_server,
                e.target_port,
                e.target_username,
                e.failure_reason,
                e.session_id,
                e.session_duration_sec,
                e.ml_risk_score,
                e.ml_threat_type,
                e.ml_confidence,
                e.is_anomaly,
                e.anomaly_reasons,
                e.was_blocked,
                e.block_id,
                e.raw_log_line,
                e.additional_metadata,
                e.created_at,
                g.country_name,
                g.country_code,
                g.city,
                g.region,
                g.latitude,
                g.longitude,
                g.timezone
            FROM auth_events e
            LEFT JOIN ip_geolocation g ON e.geo_id = g.id
            WHERE e.id = %s
        """, (event_id,))

        event = cursor.fetchone()

        if not event:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Event not found'
            }), 404

        # Format dates
        if event.get('timestamp'):
            event['timestamp'] = event['timestamp'].isoformat()
        if event.get('created_at'):
            event['created_at'] = event['created_at'].isoformat()

        # Parse JSON fields
        if event.get('anomaly_reasons') and isinstance(event['anomaly_reasons'], str):
            import json
            try:
                event['anomaly_reasons'] = json.loads(event['anomaly_reasons'])
            except:
                pass

        if event.get('additional_metadata') and isinstance(event['additional_metadata'], str):
            import json
            try:
                event['additional_metadata'] = json.loads(event['additional_metadata'])
            except:
                pass

        # Get related events from same IP
        cursor.execute("""
            SELECT
                id,
                event_type,
                target_username,
                ml_risk_score,
                timestamp
            FROM auth_events
            WHERE source_ip_text = %s
                AND id != %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (event['source_ip_text'], event_id))

        related_events = cursor.fetchall()

        # Format timestamps for related events
        for rel_event in related_events:
            if rel_event.get('timestamp'):
                rel_event['timestamp'] = rel_event['timestamp'].isoformat()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': {
                'event': event,
                'related_events': related_events
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
