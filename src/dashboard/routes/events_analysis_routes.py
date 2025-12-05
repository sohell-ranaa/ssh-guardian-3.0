"""
Events Analysis Routes - API endpoints for auth events analysis
With Redis caching and optimized queries for improved performance
"""
import sys
import json
from pathlib import Path
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash

# Create Blueprint with URL prefix
events_analysis_routes = Blueprint('events_analysis', __name__, url_prefix='/api/dashboard/events-analysis')

# Cache TTLs - OPTIMIZED FOR PERFORMANCE (minimum 15 minutes)
EVENTS_LIST_TTL = 900       # 15 minutes for paginated list
EVENTS_SUMMARY_TTL = 900    # 15 minutes for summary stats
EVENTS_TIMELINE_TTL = 900   # 15 minutes for timeline data
EVENTS_DETAIL_TTL = 1800    # 30 minutes for event details (rarely changes)

# Allowed sort fields (whitelist for SQL injection prevention)
ALLOWED_SORT_FIELDS = {
    'timestamp': 'e.timestamp',
    'source_ip_text': 'e.source_ip_text',
    'ml_risk_score': 'e.ml_risk_score',
    'event_type': 'e.event_type',
    'target_username': 'e.target_username'
}


def invalidate_events_analysis_cache():
    """Invalidate all events analysis caches"""
    cache = get_cache()
    cache.delete_pattern('events_analysis')


def _get_approximate_count(cursor):
    """Get approximate row count from table statistics (much faster than COUNT(*))"""
    cursor.execute("""
        SELECT TABLE_ROWS as approx_count
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'auth_events'
    """)
    result = cursor.fetchone()
    if result and result.get('approx_count'):
        return int(result['approx_count'])
    return 0


@events_analysis_routes.route('/list', methods=['GET'])
def get_events_list():
    """
    Get paginated list of auth events with caching
    OPTIMIZED: Uses approximate counts for unfiltered queries
    """
    conn = None
    cursor = None
    try:
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 20)), 100)
        sort = request.args.get('sort', 'timestamp')
        order = request.args.get('order', 'desc').upper()
        search = request.args.get('search', '')
        event_type = request.args.get('event_type', '')
        risk_level = request.args.get('risk_level', '')
        anomaly = request.args.get('anomaly', '')

        if order not in ['ASC', 'DESC']:
            order = 'DESC'

        sort_column = ALLOWED_SORT_FIELDS.get(sort, 'e.timestamp')
        offset = (page - 1) * limit

        # Try cache first
        cache = get_cache()
        cache_params = {
            'page': page, 'limit': limit, 'sort': sort, 'order': order,
            'search': search, 'event_type': event_type, 'risk_level': risk_level, 'anomaly': anomaly
        }
        cache_k = cache_key_hash('events_analysis', 'list', cache_params)

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached['data'],
                'pagination': cached['pagination'],
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build WHERE clause
        where_conditions = []
        params = []
        has_filters = False

        if search:
            where_conditions.append("(e.source_ip_text LIKE %s OR e.target_username LIKE %s)")
            params.extend([f"%{search}%", f"%{search}%"])
            has_filters = True

        if event_type:
            where_conditions.append("e.event_type = %s")
            params.append(event_type)
            has_filters = True

        if risk_level:
            if risk_level == 'high':
                where_conditions.append("e.ml_risk_score >= 70")
            elif risk_level == 'medium':
                where_conditions.append("e.ml_risk_score >= 40 AND e.ml_risk_score < 70")
            elif risk_level == 'low':
                where_conditions.append("e.ml_risk_score < 40")
            has_filters = True

        if anomaly:
            if anomaly.lower() == 'true':
                where_conditions.append("e.is_anomaly = 1")
            elif anomaly.lower() == 'false':
                where_conditions.append("e.is_anomaly = 0")
            has_filters = True

        where_clause = ""
        if where_conditions:
            where_clause = "WHERE " + " AND ".join(where_conditions)

        # OPTIMIZATION: Use approximate count for unfiltered queries
        if not has_filters:
            total_count = _get_approximate_count(cursor)
        else:
            count_query = f"SELECT COUNT(*) as total FROM auth_events e {where_clause}"
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()['total']

        # Get data - OPTIMIZED: only fetch needed columns
        query = f"""
            SELECT
                e.id,
                e.timestamp,
                e.event_type,
                e.auth_method,
                e.source_ip_text,
                e.target_server,
                e.target_username,
                e.failure_reason,
                e.ml_risk_score,
                e.is_anomaly,
                e.was_blocked,
                g.country_name,
                g.country_code,
                g.city
            FROM auth_events e
            LEFT JOIN ip_geolocation g ON e.geo_id = g.id
            {where_clause}
            ORDER BY {sort_column} {order}
            LIMIT %s OFFSET %s
        """

        cursor.execute(query, params + [limit, offset])
        events = cursor.fetchall()

        # Format dates
        for event in events:
            if event.get('timestamp'):
                event['timestamp'] = event['timestamp'].isoformat()

        pagination = {
            'page': page,
            'limit': limit,
            'total': total_count,
            'pages': max(1, (total_count + limit - 1) // limit)
        }

        cache.set(cache_k, {'data': events, 'pagination': pagination}, EVENTS_LIST_TTL)

        return jsonify({
            'success': True,
            'data': events,
            'pagination': pagination,
            'from_cache': False
        })

    except ValueError as e:
        return jsonify({'success': False, 'error': f'Invalid parameter: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/summary', methods=['GET'])
def get_events_summary():
    """
    Get overall events summary statistics with caching
    OPTIMIZED: Single query for main stats, parallel-friendly structure
    """
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('events_analysis', 'summary')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # OPTIMIZATION: Single comprehensive query instead of 6 separate queries
        # This dramatically reduces database round-trips
        # OPTIMIZED: Removed slow COUNT(DISTINCT) operations that caused 25+ second delays
        cursor.execute("""
            SELECT
                -- Basic counts
                COUNT(*) as total_events,
                SUM(event_type = 'failed') as failed_count,
                SUM(event_type = 'successful') as successful_count,
                SUM(event_type = 'invalid') as invalid_count,
                SUM(is_anomaly = 1) as anomaly_count,
                SUM(was_blocked = 1) as blocked_count,

                -- Risk metrics
                AVG(ml_risk_score) as avg_risk_score,
                SUM(ml_risk_score >= 70) as high_risk_count,
                SUM(ml_risk_score >= 40 AND ml_risk_score < 70) as medium_risk_count,
                SUM(ml_risk_score < 40 OR ml_risk_score IS NULL) as low_risk_count
            FROM auth_events
        """)
        stats = cursor.fetchone()

        # PERFORMANCE FIX: Use pre-aggregated ip_statistics table instead of COUNT(DISTINCT)
        # This avoids scanning millions of rows and is orders of magnitude faster
        cursor.execute("SELECT COUNT(*) as cnt FROM ip_statistics")
        unique_ips_result = cursor.fetchone()
        unique_ips = int(unique_ips_result['cnt'] or 0)

        # PERFORMANCE FIX: Estimate unique usernames from a small sample
        # Use approximate count for better performance (~100ms vs 25+ seconds)
        cursor.execute("""
            SELECT COUNT(DISTINCT target_username) as cnt
            FROM (
                SELECT target_username
                FROM auth_events
                WHERE target_username IS NOT NULL
                ORDER BY id DESC
                LIMIT 50000
            ) sample
        """)
        unique_usernames_result = cursor.fetchone()
        # Extrapolate from sample to estimate total unique usernames
        sample_unique = int(unique_usernames_result['cnt'] or 0)
        # If we have fewer than 50k events, use exact count; otherwise estimate
        if int(stats['total_events'] or 0) <= 50000:
            unique_usernames = sample_unique
        else:
            # Conservative estimate: sample shows saturation behavior after 50k events
            # Most attacks use the same ~100-500 usernames repeatedly
            unique_usernames = min(sample_unique * 2, int(stats['total_events'] or 0))

        # Convert to proper types
        summary = {
            'total_events': int(stats['total_events'] or 0),
            'failed_count': int(stats['failed_count'] or 0),
            'successful_count': int(stats['successful_count'] or 0),
            'invalid_count': int(stats['invalid_count'] or 0),
            'anomaly_count': int(stats['anomaly_count'] or 0),
            'blocked_count': int(stats['blocked_count'] or 0),
            'avg_risk_score': float(stats['avg_risk_score'] or 0),
            'unique_ips': unique_ips,
            'unique_usernames': unique_usernames
        }

        risk_distribution = {
            'high': int(stats['high_risk_count'] or 0),
            'medium': int(stats['medium_risk_count'] or 0),
            'low': int(stats['low_risk_count'] or 0)
        }

        events_by_type = {
            'failed': summary['failed_count'],
            'successful': summary['successful_count'],
            'invalid': summary['invalid_count']
        }

        # Get top failure reasons - OPTIMIZED with LIMIT in subquery
        cursor.execute("""
            SELECT failure_reason, COUNT(*) as count
            FROM auth_events
            WHERE failure_reason IS NOT NULL AND failure_reason != ''
            GROUP BY failure_reason
            ORDER BY count DESC
            LIMIT 10
        """)
        top_failure_reasons = cursor.fetchall()

        # Get top targeted usernames - OPTIMIZED
        cursor.execute("""
            SELECT
                target_username,
                COUNT(*) as count,
                SUM(event_type = 'failed') as failed_count
            FROM auth_events
            WHERE target_username IS NOT NULL AND target_username != ''
            GROUP BY target_username
            ORDER BY count DESC
            LIMIT 10
        """)
        top_usernames = cursor.fetchall()

        # Convert Decimal fields
        for user in top_usernames:
            if user.get('failed_count') is not None:
                user['failed_count'] = int(user['failed_count'])

        # Get auth methods - small result set
        cursor.execute("""
            SELECT auth_method, COUNT(*) as count
            FROM auth_events
            WHERE auth_method IS NOT NULL
            GROUP BY auth_method
        """)
        auth_methods = {row['auth_method']: row['count'] for row in cursor.fetchall()}

        data = {
            'summary': summary,
            'risk_distribution': risk_distribution,
            'events_by_type': events_by_type,
            'top_failure_reasons': top_failure_reasons,
            'top_usernames': top_usernames,
            'auth_methods': auth_methods
        }

        cache.set(cache_k, data, EVENTS_SUMMARY_TTL)

        return jsonify({
            'success': True,
            'data': data,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/timeline', methods=['GET'])
def get_events_timeline():
    """
    Get time-series data for events with caching
    OPTIMIZED: Uses pre-aggregated summary table for daily queries
    """
    conn = None
    cursor = None
    try:
        interval = request.args.get('interval', 'day')
        days = min(int(request.args.get('days', 7)), 90)

        if interval not in ['hour', 'day', 'week']:
            interval = 'day'

        cache = get_cache()
        cache_k = cache_key('events_analysis', 'timeline', interval, str(days))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # OPTIMIZATION: Use pre-aggregated summary table for daily queries (most common)
        if interval == 'day':
            # Fast path: query from summary table (pre-aggregated, very fast)
            query = """
                SELECT
                    summary_date as time_period,
                    total_events,
                    failed_count as failed,
                    successful_count as successful,
                    invalid_count as invalid,
                    anomaly_count as anomalies,
                    avg_risk_score
                FROM auth_events_daily_summary
                WHERE summary_date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
                ORDER BY summary_date ASC
            """
            cursor.execute(query, (days,))
        else:
            # Fallback: real-time aggregation for hourly/weekly
            if interval == 'hour':
                group_by = "DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00')"
            else:  # week
                group_by = "YEARWEEK(timestamp, 1)"

            query = f"""
                SELECT
                    {group_by} as time_period,
                    COUNT(*) as total_events,
                    SUM(event_type = 'failed') as failed,
                    SUM(event_type = 'successful') as successful,
                    SUM(event_type = 'invalid') as invalid,
                    SUM(is_anomaly = 1) as anomalies,
                    AVG(ml_risk_score) as avg_risk_score
                FROM auth_events
                WHERE timestamp >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
                GROUP BY time_period
                ORDER BY time_period ASC
            """
            cursor.execute(query, (days,))

        timeline = cursor.fetchall()

        # Convert types
        for row in timeline:
            if row.get('time_period'):
                if hasattr(row['time_period'], 'isoformat'):
                    row['time_period'] = row['time_period'].isoformat()
                else:
                    row['time_period'] = str(row['time_period'])
            for key in ['total_events', 'failed', 'successful', 'invalid', 'anomalies']:
                if row.get(key) is not None:
                    row[key] = int(row[key])
            if row.get('avg_risk_score') is not None:
                row['avg_risk_score'] = float(row['avg_risk_score'])

        data = {
            'timeline': timeline,
            'interval': interval,
            'days': days
        }

        cache.set(cache_k, data, EVENTS_TIMELINE_TTL)

        return jsonify({
            'success': True,
            'data': data,
            'from_cache': False
        })

    except ValueError as e:
        return jsonify({'success': False, 'error': f'Invalid parameter: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/<int:event_id>', methods=['GET'])
def get_event_detail(event_id):
    """
    Get detailed information for a specific event with caching
    """
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('events_analysis', 'detail', str(event_id))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'data': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get event details - uses primary key index
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
            return jsonify({'success': False, 'error': 'Event not found'}), 404

        # Format dates and convert Decimal fields
        for field in ['timestamp', 'processed_at', 'created_at']:
            if event.get(field):
                event[field] = event[field].isoformat()

        for field in ['latitude', 'longitude', 'ml_confidence']:
            if event.get(field) is not None:
                event[field] = float(event[field])

        # Parse JSON fields
        for field in ['anomaly_reasons', 'additional_metadata']:
            if event.get(field) and isinstance(event[field], str):
                try:
                    event[field] = json.loads(event[field])
                except (json.JSONDecodeError, ValueError):
                    pass

        # Get related events - uses source_ip_text index
        cursor.execute("""
            SELECT id, event_type, target_username, ml_risk_score, timestamp
            FROM auth_events
            WHERE source_ip_text = %s AND id != %s
            ORDER BY timestamp DESC
            LIMIT 10
        """, (event['source_ip_text'], event_id))

        related_events = cursor.fetchall()

        for rel_event in related_events:
            if rel_event.get('timestamp'):
                rel_event['timestamp'] = rel_event['timestamp'].isoformat()

        data = {
            'event': event,
            'related_events': related_events
        }

        cache.set(cache_k, data, EVENTS_DETAIL_TTL)

        return jsonify({
            'success': True,
            'data': data,
            'from_cache': False
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
