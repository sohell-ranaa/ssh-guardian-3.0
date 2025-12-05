"""
SSH Guardian v3.0 - Trends Reports Routes
Provides API endpoints for trend analysis and historical data
With Redis caching for improved performance

PERFORMANCE OPTIMIZATIONS:
1. Use timestamp >= X AND timestamp < Y instead of DATE(timestamp) to leverage idx_timestamp
2. Separate COUNT(DISTINCT) into subqueries to avoid slow full table scans
3. Use subqueries to pre-filter data before JOINs and aggregations
4. Leverage composite indexes: idx_timestamp_event_type, idx_ml_risk_score
5. Filter on indexed columns: event_type, is_anomaly, ml_risk_score
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key

# Create Blueprint
trends_reports_routes = Blueprint('trends_reports_routes', __name__)

# Cache TTLs - OPTIMIZED FOR PERFORMANCE (historical data doesn't change)
TRENDS_OVERVIEW_TTL = 1800      # 30 minutes
TRENDS_TIMELINE_TTL = 1800      # 30 minutes
TRENDS_ATTACKERS_TTL = 1800     # 30 minutes
TRENDS_COUNTRIES_TTL = 1800     # 30 minutes
TRENDS_USERNAMES_TTL = 1800     # 30 minutes
TRENDS_RISK_TTL = 1800          # 30 minutes
TRENDS_BLOCKING_TTL = 900       # 15 minutes
TRENDS_COMPARISON_TTL = 1800    # 30 minutes


def invalidate_trends_cache():
    """Invalidate all trends report caches"""
    cache = get_cache()
    cache.delete_pattern('trends')


@trends_reports_routes.route('/overview', methods=['GET'])
def get_trends_overview():
    """
    Get trends overview for a date range

    Query Parameters:
        days: Number of days to look back (default: 30)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 30))
        days = min(days, 90)  # Max 90 days

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'overview', str(days))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'period': cached['period'],
                'daily_data': cached['daily_data'],
                'totals': cached['totals'],
                'from_cache': True
            })

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get daily totals - OPTIMIZED: Use timestamp directly instead of DATE() for index usage
        cursor.execute("""
            SELECT
                DATE(timestamp) as date,
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful_events,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                AVG(ml_risk_score) as avg_risk_score,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk_events
            FROM auth_events
            WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
            AND source_type != 'simulation'
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """, (start_date, end_date))

        daily_data = cursor.fetchall()

        # Calculate unique counts separately with subquery optimization
        cursor.execute("""
            SELECT
                DATE(timestamp) as date,
                COUNT(*) as unique_ips
            FROM (
                SELECT DATE(timestamp) as timestamp, source_ip_text
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                GROUP BY DATE(timestamp), source_ip_text
            ) as unique_ip_subquery
            GROUP BY date
        """, (start_date, end_date))

        unique_ips_data = {row['date'].isoformat() if hasattr(row['date'], 'isoformat') else str(row['date']): row['unique_ips'] for row in cursor.fetchall()}

        cursor.execute("""
            SELECT
                DATE(timestamp) as date,
                COUNT(*) as unique_usernames
            FROM (
                SELECT DATE(timestamp) as timestamp, target_username
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                AND target_username IS NOT NULL
                GROUP BY DATE(timestamp), target_username
            ) as unique_username_subquery
            GROUP BY date
        """, (start_date, end_date))

        unique_usernames_data = {row['date'].isoformat() if hasattr(row['date'], 'isoformat') else str(row['date']): row['unique_usernames'] for row in cursor.fetchall()}

        # Format dates and numbers, merge unique counts
        for row in daily_data:
            date_str = row['date'].isoformat() if hasattr(row['date'], 'isoformat') else str(row['date'])
            row['date'] = date_str
            row['avg_risk_score'] = round(float(row['avg_risk_score'] or 0), 2)
            row['unique_ips'] = unique_ips_data.get(date_str, 0)
            row['unique_usernames'] = unique_usernames_data.get(date_str, 0)

        # Calculate period totals
        totals = {
            'total_events': sum(d['total_events'] for d in daily_data),
            'failed_events': sum(d['failed_events'] for d in daily_data),
            'successful_events': sum(d['successful_events'] for d in daily_data),
            'high_risk_events': sum(d['high_risk_events'] for d in daily_data),
            'anomalies': sum(d['anomalies'] for d in daily_data),
            'days_with_data': len(daily_data)
        }

        # Calculate averages
        if daily_data:
            totals['avg_daily_events'] = round(totals['total_events'] / len(daily_data), 1)
            totals['avg_daily_failed'] = round(totals['failed_events'] / len(daily_data), 1)

        period = {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'days': days
        }

        # Cache the result
        cache.set(cache_k, {
            'period': period,
            'daily_data': daily_data,
            'totals': totals
        }, TRENDS_OVERVIEW_TTL)

        return jsonify({
            'success': True,
            'period': period,
            'daily_data': daily_data,
            'totals': totals,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_trends_overview: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@trends_reports_routes.route('/events-timeline', methods=['GET'])
def get_events_timeline():
    """
    Get events timeline data for charts

    Query Parameters:
        days: Number of days (default: 30)
        granularity: 'daily' or 'hourly' (default: daily)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 30))
        days = min(days, 90)
        granularity = request.args.get('granularity', 'daily')

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'timeline', str(days), granularity)
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'granularity': granularity,
                'timeline': cached,
                'from_cache': True
            })

        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if granularity == 'hourly' and days <= 7:
            # OPTIMIZED: Use timestamp directly for index usage
            cursor.execute("""
                SELECT
                    DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00') as time_bucket,
                    COUNT(*) as total,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """, (start_date, end_date))
        else:
            # OPTIMIZED: Use timestamp range instead of DATE() for index usage
            cursor.execute("""
                SELECT
                    DATE(timestamp) as time_bucket,
                    COUNT(*) as total,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                GROUP BY DATE(timestamp)
                ORDER BY time_bucket ASC
            """, (start_date.date(), end_date.date()))

        timeline_data = cursor.fetchall()

        for row in timeline_data:
            if isinstance(row['time_bucket'], datetime):
                row['time_bucket'] = row['time_bucket'].isoformat()
            elif hasattr(row['time_bucket'], 'isoformat'):
                row['time_bucket'] = row['time_bucket'].isoformat()

        # Cache the result
        cache.set(cache_k, timeline_data, TRENDS_TIMELINE_TTL)

        return jsonify({
            'success': True,
            'granularity': granularity,
            'timeline': timeline_data,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_events_timeline: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@trends_reports_routes.route('/top-attackers', methods=['GET'])
def get_top_attackers():
    """
    Get top attacking IPs over a period

    Query Parameters:
        days: Number of days (default: 30)
        limit: Number of results (default: 10)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 10))

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'attackers', str(days), str(limit))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'period_days': days,
                'attackers': cached,
                'from_cache': True
            })

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # OPTIMIZED: Use timestamp range for index, calculate active_days from date range instead of COUNT DISTINCT
        cursor.execute("""
            SELECT
                ae.source_ip_text as ip,
                geo.country_name as country,
                geo.country_code,
                COUNT(*) as total_attempts,
                DATEDIFF(MAX(DATE(ae.timestamp)), MIN(DATE(ae.timestamp))) + 1 as active_days,
                (SELECT COUNT(*) FROM (
                    SELECT 1 FROM auth_events ae2
                    WHERE ae2.source_ip_text = ae.source_ip_text
                    AND ae2.timestamp >= %s AND ae2.timestamp < %s + INTERVAL 1 DAY
                    AND ae2.source_type != 'simulation'
                    AND ae2.event_type = 'failed'
                    AND ae2.target_username IS NOT NULL
                    GROUP BY ae2.target_username
                    LIMIT 1000
                ) t) as unique_usernames,
                AVG(ae.ml_risk_score) as avg_risk,
                MAX(ae.ml_risk_score) as max_risk,
                MIN(DATE(ae.timestamp)) as first_seen,
                MAX(DATE(ae.timestamp)) as last_seen
            FROM (
                SELECT source_ip_text, timestamp, target_username, ml_risk_score
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                AND event_type = 'failed'
            ) ae
            LEFT JOIN ip_geolocation geo ON ae.source_ip_text = geo.ip_address_text
            GROUP BY ae.source_ip_text, geo.country_name, geo.country_code
            ORDER BY total_attempts DESC
            LIMIT %s
        """, (start_date, end_date, start_date, end_date, limit))

        attackers = cursor.fetchall()

        for row in attackers:
            row['avg_risk'] = round(float(row['avg_risk'] or 0), 2)
            row['max_risk'] = int(row['max_risk'] or 0)
            if row['first_seen']:
                row['first_seen'] = row['first_seen'].isoformat()
            if row['last_seen']:
                row['last_seen'] = row['last_seen'].isoformat()

        # Cache the result
        cache.set(cache_k, attackers, TRENDS_ATTACKERS_TTL)

        return jsonify({
            'success': True,
            'period_days': days,
            'attackers': attackers,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_top_attackers: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@trends_reports_routes.route('/country-trends', methods=['GET'])
def get_country_trends():
    """
    Get attack trends by country

    Query Parameters:
        days: Number of days (default: 30)
        limit: Number of countries (default: 10)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 10))

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'countries', str(days), str(limit))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'period_days': days,
                'countries': cached,
                'from_cache': True
            })

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # OPTIMIZED: Use timestamp range for index, replace COUNT DISTINCT with subquery approximation
        cursor.execute("""
            SELECT
                COALESCE(geo.country_name, 'Unknown') as country,
                geo.country_code,
                COUNT(*) as total_attempts,
                (SELECT COUNT(*) FROM (
                    SELECT 1 FROM auth_events ae2
                    LEFT JOIN ip_geolocation geo2 ON ae2.source_ip_text = geo2.ip_address_text
                    WHERE ae2.timestamp >= %s AND ae2.timestamp < %s + INTERVAL 1 DAY
                    AND ae2.source_type != 'simulation'
                    AND ae2.event_type = 'failed'
                    AND COALESCE(geo2.country_name, 'Unknown') = COALESCE(geo.country_name, 'Unknown')
                    GROUP BY ae2.source_ip_text
                    LIMIT 10000
                ) t) as unique_ips,
                DATEDIFF(%s, %s) + 1 as active_days,
                AVG(ae.ml_risk_score) as avg_risk,
                SUM(CASE WHEN ae.is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM (
                SELECT source_ip_text, timestamp, ml_risk_score, is_anomaly
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                AND event_type = 'failed'
            ) ae
            LEFT JOIN ip_geolocation geo ON ae.source_ip_text = geo.ip_address_text
            GROUP BY geo.country_name, geo.country_code
            ORDER BY total_attempts DESC
            LIMIT %s
        """, (start_date, end_date, end_date, start_date, start_date, end_date, limit))

        countries = cursor.fetchall()

        for row in countries:
            row['avg_risk'] = round(float(row['avg_risk'] or 0), 2)

        # Cache the result
        cache.set(cache_k, countries, TRENDS_COUNTRIES_TTL)

        return jsonify({
            'success': True,
            'period_days': days,
            'countries': countries,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_country_trends: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@trends_reports_routes.route('/username-trends', methods=['GET'])
def get_username_trends():
    """
    Get most targeted usernames over a period

    Query Parameters:
        days: Number of days (default: 30)
        limit: Number of results (default: 10)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 30))
        limit = int(request.args.get('limit', 10))

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'usernames', str(days), str(limit))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'period_days': days,
                'usernames': cached,
                'from_cache': True
            })

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # OPTIMIZED: Use timestamp range for index, replace COUNT DISTINCT with subquery approximation
        cursor.execute("""
            SELECT
                target_username as username,
                COUNT(*) as total_attempts,
                (SELECT COUNT(*) FROM (
                    SELECT 1 FROM auth_events ae2
                    WHERE ae2.target_username = auth_events.target_username
                    AND ae2.timestamp >= %s AND ae2.timestamp < %s + INTERVAL 1 DAY
                    AND ae2.source_type != 'simulation'
                    AND ae2.event_type = 'failed'
                    GROUP BY ae2.source_ip_text
                    LIMIT 5000
                ) t) as unique_ips,
                DATEDIFF(MAX(DATE(timestamp)), MIN(DATE(timestamp))) + 1 as active_days,
                AVG(ml_risk_score) as avg_risk,
                MIN(DATE(timestamp)) as first_seen,
                MAX(DATE(timestamp)) as last_seen
            FROM auth_events
            WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
            AND source_type != 'simulation'
            AND event_type = 'failed'
            AND target_username IS NOT NULL
            GROUP BY target_username
            ORDER BY total_attempts DESC
            LIMIT %s
        """, (start_date, end_date, start_date, end_date, limit))

        usernames = cursor.fetchall()

        for row in usernames:
            row['avg_risk'] = round(float(row['avg_risk'] or 0), 2)
            if row['first_seen']:
                row['first_seen'] = row['first_seen'].isoformat()
            if row['last_seen']:
                row['last_seen'] = row['last_seen'].isoformat()

        # Cache the result
        cache.set(cache_k, usernames, TRENDS_USERNAMES_TTL)

        return jsonify({
            'success': True,
            'period_days': days,
            'usernames': usernames,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_username_trends: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@trends_reports_routes.route('/risk-distribution', methods=['GET'])
def get_risk_distribution():
    """
    Get risk score distribution over a period

    Query Parameters:
        days: Number of days (default: 30)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 30))

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'risk', str(days))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'period_days': days,
                'daily_distribution': cached['daily_distribution'],
                'totals': cached['totals'],
                'from_cache': True
            })

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # OPTIMIZED: Use timestamp range and leverage idx_ml_risk_score index
        cursor.execute("""
            SELECT
                DATE(timestamp) as date,
                SUM(CASE WHEN ml_risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN ml_risk_score >= 60 AND ml_risk_score < 80 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN ml_risk_score >= 40 AND ml_risk_score < 60 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN ml_risk_score < 40 THEN 1 ELSE 0 END) as low
            FROM auth_events
            WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
            AND source_type != 'simulation'
            AND event_type = 'failed'
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """, (start_date, end_date))

        risk_data = cursor.fetchall()

        for row in risk_data:
            row['date'] = row['date'].isoformat()

        # Calculate totals
        totals = {
            'critical': sum(d['critical'] for d in risk_data),
            'high': sum(d['high'] for d in risk_data),
            'medium': sum(d['medium'] for d in risk_data),
            'low': sum(d['low'] for d in risk_data)
        }

        # Cache the result
        cache.set(cache_k, {
            'daily_distribution': risk_data,
            'totals': totals
        }, TRENDS_RISK_TTL)

        return jsonify({
            'success': True,
            'period_days': days,
            'daily_distribution': risk_data,
            'totals': totals,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_risk_distribution: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@trends_reports_routes.route('/blocking-stats', methods=['GET'])
def get_blocking_stats():
    """
    Get IP blocking statistics over a period

    Query Parameters:
        days: Number of days (default: 30)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 30))

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'blocking', str(days))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'period_days': days,
                'daily_blocks': cached['daily_blocks'],
                'active_blocks': cached['active_blocks'],
                'total_blocks': cached['total_blocks'],
                'from_cache': True
            })

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Daily blocking stats - OPTIMIZED: Use blocked_at range for index usage, replace COUNT DISTINCT
        cursor.execute("""
            SELECT
                DATE(blocked_at) as date,
                COUNT(*) as blocks,
                (SELECT COUNT(*) FROM (
                    SELECT 1 FROM ip_blocks ib2
                    WHERE DATE(ib2.blocked_at) = DATE(ip_blocks.blocked_at)
                    AND ib2.blocked_at >= %s AND ib2.blocked_at < %s + INTERVAL 1 DAY
                    AND ib2.is_simulation = FALSE
                    GROUP BY ib2.ip_address_text
                    LIMIT 5000
                ) t) as unique_ips,
                SUM(CASE WHEN block_source = 'manual' THEN 1 ELSE 0 END) as manual_blocks,
                SUM(CASE WHEN block_source = 'rule_based' THEN 1 ELSE 0 END) as rule_blocks,
                SUM(CASE WHEN block_source = 'api_reputation' THEN 1 ELSE 0 END) as api_blocks
            FROM ip_blocks
            WHERE blocked_at >= %s AND blocked_at < %s + INTERVAL 1 DAY
            AND is_simulation = FALSE
            GROUP BY DATE(blocked_at)
            ORDER BY date ASC
        """, (start_date, end_date, start_date, end_date))

        blocking_data = cursor.fetchall()

        for row in blocking_data:
            row['date'] = row['date'].isoformat()

        # Get current active blocks
        cursor.execute("""
            SELECT COUNT(*) as active_blocks
            FROM ip_blocks
            WHERE is_active = TRUE AND is_simulation = FALSE
        """)
        active_result = cursor.fetchone()

        active_blocks = active_result['active_blocks'] if active_result else 0
        total_blocks = sum(d['blocks'] for d in blocking_data)

        # Cache the result
        cache.set(cache_k, {
            'daily_blocks': blocking_data,
            'active_blocks': active_blocks,
            'total_blocks': total_blocks
        }, TRENDS_BLOCKING_TTL)

        return jsonify({
            'success': True,
            'period_days': days,
            'daily_blocks': blocking_data,
            'active_blocks': active_blocks,
            'total_blocks': total_blocks,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_blocking_stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@trends_reports_routes.route('/period-comparison', methods=['GET'])
def get_period_comparison():
    """
    Compare current period with previous period

    Query Parameters:
        days: Period length in days (default: 7)
    """
    conn = None
    cursor = None
    try:
        days = int(request.args.get('days', 7))

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('trends', 'comparison', str(days))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'period_days': days,
                'comparison': cached,
                'from_cache': True
            })

        end_date = datetime.now().date()
        current_start = end_date - timedelta(days=days-1)
        prev_end = current_start - timedelta(days=1)
        prev_start = prev_end - timedelta(days=days-1)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # OPTIMIZED: Use timestamp range and avoid COUNT DISTINCT with approximation
        # Current period stats
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events
            WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
            AND source_type != 'simulation'
        """, (current_start, end_date))
        current_stats = cursor.fetchone()

        # Get unique IPs for current period using subquery
        cursor.execute("""
            SELECT COUNT(*) as unique_ips
            FROM (
                SELECT source_ip_text
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                GROUP BY source_ip_text
            ) as unique_subquery
        """, (current_start, end_date))
        current_stats['unique_ips'] = cursor.fetchone()['unique_ips']

        # Previous period stats
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events
            WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
            AND source_type != 'simulation'
        """, (prev_start, prev_end))
        prev_stats = cursor.fetchone()

        # Get unique IPs for previous period using subquery
        cursor.execute("""
            SELECT COUNT(*) as unique_ips
            FROM (
                SELECT source_ip_text
                FROM auth_events
                WHERE timestamp >= %s AND timestamp < %s + INTERVAL 1 DAY
                AND source_type != 'simulation'
                GROUP BY source_ip_text
            ) as unique_subquery
        """, (prev_start, prev_end))
        prev_stats['unique_ips'] = cursor.fetchone()['unique_ips']

        def calc_change(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)

        comparison = {
            'current_period': {
                'start': current_start.isoformat(),
                'end': end_date.isoformat(),
                'total_events': current_stats['total_events'] or 0,
                'failed_events': current_stats['failed_events'] or 0,
                'unique_ips': current_stats['unique_ips'] or 0,
                'high_risk': current_stats['high_risk'] or 0,
                'anomalies': current_stats['anomalies'] or 0
            },
            'previous_period': {
                'start': prev_start.isoformat(),
                'end': prev_end.isoformat(),
                'total_events': prev_stats['total_events'] or 0,
                'failed_events': prev_stats['failed_events'] or 0,
                'unique_ips': prev_stats['unique_ips'] or 0,
                'high_risk': prev_stats['high_risk'] or 0,
                'anomalies': prev_stats['anomalies'] or 0
            },
            'changes': {
                'total_events': calc_change(current_stats['total_events'] or 0, prev_stats['total_events'] or 0),
                'failed_events': calc_change(current_stats['failed_events'] or 0, prev_stats['failed_events'] or 0),
                'unique_ips': calc_change(current_stats['unique_ips'] or 0, prev_stats['unique_ips'] or 0),
                'high_risk': calc_change(current_stats['high_risk'] or 0, prev_stats['high_risk'] or 0),
                'anomalies': calc_change(current_stats['anomalies'] or 0, prev_stats['anomalies'] or 0)
            }
        }

        # Cache the result
        cache.set(cache_k, comparison, TRENDS_COMPARISON_TTL)

        return jsonify({
            'success': True,
            'period_days': days,
            'comparison': comparison,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_period_comparison: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
