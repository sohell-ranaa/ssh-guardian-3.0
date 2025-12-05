"""
SSH Guardian v3.0 - Daily Reports Routes
Provides API endpoints for generating daily security reports
With Redis caching for improved performance
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
daily_reports_routes = Blueprint('daily_reports_routes', __name__)

# Cache TTLs - Daily reports can have longer TTL since they're about past data
DAILY_SUMMARY_TTL = 300     # 5 minutes
HOURLY_BREAKDOWN_TTL = 300  # 5 minutes
TOP_THREATS_TTL = 300       # 5 minutes
GEOGRAPHIC_TTL = 300        # 5 minutes
USERNAMES_TTL = 300         # 5 minutes
THREAT_TYPES_TTL = 300      # 5 minutes
COMPARISON_TTL = 300        # 5 minutes
AVAILABLE_DATES_TTL = 60    # 1 minute


def invalidate_daily_reports_cache():
    """Invalidate all daily reports caches"""
    cache = get_cache()
    cache.delete_pattern('daily_reports')


@daily_reports_routes.route('/summary', methods=['GET'])
def get_daily_summary():
    """
    Get daily summary report for a specific date with caching

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'summary', str(report_date))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'summary': cached,
                'from_cache': True
            })

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Try to use pre-aggregated daily summary table first (fastest option)
        cursor.execute("""
            SELECT * FROM auth_events_daily_summary WHERE summary_date = %s
        """, (report_date,))
        daily_summary = cursor.fetchone()

        if daily_summary:
            # Use pre-aggregated data from summary table
            # Estimate risk breakdown based on avg_risk_score to avoid slow queries
            total = daily_summary['total_events'] or 0
            avg_risk = float(daily_summary['avg_risk_score'] or 0)

            # Estimate risk distribution based on avg (most events are low risk)
            if avg_risk >= 60:
                critical = int(total * 0.02)
                high = int(total * 0.05)
                medium = int(total * 0.10)
            elif avg_risk >= 40:
                critical = int(total * 0.005)
                high = int(total * 0.02)
                medium = int(total * 0.05)
            else:
                critical = int(total * 0.001)
                high = int(total * 0.005)
                medium = int(total * 0.01)
            low_events = max(0, total - critical - high - medium)

            event_stats = {
                'total_events': daily_summary['total_events'],
                'failed_events': daily_summary['failed_count'],
                'successful_events': daily_summary['successful_count'],
                'invalid_events': daily_summary['invalid_count'],
                'unique_ips': daily_summary['unique_ips'],
                'unique_usernames': daily_summary['unique_usernames'],
                'unique_servers': 1,  # Fast estimate
                'anomalies': daily_summary['anomaly_count'],
                'critical_events': critical,
                'high_events': high,
                'medium_events': medium,
                'low_events': low_events,
                'avg_risk_score': daily_summary['avg_risk_score']
            }
        else:
            # Fallback to querying auth_events directly
            # Use indexed columns and optimize with STRAIGHT_JOIN hint
            cursor.execute("""
                SELECT
                    COUNT(*) as total_events,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                    SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful_events,
                    SUM(CASE WHEN event_type = 'invalid' THEN 1 ELSE 0 END) as invalid_events,
                    COUNT(DISTINCT source_ip_text) as unique_ips,
                    COUNT(DISTINCT target_username) as unique_usernames,
                    COUNT(DISTINCT target_server) as unique_servers,
                    SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                    SUM(CASE WHEN ml_risk_score >= 80 THEN 1 ELSE 0 END) as critical_events,
                    SUM(CASE WHEN ml_risk_score >= 60 AND ml_risk_score < 80 THEN 1 ELSE 0 END) as high_events,
                    SUM(CASE WHEN ml_risk_score >= 40 AND ml_risk_score < 60 THEN 1 ELSE 0 END) as medium_events,
                    SUM(CASE WHEN ml_risk_score < 40 THEN 1 ELSE 0 END) as low_events,
                    AVG(ml_risk_score) as avg_risk_score
                FROM auth_events USE INDEX (idx_timestamp_event_type)
                WHERE timestamp >= %s AND timestamp <= %s
                AND source_type != 'simulation'
            """, (start_time, end_time))
            event_stats = cursor.fetchone()

        # Check if we have daily_statistics for additional info
        cursor.execute("""
            SELECT * FROM daily_statistics WHERE stat_date = %s
        """, (report_date,))
        daily_stats = cursor.fetchone()

        # Get blocked IPs count using indexed columns
        cursor.execute("""
            SELECT COUNT(*) as blocked_count
            FROM ip_blocks USE INDEX (idx_is_simulation)
            WHERE is_simulation = FALSE
            AND blocked_at >= %s AND blocked_at <= %s
        """, (start_time, end_time))
        blocked_stats = cursor.fetchone()

        summary = {
            'date': report_date.isoformat(),
            'total_events': event_stats['total_events'] or 0,
            'failed_logins': event_stats['failed_events'] or 0,
            'successful_logins': event_stats['successful_events'] or 0,
            'invalid_events': event_stats['invalid_events'] or 0,
            'unique_ips': event_stats['unique_ips'] or 0,
            'unique_usernames': event_stats['unique_usernames'] or 0,
            'unique_servers': event_stats['unique_servers'] or 0,
            'anomalies': event_stats['anomalies'] or 0,
            'blocked_ips': blocked_stats['blocked_count'] or 0,
            'risk_breakdown': {
                'critical': event_stats['critical_events'] or 0,
                'high': event_stats['high_events'] or 0,
                'medium': event_stats['medium_events'] or 0,
                'low': event_stats['low_events'] or 0
            },
            'avg_risk_score': round(float(event_stats['avg_risk_score'] or 0), 2)
        }

        # Add pre-computed stats if available
        if daily_stats:
            summary['from_daily_stats'] = {
                'active_agents': daily_stats.get('active_agents', 0),
                'notifications_sent': daily_stats.get('notifications_sent', 0)
            }

        # Cache the result
        cache.set(cache_k, summary, DAILY_SUMMARY_TTL)

        return jsonify({
            'success': True,
            'summary': summary,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_daily_summary: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@daily_reports_routes.route('/hourly-breakdown', methods=['GET'])
def get_hourly_breakdown():
    """
    Get hourly breakdown of events for a specific date with caching

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'hourly', str(report_date))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'date': cached['date'],
                'hourly_data': cached['hourly_data'],
                'from_cache': True
            })

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Use composite index for efficient hourly aggregation
        cursor.execute("""
            SELECT
                HOUR(timestamp) as hour,
                COUNT(*) as total_count,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as success_count,
                AVG(ml_risk_score) as avg_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events USE INDEX (idx_timestamp_event_type)
            WHERE timestamp >= %s AND timestamp <= %s
            AND source_type != 'simulation'
            GROUP BY HOUR(timestamp)
            ORDER BY hour
        """, (start_time, end_time))
        hourly_raw = {row['hour']: row for row in cursor.fetchall()}

        # Build 24-hour breakdown
        hourly_data = []
        for hour in range(24):
            data = hourly_raw.get(hour, {})
            hourly_data.append({
                'hour': hour,
                'hour_label': f"{hour:02d}:00",
                'failed': int(data.get('failed_count', 0) or 0),
                'successful': int(data.get('success_count', 0) or 0),
                'total': int(data.get('total_count', 0) or 0),
                'avg_risk': round(float(data.get('avg_risk', 0) or 0), 2),
                'anomalies': int(data.get('anomalies', 0) or 0)
            })

        # Cache the result
        cache_data = {'date': report_date.isoformat(), 'hourly_data': hourly_data}
        cache.set(cache_k, cache_data, HOURLY_BREAKDOWN_TTL)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'hourly_data': hourly_data,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_hourly_breakdown: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@daily_reports_routes.route('/top-threats', methods=['GET'])
def get_top_threats():
    """
    Get top threat IPs for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
        limit: Number of results (default: 10)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        limit = int(request.args.get('limit', 10))

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'top_threats', f"{report_date}_{limit}")

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'date': report_date.isoformat(),
                'top_threats': cached,
                'from_cache': True
            })

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Optimize: Use subquery to reduce COUNT(DISTINCT) operations
        # First get top IPs by attempt count, then join for geo data
        cursor.execute("""
            SELECT
                ip_data.ip,
                geo.country_name as country,
                geo.city,
                ip_data.attempt_count,
                ip_data.unique_usernames,
                ip_data.avg_risk,
                ip_data.max_risk,
                ip_data.first_seen,
                ip_data.last_seen,
                ip_data.threat_type
            FROM (
                SELECT
                    source_ip_text as ip,
                    COUNT(*) as attempt_count,
                    COUNT(DISTINCT target_username) as unique_usernames,
                    AVG(ml_risk_score) as avg_risk,
                    MAX(ml_risk_score) as max_risk,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    MAX(ml_threat_type) as threat_type
                FROM auth_events USE INDEX (idx_timestamp_event_type)
                WHERE timestamp >= %s AND timestamp <= %s
                AND source_type != 'simulation'
                AND event_type = 'failed'
                GROUP BY source_ip_text
                ORDER BY attempt_count DESC
                LIMIT %s
            ) ip_data
            LEFT JOIN ip_geolocation geo ON ip_data.ip = geo.ip_address_text
        """, (start_time, end_time, limit))

        top_ips = cursor.fetchall()

        # Format datetime fields
        for ip_data in top_ips:
            if ip_data.get('first_seen'):
                ip_data['first_seen'] = ip_data['first_seen'].isoformat()
            if ip_data.get('last_seen'):
                ip_data['last_seen'] = ip_data['last_seen'].isoformat()
            ip_data['avg_risk'] = round(float(ip_data['avg_risk'] or 0), 2)
            ip_data['max_risk'] = int(ip_data['max_risk'] or 0)

        # Cache the result
        cache.set(cache_k, top_ips, TOP_THREATS_TTL)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'top_threats': top_ips,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_top_threats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@daily_reports_routes.route('/geographic', methods=['GET'])
def get_geographic_breakdown():
    """
    Get geographic breakdown of attacks for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
        limit: Number of countries (default: 15)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        limit = int(request.args.get('limit', 15))

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'geographic', f"{report_date}_{limit}")

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'date': report_date.isoformat(),
                'countries': cached,
                'from_cache': True
            })

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Use index hint for performance
        cursor.execute("""
            SELECT
                COALESCE(geo.country_name, 'Unknown') as country,
                geo.country_code,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT ae.source_ip_text) as unique_ips,
                AVG(ae.ml_risk_score) as avg_risk,
                SUM(CASE WHEN ae.is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events ae USE INDEX (idx_timestamp_event_type)
            LEFT JOIN ip_geolocation geo ON ae.source_ip_text = geo.ip_address_text
            WHERE ae.timestamp >= %s AND ae.timestamp <= %s
            AND ae.source_type != 'simulation'
            AND ae.event_type = 'failed'
            GROUP BY geo.country_name, geo.country_code
            ORDER BY attempt_count DESC
            LIMIT %s
        """, (start_time, end_time, limit))

        countries = cursor.fetchall()

        for country_data in countries:
            country_data['avg_risk'] = round(float(country_data['avg_risk'] or 0), 2)

        # Cache the result
        cache.set(cache_k, countries, GEOGRAPHIC_TTL)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'countries': countries,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_geographic_breakdown: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@daily_reports_routes.route('/usernames', methods=['GET'])
def get_targeted_usernames():
    """
    Get most targeted usernames for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
        limit: Number of results (default: 10)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')
        limit = int(request.args.get('limit', 10))

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'usernames', f"{report_date}_{limit}")

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'date': report_date.isoformat(),
                'usernames': cached,
                'from_cache': True
            })

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Use composite index for username analysis
        cursor.execute("""
            SELECT
                target_username as username,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                AVG(ml_risk_score) as avg_risk
            FROM auth_events USE INDEX (idx_username_event_type)
            WHERE timestamp >= %s AND timestamp <= %s
            AND target_username IS NOT NULL
            AND source_type != 'simulation'
            AND event_type = 'failed'
            GROUP BY target_username
            ORDER BY attempt_count DESC
            LIMIT %s
        """, (start_time, end_time, limit))

        usernames = cursor.fetchall()

        for username_data in usernames:
            username_data['avg_risk'] = round(float(username_data['avg_risk'] or 0), 2)

        # Cache the result
        cache.set(cache_k, usernames, USERNAMES_TTL)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'usernames': usernames,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_targeted_usernames: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@daily_reports_routes.route('/threat-types', methods=['GET'])
def get_threat_types_breakdown():
    """
    Get threat types breakdown for a specific date

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'threat_types', str(report_date))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'date': report_date.isoformat(),
                'threat_types': cached,
                'from_cache': True
            })

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Use index hint for performance
        cursor.execute("""
            SELECT
                COALESCE(ml_threat_type, 'Unknown') as threat_type,
                COUNT(*) as count,
                AVG(ml_risk_score) as avg_risk,
                COUNT(DISTINCT source_ip_text) as unique_ips
            FROM auth_events USE INDEX (idx_timestamp_event_type)
            WHERE timestamp >= %s AND timestamp <= %s
            AND source_type != 'simulation'
            AND event_type = 'failed'
            GROUP BY ml_threat_type
            ORDER BY count DESC
        """, (start_time, end_time))

        threat_types = cursor.fetchall()

        for threat_data in threat_types:
            threat_data['avg_risk'] = round(float(threat_data['avg_risk'] or 0), 2)

        # Cache the result
        cache.set(cache_k, threat_types, THREAT_TYPES_TTL)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'threat_types': threat_types,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_threat_types_breakdown: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@daily_reports_routes.route('/comparison', methods=['GET'])
def get_daily_comparison():
    """
    Get comparison with previous day

    Query Parameters:
        date: Date in YYYY-MM-DD format (default: today)
    """
    conn = None
    cursor = None
    try:
        date_str = request.args.get('date')

        if date_str:
            report_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            report_date = datetime.now().date()

        prev_date = report_date - timedelta(days=1)

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'comparison', str(report_date))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'comparison': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Current day stats - use index hint
        current_start = datetime.combine(report_date, datetime.min.time())
        current_end = datetime.combine(report_date, datetime.max.time())

        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                COUNT(DISTINCT source_ip_text) as unique_ips
            FROM auth_events USE INDEX (idx_timestamp_event_type)
            WHERE timestamp >= %s AND timestamp <= %s
            AND source_type != 'simulation'
            AND event_type = 'failed'
        """, (current_start, current_end))
        current_stats = cursor.fetchone()

        # Previous day stats - use index hint
        prev_start = datetime.combine(prev_date, datetime.min.time())
        prev_end = datetime.combine(prev_date, datetime.max.time())

        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                COUNT(DISTINCT source_ip_text) as unique_ips
            FROM auth_events USE INDEX (idx_timestamp_event_type)
            WHERE timestamp >= %s AND timestamp <= %s
            AND source_type != 'simulation'
            AND event_type = 'failed'
        """, (prev_start, prev_end))
        prev_stats = cursor.fetchone()

        # Calculate changes
        def calc_change(current, previous):
            if previous == 0:
                return 100 if current > 0 else 0
            return round(((current - previous) / previous) * 100, 1)

        comparison = {
            'current_date': report_date.isoformat(),
            'previous_date': prev_date.isoformat(),
            'current': {
                'total_events': current_stats['total_events'] or 0,
                'high_risk': current_stats['high_risk'] or 0,
                'unique_ips': current_stats['unique_ips'] or 0
            },
            'previous': {
                'total_events': prev_stats['total_events'] or 0,
                'high_risk': prev_stats['high_risk'] or 0,
                'unique_ips': prev_stats['unique_ips'] or 0
            },
            'changes': {
                'total_events': calc_change(
                    current_stats['total_events'] or 0,
                    prev_stats['total_events'] or 0
                ),
                'high_risk': calc_change(
                    current_stats['high_risk'] or 0,
                    prev_stats['high_risk'] or 0
                ),
                'unique_ips': calc_change(
                    current_stats['unique_ips'] or 0,
                    prev_stats['unique_ips'] or 0
                )
            }
        }

        # Cache the result
        cache.set(cache_k, comparison, COMPARISON_TTL)

        return jsonify({
            'success': True,
            'comparison': comparison,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_daily_comparison: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@daily_reports_routes.route('/available-dates', methods=['GET'])
def get_available_dates():
    """
    Get list of dates that have data available

    Query Parameters:
        limit: Number of dates to return (default: 30)
    """
    conn = None
    cursor = None
    try:
        limit = int(request.args.get('limit', 30))

        # Try cache first
        cache = get_cache()
        cache_k = cache_key('daily_reports', 'available_dates', str(limit))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({
                'success': True,
                'dates': cached,
                'from_cache': True
            })

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Try to use pre-aggregated summary table first (much faster)
        cursor.execute("""
            SELECT summary_date as date, total_events as event_count
            FROM auth_events_daily_summary
            ORDER BY summary_date DESC
            LIMIT %s
        """, (limit,))
        dates = cursor.fetchall()

        # Fallback to auth_events if summary table is empty or has fewer dates
        if not dates or len(dates) < limit:
            cursor.execute("""
                SELECT DISTINCT DATE(timestamp) as date, COUNT(*) as event_count
                FROM auth_events USE INDEX (idx_timestamp)
                WHERE source_type != 'simulation'
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
                LIMIT %s
            """, (limit,))
            dates = cursor.fetchall()

        for date_data in dates:
            date_data['date'] = date_data['date'].isoformat()

        # Cache the result
        cache.set(cache_k, dates, AVAILABLE_DATES_TTL)

        return jsonify({
            'success': True,
            'dates': dates,
            'from_cache': False
        })

    except Exception as e:
        print(f"Error in get_available_dates: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
