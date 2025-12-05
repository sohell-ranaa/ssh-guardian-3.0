"""
SSH Guardian v3.0 - Trends Reports Routes
Provides API endpoints for trend analysis and historical data
"""

from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

# Create Blueprint
trends_reports_routes = Blueprint('trends_reports_routes', __name__)


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

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get daily totals
        cursor.execute("""
            SELECT
                DATE(timestamp) as date,
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful_events,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                COUNT(DISTINCT target_username) as unique_usernames,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies,
                AVG(ml_risk_score) as avg_risk_score,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk_events
            FROM auth_events
            WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
            AND source_type != 'simulation'
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """, (start_date, end_date))

        daily_data = cursor.fetchall()

        # Format dates and numbers
        for row in daily_data:
            row['date'] = row['date'].isoformat()
            row['avg_risk_score'] = round(float(row['avg_risk_score'] or 0), 2)

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

        return jsonify({
            'success': True,
            'period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'days': days
            },
            'daily_data': daily_data,
            'totals': totals
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

        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if granularity == 'hourly' and days <= 7:
            cursor.execute("""
                SELECT
                    DATE_FORMAT(timestamp, '%%Y-%%m-%%d %%H:00') as time_bucket,
                    COUNT(*) as total,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful
                FROM auth_events
                WHERE timestamp >= %s AND timestamp <= %s
                AND source_type != 'simulation'
                GROUP BY time_bucket
                ORDER BY time_bucket ASC
            """, (start_date, end_date))
        else:
            cursor.execute("""
                SELECT
                    DATE(timestamp) as time_bucket,
                    COUNT(*) as total,
                    SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as successful
                FROM auth_events
                WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
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

        return jsonify({
            'success': True,
            'granularity': granularity,
            'timeline': timeline_data
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

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                ae.source_ip_text as ip,
                geo.country_name as country,
                geo.country_code,
                COUNT(*) as total_attempts,
                COUNT(DISTINCT DATE(ae.timestamp)) as active_days,
                COUNT(DISTINCT ae.target_username) as unique_usernames,
                AVG(ae.ml_risk_score) as avg_risk,
                MAX(ae.ml_risk_score) as max_risk,
                MIN(DATE(ae.timestamp)) as first_seen,
                MAX(DATE(ae.timestamp)) as last_seen
            FROM auth_events ae
            LEFT JOIN ip_geolocation geo ON ae.source_ip_text = geo.ip_address_text
            WHERE DATE(ae.timestamp) >= %s AND DATE(ae.timestamp) <= %s
            AND ae.source_type != 'simulation'
            AND ae.event_type = 'failed'
            GROUP BY ae.source_ip_text, geo.country_name, geo.country_code
            ORDER BY total_attempts DESC
            LIMIT %s
        """, (start_date, end_date, limit))

        attackers = cursor.fetchall()

        for row in attackers:
            row['avg_risk'] = round(float(row['avg_risk'] or 0), 2)
            row['max_risk'] = int(row['max_risk'] or 0)
            if row['first_seen']:
                row['first_seen'] = row['first_seen'].isoformat()
            if row['last_seen']:
                row['last_seen'] = row['last_seen'].isoformat()

        return jsonify({
            'success': True,
            'period_days': days,
            'attackers': attackers
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

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                COALESCE(geo.country_name, 'Unknown') as country,
                geo.country_code,
                COUNT(*) as total_attempts,
                COUNT(DISTINCT ae.source_ip_text) as unique_ips,
                COUNT(DISTINCT DATE(ae.timestamp)) as active_days,
                AVG(ae.ml_risk_score) as avg_risk,
                SUM(CASE WHEN ae.is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events ae
            LEFT JOIN ip_geolocation geo ON ae.source_ip_text = geo.ip_address_text
            WHERE DATE(ae.timestamp) >= %s AND DATE(ae.timestamp) <= %s
            AND ae.source_type != 'simulation'
            AND ae.event_type = 'failed'
            GROUP BY geo.country_name, geo.country_code
            ORDER BY total_attempts DESC
            LIMIT %s
        """, (start_date, end_date, limit))

        countries = cursor.fetchall()

        for row in countries:
            row['avg_risk'] = round(float(row['avg_risk'] or 0), 2)

        return jsonify({
            'success': True,
            'period_days': days,
            'countries': countries
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

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                target_username as username,
                COUNT(*) as total_attempts,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                COUNT(DISTINCT DATE(timestamp)) as active_days,
                AVG(ml_risk_score) as avg_risk,
                MIN(DATE(timestamp)) as first_seen,
                MAX(DATE(timestamp)) as last_seen
            FROM auth_events
            WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
            AND source_type != 'simulation'
            AND event_type = 'failed'
            AND target_username IS NOT NULL
            GROUP BY target_username
            ORDER BY total_attempts DESC
            LIMIT %s
        """, (start_date, end_date, limit))

        usernames = cursor.fetchall()

        for row in usernames:
            row['avg_risk'] = round(float(row['avg_risk'] or 0), 2)
            if row['first_seen']:
                row['first_seen'] = row['first_seen'].isoformat()
            if row['last_seen']:
                row['last_seen'] = row['last_seen'].isoformat()

        return jsonify({
            'success': True,
            'period_days': days,
            'usernames': usernames
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

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                DATE(timestamp) as date,
                SUM(CASE WHEN ml_risk_score >= 80 THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN ml_risk_score >= 60 AND ml_risk_score < 80 THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN ml_risk_score >= 40 AND ml_risk_score < 60 THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN ml_risk_score < 40 THEN 1 ELSE 0 END) as low
            FROM auth_events
            WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
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

        return jsonify({
            'success': True,
            'period_days': days,
            'daily_distribution': risk_data,
            'totals': totals
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

        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Daily blocking stats
        cursor.execute("""
            SELECT
                DATE(blocked_at) as date,
                COUNT(*) as blocks,
                COUNT(DISTINCT ip_address_text) as unique_ips,
                SUM(CASE WHEN block_source = 'manual' THEN 1 ELSE 0 END) as manual_blocks,
                SUM(CASE WHEN block_source = 'rule_based' THEN 1 ELSE 0 END) as rule_blocks,
                SUM(CASE WHEN block_source = 'api_reputation' THEN 1 ELSE 0 END) as api_blocks
            FROM ip_blocks
            WHERE DATE(blocked_at) >= %s AND DATE(blocked_at) <= %s
            AND is_simulation = FALSE
            GROUP BY DATE(blocked_at)
            ORDER BY date ASC
        """, (start_date, end_date))

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

        return jsonify({
            'success': True,
            'period_days': days,
            'daily_blocks': blocking_data,
            'active_blocks': active_result['active_blocks'] if active_result else 0,
            'total_blocks': sum(d['blocks'] for d in blocking_data)
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

        end_date = datetime.now().date()
        current_start = end_date - timedelta(days=days-1)
        prev_end = current_start - timedelta(days=1)
        prev_start = prev_end - timedelta(days=days-1)

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Current period stats
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events
            WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
            AND source_type != 'simulation'
        """, (current_start, end_date))
        current_stats = cursor.fetchone()

        # Previous period stats
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_events,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events
            WHERE DATE(timestamp) >= %s AND DATE(timestamp) <= %s
            AND source_type != 'simulation'
        """, (prev_start, prev_end))
        prev_stats = cursor.fetchone()

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

        return jsonify({
            'success': True,
            'period_days': days,
            'comparison': comparison
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
