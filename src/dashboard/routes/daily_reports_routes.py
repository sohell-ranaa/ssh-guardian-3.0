"""
SSH Guardian v3.0 - Daily Reports Routes
Provides API endpoints for generating daily security reports
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
daily_reports_routes = Blueprint('daily_reports_routes', __name__)


@daily_reports_routes.route('/summary', methods=['GET'])
def get_daily_summary():
    """
    Get daily summary report for a specific date

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

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if we have pre-computed daily statistics
        cursor.execute("""
            SELECT * FROM daily_statistics WHERE stat_date = %s
        """, (report_date,))
        daily_stats = cursor.fetchone()

        # Get detailed stats from auth_events
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
            FROM auth_events
            WHERE timestamp >= %s AND timestamp <= %s
            AND source_type != 'simulation'
        """, (start_time, end_time))
        event_stats = cursor.fetchone()

        # Get blocked IPs count
        cursor.execute("""
            SELECT COUNT(*) as blocked_count
            FROM ip_blocks
            WHERE blocked_at >= %s AND blocked_at <= %s
            AND is_simulation = FALSE
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

        return jsonify({
            'success': True,
            'summary': summary
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
    Get hourly breakdown of events for a specific date

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

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                HOUR(timestamp) as hour,
                COUNT(*) as total_count,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as success_count,
                AVG(ml_risk_score) as avg_risk,
                SUM(CASE WHEN is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events
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
                'failed': data.get('failed_count', 0),
                'successful': data.get('success_count', 0),
                'total': data.get('total_count', 0),
                'avg_risk': round(float(data.get('avg_risk', 0) or 0), 2),
                'anomalies': data.get('anomalies', 0)
            })

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'hourly_data': hourly_data
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

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                ae.source_ip_text as ip,
                geo.country_name as country,
                geo.city,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT ae.target_username) as unique_usernames,
                AVG(ae.ml_risk_score) as avg_risk,
                MAX(ae.ml_risk_score) as max_risk,
                MIN(ae.timestamp) as first_seen,
                MAX(ae.timestamp) as last_seen,
                MAX(ae.ml_threat_type) as threat_type
            FROM auth_events ae
            LEFT JOIN ip_geolocation geo ON ae.source_ip_text = geo.ip_address_text
            WHERE ae.timestamp >= %s AND ae.timestamp <= %s
            AND ae.source_type != 'simulation'
            AND ae.event_type = 'failed'
            GROUP BY ae.source_ip_text, geo.country_name, geo.city
            ORDER BY attempt_count DESC
            LIMIT %s
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

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'top_threats': top_ips
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

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                COALESCE(geo.country_name, 'Unknown') as country,
                geo.country_code,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT ae.source_ip_text) as unique_ips,
                AVG(ae.ml_risk_score) as avg_risk,
                SUM(CASE WHEN ae.is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM auth_events ae
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

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'countries': countries
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

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                target_username as username,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT source_ip_text) as unique_ips,
                AVG(ml_risk_score) as avg_risk
            FROM auth_events
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

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'usernames': usernames
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

        start_time = datetime.combine(report_date, datetime.min.time())
        end_time = datetime.combine(report_date, datetime.max.time())

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                COALESCE(ml_threat_type, 'Unknown') as threat_type,
                COUNT(*) as count,
                AVG(ml_risk_score) as avg_risk,
                COUNT(DISTINCT source_ip_text) as unique_ips
            FROM auth_events
            WHERE timestamp >= %s AND timestamp <= %s
            AND source_type != 'simulation'
            AND event_type = 'failed'
            GROUP BY ml_threat_type
            ORDER BY count DESC
        """, (start_time, end_time))

        threat_types = cursor.fetchall()

        for threat_data in threat_types:
            threat_data['avg_risk'] = round(float(threat_data['avg_risk'] or 0), 2)

        return jsonify({
            'success': True,
            'date': report_date.isoformat(),
            'threat_types': threat_types
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

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Current day stats
        current_start = datetime.combine(report_date, datetime.min.time())
        current_end = datetime.combine(report_date, datetime.max.time())

        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                COUNT(DISTINCT source_ip_text) as unique_ips
            FROM auth_events
            WHERE timestamp >= %s AND timestamp <= %s
            AND source_type != 'simulation'
            AND event_type = 'failed'
        """, (current_start, current_end))
        current_stats = cursor.fetchone()

        # Previous day stats
        prev_start = datetime.combine(prev_date, datetime.min.time())
        prev_end = datetime.combine(prev_date, datetime.max.time())

        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(CASE WHEN ml_risk_score >= 60 THEN 1 ELSE 0 END) as high_risk,
                COUNT(DISTINCT source_ip_text) as unique_ips
            FROM auth_events
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

        return jsonify({
            'success': True,
            'comparison': comparison
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

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT DATE(timestamp) as date, COUNT(*) as event_count
            FROM auth_events
            WHERE source_type != 'simulation'
            GROUP BY DATE(timestamp)
            ORDER BY date DESC
            LIMIT %s
        """, (limit,))

        dates = cursor.fetchall()

        for date_data in dates:
            date_data['date'] = date_data['date'].isoformat()

        return jsonify({
            'success': True,
            'dates': dates
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
