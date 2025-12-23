"""
SSH Guardian v3.1 - Events Analysis Routes
API endpoints for auth events analysis with enrichment data
Updated for v3.1 schema:
- ML data in auth_events_ml table
- Threat data merged into ip_geolocation table
- auth_events_daily for aggregated data
"""
import sys
import json
from pathlib import Path
from flask import Blueprint, jsonify, request

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash

events_analysis_routes = Blueprint('events_analysis', __name__, url_prefix='/api/dashboard/events-analysis')

# Cache TTLs
EVENTS_LIST_TTL = 30
EVENTS_SUMMARY_TTL = 60
EVENTS_TIMELINE_TTL = 60
EVENTS_DETAIL_TTL = 120

# Allowed sort fields
ALLOWED_SORT_FIELDS = {
    'timestamp': 'e.timestamp',
    'source_ip_text': 'e.source_ip_text',
    'event_type': 'e.event_type',
    'target_username': 'e.target_username'
}


def _get_approximate_count(cursor):
    """Get approximate row count from table statistics"""
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
    """Get paginated list of auth events - v3.1 schema"""
    conn = None
    cursor = None
    try:
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

        # Build WHERE clause - v3.1: ML data from auth_events_ml
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
            # v3.1: risk_score is in auth_events_ml
            if risk_level == 'high':
                where_conditions.append("ml.risk_score >= 0.70")
            elif risk_level == 'medium':
                where_conditions.append("ml.risk_score >= 0.40 AND ml.risk_score < 0.70")
            elif risk_level == 'low':
                where_conditions.append("(ml.risk_score < 0.40 OR ml.risk_score IS NULL)")
            has_filters = True

        if anomaly:
            # v3.1: is_anomaly is in auth_events_ml
            if anomaly.lower() == 'true':
                where_conditions.append("ml.is_anomaly = 1")
            elif anomaly.lower() == 'false':
                where_conditions.append("(ml.is_anomaly = 0 OR ml.is_anomaly IS NULL)")
            has_filters = True

        where_clause = ""
        if where_conditions:
            where_clause = "WHERE " + " AND ".join(where_conditions)

        if not has_filters:
            total_count = _get_approximate_count(cursor)
        else:
            count_query = f"""
                SELECT COUNT(*) as total
                FROM auth_events e
                LEFT JOIN auth_events_ml ml ON e.id = ml.event_id
                {where_clause}
            """
            cursor.execute(count_query, params)
            total_count = cursor.fetchone()['total']

        # v3.1: Join with auth_events_ml for ML data
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
                ml.risk_score as ml_risk_score,
                ml.is_anomaly,
                g.country_name,
                g.country_code,
                g.city,
                g.threat_level
            FROM auth_events e
            LEFT JOIN auth_events_ml ml ON e.id = ml.event_id
            LEFT JOIN ip_geolocation g ON e.geo_id = g.id
            {where_clause}
            ORDER BY {sort_column} {order}
            LIMIT %s OFFSET %s
        """

        cursor.execute(query, params + [limit, offset])
        events = cursor.fetchall()

        for event in events:
            if event.get('timestamp'):
                event['timestamp'] = event['timestamp'].isoformat()
            if event.get('ml_risk_score'):
                event['ml_risk_score'] = round(float(event['ml_risk_score']) * 100, 1)

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
    """Get overall events summary statistics - v3.1 schema"""
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

        # Basic counts from auth_events
        cursor.execute("""
            SELECT
                COUNT(*) as total_events,
                SUM(event_type = 'failed') as failed_count,
                SUM(event_type = 'successful') as successful_count,
                SUM(event_type = 'invalid') as invalid_count
            FROM auth_events
        """)
        stats = cursor.fetchone()

        # v3.1: ML stats from auth_events_ml
        cursor.execute("""
            SELECT
                SUM(is_anomaly = 1) as anomaly_count,
                SUM(was_blocked = 1) as blocked_count,
                AVG(risk_score) as avg_risk_score,
                SUM(risk_score >= 0.70) as high_risk_count,
                SUM(risk_score >= 0.40 AND risk_score < 0.70) as medium_risk_count,
                SUM(risk_score < 0.40 OR risk_score IS NULL) as low_risk_count
            FROM auth_events_ml
        """)
        ml_stats = cursor.fetchone()

        # Unique IPs count
        cursor.execute("SELECT COUNT(DISTINCT source_ip_text) as cnt FROM auth_events")
        unique_ips = cursor.fetchone()['cnt'] or 0

        # Unique usernames (optimized with limit)
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
        unique_usernames = cursor.fetchone()['cnt'] or 0

        summary = {
            'total_events': int(stats['total_events'] or 0),
            'failed_count': int(stats['failed_count'] or 0),
            'successful_count': int(stats['successful_count'] or 0),
            'invalid_count': int(stats['invalid_count'] or 0),
            'anomaly_count': int(ml_stats['anomaly_count'] or 0) if ml_stats else 0,
            'blocked_count': int(ml_stats['blocked_count'] or 0) if ml_stats else 0,
            'avg_risk_score': float(ml_stats['avg_risk_score'] or 0) if ml_stats else 0,
            'unique_ips': unique_ips,
            'unique_usernames': unique_usernames
        }

        risk_distribution = {
            'high': int(ml_stats['high_risk_count'] or 0) if ml_stats else 0,
            'medium': int(ml_stats['medium_risk_count'] or 0) if ml_stats else 0,
            'low': int(ml_stats['low_risk_count'] or 0) if ml_stats else 0
        }

        events_by_type = {
            'failed': summary['failed_count'],
            'successful': summary['successful_count'],
            'invalid': summary['invalid_count']
        }

        # Top failure reasons
        cursor.execute("""
            SELECT failure_reason, COUNT(*) as count
            FROM auth_events
            WHERE failure_reason IS NOT NULL AND failure_reason != ''
            GROUP BY failure_reason
            ORDER BY count DESC
            LIMIT 10
        """)
        top_failure_reasons = cursor.fetchall()

        # Top targeted usernames
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

        for user in top_usernames:
            if user.get('failed_count') is not None:
                user['failed_count'] = int(user['failed_count'])

        # Auth methods
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
    """Get time-series data for events - v3.1 schema"""
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

        # v3.1: Use auth_events_daily for daily queries
        if interval == 'day':
            query = """
                SELECT
                    summary_date as time_period,
                    total_events,
                    failed_events as failed,
                    successful_events as successful,
                    invalid_user_events as invalid,
                    0 as anomalies,
                    0.0 as avg_risk_score
                FROM auth_events_daily
                WHERE summary_date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
                ORDER BY summary_date ASC
            """
            cursor.execute(query, (days,))
        else:
            # Real-time aggregation for hourly/weekly with ML join
            if interval == 'hour':
                group_by = "DATE_FORMAT(e.timestamp, '%Y-%m-%d %H:00:00')"
            else:
                group_by = "YEARWEEK(e.timestamp, 1)"

            query = f"""
                SELECT
                    {group_by} as time_period,
                    COUNT(*) as total_events,
                    SUM(e.event_type = 'failed') as failed,
                    SUM(e.event_type = 'successful') as successful,
                    SUM(e.event_type = 'invalid') as invalid,
                    SUM(ml.is_anomaly = 1) as anomalies,
                    AVG(COALESCE(ml.risk_score, 0)) as avg_risk_score
                FROM auth_events e
                LEFT JOIN auth_events_ml ml ON e.id = ml.event_id
                WHERE e.timestamp >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
                GROUP BY time_period
                ORDER BY time_period ASC
            """
            cursor.execute(query, (days,))

        timeline = cursor.fetchall()

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
    """Get detailed information for a specific event - v3.1 schema"""
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

        # v3.1: ML from auth_events_ml, threat from ip_geolocation
        cursor.execute("""
            SELECT
                e.id,
                e.event_uuid,
                e.timestamp,
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
                e.raw_log_line,
                e.created_at,
                COALESCE(e.ml_risk_score, ml.risk_score) as ml_risk_score,
                COALESCE(e.ml_threat_type, ml.threat_type) as ml_threat_type,
                COALESCE(e.ml_confidence, ml.confidence) as ml_confidence,
                COALESCE(e.is_anomaly, ml.is_anomaly) as is_anomaly,
                ml.was_blocked,
                g.country_name,
                g.country_code,
                g.city,
                g.region,
                g.latitude,
                g.longitude,
                g.timezone,
                g.threat_level,
                g.abuseipdb_score,
                g.virustotal_positives
            FROM auth_events e
            LEFT JOIN auth_events_ml ml ON e.id = ml.event_id
            LEFT JOIN ip_geolocation g ON e.geo_id = g.id
            WHERE e.id = %s
        """, (event_id,))

        event = cursor.fetchone()

        if not event:
            return jsonify({'success': False, 'error': 'Event not found'}), 404

        for field in ['timestamp', 'created_at']:
            if event.get(field):
                event[field] = event[field].isoformat()

        for field in ['latitude', 'longitude']:
            if event.get(field) is not None:
                event[field] = float(event[field])

        # ML fields: confidence is always 0-1, risk_score varies by source
        # auth_events stores risk_score as 0-100, auth_events_ml stores as 0-1
        if event.get('ml_confidence') is not None:
            val = float(event['ml_confidence'])
            event['ml_confidence'] = round(val * 100, 1) if val <= 1 else round(val, 1)
        if event.get('ml_risk_score') is not None:
            val = float(event['ml_risk_score'])
            # Only multiply if value is 0-1 scale (from auth_events_ml)
            event['ml_risk_score'] = round(val * 100, 1) if val <= 1 else round(val, 1)

        # Get related events
        cursor.execute("""
            SELECT e.id, e.event_type, e.target_username, ml.risk_score as ml_risk_score, e.timestamp
            FROM auth_events e
            LEFT JOIN auth_events_ml ml ON e.id = ml.event_id
            WHERE e.source_ip_text = %s AND e.id != %s
            ORDER BY e.timestamp DESC
            LIMIT 10
        """, (event['source_ip_text'], event_id))

        related_events = cursor.fetchall()

        for rel_event in related_events:
            if rel_event.get('timestamp'):
                rel_event['timestamp'] = rel_event['timestamp'].isoformat()
            if rel_event.get('ml_risk_score'):
                rel_event['ml_risk_score'] = round(float(rel_event['ml_risk_score']) * 100, 1)

        # Get block info if IP was blocked
        block_info = None
        cursor.execute("""
            SELECT
                id, block_source, block_reason, risk_score, threat_level,
                trigger_event_id, blocked_at, is_active
            FROM ip_blocks
            WHERE ip_address_text = %s
            ORDER BY blocked_at DESC
            LIMIT 1
        """, (event['source_ip_text'],))
        block_record = cursor.fetchone()

        if block_record:
            block_info = {
                'is_blocked': True,
                'block_source': block_record['block_source'],
                'block_reason': block_record['block_reason'],
                'risk_score': block_record['risk_score'],
                'threat_level': block_record['threat_level'],
                'triggered_by_event': block_record['trigger_event_id'] == event_id,
                'blocked_at': block_record['blocked_at'].isoformat() if block_record['blocked_at'] else None,
                'is_active': bool(block_record['is_active'])
            }

        # Build ML decision explanation
        ml_decision = None
        if event.get('ml_risk_score') is not None:
            risk = event['ml_risk_score']
            conf = event.get('ml_confidence', 0)
            threat_type = event.get('ml_threat_type', '')
            is_anomaly = event.get('is_anomaly', 0)
            event_type = event.get('event_type', '')
            abuseipdb_score = event.get('abuseipdb_score') or 0

            # Count failed attempts from related events
            failed_count = sum(1 for e in related_events if e.get('event_type') == 'failed')
            if event_type == 'failed':
                failed_count += 1

            # Detect actual malicious behavior patterns
            has_brute_force = failed_count >= 5
            has_bad_reputation = abuseipdb_score >= 50
            is_successful_login = event_type == 'successful'
            has_good_reputation = abuseipdb_score <= 10

            # Decision logic: Block on BEHAVIOR, not just risk score
            if has_good_reputation and is_successful_login and not has_brute_force:
                # Good reputation + successful login + no attack pattern = Allow
                decision = 'allow'
                decision_text = 'Allow - Good reputation, legitimate login'
                reason = f'Successful login from IP with good reputation (AbuseIPDB: {abuseipdb_score})'
            elif has_brute_force and risk >= 60:
                # Actual brute force attack pattern
                if risk >= 80:
                    decision = 'block_permanent'
                    decision_text = 'Block permanently via UFW'
                    reason = f'Brute force detected ({failed_count} failed attempts) with critical risk ({risk})'
                else:
                    decision = 'block_temporary'
                    decision_text = 'Block temporarily via Fail2ban (48h)'
                    reason = f'Brute force detected ({failed_count} failed attempts) with high risk ({risk})'
            elif has_bad_reputation and failed_count >= 2:
                # Known bad IP with failed attempts
                decision = 'block_temporary'
                decision_text = 'Block temporarily via Fail2ban (48h)'
                reason = f'Bad reputation (AbuseIPDB: {abuseipdb_score}) with {failed_count} failed attempts'
            elif is_successful_login and not has_bad_reputation:
                # Successful login without bad reputation = Allow or Monitor
                if risk >= 60:
                    decision = 'monitor'
                    decision_text = 'Monitor - First time IP with successful login'
                    reason = f'New IP with successful login, monitoring recommended'
                else:
                    decision = 'allow'
                    decision_text = 'Allow - Successful authentication'
                    reason = f'Successful login with acceptable risk ({risk})'
            elif risk >= 80:
                decision = 'block_permanent'
                decision_text = 'Block permanently via UFW'
                reason = f'Critical risk score ({risk}) with suspicious behavior'
            elif risk >= 60:
                decision = 'block_temporary'
                decision_text = 'Block temporarily via Fail2ban (48h)'
                reason = f'High risk score ({risk}) exceeds temporary block threshold (60)'
            elif risk >= 40:
                decision = 'monitor'
                decision_text = 'Monitor closely'
                reason = f'Medium risk score ({risk}) - requires monitoring'
            else:
                decision = 'allow'
                decision_text = 'Allow - low risk'
                reason = f'Risk score ({risk}) below monitoring threshold'

            ml_decision = {
                'decision': decision,
                'decision_text': decision_text,
                'reason': reason,
                'factors': []
            }

            # Add contributing factors - only show real threats, not generic classifications
            threat_types_to_skip = ['low_threat', 'medium_threat', 'anomaly', 'normal', 'benign']
            if threat_type and threat_type.lower() not in threat_types_to_skip:
                ml_decision['factors'].append({
                    'type': 'threat_type',
                    'label': 'Threat Classification',
                    'value': threat_type.replace('_', ' ').title(),
                    'impact': 'high' if 'critical' in threat_type or 'suspicious' in threat_type else 'medium'
                })
            # Only show anomaly for actual malicious behavior, not just "new IP"
            if is_anomaly and (has_brute_force or has_bad_reputation or failed_count >= 3):
                ml_decision['factors'].append({
                    'type': 'anomaly',
                    'label': 'Behavioral Anomaly',
                    'value': 'Detected',
                    'impact': 'high'
                })
            # Show brute force pattern if detected
            if has_brute_force:
                ml_decision['factors'].append({
                    'type': 'brute_force',
                    'label': 'Brute Force Pattern',
                    'value': f'{failed_count} failed attempts',
                    'impact': 'critical'
                })
            if event.get('abuseipdb_score') and event['abuseipdb_score'] >= 50:
                ml_decision['factors'].append({
                    'type': 'abuseipdb',
                    'label': 'AbuseIPDB Score',
                    'value': f"{event['abuseipdb_score']}%",
                    'impact': 'critical' if event['abuseipdb_score'] >= 80 else 'high'
                })
            if event.get('country_code') in ['CN', 'RU', 'KP', 'IR']:
                ml_decision['factors'].append({
                    'type': 'geo_risk',
                    'label': 'High-Risk Country',
                    'value': event.get('country_name', event['country_code']),
                    'impact': 'medium'
                })

        data = {
            'event': event,
            'related_events': related_events,
            'block_info': block_info,
            'ml_decision': ml_decision
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


@events_analysis_routes.route('/geography', methods=['GET'])
def get_geography_data():
    """Get geographic distribution of events - v3.1 schema"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_params = dict(request.args)
        cache_k = cache_key_hash('events_analysis', 'geography', cache_params)

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1: ML data from auth_events_ml
        cursor.execute("""
            SELECT
                g.country_name as name,
                g.country_code as code,
                COUNT(*) as count,
                SUM(e.event_type = 'failed') as failed_count,
                SUM(ml.risk_score >= 0.70) as high_threat_count
            FROM auth_events e
            JOIN ip_geolocation g ON e.geo_id = g.id
            LEFT JOIN auth_events_ml ml ON e.id = ml.event_id
            WHERE g.country_name IS NOT NULL
            GROUP BY g.country_name, g.country_code
            ORDER BY count DESC
            LIMIT 20
        """)
        countries = cursor.fetchall()

        total = sum(c['count'] for c in countries)
        for country in countries:
            country['count'] = int(country['count'])
            country['failed_count'] = int(country['failed_count'] or 0)
            country['high_threat_count'] = int(country['high_threat_count'] or 0)
            country['percentage'] = (country['count'] / total * 100) if total > 0 else 0
            country['flag'] = get_country_flag(country['code'])

        data = {'countries': countries}
        cache.set(cache_k, data, EVENTS_SUMMARY_TTL)

        return jsonify({'success': True, 'data': data, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/top-ips', methods=['GET'])
def get_top_ips():
    """Get top attacking IP addresses - v3.1 schema"""
    conn = None
    cursor = None
    try:
        limit = min(int(request.args.get('limit', 10)), 50)

        cache = get_cache()
        cache_k = cache_key('events_analysis', 'top_ips', str(limit))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1: threat_level from ip_geolocation, risk_score from auth_events_ml
        cursor.execute("""
            SELECT
                e.source_ip_text as ip_address,
                COUNT(*) as count,
                SUM(e.event_type = 'failed') as failed_count,
                MAX(ml.risk_score) as max_risk_score,
                g.threat_level,
                g.country_name as country,
                g.country_code,
                (SELECT 1 FROM ip_blocks WHERE ip_address_text = e.source_ip_text AND is_active = 1 LIMIT 1) as is_blocked
            FROM auth_events e
            LEFT JOIN ip_geolocation g ON e.geo_id = g.id
            LEFT JOIN auth_events_ml ml ON e.id = ml.event_id
            WHERE e.event_type = 'failed'
            GROUP BY e.source_ip_text, g.threat_level, g.country_name, g.country_code
            ORDER BY count DESC
            LIMIT %s
        """, (limit,))
        ips = cursor.fetchall()

        for ip in ips:
            ip['count'] = int(ip['count'])
            ip['failed_count'] = int(ip['failed_count'] or 0)
            ip['max_risk_score'] = round(float(ip['max_risk_score']) * 100, 1) if ip['max_risk_score'] else 0
            ip['is_blocked'] = bool(ip['is_blocked'])
            ip['country_flag'] = get_country_flag(ip.get('country_code'))

        data = {'ips': ips}
        cache.set(cache_k, data, EVENTS_SUMMARY_TTL)

        return jsonify({'success': True, 'data': data, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/recommendations', methods=['GET'])
def get_ai_recommendations():
    """Get security recommendations - v3.1 schema"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('events_analysis', 'recommendations')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        recommendations = []

        # v3.1: High-risk IPs from auth_events_ml
        cursor.execute("""
            SELECT COUNT(DISTINCT e.source_ip_text) as count
            FROM auth_events e
            JOIN auth_events_ml ml ON e.id = ml.event_id
            WHERE ml.risk_score >= 0.80
            AND e.timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            AND e.source_ip_text NOT IN (SELECT ip_address_text FROM ip_blocks WHERE is_active = 1)
        """)
        high_risk = cursor.fetchone()
        if high_risk and high_risk['count'] > 5:
            recommendations.append({
                'priority': 'critical',
                'title': f"{high_risk['count']} High-Risk IPs Detected",
                'description': f"{high_risk['count']} IPs with risk scores above 80% are actively attacking. Consider blocking them.",
                'action': 'Review & Block IPs'
            })

        # Brute force attempts
        cursor.execute("""
            SELECT COUNT(*) as count, source_ip_text
            FROM auth_events
            WHERE event_type = 'failed'
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
            GROUP BY source_ip_text
            HAVING count > 20
            ORDER BY count DESC
            LIMIT 1
        """)
        brute_force = cursor.fetchone()
        if brute_force and brute_force['count'] > 20:
            recommendations.append({
                'priority': 'high',
                'title': 'Brute Force Attack Detected',
                'description': f"IP {brute_force['source_ip_text']} made {brute_force['count']} failed login attempts in the last hour.",
                'action': 'Block IP'
            })

        # Weak usernames
        cursor.execute("""
            SELECT target_username, COUNT(*) as count
            FROM auth_events
            WHERE event_type = 'failed'
            AND target_username IN ('root', 'admin', 'Administrator', 'user', 'test')
            AND timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
            GROUP BY target_username
            ORDER BY count DESC
            LIMIT 1
        """)
        weak_user = cursor.fetchone()
        if weak_user and weak_user['count'] > 50:
            recommendations.append({
                'priority': 'medium',
                'title': 'Common Username Under Attack',
                'description': f"Username '{weak_user['target_username']}' received {weak_user['count']} failed login attempts.",
                'action': 'Review Account'
            })

        data = {'recommendations': recommendations}
        cache.set(cache_k, data, EVENTS_SUMMARY_TTL)

        return jsonify({'success': True, 'data': data, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/threat-distribution', methods=['GET'])
def get_threat_distribution():
    """Get threat level distribution - v3.1 schema"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('events_analysis', 'threat_distribution')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1: threat_level is in ip_geolocation
        cursor.execute("""
            SELECT
                CASE
                    WHEN g.threat_level IS NULL OR g.threat_level = '' THEN 'clean'
                    ELSE LOWER(g.threat_level)
                END as threat_level,
                COUNT(*) as count
            FROM auth_events e
            LEFT JOIN ip_geolocation g ON e.geo_id = g.id
            GROUP BY threat_level
        """)
        results = cursor.fetchall()

        distribution = {}
        for row in results:
            threat_level = row['threat_level'] or 'clean'
            distribution[threat_level] = int(row['count'])

        data = {'distribution': distribution}
        cache.set(cache_k, data, EVENTS_SUMMARY_TTL)

        return jsonify({'success': True, 'data': data, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/attack-patterns', methods=['GET'])
def get_attack_patterns():
    """Get attack patterns (failure reasons)"""
    conn = None
    cursor = None
    try:
        cache = get_cache()
        cache_k = cache_key('events_analysis', 'attack_patterns')

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                failure_reason as reason,
                COUNT(*) as count
            FROM auth_events
            WHERE event_type = 'failed'
            AND failure_reason IS NOT NULL
            AND failure_reason != ''
            GROUP BY failure_reason
            ORDER BY count DESC
            LIMIT 10
        """)
        patterns = cursor.fetchall()

        for pattern in patterns:
            pattern['count'] = int(pattern['count'])
            pattern['trend'] = 0.0

        data = {'patterns': patterns}
        cache.set(cache_k, data, EVENTS_SUMMARY_TTL)

        return jsonify({'success': True, 'data': data, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@events_analysis_routes.route('/top-usernames', methods=['GET'])
def get_top_usernames():
    """Get targeted usernames with statistics"""
    conn = None
    cursor = None
    try:
        limit = min(int(request.args.get('limit', 10)), 50)

        cache = get_cache()
        cache_k = cache_key('events_analysis', 'top_usernames', str(limit))

        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                target_username as username,
                COUNT(*) as total,
                SUM(event_type = 'failed') as failed,
                SUM(event_type = 'successful') as successful,
                COUNT(DISTINCT source_ip_text) as unique_ips
            FROM auth_events
            WHERE target_username IS NOT NULL
            AND target_username != ''
            GROUP BY target_username
            ORDER BY total DESC
            LIMIT %s
        """, (limit,))
        usernames = cursor.fetchall()

        for user in usernames:
            user['total'] = int(user['total'])
            user['failed'] = int(user['failed'] or 0)
            user['successful'] = int(user['successful'] or 0)
            user['unique_ips'] = int(user['unique_ips'])

        data = {'usernames': usernames}
        cache.set(cache_k, data, EVENTS_SUMMARY_TTL)

        return jsonify({'success': True, 'data': data, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def get_country_flag(country_code):
    """Convert country code to flag emoji"""
    if not country_code or len(country_code) != 2:
        return '🌍'

    code = country_code.upper()
    return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
