"""
SSH Guardian v3.0 - Simulation API Routes
API endpoints for attack simulation management
"""

import json
from flask import Blueprint, jsonify, request
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from dbs.connection import get_connection
from src.core.auth import login_required, SessionManager
from src.simulation import (
    AttackSimulator,
    ATTACK_TEMPLATES,
    get_template,
    get_template_list,
    get_pool_manager
)

simulation_routes = Blueprint('simulation_routes', __name__)


@simulation_routes.route('/templates', methods=['GET'])
@login_required
def get_templates():
    """Get all available attack templates"""
    try:
        templates = []
        for template_id, template_data in ATTACK_TEMPLATES.items():
            templates.append({
                'id': template_id,
                'name': template_data['name'],
                'description': template_data['description'],
                'category': template_data['category'],
                'severity': template_data['severity'],
                'template': template_data['template']
            })

        return jsonify({
            'success': True,
            'templates': templates,
            'count': len(templates)
        })

    except Exception as e:
        print(f"[Simulation] Error getting templates: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/template/<template_id>', methods=['GET'])
@login_required
def get_template_detail(template_id):
    """Get a specific template with IP auto-filled"""
    try:
        if template_id not in ATTACK_TEMPLATES:
            return jsonify({'error': 'Template not found'}), 404

        template = ATTACK_TEMPLATES[template_id].copy()
        template_json = template['template'].copy()

        # Auto-fill IPs based on template type
        ip_param = template_json.get('source_ip', '')
        if isinstance(ip_param, str) and ip_param.startswith('<from_pool:'):
            pool_manager = get_pool_manager()
            parts = ip_param.strip('<>').split(':')
            pool_type = parts[1]

            count = 1
            if len(parts) >= 4 and parts[2] == 'multiple':
                count = int(parts[3])

            ips = pool_manager.get_ips(pool_type, count)

            if count == 1:
                template_json['source_ip'] = ips[0]
            else:
                template_json['source_ip'] = ips

            template_json['_ip_pool_type'] = pool_type
            template_json['_ip_count'] = count

        return jsonify({
            'success': True,
            'template': template,
            'json': template_json
        })

    except Exception as e:
        print(f"[Simulation] Error getting template {template_id}: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/ip-pool/<pool_type>', methods=['GET'])
@login_required
def get_ip_pool(pool_type):
    """Get IPs from a specific pool"""
    try:
        count = int(request.args.get('count', 10))
        pool_manager = get_pool_manager()

        if pool_type not in ['malicious', 'trusted', 'random']:
            return jsonify({'error': 'Invalid pool type'}), 400

        ips = pool_manager.get_ips(pool_type, count)

        return jsonify({
            'success': True,
            'pool_type': pool_type,
            'ips': ips,
            'count': len(ips)
        })

    except Exception as e:
        print(f"[Simulation] Error getting IP pool: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/ip-pool/info', methods=['GET'])
@login_required
def get_ip_pool_info():
    """Get information about available IP pools"""
    try:
        pool_manager = get_pool_manager()
        info = pool_manager.get_pool_info()

        return jsonify({
            'success': True,
            'pools': info
        })

    except Exception as e:
        print(f"[Simulation] Error getting pool info: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/execute', methods=['POST'])
@login_required
def execute_simulation():
    """Execute an attack simulation"""
    try:
        data = request.get_json()

        template_name = data.get('template_name')
        custom_params = data.get('parameters', {})

        if not template_name:
            return jsonify({'error': 'template_name is required'}), 400

        # Get current user info
        session_token = request.cookies.get('session_token')
        user = SessionManager.get_user_from_session(session_token) if session_token else None

        # Execute simulation
        simulator = AttackSimulator(verbose=True)
        result = simulator.execute(
            template_name=template_name,
            custom_params=custom_params,
            user_id=user.get('id') if user else None,
            user_email=user.get('email') if user else None
        )

        return jsonify({
            'success': True,
            'message': 'Simulation completed',
            'simulation_id': result['simulation_id'],
            'status': result['status'],
            'summary': result['summary']
        })

    except Exception as e:
        print(f"[Simulation] Error executing simulation: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/history', methods=['GET'])
@login_required
def get_history():
    """Get simulation history"""
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        attack_type = request.args.get('attack_type', '').strip()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Build query
        query = """
            SELECT
                id,
                run_uuid,
                user_email,
                template_name,
                template_display_name,
                status,
                total_events_planned,
                events_generated,
                ips_blocked,
                anomalies_detected,
                notifications_sent,
                error_message,
                started_at,
                completed_at,
                duration_seconds
            FROM simulation_runs
        """

        params = []
        if attack_type:
            query += " WHERE template_name = %s"
            params.append(attack_type)

        query += " ORDER BY started_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cursor.execute(query, tuple(params))
        history = cursor.fetchall()

        # Convert datetime to string
        for record in history:
            if record.get('started_at'):
                record['started_at'] = record['started_at'].isoformat()
            if record.get('completed_at'):
                record['completed_at'] = record['completed_at'].isoformat()

        # Get total count
        count_query = "SELECT COUNT(*) as total FROM simulation_runs"
        count_params = []
        if attack_type:
            count_query += " WHERE template_name = %s"
            count_params.append(attack_type)

        cursor.execute(count_query, tuple(count_params))
        total = cursor.fetchone()['total']

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'history': history,
            'total': total,
            'limit': limit,
            'offset': offset,
            'attack_type': attack_type
        })

    except Exception as e:
        print(f"[Simulation] Error getting history: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/attack-types', methods=['GET'])
@login_required
def get_attack_types():
    """Get distinct attack types from simulation history"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT DISTINCT
                template_name,
                template_display_name
            FROM simulation_runs
            WHERE template_name IS NOT NULL
            ORDER BY template_display_name
        """)

        attack_types = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'attack_types': attack_types
        })

    except Exception as e:
        print(f"[Simulation] Error getting attack types: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/history/<int:simulation_id>', methods=['GET'])
@login_required
def get_simulation_detail(simulation_id):
    """Get detailed information about a specific simulation"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT * FROM simulation_runs
            WHERE id = %s
        """, (simulation_id,))

        simulation = cursor.fetchone()

        if not simulation:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Simulation not found'}), 404

        # Convert datetime
        if simulation.get('started_at'):
            simulation['started_at'] = simulation['started_at'].isoformat()
        if simulation.get('completed_at'):
            simulation['completed_at'] = simulation['completed_at'].isoformat()
        if simulation.get('created_at'):
            simulation['created_at'] = simulation['created_at'].isoformat()

        # Parse JSON config
        if simulation.get('config'):
            try:
                simulation['config'] = json.loads(simulation['config'])
            except:
                pass

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'simulation': simulation
        })

    except Exception as e:
        print(f"[Simulation] Error getting simulation detail: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/logs/<int:simulation_id>', methods=['GET'])
@login_required
def get_simulation_logs(simulation_id):
    """Get logs for a specific simulation"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                log_uuid,
                log_timestamp,
                sequence_number,
                stage,
                level,
                message,
                ip_address,
                username,
                event_count,
                metadata
            FROM simulation_logs
            WHERE simulation_run_id = %s
            ORDER BY sequence_number ASC
        """, (simulation_id,))

        logs = cursor.fetchall()

        # Convert datetime and parse JSON
        for log in logs:
            if log.get('log_timestamp'):
                log['log_timestamp'] = log['log_timestamp'].isoformat()
            if log.get('metadata'):
                try:
                    log['metadata'] = json.loads(log['metadata'])
                except:
                    pass

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'simulation_id': simulation_id,
            'logs': logs,
            'count': len(logs)
        })

    except Exception as e:
        print(f"[Simulation] Error getting simulation logs: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/analytics/<int:simulation_id>', methods=['GET'])
@login_required
def get_simulation_analytics(simulation_id):
    """Get detailed analytics for a simulation"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get simulation info
        cursor.execute("""
            SELECT template_name, template_display_name, started_at, status
            FROM simulation_runs
            WHERE id = %s
        """, (simulation_id,))
        sim_info = cursor.fetchone()

        if not sim_info:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Simulation not found'}), 404

        # Get events from auth_events
        cursor.execute("""
            SELECT
                source_ip_text as ip_address,
                COUNT(*) as event_count,
                SUM(CASE WHEN event_type = 'failed' THEN 1 ELSE 0 END) as failed_count,
                SUM(CASE WHEN event_type = 'successful' THEN 1 ELSE 0 END) as success_count,
                AVG(ml_risk_score) as avg_risk_score,
                MAX(ml_risk_score) as max_risk_score,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen
            FROM auth_events
            WHERE simulation_run_id = %s
            GROUP BY source_ip_text
            ORDER BY event_count DESC
        """, (simulation_id,))
        ip_stats = cursor.fetchall()

        # Get blocked IPs
        cursor.execute("""
            SELECT ip_address_text, blocked_at, block_reason, risk_score
            FROM ip_blocks
            WHERE simulation_run_id = %s AND is_simulation = TRUE
            ORDER BY blocked_at DESC
        """, (simulation_id,))
        blocked_ips = cursor.fetchall()

        # Get event type breakdown
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM auth_events
            WHERE simulation_run_id = %s
            GROUP BY event_type
        """, (simulation_id,))
        event_breakdown = {row['event_type']: row['count'] for row in cursor.fetchall()}

        # Get unique usernames targeted
        cursor.execute("""
            SELECT DISTINCT target_username
            FROM auth_events
            WHERE simulation_run_id = %s
        """, (simulation_id,))
        usernames = [row['target_username'] for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        # Convert datetime
        for ip in ip_stats:
            if ip.get('first_seen'):
                ip['first_seen'] = ip['first_seen'].isoformat()
            if ip.get('last_seen'):
                ip['last_seen'] = ip['last_seen'].isoformat()
            if ip.get('avg_risk_score'):
                ip['avg_risk_score'] = float(ip['avg_risk_score'])

        for block in blocked_ips:
            if block.get('blocked_at'):
                block['blocked_at'] = block['blocked_at'].isoformat()

        if sim_info.get('started_at'):
            sim_info['started_at'] = sim_info['started_at'].isoformat()

        return jsonify({
            'success': True,
            'has_data': len(ip_stats) > 0,
            'simulation': sim_info,
            'ip_statistics': ip_stats,
            'blocked_ips': blocked_ips,
            'event_breakdown': event_breakdown,
            'usernames_targeted': usernames,
            'total_ips': len(ip_stats),
            'total_blocked': len(blocked_ips)
        })

    except Exception as e:
        print(f"[Simulation] Error getting analytics: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/events/<int:simulation_id>', methods=['GET'])
@login_required
def get_simulation_events(simulation_id):
    """Get auth events for a specific simulation"""
    try:
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                event_uuid,
                timestamp,
                event_type,
                auth_method,
                source_ip_text,
                target_server,
                target_username,
                failure_reason,
                ml_risk_score,
                ml_threat_type,
                is_anomaly,
                processing_status
            FROM auth_events
            WHERE simulation_run_id = %s
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """, (simulation_id, limit, offset))

        events = cursor.fetchall()

        # Get total count
        cursor.execute("""
            SELECT COUNT(*) as total FROM auth_events
            WHERE simulation_run_id = %s
        """, (simulation_id,))
        total = cursor.fetchone()['total']

        cursor.close()
        conn.close()

        # Convert datetime
        for event in events:
            if event.get('timestamp'):
                event['timestamp'] = event['timestamp'].isoformat()

        return jsonify({
            'success': True,
            'simulation_id': simulation_id,
            'events': events,
            'total': total,
            'limit': limit,
            'offset': offset
        })

    except Exception as e:
        print(f"[Simulation] Error getting simulation events: {e}")
        return jsonify({'error': str(e)}), 500
