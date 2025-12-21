"""
SSH Guardian v3.1 - Simulation API Routes
API endpoints for attack simulation management
Updated for v3.1 database schema
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
from src.core.auth import login_required

simulation_routes = Blueprint('simulation_routes', __name__)


@simulation_routes.route('/templates', methods=['GET'])
@login_required
def get_templates():
    """Get all available attack templates from database"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1: No display_name, severity, category columns
        cursor.execute("""
            SELECT
                id,
                template_name,
                attack_type,
                description,
                parameters,
                is_active,
                created_at
            FROM simulation_templates
            WHERE is_active = TRUE
            ORDER BY attack_type, template_name
        """)

        templates = cursor.fetchall()

        for t in templates:
            if t.get('created_at'):
                t['created_at'] = t['created_at'].isoformat()
            if t.get('parameters'):
                if isinstance(t['parameters'], str):
                    t['parameters'] = json.loads(t['parameters'])

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'templates': templates,
            'count': len(templates)
        })

    except Exception as e:
        print(f"[Simulation] Error getting templates: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/template/<int:template_id>', methods=['GET'])
@login_required
def get_template_detail(template_id):
    """Get a specific template details"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM simulation_templates
            WHERE id = %s
        """, (template_id,))

        template = cursor.fetchone()

        cursor.close()
        conn.close()

        if not template:
            return jsonify({'error': 'Template not found'}), 404

        if template.get('parameters'):
            if isinstance(template['parameters'], str):
                template['parameters'] = json.loads(template['parameters'])
        if template.get('created_at'):
            template['created_at'] = template['created_at'].isoformat()

        return jsonify({
            'success': True,
            'template': template
        })

    except Exception as e:
        print(f"[Simulation] Error getting template {template_id}: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/ip-pool/<pool_type>', methods=['GET'])
@login_required
def get_ip_pool(pool_type):
    """Get IPs from the simulation IP pool"""
    try:
        count = int(request.args.get('count', 5))

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id,
                ip_address,
                ip_type,
                country_code,
                threat_score
            FROM simulation_ip_pool
            WHERE ip_type = %s
            ORDER BY RAND()
            LIMIT %s
        """, (pool_type, count))

        ips = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'pool_type': pool_type,
            'ips': ips,
            'count': len(ips)
        })

    except Exception as e:
        print(f"[Simulation] Error getting IP pool: {e}")
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

        # v3.1: Updated column names
        query = """
            SELECT
                sr.id,
                sr.run_uuid,
                sr.run_name,
                sr.status,
                sr.attack_type,
                sr.events_generated,
                sr.events_blocked,
                sr.detection_rate,
                sr.false_positive_rate,
                sr.started_at,
                sr.completed_at,
                sr.duration_seconds,
                sr.results,
                st.template_name as template_display_name,
                st.template_name,
                u.email as user_email
            FROM simulation_runs sr
            LEFT JOIN simulation_templates st ON sr.template_id = st.id
            LEFT JOIN users u ON sr.triggered_by_user_id = u.id
        """

        params = []
        if attack_type:
            query += " WHERE sr.attack_type = %s"
            params.append(attack_type)

        query += " ORDER BY sr.started_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cursor.execute(query, tuple(params))
        history = cursor.fetchall()

        for record in history:
            if record.get('started_at'):
                record['started_at'] = record['started_at'].isoformat()
            if record.get('completed_at'):
                record['completed_at'] = record['completed_at'].isoformat()
            if record.get('detection_rate') is not None:
                record['detection_rate'] = float(record['detection_rate'])
            if record.get('false_positive_rate') is not None:
                record['false_positive_rate'] = float(record['false_positive_rate'])
            if record.get('results'):
                if isinstance(record['results'], str):
                    record['results'] = json.loads(record['results'])

        # Get total count
        count_query = "SELECT COUNT(*) as total FROM simulation_runs"
        count_params = []
        if attack_type:
            count_query += " WHERE attack_type = %s"
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

        # v3.1: No display_name in simulation_templates
        cursor.execute("""
            SELECT DISTINCT
                sr.attack_type,
                st.template_name as display_name
            FROM simulation_runs sr
            LEFT JOIN simulation_templates st ON sr.template_id = st.id
            WHERE sr.attack_type IS NOT NULL
            ORDER BY st.template_name
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


@simulation_routes.route('/run/<int:simulation_id>', methods=['GET'])
@login_required
def get_simulation_detail(simulation_id):
    """Get detailed info about a simulation run"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                sr.*,
                st.template_name,
                st.template_name as template_display_name,
                st.description as template_description,
                u.email as user_email,
                a.hostname as target_agent_name
            FROM simulation_runs sr
            LEFT JOIN simulation_templates st ON sr.template_id = st.id
            LEFT JOIN users u ON sr.triggered_by_user_id = u.id
            LEFT JOIN agents a ON sr.target_agent_id = a.id
            WHERE sr.id = %s
        """, (simulation_id,))

        simulation = cursor.fetchone()

        cursor.close()
        conn.close()

        if not simulation:
            return jsonify({'error': 'Simulation not found'}), 404

        if simulation.get('started_at'):
            simulation['started_at'] = simulation['started_at'].isoformat()
        if simulation.get('completed_at'):
            simulation['completed_at'] = simulation['completed_at'].isoformat()
        if simulation.get('created_at'):
            simulation['created_at'] = simulation['created_at'].isoformat()
        if simulation.get('parameters'):
            if isinstance(simulation['parameters'], str):
                simulation['parameters'] = json.loads(simulation['parameters'])
        if simulation.get('results'):
            if isinstance(simulation['results'], str):
                simulation['results'] = json.loads(simulation['results'])
        if simulation.get('detection_rate') is not None:
            simulation['detection_rate'] = float(simulation['detection_rate'])
        if simulation.get('false_positive_rate') is not None:
            simulation['false_positive_rate'] = float(simulation['false_positive_rate'])

        return jsonify({
            'success': True,
            'simulation': simulation
        })

    except Exception as e:
        print(f"[Simulation] Error getting simulation details: {e}")
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
            SELECT
                sr.run_name,
                sr.attack_type,
                sr.started_at,
                sr.completed_at,
                sr.status,
                sr.events_generated,
                sr.events_blocked,
                sr.detection_rate,
                sr.results,
                st.template_name as template_display_name
            FROM simulation_runs sr
            LEFT JOIN simulation_templates st ON sr.template_id = st.id
            WHERE sr.id = %s
        """, (simulation_id,))
        sim_info = cursor.fetchone()

        if not sim_info:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Simulation not found'}), 404

        if sim_info.get('started_at'):
            sim_info['started_at'] = sim_info['started_at'].isoformat()
        if sim_info.get('completed_at'):
            sim_info['completed_at'] = sim_info['completed_at'].isoformat()
        if sim_info.get('detection_rate') is not None:
            sim_info['detection_rate'] = float(sim_info['detection_rate'])
        if sim_info.get('results'):
            if isinstance(sim_info['results'], str):
                sim_info['results'] = json.loads(sim_info['results'])

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'simulation': sim_info
        })

    except Exception as e:
        print(f"[Simulation] Error getting simulation analytics: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/live/list', methods=['GET'])
@login_required
def get_live_simulations():
    """Get list of live simulation runs"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                ls.*,
                a.hostname as agent_name,
                u.email as user_email
            FROM live_simulation_runs ls
            LEFT JOIN agents a ON ls.agent_id = a.id
            LEFT JOIN users u ON ls.triggered_by_user_id = u.id
            ORDER BY ls.created_at DESC
            LIMIT 50
        """)

        runs = cursor.fetchall()

        for run in runs:
            if run.get('started_at'):
                run['started_at'] = run['started_at'].isoformat()
            if run.get('completed_at'):
                run['completed_at'] = run['completed_at'].isoformat()
            if run.get('created_at'):
                run['created_at'] = run['created_at'].isoformat()
            if run.get('parameters'):
                if isinstance(run['parameters'], str):
                    run['parameters'] = json.loads(run['parameters'])
            if run.get('results'):
                if isinstance(run['results'], str):
                    run['results'] = json.loads(run['results'])

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'runs': runs,
            'count': len(runs)
        })

    except Exception as e:
        print(f"[Simulation] Error getting live simulations: {e}")
        return jsonify({'error': str(e)}), 500


@simulation_routes.route('/stats', methods=['GET'])
@login_required
def get_simulation_stats():
    """Get overall simulation statistics"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Total simulations
        cursor.execute("SELECT COUNT(*) as total FROM simulation_runs")
        total = cursor.fetchone()['total']

        # By status
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM simulation_runs
            GROUP BY status
        """)
        by_status = {row['status']: row['count'] for row in cursor.fetchall()}

        # By attack type
        cursor.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM simulation_runs
            WHERE attack_type IS NOT NULL
            GROUP BY attack_type
            ORDER BY count DESC
            LIMIT 10
        """)
        by_type = cursor.fetchall()

        # Recent activity
        cursor.execute("""
            SELECT
                DATE(started_at) as date,
                COUNT(*) as count
            FROM simulation_runs
            WHERE started_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(started_at)
            ORDER BY date DESC
        """)
        recent = cursor.fetchall()

        for r in recent:
            if r.get('date'):
                r['date'] = str(r['date'])

        # Average detection rate
        cursor.execute("""
            SELECT AVG(detection_rate) as avg_rate
            FROM simulation_runs
            WHERE detection_rate IS NOT NULL
        """)
        avg_detection = cursor.fetchone()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'stats': {
                'total_simulations': total,
                'by_status': by_status,
                'by_attack_type': by_type,
                'recent_30_days': recent,
                'avg_detection_rate': float(avg_detection['avg_rate'] or 0) if avg_detection else 0
            }
        })

    except Exception as e:
        print(f"[Simulation] Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500
