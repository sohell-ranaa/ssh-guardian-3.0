"""
SSH Guardian v3.0 - Trusted Sources API
Manage auto-learned trusted IPs and networks
"""

from flask import Blueprint, request, jsonify
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "src" / "core"))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection
from auto_trust_learner import AutoTrustLearner, is_ip_trusted

trusted_bp = Blueprint('trusted', __name__, url_prefix='/api/trusted')


@trusted_bp.route('/sources', methods=['GET'])
def get_trusted_sources():
    """Get all trusted sources"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT
                id, source_type, ip_address, network_cidr,
                trust_score, successful_logins, failed_logins,
                unique_users, days_active,
                is_auto_trusted, is_manually_trusted,
                trusted_at, trust_reason,
                first_seen_at, last_seen_at
            FROM trusted_sources
            WHERE is_auto_trusted = TRUE OR is_manually_trusted = TRUE
            ORDER BY trust_score DESC
        """)

        sources = cursor.fetchall()

        # Convert datetime objects
        for s in sources:
            for key in ['trusted_at', 'first_seen_at', 'last_seen_at']:
                if s.get(key):
                    s[key] = s[key].isoformat()

        return jsonify({
            'success': True,
            'count': len(sources),
            'sources': sources
        })

    finally:
        cursor.close()
        conn.close()


@trusted_bp.route('/check/<ip_address>', methods=['GET'])
def check_ip_trust(ip_address):
    """Check if an IP is trusted"""
    is_trusted, reason = is_ip_trusted(ip_address)

    return jsonify({
        'success': True,
        'ip_address': ip_address,
        'is_trusted': is_trusted,
        'reason': reason
    })


@trusted_bp.route('/learn', methods=['POST'])
def run_learning():
    """Run the trust learning process"""
    learner = AutoTrustLearner(verbose=False)
    results = learner.learn_from_all_events()

    return jsonify({
        'success': True,
        'message': 'Trust learning completed',
        'results': results
    })


@trusted_bp.route('/add', methods=['POST'])
def add_trusted_source():
    """Manually add a trusted IP or network"""
    data = request.json
    ip_address = data.get('ip_address')
    network_cidr = data.get('network_cidr')
    reason = data.get('reason', 'Manually added')

    if not ip_address and not network_cidr:
        return jsonify({
            'success': False,
            'error': 'Either ip_address or network_cidr required'
        }), 400

    conn = get_connection()
    cursor = conn.cursor()

    try:
        if ip_address:
            cursor.execute("""
                INSERT INTO trusted_sources (
                    source_type, ip_address, trust_score,
                    is_manually_trusted, trusted_at, trust_reason
                ) VALUES ('ip', %s, 100, TRUE, NOW(), %s)
                ON DUPLICATE KEY UPDATE
                    is_manually_trusted = TRUE,
                    trusted_at = NOW(),
                    trust_reason = VALUES(trust_reason)
            """, (ip_address, reason))
        else:
            cursor.execute("""
                INSERT INTO trusted_sources (
                    source_type, network_cidr, trust_score,
                    is_manually_trusted, trusted_at, trust_reason
                ) VALUES ('network', %s, 100, TRUE, NOW(), %s)
                ON DUPLICATE KEY UPDATE
                    is_manually_trusted = TRUE,
                    trusted_at = NOW(),
                    trust_reason = VALUES(trust_reason)
            """, (network_cidr, reason))

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'Added trusted {"IP: " + ip_address if ip_address else "network: " + network_cidr}'
        })

    except Exception as e:
        conn.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        cursor.close()
        conn.close()


@trusted_bp.route('/remove/<int:source_id>', methods=['DELETE'])
def remove_trusted_source(source_id):
    """Remove a trusted source"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE trusted_sources
            SET is_auto_trusted = FALSE, is_manually_trusted = FALSE
            WHERE id = %s
        """, (source_id,))
        conn.commit()

        return jsonify({
            'success': True,
            'message': f'Removed trusted source {source_id}'
        })
    finally:
        cursor.close()
        conn.close()
