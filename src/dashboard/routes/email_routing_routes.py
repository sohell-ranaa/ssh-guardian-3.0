"""
SSH Guardian v3.1 - Email Routing Routes
API endpoints for managing email notification routing rules.
Routes notifications from specific agents and rule types to designated email addresses.
Uses system_settings table with 'email_routing_rules' key.
"""
import sys
import json
import uuid
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

email_routing_routes = Blueprint('email_routing', __name__)


def get_routing_rules():
    """Get email routing rules from system_settings"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT setting_value FROM system_settings
            WHERE setting_key = 'email_routing_rules'
        """)
        row = cursor.fetchone()
        if row and row['setting_value']:
            try:
                return json.loads(row['setting_value'])
            except json.JSONDecodeError:
                return []
        return []
    finally:
        cursor.close()
        conn.close()


def save_routing_rules(rules):
    """Save email routing rules to system_settings"""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE system_settings
            SET setting_value = %s, updated_at = NOW()
            WHERE setting_key = 'email_routing_rules'
        """, (json.dumps(rules),))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()


def get_agents_list():
    """Get list of active agents"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT id, agent_id, hostname, is_active
            FROM agents
            ORDER BY hostname
        """)
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


# Valid rule types (matches blocking_rules.rule_type)
RULE_TYPES = [
    {'value': 'brute_force', 'label': 'Brute Force Attack', 'icon': '🔨'},
    {'value': 'distributed_brute_force', 'label': 'Distributed Brute Force', 'icon': '🤖'},
    {'value': 'account_takeover', 'label': 'Account Takeover', 'icon': '🎭'},
    {'value': 'credential_stuffing', 'label': 'Credential Stuffing', 'icon': '🔑'},
    {'value': 'velocity', 'label': 'Velocity/DDoS Attack', 'icon': '⚡'},
    {'value': 'ml_threshold', 'label': 'ML Risk Threshold', 'icon': '🧠'},
    {'value': 'behavioral_analysis', 'label': 'Behavioral Anomaly', 'icon': '📊'},
    {'value': 'api_reputation', 'label': 'API Reputation Check', 'icon': '🌐'},
    {'value': 'geo_restriction', 'label': 'Geographic Restriction', 'icon': '🌍'},
    {'value': 'off_hours_anomaly', 'label': 'Off-Hours Activity', 'icon': '🌙'},
    {'value': 'repeat_offender', 'label': 'Repeat Offender', 'icon': '🔄'},
    {'value': 'high_risk_detected', 'label': 'High Risk Detection', 'icon': '⚠️'},
    {'value': 'ip_blocked', 'label': 'IP Blocked', 'icon': '🚫'},
    {'value': 'custom', 'label': 'Custom Rule', 'icon': '⚙️'}
]


@email_routing_routes.route('/list', methods=['GET'])
def list_routing_rules():
    """Get all email routing rules"""
    try:
        rules = get_routing_rules()
        agents = get_agents_list()

        return jsonify({
            'success': True,
            'data': {
                'rules': rules,
                'agents': agents,
                'rule_types': RULE_TYPES
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@email_routing_routes.route('/create', methods=['POST'])
def create_routing_rule():
    """Create a new email routing rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        name = data.get('name', '').strip()
        if not name:
            return jsonify({'success': False, 'error': 'Rule name is required'}), 400

        email_addresses = data.get('email_addresses', [])
        if not email_addresses:
            return jsonify({'success': False, 'error': 'At least one email address is required'}), 400

        # Validate email addresses
        import re
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        for email in email_addresses:
            if not email_pattern.match(email):
                return jsonify({'success': False, 'error': f'Invalid email: {email}'}), 400

        agents = data.get('agents', ['all'])  # List of agent IDs or ['all']
        rule_types = data.get('rule_types', ['all'])  # List of rule types or ['all']

        new_rule = {
            'id': str(uuid.uuid4())[:8],
            'name': name,
            'description': data.get('description', ''),
            'agents': agents,
            'rule_types': rule_types,
            'email_addresses': email_addresses,
            'is_enabled': data.get('is_enabled', True),
            'priority': int(data.get('priority', 50)),
            'created_at': __import__('datetime').datetime.now().isoformat()
        }

        rules = get_routing_rules()
        rules.append(new_rule)
        save_routing_rules(rules)

        return jsonify({
            'success': True,
            'message': f'Routing rule "{name}" created',
            'rule': new_rule
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@email_routing_routes.route('/update/<rule_id>', methods=['PUT'])
def update_routing_rule(rule_id):
    """Update an existing email routing rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        rules = get_routing_rules()

        # Find rule by ID
        rule_index = None
        for i, rule in enumerate(rules):
            if rule.get('id') == rule_id:
                rule_index = i
                break

        if rule_index is None:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        # Validate email addresses if provided
        if 'email_addresses' in data:
            import re
            email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            for email in data['email_addresses']:
                if not email_pattern.match(email):
                    return jsonify({'success': False, 'error': f'Invalid email: {email}'}), 400

        # Update fields
        if 'name' in data:
            rules[rule_index]['name'] = data['name'].strip()
        if 'description' in data:
            rules[rule_index]['description'] = data['description']
        if 'agents' in data:
            rules[rule_index]['agents'] = data['agents']
        if 'rule_types' in data:
            rules[rule_index]['rule_types'] = data['rule_types']
        if 'email_addresses' in data:
            rules[rule_index]['email_addresses'] = data['email_addresses']
        if 'is_enabled' in data:
            rules[rule_index]['is_enabled'] = data['is_enabled']
        if 'priority' in data:
            rules[rule_index]['priority'] = int(data['priority'])

        rules[rule_index]['updated_at'] = __import__('datetime').datetime.now().isoformat()

        save_routing_rules(rules)

        return jsonify({
            'success': True,
            'message': 'Routing rule updated',
            'rule': rules[rule_index]
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@email_routing_routes.route('/delete/<rule_id>', methods=['DELETE'])
def delete_routing_rule(rule_id):
    """Delete an email routing rule"""
    try:
        rules = get_routing_rules()

        # Find and remove rule
        original_count = len(rules)
        rules = [r for r in rules if r.get('id') != rule_id]

        if len(rules) == original_count:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        save_routing_rules(rules)

        return jsonify({
            'success': True,
            'message': 'Routing rule deleted'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@email_routing_routes.route('/toggle/<rule_id>', methods=['POST'])
def toggle_routing_rule(rule_id):
    """Toggle a routing rule's enabled status"""
    try:
        rules = get_routing_rules()

        for rule in rules:
            if rule.get('id') == rule_id:
                rule['is_enabled'] = not rule.get('is_enabled', True)
                rule['updated_at'] = __import__('datetime').datetime.now().isoformat()
                save_routing_rules(rules)
                return jsonify({
                    'success': True,
                    'message': f"Rule {'enabled' if rule['is_enabled'] else 'disabled'}",
                    'is_enabled': rule['is_enabled']
                })

        return jsonify({'success': False, 'error': 'Rule not found'}), 404

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@email_routing_routes.route('/agents', methods=['GET'])
def list_agents():
    """Get list of agents for selection"""
    try:
        agents = get_agents_list()
        return jsonify({
            'success': True,
            'data': {
                'agents': agents
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@email_routing_routes.route('/rule-types', methods=['GET'])
def list_rule_types():
    """Get list of rule types for selection"""
    return jsonify({
        'success': True,
        'data': {
            'rule_types': RULE_TYPES
        }
    })


@email_routing_routes.route('/resolve', methods=['POST'])
def resolve_recipients():
    """
    Resolve which email addresses should receive a notification.
    Used by notification dispatcher.

    Request body:
    {
        "agent_id": "agent-123",
        "rule_type": "brute_force"
    }

    Returns:
    {
        "success": true,
        "email_addresses": ["admin@example.com", "security@example.com"]
    }
    """
    try:
        data = request.get_json() or {}
        agent_id = data.get('agent_id')
        rule_type = data.get('rule_type')

        rules = get_routing_rules()
        matched_emails = set()

        # Sort by priority (lower = higher priority)
        rules_sorted = sorted(
            [r for r in rules if r.get('is_enabled', True)],
            key=lambda x: x.get('priority', 50)
        )

        for rule in rules_sorted:
            agents = rule.get('agents', ['all'])
            rule_types = rule.get('rule_types', ['all'])

            # Check if agent matches
            agent_match = False
            if 'all' in agents:
                agent_match = True
            elif agent_id and agent_id in agents:
                agent_match = True

            # Check if rule type matches
            type_match = False
            if 'all' in rule_types:
                type_match = True
            elif rule_type and rule_type in rule_types:
                type_match = True

            # If both match, add emails
            if agent_match and type_match:
                for email in rule.get('email_addresses', []):
                    matched_emails.add(email)

        return jsonify({
            'success': True,
            'email_addresses': list(matched_emails)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
