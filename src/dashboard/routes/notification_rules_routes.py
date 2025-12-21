"""
SSH Guardian v3.1 - Alert Rules Routes
API endpoints for alert/monitor rules (uses blocking_rules table with action_type='alert'/'monitor')
Unified with blocking rules system
"""
import sys
import json
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection
from core.cache import get_cache, cache_key_hash

notification_rules_routes = Blueprint('notification_rules', __name__)

# Cache TTL
ALERT_RULES_LIST_TTL = 300


def invalidate_alert_rules_cache():
    """Invalidate alert rules caches"""
    cache = get_cache()
    cache.delete_pattern('alert_rules')
    cache.delete_pattern('blocking_rules')  # Also invalidate blocking rules cache


# Valid rule types (same as blocking rules)
VALID_RULE_TYPES = [
    'brute_force', 'distributed_brute_force', 'account_takeover',
    'credential_stuffing', 'velocity', 'ml_threshold', 'behavioral_analysis',
    'api_reputation', 'geo_restriction', 'off_hours_anomaly',
    'repeat_offender', 'custom'
]

# Valid channels
VALID_CHANNELS = ['telegram', 'email', 'webhook']


@notification_rules_routes.route('/list', methods=['GET'])
def list_alert_rules():
    """Get all alert/monitor rules from blocking_rules table"""
    conn = None
    cursor = None
    try:
        action_filter = request.args.get('action_type', '')  # 'alert', 'monitor', or '' for both

        cache = get_cache()
        cache_k = cache_key_hash('alert_rules', 'list', action_filter)
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({**cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get alert and monitor rules from blocking_rules
        where_clause = "WHERE action_type IN ('alert', 'monitor')"
        params = []
        if action_filter in ('alert', 'monitor'):
            where_clause = "WHERE action_type = %s"
            params = [action_filter]

        cursor.execute(f"""
            SELECT
                id, rule_name, rule_type, action_type, is_enabled, is_system_rule,
                priority, conditions, block_duration_minutes, notify_on_trigger,
                notification_channels, times_triggered, last_triggered_at,
                description, created_at, updated_at
            FROM blocking_rules
            {where_clause}
            ORDER BY priority ASC, created_at DESC
        """, params)

        rules = cursor.fetchall()

        for rule in rules:
            if rule['last_triggered_at']:
                rule['last_triggered_at'] = rule['last_triggered_at'].isoformat()
            if rule['created_at']:
                rule['created_at'] = rule['created_at'].isoformat()
            if rule['updated_at']:
                rule['updated_at'] = rule['updated_at'].isoformat()
            # Parse JSON fields
            if isinstance(rule['conditions'], str):
                try:
                    rule['conditions'] = json.loads(rule['conditions'])
                except:
                    rule['conditions'] = {}
            if isinstance(rule['notification_channels'], str):
                try:
                    rule['notification_channels'] = json.loads(rule['notification_channels'])
                except:
                    rule['notification_channels'] = []
            # Alias for backwards compatibility
            rule['channels'] = rule['notification_channels'] or []
            rule['event_type'] = rule['rule_type']
            rule['cooldown_minutes'] = rule.get('block_duration_minutes', 5)

        response_data = {
            'success': True,
            'rules': rules,
            'total': len(rules)
        }

        cache.set(cache_k, response_data, ALERT_RULES_LIST_TTL)

        return jsonify({**response_data, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/details/<int:rule_id>', methods=['GET'])
def get_alert_rule(rule_id):
    """Get a specific alert/monitor rule"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id, rule_name, rule_type, action_type, is_enabled, is_system_rule,
                priority, conditions, block_duration_minutes, notify_on_trigger,
                notification_channels, times_triggered, last_triggered_at,
                description, created_at, updated_at
            FROM blocking_rules
            WHERE id = %s AND action_type IN ('alert', 'monitor')
        """, (rule_id,))

        rule = cursor.fetchone()

        if not rule:
            return jsonify({'success': False, 'error': 'Alert rule not found'}), 404

        # Format dates and JSON
        if rule['last_triggered_at']:
            rule['last_triggered_at'] = rule['last_triggered_at'].isoformat()
        if rule['created_at']:
            rule['created_at'] = rule['created_at'].isoformat()
        if rule['updated_at']:
            rule['updated_at'] = rule['updated_at'].isoformat()
        if isinstance(rule['conditions'], str):
            rule['conditions'] = json.loads(rule['conditions']) if rule['conditions'] else {}
        if isinstance(rule['notification_channels'], str):
            rule['notification_channels'] = json.loads(rule['notification_channels']) if rule['notification_channels'] else []
        rule['channels'] = rule['notification_channels'] or []

        return jsonify({'success': True, 'rule': rule})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/create', methods=['POST'])
def create_alert_rule():
    """Create a new alert/monitor rule in blocking_rules table"""
    conn = None
    cursor = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        rule_name = data.get('rule_name', '').strip()
        if not rule_name:
            return jsonify({'success': False, 'error': 'Rule name is required'}), 400

        rule_type = data.get('rule_type') or data.get('event_type', 'custom')
        action_type = data.get('action_type', 'alert')
        if action_type not in ('alert', 'monitor'):
            action_type = 'alert'

        channels = data.get('channels') or data.get('notification_channels', [])
        if not channels and action_type == 'alert':
            return jsonify({'success': False, 'error': 'At least one notification channel is required for alerts'}), 400

        conditions = data.get('conditions', {})
        priority = int(data.get('priority', 50))
        is_enabled = data.get('is_enabled', True)
        description = data.get('description', '')
        notify_on_trigger = data.get('notify_on_trigger', True)

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO blocking_rules (
                rule_name, rule_type, action_type, is_enabled, priority,
                conditions, notify_on_trigger, notification_channels, description
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            rule_name, rule_type, action_type, is_enabled, priority,
            json.dumps(conditions), notify_on_trigger, json.dumps(channels), description
        ))

        rule_id = cursor.lastrowid
        conn.commit()

        invalidate_alert_rules_cache()

        return jsonify({
            'success': True,
            'message': f'Alert rule "{rule_name}" created',
            'rule_id': rule_id
        }), 201

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/update/<int:rule_id>', methods=['PUT'])
def update_alert_rule(rule_id):
    """Update an alert/monitor rule"""
    conn = None
    cursor = None
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check rule exists and is an alert/monitor rule
        cursor.execute("""
            SELECT id, is_system_rule FROM blocking_rules
            WHERE id = %s AND action_type IN ('alert', 'monitor')
        """, (rule_id,))
        existing = cursor.fetchone()

        if not existing:
            return jsonify({'success': False, 'error': 'Alert rule not found'}), 404

        if existing['is_system_rule'] and 'is_system_rule' not in data:
            # Can only update certain fields on system rules
            allowed_fields = ['is_enabled', 'notification_channels', 'channels', 'priority']
            data = {k: v for k, v in data.items() if k in allowed_fields}

        updates = []
        params = []

        if 'rule_name' in data:
            updates.append("rule_name = %s")
            params.append(data['rule_name'])

        if 'is_enabled' in data:
            updates.append("is_enabled = %s")
            params.append(data['is_enabled'])

        if 'rule_type' in data or 'event_type' in data:
            updates.append("rule_type = %s")
            params.append(data.get('rule_type') or data.get('event_type'))

        if 'action_type' in data and data['action_type'] in ('alert', 'monitor'):
            updates.append("action_type = %s")
            params.append(data['action_type'])

        if 'conditions' in data:
            updates.append("conditions = %s")
            params.append(json.dumps(data['conditions']))

        if 'channels' in data or 'notification_channels' in data:
            channels = data.get('channels') or data.get('notification_channels', [])
            updates.append("notification_channels = %s")
            params.append(json.dumps(channels))

        if 'priority' in data:
            updates.append("priority = %s")
            params.append(int(data['priority']))

        if 'description' in data:
            updates.append("description = %s")
            params.append(data['description'])

        if 'notify_on_trigger' in data:
            updates.append("notify_on_trigger = %s")
            params.append(data['notify_on_trigger'])

        if not updates:
            return jsonify({'success': False, 'error': 'No fields to update'}), 400

        updates.append("updated_at = NOW()")
        query = f"UPDATE blocking_rules SET {', '.join(updates)} WHERE id = %s"
        params.append(rule_id)

        cursor.execute(query, params)
        conn.commit()

        invalidate_alert_rules_cache()

        return jsonify({'success': True, 'message': 'Alert rule updated'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/delete/<int:rule_id>', methods=['DELETE'])
def delete_alert_rule(rule_id):
    """Delete an alert/monitor rule"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT rule_name, is_system_rule FROM blocking_rules
            WHERE id = %s AND action_type IN ('alert', 'monitor')
        """, (rule_id,))
        rule = cursor.fetchone()

        if not rule:
            return jsonify({'success': False, 'error': 'Alert rule not found'}), 404

        if rule['is_system_rule']:
            return jsonify({'success': False, 'error': 'Cannot delete system rules'}), 403

        cursor.execute("DELETE FROM blocking_rules WHERE id = %s", (rule_id,))
        conn.commit()

        invalidate_alert_rules_cache()

        return jsonify({'success': True, 'message': f'Rule "{rule["rule_name"]}" deleted'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/toggle/<int:rule_id>', methods=['POST'])
def toggle_alert_rule(rule_id):
    """Toggle alert rule enabled status"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE blocking_rules
            SET is_enabled = NOT is_enabled, updated_at = NOW()
            WHERE id = %s AND action_type IN ('alert', 'monitor')
        """, (rule_id,))

        if cursor.rowcount == 0:
            return jsonify({'success': False, 'error': 'Alert rule not found'}), 404

        conn.commit()
        invalidate_alert_rules_cache()

        return jsonify({'success': True, 'message': 'Rule toggled'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/test/<int:rule_id>', methods=['POST'])
def test_alert_rule(rule_id):
    """Send a test notification for an alert rule"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, rule_name, rule_type, notification_channels
            FROM blocking_rules
            WHERE id = %s AND action_type IN ('alert', 'monitor')
        """, (rule_id,))

        rule = cursor.fetchone()
        if not rule:
            return jsonify({'success': False, 'error': 'Alert rule not found'}), 404

        channels = rule['notification_channels']
        if isinstance(channels, str):
            channels = json.loads(channels) if channels else []

        if not channels:
            return jsonify({'success': False, 'error': 'No notification channels configured'}), 400

        test_message = f"Test Alert\n\nRule: {rule['rule_name']}\nType: {rule['rule_type']}\n\nThis is a test notification from SSH Guardian"
        results = []

        for channel in channels:
            result = {'channel': channel, 'success': False, 'message': 'Not implemented'}

            if channel == 'telegram':
                try:
                    # Get telegram config from integrations table
                    cursor.execute("""
                        SELECT config, credentials FROM integrations
                        WHERE integration_type = 'telegram' AND is_enabled = 1
                    """)
                    tg_config = cursor.fetchone()
                    if tg_config:
                        import requests
                        config = json.loads(tg_config['config'] or '{}')
                        creds = json.loads(tg_config['credentials'] or '{}')
                        bot_token = creds.get('bot_token') or config.get('bot_token')
                        chat_id = config.get('chat_id')
                        if bot_token and chat_id:
                            response = requests.post(
                                f'https://api.telegram.org/bot{bot_token}/sendMessage',
                                json={'chat_id': chat_id, 'text': test_message, 'parse_mode': 'HTML'},
                                timeout=10
                            )
                            if response.json().get('ok'):
                                result = {'channel': 'telegram', 'success': True, 'message': 'Sent'}
                            else:
                                result = {'channel': 'telegram', 'success': False, 'message': response.json().get('description', 'Failed')}
                        else:
                            result = {'channel': 'telegram', 'success': False, 'message': 'Not configured'}
                    else:
                        result = {'channel': 'telegram', 'success': False, 'message': 'Not configured'}
                except Exception as e:
                    result = {'channel': 'telegram', 'success': False, 'message': str(e)}

            results.append(result)

        return jsonify({'success': True, 'results': results})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/event-types', methods=['GET'])
def get_event_types():
    """Get list of valid rule types for alerts"""
    event_types = [
        {'value': 'brute_force', 'label': 'Brute Force Attack', 'icon': '🔨', 'category': 'attack'},
        {'value': 'distributed_brute_force', 'label': 'Distributed Brute Force', 'icon': '🤖', 'category': 'attack'},
        {'value': 'account_takeover', 'label': 'Account Takeover', 'icon': '🎭', 'category': 'attack'},
        {'value': 'credential_stuffing', 'label': 'Credential Stuffing', 'icon': '🔑', 'category': 'attack'},
        {'value': 'velocity', 'label': 'Velocity/DDoS Attack', 'icon': '⚡', 'category': 'attack'},
        {'value': 'ml_threshold', 'label': 'ML Risk Threshold', 'icon': '🧠', 'category': 'ml'},
        {'value': 'behavioral_analysis', 'label': 'Behavioral Anomaly', 'icon': '📊', 'category': 'ml'},
        {'value': 'api_reputation', 'label': 'API Reputation Check', 'icon': '🌐', 'category': 'ml'},
        {'value': 'geo_restriction', 'label': 'Geographic Restriction', 'icon': '🌍', 'category': 'geo'},
        {'value': 'off_hours_anomaly', 'label': 'Off-Hours Activity', 'icon': '🌙', 'category': 'geo'},
        {'value': 'repeat_offender', 'label': 'Repeat Offender', 'icon': '🔄', 'category': 'other'},
        {'value': 'custom', 'label': 'Custom Rule', 'icon': '⚙️', 'category': 'other'}
    ]

    return jsonify({
        'success': True,
        'event_types': event_types,
        'triggers': [e['value'] for e in event_types]  # Backwards compatibility
    })


@notification_rules_routes.route('/channels', methods=['GET'])
def get_channels():
    """Get list of available notification channels"""
    return jsonify({
        'success': True,
        'channels': VALID_CHANNELS
    })
