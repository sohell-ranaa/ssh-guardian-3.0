"""
Notification Rules Routes - API endpoints for notification rule management
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
NOTIFICATION_RULES_LIST_TTL = 900  # 15 minutes for notification rules list


def invalidate_notification_rules_cache():
    """Invalidate all notification rules caches"""
    cache = get_cache()
    cache.delete_pattern('notification_rules')

# Valid trigger types - aligned with blocking rules
VALID_TRIGGERS = [
    # Core triggers
    'ip_blocked',
    'agent_offline',
    'system_error',
    'successful_login',
    # Blocking rule triggers
    'brute_force_detected',
    'distributed_brute_force_detected',
    'account_takeover_detected',
    'credential_stuffing_detected',
    'off_hours_anomaly_detected',
    'velocity_attack_detected',
    # ML/API triggers
    'ml_threat_detected',
    'high_risk_detected',
    'anomaly_detected',
    # Geo/Network triggers
    'geo_anomaly_detected',
    'tor_detected',
    'proxy_detected',
    'geo_blocked'
]

# Valid channels
VALID_CHANNELS = ['telegram', 'email', 'webhook']

# Valid message formats
VALID_FORMATS = ['text', 'html', 'markdown']


@notification_rules_routes.route('/list', methods=['GET'])
def list_notification_rules():
    """Get all notification rules with caching support"""
    conn = None
    cursor = None
    try:
        # Generate cache key based on query parameters (for pagination support)
        cache = get_cache()
        cache_k = cache_key_hash('notification_rules', 'list')

        # Try cache first
        cached = cache.get(cache_k)
        if cached is not None:
            cached['from_cache'] = True
            return jsonify(cached), 200

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id, rule_name, is_enabled, trigger_on, conditions, channels,
                telegram_chat_id, email_recipients, webhook_url,
                message_template, message_format, rate_limit_minutes,
                times_triggered, last_triggered_at, created_at, updated_at
            FROM notification_rules
            ORDER BY created_at DESC
        """)

        rules = cursor.fetchall()

        # Format data
        for rule in rules:
            if rule['last_triggered_at']:
                rule['last_triggered_at'] = rule['last_triggered_at'].isoformat()
            if rule['created_at']:
                rule['created_at'] = rule['created_at'].isoformat()
            if rule['updated_at']:
                rule['updated_at'] = rule['updated_at'].isoformat()

        response_data = {
            'success': True,
            'data': {
                'rules': rules,
                'total': len(rules)
            }
        }

        # Cache the result
        cache.set(cache_k, response_data, NOTIFICATION_RULES_LIST_TTL)

        return jsonify(response_data)

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/triggers', methods=['GET'])
def list_trigger_types():
    """Get available trigger types - aligned with blocking rules"""
    triggers = [
        # Core system triggers
        {'value': 'ip_blocked', 'label': 'IP Blocked', 'description': 'When any IP is blocked by the system', 'category': 'core', 'icon': '🛡️'},
        {'value': 'agent_offline', 'label': 'Agent Offline', 'description': 'When a monitoring agent goes offline', 'category': 'core', 'icon': '📴'},
        {'value': 'system_error', 'label': 'System Error', 'description': 'When a system error occurs', 'category': 'core', 'icon': '❌'},
        {'value': 'successful_login', 'label': 'Successful Login', 'description': 'When a successful SSH login occurs (for monitoring)', 'category': 'core', 'icon': '✅'},

        # Blocking rule triggers
        {'value': 'brute_force_detected', 'label': 'Brute Force Attack', 'description': 'Same IP, multiple failed attempts in short time', 'category': 'attack', 'icon': '🔨'},
        {'value': 'distributed_brute_force_detected', 'label': 'Distributed Brute Force', 'description': 'Many IPs targeting many usernames with slow frequency (botnet)', 'category': 'attack', 'icon': '🤖'},
        {'value': 'account_takeover_detected', 'label': 'Account Takeover Attempt', 'description': 'Same username from multiple IPs/countries quickly', 'category': 'attack', 'icon': '🎭'},
        {'value': 'credential_stuffing_detected', 'label': 'Credential Stuffing', 'description': 'Leaked credentials being tested from multiple locations', 'category': 'attack', 'icon': '🔑'},
        {'value': 'off_hours_anomaly_detected', 'label': 'Off-Hours Anomaly', 'description': 'Login attempt outside normal business hours', 'category': 'attack', 'icon': '🌙'},
        {'value': 'velocity_attack_detected', 'label': 'Velocity/DDoS Attack', 'description': 'Rapid-fire login attempts detected', 'category': 'attack', 'icon': '⚡'},

        # ML/API triggers
        {'value': 'ml_threat_detected', 'label': 'ML Threat Detected', 'description': 'Machine learning model detected suspicious behavior', 'category': 'ml', 'icon': '🧠'},
        {'value': 'high_risk_detected', 'label': 'High Risk IP (API)', 'description': 'IP flagged by AbuseIPDB/VirusTotal reputation', 'category': 'ml', 'icon': '⚠️'},
        {'value': 'anomaly_detected', 'label': 'Behavioral Anomaly', 'description': 'Unusual pattern detected by anomaly detection', 'category': 'ml', 'icon': '🔍'},

        # Geo/Network triggers
        {'value': 'geo_anomaly_detected', 'label': 'Impossible Travel', 'description': 'Login from distant location too quickly', 'category': 'geo', 'icon': '🌍'},
        {'value': 'tor_detected', 'label': 'Tor Exit Node', 'description': 'Login attempt from Tor network', 'category': 'geo', 'icon': '🧅'},
        {'value': 'proxy_detected', 'label': 'Proxy/VPN Detected', 'description': 'Login attempt through proxy or VPN', 'category': 'geo', 'icon': '🔒'},
        {'value': 'geo_blocked', 'label': 'Geo-Restricted Country', 'description': 'Login from blocked/high-risk country', 'category': 'geo', 'icon': '🚫'}
    ]

    return jsonify({
        'success': True,
        'data': {'triggers': triggers}
    })


@notification_rules_routes.route('/<int:rule_id>', methods=['GET'])
def get_notification_rule(rule_id):
    """Get a specific notification rule"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id, rule_name, is_enabled, trigger_on, conditions, channels,
                telegram_bot_token, telegram_chat_id, email_recipients,
                webhook_url, webhook_headers,
                message_template, message_format, rate_limit_minutes,
                times_triggered, last_triggered_at, created_at, updated_at
            FROM notification_rules
            WHERE id = %s
        """, (rule_id,))

        rule = cursor.fetchone()

        if not rule:
            return jsonify({
                'success': False,
                'error': 'Rule not found'
            }), 404

        # Format timestamps
        if rule['last_triggered_at']:
            rule['last_triggered_at'] = rule['last_triggered_at'].isoformat()
        if rule['created_at']:
            rule['created_at'] = rule['created_at'].isoformat()
        if rule['updated_at']:
            rule['updated_at'] = rule['updated_at'].isoformat()

        # Mask sensitive data
        if rule['telegram_bot_token']:
            rule['telegram_bot_token'] = '***' + rule['telegram_bot_token'][-8:]

        return jsonify({
            'success': True,
            'data': rule
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/create', methods=['POST'])
def create_notification_rule():
    """Create a new notification rule"""
    conn = None
    cursor = None
    try:
        data = request.get_json()

        rule_name = data.get('rule_name', '').strip()
        trigger_on = data.get('trigger_on', '')
        channels = data.get('channels', [])
        message_template = data.get('message_template', '').strip()

        # Validate required fields
        if not rule_name:
            return jsonify({'success': False, 'error': 'Rule name is required'}), 400

        if trigger_on not in VALID_TRIGGERS:
            return jsonify({'success': False, 'error': f'Invalid trigger type. Valid: {", ".join(VALID_TRIGGERS)}'}), 400

        if not channels or not isinstance(channels, list):
            return jsonify({'success': False, 'error': 'At least one channel is required'}), 400

        for channel in channels:
            if channel not in VALID_CHANNELS:
                return jsonify({'success': False, 'error': f'Invalid channel: {channel}'}), 400

        if not message_template:
            return jsonify({'success': False, 'error': 'Message template is required'}), 400

        # Optional fields
        is_enabled = data.get('is_enabled', True)
        conditions = data.get('conditions', {})
        telegram_bot_token = data.get('telegram_bot_token', '').strip() or None
        telegram_chat_id = data.get('telegram_chat_id', '').strip() or None
        email_recipients = data.get('email_recipients', [])
        webhook_url = data.get('webhook_url', '').strip() or None
        webhook_headers = data.get('webhook_headers', {})
        message_format = data.get('message_format', 'markdown')
        rate_limit_minutes = int(data.get('rate_limit_minutes', 5))

        if message_format not in VALID_FORMATS:
            message_format = 'markdown'

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO notification_rules (
                    rule_name, is_enabled, trigger_on, conditions, channels,
                    telegram_bot_token, telegram_chat_id, email_recipients,
                    webhook_url, webhook_headers, message_template,
                    message_format, rate_limit_minutes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                rule_name, is_enabled, trigger_on,
                json.dumps(conditions) if conditions else None,
                json.dumps(channels),
                telegram_bot_token, telegram_chat_id,
                json.dumps(email_recipients) if email_recipients else None,
                webhook_url,
                json.dumps(webhook_headers) if webhook_headers else None,
                message_template, message_format, rate_limit_minutes
            ))

            conn.commit()
            new_id = cursor.lastrowid

            # Invalidate cache after successful creation
            invalidate_notification_rules_cache()

            return jsonify({
                'success': True,
                'message': 'Notification rule created successfully',
                'data': {'id': new_id}
            })

        except Exception as e:
            conn.rollback()

            if 'Duplicate entry' in str(e):
                return jsonify({
                    'success': False,
                    'error': f'A rule with name "{rule_name}" already exists'
                }), 400

            raise e

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/<int:rule_id>', methods=['PUT'])
def update_notification_rule(rule_id):
    """Update a notification rule"""
    conn = None
    cursor = None
    try:
        data = request.get_json()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if rule exists
        cursor.execute("SELECT id FROM notification_rules WHERE id = %s", (rule_id,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        # Build update query dynamically
        updates = []
        params = []

        if 'rule_name' in data:
            updates.append("rule_name = %s")
            params.append(data['rule_name'].strip())

        if 'is_enabled' in data:
            updates.append("is_enabled = %s")
            params.append(data['is_enabled'])

        if 'trigger_on' in data:
            if data['trigger_on'] not in VALID_TRIGGERS:
                return jsonify({'success': False, 'error': 'Invalid trigger type'}), 400
            updates.append("trigger_on = %s")
            params.append(data['trigger_on'])

        if 'conditions' in data:
            updates.append("conditions = %s")
            params.append(json.dumps(data['conditions']) if data['conditions'] else None)

        if 'channels' in data:
            channels = data['channels']
            if not channels or not isinstance(channels, list):
                return jsonify({'success': False, 'error': 'At least one channel is required'}), 400
            updates.append("channels = %s")
            params.append(json.dumps(channels))

        if 'telegram_bot_token' in data:
            # Only update if not masked value
            token = data['telegram_bot_token']
            if token and not token.startswith('***'):
                updates.append("telegram_bot_token = %s")
                params.append(token.strip() or None)

        if 'telegram_chat_id' in data:
            updates.append("telegram_chat_id = %s")
            params.append(data['telegram_chat_id'].strip() or None)

        if 'email_recipients' in data:
            updates.append("email_recipients = %s")
            params.append(json.dumps(data['email_recipients']) if data['email_recipients'] else None)

        if 'webhook_url' in data:
            updates.append("webhook_url = %s")
            params.append(data['webhook_url'].strip() or None)

        if 'webhook_headers' in data:
            updates.append("webhook_headers = %s")
            params.append(json.dumps(data['webhook_headers']) if data['webhook_headers'] else None)

        if 'message_template' in data:
            updates.append("message_template = %s")
            params.append(data['message_template'].strip())

        if 'message_format' in data:
            fmt = data['message_format']
            if fmt in VALID_FORMATS:
                updates.append("message_format = %s")
                params.append(fmt)

        if 'rate_limit_minutes' in data:
            updates.append("rate_limit_minutes = %s")
            params.append(int(data['rate_limit_minutes']))

        if not updates:
            return jsonify({'success': False, 'error': 'No fields to update'}), 400

        params.append(rule_id)
        query = f"UPDATE notification_rules SET {', '.join(updates)} WHERE id = %s"

        try:
            cursor.execute(query, params)
            conn.commit()

            # Invalidate cache after successful update
            invalidate_notification_rules_cache()

        except Exception as e:
            conn.rollback()
            if 'Duplicate entry' in str(e):
                return jsonify({'success': False, 'error': 'Rule name already exists'}), 400
            raise e

        return jsonify({
            'success': True,
            'message': 'Notification rule updated successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/<int:rule_id>/toggle', methods=['POST'])
def toggle_notification_rule(rule_id):
    """Toggle notification rule enabled status"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current status
        cursor.execute("SELECT is_enabled FROM notification_rules WHERE id = %s", (rule_id,))
        rule = cursor.fetchone()

        if not rule:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        new_status = not rule['is_enabled']

        cursor.execute("""
            UPDATE notification_rules SET is_enabled = %s WHERE id = %s
        """, (new_status, rule_id))

        conn.commit()

        # Invalidate cache after successful toggle
        invalidate_notification_rules_cache()

        return jsonify({
            'success': True,
            'message': f"Rule {'enabled' if new_status else 'disabled'} successfully",
            'data': {'is_enabled': new_status}
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/<int:rule_id>', methods=['DELETE'])
def delete_notification_rule(rule_id):
    """Delete a notification rule"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM notification_rules WHERE id = %s", (rule_id,))

        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        conn.commit()

        # Invalidate cache after successful deletion
        invalidate_notification_rules_cache()

        return jsonify({
            'success': True,
            'message': 'Notification rule deleted successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@notification_rules_routes.route('/<int:rule_id>/test', methods=['POST'])
def test_notification_rule(rule_id):
    """Test a notification rule by sending a test notification"""
    import uuid
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT * FROM notification_rules WHERE id = %s
        """, (rule_id,))

        rule = cursor.fetchone()

        if not rule:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404

        channels = rule['channels']
        if isinstance(channels, str):
            channels = json.loads(channels)

        results = []
        delivery_status = {}

        # Test each channel
        for channel in channels:
            if channel == 'telegram':
                result = test_telegram_channel(rule)
                results.append({'channel': 'telegram', **result})
                delivery_status['telegram'] = 'sent' if result.get('success') else 'failed'

            elif channel == 'email':
                result = test_email_channel(rule)
                results.append({'channel': 'email', **result})
                delivery_status['email'] = 'sent' if result.get('success') else 'failed'

            elif channel == 'webhook':
                result = test_webhook_channel(rule)
                results.append({'channel': 'webhook', **result})
                delivery_status['webhook'] = 'sent' if result.get('success') else 'failed'

        # Record test notification in database
        success_count = sum(1 for r in results if r.get('success'))
        overall_status = 'sent' if success_count == len(results) else ('failed' if success_count == 0 else 'partial')

        cursor.execute("""
            INSERT INTO notifications (
                notification_uuid, notification_rule_id, trigger_type,
                channels, message_title, message_body, message_format,
                priority, status, delivery_status, sent_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            str(uuid.uuid4()), rule_id, rule['trigger_on'],
            json.dumps(channels),
            f"🧪 Test: {rule['rule_name']}",
            f"Test notification for rule: {rule['rule_name']}",
            'text', 'normal', overall_status, json.dumps(delivery_status)
        ))
        conn.commit()

        return jsonify({
            'success': True,
            'message': 'Test notifications sent',
            'data': {'results': results}
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def test_telegram_channel(rule):
    """Test telegram notification"""
    import requests

    chat_id = rule.get('telegram_chat_id')
    bot_token = rule.get('telegram_bot_token')

    # If no token in rule, get from integration_config table
    if not bot_token or not chat_id:
        conn = None
        cursor = None
        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            # Get bot_token from integration_config
            if not bot_token:
                cursor.execute("""
                    SELECT config_value FROM integration_config
                    WHERE integration_id = 'telegram' AND config_key = 'bot_token'
                """)
                row = cursor.fetchone()
                if row and row['config_value']:
                    bot_token = row['config_value']

            # Get chat_id from integration_config
            if not chat_id:
                cursor.execute("""
                    SELECT config_value FROM integration_config
                    WHERE integration_id = 'telegram' AND config_key = 'chat_id'
                """)
                row = cursor.fetchone()
                if row and row['config_value']:
                    chat_id = row['config_value']

        except Exception as e:
            return {'success': False, 'error': f'Database error: {str(e)}'}
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    if not bot_token or not chat_id:
        return {'success': False, 'error': 'Telegram not configured - missing bot_token or chat_id'}

    try:
        test_message = f"🔔 <b>Test Notification</b>\n\nRule: {rule['rule_name']}\nTrigger: {rule['trigger_on']}\n\n<i>This is a test message from SSH Guardian</i>"

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        response = requests.post(url, json={
            'chat_id': chat_id,
            'text': test_message,
            'parse_mode': 'HTML'
        }, timeout=10)

        if response.status_code == 200:
            return {'success': True, 'message': 'Telegram test sent'}
        else:
            return {'success': False, 'error': f'Telegram API error: {response.text}'}

    except Exception as e:
        return {'success': False, 'error': str(e)}


def test_email_channel(rule):
    """Test email notification"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    recipients = rule.get('email_recipients')
    if isinstance(recipients, str):
        recipients = json.loads(recipients)

    if not recipients:
        return {'success': False, 'error': 'No email recipients configured'}

    # Get SMTP config from integration_config
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        smtp_config = {}
        cursor.execute("""
            SELECT config_key, config_value FROM integration_config
            WHERE integration_id = 'smtp'
        """)
        for row in cursor.fetchall():
            smtp_config[row['config_key']] = row['config_value']

        if not smtp_config.get('host') or not smtp_config.get('user'):
            return {'success': False, 'error': 'SMTP not configured'}

        # Send test email
        msg = MIMEMultipart()
        msg['From'] = f"{smtp_config.get('from_name', 'SSH Guardian')} <{smtp_config.get('from_email', smtp_config['user'])}>"
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = f"Test Notification: {rule['rule_name']}"

        body = f"""
SSH Guardian - Test Notification

Rule: {rule['rule_name']}
Trigger: {rule['trigger_on']}

This is a test message from SSH Guardian notification system.
        """
        msg.attach(MIMEText(body, 'plain'))

        # Connect and send
        port = int(smtp_config.get('port', 587))
        use_tls = smtp_config.get('use_tls', 'true').lower() == 'true'

        if port == 465:
            server = smtplib.SMTP_SSL(smtp_config['host'], port, timeout=30)
        else:
            server = smtplib.SMTP(smtp_config['host'], port, timeout=30)
            if use_tls:
                server.starttls()

        if smtp_config.get('user') and smtp_config.get('password'):
            server.login(smtp_config['user'], smtp_config['password'])

        server.sendmail(smtp_config.get('from_email', smtp_config['user']), recipients, msg.as_string())
        server.quit()

        return {'success': True, 'message': f'Email sent to: {", ".join(recipients)}'}

    except smtplib.SMTPAuthenticationError:
        return {'success': False, 'error': 'SMTP authentication failed'}
    except smtplib.SMTPConnectError:
        return {'success': False, 'error': 'Could not connect to SMTP server'}
    except Exception as e:
        return {'success': False, 'error': f'Email error: {str(e)}'}
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


def test_webhook_channel(rule):
    """Test webhook notification"""
    import requests

    webhook_url = rule.get('webhook_url')
    if not webhook_url:
        return {'success': False, 'error': 'No webhook URL configured'}

    try:
        headers = rule.get('webhook_headers', {})
        if isinstance(headers, str):
            headers = json.loads(headers)

        payload = {
            'test': True,
            'rule_name': rule['rule_name'],
            'trigger_on': rule['trigger_on'],
            'message': 'Test notification from SSH Guardian'
        }

        response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)

        if response.status_code < 400:
            return {'success': True, 'message': f'Webhook test sent (status: {response.status_code})'}
        else:
            return {'success': False, 'error': f'Webhook error: {response.status_code}'}

    except Exception as e:
        return {'success': False, 'error': str(e)}


# Default notification rules templates (using HTML format for Telegram compatibility)
DEFAULT_RULES = [
    # ============ CORE TRIGGERS ============
    {
        'rule_name': 'IP Blocked Notification',
        'trigger_on': 'ip_blocked',
        'channels': ['telegram'],
        'message_template': '''🛡️ <b>IP BLOCKED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>Blocked IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}} ({{city}})
📝 <b>Reason:</b> {{block_reason}}
⏱️ <b>Duration:</b> {{block_duration}}
⏰ <b>Time:</b> {{timestamp}}''',
        'message_format': 'html',
        'rate_limit_minutes': 1,
        'is_enabled': True
    },
    {
        'rule_name': 'Agent Offline Alert',
        'trigger_on': 'agent_offline',
        'channels': ['telegram'],
        'message_template': '''🔴 <b>AGENT OFFLINE</b>

🖥️ <b>Agent:</b> {{agent_name}}
🌐 <b>IP:</b> {{agent_ip}}
⏰ <b>Last Seen:</b> {{last_seen}}
⏱️ <b>Downtime:</b> {{downtime}}

⚠️ Please check server connectivity.''',
        'message_format': 'html',
        'rate_limit_minutes': 15,
        'is_enabled': True
    },
    {
        'rule_name': 'System Error Alert',
        'trigger_on': 'system_error',
        'channels': ['telegram'],
        'message_template': '''❌ <b>SYSTEM ERROR</b>

🖥️ <b>Component:</b> {{component}}
📝 <b>Error:</b> {{error_message}}
🔢 <b>Code:</b> {{error_code}}
⏰ <b>Time:</b> {{timestamp}}

🚨 Immediate attention required.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': False
    },
    {
        'rule_name': 'Successful Login Monitor',
        'trigger_on': 'successful_login',
        'channels': ['telegram'],
        'message_template': '''✅ <b>SSH LOGIN</b>

🖥️ <b>Server:</b> {{agent_name}}
👤 <b>User:</b> {{username}}
🌐 <b>From IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}} ({{city}})
⏰ <b>Time:</b> {{timestamp}}''',
        'message_format': 'html',
        'rate_limit_minutes': 0,
        'is_enabled': False
    },

    # ============ ATTACK TRIGGERS ============
    {
        'rule_name': 'Brute Force Attack',
        'trigger_on': 'brute_force_detected',
        'channels': ['telegram'],
        'message_template': '''🔨 <b>BRUTE FORCE ATTACK</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>Attacker IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}} ({{city}})
🔢 <b>Failed Attempts:</b> {{attempt_count}}
👤 <b>Target User:</b> {{username}}
⏰ <b>Time:</b> {{timestamp}}

✅ IP automatically blocked.''',
        'message_format': 'html',
        'rate_limit_minutes': 1,
        'is_enabled': True
    },
    {
        'rule_name': 'Distributed Brute Force (Botnet)',
        'trigger_on': 'distributed_brute_force_detected',
        'channels': ['telegram'],
        'message_template': '''🤖 <b>DISTRIBUTED BRUTE FORCE DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>Attacking IPs:</b> {{unique_ips}} unique IPs
👥 <b>Targeted Users:</b> {{unique_usernames}} usernames
📊 <b>Pattern Score:</b> {{pattern_score}}/100
🎯 <b>Threat Level:</b> {{threat_level}}
⏰ <b>Time Window:</b> {{time_window}}

⚠️ <b>Botnet-style attack pattern detected!</b>
Multiple IPs coordinating slow attacks to evade rate limits.

✅ All participating IPs blocked.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    },
    {
        'rule_name': 'Account Takeover Attempt',
        'trigger_on': 'account_takeover_detected',
        'channels': ['telegram'],
        'message_template': '''🎭 <b>ACCOUNT TAKEOVER ATTEMPT</b>

🖥️ <b>Server:</b> {{agent_name}}
👤 <b>Target User:</b> {{username}}
🌐 <b>Attacking IPs:</b> {{unique_ips}} different IPs
🌍 <b>Countries:</b> {{countries}}
⏱️ <b>Time Window:</b> {{time_window}}
🎯 <b>Threat Level:</b> {{threat_level}}

⚠️ <b>Possible credential leak!</b>
Same username being tried from multiple locations.

✅ All attacking IPs blocked.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    },
    {
        'rule_name': 'Credential Stuffing Attack',
        'trigger_on': 'credential_stuffing_detected',
        'channels': ['telegram'],
        'message_template': '''🔑 <b>CREDENTIAL STUFFING DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}} ({{city}})
👥 <b>Usernames Tried:</b> {{username_count}}
⏱️ <b>Time Window:</b> {{time_window}}

⚠️ <b>Bulk credential testing detected!</b>
Attacker using list of leaked credentials.

✅ IP blocked.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    },
    {
        'rule_name': 'Off-Hours Login Anomaly',
        'trigger_on': 'off_hours_anomaly_detected',
        'channels': ['telegram'],
        'message_template': '''🌙 <b>OFF-HOURS ANOMALY</b>

🖥️ <b>Server:</b> {{agent_name}}
👤 <b>User:</b> {{username}}
🌐 <b>IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}} ({{city}})
⏰ <b>Login Time:</b> {{timestamp}}
📊 <b>Anomaly Score:</b> {{anomaly_score}}/100
🕐 <b>Work Hours:</b> {{work_hours}}

⚠️ <b>Login attempt outside business hours!</b>
User typically logs in during {{normal_hours}}.

🔍 Manual verification recommended.''',
        'message_format': 'html',
        'rate_limit_minutes': 10,
        'is_enabled': True
    },
    {
        'rule_name': 'Velocity/DDoS Attack',
        'trigger_on': 'velocity_attack_detected',
        'channels': ['telegram'],
        'message_template': '''⚡ <b>VELOCITY ATTACK DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}}
🔢 <b>Requests:</b> {{request_count}} in {{time_window}}s
📊 <b>Rate:</b> {{rate_per_second}}/sec

⚠️ <b>Rapid-fire attack detected!</b>
Automated tool or DDoS attempt.

✅ IP blocked.''',
        'message_format': 'html',
        'rate_limit_minutes': 1,
        'is_enabled': True
    },

    # ============ ML/API TRIGGERS ============
    {
        'rule_name': 'ML Threat Detection',
        'trigger_on': 'ml_threat_detected',
        'channels': ['telegram'],
        'message_template': '''🧠 <b>ML THREAT DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}} ({{city}})
📊 <b>Risk Score:</b> {{risk_score}}/100
🎯 <b>Confidence:</b> {{confidence}}%
🏷️ <b>Indicators:</b> {{risk_factors}}
⏰ <b>Time:</b> {{timestamp}}

⚠️ <b>Machine Learning model flagged suspicious behavior.</b>

✅ IP blocked based on ML prediction.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    },
    {
        'rule_name': 'High Risk IP (API Reputation)',
        'trigger_on': 'high_risk_detected',
        'channels': ['telegram'],
        'message_template': '''⚠️ <b>HIGH RISK IP DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
📍 <b>Location:</b> {{country}} ({{city}})
📊 <b>AbuseIPDB Score:</b> {{abuse_score}}/100
🦠 <b>VirusTotal:</b> {{vt_malicious}}/{{vt_total}} engines
🏷️ <b>Categories:</b> {{threat_categories}}
⏰ <b>Time:</b> {{timestamp}}

⚠️ <b>IP has poor reputation in threat intelligence databases.</b>

✅ IP blocked based on API reputation.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    },
    {
        'rule_name': 'Behavioral Anomaly',
        'trigger_on': 'anomaly_detected',
        'channels': ['telegram'],
        'message_template': '''🔍 <b>BEHAVIORAL ANOMALY</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
📊 <b>Anomaly Type:</b> {{anomaly_type}}
📝 <b>Details:</b> {{anomaly_details}}
⏰ <b>Time:</b> {{timestamp}}

⚠️ Unusual activity pattern detected.''',
        'message_format': 'html',
        'rate_limit_minutes': 10,
        'is_enabled': True
    },

    # ============ GEO/NETWORK TRIGGERS ============
    {
        'rule_name': 'Impossible Travel Alert',
        'trigger_on': 'geo_anomaly_detected',
        'channels': ['telegram'],
        'message_template': '''🌍 <b>IMPOSSIBLE TRAVEL DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
👤 <b>User:</b> {{username}}
📍 <b>Previous:</b> {{prev_location}} at {{prev_time}}
📍 <b>Current:</b> {{curr_location}} at {{curr_time}}
📏 <b>Distance:</b> {{distance_km}} km
⏱️ <b>Time Diff:</b> {{time_diff}}

⚠️ <b>Physically impossible travel detected!</b>
User cannot be in both locations this quickly.

🔍 Account may be compromised.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    },
    {
        'rule_name': 'Tor Exit Node Detected',
        'trigger_on': 'tor_detected',
        'channels': ['telegram'],
        'message_template': '''🧅 <b>TOR EXIT NODE DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
👤 <b>User Attempt:</b> {{username}}
📊 <b>Event:</b> {{event_type}}
⏰ <b>Time:</b> {{timestamp}}

⚠️ <b>Login attempt from Tor anonymization network.</b>
Often used to hide malicious activity.

✅ IP blocked per policy.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    },
    {
        'rule_name': 'Proxy/VPN Detected',
        'trigger_on': 'proxy_detected',
        'channels': ['telegram'],
        'message_template': '''🔒 <b>PROXY/VPN DETECTED</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
📍 <b>Apparent Location:</b> {{country}}
🏢 <b>Provider:</b> {{provider}}
📊 <b>Proxy Type:</b> {{proxy_type}}
⏰ <b>Time:</b> {{timestamp}}

⚠️ <b>Connection through anonymizing proxy.</b>

🔍 Manual review may be needed.''',
        'message_format': 'html',
        'rate_limit_minutes': 10,
        'is_enabled': False
    },
    {
        'rule_name': 'Geo-Restricted Country',
        'trigger_on': 'geo_blocked',
        'channels': ['telegram'],
        'message_template': '''🚫 <b>GEO-RESTRICTED ACCESS</b>

🖥️ <b>Server:</b> {{agent_name}}
🌐 <b>IP:</b> {{ip_address}}
📍 <b>Country:</b> {{country}} ({{country_code}})
👤 <b>User Attempt:</b> {{username}}
⏰ <b>Time:</b> {{timestamp}}

⚠️ <b>Login from restricted country blocked.</b>

✅ IP blocked per geo-restriction policy.''',
        'message_format': 'html',
        'rate_limit_minutes': 5,
        'is_enabled': True
    }
]


@notification_rules_routes.route('/defaults', methods=['GET'])
def get_default_rules():
    """Get available default notification rule templates"""
    return jsonify({
        'success': True,
        'data': {
            'rules': DEFAULT_RULES,
            'total': len(DEFAULT_RULES)
        }
    })


@notification_rules_routes.route('/seed-defaults', methods=['POST'])
def seed_default_rules():
    """Seed default notification rules into the database"""
    conn = None
    cursor = None
    try:
        data = request.get_json() or {}
        skip_existing = data.get('skip_existing', True)
        rules_to_seed = data.get('rules', None)  # Optional: specific rules to seed

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get existing rule names
        cursor.execute("SELECT rule_name FROM notification_rules")
        existing_names = {row['rule_name'] for row in cursor.fetchall()}

        created = []
        skipped = []

        for rule in DEFAULT_RULES:
            # If specific rules requested, filter
            if rules_to_seed and rule['rule_name'] not in rules_to_seed:
                continue

            if rule['rule_name'] in existing_names:
                if skip_existing:
                    skipped.append(rule['rule_name'])
                    continue
                else:
                    # Delete existing to replace
                    cursor.execute(
                        "DELETE FROM notification_rules WHERE rule_name = %s",
                        (rule['rule_name'],)
                    )

            # Insert the rule
            cursor.execute("""
                INSERT INTO notification_rules (
                    rule_name, is_enabled, trigger_on, channels,
                    message_template, message_format, rate_limit_minutes
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                rule['rule_name'],
                rule['is_enabled'],
                rule['trigger_on'],
                json.dumps(rule['channels']),
                rule['message_template'],
                rule['message_format'],
                rule['rate_limit_minutes']
            ))

            created.append(rule['rule_name'])

        conn.commit()

        # Invalidate cache after seeding rules
        if created:
            invalidate_notification_rules_cache()

        return jsonify({
            'success': True,
            'message': f'Seeded {len(created)} default rules',
            'data': {
                'created': created,
                'skipped': skipped
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
