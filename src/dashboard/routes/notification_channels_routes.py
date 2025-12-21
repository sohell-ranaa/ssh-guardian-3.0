"""
Notification Channels Routes - API endpoints for notification channel management
Manages Telegram, Email, and Webhook notification channels
Updated to match actual database schema (integrations table)
"""
import sys
import json
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

notification_channels_routes = Blueprint('notification_channels', __name__)

# Channel definitions with icons and metadata
CHANNEL_DEFINITIONS = {
    'telegram': {
        'name': 'Telegram',
        'icon': '📱',
        'category': 'notifications',
        'description': 'Send notifications via Telegram bot',
        'config_fields': [
            {'key': 'bot_token', 'label': 'Bot Token', 'type': 'password', 'required': True, 'description': 'Telegram bot API token from @BotFather'},
            {'key': 'chat_id', 'label': 'Chat ID', 'type': 'text', 'required': True, 'description': 'Target chat or channel ID'}
        ]
    },
    'smtp': {
        'name': 'Email (SMTP)',
        'icon': '📧',
        'category': 'email',
        'description': 'Send notifications via email',
        'config_fields': [
            {'key': 'host', 'label': 'SMTP Host', 'type': 'text', 'required': True, 'description': 'SMTP server address'},
            {'key': 'port', 'label': 'Port', 'type': 'number', 'required': True, 'description': 'SMTP port (587 for TLS, 465 for SSL)'},
            {'key': 'user', 'label': 'Username', 'type': 'text', 'required': True, 'description': 'SMTP username/email'},
            {'key': 'password', 'label': 'Password', 'type': 'password', 'required': True, 'description': 'SMTP password or app password'},
            {'key': 'from_email', 'label': 'From Email', 'type': 'email', 'required': False, 'description': 'Sender email address'},
            {'key': 'from_name', 'label': 'From Name', 'type': 'text', 'required': False, 'description': 'Sender display name'},
            {'key': 'to_email', 'label': 'Default Recipient', 'type': 'email', 'required': False, 'description': 'Default email to receive alerts (can be overridden per rule)'},
            {'key': 'use_tls', 'label': 'Use TLS', 'type': 'boolean', 'required': False, 'description': 'Enable STARTTLS'}
        ]
    },
    'webhook': {
        'name': 'Webhook',
        'icon': '🔗',
        'category': 'notifications',
        'description': 'Send notifications to webhook URL',
        'config_fields': [
            {'key': 'url', 'label': 'Webhook URL', 'type': 'url', 'required': True, 'description': 'Target webhook endpoint'},
            {'key': 'secret', 'label': 'Secret Key', 'type': 'password', 'required': False, 'description': 'HMAC secret for request signing'},
            {'key': 'headers', 'label': 'Custom Headers', 'type': 'json', 'required': False, 'description': 'Additional HTTP headers as JSON'}
        ]
    }
}


def parse_json_field(value, default=None):
    """Safely parse JSON field"""
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


@notification_channels_routes.route('/list', methods=['GET'])
def list_channels():
    """Get all notification channels with their configuration"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all integrations from the table
        cursor.execute("""
            SELECT
                id, integration_type, name, is_enabled, config, credentials,
                last_used_at, last_error, error_count, created_at, updated_at
            FROM integrations
            WHERE integration_type IN ('telegram', 'smtp', 'webhook')
            ORDER BY id
        """)
        db_channels = cursor.fetchall()

        # Build channel list from DB + definitions
        channels = []
        found_types = set()

        for ch in db_channels:
            found_types.add(ch['integration_type'])
            definition = CHANNEL_DEFINITIONS.get(ch['integration_type'], {})

            config = parse_json_field(ch['config'], {})
            credentials = parse_json_field(ch['credentials'], {})

            # Mask sensitive values
            masked_config = {}
            for key, value in {**config, **credentials}.items():
                field_def = next((f for f in definition.get('config_fields', []) if f['key'] == key), None)
                if field_def and field_def.get('type') == 'password' and value:
                    masked_config[key] = '********'
                else:
                    masked_config[key] = value

            channels.append({
                'id': ch['id'],
                'integration_type': ch['integration_type'],
                'name': ch['name'] or definition.get('name', ch['integration_type']),
                'icon': definition.get('icon', '📌'),
                'description': definition.get('description', ''),
                'category': definition.get('category', 'notifications'),
                'is_enabled': bool(ch['is_enabled']),
                'status': 'error' if ch['last_error'] else ('active' if ch['is_enabled'] else 'inactive'),
                'config': masked_config,
                'config_fields': definition.get('config_fields', []),
                'last_used_at': ch['last_used_at'].isoformat() if ch['last_used_at'] else None,
                'last_error': ch['last_error'],
                'error_count': ch['error_count'] or 0,
                'created_at': ch['created_at'].isoformat() if ch['created_at'] else None,
                'updated_at': ch['updated_at'].isoformat() if ch['updated_at'] else None
            })

        # Add missing channel types as "not configured"
        for ch_type, definition in CHANNEL_DEFINITIONS.items():
            if ch_type not in found_types:
                channels.append({
                    'id': None,
                    'integration_type': ch_type,
                    'name': definition['name'],
                    'icon': definition['icon'],
                    'description': definition['description'],
                    'category': definition['category'],
                    'is_enabled': False,
                    'status': 'not_configured',
                    'config': {},
                    'config_fields': definition['config_fields'],
                    'last_used_at': None,
                    'last_error': None,
                    'error_count': 0,
                    'created_at': None,
                    'updated_at': None
                })

        return jsonify({
            'success': True,
            'data': {
                'channels': channels
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


@notification_channels_routes.route('/<channel_type>', methods=['GET'])
def get_channel(channel_type):
    """Get a specific channel with full configuration"""
    conn = None
    cursor = None
    try:
        if channel_type not in CHANNEL_DEFINITIONS:
            return jsonify({
                'success': False,
                'error': f'Unknown channel type: {channel_type}'
            }), 404

        definition = CHANNEL_DEFINITIONS[channel_type]

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                id, integration_type, name, is_enabled, config, credentials,
                last_used_at, last_error, error_count, created_at, updated_at
            FROM integrations
            WHERE integration_type = %s
        """, (channel_type,))
        ch = cursor.fetchone()

        if ch:
            config = parse_json_field(ch['config'], {})
            credentials = parse_json_field(ch['credentials'], {})

            channel = {
                'id': ch['id'],
                'integration_type': ch['integration_type'],
                'name': ch['name'] or definition['name'],
                'icon': definition['icon'],
                'description': definition['description'],
                'category': definition['category'],
                'is_enabled': bool(ch['is_enabled']),
                'status': 'error' if ch['last_error'] else ('active' if ch['is_enabled'] else 'inactive'),
                'config': {**config, **credentials},  # Full values for editing
                'config_fields': definition['config_fields'],
                'last_used_at': ch['last_used_at'].isoformat() if ch['last_used_at'] else None,
                'last_error': ch['last_error'],
                'error_count': ch['error_count'] or 0,
                'created_at': ch['created_at'].isoformat() if ch['created_at'] else None,
                'updated_at': ch['updated_at'].isoformat() if ch['updated_at'] else None
            }
        else:
            # Return unconfigured channel template
            channel = {
                'id': None,
                'integration_type': channel_type,
                'name': definition['name'],
                'icon': definition['icon'],
                'description': definition['description'],
                'category': definition['category'],
                'is_enabled': False,
                'status': 'not_configured',
                'config': {},
                'config_fields': definition['config_fields'],
                'last_used_at': None,
                'last_error': None,
                'error_count': 0,
                'created_at': None,
                'updated_at': None
            }

        return jsonify({
            'success': True,
            'data': channel
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


@notification_channels_routes.route('/<channel_type>/configure', methods=['POST'])
def configure_channel(channel_type):
    """Update channel configuration"""
    conn = None
    cursor = None
    try:
        if channel_type not in CHANNEL_DEFINITIONS:
            return jsonify({
                'success': False,
                'error': f'Unknown channel type: {channel_type}'
            }), 404

        data = request.get_json() or {}
        if not data:
            return jsonify({
                'success': False,
                'error': 'No configuration data provided'
            }), 400

        definition = CHANNEL_DEFINITIONS[channel_type]

        # Separate config and credentials (sensitive fields)
        config = {}
        credentials = {}
        for field in definition['config_fields']:
            key = field['key']
            if key in data:
                value = data[key]
                # Skip unchanged masked values
                if value == '********':
                    continue
                if field.get('type') == 'password':
                    credentials[key] = value
                else:
                    config[key] = value

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if exists
        cursor.execute("SELECT id, config, credentials FROM integrations WHERE integration_type = %s", (channel_type,))
        existing = cursor.fetchone()

        if existing:
            # Merge with existing values (for unchanged masked fields)
            existing_config = parse_json_field(existing['config'], {})
            existing_creds = parse_json_field(existing['credentials'], {})
            existing_config.update(config)
            existing_creds.update(credentials)

            cursor.execute("""
                UPDATE integrations
                SET config = %s, credentials = %s, last_error = NULL, error_count = 0, updated_at = NOW()
                WHERE integration_type = %s
            """, (json.dumps(existing_config), json.dumps(existing_creds), channel_type))
        else:
            # Create new
            cursor.execute("""
                INSERT INTO integrations (integration_type, name, is_enabled, config, credentials)
                VALUES (%s, %s, 0, %s, %s)
            """, (channel_type, definition['name'], json.dumps(config), json.dumps(credentials)))

        conn.commit()

        return jsonify({
            'success': True,
            'message': 'Configuration updated successfully'
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


@notification_channels_routes.route('/<channel_type>/enable', methods=['POST'])
def enable_channel(channel_type):
    """Enable a notification channel"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE integrations
            SET is_enabled = 1, updated_at = NOW()
            WHERE integration_type = %s
        """, (channel_type,))

        if cursor.rowcount == 0:
            return jsonify({
                'success': False,
                'error': 'Channel not found or not configured'
            }), 404

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'{channel_type} enabled successfully'
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


@notification_channels_routes.route('/<channel_type>/disable', methods=['POST'])
def disable_channel(channel_type):
    """Disable a notification channel"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE integrations
            SET is_enabled = 0, updated_at = NOW()
            WHERE integration_type = %s
        """, (channel_type,))

        if cursor.rowcount == 0:
            return jsonify({
                'success': False,
                'error': 'Channel not found'
            }), 404

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'{channel_type} disabled successfully'
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


@notification_channels_routes.route('/<channel_type>/test', methods=['POST'])
def test_channel(channel_type):
    """Test a notification channel"""
    conn = None
    cursor = None
    try:
        data = request.get_json() or {}

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get channel config
        cursor.execute("""
            SELECT config, credentials FROM integrations WHERE integration_type = %s
        """, (channel_type,))
        row = cursor.fetchone()

        if not row:
            return jsonify({
                'success': False,
                'error': 'Channel not configured'
            }), 404

        config = {**parse_json_field(row['config'], {}), **parse_json_field(row['credentials'], {})}

        if channel_type == 'telegram':
            result = test_telegram_channel(config, data)
        elif channel_type == 'smtp':
            result = test_smtp_channel(config, data)
        elif channel_type == 'webhook':
            result = test_webhook_channel(config, data)
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown channel: {channel_type}'
            }), 404

        # Update test result
        success = result.get('success', False)
        message = result.get('message') or result.get('error', '')

        cursor.execute("""
            UPDATE integrations
            SET last_used_at = NOW(),
                last_error = %s,
                error_count = CASE WHEN %s THEN 0 ELSE error_count + 1 END,
                updated_at = NOW()
            WHERE integration_type = %s
        """, (
            None if success else message,
            success,
            channel_type
        ))

        conn.commit()

        return jsonify(result)

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


def test_telegram_channel(config, params):
    """Test Telegram bot connection"""
    import requests
    from datetime import datetime

    token = config.get('bot_token')
    chat_id = config.get('chat_id')

    if not token:
        return {'success': False, 'error': 'Telegram bot token not configured'}

    try:
        # Verify bot
        response = requests.get(f'https://api.telegram.org/bot{token}/getMe', timeout=10)
        data = response.json()

        if not data.get('ok'):
            return {'success': False, 'error': data.get('description', 'Invalid bot token')}

        bot_info = data.get('result', {})
        bot_username = bot_info.get('username', 'unknown')

        # Send test message if chat_id configured
        if chat_id:
            test_message = (
                f"<b>SSH Guardian Test Notification</b>\n\n"
                f"Telegram integration is working correctly!\n"
                f"Bot: @{bot_username}\n"
                f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"<i>This is a test message from SSH Guardian v3.0</i>"
            )

            msg_response = requests.post(
                f'https://api.telegram.org/bot{token}/sendMessage',
                json={
                    'chat_id': chat_id,
                    'text': test_message,
                    'parse_mode': 'HTML'
                },
                timeout=10
            )
            msg_data = msg_response.json()

            if msg_data.get('ok'):
                return {
                    'success': True,
                    'message': f'Test message sent to chat {chat_id} via @{bot_username}'
                }
            else:
                return {
                    'success': False,
                    'error': f"Bot verified but failed to send: {msg_data.get('description', 'Unknown error')}"
                }
        else:
            return {
                'success': True,
                'message': f'Bot @{bot_username} verified (no chat ID configured)'
            }

    except requests.RequestException as e:
        return {'success': False, 'error': f'Connection failed: {str(e)}'}


def test_smtp_channel(config, params):
    """Test SMTP connection"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime

    host = config.get('host')
    port = int(config.get('port') or 587)
    user = config.get('user')
    password = config.get('password')
    from_email = config.get('from_email') or user
    from_name = config.get('from_name') or 'SSH Guardian'
    use_tls = str(config.get('use_tls', 'true')).lower() == 'true'

    if not host or not user:
        return {'success': False, 'error': 'SMTP not configured'}

    test_email = params.get('test_email', '').strip()

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=30)
        else:
            server = smtplib.SMTP(host, port, timeout=30)
            if use_tls and port != 25:
                server.starttls()

        server.login(user, password)

        if test_email:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'SSH Guardian - Test Email'
            msg['From'] = f'{from_name} <{from_email}>'
            msg['To'] = test_email

            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #0078D4;">SSH Guardian Test Email</h2>
                <p>This is a test email from SSH Guardian v3.0</p>
                <p>If you're receiving this email, your SMTP integration is working correctly!</p>
                <hr style="border: 1px solid #EDEBE9; margin: 20px 0;">
                <p style="color: #605E5C; font-size: 12px;">
                    Sent at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                    SMTP Server: {host}:{port}
                </p>
            </body>
            </html>
            """
            msg.attach(MIMEText(html_body, 'html'))
            server.sendmail(from_email, test_email, msg.as_string())
            server.quit()

            return {
                'success': True,
                'message': f'Test email sent to {test_email}'
            }
        else:
            server.quit()
            return {
                'success': True,
                'message': f'SMTP connection to {host}:{port} verified'
            }

    except smtplib.SMTPAuthenticationError:
        return {'success': False, 'error': 'SMTP authentication failed'}
    except smtplib.SMTPConnectError:
        return {'success': False, 'error': f'Failed to connect to {host}:{port}'}
    except Exception as e:
        return {'success': False, 'error': f'SMTP error: {str(e)}'}


def test_webhook_channel(config, params):
    """Test webhook endpoint"""
    import requests
    from datetime import datetime

    url = config.get('url')
    secret = config.get('secret')
    headers = parse_json_field(config.get('headers'), {})

    if not url:
        return {'success': False, 'error': 'Webhook URL not configured'}

    try:
        payload = {
            'type': 'test',
            'message': 'SSH Guardian test notification',
            'timestamp': datetime.now().isoformat()
        }

        response = requests.post(url, json=payload, headers=headers, timeout=10)

        if response.status_code < 400:
            return {
                'success': True,
                'message': f'Webhook test successful (HTTP {response.status_code})'
            }
        else:
            return {
                'success': False,
                'error': f'Webhook returned HTTP {response.status_code}'
            }

    except requests.RequestException as e:
        return {'success': False, 'error': f'Connection failed: {str(e)}'}


@notification_channels_routes.route('/stats', methods=['GET'])
def get_channel_stats():
    """Get notification channel statistics"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get channels summary
        cursor.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN is_enabled = 1 THEN 1 ELSE 0 END) as enabled,
                SUM(CASE WHEN is_enabled = 1 AND last_error IS NULL THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN last_error IS NOT NULL THEN 1 ELSE 0 END) as errors
            FROM integrations
            WHERE integration_type IN ('telegram', 'smtp', 'webhook')
        """)
        stats = cursor.fetchone()

        # Get recent notification counts by channel
        cursor.execute("""
            SELECT
                channel,
                COUNT(*) as count,
                SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM notifications
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY channel
        """)
        by_channel = cursor.fetchall()

        return jsonify({
            'success': True,
            'data': {
                'total_channels': stats['total'] or 0,
                'enabled_channels': stats['enabled'] or 0,
                'active_channels': stats['active'] or 0,
                'error_channels': stats['errors'] or 0,
                'notifications_by_channel': by_channel
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
