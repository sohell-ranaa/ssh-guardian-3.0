"""
Notification Channels Routes - API endpoints for notification channel management
Manages Telegram, Email, and Webhook notification channels
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

notification_channels_routes = Blueprint('notification_channels', __name__)


@notification_channels_routes.route('/list', methods=['GET'])
def list_channels():
    """Get all notification channels with their configuration"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get notification-related integrations
        cursor.execute("""
            SELECT
                i.id, i.integration_id, i.name, i.description, i.icon,
                i.category, i.is_enabled, i.status, i.last_test_at,
                i.last_test_result, i.error_message, i.created_at, i.updated_at
            FROM integrations i
            WHERE i.category IN ('notifications', 'email')
            ORDER BY i.id
        """)
        channels = cursor.fetchall()

        # Get config for each channel
        for channel in channels:
            cursor.execute("""
                SELECT config_key, config_value, value_type, is_sensitive,
                       is_required, display_name, description, display_order
                FROM integration_config
                WHERE integration_id = %s
                ORDER BY display_order
            """, (channel['integration_id'],))

            config_rows = cursor.fetchall()
            config = {}
            for row in config_rows:
                # Mask sensitive values
                value = row['config_value']
                if row['is_sensitive'] and value:
                    value = '********'
                config[row['config_key']] = {
                    'value': value,
                    'type': row['value_type'],
                    'is_sensitive': bool(row['is_sensitive']),
                    'is_required': bool(row['is_required']),
                    'display_name': row['display_name'],
                    'description': row['description']
                }
            channel['config'] = config

            # Format timestamps
            if channel['last_test_at']:
                channel['last_test_at'] = channel['last_test_at'].isoformat()
            if channel['created_at']:
                channel['created_at'] = channel['created_at'].isoformat()
            if channel['updated_at']:
                channel['updated_at'] = channel['updated_at'].isoformat()

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


@notification_channels_routes.route('/<channel_id>', methods=['GET'])
def get_channel(channel_id):
    """Get a specific channel with full configuration"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                i.id, i.integration_id, i.name, i.description, i.icon,
                i.category, i.is_enabled, i.status, i.last_test_at,
                i.last_test_result, i.error_message, i.created_at, i.updated_at
            FROM integrations i
            WHERE i.integration_id = %s
        """, (channel_id,))
        channel = cursor.fetchone()

        if not channel:
            return jsonify({
                'success': False,
                'error': 'Channel not found'
            }), 404

        # Get config (with actual values for editing)
        cursor.execute("""
            SELECT config_key, config_value, value_type, is_sensitive,
                   is_required, display_name, description, display_order
            FROM integration_config
            WHERE integration_id = %s
            ORDER BY display_order
        """, (channel_id,))

        config_rows = cursor.fetchall()
        config = {}
        for row in config_rows:
            config[row['config_key']] = {
                'value': row['config_value'],
                'type': row['value_type'],
                'is_sensitive': bool(row['is_sensitive']),
                'is_required': bool(row['is_required']),
                'display_name': row['display_name'],
                'description': row['description']
            }
        channel['config'] = config

        # Format timestamps
        if channel['last_test_at']:
            channel['last_test_at'] = channel['last_test_at'].isoformat()
        if channel['created_at']:
            channel['created_at'] = channel['created_at'].isoformat()
        if channel['updated_at']:
            channel['updated_at'] = channel['updated_at'].isoformat()

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


@notification_channels_routes.route('/<channel_id>/configure', methods=['POST'])
def configure_channel(channel_id):
    """Update channel configuration"""
    conn = None
    cursor = None
    try:
        data = request.get_json() or {}

        if not data:
            return jsonify({
                'success': False,
                'error': 'No configuration data provided'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Check channel exists
        cursor.execute("SELECT id FROM integrations WHERE integration_id = %s", (channel_id,))
        if not cursor.fetchone():
            return jsonify({
                'success': False,
                'error': 'Channel not found'
            }), 404

        # Update each config value
        for key, value in data.items():
            cursor.execute("""
                UPDATE integration_config
                SET config_value = %s, updated_at = NOW()
                WHERE integration_id = %s AND config_key = %s
            """, (value, channel_id, key))

        # Update integration status
        cursor.execute("""
            UPDATE integrations
            SET status = 'configured', updated_at = NOW()
            WHERE integration_id = %s
        """, (channel_id,))

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


@notification_channels_routes.route('/<channel_id>/enable', methods=['POST'])
def enable_channel(channel_id):
    """Enable a notification channel"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE integrations
            SET is_enabled = 1, status = 'active', updated_at = NOW()
            WHERE integration_id = %s
        """, (channel_id,))

        # Also update enabled config if exists
        cursor.execute("""
            UPDATE integration_config
            SET config_value = 'true'
            WHERE integration_id = %s AND config_key = 'enabled'
        """, (channel_id,))

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'{channel_id} enabled successfully'
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


@notification_channels_routes.route('/<channel_id>/disable', methods=['POST'])
def disable_channel(channel_id):
    """Disable a notification channel"""
    conn = None
    cursor = None
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE integrations
            SET is_enabled = 0, status = 'inactive', updated_at = NOW()
            WHERE integration_id = %s
        """, (channel_id,))

        # Also update enabled config if exists
        cursor.execute("""
            UPDATE integration_config
            SET config_value = 'false'
            WHERE integration_id = %s AND config_key = 'enabled'
        """, (channel_id,))

        conn.commit()

        return jsonify({
            'success': True,
            'message': f'{channel_id} disabled successfully'
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


@notification_channels_routes.route('/<channel_id>/test', methods=['POST'])
def test_channel(channel_id):
    """Test a notification channel"""
    conn = None
    cursor = None
    try:
        data = request.get_json() or {}

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if channel_id == 'telegram':
            result = test_telegram_channel(cursor, data)
        elif channel_id == 'smtp':
            result = test_smtp_channel(cursor, data)
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown channel: {channel_id}'
            }), 404

        # Update test result
        success = result.get('success', False)
        message = result.get('message') or result.get('error', '')

        cursor.execute("""
            UPDATE integrations
            SET last_test_at = NOW(),
                last_test_result = %s,
                status = %s,
                error_message = %s,
                updated_at = NOW()
            WHERE integration_id = %s
        """, (
            message,
            'active' if success else 'error',
            None if success else message,
            channel_id
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


def test_telegram_channel(cursor, params):
    """Test Telegram bot connection"""
    import requests
    from datetime import datetime

    # Get config
    cursor.execute("""
        SELECT config_key, config_value
        FROM integration_config
        WHERE integration_id = 'telegram'
    """)
    config = {row['config_key']: row['config_value'] for row in cursor.fetchall()}

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


def test_smtp_channel(cursor, params):
    """Test SMTP connection"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime

    # Get config
    cursor.execute("""
        SELECT config_key, config_value
        FROM integration_config
        WHERE integration_id = 'smtp'
    """)
    config = {row['config_key']: row['config_value'] for row in cursor.fetchall()}

    host = config.get('host')
    port = int(config.get('port') or 587)
    user = config.get('user')
    password = config.get('password')
    from_email = config.get('from_email') or user
    from_name = config.get('from_name') or 'SSH Guardian'
    use_tls = config.get('use_tls', 'true').lower() == 'true'

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
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as errors
            FROM integrations
            WHERE category IN ('notifications', 'email')
        """)
        stats = cursor.fetchone()

        # Get recent notification counts by channel
        cursor.execute("""
            SELECT
                JSON_UNQUOTE(JSON_EXTRACT(channels, '$[0]')) as channel,
                COUNT(*) as count,
                SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM notifications
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY JSON_UNQUOTE(JSON_EXTRACT(channels, '$[0]'))
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
