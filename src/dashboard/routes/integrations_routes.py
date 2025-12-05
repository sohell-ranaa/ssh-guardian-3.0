"""
Integrations Routes - API endpoints for third-party service integrations
Manages configuration for Telegram, AbuseIPDB, VirusTotal, Shodan, SMTP, etc.
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from integrations_config import (
    get_all_integrations,
    get_integration,
    get_integration_config_value,
    update_integration_config,
    set_integration_enabled,
    update_test_result
)

integrations_routes = Blueprint('integrations', __name__)


@integrations_routes.route('/list', methods=['GET'])
def list_integrations():
    """Get all integrations with their status and configuration"""
    try:
        integrations = get_all_integrations()

        return jsonify({
            'success': True,
            'data': {
                'integrations': integrations
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@integrations_routes.route('/<integration_id>', methods=['GET'])
def get_integration_details(integration_id):
    """Get details for a specific integration"""
    try:
        integration = get_integration(integration_id)

        if not integration:
            return jsonify({
                'success': False,
                'error': 'Integration not found'
            }), 404

        return jsonify({
            'success': True,
            'data': integration
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@integrations_routes.route('/<integration_id>/configure', methods=['POST'])
def configure_integration(integration_id):
    """Update configuration for an integration"""
    try:
        data = request.json

        if not data:
            return jsonify({
                'success': False,
                'error': 'No configuration data provided'
            }), 400

        # Update configuration
        update_integration_config(integration_id, data)

        # Get updated integration
        integration = get_integration(integration_id)

        return jsonify({
            'success': True,
            'message': 'Configuration updated successfully',
            'data': integration
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@integrations_routes.route('/<integration_id>/enable', methods=['POST'])
def enable_integration(integration_id):
    """Enable an integration"""
    try:
        set_integration_enabled(integration_id, True)

        return jsonify({
            'success': True,
            'message': f'{integration_id} enabled successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@integrations_routes.route('/<integration_id>/disable', methods=['POST'])
def disable_integration(integration_id):
    """Disable an integration"""
    try:
        set_integration_enabled(integration_id, False)

        return jsonify({
            'success': True,
            'message': f'{integration_id} disabled successfully'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@integrations_routes.route('/<integration_id>/test', methods=['POST'])
def test_integration(integration_id):
    """Test an integration connection"""
    try:
        # Get optional test parameters from request
        test_params = request.json or {}

        if integration_id == 'telegram':
            result = test_telegram(test_params)
        elif integration_id == 'abuseipdb':
            result = test_abuseipdb(test_params)
        elif integration_id == 'virustotal':
            result = test_virustotal(test_params)
        elif integration_id == 'shodan':
            result = test_shodan(test_params)
        elif integration_id == 'smtp':
            result = test_smtp(test_params)
        elif integration_id == 'ipapi':
            result = test_ipapi(test_params)
        else:
            return jsonify({
                'success': False,
                'error': f'Unknown integration: {integration_id}'
            }), 404

        # Update test result in database
        response_data = result.get_json()
        update_test_result(
            integration_id,
            response_data.get('success', False),
            response_data.get('message') or response_data.get('error')
        )

        return result

    except Exception as e:
        update_test_result(integration_id, False, str(e))
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def test_telegram(params=None):
    """Test Telegram bot connection and send test message"""
    import requests
    from datetime import datetime

    token = get_integration_config_value('telegram', 'bot_token')
    chat_id = get_integration_config_value('telegram', 'chat_id')

    if not token:
        return jsonify({'success': False, 'error': 'Telegram bot token not configured'})

    try:
        # First verify the bot
        response = requests.get(f'https://api.telegram.org/bot{token}/getMe', timeout=10)
        data = response.json()

        if not data.get('ok'):
            return jsonify({'success': False, 'error': data.get('description', 'Invalid bot token')})

        bot_info = data.get('result', {})
        bot_username = bot_info.get('username', 'unknown')

        # If chat_id is configured, send a test message
        if chat_id:
            test_message = (
                f"🔔 *SSH Guardian Test Notification*\n\n"
                f"✅ Telegram integration is working correctly!\n"
                f"🤖 Bot: @{bot_username}\n"
                f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"_This is a test message from SSH Guardian v3.0_"
            )

            msg_response = requests.post(
                f'https://api.telegram.org/bot{token}/sendMessage',
                json={
                    'chat_id': chat_id,
                    'text': test_message,
                    'parse_mode': 'Markdown'
                },
                timeout=10
            )
            msg_data = msg_response.json()

            if msg_data.get('ok'):
                return jsonify({
                    'success': True,
                    'message': f'Test message sent to chat {chat_id} via @{bot_username}',
                    'data': {
                        'bot_username': bot_username,
                        'chat_id': chat_id,
                        'message_sent': True
                    }
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f"Bot verified but failed to send message: {msg_data.get('description', 'Unknown error')}"
                })
        else:
            return jsonify({
                'success': True,
                'message': f'Bot @{bot_username} verified (no chat ID configured to send test message)',
                'data': {
                    'bot_username': bot_username,
                    'message_sent': False
                }
            })

    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Connection failed: {str(e)}'})


def test_abuseipdb(params=None):
    """Test AbuseIPDB API connection"""
    import requests

    api_key = get_integration_config_value('abuseipdb', 'api_key')
    if not api_key:
        return jsonify({'success': False, 'error': 'AbuseIPDB API key not configured'})

    # Use custom IP or default to Google DNS
    test_ip = (params or {}).get('test_ip', '8.8.8.8')

    try:
        headers = {'Key': api_key, 'Accept': 'application/json'}
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params={'ipAddress': test_ip, 'maxAgeInDays': 90},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json().get('data', {})
            return jsonify({
                'success': True,
                'message': f'AbuseIPDB API verified - tested IP: {test_ip}',
                'data': {
                    'test_ip': test_ip,
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'country': data.get('countryCode', 'N/A'),
                    'total_reports': data.get('totalReports', 0)
                }
            })
        elif response.status_code == 401:
            return jsonify({'success': False, 'error': 'Invalid API key'})
        elif response.status_code == 429:
            return jsonify({'success': False, 'error': 'Rate limit exceeded'})
        else:
            return jsonify({'success': False, 'error': f'API returned status {response.status_code}'})
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Connection failed: {str(e)}'})


def test_virustotal(params=None):
    """Test VirusTotal API connection"""
    import requests

    api_key = get_integration_config_value('virustotal', 'api_key')
    if not api_key:
        return jsonify({'success': False, 'error': 'VirusTotal API key not configured'})

    test_ip = (params or {}).get('test_ip', '8.8.8.8')

    try:
        headers = {'x-apikey': api_key}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{test_ip}',
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return jsonify({
                'success': True,
                'message': f'VirusTotal API verified - tested IP: {test_ip}',
                'data': {
                    'test_ip': test_ip,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'country': data.get('country', 'N/A')
                }
            })
        elif response.status_code == 401:
            return jsonify({'success': False, 'error': 'Invalid API key'})
        elif response.status_code == 429:
            return jsonify({'success': False, 'error': 'Rate limit exceeded'})
        else:
            return jsonify({'success': False, 'error': f'API returned status {response.status_code}'})
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Connection failed: {str(e)}'})


def test_shodan(params=None):
    """Test Shodan API connection"""
    import requests

    api_key = get_integration_config_value('shodan', 'api_key')
    if not api_key:
        return jsonify({'success': False, 'error': 'Shodan API key not configured'})

    try:
        # First check API info/credits
        response = requests.get(
            f'https://api.shodan.io/api-info?key={api_key}',
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'success': True,
                'message': 'Shodan API verified',
                'data': {
                    'query_credits': data.get('query_credits', 0),
                    'scan_credits': data.get('scan_credits', 0),
                    'plan': data.get('plan', 'Free')
                }
            })
        elif response.status_code == 401:
            return jsonify({'success': False, 'error': 'Invalid API key'})
        else:
            return jsonify({'success': False, 'error': f'API returned status {response.status_code}'})
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Connection failed: {str(e)}'})


def test_smtp(params=None):
    """Test SMTP connection and optionally send test email"""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime

    host = get_integration_config_value('smtp', 'host')
    port = int(get_integration_config_value('smtp', 'port') or 587)
    user = get_integration_config_value('smtp', 'user')
    password = get_integration_config_value('smtp', 'password')
    from_email = get_integration_config_value('smtp', 'from_email') or user
    from_name = get_integration_config_value('smtp', 'from_name') or 'SSH Guardian'

    if not host or not user:
        return jsonify({'success': False, 'error': 'SMTP not configured'})

    # Get test email recipient from params
    test_email = (params or {}).get('test_email', '').strip()

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=10)
        else:
            server = smtplib.SMTP(host, port, timeout=10)
            server.starttls()

        server.login(user, password)

        # If test email provided, send actual test email
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

            return jsonify({
                'success': True,
                'message': f'Test email sent to {test_email}',
                'data': {
                    'smtp_host': host,
                    'smtp_port': port,
                    'recipient': test_email,
                    'email_sent': True
                }
            })
        else:
            server.quit()
            return jsonify({
                'success': True,
                'message': f'SMTP connection to {host}:{port} verified (no test email sent)',
                'data': {
                    'smtp_host': host,
                    'smtp_port': port,
                    'email_sent': False
                }
            })

    except smtplib.SMTPAuthenticationError:
        return jsonify({'success': False, 'error': 'SMTP authentication failed - check username/password'})
    except smtplib.SMTPConnectError:
        return jsonify({'success': False, 'error': f'Failed to connect to {host}:{port}'})
    except Exception as e:
        return jsonify({'success': False, 'error': f'SMTP error: {str(e)}'})


def test_ipapi(params=None):
    """Test IP-API connection"""
    import requests

    test_ip = (params or {}).get('test_ip', '8.8.8.8')

    try:
        response = requests.get(
            f'http://ip-api.com/json/{test_ip}',
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return jsonify({
                    'success': True,
                    'message': f'IP-API verified - tested IP: {test_ip}',
                    'data': {
                        'test_ip': test_ip,
                        'country': data.get('country'),
                        'city': data.get('city'),
                        'isp': data.get('isp'),
                        'org': data.get('org')
                    }
                })
            else:
                return jsonify({'success': False, 'error': data.get('message', 'Invalid IP or rate limited')})
        return jsonify({'success': False, 'error': 'IP-API returned invalid response'})
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'Connection failed: {str(e)}'})
