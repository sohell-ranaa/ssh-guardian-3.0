"""
SSH Guardian v3.1 - Integrations Configuration Manager
Handles database operations for third-party integrations
Updated for v3.1 schema with JSON config/credentials columns
"""
import sys
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def mask_sensitive_value(value, show_chars=4):
    """Mask sensitive values for display"""
    if not value:
        return ''
    if len(value) <= show_chars * 2:
        return '*' * len(value)
    return value[:show_chars] + '*' * (len(value) - show_chars * 2) + value[-show_chars:]


# Integration metadata (icons and descriptions)
INTEGRATION_METADATA = {
    'telegram': {
        'icon': '📱',
        'description': 'Receive real-time security alerts via Telegram messenger.'
    },
    'abuseipdb': {
        'icon': '🛡️',
        'description': 'Check IP reputation and abuse reports from AbuseIPDB database.'
    },
    'virustotal': {
        'icon': '🔬',
        'description': 'Scan IPs against 70+ security vendors via VirusTotal API.'
    },
    'shodan': {
        'icon': '🔍',
        'description': 'Discover open ports, services, and vulnerabilities on IP addresses.'
    },
    'smtp': {
        'icon': '📧',
        'description': 'Send email notifications and alerts via SMTP server.'
    },
    'ipapi': {
        'icon': '🌍',
        'description': 'Free GeoIP lookup service for IP geolocation data.'
    },
    'freeipapi': {
        'icon': '🌐',
        'description': 'Alternative GeoIP service with proxy/VPN detection.'
    },
    'greynoise': {
        'icon': '🔇',
        'description': 'Identify mass internet scanners vs targeted attacks. Free: 100 lookups/day, no API key required.'
    }
}


def _parse_json(json_value):
    """Parse JSON value from database"""
    if json_value is None:
        return {}
    if isinstance(json_value, dict):
        return json_value
    if isinstance(json_value, str):
        try:
            return json.loads(json_value)
        except json.JSONDecodeError:
            return {}
    return {}


def get_all_integrations():
    """Get all integrations with their configurations (v3.1 schema)"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id, integration_type, name, is_enabled, config, credentials,
                   last_used_at, last_error, error_count, created_at, updated_at
            FROM integrations
            ORDER BY name
        """)
        integrations = cursor.fetchall()

        result = []
        for integration in integrations:
            config = _parse_json(integration.get('config'))
            credentials = _parse_json(integration.get('credentials'))

            # Build config dict with masked sensitive values
            config_display = dict(config)
            for key, value in credentials.items():
                if value:
                    config_display[key] = mask_sensitive_value(str(value))
                    config_display[f"{key}_has_value"] = True
                else:
                    config_display[key] = ''
                    config_display[f"{key}_has_value"] = False

            # Build config_fields for form generation
            config_fields = []

            # Boolean field keys - these should render as checkboxes
            boolean_fields = {'enabled', 'use_community_api', 'use_ssl', 'verify_ssl'}

            # Add config fields (non-sensitive)
            for key, value in config.items():
                field_type = 'boolean' if key in boolean_fields else 'text'
                config_fields.append({
                    'key': key,
                    'value': value if value else '',
                    'type': field_type,
                    'is_sensitive': False,
                    'is_required': False,
                    'display_name': key.replace('_', ' ').title(),
                    'description': '',
                    'has_value': bool(value)
                })

            # Integrations with optional credentials (free tier available)
            optional_creds = {'greynoise', 'ipapi', 'freeipapi'}
            integration_type = integration['integration_type']

            # Add credential fields (sensitive)
            for key, value in credentials.items():
                # Mark as optional for integrations with free tier
                is_required = integration_type not in optional_creds
                description = '(Optional - Free tier available)' if not is_required else ''

                config_fields.append({
                    'key': key,
                    'value': '',  # Never expose sensitive values
                    'type': 'password',
                    'is_sensitive': True,
                    'is_required': is_required,
                    'display_name': key.replace('_', ' ').title(),
                    'description': description,
                    'has_value': bool(value)
                })

            # Determine status based on config
            is_enabled = integration.get('is_enabled', False)

            if integration_type in optional_creds:
                has_credentials = True  # Credentials are optional
            else:
                has_credentials = all(credentials.values()) if credentials else True

            if is_enabled and has_credentials:
                status = 'active'
            elif has_credentials:
                status = 'configured'
            else:
                status = 'inactive'

            # Get metadata
            metadata = INTEGRATION_METADATA.get(integration['integration_type'], {})

            result.append({
                'id': integration['id'],
                'integration_id': integration['integration_type'],  # Backwards compatibility
                'integration_type': integration['integration_type'],
                'name': integration['name'],
                'icon': metadata.get('icon', '🔌'),
                'description': metadata.get('description', ''),
                'is_enabled': bool(is_enabled),
                'status': status,
                'config': config_display,
                'config_fields': config_fields,
                'last_used_at': integration['last_used_at'].isoformat() if integration.get('last_used_at') else None,
                'last_error': integration.get('last_error'),
                'error_count': integration.get('error_count', 0),
                'last_test_at': integration['last_used_at'].isoformat() if integration.get('last_used_at') else None,
                'last_test_result': 'Success' if not integration.get('last_error') else None,
                'error_message': integration.get('last_error')
            })

        return result

    finally:
        cursor.close()
        conn.close()


def get_integration(integration_type):
    """Get a single integration with its configuration (v3.1 schema)"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id, integration_type, name, is_enabled, config, credentials,
                   last_used_at, last_error, error_count, created_at, updated_at
            FROM integrations
            WHERE integration_type = %s
        """, (integration_type,))

        integration = cursor.fetchone()
        if not integration:
            return None

        config = _parse_json(integration.get('config'))
        credentials = _parse_json(integration.get('credentials'))

        # Build config dict with masked sensitive values
        config_display = dict(config)
        for key, value in credentials.items():
            if value:
                config_display[key] = mask_sensitive_value(str(value))
                config_display[f"{key}_has_value"] = True
            else:
                config_display[key] = ''
                config_display[f"{key}_has_value"] = False

        # Build config_fields for form generation
        config_fields = []

        # Boolean field keys - these should render as checkboxes
        boolean_fields = {'enabled', 'use_community_api', 'use_ssl', 'verify_ssl'}

        # Add config fields (non-sensitive)
        for key, value in config.items():
            field_type = 'boolean' if key in boolean_fields else 'text'
            config_fields.append({
                'key': key,
                'value': value if value else '',
                'type': field_type,
                'is_sensitive': False,
                'is_required': False,
                'display_name': key.replace('_', ' ').title(),
                'description': '',
                'has_value': bool(value)
            })

        # Integrations with optional credentials (free tier available)
        optional_creds = {'greynoise', 'ipapi', 'freeipapi'}
        int_type = integration['integration_type']

        # Add credential fields (sensitive)
        for key, value in credentials.items():
            # Mark as optional for integrations with free tier
            is_required = int_type not in optional_creds
            description = '(Optional - Free tier available)' if not is_required else ''

            config_fields.append({
                'key': key,
                'value': '',  # Never expose sensitive values
                'type': 'password',
                'is_sensitive': True,
                'is_required': is_required,
                'display_name': key.replace('_', ' ').title(),
                'description': description,
                'has_value': bool(value)
            })

        # Determine status
        is_enabled = integration.get('is_enabled', False)

        if int_type in optional_creds:
            has_credentials = True  # Credentials are optional
        else:
            has_credentials = all(credentials.values()) if credentials else True

        if is_enabled and has_credentials:
            status = 'active'
        elif has_credentials:
            status = 'configured'
        else:
            status = 'inactive'

        # Get metadata
        metadata = INTEGRATION_METADATA.get(integration['integration_type'], {})

        return {
            'id': integration['id'],
            'integration_id': integration['integration_type'],  # Backwards compatibility
            'integration_type': integration['integration_type'],
            'name': integration['name'],
            'icon': metadata.get('icon', '🔌'),
            'description': metadata.get('description', ''),
            'is_enabled': bool(is_enabled),
            'status': status,
            'config': config_display,
            'config_fields': config_fields,
            'last_used_at': integration['last_used_at'].isoformat() if integration.get('last_used_at') else None,
            'last_error': integration.get('last_error'),
            'error_count': integration.get('error_count', 0),
            'last_test_at': integration['last_used_at'].isoformat() if integration.get('last_used_at') else None,
            'last_test_result': 'Success' if not integration.get('last_error') else None,
            'error_message': integration.get('last_error')
        }

    finally:
        cursor.close()
        conn.close()


def get_integration_config_value(integration_type, config_key):
    """Get a single config value (unmasked) for internal use (v3.1 schema)"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT config, credentials
            FROM integrations
            WHERE integration_type = %s
        """, (integration_type,))

        result = cursor.fetchone()
        if not result:
            return None

        config = _parse_json(result.get('config'))
        credentials = _parse_json(result.get('credentials'))

        # Check config first, then credentials
        if config_key in config:
            return config[config_key]
        if config_key in credentials:
            return credentials[config_key]

        return None

    finally:
        cursor.close()
        conn.close()


def update_integration_config(integration_type, config_updates):
    """
    Update integration configuration (v3.1 schema)
    config_updates: dict of {config_key: config_value}
    Automatically determines if value goes to config or credentials based on sensitivity
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get current config and credentials
        cursor.execute("""
            SELECT config, credentials
            FROM integrations
            WHERE integration_type = %s
        """, (integration_type,))

        result = cursor.fetchone()
        if not result:
            return False

        current_config = _parse_json(result.get('config'))
        current_credentials = _parse_json(result.get('credentials'))

        # Define which keys are sensitive (go to credentials)
        sensitive_keys = {'api_key', 'bot_token', 'password', 'secret', 'token'}

        for key, value in config_updates.items():
            # Skip empty values for sensitive fields (keep existing)
            if (value == '' or value is None) and key in sensitive_keys:
                if current_credentials.get(key):
                    continue  # Keep existing sensitive value

            # Determine if this is a credential or config
            if key in sensitive_keys:
                current_credentials[key] = str(value) if value else ''
            else:
                current_config[key] = str(value) if value else ''

        # Update database
        cursor.execute("""
            UPDATE integrations
            SET config = %s, credentials = %s, updated_at = NOW()
            WHERE integration_type = %s
        """, (json.dumps(current_config), json.dumps(current_credentials), integration_type))

        conn.commit()

        # Update integration status based on config
        update_integration_status(integration_type)

        return True

    except Exception as e:
        conn.rollback()
        raise e

    finally:
        cursor.close()
        conn.close()


def update_integration_status(integration_type):
    """Update integration status based on configuration (v3.1 schema)"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT config, credentials
            FROM integrations
            WHERE integration_type = %s
        """, (integration_type,))

        result = cursor.fetchone()
        if not result:
            return

        config = _parse_json(result.get('config'))
        credentials = _parse_json(result.get('credentials'))

        # Check if enabled in config
        is_enabled = config.get('enabled', 'false').lower() == 'true'

        # Check if all credentials have values
        has_all_credentials = all(credentials.values()) if credentials else True

        cursor.execute("""
            UPDATE integrations
            SET is_enabled = %s, updated_at = NOW()
            WHERE integration_type = %s
        """, (is_enabled and has_all_credentials, integration_type))

        conn.commit()

    finally:
        cursor.close()
        conn.close()


def set_integration_enabled(integration_type, enabled):
    """Enable or disable an integration (v3.1 schema)"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get current config
        cursor.execute("""
            SELECT config
            FROM integrations
            WHERE integration_type = %s
        """, (integration_type,))

        result = cursor.fetchone()
        if not result:
            return False

        config = _parse_json(result.get('config'))
        config['enabled'] = 'true' if enabled else 'false'

        # Update config and is_enabled
        cursor.execute("""
            UPDATE integrations
            SET config = %s, is_enabled = %s, updated_at = NOW()
            WHERE integration_type = %s
        """, (json.dumps(config), enabled, integration_type))

        conn.commit()
        return True

    finally:
        cursor.close()
        conn.close()


def update_test_result(integration_type, success, message):
    """Update the last test result for an integration (v3.1 schema)"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        if success:
            cursor.execute("""
                UPDATE integrations
                SET last_used_at = NOW(), last_error = NULL, error_count = 0, updated_at = NOW()
                WHERE integration_type = %s
            """, (integration_type,))
        else:
            cursor.execute("""
                UPDATE integrations
                SET last_error = %s, error_count = error_count + 1, updated_at = NOW()
                WHERE integration_type = %s
            """, (message, integration_type))

        conn.commit()

    finally:
        cursor.close()
        conn.close()


def update_last_used(integration_type):
    """Update last_used_at timestamp for an integration"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE integrations
            SET last_used_at = NOW(), updated_at = NOW()
            WHERE integration_type = %s
        """, (integration_type,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def sync_env_to_database():
    """
    Sync .env values to database (one-time migration helper)
    This should be called once to populate database from existing .env
    Updated for v3.1 schema with JSON columns
    """
    import os
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / '.env')

    env_mappings = {
        'telegram': {
            'config': {
                'chat_id': 'TELEGRAM_CHAT_ID',
                'enabled': lambda: 'true' if os.getenv('TELEGRAM_BOT_TOKEN') else 'false'
            },
            'credentials': {
                'bot_token': 'TELEGRAM_BOT_TOKEN'
            }
        },
        'abuseipdb': {
            'config': {
                'enabled': 'ABUSEIPDB_ENABLED',
                'rate_limit_day': 'ABUSEIPDB_RATE_LIMIT_PER_DAY',
                'rate_limit_minute': 'ABUSEIPDB_RATE_LIMIT_PER_MINUTE'
            },
            'credentials': {
                'api_key': 'ABUSEIPDB_API_KEY'
            }
        },
        'virustotal': {
            'config': {
                'enabled': 'VIRUSTOTAL_ENABLED',
                'rate_limit_day': 'VIRUSTOTAL_RATE_LIMIT_PER_DAY',
                'rate_limit_minute': 'VIRUSTOTAL_RATE_LIMIT_PER_MINUTE'
            },
            'credentials': {
                'api_key': 'VIRUSTOTAL_API_KEY'
            }
        },
        'shodan': {
            'config': {
                'enabled': 'SHODAN_ENABLED',
                'high_risk_only': 'SHODAN_HIGH_RISK_ONLY',
                'rate_limit_month': 'SHODAN_RATE_LIMIT_PER_MONTH',
                'rate_limit_day': 'SHODAN_RATE_LIMIT_PER_DAY'
            },
            'credentials': {
                'api_key': 'SHODAN_API_KEY'
            }
        },
        'smtp': {
            'config': {
                'host': 'SMTP_HOST',
                'port': 'SMTP_PORT',
                'from_email': 'FROM_EMAIL',
                'from_name': 'FROM_NAME'
            },
            'credentials': {
                'user': 'SMTP_USER',
                'password': 'SMTP_PASSWORD'
            }
        },
        'greynoise': {
            'config': {
                'enabled': 'GREYNOISE_ENABLED',
                'use_community_api': 'GREYNOISE_USE_COMMUNITY_API'
            },
            'credentials': {
                'api_key': 'GREYNOISE_API_KEY'
            }
        }
    }

    conn = get_connection()
    cursor = conn.cursor()

    try:
        for integration_type, mappings in env_mappings.items():
            config = {}
            credentials = {}

            for config_key, env_key in mappings.get('config', {}).items():
                if callable(env_key):
                    config[config_key] = env_key()
                else:
                    env_value = os.getenv(env_key, '')
                    if env_value:
                        config[config_key] = env_value

            for cred_key, env_key in mappings.get('credentials', {}).items():
                env_value = os.getenv(env_key, '')
                if env_value:
                    credentials[cred_key] = env_value

            if config or credentials:
                cursor.execute("""
                    UPDATE integrations
                    SET config = %s, credentials = %s, updated_at = NOW()
                    WHERE integration_type = %s
                """, (json.dumps(config), json.dumps(credentials), integration_type))

        conn.commit()
        print("Environment variables synced to database")

    finally:
        cursor.close()
        conn.close()
