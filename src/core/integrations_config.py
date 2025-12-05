"""
Integrations Configuration Manager
Handles database operations for third-party integrations
"""
import sys
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


def get_all_integrations():
    """Get all integrations with their configurations"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get all integrations
        cursor.execute("""
            SELECT id, integration_id, name, description, icon, category,
                   is_enabled, status, last_test_at, last_test_result, error_message
            FROM integrations
            ORDER BY category, name
        """)
        integrations = cursor.fetchall()

        # Get configurations for each integration
        for integration in integrations:
            cursor.execute("""
                SELECT config_key, config_value, value_type, is_sensitive,
                       is_required, display_name, description, display_order
                FROM integration_config
                WHERE integration_id = %s
                ORDER BY display_order
            """, (integration['integration_id'],))

            configs = cursor.fetchall()
            integration['config'] = {}
            integration['config_fields'] = []

            for config in configs:
                # Mask sensitive values for display
                value = config['config_value']
                if config['is_sensitive'] and value:
                    integration['config'][config['config_key']] = mask_sensitive_value(value)
                    integration['config'][f"{config['config_key']}_has_value"] = bool(value)
                else:
                    integration['config'][config['config_key']] = value

                # Add field metadata for form generation
                integration['config_fields'].append({
                    'key': config['config_key'],
                    'value': value if not config['is_sensitive'] else '',
                    'type': config['value_type'],
                    'is_sensitive': config['is_sensitive'],
                    'is_required': config['is_required'],
                    'display_name': config['display_name'],
                    'description': config['description'],
                    'has_value': bool(value)
                })

            # Format timestamps
            if integration['last_test_at']:
                integration['last_test_at'] = integration['last_test_at'].isoformat()

        return integrations

    finally:
        cursor.close()
        conn.close()


def get_integration(integration_id):
    """Get a single integration with its configuration"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT id, integration_id, name, description, icon, category,
                   is_enabled, status, last_test_at, last_test_result, error_message
            FROM integrations
            WHERE integration_id = %s
        """, (integration_id,))

        integration = cursor.fetchone()
        if not integration:
            return None

        # Get configurations
        cursor.execute("""
            SELECT config_key, config_value, value_type, is_sensitive,
                   is_required, display_name, description, display_order
            FROM integration_config
            WHERE integration_id = %s
            ORDER BY display_order
        """, (integration_id,))

        configs = cursor.fetchall()
        integration['config'] = {}
        integration['config_fields'] = []

        for config in configs:
            value = config['config_value']
            if config['is_sensitive'] and value:
                integration['config'][config['config_key']] = mask_sensitive_value(value)
                integration['config'][f"{config['config_key']}_has_value"] = bool(value)
            else:
                integration['config'][config['config_key']] = value

            integration['config_fields'].append({
                'key': config['config_key'],
                'value': value if not config['is_sensitive'] else '',
                'type': config['value_type'],
                'is_sensitive': config['is_sensitive'],
                'is_required': config['is_required'],
                'display_name': config['display_name'],
                'description': config['description'],
                'has_value': bool(value)
            })

        if integration['last_test_at']:
            integration['last_test_at'] = integration['last_test_at'].isoformat()

        return integration

    finally:
        cursor.close()
        conn.close()


def get_integration_config_value(integration_id, config_key):
    """Get a single config value (unmasked) for internal use"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("""
            SELECT config_value
            FROM integration_config
            WHERE integration_id = %s AND config_key = %s
        """, (integration_id, config_key))

        result = cursor.fetchone()
        return result['config_value'] if result else None

    finally:
        cursor.close()
        conn.close()


def update_integration_config(integration_id, config_updates):
    """
    Update integration configuration
    config_updates: dict of {config_key: config_value}
    """
    conn = get_connection()
    cursor = conn.cursor()

    try:
        for config_key, config_value in config_updates.items():
            # Skip empty values for sensitive fields (keep existing)
            if config_value == '' or config_value is None:
                cursor.execute("""
                    SELECT is_sensitive, config_value
                    FROM integration_config
                    WHERE integration_id = %s AND config_key = %s
                """, (integration_id, config_key))
                result = cursor.fetchone()
                if result and result[0] and result[1]:  # is_sensitive and has value
                    continue  # Keep existing sensitive value

            cursor.execute("""
                UPDATE integration_config
                SET config_value = %s, updated_at = NOW()
                WHERE integration_id = %s AND config_key = %s
            """, (str(config_value) if config_value is not None else '', integration_id, config_key))

        conn.commit()

        # Update integration status based on config
        update_integration_status(integration_id)

        return True

    except Exception as e:
        conn.rollback()
        raise e

    finally:
        cursor.close()
        conn.close()


def update_integration_status(integration_id):
    """Update integration status based on configuration"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if all required fields have values
        cursor.execute("""
            SELECT config_key, config_value, is_required
            FROM integration_config
            WHERE integration_id = %s
        """, (integration_id,))

        configs = cursor.fetchall()

        all_required_filled = True
        is_enabled = False

        for config in configs:
            if config['is_required'] and not config['config_value']:
                all_required_filled = False
            if config['config_key'] == 'enabled' and config['config_value'] == 'true':
                is_enabled = True

        # Determine status
        if all_required_filled and is_enabled:
            status = 'active'
        elif all_required_filled:
            status = 'configured'
        else:
            status = 'inactive'

        cursor.execute("""
            UPDATE integrations
            SET status = %s, is_enabled = %s, updated_at = NOW()
            WHERE integration_id = %s
        """, (status, is_enabled, integration_id))

        conn.commit()

    finally:
        cursor.close()
        conn.close()


def set_integration_enabled(integration_id, enabled):
    """Enable or disable an integration"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Update enabled config
        cursor.execute("""
            UPDATE integration_config
            SET config_value = %s, updated_at = NOW()
            WHERE integration_id = %s AND config_key = 'enabled'
        """, ('true' if enabled else 'false', integration_id))

        conn.commit()

        # Update status
        update_integration_status(integration_id)

        return True

    finally:
        cursor.close()
        conn.close()


def update_test_result(integration_id, success, message):
    """Update the last test result for an integration"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        if success:
            cursor.execute("""
                UPDATE integrations
                SET last_test_at = NOW(), last_test_result = %s, error_message = NULL, updated_at = NOW()
                WHERE integration_id = %s
            """, (message, integration_id))
        else:
            cursor.execute("""
                UPDATE integrations
                SET last_test_result = NULL, error_message = %s, updated_at = NOW()
                WHERE integration_id = %s
            """, (message, integration_id))

        conn.commit()

    finally:
        cursor.close()
        conn.close()


def sync_env_to_database():
    """
    Sync .env values to database (one-time migration helper)
    This should be called once to populate database from existing .env
    """
    import os
    from dotenv import load_dotenv

    load_dotenv(PROJECT_ROOT / '.env')

    env_mappings = {
        'telegram': {
            'bot_token': 'TELEGRAM_BOT_TOKEN',
            'chat_id': 'TELEGRAM_CHAT_ID',
        },
        'abuseipdb': {
            'api_key': 'ABUSEIPDB_API_KEY',
            'enabled': 'ABUSEIPDB_ENABLED',
            'rate_limit_day': 'ABUSEIPDB_RATE_LIMIT_PER_DAY',
            'rate_limit_minute': 'ABUSEIPDB_RATE_LIMIT_PER_MINUTE',
        },
        'virustotal': {
            'api_key': 'VIRUSTOTAL_API_KEY',
            'enabled': 'VIRUSTOTAL_ENABLED',
            'rate_limit_day': 'VIRUSTOTAL_RATE_LIMIT_PER_DAY',
            'rate_limit_minute': 'VIRUSTOTAL_RATE_LIMIT_PER_MINUTE',
        },
        'shodan': {
            'api_key': 'SHODAN_API_KEY',
            'enabled': 'SHODAN_ENABLED',
            'high_risk_only': 'SHODAN_HIGH_RISK_ONLY',
            'rate_limit_month': 'SHODAN_RATE_LIMIT_PER_MONTH',
            'rate_limit_day': 'SHODAN_RATE_LIMIT_PER_DAY',
        },
        'smtp': {
            'host': 'SMTP_HOST',
            'port': 'SMTP_PORT',
            'user': 'SMTP_USER',
            'password': 'SMTP_PASSWORD',
            'from_email': 'FROM_EMAIL',
            'from_name': 'FROM_NAME',
        },
    }

    for integration_id, mappings in env_mappings.items():
        config_updates = {}
        for config_key, env_key in mappings.items():
            env_value = os.getenv(env_key, '')
            if env_value:
                config_updates[config_key] = env_value

        if config_updates:
            update_integration_config(integration_id, config_updates)

    print("Environment variables synced to database")
