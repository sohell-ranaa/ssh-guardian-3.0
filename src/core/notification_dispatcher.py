"""
SSH Guardian v3.0 - Notification Dispatcher
Sends notifications via Telegram, Email, and Webhooks based on rules
"""

import sys
import json
import smtplib
import requests
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


class NotificationDispatcher:
    """
    Dispatches notifications based on rules and detected threats.
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._telegram_config = None
        self._smtp_config = None

    def _log(self, message: str):
        if self.verbose:
            print(message)

    def _get_telegram_config(self) -> Optional[Dict]:
        """Get Telegram configuration from database"""
        if self._telegram_config is not None:
            return self._telegram_config

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Use integrations table with JSON config/credentials columns
            cursor.execute("""
                SELECT config, credentials, is_enabled
                FROM integrations
                WHERE integration_type = 'telegram'
            """)
            row = cursor.fetchone()

            if row and row.get('is_enabled'):
                config = row.get('config') or {}
                credentials = row.get('credentials') or {}

                # Parse JSON if needed
                if isinstance(config, str):
                    import json
                    config = json.loads(config)
                if isinstance(credentials, str):
                    import json
                    credentials = json.loads(credentials)

                # Merge config and credentials
                merged = {**config, **credentials}

                if merged.get('bot_token') and merged.get('chat_id'):
                    self._telegram_config = merged
                    return merged
            return None
        finally:
            cursor.close()
            conn.close()

    def _get_smtp_config(self) -> Optional[Dict]:
        """Get SMTP configuration from database"""
        if self._smtp_config is not None:
            return self._smtp_config

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Use integrations table with JSON config/credentials columns
            cursor.execute("""
                SELECT config, credentials, is_enabled
                FROM integrations
                WHERE integration_type = 'smtp'
            """)
            row = cursor.fetchone()

            if row and row.get('is_enabled'):
                config = row.get('config') or {}
                credentials = row.get('credentials') or {}

                # Parse JSON if needed
                if isinstance(config, str):
                    import json
                    config = json.loads(config)
                if isinstance(credentials, str):
                    import json
                    credentials = json.loads(credentials)

                # Merge config and credentials
                merged = {**config, **credentials}

                if merged.get('host') and merged.get('from_email'):
                    self._smtp_config = merged
                    return merged
            return None
        finally:
            cursor.close()
            conn.close()

    def _get_email_routing_recipients(self, agent_id: str = None, rule_type: str = None) -> List[str]:
        """
        Get email recipients from routing rules based on agent and rule type.

        Args:
            agent_id: Agent ID triggering the notification
            rule_type: Type of rule/trigger (e.g., 'brute_force', 'ml_threshold')

        Returns:
            List of email addresses to send notification to
        """
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT setting_value FROM system_settings
                WHERE setting_key = 'email_routing_rules'
            """)
            row = cursor.fetchone()

            if not row or not row['setting_value']:
                return []

            try:
                rules = json.loads(row['setting_value'])
            except json.JSONDecodeError:
                return []

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

            return list(matched_emails)

        except Exception as e:
            self._log(f"  [EMAIL ROUTING] Error getting routing rules: {e}")
            return []
        finally:
            cursor.close()
            conn.close()

    def _get_geo_from_db(self, ip_address: str) -> Optional[Dict]:
        """Get geo data from database for an IP"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT country_code, country_name, city, region, isp, asn_org,
                       latitude, longitude, is_proxy, is_vpn, is_tor, is_datacenter
                FROM ip_geolocation
                WHERE ip_address_text = %s
                ORDER BY last_seen DESC LIMIT 1
            """, (ip_address,))
            return cursor.fetchone()
        except Exception as e:
            self._log(f"Geo lookup error: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    def _get_threat_from_db(self, ip_address: str) -> Optional[Dict]:
        """Get threat intel data from database for an IP"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT abuseipdb_score, abuseipdb_confidence, abuseipdb_reports,
                       virustotal_positives, virustotal_total,
                       overall_threat_level, threat_confidence
                FROM ip_threat_intelligence
                WHERE ip_address_text = %s
                ORDER BY updated_at DESC LIMIT 1
            """, (ip_address,))
            return cursor.fetchone()
        except Exception as e:
            self._log(f"Threat lookup error: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    def _get_event_data(self, event_id: int) -> Optional[Dict]:
        """Get event data including agent info from database"""
        if not event_id:
            return None

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT ae.id, ae.source_ip_text, ae.target_username, ae.event_type,
                       ae.agent_id, a.display_name as agent_name, a.hostname as agent_hostname
                FROM auth_events ae
                LEFT JOIN agents a ON ae.agent_id = a.id
                WHERE ae.id = %s
            """, (event_id,))
            return cursor.fetchone()
        except Exception as e:
            self._log(f"Event lookup error: {e}")
            return None
        finally:
            cursor.close()
            conn.close()

    def check_rate_limit(self, rule_id: int, cooldown_minutes: int) -> bool:
        """Check if notification is rate-limited (cooldown period)"""
        if cooldown_minutes <= 0:
            return True

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                SELECT COUNT(*) FROM notifications
                WHERE notification_rule_id = %s
                AND created_at > DATE_SUB(NOW(), INTERVAL %s MINUTE)
                AND status = 'sent'
            """, (rule_id, cooldown_minutes))

            count = cursor.fetchone()[0]
            return count == 0  # True if no recent notifications
        finally:
            cursor.close()
            conn.close()

    def get_matching_rules(self, trigger_type: str) -> List[Dict]:
        """Get all enabled rules matching a trigger type (event_type)"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Use event_type column (actual schema) instead of trigger_on
            cursor.execute("""
                SELECT id, rule_name, event_type as trigger_on, channels, conditions,
                       message_template, cooldown_minutes as rate_limit_minutes
                FROM notification_rules
                WHERE event_type = %s AND is_enabled = TRUE
            """, (trigger_type,))

            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()

    def render_template(self, template: str, context: Dict) -> str:
        """Render message template with context variables"""
        message = template
        for key, value in context.items():
            placeholder = '{{' + key + '}}'
            message = message.replace(placeholder, str(value) if value else 'N/A')
        return message

    def send_telegram(self, message: str, config: Dict) -> bool:
        """Send Telegram notification"""
        try:
            bot_token = config.get('bot_token')
            chat_id = config.get('chat_id')

            if not bot_token or not chat_id:
                self._log("Telegram not configured")
                return False

            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }

            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                self._log(f"Telegram notification sent to {chat_id}")
                return True
            else:
                self._log(f"Telegram error: {response.text}")
                return False

        except Exception as e:
            self._log(f"Telegram error: {str(e)}")
            return False

    def send_email(self, subject: str, message: str, config: Dict, recipients: List[str] = None) -> bool:
        """Send email notification

        Args:
            subject: Email subject
            message: Email body (HTML)
            config: SMTP configuration
            recipients: List of recipient emails (from rule), overrides config.to_email
        """
        try:
            host = config.get('host')
            port = int(config.get('port', 587))
            user = config.get('user')
            password = config.get('password')
            from_email = config.get('from_email')
            from_name = config.get('from_name', 'SSH Guardian')
            use_tls = config.get('use_tls', 'true').lower() == 'true'

            # Use recipients from rule, or fall back to config, or from_email
            to_emails = recipients if recipients else []
            if not to_emails:
                default_to = config.get('to_email') or config.get('default_recipient')
                if default_to:
                    to_emails = [default_to]
                elif from_email:
                    to_emails = [from_email]

            if not host or not from_email:
                self._log("  [EMAIL] SMTP not configured (missing host or from_email)")
                return False

            if not to_emails:
                self._log("  [EMAIL] No recipients configured")
                return False

            self._log(f"  [EMAIL] Sending to: {', '.join(to_emails)}")

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{from_name} <{from_email}>"
            msg['To'] = ', '.join(to_emails)

            # Strip HTML tags for plain text version
            import re
            plain_text = re.sub(r'<[^>]+>', '', message)
            plain_text = plain_text.replace('&nbsp;', ' ').replace('&amp;', '&')
            text_part = MIMEText(plain_text, 'plain', 'utf-8')
            msg.attach(text_part)

            # HTML version with proper styling
            html_content = f"""
            <html>
            <head>
                <style>
                    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #0078D4 0%, #005A9E 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                    .content {{ background: #f9f9f9; padding: 20px; border: 1px solid #e0e0e0; border-top: none; border-radius: 0 0 8px 8px; }}
                    .footer {{ margin-top: 20px; font-size: 12px; color: #666; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="content">
                        {message.replace(chr(10), '<br>')}
                    </div>
                    <div class="footer">
                        Sent by SSH Guardian v3.0
                    </div>
                </div>
            </body>
            </html>
            """
            html_part = MIMEText(html_content, 'html', 'utf-8')
            msg.attach(html_part)

            # Connect to SMTP server
            self._log(f"  [EMAIL] Connecting to {host}:{port} (TLS: {use_tls})")

            if port == 465:
                server = smtplib.SMTP_SSL(host, port, timeout=30)
            else:
                server = smtplib.SMTP(host, port, timeout=30)
                if use_tls:
                    server.starttls()

            if user and password:
                self._log(f"  [EMAIL] Authenticating as {user}")
                server.login(user, password)

            server.sendmail(from_email, to_emails, msg.as_string())
            server.quit()

            self._log(f"  [EMAIL] Successfully sent to {', '.join(to_emails)}")
            return True

        except smtplib.SMTPAuthenticationError as e:
            self._log(f"  [EMAIL] Authentication failed: {str(e)}")
            return False
        except smtplib.SMTPConnectError as e:
            self._log(f"  [EMAIL] Connection failed: {str(e)}")
            return False
        except smtplib.SMTPException as e:
            self._log(f"  [EMAIL] SMTP error: {str(e)}")
            return False
        except Exception as e:
            self._log(f"  [EMAIL] Error: {str(e)}")
            return False

    def create_notification_record(self, rule_id: int, trigger_type: str,
                                   event_id: Optional[int], channels: List[str],
                                   message: str, priority: str = 'normal',
                                   ip_address: str = None, context: Dict = None) -> int:
        """Create notification record in database for each channel"""

        conn = get_connection()
        cursor = conn.cursor()

        # Extract title from message (first line or first 100 chars)
        title = message.split('\n')[0][:100] if '\n' in message else message[:100]

        # Determine if this is a security alert based on trigger type
        is_security_alert = trigger_type in ['high_risk_detected', 'brute_force_detected', 'anomaly_detected', 'ip_blocked']

        try:
            # Create one notification record per channel
            # Use the first channel as the main channel for the record
            main_channel = channels[0] if channels else 'telegram'

            cursor.execute("""
                INSERT INTO notifications (
                    notification_rule_id, channel, subject, message,
                    status, ip_address, is_security_alert
                ) VALUES (%s, %s, %s, %s, 'pending', %s, %s)
            """, (
                rule_id, main_channel, title, message,
                ip_address, is_security_alert
            ))
            conn.commit()
            return cursor.lastrowid
        finally:
            cursor.close()
            conn.close()

    def update_notification_status(self, notif_id: int, status: str,
                                   delivery_status: Dict = None):
        """Update notification status"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            # Table doesn't have delivery_status column, just update status
            if status == 'sent':
                cursor.execute("""
                    UPDATE notifications SET status = %s, sent_at = NOW() WHERE id = %s
                """, (status, notif_id))
            else:
                cursor.execute("""
                    UPDATE notifications SET status = %s WHERE id = %s
                """, (status, notif_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def dispatch_notification(self, trigger_type: str, context: Dict,
                             event_id: Optional[int] = None) -> Dict:
        """
        Main dispatch function - checks rules and sends notifications.

        Args:
            trigger_type: Type of trigger (high_risk_detected, anomaly_detected, etc.)
            context: Dictionary with template variables
            event_id: Optional auth_event ID

        Returns:
            Dict with results
        """
        self._log(f"\n Checking notifications for trigger: {trigger_type}")

        results = {
            'trigger_type': trigger_type,
            'rules_matched': 0,
            'notifications_sent': 0,
            'notifications_skipped': 0,
            'errors': []
        }

        # Get matching rules
        rules = self.get_matching_rules(trigger_type)
        results['rules_matched'] = len(rules)

        if not rules:
            self._log(f"  No enabled rules for {trigger_type}")
            return results

        for rule in rules:
            rule_id = rule['id']
            rule_name = rule['rule_name']
            channels = json.loads(rule['channels']) if isinstance(rule['channels'], str) else rule['channels']
            rate_limit = rule.get('rate_limit_minutes', 5)

            # Check rate limit
            if not self.check_rate_limit(rule_id, rate_limit):
                self._log(f"  Rule '{rule_name}' rate-limited (within {rate_limit} min)")
                results['notifications_skipped'] += 1
                continue

            # Render message
            template = rule['message_template']
            message = self.render_template(template, context)

            # Determine priority
            priority = 'high' if trigger_type in ['high_risk_detected', 'brute_force_detected'] else 'normal'

            # Get IP address from context
            ip_address = context.get('ip_address')

            # Create notification record
            notif_id = self.create_notification_record(
                rule_id, trigger_type, event_id, channels, message, priority,
                ip_address=ip_address, context=context
            )

            delivery_status = {}
            success = False

            # Send to each channel
            for channel in channels:
                if channel == 'telegram':
                    config = self._get_telegram_config()
                    if config:
                        sent = self.send_telegram(message, config)
                        delivery_status['telegram'] = 'sent' if sent else 'failed'
                        if sent:
                            success = True

                elif channel == 'email':
                    config = self._get_smtp_config()
                    if config:
                        subject = f"SSH Guardian Alert: {trigger_type.replace('_', ' ').title()}"

                        # Collect recipients from multiple sources
                        all_recipients = set()

                        # 1. Get recipients from email routing rules
                        agent_id = context.get('agent_id') or context.get('agent_name')
                        routing_recipients = self._get_email_routing_recipients(
                            agent_id=agent_id,
                            rule_type=trigger_type
                        )
                        if routing_recipients:
                            self._log(f"  [EMAIL ROUTING] Found {len(routing_recipients)} recipients from routing rules")
                            all_recipients.update(routing_recipients)

                        # 2. Parse email_recipients from rule (JSON array or comma-separated string)
                        raw_recipients = rule.get('email_recipients')
                        if raw_recipients:
                            if isinstance(raw_recipients, str):
                                try:
                                    rule_recipients = json.loads(raw_recipients)
                                except json.JSONDecodeError:
                                    # Treat as comma-separated string
                                    rule_recipients = [e.strip() for e in raw_recipients.split(',') if e.strip()]
                            elif isinstance(raw_recipients, list):
                                rule_recipients = raw_recipients
                            else:
                                rule_recipients = []
                            if rule_recipients:
                                self._log(f"  [EMAIL] Rule-specific recipients: {rule_recipients}")
                                all_recipients.update(rule_recipients)

                        # Convert to list
                        email_recipients = list(all_recipients) if all_recipients else None

                        self._log(f"  [EMAIL] Final recipients: {email_recipients}")
                        sent = self.send_email(subject, message, config, recipients=email_recipients)
                        delivery_status['email'] = 'sent' if sent else 'failed'
                        if sent:
                            success = True

            # Update notification status
            final_status = 'sent' if success else 'failed'
            self.update_notification_status(notif_id, final_status, delivery_status)

            if success:
                results['notifications_sent'] += 1
                self._log(f"  Notification sent for rule '{rule_name}'")
            else:
                results['errors'].append(f"Failed to send for rule '{rule_name}'")

        return results


# Global dispatcher instance
_dispatcher = None


def get_dispatcher(verbose: bool = True) -> NotificationDispatcher:
    """Get or create the global dispatcher instance"""
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = NotificationDispatcher(verbose=verbose)
    return _dispatcher


def notify_high_risk(event_id: int, ip_address: str, risk_score: int,
                     threat_type: str, geo_data: Dict = None,
                     threat_data: Dict = None, verbose: bool = True,
                     agent_name: str = None, username: str = None) -> Dict:
    """
    Send notification for high-risk IP detection.

    Args:
        event_id: auth_events.id
        ip_address: Detected IP
        risk_score: ML risk score (0-100)
        threat_type: ML threat type classification
        geo_data: GeoIP data
        threat_data: Threat intelligence data
        verbose: Print progress
        agent_name: Agent name (if not provided, will be fetched from event)
        username: Target username

    Returns:
        Dispatch result
    """
    dispatcher = get_dispatcher(verbose)

    # Get geo and threat data if not provided
    if not geo_data:
        geo_data = dispatcher._get_geo_from_db(ip_address)
    if not threat_data:
        threat_data = dispatcher._get_threat_from_db(ip_address)

    # Get agent name and username from event if not provided
    if not agent_name or not username:
        event_data = dispatcher._get_event_data(event_id)
        if event_data:
            if not agent_name:
                agent_name = event_data.get('agent_name') or event_data.get('agent_hostname') or 'Unknown Agent'
            if not username:
                username = event_data.get('target_username') or 'unknown'

    # Build context with all available data
    context = {
        'ip_address': ip_address,
        'risk_score': risk_score,
        'threat_type': threat_type or 'unknown',
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': event_id,
        'agent_name': agent_name or 'Unknown Agent',
        'username': username or 'unknown',
        # Geo data
        'country': geo_data.get('country_name') or geo_data.get('country') or 'Unknown' if geo_data else 'Unknown',
        'city': geo_data.get('city') or 'Unknown' if geo_data else 'Unknown',
        'isp': geo_data.get('isp') or geo_data.get('org') or 'Unknown' if geo_data else 'Unknown',
        # Threat intel data
        'abuseipdb_score': threat_data.get('abuseipdb_score') if threat_data and threat_data.get('abuseipdb_score') is not None else 'N/A',
        'virustotal_positives': threat_data.get('virustotal_positives', 0) if threat_data else 0,
        'threat_level': (threat_data.get('overall_threat_level') or 'unknown').upper() if threat_data else 'UNKNOWN',
        'risk_factors': f"ML Risk: {risk_score}, Type: {threat_type}"
    }

    return dispatcher.dispatch_notification('high_risk_detected', context, event_id)


def notify_anomaly(event_id: int, ip_address: str, risk_score: int,
                   threat_type: str, confidence: float,
                   geo_data: Dict = None, username: str = None,
                   anomaly_factors: List[str] = None, anomaly_details: List[str] = None,
                   verbose: bool = True) -> Dict:
    """
    Send notification for anomaly detection (including behavioral anomalies).

    Args:
        event_id: auth_events.id
        ip_address: Detected IP
        risk_score: ML risk score (0-100)
        threat_type: Detected anomaly type (e.g., 'unusual_time', 'new_location')
        confidence: ML confidence (0-1)
        geo_data: GeoIP data
        username: Username associated with the anomaly
        anomaly_factors: List of detected factors ['unusual_time', 'new_location']
        anomaly_details: Human-readable factor details
        verbose: Print progress

    Returns:
        Dispatch result
    """
    dispatcher = get_dispatcher(verbose)

    # Get geo data if not provided
    if not geo_data:
        geo_data = dispatcher._get_geo_from_db(ip_address)

    # Format factor details
    factor_str = ', '.join(anomaly_factors) if anomaly_factors else threat_type or 'behavioral_anomaly'
    details_str = '; '.join(anomaly_details) if anomaly_details else f"Risk Score: {risk_score}/100"

    context = {
        'ip_address': ip_address,
        'username': username or 'unknown',
        'risk_score': risk_score,
        'threat_type': threat_type or 'behavioral_anomaly',
        'anomaly_type': threat_type or 'behavioral_anomaly',
        'anomaly_factors': factor_str,
        'anomaly_details': details_str,
        'confidence': f"{confidence*100:.1f}",
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': event_id,
        'agent_name': 'SSH Guardian',
        'country': geo_data.get('country_name') or geo_data.get('country') or 'Unknown' if geo_data else 'Unknown',
        'city': geo_data.get('city') or 'Unknown' if geo_data else 'Unknown',
    }

    return dispatcher.dispatch_notification('anomaly_detected', context, event_id)


def notify_brute_force(event_id: int, ip_address: str, attempt_count: int,
                       geo_data: Dict = None, verbose: bool = True) -> Dict:
    """
    Send notification for brute force detection.
    """
    dispatcher = get_dispatcher(verbose)

    context = {
        'ip_address': ip_address,
        'attempt_count': attempt_count,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'event_id': event_id,
        'agent_name': 'SSH Guardian',
        'country': geo_data.get('country_name', 'Unknown') if geo_data else 'Unknown',
        'city': geo_data.get('city', 'Unknown') if geo_data else 'Unknown',
    }

    return dispatcher.dispatch_notification('brute_force_detected', context, event_id)


def notify_ip_blocked(ip_address: str, block_reason: str,
                      block_duration: str = 'permanent',
                      geo_data: Dict = None, verbose: bool = True) -> Dict:
    """
    Send notification when IP is blocked.
    """
    dispatcher = get_dispatcher(verbose)

    context = {
        'ip_address': ip_address,
        'block_reason': block_reason,
        'block_duration': block_duration,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'agent_name': 'SSH Guardian',
        'country': geo_data.get('country_name', 'Unknown') if geo_data else 'Unknown',
    }

    return dispatcher.dispatch_notification('ip_blocked', context)
