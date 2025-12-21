#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Live Agent
Collects SSH authentication logs from remote Ubuntu servers and sends them to the central server

Features:
- Real-time log monitoring (/var/log/auth.log)
- Batch submission to central server
- Automatic heartbeat monitoring
- Firewall (iptables) collection and management
- Error handling and retry logic
- Systemd service compatible
"""

import os
import sys
import time
import json
import uuid
import socket
import hashlib
import logging
import argparse
import requests
import platform
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Import UFW manager (primary) or firewall collector (fallback)
try:
    from ufw_manager import UFWManager
    UFW_AVAILABLE = True
except ImportError:
    UFW_AVAILABLE = False

try:
    from firewall_collector import FirewallCollector, FirewallManager
    FIREWALL_AVAILABLE = True
except ImportError:
    FIREWALL_AVAILABLE = False

# ============================================================================
# CONFIGURATION
# ============================================================================

class AgentConfig:
    """Agent configuration"""

    def __init__(self, config_file: Optional[str] = None):
        # Default configuration
        self.server_url = os.getenv("SSH_GUARDIAN_SERVER", "http://localhost:8081")
        self.api_key = os.getenv("SSH_GUARDIAN_API_KEY", "")
        self.agent_id = os.getenv("SSH_GUARDIAN_AGENT_ID", self._generate_agent_id())

        # Agent settings
        self.hostname = socket.gethostname()
        self.check_interval = int(os.getenv("SSH_GUARDIAN_CHECK_INTERVAL", "30"))  # seconds
        self.batch_size = int(os.getenv("SSH_GUARDIAN_BATCH_SIZE", "100"))  # logs per batch
        self.heartbeat_interval = int(os.getenv("SSH_GUARDIAN_HEARTBEAT_INTERVAL", "60"))  # seconds
        self.firewall_sync_interval = int(os.getenv("SSH_GUARDIAN_FIREWALL_SYNC_INTERVAL", "300"))  # 5 minutes

        # Log file paths
        self.auth_log_path = "/var/log/auth.log"
        self.state_file = "/var/lib/ssh-guardian/agent-state.json"
        self.log_file = "/var/log/ssh-guardian-agent.log"

        # Firewall management
        self.firewall_enabled = os.getenv("SSH_GUARDIAN_FIREWALL_ENABLED", "true").lower() == "true"

        # Fail2ban integration (hybrid mode)
        self.use_fail2ban = os.getenv("SSH_GUARDIAN_USE_FAIL2BAN", "false").lower() == "true"
        self.fail2ban_sync_interval = int(os.getenv("SSH_GUARDIAN_FAIL2BAN_SYNC_INTERVAL", "30"))  # seconds

        # Load from config file if provided
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)

    def _generate_agent_id(self) -> str:
        """Generate unique agent ID based on hostname"""
        hostname = socket.gethostname()
        # Use hostname + MAC address for uniqueness
        mac = uuid.getnode()
        return f"{hostname}-{mac}"

    def load_from_file(self, config_file: str):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                for key, value in config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
        except Exception as e:
            logging.error(f"Failed to load config from {config_file}: {e}")

    def save_to_file(self, config_file: str):
        """Save configuration to JSON file"""
        config = {
            "server_url": self.server_url,
            "api_key": self.api_key,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "check_interval": self.check_interval,
            "batch_size": self.batch_size,
            "heartbeat_interval": self.heartbeat_interval,
            "firewall_sync_interval": self.firewall_sync_interval,
            "firewall_enabled": self.firewall_enabled,
            "use_fail2ban": self.use_fail2ban,
            "fail2ban_sync_interval": self.fail2ban_sync_interval
        }

        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)


# ============================================================================
# AGENT STATE MANAGEMENT
# ============================================================================

class AgentState:
    """Manages agent state (last read position, statistics, etc.)"""

    def __init__(self, state_file: str):
        self.state_file = state_file
        self.last_inode = 0
        self.last_position = 0
        self.last_heartbeat = None
        self.total_logs_sent = 0
        self.total_batches_sent = 0
        self.agent_start_time = datetime.now().isoformat()

        self.load()

    def load(self):
        """Load state from file"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.last_inode = data.get('last_inode', 0)
                    self.last_position = data.get('last_position', 0)
                    self.last_heartbeat = data.get('last_heartbeat')
                    self.total_logs_sent = data.get('total_logs_sent', 0)
                    self.total_batches_sent = data.get('total_batches_sent', 0)
                    self.agent_start_time = data.get('agent_start_time', datetime.now().isoformat())
            except Exception as e:
                logging.error(f"Failed to load state: {e}")

    def save(self):
        """Save state to file"""
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            data = {
                'last_inode': self.last_inode,
                'last_position': self.last_position,
                'last_heartbeat': self.last_heartbeat,
                'total_logs_sent': self.total_logs_sent,
                'total_batches_sent': self.total_batches_sent,
                'agent_start_time': self.agent_start_time
            }
            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.error(f"Failed to save state: {e}")


# ============================================================================
# LOG COLLECTOR
# ============================================================================

class LogCollector:
    """Collects SSH authentication logs from auth.log"""

    def __init__(self, auth_log_path: str, state: AgentState):
        self.auth_log_path = auth_log_path
        self.state = state

    def collect_new_logs(self) -> List[str]:
        """Collect new log lines since last check"""
        if not os.path.exists(self.auth_log_path):
            logging.error(f"Auth log file not found: {self.auth_log_path}")
            return []

        try:
            # Get current file inode (to detect log rotation)
            current_inode = os.stat(self.auth_log_path).st_ino

            # Check for log rotation
            if current_inode != self.state.last_inode:
                logging.info(f"Log rotation detected (inode changed: {self.state.last_inode} -> {current_inode})")
                self.state.last_inode = current_inode
                self.state.last_position = 0

            # Read new lines from file
            with open(self.auth_log_path, 'r') as f:
                # Seek to last position
                f.seek(self.state.last_position)

                # Read new lines
                new_lines = []
                for line in f:
                    line = line.strip()
                    if line and self._is_ssh_related(line):
                        new_lines.append(line)

                # Update position
                self.state.last_position = f.tell()

            return new_lines

        except Exception as e:
            logging.error(f"Error collecting logs: {e}")
            return []

    def _is_ssh_related(self, line: str) -> bool:
        """Check if log line is SSH-related"""
        ssh_keywords = ['sshd', 'ssh', 'Failed password', 'Accepted password',
                       'Accepted publickey', 'Invalid user', 'Connection closed']
        return any(keyword in line for keyword in ssh_keywords)


# ============================================================================
# API CLIENT
# ============================================================================

class GuardianAPIClient:
    """API client for communicating with SSH Guardian central server"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': f'SSH-Guardian-Agent/{self.config.agent_id}',
            'X-API-Key': self.config.api_key,
            'X-Agent-ID': self.config.agent_id
        })

    def register_agent(self) -> bool:
        """Register agent with central server"""
        try:
            system_info = self._get_system_info()

            payload = {
                'agent_id': self.config.agent_id,
                'hostname': self.config.hostname,
                'system_info': system_info,
                'version': '3.0.0',
                'heartbeat_interval_sec': self.config.heartbeat_interval
            }

            url = f"{self.config.server_url}/api/agents/register"
            response = self.session.post(url, json=payload, timeout=30)

            if response.status_code in [200, 201]:
                data = response.json()
                logging.info(f"✅ Agent registered successfully: {data.get('message')}")

                # Update API key with the one returned by server
                if data.get('api_key'):
                    old_key = self.config.api_key
                    self.config.api_key = data['api_key']
                    self.session.headers['X-API-Key'] = self.config.api_key

                    # Save updated config to file
                    config_file = os.getenv('SSH_GUARDIAN_CONFIG', '/etc/ssh-guardian/agent.json')
                    try:
                        self.config.save_to_file(config_file)
                        if old_key != self.config.api_key:
                            logging.info(f"✅ API key updated and saved to {config_file}")
                    except Exception as e:
                        logging.warning(f"Could not save updated config: {e}")

                return True
            else:
                logging.error(f"❌ Agent registration failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logging.error(f"❌ Agent registration error: {e}")
            return False

    def send_heartbeat(self, state: AgentState) -> bool:
        """Send heartbeat to central server"""
        try:
            metrics = {
                'cpu_usage_percent': self._get_cpu_usage(),
                'memory_usage_percent': self._get_memory_usage(),
                'disk_usage_percent': self._get_disk_usage(),
                'events_processed_last_minute': 0,  # TODO: Calculate from state
                'uptime_seconds': self._get_uptime_seconds(state)
            }

            payload = {
                'agent_id': self.config.agent_id,
                'metrics': metrics,
                'status': 'online',
                'health_status': 'healthy'
            }

            url = f"{self.config.server_url}/api/agents/heartbeat"
            response = self.session.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                state.last_heartbeat = datetime.now().isoformat()
                return True
            else:
                logging.warning(f"Heartbeat failed: {response.status_code}")
                return False

        except Exception as e:
            logging.error(f"Heartbeat error: {e}")
            return False

    def submit_log_batch(self, log_lines: List[str]) -> bool:
        """Submit batch of log lines to central server"""
        try:
            batch_uuid = str(uuid.uuid4())

            payload = {
                'batch_uuid': batch_uuid,
                'agent_id': self.config.agent_id,
                'hostname': self.config.hostname,
                'log_lines': log_lines,
                'batch_size': len(log_lines),
                'source_filename': self.config.auth_log_path
            }

            url = f"{self.config.server_url}/api/agents/logs"
            response = self.session.post(url, json=payload, timeout=60)

            if response.status_code == 200:
                data = response.json()
                logging.info(f"✅ Batch submitted: {len(log_lines)} logs, {data.get('events_created', 0)} events created")
                return True
            else:
                logging.error(f"❌ Batch submission failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logging.error(f"❌ Batch submission error: {e}")
            return False

    # =========================================================================
    # FIREWALL API METHODS
    # =========================================================================

    def submit_firewall_rules(self, firewall_data: Dict) -> bool:
        """Submit firewall rules to central server"""
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'hostname': self.config.hostname,
                'firewall_data': firewall_data,
                'submitted_at': datetime.now().isoformat()
            }

            url = f"{self.config.server_url}/api/agents/firewall/sync"
            response = self.session.post(url, json=payload, timeout=60)

            if response.status_code == 200:
                data = response.json()
                logging.info(f"🔥 Firewall rules synced: {data.get('rules_count', 0)} rules")
                return True
            else:
                logging.error(f"❌ Firewall sync failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logging.error(f"❌ Firewall sync error: {e}")
            return False

    def get_pending_firewall_commands(self) -> List[Dict]:
        """Get pending firewall commands from central server"""
        try:
            url = f"{self.config.server_url}/api/agents/firewall/commands"
            params = {'agent_id': self.config.agent_id}
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return data.get('commands', [])
            else:
                logging.warning(f"Failed to get firewall commands: {response.status_code}")
                return []

        except Exception as e:
            logging.error(f"Error getting firewall commands: {e}")
            return []

    def report_command_result(self, command_id: str, success: bool, message: str) -> bool:
        """Report the result of a firewall command execution (tries UFW endpoint first)"""
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'command_id': command_id,
                'success': success,
                'message': message,
                'executed_at': datetime.now().isoformat()
            }

            # Try UFW endpoint first (for UFW commands from agent_ufw_commands table)
            url = f"{self.config.server_url}/api/agents/ufw/command-result"
            response = self.session.post(url, json=payload, timeout=30)

            if response.status_code == 200:
                return True

            # Fallback to generic firewall endpoint (for iptables commands)
            url = f"{self.config.server_url}/api/agents/firewall/command-result"
            response = self.session.post(url, json=payload, timeout=30)

            return response.status_code == 200

        except Exception as e:
            logging.error(f"Error reporting command result: {e}")
            return False

    def submit_extended_data(self, extended_data: Dict) -> bool:
        """Submit extended system data (ports, users, suggestions) to central server"""
        try:
            url = f"{self.config.server_url}/api/agents/firewall/sync-extended"
            response = self.session.post(url, json=extended_data, timeout=60)

            if response.status_code == 200:
                data = response.json()
                logging.debug(f"Extended data synced: {data.get('counts', {})}")
                return True
            else:
                logging.error(f"❌ Extended data sync failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logging.error(f"❌ Extended data sync error: {e}")
            return False

    # =========================================================================
    # UFW API METHODS
    # =========================================================================

    def submit_ufw_rules(self, ufw_data: Dict) -> bool:
        """Submit UFW rules to central server"""
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'hostname': self.config.hostname,
                'ufw_data': ufw_data,
                'submitted_at': datetime.now().isoformat()
            }

            url = f"{self.config.server_url}/api/agents/ufw/sync"
            response = self.session.post(url, json=payload, timeout=60)

            if response.status_code == 200:
                data = response.json()
                logging.info(f"🔥 UFW rules synced: {data.get('rules_count', 0)} rules, status: {data.get('ufw_status', 'unknown')}")
                return True
            else:
                logging.error(f"❌ UFW sync failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logging.error(f"❌ UFW sync error: {e}")
            return False

    def get_pending_ufw_commands(self) -> List[Dict]:
        """Get pending UFW commands from central server"""
        try:
            url = f"{self.config.server_url}/api/agents/ufw/commands"
            params = {'agent_id': self.config.agent_id}
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return data.get('commands', [])
            else:
                logging.warning(f"Failed to get UFW commands: {response.status_code}")
                return []

        except Exception as e:
            logging.error(f"Error getting UFW commands: {e}")
            return []

    # =========================================================================
    # FAIL2BAN API METHODS
    # =========================================================================

    def get_pending_fail2ban_unbans(self) -> List[Dict]:
        """Get pending fail2ban unban commands from central server"""
        try:
            url = f"{self.config.server_url}/api/agents/fail2ban/pending-unbans"
            response = self.session.get(url, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return data.get('commands', [])
            else:
                logging.warning(f"Failed to get fail2ban unbans: {response.status_code}")
                return []

        except Exception as e:
            logging.error(f"Error getting fail2ban unbans: {e}")
            return []

    def report_fail2ban_unban_result(self, block_id: int, success: bool, message: str) -> bool:
        """Report the result of a fail2ban unban command execution"""
        try:
            payload = {
                'id': block_id,
                'success': success,
                'message': message
            }

            url = f"{self.config.server_url}/api/agents/fail2ban/unban-result"
            response = self.session.post(url, json=payload, timeout=30)

            return response.status_code == 200

        except Exception as e:
            logging.error(f"Error reporting fail2ban unban result: {e}")
            return False

    def sync_fail2ban_bans(self, bans: List[Dict], hostname: str) -> Dict:
        """
        Sync current fail2ban bans with timestamps to central server.

        Args:
            bans: List of ban dicts with 'ip', 'jail', 'banned_at' keys
            hostname: Agent hostname

        Returns:
            dict with success status and counts
        """
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'hostname': hostname,
                'bans': bans
            }

            url = f"{self.config.server_url}/api/agents/fail2ban/sync"
            response = self.session.post(url, json=payload, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return data
            else:
                logging.warning(f"Failed to sync fail2ban bans: {response.status_code}")
                return {'success': False, 'error': f'HTTP {response.status_code}'}

        except Exception as e:
            logging.error(f"Error syncing fail2ban bans: {e}")
            return {'success': False, 'error': str(e)}

    def _get_system_info(self) -> Dict:
        """Collect system information"""
        return {
            'os': platform.system(),
            'os_version': platform.release(),
            'platform': platform.platform(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'hostname': socket.gethostname(),
            'ip_addresses': self._get_ip_addresses()
        }

    def _get_ip_addresses(self) -> List[str]:
        """Get system IP addresses"""
        try:
            # Get primary IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            primary_ip = s.getsockname()[0]
            s.close()
            return [primary_ip]
        except:
            return []

    def _get_cpu_usage(self) -> float:
        """Get CPU usage percentage"""
        try:
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'Cpu(s)' in line:
                    parts = line.split()
                    idle = float(parts[7].replace('%id,', ''))
                    return round(100 - idle, 2)
        except:
            pass
        return 0.0

    def _get_memory_usage(self) -> float:
        """Get memory usage percentage"""
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                mem_total = int(lines[0].split()[1])
                mem_available = int(lines[2].split()[1])
                mem_used = mem_total - mem_available
                return round((mem_used / mem_total) * 100, 2)
        except:
            pass
        return 0.0

    def _get_disk_usage(self) -> float:
        """Get disk usage percentage for root partition"""
        try:
            result = subprocess.run(['df', '-h', '/'], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                usage = parts[4].replace('%', '')
                return float(usage)
        except:
            pass
        return 0.0

    def _get_uptime_seconds(self, state: AgentState) -> int:
        """Calculate agent uptime in seconds"""
        try:
            start_time = datetime.fromisoformat(state.agent_start_time)
            uptime = datetime.now() - start_time
            return int(uptime.total_seconds())
        except:
            return 0


# ============================================================================
# MAIN AGENT
# ============================================================================

class SSHGuardianAgent:
    """Main SSH Guardian agent"""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.state = AgentState(config.state_file)
        self.collector = LogCollector(config.auth_log_path, self.state)
        self.api_client = GuardianAPIClient(config)
        self.running = False

        # Initialize firewall components if available and enabled
        # Prefer UFW over iptables
        self.ufw_manager = None
        self.firewall_collector = None
        self.firewall_manager = None

        if config.firewall_enabled:
            if UFW_AVAILABLE:
                self.ufw_manager = UFWManager()
                logging.info("Using UFW for firewall management")
            elif FIREWALL_AVAILABLE:
                self.firewall_collector = FirewallCollector()
                self.firewall_manager = FirewallManager()
                logging.info("Using iptables for firewall management (UFW not available)")

    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = os.path.dirname(self.config.log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def start(self):
        """Start the agent"""
        self.setup_logging()

        logging.info("="*70)
        logging.info("🚀 SSH Guardian Agent v3.0 Starting...")
        logging.info("="*70)
        logging.info(f"Agent ID: {self.config.agent_id}")
        logging.info(f"Hostname: {self.config.hostname}")
        logging.info(f"Server: {self.config.server_url}")
        logging.info(f"Auth Log: {self.config.auth_log_path}")
        logging.info(f"Check Interval: {self.config.check_interval}s")
        logging.info(f"Batch Size: {self.config.batch_size}")
        logging.info(f"Firewall Enabled: {self.config.firewall_enabled}")
        if self.ufw_manager:
            logging.info(f"Firewall Type: UFW")
            logging.info(f"Firewall Sync Interval: {self.config.firewall_sync_interval}s")
        elif self.firewall_collector:
            logging.info(f"Firewall Type: iptables")
            logging.info(f"Firewall Sync Interval: {self.config.firewall_sync_interval}s")
        logging.info(f"Fail2ban Mode: {self.config.use_fail2ban}")
        if self.config.use_fail2ban:
            logging.info(f"Fail2ban Sync Interval: {self.config.fail2ban_sync_interval}s")
        logging.info("="*70)

        # Register agent
        if not self.api_client.register_agent():
            logging.error("Failed to register agent. Continuing anyway...")

        self.running = True
        self.run()

    def run(self):
        """Main agent loop"""
        last_heartbeat_time = time.time()
        last_firewall_sync_time = time.time()
        last_fail2ban_sync_time = time.time()

        while self.running:
            try:
                # Collect new logs
                new_logs = self.collector.collect_new_logs()

                if new_logs:
                    logging.info(f"📋 Collected {len(new_logs)} new log lines")

                    # Split into batches
                    for i in range(0, len(new_logs), self.config.batch_size):
                        batch = new_logs[i:i + self.config.batch_size]

                        if self.api_client.submit_log_batch(batch):
                            self.state.total_logs_sent += len(batch)
                            self.state.total_batches_sent += 1
                            self.state.save()

                current_time = time.time()

                # Send heartbeat if needed
                if current_time - last_heartbeat_time >= self.config.heartbeat_interval:
                    if self.api_client.send_heartbeat(self.state):
                        last_heartbeat_time = current_time
                        self.state.save()

                # Firewall synchronization (UFW or iptables)
                if self.config.firewall_enabled:
                    if current_time - last_firewall_sync_time >= self.config.firewall_sync_interval:
                        self._sync_firewall()
                        last_firewall_sync_time = current_time

                    # Process any pending firewall commands
                    self._process_firewall_commands()

                # Fail2ban sync (bans to server + unbans from server)
                if self.config.use_fail2ban:
                    if current_time - last_fail2ban_sync_time >= self.config.fail2ban_sync_interval:
                        # Sync current bans WITH timestamps to server
                        self._sync_fail2ban_bans_to_server()
                        # Process pending unbans from dashboard
                        self._sync_fail2ban_unbans()
                        last_fail2ban_sync_time = current_time

                # Sleep until next check
                time.sleep(self.config.check_interval)

            except KeyboardInterrupt:
                logging.info("\n⏹️  Received stop signal")
                self.stop()
            except Exception as e:
                logging.error(f"❌ Error in agent loop: {e}")
                time.sleep(self.config.check_interval)

    def _sync_firewall(self):
        """Collect and sync firewall rules to central server"""
        try:
            # Use UFW if available, otherwise fall back to iptables
            if self.ufw_manager:
                logging.info("🔥 Collecting UFW rules...")
                ufw_data = self.ufw_manager.collect_all()

                if 'error' not in ufw_data:
                    self.api_client.submit_ufw_rules(ufw_data)
                else:
                    logging.warning(f"UFW collection error: {ufw_data.get('error')}")

            elif self.firewall_collector:
                logging.info("🔥 Collecting iptables rules...")
                firewall_data = self.firewall_collector.collect_all()

                if 'error' not in firewall_data:
                    self.api_client.submit_firewall_rules(firewall_data)

                    # Also sync extended data (ports, users, suggestions)
                    self._sync_extended_data(firewall_data)
                else:
                    logging.warning(f"Firewall collection error: {firewall_data.get('error')}")

            else:
                # Fallback: Direct UFW collection without external modules
                self._sync_ufw_direct()

        except Exception as e:
            logging.error(f"Error syncing firewall: {e}")

    def _sync_ufw_direct(self):
        """Direct UFW sync without external modules - fallback method"""
        try:
            import re
            logging.info("🔥 Collecting UFW rules (direct mode)...")

            # Get UFW status
            status_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=30)
            if status_result.returncode != 0:
                logging.warning("UFW not available or not running")
                return

            ufw_active = 'Status: active' in status_result.stdout
            logging.info(f"🔍 UFW status check: stdout={status_result.stdout[:50]!r}, ufw_active={ufw_active}")

            # Get numbered rules
            rules = []
            result = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line.startswith('['):
                        try:
                            # Parse: [ 1] 22/tcp ALLOW IN Anywhere
                            # Or: [ 2] Anywhere DENY IN 192.168.1.100
                            idx_end = line.index(']')
                            idx = int(line[1:idx_end].strip())
                            rule_text = line[idx_end+1:].strip()

                            # Determine action
                            action = 'ALLOW'
                            if 'DENY' in rule_text:
                                action = 'DENY'
                            elif 'REJECT' in rule_text:
                                action = 'REJECT'
                            elif 'LIMIT' in rule_text:
                                action = 'LIMIT'

                            # Determine direction
                            direction = 'IN'
                            if ' OUT ' in rule_text:
                                direction = 'OUT'

                            # Check IPv6
                            is_v6 = '(v6)' in rule_text
                            rule_text_clean = rule_text.replace('(v6)', '').strip()

                            # Parse rule components
                            # Format: TO_PART ACTION [DIRECTION] FROM_PART
                            # Examples:
                            #   22/tcp                     ALLOW IN    Anywhere
                            #   Anywhere                   DENY IN     192.168.1.100
                            #   80,443/tcp                 ALLOW IN    Anywhere
                            #   Anywhere on eth0           ALLOW IN    Anywhere

                            to_port = ''
                            to_ip = 'Anywhere'
                            from_ip = 'Anywhere'
                            from_port = ''
                            protocol = ''
                            interface = ''

                            # Split by action keyword
                            action_pattern = r'\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)?\s*'
                            match = re.split(action_pattern, rule_text_clean, maxsplit=1)

                            if len(match) >= 3:
                                to_part = match[0].strip()
                                from_part = match[-1].strip() if len(match) > 3 else 'Anywhere'

                                # Parse TO part (destination - usually port or "Anywhere")
                                if '/' in to_part:
                                    # Has protocol: 22/tcp, 80,443/tcp
                                    port_proto = to_part.split('/')
                                    to_port = port_proto[0]
                                    protocol = port_proto[1] if len(port_proto) > 1 else ''
                                elif to_part.isdigit():
                                    to_port = to_part
                                elif to_part.lower() != 'anywhere':
                                    # Could be IP or interface
                                    if ' on ' in to_part:
                                        parts = to_part.split(' on ')
                                        to_ip = parts[0].strip()
                                        interface = parts[1].strip()
                                    else:
                                        to_ip = to_part

                                # Parse FROM part (source IP)
                                if from_part and from_part.lower() != 'anywhere':
                                    # Check for "port X" in from
                                    if ' port ' in from_part:
                                        parts = from_part.split(' port ')
                                        from_ip = parts[0].strip()
                                        from_port = parts[1].strip()
                                    else:
                                        from_ip = from_part

                            rules.append({
                                'rule_index': idx,
                                'rule_text': rule_text,
                                'action': action,
                                'direction': direction,
                                'from_ip': from_ip,
                                'from_port': from_port,
                                'to_ip': to_ip,
                                'to_port': to_port,
                                'protocol': protocol,
                                'interface': interface,
                                'ipv6': is_v6
                            })
                        except (ValueError, IndexError) as e:
                            logging.debug(f"Failed to parse rule: {line} - {e}")
                            continue

            # Get default policies
            default_incoming = 'deny'
            default_outgoing = 'allow'
            verbose_result = subprocess.run(['ufw', 'status', 'verbose'], capture_output=True, text=True, timeout=30)
            if verbose_result.returncode == 0:
                for line in verbose_result.stdout.split('\n'):
                    if 'Default:' in line:
                        if 'deny (incoming)' in line.lower():
                            default_incoming = 'deny'
                        elif 'allow (incoming)' in line.lower():
                            default_incoming = 'allow'
                        if 'allow (outgoing)' in line.lower():
                            default_outgoing = 'allow'
                        elif 'deny (outgoing)' in line.lower():
                            default_outgoing = 'deny'

            ufw_data = {
                'ufw_status': 'active' if ufw_active else 'inactive',
                'default_incoming': default_incoming,
                'default_outgoing': default_outgoing,
                'rules': rules
            }

            if self.api_client.submit_ufw_rules(ufw_data):
                logging.info(f"✅ UFW synced: {len(rules)} rules")
            else:
                logging.warning("Failed to submit UFW rules")

        except Exception as e:
            logging.error(f"Error in direct UFW sync: {e}")

    def _sync_extended_data(self, firewall_data: dict = None):
        """Sync extended data including ports, users, and suggestions"""
        if not self.firewall_collector:
            return

        try:
            logging.info("📊 Collecting extended system data...")

            # Use collect_extended for full data
            extended_data = self.firewall_collector.collect_extended()

            # Generate suggestions
            from firewall_collector import RuleSuggestionEngine
            suggestion_engine = RuleSuggestionEngine(self.firewall_collector)
            suggestions = suggestion_engine.generate_suggestions(extended_data)

            # Prepare data for sync
            sync_data = {
                'agent_id': self.config.agent_id,
                'listening_ports': extended_data.get('listening_ports', []),
                'system_users': extended_data.get('system_users', []),
                'active_connections': extended_data.get('active_connections', []),
                'command_history': extended_data.get('command_history', []),
                'protected_ports': extended_data.get('protected_ports', []),
                'suggestions': suggestions,
                'collected_at': datetime.now().isoformat()
            }

            # Submit to server
            self.api_client.submit_extended_data(sync_data)
            logging.info(f"📊 Synced extended data: {len(sync_data['listening_ports'])} ports, "
                        f"{len(sync_data['system_users'])} users, "
                        f"{len(sync_data['suggestions'])} suggestions")

        except ImportError:
            logging.debug("RuleSuggestionEngine not available, skipping suggestions")
        except Exception as e:
            logging.error(f"Error syncing extended data: {e}")

    def _sync_fail2ban_unbans(self):
        """
        Sync pending unbans from dashboard to fail2ban.
        When admin manually unblocks an IP in dashboard that was blocked by fail2ban,
        we need to run `fail2ban-client unbanip` to actually unblock it.
        """
        if not self.config.use_fail2ban:
            return

        try:
            # Get pending unban commands from server
            pending_unbans = self.api_client.get_pending_fail2ban_unbans()

            if not pending_unbans:
                return

            logging.info(f"🔓 Processing {len(pending_unbans)} fail2ban unban commands")

            for cmd in pending_unbans:
                block_id = cmd.get('id')
                ip_address = cmd.get('ip')
                jail = cmd.get('jail', 'sshd')

                if not ip_address:
                    continue

                try:
                    # Execute fail2ban-client unbanip
                    result = subprocess.run(
                        ['fail2ban-client', 'set', jail, 'unbanip', ip_address],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    success = result.returncode == 0
                    message = result.stdout.strip() if success else result.stderr.strip()

                    if success:
                        logging.info(f"✅ fail2ban unban: {ip_address} (jail={jail})")
                    else:
                        logging.warning(f"⚠️ fail2ban unban failed: {ip_address} - {message}")

                    # Report result back to server
                    self.api_client.report_fail2ban_unban_result(block_id, success, message)

                except subprocess.TimeoutExpired:
                    logging.error(f"❌ fail2ban unban timeout: {ip_address}")
                    self.api_client.report_fail2ban_unban_result(block_id, False, "Command timed out")
                except FileNotFoundError:
                    logging.error("❌ fail2ban-client not found. Is fail2ban installed?")
                    self.api_client.report_fail2ban_unban_result(block_id, False, "fail2ban-client not found")
                except Exception as e:
                    logging.error(f"❌ fail2ban unban error: {ip_address} - {e}")
                    self.api_client.report_fail2ban_unban_result(block_id, False, str(e))

        except Exception as e:
            logging.error(f"Error syncing fail2ban unbans: {e}")

    def _sync_fail2ban_bans_to_server(self):
        """
        Sync current fail2ban bans WITH ACTUAL TIMESTAMPS to central server.
        Queries fail2ban's sqlite database to get the real ban times.
        """
        if not self.config.use_fail2ban:
            return

        try:
            import sqlite3

            # Fail2ban stores its database here
            f2b_db_paths = [
                '/var/lib/fail2ban/fail2ban.sqlite3',
                '/var/lib/fail2ban/fail2ban.db'
            ]

            db_path = None
            for path in f2b_db_paths:
                if os.path.exists(path):
                    db_path = path
                    break

            if not db_path:
                logging.debug("Fail2ban database not found, using fail2ban-client")
                # Fall back to fail2ban-client (without timestamps)
                self._sync_fail2ban_bans_via_client()
                return

            # Query fail2ban's sqlite database for current bans with timestamps
            bans = []
            try:
                conn = sqlite3.connect(db_path, timeout=10)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Query the bans table for currently banned IPs
                # timeofban is Unix timestamp
                cursor.execute("""
                    SELECT ip, jail, timeofban
                    FROM bans
                    WHERE 1=1
                    ORDER BY timeofban DESC
                """)

                for row in cursor.fetchall():
                    ip = row['ip']
                    jail = row['jail']
                    timeofban = row['timeofban']

                    # Convert Unix timestamp to ISO format
                    if timeofban:
                        banned_at = datetime.fromtimestamp(timeofban).isoformat()
                    else:
                        banned_at = None

                    bans.append({
                        'ip': ip,
                        'jail': jail,
                        'banned_at': banned_at
                    })

                cursor.close()
                conn.close()

            except sqlite3.Error as e:
                logging.warning(f"Failed to read fail2ban database: {e}")
                # Fall back to fail2ban-client
                self._sync_fail2ban_bans_via_client()
                return

            if not bans:
                logging.debug("No fail2ban bans to sync")
                return

            # Send to server
            result = self.api_client.sync_fail2ban_bans(
                bans=bans,
                hostname=socket.gethostname()
            )

            if result.get('success'):
                new_count = result.get('new', 0)
                synced_count = result.get('synced', 0)
                if new_count > 0:
                    logging.info(f"🔒 Synced {len(bans)} fail2ban bans (new: {new_count}, existing: {synced_count})")
            else:
                logging.warning(f"Fail2ban ban sync failed: {result.get('error')}")

        except ImportError:
            logging.debug("sqlite3 not available, using fail2ban-client")
            self._sync_fail2ban_bans_via_client()
        except Exception as e:
            logging.error(f"Error syncing fail2ban bans: {e}")

    def _sync_fail2ban_bans_via_client(self):
        """
        Fallback: Sync fail2ban bans using fail2ban-client (without timestamps).
        Used when fail2ban database is not accessible.
        """
        try:
            # Get list of jails
            result = subprocess.run(
                ['fail2ban-client', 'status'],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                return

            # Parse jail list
            jails = []
            for line in result.stdout.split('\n'):
                if 'Jail list:' in line:
                    jail_str = line.split(':')[1].strip()
                    jails = [j.strip() for j in jail_str.split(',') if j.strip()]
                    break

            bans = []
            for jail in jails:
                # Get banned IPs for each jail
                result = subprocess.run(
                    ['fail2ban-client', 'status', jail],
                    capture_output=True, text=True, timeout=30
                )

                if result.returncode != 0:
                    continue

                for line in result.stdout.split('\n'):
                    if 'Banned IP list:' in line:
                        ip_str = line.split(':')[1].strip()
                        ips = [ip.strip() for ip in ip_str.split() if ip.strip()]
                        for ip in ips:
                            bans.append({
                                'ip': ip,
                                'jail': jail,
                                'banned_at': None  # No timestamp available via client
                            })
                        break

            if bans:
                result = self.api_client.sync_fail2ban_bans(
                    bans=bans,
                    hostname=socket.gethostname()
                )
                if result.get('success'):
                    logging.info(f"🔒 Synced {len(bans)} fail2ban bans (via client, no timestamps)")

        except FileNotFoundError:
            logging.debug("fail2ban-client not found")
        except Exception as e:
            logging.error(f"Error syncing fail2ban bans via client: {e}")

    def _process_firewall_commands(self):
        """Process pending firewall commands from central server"""
        try:
            # Get pending commands - works for both UFW and iptables
            commands = self.api_client.get_pending_ufw_commands()
            if not commands:
                return

            for cmd in commands:
                command_id = cmd.get('id')
                action = cmd.get('action') or cmd.get('command_type')
                params = cmd.get('params', {})

                logging.info(f"🔧 Processing firewall command: {action} (ID: {command_id})")

                success = False
                message = ""

                try:
                    if self.ufw_manager:
                        # UFW command processing with module
                        success, message = self.ufw_manager.execute_command(action, params)
                    elif self.firewall_manager:
                        # iptables command processing (legacy)
                        if action == 'add_rule':
                            success, message = self.firewall_manager.add_rule(params)
                        elif action == 'delete_rule':
                            success, message = self.firewall_manager.delete_rule(
                                params.get('table', 'filter'),
                                params.get('chain'),
                                params.get('rule_num')
                            )
                        elif action == 'add_port_forward':
                            success, message = self.firewall_manager.add_port_forward(
                                params.get('external_port'),
                                params.get('internal_ip'),
                                params.get('internal_port'),
                                params.get('protocol', 'tcp'),
                                params.get('interface')
                            )
                        elif action == 'remove_port_forward':
                            success, message = self.firewall_manager.remove_port_forward(
                                params.get('external_port'),
                                params.get('internal_ip'),
                                params.get('internal_port'),
                                params.get('protocol', 'tcp')
                            )
                        elif action == 'set_policy':
                            success, message = self.firewall_manager.set_chain_policy(
                                params.get('chain'),
                                params.get('policy'),
                                params.get('table', 'filter')
                            )
                        elif action == 'flush_chain':
                            success, message = self.firewall_manager.flush_chain(
                                params.get('chain'),
                                params.get('table', 'filter')
                            )
                        elif action == 'save_rules':
                            success, message = self.firewall_manager.save_rules(
                                params.get('filepath', '/etc/iptables/rules.v4')
                            )
                        else:
                            message = f"Unknown action: {action}"
                    else:
                        # Direct UFW command execution (fallback without modules)
                        success, message = self._execute_ufw_command_direct(action, params)

                except Exception as e:
                    message = f"Error executing command: {str(e)}"

                # Report result back to server
                self.api_client.report_command_result(command_id, success, message)

                if success:
                    logging.info(f"✅ Command {command_id} executed: {message}")
                    # Trigger immediate firewall sync after successful command
                    self._sync_firewall()
                else:
                    logging.error(f"❌ Command {command_id} failed: {message}")

        except Exception as e:
            logging.error(f"Error processing firewall commands: {e}")

    def _execute_ufw_command_direct(self, action: str, params: dict) -> Tuple[bool, str]:
        """
        Direct UFW command execution without external modules.
        Fallback method for remote servers without ufw_manager module.
        """
        try:
            if action == 'sync_now':
                # Trigger immediate sync
                self._sync_ufw_direct()
                return True, "Sync triggered successfully"

            elif action in ('deny_from', 'block_ip', 'deny'):
                ip = params.get('ip') or params.get('source_ip') or params.get('from_ip')
                if not ip:
                    return False, "No IP address provided"

                # Check if rule already exists
                check = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=30)
                if f"from {ip}" in check.stdout and "DENY" in check.stdout:
                    return True, f"Rule already exists for {ip}"

                # Add deny rule
                result = subprocess.run(['ufw', 'deny', 'from', ip], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return True, f"Blocked IP {ip}"
                return False, f"Failed to block {ip}: {result.stderr}"

            elif action in ('allow_from', 'unblock_ip', 'allow'):
                ip = params.get('ip') or params.get('source_ip') or params.get('from_ip')
                port = params.get('port')
                proto = params.get('protocol', 'tcp')

                if port:
                    # Allow port
                    result = subprocess.run(['ufw', 'allow', f'{port}/{proto}'], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        return True, f"Allowed port {port}/{proto}"
                    return False, f"Failed to allow port: {result.stderr}"
                elif ip:
                    result = subprocess.run(['ufw', 'allow', 'from', ip], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        return True, f"Allowed IP {ip}"
                    return False, f"Failed to allow {ip}: {result.stderr}"
                else:
                    return False, "No IP or port provided"

            elif action in ('delete_deny', 'delete_rule', 'delete'):
                ip = params.get('ip') or params.get('source_ip') or params.get('from_ip')
                rule_num = params.get('rule_num') or params.get('rule_number')

                if rule_num:
                    # Delete by rule number
                    result = subprocess.run(['ufw', '--force', 'delete', str(rule_num)], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        return True, f"Deleted rule {rule_num}"
                    return False, f"Failed to delete rule {rule_num}: {result.stderr}"
                elif ip:
                    # Delete by IP - need to find rule number first
                    check = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=30)
                    import re
                    for line in check.stdout.split('\n'):
                        if f"from {ip}" in line and "DENY" in line:
                            match = re.search(r'\[\s*(\d+)\]', line)
                            if match:
                                rule_num = match.group(1)
                                result = subprocess.run(['ufw', '--force', 'delete', rule_num], capture_output=True, text=True, timeout=30)
                                if result.returncode == 0:
                                    return True, f"Deleted deny rule for {ip}"
                                return False, f"Failed to delete rule for {ip}: {result.stderr}"
                    return False, f"No deny rule found for {ip}"
                return False, "No IP or rule number provided"

            elif action == 'allow_port':
                port = params.get('port')
                proto = params.get('protocol', 'tcp')
                if not port:
                    return False, "No port provided"

                result = subprocess.run(['ufw', 'allow', f'{port}/{proto}'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return True, f"Allowed port {port}/{proto}"
                return False, f"Failed to allow port: {result.stderr}"

            elif action == 'deny_port':
                port = params.get('port')
                proto = params.get('protocol', 'tcp')
                if not port:
                    return False, "No port provided"

                result = subprocess.run(['ufw', 'deny', f'{port}/{proto}'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return True, f"Denied port {port}/{proto}"
                return False, f"Failed to deny port: {result.stderr}"

            elif action == 'limit' or action == 'limit_port':
                port = params.get('port')
                proto = params.get('protocol', 'tcp')
                if not port:
                    return False, "No port provided"

                result = subprocess.run(['ufw', 'limit', f'{port}/{proto}'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return True, f"Rate limited port {port}/{proto}"
                return False, f"Failed to limit port: {result.stderr}"

            elif action == 'enable':
                result = subprocess.run(['ufw', '--force', 'enable'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return True, "UFW enabled"
                return False, f"Failed to enable UFW: {result.stderr}"

            elif action == 'disable':
                result = subprocess.run(['ufw', 'disable'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return True, "UFW disabled"
                return False, f"Failed to disable UFW: {result.stderr}"

            elif action == 'reset':
                result = subprocess.run(['ufw', '--force', 'reset'], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return True, "UFW reset to defaults"
                return False, f"Failed to reset UFW: {result.stderr}"

            else:
                return False, f"Unknown action: {action}"

        except subprocess.TimeoutExpired:
            return False, f"Command timed out: {action}"
        except Exception as e:
            return False, f"Error executing {action}: {str(e)}"

    def stop(self):
        """Stop the agent"""
        logging.info("Stopping SSH Guardian Agent...")
        self.running = False
        self.state.save()
        logging.info("Agent stopped.")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description='SSH Guardian v3.0 - Live Agent')

    parser.add_argument('--config', '-c',
                       help='Configuration file path',
                       default='/etc/ssh-guardian/agent.json')

    parser.add_argument('--server', '-s',
                       help='SSH Guardian server URL')

    parser.add_argument('--api-key', '-k',
                       help='API key for authentication')

    parser.add_argument('--agent-id',
                       help='Custom agent ID')

    parser.add_argument('--check-interval', type=int,
                       help='Log check interval in seconds (default: 30)')

    parser.add_argument('--batch-size', type=int,
                       help='Batch size for log submission (default: 100)')

    args = parser.parse_args()

    # Load configuration
    config = AgentConfig(args.config if os.path.exists(args.config) else None)

    # Override with CLI arguments
    if args.server:
        config.server_url = args.server
    if args.api_key:
        config.api_key = args.api_key
    if args.agent_id:
        config.agent_id = args.agent_id
    if args.check_interval:
        config.check_interval = args.check_interval
    if args.batch_size:
        config.batch_size = args.batch_size

    # API key is optional - will be auto-generated on registration
    if not config.api_key:
        print("ℹ️  No API key provided. Will be auto-generated on registration.")

    # Start agent
    agent = SSHGuardianAgent(config)
    agent.start()


if __name__ == "__main__":
    main()
