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
            "firewall_enabled": self.firewall_enabled
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
        """Report the result of a firewall command execution"""
        try:
            payload = {
                'agent_id': self.config.agent_id,
                'command_id': command_id,
                'success': success,
                'message': message,
                'executed_at': datetime.now().isoformat()
            }

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
                if self.config.firewall_enabled and (self.ufw_manager or self.firewall_collector):
                    if current_time - last_firewall_sync_time >= self.config.firewall_sync_interval:
                        self._sync_firewall()
                        last_firewall_sync_time = current_time

                    # Process any pending firewall commands
                    self._process_firewall_commands()

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

        except Exception as e:
            logging.error(f"Error syncing firewall: {e}")

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

    def _process_firewall_commands(self):
        """Process pending firewall commands from central server"""
        try:
            # Get pending commands - works for both UFW and iptables
            if self.ufw_manager:
                commands = self.api_client.get_pending_ufw_commands()
            elif self.firewall_manager:
                commands = self.api_client.get_pending_firewall_commands()
            else:
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
                        # UFW command processing
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

    # Validate configuration
    if not config.api_key:
        print("❌ Error: API key is required. Set SSH_GUARDIAN_API_KEY environment variable or use --api-key")
        sys.exit(1)

    # Start agent
    agent = SSHGuardianAgent(config)
    agent.start()


if __name__ == "__main__":
    main()
