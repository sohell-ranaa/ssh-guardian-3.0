#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Live Agent
Collects SSH authentication logs from remote Ubuntu servers and sends them to the central server

Features:
- Real-time log monitoring (/var/log/auth.log)
- Batch submission to central server
- Automatic heartbeat monitoring
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
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

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

        # Log file paths
        self.auth_log_path = "/var/log/auth.log"
        self.state_file = "/var/lib/ssh-guardian/agent-state.json"
        self.log_file = "/var/log/ssh-guardian-agent.log"

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
            "heartbeat_interval": self.heartbeat_interval
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

            if response.status_code == 200:
                data = response.json()
                logging.info(f"✅ Agent registered successfully: {data.get('message')}")
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
        logging.info("="*70)

        # Register agent
        if not self.api_client.register_agent():
            logging.error("Failed to register agent. Continuing anyway...")

        self.running = True
        self.run()

    def run(self):
        """Main agent loop"""
        last_heartbeat_time = time.time()

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

                # Send heartbeat if needed
                current_time = time.time()
                if current_time - last_heartbeat_time >= self.config.heartbeat_interval:
                    if self.api_client.send_heartbeat(self.state):
                        last_heartbeat_time = current_time
                        self.state.save()

                # Sleep until next check
                time.sleep(self.config.check_interval)

            except KeyboardInterrupt:
                logging.info("\n⏹️  Received stop signal")
                self.stop()
            except Exception as e:
                logging.error(f"❌ Error in agent loop: {e}")
                time.sleep(self.config.check_interval)

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
