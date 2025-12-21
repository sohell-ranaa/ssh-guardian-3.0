#!/bin/bash
#
# SSH Guardian v3.0 - Interactive Agent Installer
# Single script for install, uninstall, and management
#

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# Paths
INSTALL_DIR="/opt/ssh-guardian-agent"
CONFIG_DIR="/etc/ssh-guardian"
STATE_DIR="/var/lib/ssh-guardian"
SERVICE_NAME="ssh-guardian-agent"
CONFIG_FILE="$CONFIG_DIR/agent.json"

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root (sudo)${NC}"
        exit 1
    fi
}

# Print banner
print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║            ${BOLD}SSH GUARDIAN v3.0 - AGENT INSTALLER${NC}${CYAN}              ║"
    echo "║                                                                   ║"
    echo "║         Hybrid Security: fail2ban + ML-powered Protection         ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check installation status
check_status() {
    if [ -f "$INSTALL_DIR/ssh_guardian_agent.py" ] && systemctl is-enabled $SERVICE_NAME &>/dev/null; then
        return 0  # Installed
    else
        return 1  # Not installed
    fi
}

# Get current config
get_config() {
    if [ -f "$CONFIG_FILE" ]; then
        SERVER_URL=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('server_url', 'Not set'))" 2>/dev/null || echo "Not set")
        AGENT_ID=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('agent_id', 'Not set'))" 2>/dev/null || echo "Not set")
        API_KEY=$(python3 -c "import json; k=json.load(open('$CONFIG_FILE')).get('api_key', ''); print('Configured' if k else 'Pending')" 2>/dev/null || echo "Unknown")
        USE_FAIL2BAN=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('use_fail2ban', False))" 2>/dev/null || echo "Unknown")
    fi
}

# Show current status
show_status() {
    print_banner
    echo -e "${BOLD}Current Status:${NC}"
    echo ""
    
    if check_status; then
        echo -e "  Installation: ${GREEN}● Installed${NC}"
        get_config
        echo -e "  Server URL:   ${YELLOW}$SERVER_URL${NC}"
        echo -e "  Agent ID:     ${YELLOW}$AGENT_ID${NC}"
        echo -e "  API Key:      ${YELLOW}$API_KEY${NC}"
        echo -e "  Fail2ban:     ${YELLOW}$USE_FAIL2BAN${NC}"
        echo ""
        
        # Service status
        if systemctl is-active $SERVICE_NAME &>/dev/null; then
            echo -e "  Agent Service: ${GREEN}● Running${NC}"
        else
            echo -e "  Agent Service: ${RED}● Stopped${NC}"
        fi
        
        # Fail2ban status
        if systemctl is-active fail2ban &>/dev/null; then
            BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
            echo -e "  Fail2ban:      ${GREEN}● Running${NC} (${BANNED:-0} IPs banned)"
        else
            echo -e "  Fail2ban:      ${YELLOW}● Not running${NC}"
        fi
    else
        echo -e "  Installation: ${RED}● Not installed${NC}"
    fi
    echo ""
}

# Main menu
show_menu() {
    show_status
    
    echo -e "${BOLD}Options:${NC}"
    echo ""
    
    if check_status; then
        echo -e "  ${GREEN}1)${NC} Reinstall / Update Agent"
        echo -e "  ${GREEN}2)${NC} Uninstall Agent"
        echo -e "  ${GREEN}3)${NC} Restart Agent Service"
        echo -e "  ${GREEN}4)${NC} View Agent Logs"
        echo -e "  ${GREEN}5)${NC} Reconfigure Server URL"
        echo -e "  ${GREEN}6)${NC} Update API Key"
        echo -e "  ${GREEN}7)${NC} Test Connection to Server"
        echo -e "  ${GREEN}8)${NC} View Fail2ban Status"
        echo -e "  ${GREEN}14)${NC} Install Simulation Receiver"
    else
        echo -e "  ${GREEN}1)${NC} Install Agent"
        echo -e "  ${GREEN}14)${NC} Install Simulation Receiver (standalone)"
    fi

    # Show simulation receiver options if installed
    if [ -f "/opt/ssh-guardian/simulation_receiver.py" ]; then
        echo ""
        echo -e "  ${CYAN}--- Simulation Receiver ---${NC}"
        echo -e "  ${GREEN}9)${NC} Test Simulation Receiver"
        echo -e "  ${GREEN}10)${NC} Show Simulation API Key"
        echo -e "  ${GREEN}11)${NC} Restart Simulation Receiver"
        echo -e "  ${GREEN}12)${NC} View Simulation Receiver Logs"
        echo -e "  ${GREEN}13)${NC} Uninstall Simulation Receiver"
    fi
    echo -e "  ${GREEN}0)${NC} Exit"
    echo ""
    echo -n -e "${BOLD}Enter choice: ${NC}"
}

# Install agent
install_agent() {
    print_banner
    echo -e "${BOLD}${GREEN}Installing SSH Guardian Agent${NC}"
    echo ""
    
    # Get server URL
    echo -n -e "Enter SSH Guardian Server URL [http://localhost:8081]: "
    read INPUT_SERVER
    SERVER_URL=${INPUT_SERVER:-"http://localhost:8081"}
    
    # Get agent ID (optional)
    HOSTNAME=$(hostname)
    MAC=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address 2>/dev/null | tr -d ':' || echo "unknown")
    DEFAULT_AGENT_ID="${HOSTNAME}-${MAC}"
    
    echo -n -e "Enter Agent ID [${DEFAULT_AGENT_ID}]: "
    read INPUT_AGENT_ID
    AGENT_ID=${INPUT_AGENT_ID:-$DEFAULT_AGENT_ID}
    
    # Fail2ban option
    echo -n -e "Enable fail2ban integration? [Y/n]: "
    read INPUT_FAIL2BAN
    if [[ "$INPUT_FAIL2BAN" =~ ^[Nn]$ ]]; then
        USE_FAIL2BAN="false"
    else
        USE_FAIL2BAN="true"
    fi
    
    echo ""
    echo -e "${YELLOW}Configuration:${NC}"
    echo -e "  Server URL: $SERVER_URL"
    echo -e "  Agent ID:   $AGENT_ID"
    echo -e "  Fail2ban:   $USE_FAIL2BAN"
    echo ""
    echo -n -e "Proceed with installation? [Y/n]: "
    read CONFIRM
    
    if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}Installation cancelled.${NC}"
        return
    fi
    
    echo ""
    echo -e "${YELLOW}[1/6] Installing dependencies...${NC}"
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip curl iptables
    [ "$USE_FAIL2BAN" == "true" ] && apt-get install -y -qq fail2ban
    pip3 install requests --quiet 2>/dev/null || pip3 install requests --break-system-packages --quiet 2>/dev/null
    
    echo -e "${YELLOW}[2/6] Creating directories...${NC}"
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR"
    
    echo -e "${YELLOW}[3/6] Installing agent script...${NC}"
    install_agent_script
    
    echo -e "${YELLOW}[4/6] Creating configuration...${NC}"
    cat > "$CONFIG_FILE" << EOF
{
  "server_url": "$SERVER_URL",
  "api_key": "",
  "agent_id": "$AGENT_ID",
  "hostname": "$HOSTNAME",
  "check_interval": 30,
  "batch_size": 100,
  "heartbeat_interval": 60,
  "firewall_sync_interval": 300,
  "firewall_enabled": true,
  "use_fail2ban": $USE_FAIL2BAN,
  "fail2ban_sync_interval": 30
}
EOF
    
    echo -e "${YELLOW}[5/6] Configuring fail2ban...${NC}"
    if [ "$USE_FAIL2BAN" == "true" ]; then
        configure_fail2ban
    else
        echo "  Skipped (disabled)"
    fi
    
    echo -e "${YELLOW}[6/6] Creating systemd service...${NC}"
    create_systemd_service
    
    # Start service
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl start $SERVICE_NAME
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              Installation Complete!                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "The agent is now running and will register with the server."
    echo -e "API key will be auto-generated on registration."
    echo ""
    read -p "Press Enter to continue..."
}

# Install agent Python script
install_agent_script() {
    cat > "$INSTALL_DIR/ssh_guardian_agent.py" << 'AGENT_PY'
#!/usr/bin/env python3
"""SSH Guardian v3.0 - Live Agent with fail2ban integration"""

import os, sys, time, json, uuid, socket, logging, argparse, requests, platform, subprocess
from datetime import datetime
from typing import List, Dict, Optional

class AgentConfig:
    def __init__(self, config_file: Optional[str] = None):
        self.server_url = os.getenv("SSH_GUARDIAN_SERVER", "http://localhost:8081")
        self.api_key = os.getenv("SSH_GUARDIAN_API_KEY", "")
        self.agent_id = os.getenv("SSH_GUARDIAN_AGENT_ID", f"{socket.gethostname()}-{uuid.getnode()}")
        self.hostname = socket.gethostname()
        self.check_interval = int(os.getenv("SSH_GUARDIAN_CHECK_INTERVAL", "30"))
        self.batch_size = int(os.getenv("SSH_GUARDIAN_BATCH_SIZE", "100"))
        self.heartbeat_interval = int(os.getenv("SSH_GUARDIAN_HEARTBEAT_INTERVAL", "60"))
        self.firewall_sync_interval = int(os.getenv("SSH_GUARDIAN_FIREWALL_SYNC_INTERVAL", "300"))
        self.auth_log_path = "/var/log/auth.log"
        self.state_file = "/var/lib/ssh-guardian/agent-state.json"
        self.log_file = "/var/log/ssh-guardian-agent.log"
        self.firewall_enabled = os.getenv("SSH_GUARDIAN_FIREWALL_ENABLED", "true").lower() == "true"
        self.use_fail2ban = os.getenv("SSH_GUARDIAN_USE_FAIL2BAN", "false").lower() == "true"
        self.fail2ban_sync_interval = int(os.getenv("SSH_GUARDIAN_FAIL2BAN_SYNC_INTERVAL", "30"))
        if config_file and os.path.exists(config_file):
            self.load_from_file(config_file)

    def load_from_file(self, config_file: str):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                for key, value in config.items():
                    if hasattr(self, key): setattr(self, key, value)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")

    def save_to_file(self, config_file: str):
        config = {k: getattr(self, k) for k in ['server_url', 'api_key', 'agent_id', 'hostname', 
                  'check_interval', 'batch_size', 'heartbeat_interval', 'firewall_sync_interval',
                  'firewall_enabled', 'use_fail2ban', 'fail2ban_sync_interval']}
        os.makedirs(os.path.dirname(config_file), exist_ok=True)
        with open(config_file, 'w') as f: json.dump(config, f, indent=2)

class AgentState:
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
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    for k in ['last_inode', 'last_position', 'last_heartbeat', 'total_logs_sent', 'total_batches_sent', 'agent_start_time']:
                        if k in data: setattr(self, k, data[k])
            except: pass

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w') as f:
                json.dump({k: getattr(self, k) for k in ['last_inode', 'last_position', 'last_heartbeat', 'total_logs_sent', 'total_batches_sent', 'agent_start_time']}, f, indent=2)
        except: pass

class LogCollector:
    def __init__(self, auth_log_path: str, state: AgentState):
        self.auth_log_path = auth_log_path
        self.state = state

    def collect_new_logs(self) -> List[str]:
        if not os.path.exists(self.auth_log_path): return []
        try:
            current_inode = os.stat(self.auth_log_path).st_ino
            if current_inode != self.state.last_inode:
                self.state.last_inode = current_inode
                self.state.last_position = 0
            with open(self.auth_log_path, 'r') as f:
                f.seek(self.state.last_position)
                lines = [l.strip() for l in f if any(k in l for k in ['sshd', 'Failed password', 'Accepted password', 'Accepted publickey', 'Invalid user', 'Connection closed'])]
                self.state.last_position = f.tell()
            return lines
        except: return []

class GuardianAPIClient:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': f'SSH-Guardian-Agent/{config.agent_id}', 'X-API-Key': config.api_key, 'X-Agent-ID': config.agent_id})

    def register_agent(self) -> bool:
        try:
            payload = {'agent_id': self.config.agent_id, 'hostname': self.config.hostname,
                      'system_info': {'os': platform.system(), 'os_version': platform.release(), 'platform': platform.platform()},
                      'version': '3.0.0', 'heartbeat_interval_sec': self.config.heartbeat_interval}
            response = self.session.post(f"{self.config.server_url}/api/agents/register", json=payload, timeout=30)
            if response.status_code in [200, 201]:
                data = response.json()
                logging.info(f"Agent registered: {data.get('message')}")
                if data.get('api_key'):
                    self.config.api_key = data['api_key']
                    self.session.headers['X-API-Key'] = self.config.api_key
                    self.config.save_to_file(os.getenv('SSH_GUARDIAN_CONFIG', '/etc/ssh-guardian/agent.json'))
                return True
            return False
        except Exception as e:
            logging.error(f"Registration error: {e}")
            return False

    def send_heartbeat(self, state: AgentState) -> bool:
        try:
            # Collect system metrics
            cpu_percent = self._get_cpu_percent()
            mem_percent = self._get_memory_percent()
            disk_percent = self._get_disk_percent()
            payload = {'agent_id': self.config.agent_id, 'metrics': {
                'cpu_usage_percent': cpu_percent, 'memory_usage_percent': mem_percent, 'disk_usage_percent': disk_percent
            }, 'status': 'online'}
            response = self.session.post(f"{self.config.server_url}/api/agents/heartbeat", json=payload, timeout=10)
            if response.status_code == 200:
                state.last_heartbeat = datetime.now().isoformat()
                return True
            return False
        except: return False

    def _get_cpu_percent(self) -> float:
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
                parts = line.split()
                idle = float(parts[4])
                total = sum(float(p) for p in parts[1:])
                return round(100 * (1 - idle / total), 1) if total > 0 else 0
        except: return 0

    def _get_memory_percent(self) -> float:
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                mem = {l.split(':')[0]: int(l.split(':')[1].strip().split()[0]) for l in lines[:3]}
                total, available = mem.get('MemTotal', 1), mem.get('MemAvailable', 0)
                return round(100 * (1 - available / total), 1) if total > 0 else 0
        except: return 0

    def _get_disk_percent(self) -> float:
        try:
            result = subprocess.run(['df', '/'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5: return float(parts[4].replace('%', ''))
            return 0
        except: return 0

    def submit_log_batch(self, log_lines: List[str]) -> bool:
        try:
            payload = {'batch_uuid': str(uuid.uuid4()), 'agent_id': self.config.agent_id, 'hostname': self.config.hostname,
                      'log_lines': log_lines, 'batch_size': len(log_lines)}
            response = self.session.post(f"{self.config.server_url}/api/agents/logs", json=payload, timeout=60)
            if response.status_code == 200:
                logging.info(f"Batch submitted: {len(log_lines)} logs")
                return True
            return False
        except: return False

    def get_pending_ufw_commands(self) -> List[Dict]:
        try:
            response = self.session.get(f"{self.config.server_url}/api/agents/ufw/commands", params={'agent_id': self.config.agent_id}, timeout=30)
            return response.json().get('commands', []) if response.status_code == 200 else []
        except: return []

    def report_command_result(self, command_id: str, success: bool, message: str) -> bool:
        try:
            payload = {'agent_id': self.config.agent_id, 'command_id': command_id, 'success': success, 'message': message}
            self.session.post(f"{self.config.server_url}/api/agents/ufw/command-result", json=payload, timeout=30)
            return True
        except: return False

    def get_pending_fail2ban_unbans(self) -> List[Dict]:
        try:
            response = self.session.get(f"{self.config.server_url}/api/agents/fail2ban/pending-unbans", timeout=30)
            return response.json().get('commands', []) if response.status_code == 200 else []
        except: return []

    def report_fail2ban_unban_result(self, block_id: int, success: bool, message: str) -> bool:
        try:
            self.session.post(f"{self.config.server_url}/api/agents/fail2ban/unban-result", json={'id': block_id, 'success': success, 'message': message}, timeout=30)
            return True
        except: return False

    def submit_ufw_rules(self, ufw_data: Dict) -> bool:
        try:
            payload = {'agent_id': self.config.agent_id, 'hostname': self.config.hostname, 'ufw_data': ufw_data}
            response = self.session.post(f"{self.config.server_url}/api/agents/ufw/sync", json=payload, timeout=60)
            return response.status_code == 200
        except: return False

class SSHGuardianAgent:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.state = AgentState(config.state_file)
        self.collector = LogCollector(config.auth_log_path, self.state)
        self.api_client = GuardianAPIClient(config)
        self.running = False

    def start(self):
        os.makedirs(os.path.dirname(self.config.log_file), exist_ok=True)
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                          handlers=[logging.FileHandler(self.config.log_file), logging.StreamHandler(sys.stdout)])
        logging.info("="*60)
        logging.info("SSH Guardian Agent v3.0 Starting...")
        logging.info(f"Agent ID: {self.config.agent_id}")
        logging.info(f"Server: {self.config.server_url}")
        logging.info(f"Fail2ban: {self.config.use_fail2ban}")
        logging.info("="*60)
        self.api_client.register_agent()
        self.running = True
        self.run()

    def run(self):
        last_hb = last_fw = last_f2b = time.time()
        while self.running:
            try:
                logs = self.collector.collect_new_logs()
                if logs:
                    for i in range(0, len(logs), self.config.batch_size):
                        if self.api_client.submit_log_batch(logs[i:i+self.config.batch_size]):
                            self.state.total_logs_sent += len(logs[i:i+self.config.batch_size])
                            self.state.save()
                now = time.time()
                if now - last_hb >= self.config.heartbeat_interval:
                    if self.api_client.send_heartbeat(self.state): last_hb = now
                # Periodic firewall sync
                if self.config.firewall_enabled and now - last_fw >= self.config.firewall_sync_interval:
                    self._sync_firewall()
                    last_fw = now
                if self.config.use_fail2ban and now - last_f2b >= self.config.fail2ban_sync_interval:
                    self._sync_fail2ban_unbans()
                    last_f2b = now
                # Process UFW commands
                for cmd in self.api_client.get_pending_ufw_commands():
                    need_sync = self._execute_ufw_command(cmd)
                    if need_sync: self._sync_firewall()
                time.sleep(self.config.check_interval)
            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                logging.error(f"Error: {e}")
                time.sleep(self.config.check_interval)

    def _sync_firewall(self):
        """Collect and sync UFW rules to server"""
        try:
            result = subprocess.run(['ufw', 'status', 'numbered'], capture_output=True, text=True, timeout=30)
            if result.returncode != 0: return
            rules = []
            for line in result.stdout.split('\n'):
                if line.startswith('['):
                    parts = line.split(']', 1)
                    if len(parts) == 2:
                        idx = parts[0].replace('[', '').strip()
                        rule = parts[1].strip()
                        action = 'ALLOW' if 'ALLOW' in rule else ('DENY' if 'DENY' in rule else 'REJECT')
                        rules.append({'rule_index': int(idx), 'rule_text': rule, 'action': action, 'direction': 'IN' if '(v6)' not in rule else 'IN'})
            status_result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
            ufw_status = 'active' if 'Status: active' in status_result.stdout else 'inactive'
            ufw_data = {'ufw_status': ufw_status, 'default_incoming': 'deny', 'default_outgoing': 'allow', 'rules': rules}
            self.api_client.submit_ufw_rules(ufw_data)
            logging.info(f"Firewall synced: {len(rules)} rules")
        except Exception as e:
            logging.error(f"Firewall sync error: {e}")

    def _sync_fail2ban_unbans(self):
        for cmd in self.api_client.get_pending_fail2ban_unbans():
            ip, jail, block_id = cmd.get('ip'), cmd.get('jail', 'sshd'), cmd.get('id')
            if not ip: continue
            try:
                result = subprocess.run(['fail2ban-client', 'set', jail, 'unbanip', ip], capture_output=True, text=True, timeout=30)
                self.api_client.report_fail2ban_unban_result(block_id, result.returncode == 0, result.stdout or result.stderr)
            except Exception as e:
                self.api_client.report_fail2ban_unban_result(block_id, False, str(e))

    def _execute_ufw_command(self, cmd):
        """Execute UFW command, returns True if sync needed after"""
        command_id, action, params = cmd.get('id'), cmd.get('action') or cmd.get('command_type'), cmd.get('params', {})
        try:
            if action == 'sync_now':
                self.api_client.report_command_result(command_id, True, 'Sync requested')
                return True  # Trigger immediate sync
            elif action == 'deny_from':
                result = subprocess.run(['ufw', 'deny', 'from', params.get('ip')], capture_output=True, text=True, timeout=30)
            elif action == 'delete_deny' or action == 'delete_deny_from':
                result = subprocess.run(['ufw', 'delete', 'deny', 'from', params.get('ip')], capture_output=True, text=True, timeout=30)
            else:
                result = type('obj', (object,), {'returncode': 1, 'stderr': f'Unknown action: {action}'})()
            self.api_client.report_command_result(command_id, result.returncode == 0, result.stdout or result.stderr)
            return result.returncode == 0  # Sync after successful command
        except Exception as e:
            self.api_client.report_command_result(command_id, False, str(e))
            return False

def main():
    parser = argparse.ArgumentParser(description='SSH Guardian v3.0 Agent')
    parser.add_argument('--config', '-c', default='/etc/ssh-guardian/agent.json')
    args = parser.parse_args()
    config = AgentConfig(args.config if os.path.exists(args.config) else None)
    SSHGuardianAgent(config).start()

if __name__ == "__main__":
    main()
AGENT_PY
    chmod +x "$INSTALL_DIR/ssh_guardian_agent.py"
}

# Configure fail2ban with incremental banning
configure_fail2ban() {
    echo -e "  ${CYAN}Checking fail2ban installation...${NC}"

    # Step 1: Check and install fail2ban if not present
    if ! command -v fail2ban-client &> /dev/null; then
        echo -e "  ${YELLOW}Installing fail2ban...${NC}"
        apt-get update -qq
        apt-get install -y -qq fail2ban
        if [ $? -ne 0 ]; then
            echo -e "  ${RED}Failed to install fail2ban${NC}"
            return 1
        fi
        echo -e "  ${GREEN}fail2ban installed successfully${NC}"
    else
        echo -e "  ${GREEN}fail2ban already installed${NC}"
    fi

    # Step 2: Check and display timezone
    echo -e "  ${CYAN}Checking timezone...${NC}"
    CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "Unknown")
    echo -e "  Current timezone: ${YELLOW}$CURRENT_TZ${NC}"

    # Offer to change timezone if it's UTC or unknown
    if [[ "$CURRENT_TZ" == "Etc/UTC" || "$CURRENT_TZ" == "UTC" || "$CURRENT_TZ" == "Unknown" ]]; then
        echo -e "  ${YELLOW}Timezone is set to UTC. Would you like to change it?${NC}"
        echo -n -e "  Enter timezone (e.g., Asia/Dhaka, America/New_York) or press Enter to skip: "
        read NEW_TZ
        if [ -n "$NEW_TZ" ]; then
            if timedatectl set-timezone "$NEW_TZ" 2>/dev/null; then
                echo -e "  ${GREEN}Timezone changed to $NEW_TZ${NC}"
            else
                echo -e "  ${RED}Failed to set timezone. Please set manually with: timedatectl set-timezone <timezone>${NC}"
            fi
        fi
    fi

    # Step 3: Create SSH Guardian action file
    echo -e "  ${CYAN}Creating fail2ban action for SSH Guardian...${NC}"
    cat > /etc/fail2ban/action.d/ssh_guardian.conf << 'EOF'
[Definition]
actionban = /opt/ssh-guardian-agent/fail2ban_report.sh ban <ip> <name> <failures> <bantime>
actionunban = /opt/ssh-guardian-agent/fail2ban_report.sh unban <ip> <name>
actionstart =
actionstop =
[Init]
EOF

    # Step 4: Create reporter script
    cat > "$INSTALL_DIR/fail2ban_report.sh" << 'REPORTER'
#!/bin/bash
ACTION=$1; IP=$2; JAIL=$3; FAILURES=${4:-0}; BANTIME=${5:-3600}
CONFIG="/etc/ssh-guardian/agent.json"
SERVER=$(python3 -c "import json; print(json.load(open('$CONFIG'))['server_url'])" 2>/dev/null)
KEY=$(python3 -c "import json; print(json.load(open('$CONFIG'))['api_key'])" 2>/dev/null)
AGENT=$(python3 -c "import json; print(json.load(open('$CONFIG'))['agent_id'])" 2>/dev/null)
[ -z "$KEY" ] && exit 0
if [ "$ACTION" == "ban" ]; then
    curl -s -X POST "$SERVER/api/agents/fail2ban/ban" -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
        -d "{\"ip\": \"$IP\", \"jail\": \"$JAIL\", \"agent_id\": \"$AGENT\", \"action\": \"ban\", \"failures\": $FAILURES, \"bantime\": $BANTIME}" \
        --connect-timeout 5 --max-time 10 &>/dev/null || true
else
    curl -s -X POST "$SERVER/api/agents/fail2ban/unban" -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
        -d "{\"ip\": \"$IP\", \"jail\": \"$JAIL\", \"agent_id\": \"$AGENT\", \"action\": \"unban\"}" \
        --connect-timeout 5 --max-time 10 &>/dev/null || true
fi
REPORTER
    chmod +x "$INSTALL_DIR/fail2ban_report.sh"

    # Step 5: Create jail config with INCREMENTAL BANNING
    echo -e "  ${CYAN}Configuring fail2ban with incremental banning...${NC}"
    cat > /etc/fail2ban/jail.d/ssh_guardian.local << EOF
# SSH Guardian v3.0 - Fail2ban Configuration
# Incremental banning: repeat offenders get longer bans

[DEFAULT]
# Incremental banning settings
bantime.increment = true
bantime.factor = 2
bantime.formula = ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor
bantime.maxtime = 1w
bantime.rndtime = 4h

# Whitelist local networks (customize as needed)
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
backend = auto

# Detection settings
maxretry = 5
findtime = 10m

# Ban duration (base time - will increase with each repeat offense)
# 1st ban: 1 hour
# 2nd ban: 2 hours
# 3rd ban: 4 hours
# 4th ban: 8 hours
# ... up to 1 week max
bantime = 1h

# Actions: block via iptables AND report to SSH Guardian
action = iptables-multiport[name=sshd, port="ssh", protocol=tcp]
         ssh_guardian
EOF

    # Step 6: Restart fail2ban
    echo -e "  ${CYAN}Restarting fail2ban...${NC}"
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true

    if systemctl is-active fail2ban &>/dev/null; then
        echo -e "  ${GREEN}fail2ban configured and running${NC}"

        # Show current settings
        BANTIME=$(fail2ban-client get sshd bantime 2>/dev/null || echo "unknown")
        MAXRETRY=$(fail2ban-client get sshd maxretry 2>/dev/null || echo "unknown")
        echo -e "  ${CYAN}Settings:${NC}"
        echo -e "    Base ban time: ${YELLOW}${BANTIME}s${NC}"
        echo -e "    Max retry: ${YELLOW}${MAXRETRY}${NC}"
        echo -e "    Incremental: ${GREEN}enabled (2x multiplier)${NC}"
        echo -e "    Max ban time: ${YELLOW}1 week${NC}"
    else
        echo -e "  ${RED}Warning: fail2ban failed to start. Check logs with: journalctl -u fail2ban${NC}"
    fi
}

# Create systemd service
create_systemd_service() {
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=SSH Guardian v3.0 Agent
After=network.target

[Service]
Type=simple
User=root
Environment="SSH_GUARDIAN_CONFIG=$CONFIG_FILE"
Environment="SSH_GUARDIAN_USE_FAIL2BAN=true"
ExecStart=/usr/bin/python3 $INSTALL_DIR/ssh_guardian_agent.py --config $CONFIG_FILE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

# Uninstall agent
uninstall_agent() {
    print_banner
    echo -e "${BOLD}${RED}Uninstall SSH Guardian Agent${NC}"
    echo ""
    echo -e "${YELLOW}This will remove:${NC}"
    echo "  - Agent service and scripts"
    echo "  - Configuration files"
    echo "  - Fail2ban integration"
    echo ""
    echo -n -e "${RED}Are you sure you want to uninstall? [y/N]: ${NC}"
    read CONFIRM
    
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Uninstall cancelled.${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo ""
    echo -e "${YELLOW}Stopping service...${NC}"
    systemctl stop $SERVICE_NAME 2>/dev/null || true
    systemctl disable $SERVICE_NAME 2>/dev/null || true
    
    echo -e "${YELLOW}Removing files...${NC}"
    rm -f /etc/systemd/system/$SERVICE_NAME.service
    rm -rf "$INSTALL_DIR"
    rm -rf "$CONFIG_DIR"
    rm -rf "$STATE_DIR"
    rm -f /var/log/ssh-guardian-agent.log
    
    echo -e "${YELLOW}Removing fail2ban config...${NC}"
    rm -f /etc/fail2ban/action.d/ssh_guardian.conf
    rm -f /etc/fail2ban/jail.d/ssh_guardian.local
    systemctl restart fail2ban 2>/dev/null || true
    
    systemctl daemon-reload
    
    echo ""
    echo -e "${GREEN}Uninstallation complete!${NC}"
    read -p "Press Enter to continue..."
}

# Restart service
restart_service() {
    echo -e "${YELLOW}Restarting SSH Guardian Agent...${NC}"
    systemctl restart $SERVICE_NAME
    sleep 2
    if systemctl is-active $SERVICE_NAME &>/dev/null; then
        echo -e "${GREEN}Service restarted successfully!${NC}"
    else
        echo -e "${RED}Service failed to start. Check logs with: journalctl -u $SERVICE_NAME${NC}"
    fi
    read -p "Press Enter to continue..."
}

# View logs
view_logs() {
    print_banner
    echo -e "${BOLD}Agent Logs (last 50 lines):${NC}"
    echo ""
    journalctl -u $SERVICE_NAME -n 50 --no-pager
    echo ""
    read -p "Press Enter to continue..."
}

# Reconfigure server
reconfigure_server() {
    print_banner
    get_config
    echo -e "${BOLD}Reconfigure Server URL${NC}"
    echo ""
    echo -e "Current server: ${YELLOW}$SERVER_URL${NC}"
    echo ""
    echo -n "Enter new server URL: "
    read NEW_SERVER
    
    if [ -z "$NEW_SERVER" ]; then
        echo -e "${YELLOW}No change made.${NC}"
    else
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f: config = json.load(f)
config['server_url'] = '$NEW_SERVER'
config['api_key'] = ''  # Reset API key for re-registration
with open('$CONFIG_FILE', 'w') as f: json.dump(config, f, indent=2)
"
        echo -e "${GREEN}Server URL updated. Restarting agent...${NC}"
        systemctl restart $SERVICE_NAME
    fi
    read -p "Press Enter to continue..."
}

# Update API Key
update_api_key() {
    print_banner
    get_config
    echo -e "${BOLD}Update API Key${NC}"
    echo ""

    # Get current API key
    CURRENT_KEY=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('api_key', ''))" 2>/dev/null)

    if [ -n "$CURRENT_KEY" ]; then
        echo -e "Current API Key: ${YELLOW}${CURRENT_KEY:0:8}...${CURRENT_KEY: -4}${NC}"
    else
        echo -e "Current API Key: ${RED}Not set${NC}"
    fi
    echo ""
    echo -e "${CYAN}You can find the API key in the dashboard:${NC}"
    echo -e "  Agents → Click on agent → View Details → API Key"
    echo ""
    echo -n "Enter new API Key (or press Enter to cancel): "
    read NEW_API_KEY

    if [ -z "$NEW_API_KEY" ]; then
        echo -e "${YELLOW}No change made.${NC}"
    else
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f: config = json.load(f)
config['api_key'] = '$NEW_API_KEY'
with open('$CONFIG_FILE', 'w') as f: json.dump(config, f, indent=2)
"
        echo -e "${GREEN}API Key updated successfully!${NC}"
        echo -e "${YELLOW}Restarting agent...${NC}"
        systemctl restart $SERVICE_NAME
        sleep 2
        if systemctl is-active $SERVICE_NAME &>/dev/null; then
            echo -e "${GREEN}Agent restarted and running with new API key.${NC}"
        else
            echo -e "${RED}Agent failed to start. Check logs with option 4.${NC}"
        fi
    fi
    read -p "Press Enter to continue..."
}

# Test connection
test_connection() {
    print_banner
    get_config
    echo -e "${BOLD}Testing Connection to Server${NC}"
    echo ""
    echo -e "Server: ${YELLOW}$SERVER_URL${NC}"
    echo ""

    echo -n "Testing health endpoint... "
    if curl -s --connect-timeout 5 "$SERVER_URL/health" | grep -q "healthy"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

# View fail2ban status
view_fail2ban() {
    print_banner
    echo -e "${BOLD}Fail2ban Status${NC}"
    echo ""
    
    if ! systemctl is-active fail2ban &>/dev/null; then
        echo -e "${RED}Fail2ban is not running${NC}"
    else
        echo -e "${GREEN}Fail2ban Status:${NC}"
        fail2ban-client status
        echo ""
        echo -e "${GREEN}SSHD Jail Status:${NC}"
        fail2ban-client status sshd 2>/dev/null || echo "SSHD jail not configured"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Install simulation receiver
install_simulation_receiver() {
    print_banner
    echo -e "${BOLD}${GREEN}Installing Simulation Receiver${NC}"
    echo ""
    echo -e "This installs a lightweight HTTP server that accepts simulation commands"
    echo -e "from the SSH Guardian dashboard and writes fake attack entries to auth.log."
    echo -e ""
    echo -e "${YELLOW}This triggers fail2ban and SSH Guardian agent as if it were a real attack.${NC}"
    echo ""

    # Get API key
    echo -n -e "Enter Simulation Receiver API Key: "
    read -s SIM_API_KEY
    echo ""

    if [ -z "$SIM_API_KEY" ]; then
        echo -e "${RED}API key is required. Get it from Dashboard → Simulation → Target Servers → Add Target${NC}"
        read -p "Press Enter to continue..."
        return
    fi

    # Get port
    echo -n -e "Enter port [5001]: "
    read SIM_PORT
    SIM_PORT=${SIM_PORT:-5001}

    # Get log file path
    echo -n -e "Enter auth.log path [/var/log/auth.log]: "
    read SIM_LOG_FILE
    SIM_LOG_FILE=${SIM_LOG_FILE:-"/var/log/auth.log"}

    echo ""
    echo -e "${YELLOW}Configuration:${NC}"
    echo -e "  Port:     $SIM_PORT"
    echo -e "  Log File: $SIM_LOG_FILE"
    echo ""
    echo -n -e "Proceed with installation? [Y/n]: "
    read CONFIRM

    if [[ "$CONFIRM" =~ ^[Nn]$ ]]; then
        echo -e "${YELLOW}Installation cancelled.${NC}"
        return
    fi

    echo ""
    echo -e "${YELLOW}[1/4] Installing dependencies...${NC}"
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip
    pip3 install flask requests --quiet 2>/dev/null || pip3 install flask requests --break-system-packages --quiet 2>/dev/null

    echo -e "${YELLOW}[2/4] Creating directories...${NC}"
    mkdir -p /opt/ssh-guardian

    echo -e "${YELLOW}[3/4] Installing simulation receiver script...${NC}"

    cat > /opt/ssh-guardian/simulation_receiver.py << 'SIMRECEIVER'
#!/usr/bin/env python3
"""SSH Guardian v3.0 - Simulation Receiver"""
import os, sys, json, random, socket, argparse
from datetime import datetime
from functools import wraps
try:
    from flask import Flask, request, jsonify
except ImportError:
    print("Error: Flask required. pip3 install flask"); sys.exit(1)

app = Flask(__name__)
CONFIG = {'api_key': '', 'port': 5001, 'log_file': '/var/log/auth.log', 'hostname': socket.gethostname()}
LAST_INJECTION = {'time': None, 'scenario_id': None, 'ip': None, 'count': 0}

DEMO_SCENARIOS = {
    "abuseipdb_critical": {"id": "abuseipdb_critical", "name": "AbuseIPDB Critical (90+)", "ip": "185.220.101.1", "alternate_ips": ["185.220.101.2", "185.220.101.54", "193.56.28.103"], "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"},
    "tor_exit_attack": {"id": "tor_exit_attack", "name": "Tor Exit Node + Failed Login", "ip": "185.220.101.1", "alternate_ips": ["185.220.101.2", "185.220.101.3", "185.220.102.1"], "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"},
    "abuseipdb_high": {"id": "abuseipdb_high", "name": "AbuseIPDB High (70+)", "ip": "45.142.212.61", "alternate_ips": ["185.220.101.1", "193.56.28.103"], "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"},
    "brute_force_5_fails": {"id": "brute_force_5_fails", "name": "Brute Force (5 fails/10min)", "ip": "91.240.118.172", "alternate_ips": ["45.142.212.61", "193.56.28.103"], "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"},
    "credential_stuffing": {"id": "credential_stuffing", "name": "Credential Stuffing (5 users)", "ip": "45.227.254.0", "alternate_ips": ["193.56.28.103", "185.220.101.1"], "log_template": "sshd[{pid}]: Failed password for invalid user {username} from {ip} port {port} ssh2", "rotate_usernames": True},
    "ddos_velocity": {"id": "ddos_velocity", "name": "DDoS/Velocity (20 events/min)", "ip": "185.156.73.0", "alternate_ips": ["91.240.118.172", "193.56.28.103"], "log_template": "sshd[{pid}]: Failed password for invalid user admin from {ip} port {port} ssh2"},
    "vpn_proxy_attack": {"id": "vpn_proxy_attack", "name": "VPN/Proxy + Score 30+", "ip": "103.216.221.19", "alternate_ips": ["45.142.212.61", "91.240.118.172"], "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"},
    "high_risk_country": {"id": "high_risk_country", "name": "High-Risk Country + 2 Fails", "ip": "218.92.0.107", "alternate_ips": ["39.96.0.0", "45.142.212.61"], "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"},
    "threat_combo_tor": {"id": "threat_combo_tor", "name": "Threat Combo (Abuse 50 + Tor)", "ip": "185.220.101.54", "alternate_ips": ["185.220.101.1", "185.220.102.1"], "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"},
    "virustotal_5_vendors": {"id": "virustotal_5_vendors", "name": "VirusTotal 5+ Vendors", "ip": "193.56.28.103", "alternate_ips": ["45.142.212.61", "185.156.73.0"], "log_template": "sshd[{pid}]: Failed password for invalid user oracle from {ip} port {port} ssh2"},
    "impossible_travel": {"id": "impossible_travel", "name": "Impossible Travel (1000km/2hr)", "ip": "39.96.0.0", "alternate_ips": ["218.92.0.107", "45.142.212.61"], "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"},
    "abuseipdb_medium": {"id": "abuseipdb_medium", "name": "AbuseIPDB Medium (50+)", "ip": "162.142.125.0", "alternate_ips": ["91.240.118.172", "185.220.101.1"], "log_template": "sshd[{pid}]: Failed password for invalid user test from {ip} port {port} ssh2"},
    "datacenter_attack": {"id": "datacenter_attack", "name": "Datacenter IP Attack", "ip": "167.172.248.37", "alternate_ips": ["206.189.156.201", "159.89.133.246"], "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"},
    "night_time_login": {"id": "night_time_login", "name": "Night-Time Login (10PM-6AM)", "ip": "45.142.212.61", "alternate_ips": ["193.56.28.103", "91.240.118.172"], "log_template": "sshd[{pid}]: Failed password for admin from {ip} port {port} ssh2"},
    "clean_baseline": {"id": "clean_baseline", "name": "Clean IP Baseline", "ip": "8.8.8.8", "alternate_ips": ["8.8.4.4", "1.1.1.1"], "log_template": "sshd[{pid}]: Accepted publickey for deploy from {ip} port {port} ssh2"},
    "repeat_offender": {"id": "repeat_offender", "name": "Repeat Offender (Escalation)", "ip": "185.156.73.0", "alternate_ips": ["193.56.28.103", "45.142.212.61"], "log_template": "sshd[{pid}]: Failed password for root from {ip} port {port} ssh2"}
}
USERNAMES = ['admin', 'root', 'user', 'oracle', 'postgres', 'mysql', 'test', 'ubuntu', 'deploy', 'guest', 'ftp', 'www-data']

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not key: return jsonify({'success': False, 'error': 'API key required'}), 401
        if key != CONFIG['api_key']: return jsonify({'success': False, 'error': 'Invalid API key'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/simulation/health', methods=['GET'])
def health():
    return jsonify({'success': True, 'status': 'running', 'hostname': CONFIG['hostname'], 'port': CONFIG['port'], 'log_file': CONFIG['log_file'], 'last_injection': LAST_INJECTION, 'scenarios_available': len(DEMO_SCENARIOS)})

@app.route('/api/simulation/scenarios', methods=['GET'])
@require_api_key
def scenarios():
    return jsonify({'success': True, 'scenarios': [{'id': s['id'], 'name': s['name'], 'ip': s['ip'], 'alternate_ips': s.get('alternate_ips', [])} for s in DEMO_SCENARIOS.values()]})

@app.route('/api/simulation/test-write', methods=['POST'])
@require_api_key
def test_write():
    try:
        test_entry = f"{datetime.now().strftime('%b %d %H:%M:%S')} {CONFIG['hostname']} ssh_guardian_sim[0]: Test write from simulation receiver"
        with open(CONFIG['log_file'], 'a') as f: f.write(test_entry + '\n')
        return jsonify({'success': True, 'message': 'Write test successful', 'log_file': CONFIG['log_file']})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/simulation/inject', methods=['POST'])
@require_api_key
def inject():
    global LAST_INJECTION
    data = request.get_json() or {}
    scenario_id, event_count = data.get('scenario_id'), min(50, max(1, data.get('event_count', 15)))
    use_alt = data.get('use_alternate_ip', False)
    scenario = DEMO_SCENARIOS.get(scenario_id)
    if not scenario: return jsonify({'success': False, 'error': f'Unknown scenario: {scenario_id}'}), 400
    ip = random.choice(scenario.get('alternate_ips', [])) if use_alt and scenario.get('alternate_ips') else scenario['ip']
    template, hostname, now, entries = scenario['log_template'], CONFIG['hostname'], datetime.now(), []
    for i in range(event_count):
        t = datetime.fromtimestamp(now.timestamp() + i * random.randint(1, 3))
        username = USERNAMES[i % len(USERNAMES)] if scenario.get('rotate_usernames') else 'root'
        entry = f"{now.strftime('%b')} {now.day:2d} {t.strftime('%H:%M:%S')} {hostname} " + template.format(pid=random.randint(10000, 99999), ip=ip, port=random.randint(40000, 65000), username=username)
        entries.append(entry)
    try:
        with open(CONFIG['log_file'], 'a') as f:
            for e in entries: f.write(e + '\n')
        LAST_INJECTION = {'time': datetime.now().isoformat(), 'scenario_id': scenario_id, 'ip': ip, 'count': len(entries)}
        return jsonify({'success': True, 'scenario_id': scenario_id, 'scenario_name': scenario['name'], 'ip_used': ip, 'lines_written': len(entries), 'log_file': CONFIG['log_file'], 'injected_at': LAST_INJECTION['time']})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def print_banner(host, port, api_key, log_file):
    key_preview = api_key[:8] + '...' + api_key[-4:] if len(api_key) > 12 else '***'
    print("\n" + "=" * 60)
    print("  SSH GUARDIAN v3.0 - SIMULATION RECEIVER")
    print("=" * 60)
    print(f"\n  Status:     \033[92m● RUNNING\033[0m")
    print(f"  Host:       {host}:{port}")
    print(f"  Hostname:   {CONFIG['hostname']}")
    print(f"  Log File:   {log_file}")
    print(f"  API Key:    {key_preview}")
    print(f"  Scenarios:  {len(DEMO_SCENARIOS)} available")
    print("\n" + "-" * 60)
    print(f"  Health:  http://{host}:{port}/api/simulation/health")
    print(f"  Inject:  http://{host}:{port}/api/simulation/inject")
    print("-" * 60 + "\n")

def run_self_test(api_key, port):
    print("\n" + "=" * 60 + "\n  SELF-TEST MODE\n" + "=" * 60 + "\n")
    passed = 0
    print("  [1/3] API Key Format...")
    if api_key and len(api_key) >= 32:
        print(f"        \033[92m✓ PASS\033[0m - {len(api_key)} chars"); passed += 1
    else:
        print(f"        \033[91m✗ FAIL\033[0m - Need 32+ chars")
    print("  [2/3] Log File Write Access...")
    log_file = CONFIG['log_file']
    if os.path.exists(log_file) and os.access(log_file, os.W_OK):
        print(f"        \033[92m✓ PASS\033[0m - Can write to {log_file}"); passed += 1
    elif not os.path.exists(log_file) and os.access(os.path.dirname(log_file), os.W_OK):
        print(f"        \033[93m⚠ WARN\033[0m - File doesn't exist but dir writable"); passed += 1
    else:
        print(f"        \033[91m✗ FAIL\033[0m - No write permission")
    print("  [3/3] Port Availability...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        if s.connect_ex(('127.0.0.1', port)) != 0:
            print(f"        \033[92m✓ PASS\033[0m - Port {port} available"); passed += 1
        else:
            print(f"        \033[91m✗ FAIL\033[0m - Port {port} in use")
        s.close()
    except: passed += 1
    print("\n" + "-" * 60)
    print(f"  \033[92mAll 3 tests passed!\033[0m" if passed == 3 else f"  \033[91m{3-passed} tests failed\033[0m")
    print("-" * 60 + "\n")
    return passed == 3

def show_api_key(api_key):
    print("\n" + "=" * 60 + "\n  API KEY VERIFICATION\n" + "=" * 60)
    print(f"\n  Your API key is:\n\n  \033[96m{api_key}\033[0m\n")
    print("  Copy this and paste in Dashboard → Simulation → Enable agent")
    print("\n" + "=" * 60 + "\n")

if __name__ == '__main__':
    p = argparse.ArgumentParser(description='SSH Guardian Simulation Receiver')
    p.add_argument('--api-key', '-k', default=os.getenv('SIM_RECEIVER_API_KEY', ''))
    p.add_argument('--port', '-p', type=int, default=int(os.getenv('SIM_RECEIVER_PORT', 5001)))
    p.add_argument('--log-file', '-l', default=os.getenv('SIM_RECEIVER_LOG_FILE', '/var/log/auth.log'))
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--test', '-t', action='store_true', help='Run self-test')
    p.add_argument('--show-key', '-s', action='store_true', help='Show API key')
    p.add_argument('--status', action='store_true', help='Show status only')
    args = p.parse_args()
    CONFIG['api_key'], CONFIG['port'], CONFIG['log_file'] = args.api_key, args.port, args.log_file
    if not CONFIG['api_key']:
        print("\033[91mError: API key required.\033[0m\nUse --api-key or set SIM_RECEIVER_API_KEY"); sys.exit(1)
    if args.show_key: show_api_key(CONFIG['api_key']); sys.exit(0)
    if args.test: sys.exit(0 if run_self_test(CONFIG['api_key'], CONFIG['port']) else 1)
    if args.status: print_banner(args.host, CONFIG['port'], CONFIG['api_key'], CONFIG['log_file']); sys.exit(0)
    print_banner(args.host, CONFIG['port'], CONFIG['api_key'], CONFIG['log_file'])
    app.run(host=args.host, port=CONFIG['port'])
SIMRECEIVER

    chmod +x /opt/ssh-guardian/simulation_receiver.py

    # Create environment file
    cat > /etc/ssh-guardian/sim_receiver.env << EOF
SIM_RECEIVER_API_KEY=$SIM_API_KEY
SIM_RECEIVER_PORT=$SIM_PORT
SIM_RECEIVER_LOG_FILE=$SIM_LOG_FILE
EOF
    chmod 600 /etc/ssh-guardian/sim_receiver.env

    echo -e "${YELLOW}[4/4] Creating systemd service...${NC}"

    cat > /etc/systemd/system/ssh-guardian-sim-receiver.service << EOF
[Unit]
Description=SSH Guardian Simulation Receiver
After=network.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/ssh-guardian/sim_receiver.env
ExecStart=/usr/bin/python3 /opt/ssh-guardian/simulation_receiver.py --api-key \${SIM_RECEIVER_API_KEY} --port \${SIM_RECEIVER_PORT} --log-file \${SIM_RECEIVER_LOG_FILE}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ssh-guardian-sim-receiver
    systemctl start ssh-guardian-sim-receiver

    # Allow port through firewall
    if command -v ufw &>/dev/null; then
        ufw allow $SIM_PORT/tcp 2>/dev/null || true
    fi

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}       Simulation Receiver installed successfully!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Service Status: $(systemctl is-active ssh-guardian-sim-receiver)"
    echo -e "  Port:           ${CYAN}$SIM_PORT${NC}"
    echo -e "  Log File:       ${CYAN}$SIM_LOG_FILE${NC}"
    echo ""
    echo -e "  ${YELLOW}Add this server as a target in Dashboard:${NC}"
    echo -e "  Simulation → Live Attack → Target Servers → Add Target"
    echo -e "  IP Address: $(hostname -I | awk '{print $1}')"
    echo -e "  Port: $SIM_PORT"
    echo ""

    read -p "Press Enter to continue..."
}

# Test simulation receiver
test_simulation_receiver() {
    print_banner
    echo -e "${BOLD}Testing Simulation Receiver${NC}"
    echo ""

    if [ ! -f "/etc/ssh-guardian/sim_receiver.env" ]; then
        echo -e "${RED}Simulation receiver not configured.${NC}"
        echo -e "Install it first using option 8."
        read -p "Press Enter to continue..."
        return
    fi

    source /etc/ssh-guardian/sim_receiver.env
    SIM_PORT=${SIM_RECEIVER_PORT:-5001}

    if [ -z "$SIM_RECEIVER_API_KEY" ]; then
        echo -e "${RED}API key not found in configuration.${NC}"
        read -p "Press Enter to continue..."
        return
    fi

    echo -e "${BOLD}[1/3] Service Status${NC}"
    if systemctl is-active ssh-guardian-sim-receiver &>/dev/null; then
        echo -e "       ${GREEN}✓ PASS${NC} - Service is running"
    else
        echo -e "       ${RED}✗ FAIL${NC} - Service is not running"
    fi

    echo -e "${BOLD}[2/3] API Key Format${NC}"
    KEY_LEN=${#SIM_RECEIVER_API_KEY}
    if [ "$KEY_LEN" -ge 32 ]; then
        echo -e "       ${GREEN}✓ PASS${NC} - API key is $KEY_LEN chars"
    else
        echo -e "       ${RED}✗ FAIL${NC} - API key too short ($KEY_LEN chars, need 32+)"
    fi

    echo -e "${BOLD}[3/3] Health Endpoint${NC}"
    HEALTH_RESPONSE=$(curl -s --connect-timeout 5 "http://127.0.0.1:$SIM_PORT/api/simulation/health" 2>/dev/null)
    if echo "$HEALTH_RESPONSE" | grep -q '"success": true'; then
        echo -e "       ${GREEN}✓ PASS${NC} - Health endpoint responding on port $SIM_PORT"
    else
        echo -e "       ${RED}✗ FAIL${NC} - Health endpoint not responding"
    fi

    echo ""
    echo -e "${CYAN}Configuration:${NC}"
    echo -e "  Port:     $SIM_PORT"
    echo -e "  Log File: ${SIM_RECEIVER_LOG_FILE:-/var/log/auth.log}"
    echo -e "  API Key:  ${SIM_RECEIVER_API_KEY:0:8}...${SIM_RECEIVER_API_KEY: -4}"
    echo ""
    read -p "Press Enter to continue..."
}

# Show simulation API key
show_simulation_api_key() {
    print_banner
    echo -e "${BOLD}Simulation Receiver API Key${NC}"
    echo ""

    if [ ! -f "/etc/ssh-guardian/sim_receiver.env" ]; then
        echo -e "${RED}Simulation receiver not configured.${NC}"
        echo -e "Install it first using option 8."
        read -p "Press Enter to continue..."
        return
    fi

    source /etc/ssh-guardian/sim_receiver.env

    if [ -z "$SIM_RECEIVER_API_KEY" ]; then
        echo -e "${RED}API key not found in configuration.${NC}"
        read -p "Press Enter to continue..."
        return
    fi

    python3 /opt/ssh-guardian/simulation_receiver.py --api-key "$SIM_RECEIVER_API_KEY" --show-key
    echo ""
    read -p "Press Enter to continue..."
}

# Restart simulation receiver
restart_simulation_receiver() {
    echo -e "${YELLOW}Restarting Simulation Receiver...${NC}"
    systemctl restart ssh-guardian-sim-receiver
    sleep 2
    if systemctl is-active ssh-guardian-sim-receiver &>/dev/null; then
        echo -e "${GREEN}Simulation Receiver restarted successfully!${NC}"
    else
        echo -e "${RED}Failed to start. Check logs with option 12.${NC}"
    fi
    read -p "Press Enter to continue..."
}

# View simulation receiver logs
view_simulation_logs() {
    print_banner
    echo -e "${BOLD}Simulation Receiver Logs (last 50 lines):${NC}"
    echo ""
    journalctl -u ssh-guardian-sim-receiver -n 50 --no-pager
    echo ""
    read -p "Press Enter to continue..."
}

# Uninstall simulation receiver
uninstall_simulation_receiver() {
    print_banner
    echo -e "${BOLD}${RED}Uninstall Simulation Receiver${NC}"
    echo ""
    echo -e "${YELLOW}This will remove:${NC}"
    echo "  - Simulation receiver service"
    echo "  - Simulation receiver script"
    echo "  - Configuration files"
    echo ""
    echo -n -e "${RED}Are you sure you want to uninstall? [y/N]: ${NC}"
    read CONFIRM

    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Uninstall cancelled.${NC}"
        read -p "Press Enter to continue..."
        return
    fi

    echo ""
    echo -e "${YELLOW}Stopping service...${NC}"
    systemctl stop ssh-guardian-sim-receiver 2>/dev/null || true
    systemctl disable ssh-guardian-sim-receiver 2>/dev/null || true

    echo -e "${YELLOW}Removing files...${NC}"
    rm -f /etc/systemd/system/ssh-guardian-sim-receiver.service
    rm -f /opt/ssh-guardian/simulation_receiver.py
    rm -f /etc/ssh-guardian/sim_receiver.env

    # Remove directory if empty
    rmdir /opt/ssh-guardian 2>/dev/null || true

    systemctl daemon-reload

    echo ""
    echo -e "${GREEN}Simulation Receiver uninstalled successfully!${NC}"
    read -p "Press Enter to continue..."
}

# Main loop
main() {
    check_root

    while true; do
        show_menu
        read choice

        # Handle simulation receiver options (available if installed)
        if [ -f "/opt/ssh-guardian/simulation_receiver.py" ]; then
            case $choice in
                9) test_simulation_receiver; continue ;;
                10) show_simulation_api_key; continue ;;
                11) restart_simulation_receiver; continue ;;
                12) view_simulation_logs; continue ;;
                13) uninstall_simulation_receiver; continue ;;
            esac
        fi

        if check_status; then
            case $choice in
                1) install_agent ;;
                2) uninstall_agent ;;
                3) restart_service ;;
                4) view_logs ;;
                5) reconfigure_server ;;
                6) update_api_key ;;
                7) test_connection ;;
                8) view_fail2ban ;;
                14) install_simulation_receiver ;;
                0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
                *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
            esac
        else
            case $choice in
                1) install_agent ;;
                14) install_simulation_receiver ;;
                0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
                *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
            esac
        fi
    done
}

main
