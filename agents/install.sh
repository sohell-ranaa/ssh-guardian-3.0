#!/bin/bash
#######################################################################
# SSH Guardian v3.0 - Agent Management Script
# Install, uninstall, and manage the agent on Ubuntu/Debian servers
#######################################################################

set -e

# Version
VERSION="3.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/ssh-guardian-agent"
CONFIG_DIR="/etc/ssh-guardian"
LOG_DIR="/var/log/ssh-guardian"
STATE_DIR="/var/lib/ssh-guardian"
SERVICE_NAME="ssh-guardian-agent"
CONFIG_FILE="$CONFIG_DIR/agent.json"
STATE_FILE="$STATE_DIR/agent-state.json"

# ============================================================================
# PRINT FUNCTIONS
# ============================================================================

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_dim() {
    echo -e "${CYAN}   $1${NC}"
}

# ============================================================================
# USAGE / HELP
# ============================================================================

show_usage() {
    echo -e "${BOLD}SSH Guardian Agent Manager v${VERSION}${NC}"
    echo
    echo -e "${BOLD}Usage:${NC}"
    echo "  $0 [command] [options]"
    echo
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}install${NC}      Install the SSH Guardian agent (default)"
    echo -e "  ${RED}uninstall${NC}    Completely remove the agent"
    echo -e "  ${CYAN}status${NC}       Show detailed agent status"
    echo -e "  ${YELLOW}start${NC}        Start the agent service"
    echo -e "  ${YELLOW}stop${NC}         Stop the agent service"
    echo -e "  ${YELLOW}restart${NC}      Restart the agent service"
    echo -e "  ${MAGENTA}logs${NC}         Show agent logs (live tail)"
    echo -e "  ${MAGENTA}logs-full${NC}    Show full agent logs"
    echo -e "  ${BLUE}config${NC}       Show current configuration"
    echo -e "  ${BLUE}edit-config${NC}  Edit configuration file"
    echo -e "  ${CYAN}test${NC}         Test connection to server"
    echo -e "  ${CYAN}health${NC}       Run health checks"
    echo -e "  ${YELLOW}update${NC}       Update agent to latest version"
    echo -e "  ${MAGENTA}info${NC}         Show installation info"
    echo -e "  ${BOLD}help${NC}         Show this help message"
    echo
    echo -e "${BOLD}Options:${NC}"
    echo "  --force, -f       Force operation without confirmation"
    echo "  --keep-config     Keep config during uninstall"
    echo "  --keep-logs       Keep logs during uninstall"
    echo "  --purge           Remove everything including config"
    echo "  --quiet, -q       Minimal output"
    echo
    echo -e "${BOLD}Examples:${NC}"
    echo "  sudo $0 install          # Install the agent"
    echo "  sudo $0 status           # Check agent status"
    echo "  sudo $0 uninstall        # Remove agent (keep config)"
    echo "  sudo $0 uninstall --purge  # Remove everything"
    echo "  sudo $0 logs             # Tail agent logs"
    echo "  sudo $0 restart          # Restart agent"
    echo
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This installer is designed for Ubuntu/Debian systems"
        exit 1
    fi
    print_success "Detected Ubuntu/Debian system"
}

is_installed() {
    [[ -f "$INSTALL_DIR/ssh_guardian_agent.py" ]] && [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]
}

is_running() {
    systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null
}

is_enabled() {
    systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null
}

get_config_value() {
    local key="$1"
    if [[ -f "$CONFIG_FILE" ]]; then
        python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('$key', ''))" 2>/dev/null || echo ""
    fi
}

get_state_value() {
    local key="$1"
    if [[ -f "$STATE_FILE" ]]; then
        python3 -c "import json; print(json.load(open('$STATE_FILE')).get('$key', ''))" 2>/dev/null || echo ""
    fi
}

confirm_action() {
    local message="$1"
    if [[ "$FORCE" == "true" ]]; then
        return 0
    fi
    echo -n -e "${YELLOW}$message (y/N): ${NC}"
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

# ============================================================================
# STATUS COMMAND
# ============================================================================

cmd_status() {
    print_header "SSH Guardian Agent Status"
    echo

    # Installation status
    echo -e "${BOLD}Installation:${NC}"
    if is_installed; then
        print_success "Agent is installed"
        print_dim "Install directory: $INSTALL_DIR"
        print_dim "Config directory: $CONFIG_DIR"

        # Check Python venv
        if [[ -f "$INSTALL_DIR/venv/bin/python3" ]]; then
            local py_version=$("$INSTALL_DIR/venv/bin/python3" --version 2>&1)
            print_dim "Python: $py_version"
        fi
    else
        print_error "Agent is NOT installed"
        echo
        echo "Run: sudo $0 install"
        return 1
    fi
    echo

    # Service status
    echo -e "${BOLD}Service Status:${NC}"
    if is_running; then
        print_success "Service is RUNNING"
        local pid=$(systemctl show -p MainPID --value "$SERVICE_NAME" 2>/dev/null)
        local uptime=$(ps -o etime= -p "$pid" 2>/dev/null | xargs)
        print_dim "PID: $pid"
        print_dim "Uptime: $uptime"

        # Memory usage
        local mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        print_dim "Memory: $mem"
    else
        print_error "Service is STOPPED"
    fi

    if is_enabled; then
        print_dim "Auto-start: enabled"
    else
        print_warning "Auto-start: disabled"
    fi
    echo

    # Configuration
    echo -e "${BOLD}Configuration:${NC}"
    if [[ -f "$CONFIG_FILE" ]]; then
        local server_url=$(get_config_value "server_url")
        local agent_id=$(get_config_value "agent_id")
        local hostname=$(get_config_value "hostname")
        local check_interval=$(get_config_value "check_interval")
        local batch_size=$(get_config_value "batch_size")

        print_dim "Server URL: $server_url"
        print_dim "Agent ID: $agent_id"
        print_dim "Hostname: $hostname"
        print_dim "Check interval: ${check_interval}s"
        print_dim "Batch size: $batch_size"
    else
        print_warning "Config file not found: $CONFIG_FILE"
    fi
    echo

    # State / Statistics
    echo -e "${BOLD}Statistics:${NC}"
    if [[ -f "$STATE_FILE" ]]; then
        local total_logs=$(get_state_value "total_logs_sent")
        local total_batches=$(get_state_value "total_batches_sent")
        local last_heartbeat=$(get_state_value "last_heartbeat")
        local start_time=$(get_state_value "agent_start_time")

        print_dim "Total logs sent: ${total_logs:-0}"
        print_dim "Total batches: ${total_batches:-0}"
        print_dim "Last heartbeat: ${last_heartbeat:-never}"
        print_dim "Agent started: ${start_time:-unknown}"
    else
        print_dim "No state file (agent hasn't run yet)"
    fi
    echo

    # Server connectivity
    echo -e "${BOLD}Server Connection:${NC}"
    local server_url=$(get_config_value "server_url")
    if [[ -n "$server_url" ]]; then
        if curl -s --connect-timeout 3 "$server_url" > /dev/null 2>&1; then
            print_success "Server reachable: $server_url"
        else
            print_error "Cannot reach server: $server_url"
        fi
    else
        print_warning "Server URL not configured"
    fi
    echo

    # Log files
    echo -e "${BOLD}Log Files:${NC}"
    if [[ -f "$LOG_DIR/agent.log" ]]; then
        local log_size=$(du -h "$LOG_DIR/agent.log" 2>/dev/null | cut -f1)
        local log_lines=$(wc -l < "$LOG_DIR/agent.log" 2>/dev/null)
        print_dim "Agent log: $LOG_DIR/agent.log ($log_size, $log_lines lines)"
    fi
    if [[ -f "$LOG_DIR/service.log" ]]; then
        local log_size=$(du -h "$LOG_DIR/service.log" 2>/dev/null | cut -f1)
        print_dim "Service log: $LOG_DIR/service.log ($log_size)"
    fi
    echo

    # Auth log monitoring
    echo -e "${BOLD}Auth Log Monitoring:${NC}"
    local auth_log="/var/log/auth.log"
    if [[ -f "$auth_log" ]]; then
        print_success "Auth log exists: $auth_log"
        local auth_size=$(du -h "$auth_log" 2>/dev/null | cut -f1)
        print_dim "Size: $auth_size"

        # Check if readable
        if [[ -r "$auth_log" ]]; then
            print_dim "Readable: yes"
        else
            print_warning "Not readable by current user"
        fi
    else
        print_error "Auth log not found: $auth_log"
    fi
    echo

    # Recent errors
    echo -e "${BOLD}Recent Issues:${NC}"
    if [[ -f "$LOG_DIR/agent.log" ]]; then
        local errors=$(grep -i "error\|failed\|exception" "$LOG_DIR/agent.log" 2>/dev/null | tail -3)
        if [[ -n "$errors" ]]; then
            print_warning "Recent errors found:"
            echo "$errors" | while read -r line; do
                print_dim "$line"
            done
        else
            print_success "No recent errors"
        fi
    fi
    echo
}

# ============================================================================
# HEALTH CHECK COMMAND
# ============================================================================

cmd_health() {
    print_header "Agent Health Check"
    echo

    local issues=0

    # Check 1: Installation
    echo -e "${BOLD}[1/8] Installation${NC}"
    if is_installed; then
        print_success "Agent files present"
    else
        print_error "Agent not installed"
        ((issues++))
    fi

    # Check 2: Service file
    echo -e "${BOLD}[2/8] Service Configuration${NC}"
    if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
        print_success "Systemd service configured"
    else
        print_error "Systemd service missing"
        ((issues++))
    fi

    # Check 3: Config file
    echo -e "${BOLD}[3/8] Configuration File${NC}"
    if [[ -f "$CONFIG_FILE" ]]; then
        # Validate JSON
        if python3 -c "import json; json.load(open('$CONFIG_FILE'))" 2>/dev/null; then
            print_success "Config file valid"
        else
            print_error "Config file is invalid JSON"
            ((issues++))
        fi
    else
        print_error "Config file missing"
        ((issues++))
    fi

    # Check 4: Python environment
    echo -e "${BOLD}[4/8] Python Environment${NC}"
    if [[ -f "$INSTALL_DIR/venv/bin/python3" ]]; then
        if "$INSTALL_DIR/venv/bin/python3" -c "import requests" 2>/dev/null; then
            print_success "Python environment OK"
        else
            print_error "Missing Python dependencies"
            ((issues++))
        fi
    else
        print_error "Python venv not found"
        ((issues++))
    fi

    # Check 5: Service running
    echo -e "${BOLD}[5/8] Service Status${NC}"
    if is_running; then
        print_success "Service is running"
    else
        print_error "Service is not running"
        ((issues++))
    fi

    # Check 6: Server connectivity
    echo -e "${BOLD}[6/8] Server Connectivity${NC}"
    local server_url=$(get_config_value "server_url")
    if [[ -n "$server_url" ]]; then
        if curl -s --connect-timeout 5 "$server_url" > /dev/null 2>&1; then
            print_success "Server reachable"
        else
            print_error "Cannot reach server: $server_url"
            ((issues++))
        fi
    else
        print_warning "Server URL not configured"
        ((issues++))
    fi

    # Check 7: Auth log access
    echo -e "${BOLD}[7/8] Auth Log Access${NC}"
    if [[ -r "/var/log/auth.log" ]]; then
        print_success "Auth log readable"
    else
        print_error "Cannot read /var/log/auth.log"
        ((issues++))
    fi

    # Check 8: Disk space
    echo -e "${BOLD}[8/8] Disk Space${NC}"
    local disk_usage=$(df "$INSTALL_DIR" 2>/dev/null | tail -1 | awk '{print $5}' | tr -d '%')
    if [[ -n "$disk_usage" ]] && [[ "$disk_usage" -lt 90 ]]; then
        print_success "Disk usage OK (${disk_usage}%)"
    else
        print_warning "Disk usage high: ${disk_usage}%"
        ((issues++))
    fi

    echo
    echo -e "${BOLD}Summary:${NC}"
    if [[ $issues -eq 0 ]]; then
        print_success "All health checks passed!"
    else
        print_error "$issues issue(s) found"
    fi
    echo

    return $issues
}

# ============================================================================
# TEST CONNECTION COMMAND
# ============================================================================

cmd_test() {
    print_header "Testing Server Connection"
    echo

    local server_url=$(get_config_value "server_url")
    local api_key=$(get_config_value "api_key")
    local agent_id=$(get_config_value "agent_id")

    if [[ -z "$server_url" ]]; then
        print_error "Server URL not configured"
        return 1
    fi

    print_info "Server: $server_url"
    print_info "Agent ID: $agent_id"
    echo

    # Test 1: Basic connectivity
    echo -e "${BOLD}[1/3] Basic Connectivity${NC}"
    if curl -s --connect-timeout 5 "$server_url" > /dev/null 2>&1; then
        print_success "Server is reachable"
    else
        print_error "Cannot connect to server"
        return 1
    fi

    # Test 2: API health endpoint
    echo -e "${BOLD}[2/3] API Health Check${NC}"
    local health_response=$(curl -s --connect-timeout 5 "$server_url/api/health" 2>/dev/null || echo "")
    if [[ -n "$health_response" ]]; then
        print_success "API responding"
        print_dim "Response: $health_response"
    else
        print_warning "API health endpoint not available (may be normal)"
    fi

    # Test 3: Agent registration endpoint
    echo -e "${BOLD}[3/3] Registration Endpoint${NC}"
    local reg_response=$(curl -s --connect-timeout 5 -X POST \
        -H "Content-Type: application/json" \
        -d "{\"agent_id\": \"$agent_id\", \"hostname\": \"$(hostname)\", \"version\": \"$VERSION\"}" \
        "$server_url/api/agents/register" 2>/dev/null || echo "")

    if [[ -n "$reg_response" ]]; then
        if echo "$reg_response" | grep -q "success"; then
            print_success "Registration endpoint OK"
        else
            print_warning "Registration response: $reg_response"
        fi
    else
        print_error "Cannot reach registration endpoint"
    fi

    echo
}

# ============================================================================
# LOGS COMMAND
# ============================================================================

cmd_logs() {
    local full="$1"

    if [[ "$full" == "full" ]]; then
        print_header "Full Agent Logs"
        if [[ -f "$LOG_DIR/agent.log" ]]; then
            less "$LOG_DIR/agent.log"
        else
            journalctl -u "$SERVICE_NAME" --no-pager
        fi
    else
        print_header "Agent Logs (Ctrl+C to exit)"
        if [[ -f "$LOG_DIR/agent.log" ]]; then
            tail -f "$LOG_DIR/agent.log"
        else
            journalctl -u "$SERVICE_NAME" -f
        fi
    fi
}

# ============================================================================
# CONFIG COMMANDS
# ============================================================================

cmd_config() {
    print_header "Current Configuration"
    echo

    if [[ -f "$CONFIG_FILE" ]]; then
        cat "$CONFIG_FILE" | python3 -m json.tool 2>/dev/null || cat "$CONFIG_FILE"
    else
        print_error "Config file not found: $CONFIG_FILE"
        return 1
    fi
    echo
}

cmd_edit_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        ${EDITOR:-nano} "$CONFIG_FILE"
        print_info "Config edited. Restart the agent to apply changes:"
        echo "  sudo $0 restart"
    else
        print_error "Config file not found: $CONFIG_FILE"
        return 1
    fi
}

# ============================================================================
# INFO COMMAND
# ============================================================================

cmd_info() {
    print_header "Installation Information"
    echo

    echo -e "${BOLD}Directories:${NC}"
    echo "  Install:  $INSTALL_DIR"
    echo "  Config:   $CONFIG_DIR"
    echo "  Logs:     $LOG_DIR"
    echo "  State:    $STATE_DIR"
    echo

    echo -e "${BOLD}Files:${NC}"
    echo "  Agent script:  $INSTALL_DIR/ssh_guardian_agent.py"
    echo "  Config file:   $CONFIG_FILE"
    echo "  State file:    $STATE_FILE"
    echo "  Service file:  /etc/systemd/system/${SERVICE_NAME}.service"
    echo

    echo -e "${BOLD}Commands:${NC}"
    echo "  Status:   systemctl status $SERVICE_NAME"
    echo "  Start:    systemctl start $SERVICE_NAME"
    echo "  Stop:     systemctl stop $SERVICE_NAME"
    echo "  Restart:  systemctl restart $SERVICE_NAME"
    echo "  Logs:     journalctl -u $SERVICE_NAME -f"
    echo

    echo -e "${BOLD}Disk Usage:${NC}"
    if [[ -d "$INSTALL_DIR" ]]; then
        du -sh "$INSTALL_DIR" 2>/dev/null | awk '{print "  Install dir: " $1}'
    fi
    if [[ -d "$LOG_DIR" ]]; then
        du -sh "$LOG_DIR" 2>/dev/null | awk '{print "  Log dir:     " $1}'
    fi
    if [[ -d "$STATE_DIR" ]]; then
        du -sh "$STATE_DIR" 2>/dev/null | awk '{print "  State dir:   " $1}'
    fi
    echo
}

# ============================================================================
# SERVICE CONTROL COMMANDS
# ============================================================================

cmd_start() {
    print_header "Starting Agent"

    if ! is_installed; then
        print_error "Agent is not installed"
        return 1
    fi

    if is_running; then
        print_warning "Agent is already running"
        return 0
    fi

    systemctl start "$SERVICE_NAME"
    sleep 2

    if is_running; then
        print_success "Agent started successfully"
        local pid=$(systemctl show -p MainPID --value "$SERVICE_NAME")
        print_info "PID: $pid"
    else
        print_error "Failed to start agent"
        print_info "Check logs: journalctl -u $SERVICE_NAME -n 50"
        return 1
    fi
}

cmd_stop() {
    print_header "Stopping Agent"

    if ! is_running; then
        print_warning "Agent is not running"
        return 0
    fi

    systemctl stop "$SERVICE_NAME"
    sleep 1

    if ! is_running; then
        print_success "Agent stopped"
    else
        print_error "Failed to stop agent"
        return 1
    fi
}

cmd_restart() {
    print_header "Restarting Agent"

    if ! is_installed; then
        print_error "Agent is not installed"
        return 1
    fi

    systemctl restart "$SERVICE_NAME"
    sleep 2

    if is_running; then
        print_success "Agent restarted successfully"
        local pid=$(systemctl show -p MainPID --value "$SERVICE_NAME")
        print_info "PID: $pid"
    else
        print_error "Failed to restart agent"
        print_info "Check logs: journalctl -u $SERVICE_NAME -n 50"
        return 1
    fi
}

# ============================================================================
# INSTALL COMMAND
# ============================================================================

install_dependencies() {
    print_header "Installing Dependencies"

    print_info "Updating package lists..."
    apt-get update -qq

    print_info "Installing Python 3 and pip..."
    apt-get install -y python3 python3-pip python3-venv curl wget > /dev/null 2>&1

    print_info "Installing UFW (firewall)..."
    apt-get install -y ufw > /dev/null 2>&1

    print_success "Dependencies installed"
}

# ============================================================================
# FIREWALL SETUP (UFW)
# ============================================================================

setup_firewall() {
    print_header "Firewall Configuration"
    echo

    # Check if UFW is installed
    if ! command -v ufw &> /dev/null; then
        print_error "UFW is not installed. Installing..."
        apt-get install -y ufw > /dev/null 2>&1
    fi

    # Check current UFW status
    local ufw_status=$(ufw status | head -1)
    print_info "Current firewall status: $ufw_status"
    echo

    # Show current rules if active
    if ufw status | grep -q "Status: active"; then
        print_info "Current firewall rules:"
        ufw status numbered
        echo
    fi

    # Essential ports explanation
    echo -e "${BOLD}Essential Ports for SSH Guardian:${NC}"
    echo "  - Port 22 (SSH) - Required for remote access"
    echo "  - Port 8081 - SSH Guardian Dashboard (if running locally)"
    echo

    # Ask user about firewall setup
    echo -e "${YELLOW}Firewall setup is recommended to secure your server.${NC}"
    echo
    echo "Options:"
    echo "  1) Quick Setup - Enable UFW with SSH (22) only [Recommended for remote servers]"
    echo "  2) Custom Setup - Choose which ports to allow"
    echo "  3) Skip - Don't configure firewall (not recommended)"
    echo
    echo -n "Choose an option (1/2/3): "
    read fw_choice

    case "$fw_choice" in
        1)
            setup_firewall_quick
            ;;
        2)
            setup_firewall_custom
            ;;
        3)
            print_warning "Skipping firewall setup. You can configure it later with: sudo ufw enable"
            return 0
            ;;
        *)
            print_warning "Invalid choice. Skipping firewall setup."
            return 0
            ;;
    esac
}

setup_firewall_quick() {
    print_info "Setting up firewall with quick configuration..."
    echo

    # Reset UFW to defaults (but don't enable yet)
    print_info "Configuring UFW defaults..."
    ufw --force reset > /dev/null 2>&1

    # Set default policies
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1

    # Always allow SSH first (critical!)
    print_info "Allowing SSH (port 22)..."
    ufw allow 22/tcp > /dev/null 2>&1
    print_success "SSH (22) allowed"

    # Check if dashboard server URL is local, if so allow 8081
    if [[ "$SERVER_URL" == *"localhost"* ]] || [[ "$SERVER_URL" == *"127.0.0.1"* ]]; then
        print_info "Allowing SSH Guardian Dashboard (port 8081)..."
        ufw allow 8081/tcp > /dev/null 2>&1
        print_success "Dashboard (8081) allowed"
    fi

    # Enable UFW
    print_info "Enabling firewall..."
    echo "y" | ufw enable > /dev/null 2>&1

    echo
    print_success "Firewall enabled with the following rules:"
    ufw status numbered
    echo
}

setup_firewall_custom() {
    print_info "Custom firewall configuration"
    echo

    # Reset UFW to defaults
    print_info "Resetting UFW to defaults..."
    ufw --force reset > /dev/null 2>&1

    # Set default policies
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1

    # SSH is mandatory for remote servers
    echo -e "${BOLD}SSH (Port 22)${NC}"
    echo -n "Allow SSH access? (Y/n): "
    read allow_ssh
    if [[ ! "$allow_ssh" =~ ^[Nn]$ ]]; then
        ufw allow 22/tcp > /dev/null 2>&1
        print_success "SSH (22) allowed"
    else
        print_warning "WARNING: You may lose remote access if SSH is not allowed!"
        echo -n "Are you sure you don't want SSH? (y/N): "
        read confirm_no_ssh
        if [[ "$confirm_no_ssh" =~ ^[Yy]$ ]]; then
            print_warning "SSH not allowed - make sure you have console access!"
        else
            ufw allow 22/tcp > /dev/null 2>&1
            print_success "SSH (22) allowed"
        fi
    fi

    # Common ports menu
    echo
    echo -e "${BOLD}Select additional ports to allow:${NC}"
    echo

    # HTTP/HTTPS
    echo -n "Allow HTTP (80) and HTTPS (443)? (y/N): "
    read allow_http
    if [[ "$allow_http" =~ ^[Yy]$ ]]; then
        ufw allow 80/tcp > /dev/null 2>&1
        ufw allow 443/tcp > /dev/null 2>&1
        print_success "HTTP (80) and HTTPS (443) allowed"
    fi

    # SSH Guardian Dashboard
    echo -n "Allow SSH Guardian Dashboard (8081)? (y/N): "
    read allow_dashboard
    if [[ "$allow_dashboard" =~ ^[Yy]$ ]]; then
        ufw allow 8081/tcp > /dev/null 2>&1
        print_success "Dashboard (8081) allowed"
    fi

    # MySQL
    echo -n "Allow MySQL (3306)? (y/N): "
    read allow_mysql
    if [[ "$allow_mysql" =~ ^[Yy]$ ]]; then
        ufw allow 3306/tcp > /dev/null 2>&1
        print_success "MySQL (3306) allowed"
    fi

    # PostgreSQL
    echo -n "Allow PostgreSQL (5432)? (y/N): "
    read allow_postgres
    if [[ "$allow_postgres" =~ ^[Yy]$ ]]; then
        ufw allow 5432/tcp > /dev/null 2>&1
        print_success "PostgreSQL (5432) allowed"
    fi

    # Redis
    echo -n "Allow Redis (6379)? (y/N): "
    read allow_redis
    if [[ "$allow_redis" =~ ^[Yy]$ ]]; then
        ufw allow 6379/tcp > /dev/null 2>&1
        print_success "Redis (6379) allowed"
    fi

    # Custom ports
    echo
    echo -n "Enter any additional ports to allow (comma-separated, e.g., 3000,8080,9000) or press Enter to skip: "
    read custom_ports
    if [[ -n "$custom_ports" ]]; then
        IFS=',' read -ra PORTS <<< "$custom_ports"
        for port in "${PORTS[@]}"; do
            port=$(echo "$port" | tr -d ' ')
            if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
                ufw allow "$port/tcp" > /dev/null 2>&1
                print_success "Port $port allowed"
            else
                print_warning "Invalid port: $port (skipped)"
            fi
        done
    fi

    # Enable UFW
    echo
    echo -e "${BOLD}Review your firewall rules:${NC}"
    ufw status numbered
    echo

    echo -n "Enable firewall with these rules? (Y/n): "
    read enable_fw
    if [[ ! "$enable_fw" =~ ^[Nn]$ ]]; then
        print_info "Enabling firewall..."
        echo "y" | ufw enable > /dev/null 2>&1
        print_success "Firewall enabled!"
    else
        print_warning "Firewall NOT enabled. Enable manually with: sudo ufw enable"
    fi

    echo
    print_success "Firewall configuration complete"
    ufw status
    echo
}

get_configuration() {
    print_header "Configuration"

    # Server URL
    echo -n "Enter SSH Guardian Server URL (e.g., http://192.168.1.100:8081): "
    read SERVER_URL

    if [[ -z "$SERVER_URL" ]]; then
        print_error "Server URL is required"
        exit 1
    fi

    # API Key (optional - will be auto-generated by server if not provided)
    echo -n "Enter API Key (press Enter to auto-generate during registration): "
    read -s API_KEY
    echo

    # Use placeholder if not provided - server will generate actual key
    if [[ -z "$API_KEY" ]]; then
        API_KEY="auto-generate-on-registration"
        print_info "API key will be auto-generated during registration"
    fi

    # Agent ID (optional)
    HOSTNAME=$(hostname)
    MAC=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address 2>/dev/null || echo "unknown")
    DEFAULT_AGENT_ID="${HOSTNAME}-${MAC//:/}"

    echo -n "Enter Agent ID (press Enter for default: $DEFAULT_AGENT_ID): "
    read CUSTOM_AGENT_ID
    AGENT_ID=${CUSTOM_AGENT_ID:-$DEFAULT_AGENT_ID}

    print_success "Configuration collected"
}

create_directories() {
    print_header "Creating Directories"

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$STATE_DIR"

    chmod 755 "$INSTALL_DIR"
    chmod 750 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"
    chmod 750 "$STATE_DIR"

    print_success "Directories created"
}

install_agent() {
    print_header "Installing Agent"

    # Copy agent script
    if [[ -f "ssh_guardian_agent.py" ]]; then
        cp ssh_guardian_agent.py "$INSTALL_DIR/"
        chmod +x "$INSTALL_DIR/ssh_guardian_agent.py"
        print_success "Agent script installed"
    else
        print_error "ssh_guardian_agent.py not found in current directory"
        exit 1
    fi

    # Copy firewall collector if exists
    if [[ -f "firewall_collector.py" ]]; then
        cp firewall_collector.py "$INSTALL_DIR/"
        print_success "Firewall collector installed"
    fi

    # Create virtual environment
    print_info "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"

    # Install Python dependencies
    print_info "Installing Python packages..."
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip > /dev/null 2>&1
    "$INSTALL_DIR/venv/bin/pip" install requests > /dev/null 2>&1

    print_success "Python environment configured"
}

create_config() {
    print_header "Creating Configuration"

    cat > "$CONFIG_FILE" <<EOF
{
  "server_url": "$SERVER_URL",
  "api_key": "$API_KEY",
  "agent_id": "$AGENT_ID",
  "hostname": "$(hostname)",
  "check_interval": 30,
  "batch_size": 100,
  "heartbeat_interval": 60,
  "auth_log_path": "/var/log/auth.log",
  "state_file": "$STATE_DIR/agent-state.json",
  "log_file": "$LOG_DIR/agent.log",
  "firewall_enabled": true,
  "firewall_sync_interval": 300
}
EOF

    chmod 600 "$CONFIG_FILE"
    print_success "Configuration file created: $CONFIG_FILE"
}

create_systemd_service() {
    print_header "Creating Systemd Service"

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SSH Guardian Agent v${VERSION}
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PYTHONUNBUFFERED=1"
Environment="SSH_GUARDIAN_CONFIG=$CONFIG_FILE"
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/ssh_guardian_agent.py --config $CONFIG_FILE
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/service.log
StandardError=append:$LOG_DIR/service.log

# Security
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service created"
}

test_connection() {
    print_header "Testing Connection"

    print_info "Testing connection to $SERVER_URL..."

    if curl -s --connect-timeout 5 "$SERVER_URL" > /dev/null 2>&1; then
        print_success "Server is reachable"
        return 0
    else
        print_warning "Cannot reach server. Make sure the server is running and the URL is correct."
        return 1
    fi
}

start_service() {
    print_header "Starting Service"

    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    sleep 2

    if is_running; then
        print_success "Service started successfully"
    else
        print_error "Service failed to start. Check logs:"
        print_info "journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

show_install_complete() {
    print_header "Installation Complete!"

    echo -e "${GREEN}Agent is now running!${NC}"
    echo
    echo -e "${BOLD}Next Steps:${NC}"
    echo "  1. Approve this agent in the SSH Guardian dashboard"
    echo "  2. The agent will start sending logs once approved"
    echo
    echo -e "${BOLD}Configuration:${NC}"
    echo "   Agent ID: $AGENT_ID"
    echo "   Server:   $SERVER_URL"
    echo "   Config:   $CONFIG_FILE"
    echo

    # Show firewall status
    echo -e "${BOLD}Firewall Status:${NC}"
    if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
        echo "   UFW: Active"
        ufw status | grep -E "^\s*[0-9]+|ALLOW" | head -5 | while read line; do
            echo "   $line"
        done
    else
        echo "   UFW: Not enabled"
    fi
    echo

    echo -e "${BOLD}Useful Commands:${NC}"
    echo "   Status:  sudo $0 status"
    echo "   Logs:    sudo $0 logs"
    echo "   Health:  sudo $0 health"
    echo "   Restart: sudo $0 restart"
    echo "   Firewall: sudo ufw status"
    echo
}

cmd_install() {
    print_header "SSH Guardian v${VERSION} - Agent Installer"

    if is_installed; then
        print_warning "Agent is already installed"
        if ! confirm_action "Reinstall agent?"; then
            exit 0
        fi
        cmd_stop 2>/dev/null || true
    fi

    check_os
    install_dependencies
    get_configuration
    create_directories
    install_agent
    create_config
    create_systemd_service
    test_connection
    setup_firewall
    start_service
    show_install_complete
}

# ============================================================================
# UPDATE COMMAND
# ============================================================================

cmd_update() {
    print_header "Updating Agent"

    if ! is_installed; then
        print_error "Agent is not installed"
        return 1
    fi

    if [[ ! -f "ssh_guardian_agent.py" ]]; then
        print_error "ssh_guardian_agent.py not found in current directory"
        print_info "Please run this command from the directory containing the new agent files"
        return 1
    fi

    print_info "Stopping agent..."
    cmd_stop 2>/dev/null || true

    print_info "Backing up current agent..."
    cp "$INSTALL_DIR/ssh_guardian_agent.py" "$INSTALL_DIR/ssh_guardian_agent.py.bak"

    print_info "Installing new version..."
    cp ssh_guardian_agent.py "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/ssh_guardian_agent.py"

    if [[ -f "firewall_collector.py" ]]; then
        cp firewall_collector.py "$INSTALL_DIR/"
    fi

    print_info "Starting agent..."
    cmd_start

    print_success "Agent updated successfully"
}

# ============================================================================
# UNINSTALL COMMAND
# ============================================================================

cmd_uninstall() {
    print_header "Uninstalling SSH Guardian Agent"

    if ! is_installed; then
        print_warning "Agent is not installed"
        return 0
    fi

    if [[ "$FORCE" != "true" ]]; then
        echo
        print_warning "This will remove the SSH Guardian agent from this system."
        echo
        if ! confirm_action "Are you sure you want to uninstall?"; then
            print_info "Uninstall cancelled"
            return 0
        fi
    fi

    echo

    # Stop and disable service
    print_info "Stopping service..."
    if is_running; then
        systemctl stop "$SERVICE_NAME"
        print_success "Service stopped"
    fi

    print_info "Disabling service..."
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true

    # Remove service file
    print_info "Removing systemd service..."
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    print_success "Service removed"

    # Remove installation directory
    print_info "Removing installation directory..."
    rm -rf "$INSTALL_DIR"
    print_success "Installation directory removed"

    # Remove state directory
    print_info "Removing state directory..."
    rm -rf "$STATE_DIR"
    print_success "State directory removed"

    # Handle logs
    if [[ "$KEEP_LOGS" != "true" ]] && [[ "$PURGE" == "true" || "$FORCE" == "true" ]]; then
        print_info "Removing log directory..."
        rm -rf "$LOG_DIR"
        print_success "Log directory removed"
    elif [[ "$KEEP_LOGS" != "true" ]]; then
        if confirm_action "Remove log directory ($LOG_DIR)?"; then
            rm -rf "$LOG_DIR"
            print_success "Log directory removed"
        else
            print_info "Keeping log directory"
        fi
    else
        print_info "Keeping log directory (--keep-logs)"
    fi

    # Handle config
    if [[ "$KEEP_CONFIG" == "true" ]]; then
        print_info "Keeping config directory (--keep-config)"
    elif [[ "$PURGE" == "true" ]]; then
        print_info "Removing config directory..."
        rm -rf "$CONFIG_DIR"
        print_success "Config directory removed"
    else
        if confirm_action "Remove config directory ($CONFIG_DIR)?"; then
            rm -rf "$CONFIG_DIR"
            print_success "Config directory removed"
        else
            print_info "Keeping config directory"
        fi
    fi

    echo
    print_success "Uninstallation complete!"
    echo

    # Show what remains
    local remaining=""
    [[ -d "$CONFIG_DIR" ]] && remaining+="  - Config: $CONFIG_DIR\n"
    [[ -d "$LOG_DIR" ]] && remaining+="  - Logs: $LOG_DIR\n"

    if [[ -n "$remaining" ]]; then
        print_info "Remaining directories:"
        echo -e "$remaining"
        echo "Remove manually if needed: sudo rm -rf <directory>"
    fi
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

# Parse global options
FORCE="false"
KEEP_CONFIG="false"
KEEP_LOGS="false"
PURGE="false"
QUIET="false"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force|-f)
            FORCE="true"
            shift
            ;;
        --keep-config)
            KEEP_CONFIG="true"
            shift
            ;;
        --keep-logs)
            KEEP_LOGS="true"
            shift
            ;;
        --purge)
            PURGE="true"
            shift
            ;;
        --quiet|-q)
            QUIET="true"
            shift
            ;;
        --help|-h|help)
            show_usage
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# Get command (default: install)
COMMAND="${1:-install}"
shift 2>/dev/null || true

# Handle legacy --uninstall flag
if [[ "$COMMAND" == "--uninstall" ]]; then
    COMMAND="uninstall"
fi

# Execute command
case "$COMMAND" in
    install)
        check_root
        cmd_install
        ;;
    uninstall|remove)
        check_root
        cmd_uninstall
        ;;
    status)
        check_root
        cmd_status
        ;;
    start)
        check_root
        cmd_start
        ;;
    stop)
        check_root
        cmd_stop
        ;;
    restart)
        check_root
        cmd_restart
        ;;
    logs)
        cmd_logs
        ;;
    logs-full)
        cmd_logs "full"
        ;;
    config)
        cmd_config
        ;;
    edit-config)
        check_root
        cmd_edit_config
        ;;
    test)
        cmd_test
        ;;
    health|check)
        check_root
        cmd_health
        ;;
    update|upgrade)
        check_root
        cmd_update
        ;;
    info)
        cmd_info
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        echo
        show_usage
        exit 1
        ;;
esac
