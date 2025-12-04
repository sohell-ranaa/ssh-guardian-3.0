#!/bin/bash
#######################################################################
# SSH Guardian v3.0 - Agent Installation Script
# Install the agent on Ubuntu/Debian servers to collect SSH logs
#######################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/ssh-guardian-agent"
CONFIG_DIR="/etc/ssh-guardian"
LOG_DIR="/var/log/ssh-guardian"
STATE_DIR="/var/lib/ssh-guardian"
SERVICE_NAME="ssh-guardian-agent"

# Print functions
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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check Ubuntu/Debian
check_os() {
    if [[ ! -f /etc/debian_version ]]; then
        print_error "This installer is designed for Ubuntu/Debian systems"
        exit 1
    fi
    print_success "Detected Ubuntu/Debian system"
}

# Install dependencies
install_dependencies() {
    print_header "Installing Dependencies"

    print_info "Updating package lists..."
    apt-get update -qq

    print_info "Installing Python 3 and pip..."
    apt-get install -y python3 python3-pip python3-venv curl wget > /dev/null 2>&1

    print_success "Dependencies installed"
}

# Get configuration from user
get_configuration() {
    print_header "Configuration"

    # Server URL
    echo -n "Enter SSH Guardian Server URL (e.g., http://192.168.1.100:8081): "
    read SERVER_URL

    # API Key
    echo -n "Enter API Key: "
    read -s API_KEY
    echo

    # Agent ID (optional)
    HOSTNAME=$(hostname)
    MAC=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address 2>/dev/null || echo "unknown")
    DEFAULT_AGENT_ID="${HOSTNAME}-${MAC//:/}"

    echo -n "Enter Agent ID (press Enter for default: $DEFAULT_AGENT_ID): "
    read CUSTOM_AGENT_ID
    AGENT_ID=${CUSTOM_AGENT_ID:-$DEFAULT_AGENT_ID}

    print_success "Configuration collected"
}

# Create directories
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

# Install agent files
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

    # Create virtual environment
    print_info "Creating Python virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"

    # Install Python dependencies
    print_info "Installing Python packages..."
    "$INSTALL_DIR/venv/bin/pip" install --upgrade pip > /dev/null 2>&1
    "$INSTALL_DIR/venv/bin/pip" install requests > /dev/null 2>&1

    print_success "Python environment configured"
}

# Create configuration file
create_config() {
    print_header "Creating Configuration"

    cat > "$CONFIG_DIR/agent.json" <<EOF
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
  "log_file": "$LOG_DIR/agent.log"
}
EOF

    chmod 600 "$CONFIG_DIR/agent.json"
    print_success "Configuration file created: $CONFIG_DIR/agent.json"
}

# Create systemd service
create_systemd_service() {
    print_header "Creating Systemd Service"

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SSH Guardian Agent v3.0
After=network.target syslog.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
Environment="PYTHONUNBUFFERED=1"
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/ssh_guardian_agent.py --config $CONFIG_DIR/agent.json
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

# Test connection
test_connection() {
    print_header "Testing Connection"

    print_info "Testing connection to $SERVER_URL..."

    # Simple curl test
    if curl -s --connect-timeout 5 "$SERVER_URL" > /dev/null 2>&1; then
        print_success "Server is reachable"
        return 0
    else
        print_warning "Cannot reach server. Make sure the server is running and the URL is correct."
        return 1
    fi
}

# Start service
start_service() {
    print_header "Starting Service"

    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "Service started successfully"
    else
        print_error "Service failed to start. Check logs:"
        print_info "journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

# Show status
show_status() {
    print_header "Installation Complete!"

    echo -e "${GREEN}Agent is now running!${NC}"
    echo
    echo "📝 Configuration:"
    echo "   - Agent ID: $AGENT_ID"
    echo "   - Server: $SERVER_URL"
    echo "   - Config: $CONFIG_DIR/agent.json"
    echo
    echo "📊 Useful Commands:"
    echo "   - Status:  systemctl status $SERVICE_NAME"
    echo "   - Logs:    journalctl -u $SERVICE_NAME -f"
    echo "   - Stop:    systemctl stop $SERVICE_NAME"
    echo "   - Start:   systemctl start $SERVICE_NAME"
    echo "   - Restart: systemctl restart $SERVICE_NAME"
    echo
    echo "📁 Directories:"
    echo "   - Install: $INSTALL_DIR"
    echo "   - Config:  $CONFIG_DIR"
    echo "   - Logs:    $LOG_DIR"
    echo "   - State:   $STATE_DIR"
    echo
}

# Uninstall function
uninstall() {
    print_header "Uninstalling SSH Guardian Agent"

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME"
        print_success "Service stopped"
    fi

    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload

    print_info "Remove directories? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
        rm -rf "$LOG_DIR"
        rm -rf "$STATE_DIR"
        print_warning "Keeping config directory: $CONFIG_DIR (remove manually if needed)"
        print_success "Directories removed"
    fi

    print_success "Uninstallation complete"
}

# Main installation flow
main() {
    print_header "SSH Guardian v3.0 - Agent Installer"

    # Check if uninstall flag
    if [[ "$1" == "--uninstall" ]]; then
        check_root
        uninstall
        exit 0
    fi

    # Installation steps
    check_root
    check_os
    install_dependencies
    get_configuration
    create_directories
    install_agent
    create_config
    create_systemd_service
    test_connection
    start_service
    show_status
}

# Run main function
main "$@"
