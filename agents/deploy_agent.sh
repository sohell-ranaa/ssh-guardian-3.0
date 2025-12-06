#!/bin/bash
#
# SSH Guardian v3.0 - Agent Deployment Script
# This script deploys/updates the standalone agent with UFW support
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_FILE="$SCRIPT_DIR/ssh_guardian_agent_standalone.py"
INSTALL_DIR="/opt/ssh-guardian"
SERVICE_NAME="ssh-guardian-agent"
CONFIG_DIR="/etc/ssh-guardian"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "========================================"
echo "  SSH Guardian v3.0 - Agent Deployment"
echo "========================================"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root${NC}"
    exit 1
fi

# Check if agent file exists
if [ ! -f "$AGENT_FILE" ]; then
    echo -e "${RED}Error: Agent file not found: $AGENT_FILE${NC}"
    exit 1
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"

# Stop existing service if running
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo -e "${YELLOW}Stopping existing agent service...${NC}"
    systemctl stop "$SERVICE_NAME"
fi

# Copy agent file
echo -e "${YELLOW}Installing agent...${NC}"
cp "$AGENT_FILE" "$INSTALL_DIR/agent.py"
chmod +x "$INSTALL_DIR/agent.py"

# Check for existing config
if [ -f "$CONFIG_DIR/agent.json" ]; then
    echo -e "${GREEN}Found existing configuration at $CONFIG_DIR/agent.json${NC}"
else
    echo -e "${YELLOW}No configuration found. Creating template...${NC}"
    cat > "$CONFIG_DIR/agent.json" << 'EOF'
{
    "server_url": "http://YOUR_DASHBOARD_IP:8081",
    "api_key": "YOUR_API_KEY",
    "firewall_enabled": true,
    "firewall_sync_interval": 60,
    "heartbeat_interval": 30,
    "check_interval": 5,
    "batch_size": 50
}
EOF
    echo -e "${YELLOW}Please edit $CONFIG_DIR/agent.json with your settings${NC}"
fi

# Install Python dependencies
echo -e "${YELLOW}Checking Python dependencies...${NC}"
pip3 install requests psutil >/dev/null 2>&1 || apt-get install -y python3-requests python3-psutil

# Create/update systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=SSH Guardian v3.0 Agent with UFW Support
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py --config $CONFIG_DIR/agent.json
Restart=always
RestartSec=10
User=root
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

# Enable service
systemctl enable "$SERVICE_NAME"

echo ""
echo -e "${GREEN}========================================"
echo "  Deployment Complete!"
echo "========================================${NC}"
echo ""
echo "Agent installed to: $INSTALL_DIR/agent.py"
echo "Config file: $CONFIG_DIR/agent.json"
echo "Service name: $SERVICE_NAME"
echo ""
echo "Commands:"
echo "  Start:   systemctl start $SERVICE_NAME"
echo "  Stop:    systemctl stop $SERVICE_NAME"
echo "  Status:  systemctl status $SERVICE_NAME"
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
echo ""

# Check if config is ready
if grep -q "YOUR_API_KEY" "$CONFIG_DIR/agent.json" 2>/dev/null; then
    echo -e "${YELLOW}NOTE: Please update $CONFIG_DIR/agent.json with your dashboard URL and API key before starting${NC}"
else
    echo -e "${GREEN}Starting agent service...${NC}"
    systemctl start "$SERVICE_NAME"
    sleep 2
    systemctl status "$SERVICE_NAME" --no-pager
fi
