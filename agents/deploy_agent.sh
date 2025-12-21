#!/bin/bash
# SSH Guardian Agent - Full Deployment & Management Script
# Installs and manages the full-featured agent

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

AGENT_DIR="/opt/ssh-guardian-agent"
CONFIG_DIR="/etc/ssh-guardian"
CONFIG_FILE="$CONFIG_DIR/agent.json"
SERVICE_NAME="ssh-guardian-agent"
LOG_FILE="/var/log/ssh-guardian/agent.log"

# Default server
DEFAULT_SERVER="http://31.220.94.187:8081"

print_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════╗"
    echo "║     SSH Guardian Agent - Management Console       ║"
    echo "╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Please run as root (sudo)${NC}"
        exit 1
    fi
}

check_installed() {
    [ -f "$AGENT_DIR/ssh_guardian_agent.py" ] && [ -f "$CONFIG_FILE" ]
}

get_config() {
    if [ -f "$CONFIG_FILE" ]; then
        AGENT_ID=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('agent_id', 'N/A'))" 2>/dev/null)
        SERVER_URL=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('server_url', 'N/A'))" 2>/dev/null)
        API_KEY=$(python3 -c "import json; print(json.load(open('$CONFIG_FILE')).get('api_key', ''))" 2>/dev/null)
    fi
}

show_status() {
    print_banner
    echo -e "${BOLD}Current Status:${NC}"
    echo ""

    if check_installed; then
        get_config

        # Service status
        if systemctl is-active --quiet $SERVICE_NAME 2>/dev/null; then
            echo -e "  Service:    ${GREEN}● Running${NC}"
        else
            echo -e "  Service:    ${RED}● Stopped${NC}"
        fi

        echo -e "  Agent ID:   ${YELLOW}$AGENT_ID${NC}"
        echo -e "  Server:     ${YELLOW}$SERVER_URL${NC}"

        if [ -n "$API_KEY" ]; then
            echo -e "  API Key:    ${GREEN}${API_KEY:0:8}...${API_KEY: -4}${NC}"
        else
            echo -e "  API Key:    ${RED}Not set${NC}"
        fi

        echo -e "  Config:     ${CYAN}$CONFIG_FILE${NC}"
    else
        echo -e "  ${YELLOW}Agent not installed${NC}"
    fi
    echo ""
}

show_menu() {
    show_status
    echo -e "${BOLD}Options:${NC}"
    echo ""

    if check_installed; then
        echo -e "  ${GREEN}1)${NC} Update Agent (download latest)"
        echo -e "  ${GREEN}2)${NC} View Logs"
        echo -e "  ${GREEN}3)${NC} View Config"
        echo -e "  ${GREEN}4)${NC} Update API Key"
        echo -e "  ${GREEN}5)${NC} Update Server URL"
        echo -e "  ${GREEN}6)${NC} Restart Service"
        echo -e "  ${GREEN}7)${NC} Stop Service"
        echo -e "  ${GREEN}8)${NC} Test Connection"
        echo -e "  ${GREEN}9)${NC} Uninstall Agent"
    else
        echo -e "  ${GREEN}1)${NC} Install Agent"
    fi

    echo -e "  ${GREEN}0)${NC} Exit"
    echo ""
    echo -n -e "${BOLD}Enter choice: ${NC}"
}

install_agent() {
    print_banner
    echo -e "${BOLD}${GREEN}Installing SSH Guardian Agent${NC}"
    echo ""

    # Get server URL
    echo -n -e "Server URL [${YELLOW}$DEFAULT_SERVER${NC}]: "
    read INPUT_SERVER
    SERVER_URL="${INPUT_SERVER:-$DEFAULT_SERVER}"

    # Install dependencies
    echo ""
    echo -e "${YELLOW}Installing dependencies...${NC}"
    apt-get update -qq --allow-releaseinfo-change 2>/dev/null || apt-get update -qq 2>/dev/null || true
    apt-get install -y python3 python3-pip python3-venv curl ufw 2>/dev/null

    # Create directories
    echo -e "${YELLOW}Creating directories...${NC}"
    mkdir -p "$AGENT_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$(dirname $LOG_FILE)"

    # Download agent
    echo -e "${YELLOW}Downloading agent...${NC}"
    if curl -sL "$SERVER_URL/static/installer/ssh_guardian_agent.py" -o "$AGENT_DIR/ssh_guardian_agent.py"; then
        chmod +x "$AGENT_DIR/ssh_guardian_agent.py"
        echo -e "${GREEN}Agent downloaded successfully${NC}"
    else
        echo -e "${RED}Failed to download agent${NC}"
        read -p "Press Enter to continue..."
        return
    fi

    # Setup Python venv
    echo -e "${YELLOW}Setting up Python environment...${NC}"
    if [ ! -d "$AGENT_DIR/venv" ]; then
        python3 -m venv "$AGENT_DIR/venv"
    fi
    source "$AGENT_DIR/venv/bin/activate"
    pip install -q requests
    deactivate

    # Generate agent ID
    HOSTNAME=$(hostname)
    AGENT_ID="${HOSTNAME}-$(cat /etc/machine-id 2>/dev/null | head -c 12 || echo $(date +%s | sha256sum | head -c 12))"

    # Create config
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}Creating configuration...${NC}"
        cat > "$CONFIG_FILE" << EOF
{
    "agent_id": "$AGENT_ID",
    "server_url": "$SERVER_URL",
    "api_key": "",
    "heartbeat_interval": 60,
    "firewall_sync_interval": 300,
    "firewall_enabled": true,
    "use_fail2ban": true,
    "fail2ban_sync_interval": 60
}
EOF
    fi

    # Create systemd service
    echo -e "${YELLOW}Creating systemd service...${NC}"
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=SSH Guardian Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$AGENT_DIR
ExecStart=$AGENT_DIR/venv/bin/python $AGENT_DIR/ssh_guardian_agent.py --config $CONFIG_FILE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start
    systemctl daemon-reload
    systemctl enable $SERVICE_NAME 2>/dev/null
    systemctl restart $SERVICE_NAME

    sleep 2

    if systemctl is-active --quiet $SERVICE_NAME; then
        echo ""
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo -e "${GREEN}  Agent installed and running!${NC}"
        echo -e "${GREEN}════════════════════════════════════════${NC}"
        echo ""
        echo -e "  Agent will auto-register with server."
        echo -e "  Check dashboard for API key, then use"
        echo -e "  option 4 to set it here."
    else
        echo -e "${RED}Service failed to start${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

update_agent() {
    print_banner
    echo -e "${BOLD}Updating Agent${NC}"
    echo ""

    get_config

    echo -e "Downloading from: ${YELLOW}$SERVER_URL${NC}"
    echo ""

    if curl -sL "$SERVER_URL/static/installer/ssh_guardian_agent.py" -o "$AGENT_DIR/ssh_guardian_agent.py"; then
        chmod +x "$AGENT_DIR/ssh_guardian_agent.py"
        echo -e "${GREEN}Agent updated successfully${NC}"

        echo -e "${YELLOW}Restarting service...${NC}"
        systemctl restart $SERVICE_NAME
        sleep 2

        if systemctl is-active --quiet $SERVICE_NAME; then
            echo -e "${GREEN}Service running${NC}"
        else
            echo -e "${RED}Service failed to start${NC}"
        fi
    else
        echo -e "${RED}Failed to download agent${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

view_logs() {
    print_banner
    echo -e "${BOLD}Agent Logs (last 50 lines)${NC}"
    echo -e "${CYAN}Press Ctrl+C to exit live view${NC}"
    echo ""

    journalctl -u $SERVICE_NAME -n 50 --no-pager

    echo ""
    echo -e "${YELLOW}View live logs? (y/n): ${NC}"
    read LIVE
    if [ "$LIVE" = "y" ] || [ "$LIVE" = "Y" ]; then
        journalctl -u $SERVICE_NAME -f
    fi
}

view_config() {
    print_banner
    echo -e "${BOLD}Current Configuration${NC}"
    echo -e "${CYAN}$CONFIG_FILE${NC}"
    echo ""

    if [ -f "$CONFIG_FILE" ]; then
        cat "$CONFIG_FILE"
    else
        echo -e "${RED}Config file not found${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

update_api_key() {
    print_banner
    echo -e "${BOLD}Update API Key${NC}"
    echo ""

    get_config

    if [ -n "$API_KEY" ]; then
        echo -e "Current: ${YELLOW}${API_KEY:0:8}...${API_KEY: -4}${NC}"
    else
        echo -e "Current: ${RED}Not set${NC}"
    fi

    echo ""
    echo -e "${CYAN}Find API key in dashboard: Agents → Click agent → Details${NC}"
    echo ""
    echo -n "Enter new API Key (or press Enter to cancel): "
    read NEW_KEY

    if [ -n "$NEW_KEY" ]; then
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f: config = json.load(f)
config['api_key'] = '$NEW_KEY'
with open('$CONFIG_FILE', 'w') as f: json.dump(config, f, indent=2)
"
        echo -e "${GREEN}API Key updated${NC}"
        echo -e "${YELLOW}Restarting service...${NC}"
        systemctl restart $SERVICE_NAME
        sleep 2

        if systemctl is-active --quiet $SERVICE_NAME; then
            echo -e "${GREEN}Service running with new API key${NC}"
        fi
    else
        echo -e "${YELLOW}No changes made${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

update_server_url() {
    print_banner
    echo -e "${BOLD}Update Server URL${NC}"
    echo ""

    get_config
    echo -e "Current: ${YELLOW}$SERVER_URL${NC}"
    echo ""
    echo -n "Enter new Server URL (or press Enter to cancel): "
    read NEW_URL

    if [ -n "$NEW_URL" ]; then
        python3 -c "
import json
with open('$CONFIG_FILE', 'r') as f: config = json.load(f)
config['server_url'] = '$NEW_URL'
with open('$CONFIG_FILE', 'w') as f: json.dump(config, f, indent=2)
"
        echo -e "${GREEN}Server URL updated${NC}"
        echo -e "${YELLOW}Restarting service...${NC}"
        systemctl restart $SERVICE_NAME
    else
        echo -e "${YELLOW}No changes made${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

restart_service() {
    print_banner
    echo -e "${YELLOW}Restarting service...${NC}"
    systemctl restart $SERVICE_NAME
    sleep 2

    if systemctl is-active --quiet $SERVICE_NAME; then
        echo -e "${GREEN}Service is running${NC}"
    else
        echo -e "${RED}Service failed to start${NC}"
        echo ""
        echo "Recent logs:"
        journalctl -u $SERVICE_NAME -n 10 --no-pager
    fi

    echo ""
    read -p "Press Enter to continue..."
}

stop_service() {
    print_banner
    echo -e "${YELLOW}Stopping service...${NC}"
    systemctl stop $SERVICE_NAME
    echo -e "${GREEN}Service stopped${NC}"

    echo ""
    read -p "Press Enter to continue..."
}

test_connection() {
    print_banner
    echo -e "${BOLD}Testing Connection${NC}"
    echo ""

    get_config
    echo -e "Server: ${YELLOW}$SERVER_URL${NC}"
    echo ""

    echo -n "Testing health endpoint... "
    if curl -s --connect-timeout 5 "$SERVER_URL/health" | grep -q "healthy"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi

    echo -n "Testing agents API... "
    if curl -s --connect-timeout 5 "$SERVER_URL/api/agents/list" | grep -q "success"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAILED${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

uninstall_agent() {
    print_banner
    echo -e "${RED}${BOLD}Uninstall Agent${NC}"
    echo ""
    echo -e "${YELLOW}This will remove:${NC}"
    echo "  - Agent files ($AGENT_DIR)"
    echo "  - Configuration ($CONFIG_DIR)"
    echo "  - Systemd service"
    echo ""
    echo -n -e "${RED}Are you sure? (type 'yes' to confirm): ${NC}"
    read CONFIRM

    if [ "$CONFIRM" = "yes" ]; then
        echo ""
        echo -e "${YELLOW}Stopping service...${NC}"
        systemctl stop $SERVICE_NAME 2>/dev/null
        systemctl disable $SERVICE_NAME 2>/dev/null

        echo -e "${YELLOW}Removing files...${NC}"
        rm -f /etc/systemd/system/$SERVICE_NAME.service
        rm -rf "$AGENT_DIR"
        rm -rf "$CONFIG_DIR"

        systemctl daemon-reload

        echo -e "${GREEN}Agent uninstalled${NC}"
    else
        echo -e "${YELLOW}Cancelled${NC}"
    fi

    echo ""
    read -p "Press Enter to continue..."
}

# Main
check_root

# If run with argument, use as server URL for non-interactive install
if [ -n "$1" ] && [ "$1" != "-i" ]; then
    DEFAULT_SERVER="$1"
    if ! check_installed; then
        install_agent
        exit 0
    fi
fi

# Interactive menu
while true; do
    show_menu
    read choice

    if check_installed; then
        case $choice in
            1) update_agent ;;
            2) view_logs ;;
            3) view_config ;;
            4) update_api_key ;;
            5) update_server_url ;;
            6) restart_service ;;
            7) stop_service ;;
            8) test_connection ;;
            9) uninstall_agent ;;
            0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    else
        case $choice in
            1) install_agent ;;
            0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    fi
done
