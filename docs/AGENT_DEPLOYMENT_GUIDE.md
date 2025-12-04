# SSH Guardian v3.0 - Agent Deployment Guide

## 📋 Overview

The SSH Guardian Agent allows you to collect SSH authentication logs from remote Ubuntu/Debian servers and send them to the central SSH Guardian server for analysis, threat detection, and blocking.

### Architecture

```
Remote Server (Agent)              Central Server (SSH Guardian)
┌─────────────────────┐            ┌──────────────────────────────┐
│                     │            │                              │
│  /var/log/auth.log  │            │   MySQL Database             │
│         ↓           │            │   ┌──────────────────┐       │
│   SSH Guardian      │  HTTPS     │   │  auth_events     │       │
│   Agent Client      │───────────>│   │  ip_blocks       │       │
│   (Python)          │            │   │  agents          │       │
│         ↓           │            │   │  agent_batches   │       │
│   - Parse Logs      │            │   └──────────────────┘       │
│   - Batch Submit    │            │          ↓                   │
│   - Heartbeat       │            │   Detection Engine           │
│                     │            │   Geolocation                │
│                     │            │   Blocking Rules             │
│                     │            │   Dashboard                  │
└─────────────────────┘            └──────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

**On Remote Server (where agent will be installed):**
- Ubuntu 18.04+ or Debian 10+
- Python 3.6+
- Root access (sudo)
- Network connectivity to SSH Guardian server

**On Central Server:**
- SSH Guardian v3.0 running
- Database migration 004 applied
- API endpoint accessible

---

## 📦 Installation

### Step 1: Prepare Central Server

First, ensure the central server has the agent system enabled:

```bash
# On central server
cd /home/rana-workspace/ssh_guardian_v3.0

# Apply database migration
source /home/rana-workspace/ssh_guardian_2.0/venv/bin/activate
python3 -c "
import mysql.connector
conn = mysql.connector.connect(host='localhost', user='root', password='123123', database='ssh_guardian_v3')
cursor = conn.cursor()
with open('dbs/migrations/004_agent_log_batches.sql', 'r') as f:
    for cmd in f.read().split(';'):
        if cmd.strip() and not cmd.strip().startswith('--'):
            cursor.execute(cmd)
conn.commit()
print('✅ Migration applied')
"

# Restart server if not already running
python3 src/dashboard/server.py
```

### Step 2: Generate API Key

You need to generate an API key for the agent. You can do this by:

**Option A: Via Dashboard (Recommended)**
```
1. Login to SSH Guardian Dashboard
2. Go to Security → Agent Management
3. Click "Generate New API Key"
4. Copy the generated key
```

**Option B: Manually in Database**
```bash
# Generate UUID for API key
python3 -c "import uuid; print(uuid.uuid4())"

# Copy the output - this is your API key
```

### Step 3: Download Agent Files

On the remote server where you want to install the agent:

```bash
# Create directory
mkdir -p /tmp/ssh-guardian-agent
cd /tmp/ssh-guardian-agent

# Download agent files (adjust URL to your central server)
wget http://YOUR_CENTRAL_SERVER:8081/static/agent/ssh_guardian_agent.py
wget http://YOUR_CENTRAL_SERVER:8081/static/agent/install.sh

# Or copy from central server
scp user@central-server:/home/rana-workspace/ssh_guardian_v3.0/agents/* .
```

### Step 4: Install Agent

Run the installation script:

```bash
cd /tmp/ssh-guardian-agent
sudo bash install.sh
```

The installer will prompt you for:

```
Enter SSH Guardian Server URL: http://192.168.1.100:8081
Enter API Key: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Enter Agent ID: [press Enter for auto-generated]
```

### Step 5: Verify Installation

Check agent status:

```bash
# Check service status
sudo systemctl status ssh-guardian-agent

# View live logs
sudo journalctl -u ssh-guardian-agent -f

# Check agent logs
sudo tail -f /var/log/ssh-guardian/agent.log
```

### Step 6: Approve Agent (Central Server)

The agent will register but needs approval:

```bash
# On central server dashboard
1. Go to Security → Agent Management
2. Find the new agent (will show as "Not Approved")
3. Click "Approve"
4. Agent will start sending logs
```

**Or via API:**
```bash
curl -X POST http://localhost:8081/api/agents/1/approve
```

---

## ⚙️ Configuration

### Configuration File

Location: `/etc/ssh-guardian/agent.json`

```json
{
  "server_url": "http://192.168.1.100:8081",
  "api_key": "your-api-key-here",
  "agent_id": "webserver-001",
  "hostname": "webserver-001",
  "check_interval": 30,
  "batch_size": 100,
  "heartbeat_interval": 60,
  "auth_log_path": "/var/log/auth.log",
  "state_file": "/var/lib/ssh-guardian/agent-state.json",
  "log_file": "/var/log/ssh-guardian/agent.log"
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `server_url` | Central server URL | Required |
| `api_key` | API key for authentication | Required |
| `agent_id` | Unique agent identifier | Auto-generated |
| `check_interval` | Log check interval (seconds) | 30 |
| `batch_size` | Logs per batch | 100 |
| `heartbeat_interval` | Heartbeat interval (seconds) | 60 |

### Environment Variables

You can also configure via environment variables:

```bash
export SSH_GUARDIAN_SERVER="http://192.168.1.100:8081"
export SSH_GUARDIAN_API_KEY="your-api-key"
export SSH_GUARDIAN_AGENT_ID="custom-agent-id"
export SSH_GUARDIAN_CHECK_INTERVAL="30"
export SSH_GUARDIAN_BATCH_SIZE="100"
```

---

## 🔧 Management

### Service Control

```bash
# Start agent
sudo systemctl start ssh-guardian-agent

# Stop agent
sudo systemctl stop ssh-guardian-agent

# Restart agent
sudo systemctl restart ssh-guardian-agent

# Enable autostart
sudo systemctl enable ssh-guardian-agent

# Disable autostart
sudo systemctl disable ssh-guardian-agent

# View status
sudo systemctl status ssh-guardian-agent
```

### Viewing Logs

```bash
# Service logs (systemd)
sudo journalctl -u ssh-guardian-agent -f

# Agent logs
sudo tail -f /var/log/ssh-guardian/agent.log

# Last 100 lines
sudo journalctl -u ssh-guardian-agent -n 100

# Today's logs only
sudo journalctl -u ssh-guardian-agent --since today
```

### Agent State

The agent maintains state in: `/var/lib/ssh-guardian/agent-state.json`

```json
{
  "last_inode": 1234567,
  "last_position": 98765,
  "last_heartbeat": "2025-12-04T10:30:00",
  "total_logs_sent": 15420,
  "total_batches_sent": 155,
  "agent_start_time": "2025-12-04T08:00:00"
}
```

To reset agent (start from beginning of log):

```bash
sudo systemctl stop ssh-guardian-agent
sudo rm /var/lib/ssh-guardian/agent-state.json
sudo systemctl start ssh-guardian-agent
```

---

## 📊 Monitoring

### Check Agent Status in Dashboard

```
Dashboard → Security → Agent Management
```

Shows:
- Agent status (Online/Offline)
- Last heartbeat
- Total logs sent
- Health metrics (CPU, Memory, Disk)

### API Endpoints

**List all agents:**
```bash
curl http://localhost:8081/api/agents/list
```

**Get agent details:**
```bash
curl http://localhost:8081/api/agents/1
```

**Agent statistics:**
```bash
curl http://localhost:8081/api/agents/stats
```

---

## 🔒 Security

### API Key Security

- API keys are stored in `/etc/ssh-guardian/agent.json` with permissions `600` (root only)
- Keys are validated on every API request
- Agents must be approved before they can submit logs

### Network Security

**Firewall Rules (Central Server):**
```bash
# Allow agent API endpoints (if using firewall)
sudo ufw allow 8081/tcp comment "SSH Guardian API"
```

**Recommended: Use HTTPS**

Configure nginx as reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name guardian.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /api/agents/ {
        proxy_pass http://localhost:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Then configure agents to use HTTPS:
```json
{
  "server_url": "https://guardian.example.com"
}
```

---

## 🐛 Troubleshooting

### Agent Won't Start

**Check logs:**
```bash
sudo journalctl -u ssh-guardian-agent -n 50
```

**Common Issues:**

1. **Cannot reach server**
```
Error: Connection refused
```
**Solution:** Verify server URL and network connectivity
```bash
curl http://YOUR_SERVER:8081/health
```

2. **Invalid API key**
```
Error: Invalid API key or Agent ID
```
**Solution:** Check API key in config, ensure agent is registered

3. **Permission denied**
```
Error: Permission denied: /var/log/auth.log
```
**Solution:** Agent must run as root to read auth.log

4. **Agent not approved**
```
Error: Agent is not approved yet
```
**Solution:** Approve agent in dashboard

### Agent Shows Offline

**Check heartbeat:**
```bash
# On central server
mysql -u root -p123123 ssh_guardian_v3 -e "
SELECT agent_id, hostname, last_heartbeat, status
FROM agents
WHERE agent_id = 'YOUR_AGENT_ID';
"
```

**Restart agent:**
```bash
sudo systemctl restart ssh-guardian-agent
```

### Logs Not Appearing

**Check batch submissions:**
```bash
# On central server
mysql -u root -p123123 ssh_guardian_v3 -e "
SELECT COUNT(*) as batches, SUM(events_created) as events
FROM agent_log_batches
WHERE agent_id = (SELECT id FROM agents WHERE agent_id = 'YOUR_AGENT_ID');
"
```

**Check processing errors:**
```bash
sudo tail -f /var/log/ssh-guardian/agent.log | grep ERROR
```

### High Memory Usage

**Reduce batch size:**
```bash
sudo nano /etc/ssh-guardian/agent.json
# Change: "batch_size": 50
sudo systemctl restart ssh-guardian-agent
```

---

## 🔄 Updates

### Update Agent

```bash
# Download new version
cd /tmp
wget http://YOUR_SERVER/static/agent/ssh_guardian_agent.py

# Stop service
sudo systemctl stop ssh-guardian-agent

# Backup current version
sudo cp /opt/ssh-guardian-agent/ssh_guardian_agent.py /opt/ssh-guardian-agent/ssh_guardian_agent.py.bak

# Install new version
sudo cp ssh_guardian_agent.py /opt/ssh-guardian-agent/
sudo chmod +x /opt/ssh-guardian-agent/ssh_guardian_agent.py

# Start service
sudo systemctl start ssh-guardian-agent
```

---

## 🗑️ Uninstallation

```bash
cd /tmp/ssh-guardian-agent
sudo bash install.sh --uninstall
```

Or manually:

```bash
# Stop and disable service
sudo systemctl stop ssh-guardian-agent
sudo systemctl disable ssh-guardian-agent

# Remove service file
sudo rm /etc/systemd/system/ssh-guardian-agent.service
sudo systemctl daemon-reload

# Remove files
sudo rm -rf /opt/ssh-guardian-agent
sudo rm -rf /var/log/ssh-guardian
sudo rm -rf /var/lib/ssh-guardian
sudo rm -rf /etc/ssh-guardian  # Keep if you want to preserve config
```

---

## 📈 Best Practices

### 1. Monitor Agent Health

- Check dashboard regularly
- Set up alerts for agent offline status
- Monitor heartbeat intervals

### 2. Log Rotation

Agent state file tracks position, so log rotation is handled automatically:

```bash
# /etc/logrotate.d/ssh-guardian-agent
/var/log/ssh-guardian/*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0644 root root
}
```

### 3. Backup Configuration

```bash
# Backup agent config
sudo cp /etc/ssh-guardian/agent.json /backup/location/
```

### 4. Multi-Server Deployment

Use configuration management tools:

**Ansible Example:**
```yaml
- name: Deploy SSH Guardian Agent
  hosts: all
  tasks:
    - name: Copy agent files
      copy:
        src: ssh_guardian_agent.py
        dest: /opt/ssh-guardian-agent/

    - name: Configure agent
      template:
        src: agent.json.j2
        dest: /etc/ssh-guardian/agent.json

    - name: Start agent service
      systemd:
        name: ssh-guardian-agent
        state: started
        enabled: yes
```

### 5. Testing Before Production

Test on staging server first:

```bash
# Install on staging
sudo bash install.sh

# Monitor for 24 hours
sudo journalctl -u ssh-guardian-agent -f

# Check metrics in dashboard

# Deploy to production when validated
```

---

## 📝 Example Deployment Scenarios

### Scenario 1: Single Web Server

```bash
# On web server
sudo bash install.sh

# Configure
Server URL: http://guardian.internal:8081
Agent ID: webserver-prod-01

# Verify
sudo systemctl status ssh-guardian-agent
```

### Scenario 2: Multiple Application Servers

```bash
# Server 1
Agent ID: app-server-01

# Server 2
Agent ID: app-server-02

# Server 3
Agent ID: app-server-03

# All use same server URL and separate agent IDs
```

### Scenario 3: Jump Box / Bastion Host

```bash
# High-priority monitoring
Agent ID: jumpbox-prod
check_interval: 10  # Check every 10 seconds
batch_size: 50      # Smaller batches for faster processing
```

---

## 🆘 Support

### Get Help

1. Check logs first
2. Review troubleshooting section
3. Verify configuration
4. Check dashboard for errors

### Useful Commands

```bash
# Full diagnostic output
sudo systemctl status ssh-guardian-agent -l
sudo journalctl -u ssh-guardian-agent -n 100 --no-pager
sudo cat /var/log/ssh-guardian/agent.log
sudo cat /etc/ssh-guardian/agent.json
sudo cat /var/lib/ssh-guardian/agent-state.json
```

---

## ✅ Checklist

Use this checklist when deploying agents:

- [ ] Central server migration 004 applied
- [ ] API key generated
- [ ] Agent files downloaded
- [ ] Installation script executed
- [ ] Configuration verified
- [ ] Service started successfully
- [ ] Agent shows in dashboard
- [ ] Agent approved
- [ ] Logs being received
- [ ] Heartbeat working
- [ ] Monitored for 24 hours

---

**Version:** 3.0.0
**Last Updated:** 2025-12-04
**Status:** Production Ready
