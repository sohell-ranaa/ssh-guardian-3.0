/**
 * SSH Guardian v3.0 - UFW Firewall Management
 * Easy-to-use interface for UFW (Uncomplicated Firewall) operations
 */

let currentAgentId = null;
let ufwData = null;
let currentAgentIp = null;
let currentAgentData = null;
let recentLogsData = [];
let showAdvanced = false;

// ============================================================================
// INITIALIZATION
// ============================================================================

function initFirewallPage() {
    loadAgentsForFirewall();
    setupFirewallEventListeners();
}

function setupFirewallEventListeners() {
    const agentSelector = document.getElementById('firewallAgentSelector');
    if (agentSelector) {
        agentSelector.addEventListener('change', function() {
            const agentId = this.value;
            if (agentId) {
                currentAgentId = agentId;
                const selectedOption = this.options[this.selectedIndex];
                currentAgentIp = selectedOption.dataset.ip || null;
                document.getElementById('syncNowBtn').style.display = 'inline-block';
                // Save selection for persistence
                localStorage.setItem('firewall_selected_agent', agentId);
                loadAgentDetails(agentId);
                loadUFWData(agentId);
                loadRecentLogs(agentId);
            } else {
                currentAgentId = null;
                document.getElementById('syncNowBtn').style.display = 'none';
                localStorage.removeItem('firewall_selected_agent');
                showNoAgentSelected();
            }
        });
    }
}

// ============================================================================
// DATA LOADING
// ============================================================================

async function loadAgentsForFirewall() {
    try {
        const response = await fetch('/api/agents/list');
        const data = await response.json();

        if (data.success && data.agents) {
            const selector = document.getElementById('firewallAgentSelector');
            selector.innerHTML = '<option value="">-- Select a server --</option>';

            data.agents.forEach(agent => {
                const option = document.createElement('option');
                option.value = agent.id;
                option.dataset.ip = agent.ip_address_primary || '';
                const status = agent.status === 'online' ? '🟢' : '🔴';
                option.textContent = `${status} ${agent.hostname} (${agent.ip_address_primary || agent.agent_id})`;
                selector.appendChild(option);
            });

            // Auto-select: restore saved selection or auto-select if only one agent
            const savedAgentId = localStorage.getItem('firewall_selected_agent');
            if (savedAgentId && selector.querySelector(`option[value="${savedAgentId}"]`)) {
                selector.value = savedAgentId;
                selector.dispatchEvent(new Event('change'));
            } else if (data.agents.length === 1) {
                selector.value = data.agents[0].id;
                selector.dispatchEvent(new Event('change'));
            }
        }
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

async function loadUFWData(agentId) {
    showFirewallContent();
    showLoadingStates();

    try {
        const response = await fetch(`/api/agents/${agentId}/ufw`);
        const data = await response.json();

        if (data.success && data.has_data) {
            ufwData = data;
            updateUFWStats(data);
            renderUFWRules(data.rules || []);
            renderListeningPorts(data.listening_ports || []);

            if (showAdvanced) {
                renderAdvancedRules(data.rules || []);
            }

            updateCacheIndicator('firewall', data.from_cache);

            // Hide no firewall data warning
            document.getElementById('noFirewallDataWarning').style.display = 'none';
        } else {
            showNoFirewallData();
        }
    } catch (error) {
        console.error('Error loading UFW data:', error);
        showFirewallError(error.message);
    }
}

function loadFirewallPage() {
    if (currentAgentId) {
        loadAgentDetails(currentAgentId);
        loadUFWData(currentAgentId);
        loadRecentLogs(currentAgentId);
    }
}

// Alias for backward compatibility
function loadFirewallData(agentId) {
    return loadUFWData(agentId);
}

// ============================================================================
// AGENT HEALTH & DETAILS
// ============================================================================

async function loadAgentDetails(agentId) {
    try {
        const response = await fetch(`/api/agents/${agentId}`);
        const data = await response.json();

        if (data.success && data.agent) {
            currentAgentData = data.agent;
            updateAgentHealthDisplay(data.agent);
        }
    } catch (error) {
        console.error('Error loading agent details:', error);
    }
}

function updateAgentHealthDisplay(agent) {
    // Update health indicator and status
    const indicator = document.getElementById('agentHealthIndicator');
    const statusBadge = document.getElementById('agentHealthStatus');

    const isOnline = agent.status === 'online';
    indicator.style.background = isOnline ? '#107C10' : '#D13438';

    statusBadge.textContent = isOnline ? 'Online' : 'Offline';
    statusBadge.className = 'rule-badge ' + (isOnline ? 'allow' : 'block');

    // Update hostname and details
    document.getElementById('agentHealthHostname').textContent = agent.hostname || '-';
    document.getElementById('agentHealthIP').textContent = agent.ip_address_primary || '-';
    document.getElementById('agentHealthVersion').textContent = agent.version || '-';

    // Format last heartbeat - pass raw string to let formatTimeAgo handle UTC
    if (agent.last_heartbeat) {
        document.getElementById('agentHealthHeartbeat').textContent = formatTimeAgo(agent.last_heartbeat);
    } else {
        document.getElementById('agentHealthHeartbeat').textContent = 'Never';
    }

    // Calculate uptime (rough estimate from created_at)
    if (agent.created_at && isOnline) {
        // Ensure UTC parsing for created_at
        let createdStr = String(agent.created_at);
        if (!createdStr.endsWith('Z') && !createdStr.includes('+') && !createdStr.includes('-', 10)) {
            createdStr += 'Z';
        }
        const created = new Date(createdStr);
        const now = new Date();
        const days = Math.floor((now - created) / (1000 * 60 * 60 * 24));
        document.getElementById('agentHealthUptime').textContent = days > 0 ? `${days} days` : 'Today';
    } else {
        document.getElementById('agentHealthUptime').textContent = '-';
    }

    // Show approval warning if not approved
    const approvalWarning = document.getElementById('agentApprovalStatus');
    if (!agent.is_approved) {
        approvalWarning.style.display = 'block';
    } else {
        approvalWarning.style.display = 'none';
    }
}

async function approveAgentFromFirewall() {
    if (!currentAgentId) return;

    try {
        const response = await fetch(`/api/agents/${currentAgentId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Agent approved successfully!', 'success');
            document.getElementById('agentApprovalStatus').style.display = 'none';
            loadAgentDetails(currentAgentId);
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// ============================================================================
// SYNC FUNCTIONALITY
// ============================================================================

async function requestFirewallSync() {
    if (!currentAgentId) {
        showNotification('Please select a server first', 'error');
        return;
    }

    const btn = document.getElementById('syncNowBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="sync-spinning" style="display: inline-block;">🔄</span> Syncing...';
    btn.disabled = true;

    try {
        const response = await fetch(`/api/agents/${currentAgentId}/ufw/request-sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Sync request sent! Data will update shortly.', 'success');
            // Reload data after a short delay
            setTimeout(() => {
                loadUFWData(currentAgentId);
            }, 2000);
        } else {
            showNotification(`Sync failed: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        showNotification(`Sync error: ${error.message}`, 'error');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// ============================================================================
// RECENT LOGS
// ============================================================================

async function loadRecentLogs(agentId) {
    const loadingEl = document.getElementById('recentLogsLoading');
    const containerEl = document.getElementById('recentLogsContainer');
    const noLogsEl = document.getElementById('noLogsMessage');

    loadingEl.style.display = 'block';
    containerEl.style.display = 'none';
    noLogsEl.style.display = 'none';

    try {
        const response = await fetch(`/api/dashboard/events/list?agent_id=${agentId}&limit=50`);
        const data = await response.json();

        loadingEl.style.display = 'none';

        if (data.success && data.events && data.events.length > 0) {
            recentLogsData = data.events;
            renderRecentLogs(data.events);
            containerEl.style.display = 'block';
        } else {
            noLogsEl.style.display = 'block';
        }
    } catch (error) {
        console.error('Error loading recent logs:', error);
        loadingEl.innerHTML = `<span style="color: #D13438;">Error loading logs</span>`;
    }
}

function renderRecentLogs(events) {
    const container = document.getElementById('recentLogsList');

    container.innerHTML = events.map(event => {
        let icon = '📝';
        let actionClass = '';
        let actionText = event.event_type || 'Event';

        // Determine icon and style based on event type
        if (event.event_type === 'failed' || event.event_type === 'Failed password') {
            icon = '❌';
            actionClass = 'failed';
            actionText = 'Failed Login';
        } else if (event.event_type === 'accepted' || event.event_type === 'Accepted' || event.event_type === 'successful') {
            icon = '✅';
            actionClass = 'success';
            actionText = 'Login Success';
        } else if (event.event_type === 'blocked' || event.is_blocked) {
            icon = '🚫';
            actionClass = 'blocked';
            actionText = 'Blocked';
        } else if (event.event_type === 'session_opened') {
            icon = '🔓';
            actionClass = 'success';
            actionText = 'Session Opened';
        } else if (event.event_type === 'session_closed') {
            icon = '🔒';
            actionClass = '';
            actionText = 'Session Closed';
        } else if (event.event_type === 'invalid') {
            icon = '⚠️';
            actionClass = 'failed';
            actionText = 'Invalid User';
        }

        // Handle both API response formats (ip vs source_ip, timestamp vs event_time)
        const ipAddress = event.ip || event.source_ip || '-';
        const username = event.username || event.target_username || '';
        // Pass raw timestamp string to formatTimeAgo for proper UTC handling
        const rawTimestamp = event.timestamp || event.event_time;
        const timeStr = rawTimestamp ? formatTimeAgo(rawTimestamp) : 'Just now';

        // Get location info if available
        const location = event.location;
        const locationStr = location && location.country_code ?
            `<span class="log-location">${location.country_code}</span>` : '';

        return `
            <div class="log-entry" data-type="${actionClass || 'other'}">
                <div class="log-icon">${icon}</div>
                <div class="log-content">
                    <div class="log-main">
                        <span class="log-ip">${ipAddress}</span>
                        ${username ? `<span class="log-user">@${username}</span>` : ''}
                        <span class="log-action ${actionClass}">${actionText}</span>
                        ${locationStr}
                    </div>
                    <div class="log-meta">
                        ${event.auth_method ? `via ${event.auth_method}` : ''}
                        ${event.port ? `:${event.port}` : ''}
                    </div>
                </div>
                <div class="log-time">${timeStr}</div>
            </div>
        `;
    }).join('');
}

function filterRecentLogs() {
    const filter = document.getElementById('logTypeFilter').value;
    const entries = document.querySelectorAll('.log-entry');

    entries.forEach(entry => {
        const type = entry.dataset.type;

        if (filter === 'all') {
            entry.style.display = 'flex';
        } else if (filter === 'failed' && type === 'failed') {
            entry.style.display = 'flex';
        } else if (filter === 'success' && type === 'success') {
            entry.style.display = 'flex';
        } else if (filter === 'blocked' && type === 'blocked') {
            entry.style.display = 'flex';
        } else {
            entry.style.display = 'none';
        }
    });
}

// ============================================================================
// UI UPDATES
// ============================================================================

function showNoAgentSelected() {
    document.getElementById('firewallNoAgent').style.display = 'block';
    document.getElementById('firewallContent').style.display = 'none';
}

function showFirewallContent() {
    document.getElementById('firewallNoAgent').style.display = 'none';
    document.getElementById('firewallContent').style.display = 'block';
}

function showLoadingStates() {
    document.getElementById('simpleRulesLoading').style.display = 'block';
    document.getElementById('simpleRulesContainer').style.display = 'none';
    document.getElementById('noRulesMessage').style.display = 'none';
}

function showNoFirewallData() {
    document.getElementById('simpleRulesLoading').style.display = 'none';
    document.getElementById('noRulesMessage').style.display = 'block';
    document.getElementById('noFirewallDataWarning').style.display = 'block';

    // Reset stats
    document.getElementById('stat-fw-status').textContent = 'Not installed';
    document.getElementById('stat-fw-status').style.color = '#D13438';
    document.getElementById('stat-fw-allowed').textContent = '-';
    document.getElementById('stat-fw-blocked').textContent = '-';
    document.getElementById('stat-fw-sync').textContent = 'Never';
}

function showFirewallError(error) {
    document.getElementById('simpleRulesLoading').innerHTML = `
        <div style="color: #D13438;">Error: ${error}</div>
    `;
}

function updateUFWStats(data) {
    const state = data.state || {};
    const rules = data.rules || [];

    // Count allow/deny rules
    const allowCount = rules.filter(r => r.action === 'ALLOW').length;
    const denyCount = rules.filter(r => r.action === 'DENY' || r.action === 'REJECT').length;

    // UFW status
    const isActive = state.ufw_status === 'active';
    document.getElementById('stat-fw-status').textContent = isActive ? 'Active' : (state.ufw_status || 'Inactive');
    document.getElementById('stat-fw-status').style.color = isActive ? '#107C10' : '#D13438';

    document.getElementById('stat-fw-allowed').textContent = allowCount;
    document.getElementById('stat-fw-blocked').textContent = denyCount;

    if (state.last_sync) {
        // Append 'Z' if not present to indicate UTC
        let syncTime = state.last_sync;
        if (!syncTime.endsWith('Z') && !syncTime.includes('+')) {
            syncTime += 'Z';
        }
        document.getElementById('stat-fw-sync').textContent = formatTimeAgo(new Date(syncTime));
    } else {
        document.getElementById('stat-fw-sync').textContent = 'Never';
    }

    // Update default policies display if exists
    const defaultIn = document.getElementById('stat-fw-default-in');
    const defaultOut = document.getElementById('stat-fw-default-out');
    if (defaultIn) defaultIn.textContent = state.default_incoming || 'deny';
    if (defaultOut) defaultOut.textContent = state.default_outgoing || 'allow';
}

// ============================================================================
// UFW RULES VIEW
// ============================================================================

function renderUFWRules(rules) {
    document.getElementById('simpleRulesLoading').style.display = 'none';

    if (rules.length === 0) {
        document.getElementById('noRulesMessage').style.display = 'block';
        document.getElementById('simpleRulesContainer').style.display = 'none';
        return;
    }

    document.getElementById('simpleRulesContainer').style.display = 'block';
    document.getElementById('noRulesMessage').style.display = 'none';

    const container = document.getElementById('simpleRulesList');
    container.innerHTML = rules.map(rule => {
        const isAllow = rule.action === 'ALLOW';
        const isLimit = rule.action === 'LIMIT';
        const icon = isAllow ? '✅' : (isLimit ? '⏱️' : '🚫');
        const badgeClass = isAllow ? 'allow' : (isLimit ? 'limit' : 'block');
        const action = rule.action;

        const port = rule.to_port || 'Any';
        const protocol = rule.protocol || 'All';
        const from = rule.from_ip === 'Anywhere' ? 'Anywhere' : rule.from_ip;
        const direction = rule.direction === 'OUT' ? 'Outgoing' : 'Incoming';

        // Generate human-readable description
        let description = `${direction}`;
        if (port !== 'Any' && port !== '') {
            description += ` on port ${port}`;
            if (protocol) description += `/${protocol}`;
        }
        if (from !== 'Anywhere') {
            description += ` from ${from}`;
        }

        // IPv6 indicator
        const v6Badge = rule.ipv6 || rule.is_v6 ? '<span class="rule-badge v6">IPv6</span>' : '';

        // Store rule data for reordering
        const ruleDataAttr = encodeURIComponent(JSON.stringify({
            action: rule.action,
            to_port: rule.to_port,
            protocol: rule.protocol,
            from_ip: rule.from_ip,
            direction: rule.direction,
            raw_rule: rule.raw_rule
        }));

        return `
            <div class="simple-rule-card" data-type="${badgeClass}" data-rule-index="${rule.rule_index}" data-rule="${ruleDataAttr}" draggable="true">
                <div class="drag-handle" title="Drag to reorder">⠿</div>
                <div class="rule-icon">${icon}</div>
                <div class="rule-details">
                    <div class="rule-title">${action} ${port !== 'Any' && port !== '' ? port : 'All'} ${protocol ? `(${protocol.toUpperCase()})` : ''}</div>
                    <div class="rule-subtitle">${description}</div>
                </div>
                <span class="rule-badge ${badgeClass}">${action}</span>
                ${v6Badge}
                <div class="rule-actions">
                    <button class="rule-delete-btn" onclick="deleteUFWRule(${rule.rule_index})">
                        🗑️ Remove
                    </button>
                </div>
            </div>
        `;
    }).join('');

    // Initialize drag-and-drop
    initDragAndDrop();
}

function renderSimpleRules(rules) {
    // Backward compatibility - call UFW version
    renderUFWRules(rules);
}

function filterSimpleRules() {
    const filter = document.getElementById('filterRuleType').value;
    const cards = document.querySelectorAll('.simple-rule-card');

    cards.forEach(card => {
        const type = card.dataset.type;
        if (filter === 'all' ||
            (filter === 'allow' && type === 'allow') ||
            (filter === 'block' && (type === 'block' || type === 'deny'))) {
            card.style.display = 'flex';
        } else {
            card.style.display = 'none';
        }
    });
}

// ============================================================================
// LISTENING PORTS VIEW
// ============================================================================

function renderListeningPorts(ports) {
    const container = document.getElementById('interfacesGrid');

    if (!ports || ports.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary);">No listening ports detected</p>';
        return;
    }

    // Group by port status
    const protectedPorts = ports.filter(p => p.is_protected);
    const otherPorts = ports.filter(p => !p.is_protected);

    container.innerHTML = `
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px;">
            ${ports.slice(0, 12).map(port => {
                const isProtected = port.is_protected;
                return `
                    <div style="background: var(--background); padding: 10px 14px; border-radius: 4px; border: 1px solid var(--border); ${isProtected ? 'border-left: 3px solid #107C10;' : ''}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-weight: 600; font-size: 16px;">${port.port}</span>
                            <span style="font-size: 11px; color: var(--text-secondary);">${port.protocol.toUpperCase()}</span>
                        </div>
                        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
                            ${port.process_name || 'unknown'}
                        </div>
                        ${isProtected ? '<span style="font-size: 10px; color: #107C10;">Protected</span>' : ''}
                    </div>
                `;
            }).join('')}
        </div>
        ${ports.length > 12 ? `<p style="color: var(--text-secondary); margin-top: 10px; font-size: 12px;">+ ${ports.length - 12} more ports</p>` : ''}
    `;
}

// Backward compatibility
function renderInterfaces(interfaces) {
    // If we have listening ports in ufwData, render those instead
    if (ufwData && ufwData.listening_ports) {
        renderListeningPorts(ufwData.listening_ports);
    }
}

// ============================================================================
// TOGGLE FUNCTIONS
// ============================================================================

function toggleCustomPort(select) {
    const customDiv = document.getElementById('customPortDiv');
    customDiv.style.display = select.value === 'custom' ? 'block' : 'none';
}

function toggleCustomSource(select) {
    const customDiv = document.getElementById('customSourceDiv');
    customDiv.style.display = select.value === 'custom' ? 'block' : 'none';
}

function toggleAdvancedView() {
    showAdvanced = !showAdvanced;
    const section = document.getElementById('advancedViewSection');

    if (showAdvanced) {
        section.style.display = 'block';
        if (ufwData) {
            renderAdvancedRules(ufwData.rules || []);
        }
    } else {
        section.style.display = 'none';
    }
}

// ============================================================================
// ADVANCED RULES VIEW
// ============================================================================

function renderAdvancedRules(rules) {
    const container = document.getElementById('advancedRulesGrid');

    if (!rules || rules.length === 0) {
        container.innerHTML = '<p style="text-align: center; padding: 20px; color: var(--text-secondary);">No rules found</p>';
        return;
    }

    container.innerHTML = `
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
            <thead>
                <tr style="background: var(--background); border-bottom: 2px solid var(--border);">
                    <th style="padding: 10px; text-align: left;">#</th>
                    <th style="padding: 10px; text-align: left;">Action</th>
                    <th style="padding: 10px; text-align: left;">Dir</th>
                    <th style="padding: 10px; text-align: left;">To Port</th>
                    <th style="padding: 10px; text-align: left;">Protocol</th>
                    <th style="padding: 10px; text-align: left;">From</th>
                    <th style="padding: 10px; text-align: left;">IPv6</th>
                </tr>
            </thead>
            <tbody>
                ${rules.map(rule => `
                    <tr style="border-bottom: 1px solid var(--border);">
                        <td style="padding: 8px 10px;">${rule.rule_index}</td>
                        <td style="padding: 8px 10px;">
                            <span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; ${getActionStyle(rule.action)}">${rule.action}</span>
                        </td>
                        <td style="padding: 8px 10px;">${rule.direction}</td>
                        <td style="padding: 8px 10px; font-family: monospace;">${rule.to_port || 'Any'}</td>
                        <td style="padding: 8px 10px;">${rule.protocol || 'all'}</td>
                        <td style="padding: 8px 10px; font-family: monospace; font-size: 11px;">${rule.from_ip || 'Anywhere'}</td>
                        <td style="padding: 8px 10px;">${rule.is_v6 ? 'Yes' : 'No'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

function getActionStyle(action) {
    switch (action?.toUpperCase()) {
        case 'ALLOW': return 'background: rgba(16, 124, 16, 0.1); color: #107C10;';
        case 'DENY': return 'background: rgba(209, 52, 56, 0.1); color: #D13438;';
        case 'REJECT': return 'background: rgba(255, 185, 0, 0.1); color: #CC9400;';
        case 'LIMIT': return 'background: rgba(0, 120, 212, 0.1); color: #0078D4;';
        default: return 'background: var(--surface); color: var(--text-secondary);';
    }
}

// Backward compatibility
function getTargetStyle(target) {
    return getActionStyle(target);
}

// ============================================================================
// UFW ACTIONS
// ============================================================================

async function quickAction(action) {
    if (!currentAgentId) {
        showNotification('Please select a server first', 'error');
        return;
    }

    let actionType = '';
    let params = {};
    let confirmMsg = '';

    switch (action) {
        case 'allow-ssh':
            actionType = 'allow_port';
            params = { port: 22, protocol: 'tcp' };
            confirmMsg = 'Allow SSH (port 22) from anywhere?';
            break;
        case 'allow-http':
            // Add both HTTP and HTTPS
            if (confirm('Allow HTTP (80) and HTTPS (443) from anywhere?')) {
                await executeUFWQuickAction('allow_port', { port: 80, protocol: 'tcp' });
                await executeUFWQuickAction('allow_port', { port: 443, protocol: 'tcp' });
                return;
            }
            return;
        case 'allow-mysql':
            actionType = 'allow_port';
            params = { port: 3306, protocol: 'tcp' };
            confirmMsg = 'Allow MySQL (port 3306) from anywhere? Consider restricting to specific IPs for security.';
            break;
        case 'limit-ssh':
            actionType = 'limit_port';
            params = { port: 22, protocol: 'tcp' };
            confirmMsg = 'Enable SSH rate limiting (brute force protection)?';
            break;
        case 'enable':
            actionType = 'enable';
            confirmMsg = 'Enable UFW firewall?';
            break;
        case 'disable':
            actionType = 'disable';
            confirmMsg = 'WARNING: This will disable the firewall completely. Are you sure?';
            break;
    }

    if (confirmMsg && confirm(confirmMsg)) {
        await executeUFWQuickAction(actionType, params);
    }
}

async function addSimpleRule() {
    if (!currentAgentId) {
        showMessage('Please select a server first', 'error');
        return;
    }

    const action = document.getElementById('simpleRuleAction').value;
    const direction = document.getElementById('simpleRuleDirection').value;
    const protocol = document.getElementById('simpleRuleProtocol').value;
    let port = document.getElementById('simpleRulePort').value;
    let source = document.getElementById('simpleRuleSource').value;

    // Handle custom port
    if (port === 'custom') {
        port = document.getElementById('simpleRuleCustomPort').value;
        if (!port) {
            showMessage('Please enter a custom port', 'error');
            return;
        }
    }

    // Handle custom source
    if (source === 'custom') {
        source = document.getElementById('simpleRuleCustomSource').value;
        if (!source) {
            showMessage('Please enter an IP address or network', 'error');
            return;
        }
    } else if (source === 'local') {
        source = '192.168.0.0/16'; // Common local network range
    } else {
        source = undefined; // Any
    }

    // Map action to UFW command type
    const commandType = action === 'ACCEPT' ? 'allow' : (action === 'REJECT' ? 'reject' : 'deny');

    const params = {
        port: port && port !== 'any' ? port : undefined,
        protocol: protocol === 'all' ? undefined : protocol,
        from_ip: source
    };

    showMessage('Adding rule...', 'info');
    await executeUFWCommand(commandType, params);
}

async function deleteUFWRule(ruleIndex) {
    if (!currentAgentId) return;

    if (!confirm(`Remove UFW rule #${ruleIndex}?`)) return;

    await executeUFWQuickAction('delete_rule', { rule_number: ruleIndex });
}

// Backward compatibility
async function deleteSimpleRule(table, chain, ruleNum) {
    await deleteUFWRule(ruleNum);
}

async function executeUFWQuickAction(actionType, params = {}) {
    try {
        const response = await fetch(`/api/agents/${currentAgentId}/ufw/quick-action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action_type: actionType, ...params })
        });

        const data = await response.json();

        if (data.success) {
            showMessage('Command queued! Syncing with agent...', 'success');
            showNotification(`UFW: ${data.ufw_command}`, 'success');
            // Request immediate sync from agent
            await fetch(`/api/agents/${currentAgentId}/ufw/request-sync`, { method: 'POST' });
            // Poll for data update
            pollForUpdate(currentAgentId);
        } else {
            showMessage(`Error: ${data.error}`, 'error');
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showMessage(`Error: ${error.message}`, 'error');
        showNotification(`Error: ${error.message}`, 'error');
    }
}

function pollForUpdate(agentId, attempts = 0) {
    if (attempts > 10) {
        // Max 10 attempts (10 seconds)
        loadUFWData(agentId);
        return;
    }
    setTimeout(async () => {
        try {
            const resp = await fetch(`/api/agents/${agentId}/ufw`);
            const data = await resp.json();
            if (data.success && data.has_data) {
                loadUFWData(agentId);
            } else {
                pollForUpdate(agentId, attempts + 1);
            }
        } catch (e) {
            pollForUpdate(agentId, attempts + 1);
        }
    }, 1000);
}

async function executeUFWCommand(commandType, params) {
    try {
        const response = await fetch(`/api/agents/${currentAgentId}/ufw/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command_type: commandType, params })
        });

        const data = await response.json();

        if (data.success) {
            showMessage('Rule queued! Syncing with agent...', 'success');
            showNotification('UFW rule queued', 'success');
            // Request immediate sync from agent
            await fetch(`/api/agents/${currentAgentId}/ufw/request-sync`, { method: 'POST' });
            // Poll for data update
            pollForUpdate(currentAgentId);
        } else {
            showMessage(`Error: ${data.error}`, 'error');
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showMessage(`Error: ${error.message}`, 'error');
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// Backward compatibility
async function executeFirewallCommand(action, params) {
    // Map old iptables actions to UFW
    let commandType = action;
    if (action === 'add_rule') {
        commandType = params.target === 'ACCEPT' ? 'allow' : 'deny';
    } else if (action === 'delete_rule') {
        return deleteUFWRule(params.rule_num);
    }

    return executeUFWCommand(commandType, params);
}

// ============================================================================
// HELPERS
// ============================================================================

function showMessage(message, type) {
    const el = document.getElementById('addRuleMessage');
    el.style.display = 'block';
    el.textContent = message;

    if (type === 'error') {
        el.style.background = 'rgba(209, 52, 56, 0.1)';
        el.style.color = '#D13438';
    } else if (type === 'success') {
        el.style.background = 'rgba(16, 124, 16, 0.1)';
        el.style.color = '#107C10';
    } else {
        el.style.background = 'rgba(0, 120, 212, 0.1)';
        el.style.color = '#0078D4';
    }

    if (type !== 'error') {
        setTimeout(() => { el.style.display = 'none'; }, 3000);
    }
}

function showNotification(message, type) {
    if (typeof window.showToast === 'function') {
        window.showToast(message, type);
    }
}

function formatTimeAgo(dateInput) {
    let date;
    if (dateInput instanceof Date) {
        date = dateInput;
    } else {
        // Ensure UTC parsing - append Z if no timezone info
        let dateStr = String(dateInput);
        if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.includes('-', 10)) {
            dateStr += 'Z';
        }
        date = new Date(dateStr);
    }

    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
}

function updateCacheIndicator(endpoint, fromCache) {
    const indicator = document.querySelector(`[data-cache-endpoint="${endpoint}"]`);
    if (indicator) {
        indicator.classList.remove('loading', 'cached', 'fresh', 'error');
        indicator.classList.add(fromCache ? 'cached' : 'fresh');

        const text = indicator.querySelector('.cache-indicator-text');
        if (text) text.textContent = fromCache ? 'Cached' : 'Fresh';

        const refreshBtn = indicator.querySelector('.cache-refresh-btn');
        if (refreshBtn) {
            refreshBtn.classList.remove('spinning');
            refreshBtn.disabled = false;
        }
    }
}

// ============================================================================
// DRAG AND DROP REORDERING
// ============================================================================

let draggedElement = null;
let draggedIndex = null;

function initDragAndDrop() {
    const container = document.getElementById('simpleRulesList');
    if (!container) return;

    const cards = container.querySelectorAll('.simple-rule-card');
    cards.forEach(card => {
        card.addEventListener('dragstart', handleDragStart);
        card.addEventListener('dragover', handleDragOver);
        card.addEventListener('drop', handleDrop);
        card.addEventListener('dragend', handleDragEnd);
        card.addEventListener('dragenter', handleDragEnter);
        card.addEventListener('dragleave', handleDragLeave);
    });
}

function handleDragStart(e) {
    draggedElement = this;
    draggedIndex = parseInt(this.dataset.ruleIndex);
    this.classList.add('dragging');
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', this.dataset.ruleIndex);
}

function handleDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
}

function handleDragEnter(e) {
    e.preventDefault();
    if (this !== draggedElement) {
        this.classList.add('drag-over');
    }
}

function handleDragLeave(e) {
    this.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();

    this.classList.remove('drag-over');

    if (draggedElement !== this) {
        const targetIndex = parseInt(this.dataset.ruleIndex);
        const sourceIndex = draggedIndex;

        if (sourceIndex !== targetIndex) {
            // Show confirmation
            if (confirm(`Move rule #${sourceIndex} to position #${targetIndex}?`)) {
                reorderUFWRules(sourceIndex, targetIndex);
            }
        }
    }

    return false;
}

function handleDragEnd(e) {
    this.classList.remove('dragging');
    document.querySelectorAll('.simple-rule-card').forEach(card => {
        card.classList.remove('drag-over');
    });
    draggedElement = null;
    draggedIndex = null;
}

async function reorderUFWRules(fromIndex, toIndex) {
    if (!currentAgentId) return;

    showMessage('Reordering rules... This may take a moment.', 'info');

    try {
        const response = await fetch(`/api/agents/${currentAgentId}/ufw/reorder`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                from_index: fromIndex,
                to_index: toIndex
            })
        });

        const data = await response.json();

        if (data.success) {
            showMessage('Reorder command queued! Syncing...', 'success');
            showNotification('UFW rules reorder queued', 'success');
            // Request sync and poll for update
            await fetch(`/api/agents/${currentAgentId}/ufw/request-sync`, { method: 'POST' });
            pollForUpdate(currentAgentId);
        } else {
            showMessage(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showMessage(`Error: ${error.message}`, 'error');
    }
}

// Initialize
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFirewallPage);
} else {
    initFirewallPage();
}
