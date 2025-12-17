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
    loadFail2banBans();  // Load fail2ban data on init
    loadF2bStats();      // Load fail2ban stats
}

function setupFirewallEventListeners() {
    const agentSelector = document.getElementById('firewallAgentSelector');
    if (agentSelector) {
        agentSelector.addEventListener('change', function() {
            const agentId = this.value;
            const syncBtn = document.getElementById('syncNowBtn');
            if (agentId) {
                currentAgentId = agentId;
                const selectedOption = this.options[this.selectedIndex];
                currentAgentIp = selectedOption.dataset.ip || null;
                if (syncBtn) syncBtn.style.display = 'inline-block';
                // Save selection for persistence
                localStorage.setItem('firewall_selected_agent', agentId);
                loadAgentDetails(agentId);
                loadUFWData(agentId);
                loadRecentLogs(agentId);
                // Also reload Fail2ban and Blocked IPs with agent filter
                loadFail2banBans();
                if (typeof loadBlockedIPs === 'function') {
                    loadBlockedIPs();
                }
            } else {
                currentAgentId = null;
                if (syncBtn) syncBtn.style.display = 'none';
                localStorage.removeItem('firewall_selected_agent');
                showNoAgentSelected();
                // Reload Fail2ban and Blocked IPs without agent filter (show all)
                loadFail2banBans();
                if (typeof loadBlockedIPs === 'function') {
                    loadBlockedIPs();
                }
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
            const noDataWarning = document.getElementById('noFirewallDataWarning');
            if (noDataWarning) noDataWarning.style.display = 'none';
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
    loadFail2banBans();  // Always load fail2ban data
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

    if (statusBadge) {
        statusBadge.textContent = isOnline ? 'Online' : 'Offline';
        statusBadge.className = 'rule-badge ' + (isOnline ? 'allow' : 'block');
    }

    // Update hostname and IP (simplified view)
    const hostnameEl = document.getElementById('agentHealthHostname');
    const ipEl = document.getElementById('agentHealthIP');
    if (hostnameEl) hostnameEl.textContent = agent.hostname || '-';
    if (ipEl) ipEl.textContent = agent.ip_address_primary || '-';

    // Show approval warning if not approved
    const approvalWarning = document.getElementById('agentApprovalStatus');
    if (approvalWarning) {
        approvalWarning.style.display = agent.is_approved ? 'none' : 'block';
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
            const approvalEl = document.getElementById('agentApprovalStatus');
            if (approvalEl) approvalEl.style.display = 'none';
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
    const noAgent = document.getElementById('firewallNoAgent');
    const content = document.getElementById('firewallContent');
    if (noAgent) noAgent.style.display = 'block';
    if (content) content.style.display = 'none';
}

function showFirewallContent() {
    const noAgent = document.getElementById('firewallNoAgent');
    const content = document.getElementById('firewallContent');
    if (noAgent) noAgent.style.display = 'none';
    if (content) content.style.display = 'block';
}

function showLoadingStates() {
    const loading = document.getElementById('simpleRulesLoading');
    const container = document.getElementById('simpleRulesContainer');
    const noRules = document.getElementById('noRulesMessage');
    if (loading) loading.style.display = 'block';
    if (container) container.style.display = 'none';
    if (noRules) noRules.style.display = 'none';
}

function showNoFirewallData() {
    const loading = document.getElementById('simpleRulesLoading');
    const noRules = document.getElementById('noRulesMessage');
    const noDataWarning = document.getElementById('noFirewallDataWarning');
    if (loading) loading.style.display = 'none';
    if (noRules) noRules.style.display = 'block';
    if (noDataWarning) noDataWarning.style.display = 'block';

    // Reset stats
    const fwStatus = document.getElementById('stat-fw-status');
    const fwAllowed = document.getElementById('stat-fw-allowed');
    const fwBlocked = document.getElementById('stat-fw-blocked');
    const fwSync = document.getElementById('stat-fw-sync');

    if (fwStatus) {
        fwStatus.textContent = 'Not installed';
        fwStatus.style.color = '#D13438';
    }
    if (fwAllowed) fwAllowed.textContent = '-';
    if (fwBlocked) fwBlocked.textContent = '-';
    if (fwSync) fwSync.textContent = 'Never';
}

function showFirewallError(error) {
    const loading = document.getElementById('simpleRulesLoading');
    if (loading) {
        loading.innerHTML = `<div style="color: #D13438;">Error: ${error}</div>`;
    }
}

function updateUFWStats(data) {
    const state = data.state || {};
    const rules = data.rules || [];

    // Count allow/deny rules
    const allowCount = rules.filter(r => r.action === 'ALLOW').length;
    const denyCount = rules.filter(r => r.action === 'DENY' || r.action === 'REJECT').length;

    // UFW status
    const isActive = state.ufw_status === 'active';
    const fwStatus = document.getElementById('stat-fw-status');
    const fwAllowed = document.getElementById('stat-fw-allowed');
    const fwBlocked = document.getElementById('stat-fw-blocked');
    const fwSync = document.getElementById('stat-fw-sync');

    if (fwStatus) {
        fwStatus.textContent = isActive ? 'Active' : (state.ufw_status || 'Inactive');
        fwStatus.style.color = isActive ? '#107C10' : '#D13438';
    }
    if (fwAllowed) fwAllowed.textContent = allowCount;
    if (fwBlocked) fwBlocked.textContent = denyCount;

    // Update UFW toggle button state
    updateUFWToggleButton(isActive);

    if (fwSync) {
        if (state.last_sync) {
            // Append 'Z' if not present to indicate UTC
            let syncTime = state.last_sync;
            if (!syncTime.endsWith('Z') && !syncTime.includes('+')) {
                syncTime += 'Z';
            }
            fwSync.textContent = formatTimeAgo(new Date(syncTime));
        } else {
            fwSync.textContent = 'Never';
        }
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
    const loading = document.getElementById('simpleRulesLoading');
    const noRules = document.getElementById('noRulesMessage');
    const rulesContainer = document.getElementById('simpleRulesContainer');
    const container = document.getElementById('simpleRulesList');

    if (loading) loading.style.display = 'none';

    if (rules.length === 0) {
        if (noRules) noRules.style.display = 'block';
        if (rulesContainer) rulesContainer.style.display = 'none';
        return;
    }

    if (rulesContainer) rulesContainer.style.display = 'block';
    if (noRules) noRules.style.display = 'none';
    if (!container) return;

    container.innerHTML = rules.map(rule => {
        const isAllow = rule.action === 'ALLOW';
        const isLimit = rule.action === 'LIMIT';
        const icon = isAllow ? '✅' : (isLimit ? '⏱️' : '🚫');
        const badgeClass = isAllow ? 'allow' : (isLimit ? 'limit' : 'block');
        const action = rule.action;

        const port = rule.to_port || 'Any';
        const protocol = rule.protocol || '';
        const from = rule.from_ip === 'Anywhere' ? '' : rule.from_ip;

        // Generate human-readable description
        let description = '';
        if (port !== 'Any' && port !== '') {
            description += `Port ${port}`;
            if (protocol) description += `/${protocol.toUpperCase()}`;
        } else {
            description = 'All ports';
        }
        if (from) {
            description += ` from ${from}`;
        }

        return `
            <div class="simple-rule-card" data-type="${badgeClass}" data-rule-index="${rule.rule_index}">
                <div class="rule-icon">${icon}</div>
                <div class="rule-details">
                    <div class="rule-title">${description}</div>
                </div>
                <span class="rule-badge ${badgeClass}">${action}</span>
                <button class="rule-delete-btn" onclick="deleteUFWRule(${rule.rule_index})">🗑️</button>
            </div>
        `;
    }).join('');
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
    if (!container) return;  // Element doesn't exist in simplified UI

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
    const customInput = document.getElementById('simpleRuleCustomPort');
    if (customInput) {
        customInput.style.display = select.value === 'custom' ? 'inline-block' : 'none';
    }
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

// Update UFW toggle button state
function updateUFWToggleButton(isActive) {
    const toggleBtn = document.getElementById('ufwToggleBtn');
    if (!toggleBtn) return;

    const icon = toggleBtn.querySelector('.toggle-icon');
    const text = toggleBtn.querySelector('.toggle-text');

    if (isActive) {
        toggleBtn.setAttribute('data-status', 'active');
        if (icon) icon.textContent = '🛡️';
        if (text) text.textContent = 'UFW Active';
    } else {
        toggleBtn.setAttribute('data-status', 'inactive');
        if (icon) icon.textContent = '⚠️';
        if (text) text.textContent = 'UFW Disabled';
    }
}

// Toggle UFW on/off
async function toggleUFW() {
    if (!currentAgentId) {
        showNotification('Please select a server first', 'error');
        return;
    }

    const toggleBtn = document.getElementById('ufwToggleBtn');
    const currentStatus = toggleBtn?.getAttribute('data-status');

    if (currentStatus === 'unknown') {
        showNotification('UFW status is loading, please wait...', 'warning');
        return;
    }

    const isCurrentlyActive = currentStatus === 'active';
    const action = isCurrentlyActive ? 'disable' : 'enable';
    const confirmMsg = isCurrentlyActive
        ? 'WARNING: This will disable the firewall completely. Are you sure?'
        : 'Enable UFW firewall?';

    if (confirm(confirmMsg)) {
        // Set loading state
        const text = toggleBtn?.querySelector('.toggle-text');
        const icon = toggleBtn?.querySelector('.toggle-icon');
        if (text) text.textContent = 'Processing...';
        if (icon) icon.textContent = '⏳';
        toggleBtn?.setAttribute('data-status', 'unknown');

        await executeUFWQuickAction(action, {});
    }
}

async function addSimpleRule() {
    if (!currentAgentId) {
        showMessage('Please select a server first', 'error');
        return;
    }

    const action = document.getElementById('simpleRuleAction').value;
    const protocol = document.getElementById('simpleRuleProtocol').value;
    let port = document.getElementById('simpleRulePort').value;
    let source = document.getElementById('simpleRuleCustomSource').value.trim();

    // Handle custom port
    if (port === 'custom') {
        port = document.getElementById('simpleRuleCustomPort').value.trim();
        if (!port) {
            showMessage('Please enter a custom port', 'error');
            return;
        }
    }

    // Map action to UFW command type
    const commandType = action === 'ACCEPT' ? 'allow' : (action === 'REJECT' ? 'reject' : 'deny');

    const params = {
        port: port && port !== 'any' ? port : undefined,
        protocol: protocol === 'all' ? undefined : protocol,
        from_ip: source || undefined
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

// ============================================================================
// FAIL2BAN INTEGRATION
// ============================================================================

async function loadFail2banBans() {
    const loading = document.getElementById('f2bBansLoading');
    const container = document.getElementById('f2bBansContainer');
    const noBans = document.getElementById('f2bNoBans');
    const bansList = document.getElementById('f2bBansList');
    const banCount = document.getElementById('f2bBanCount');
    const statBans = document.getElementById('stat-f2b-bans');

    if (loading) loading.style.display = 'block';
    if (container) container.style.display = 'none';
    if (noBans) noBans.style.display = 'none';

    try {
        // Build API URL with agent filter if server is selected
        let apiUrl = '/api/dashboard/fail2ban/events?action=ban&time_range=24h&page_size=50';
        if (currentAgentId) {
            apiUrl += `&agent_id=${encodeURIComponent(currentAgentId)}`;
        }

        // Get active bans (bans without matching unbans)
        const response = await fetch(apiUrl);
        const data = await response.json();

        if (loading) loading.style.display = 'none';

        if (data.success && data.events && data.events.length > 0) {
            // Filter to only show truly active bans (not yet unbanned)
            const activeBans = await filterActiveBans(data.events);

            if (activeBans.length > 0) {
                if (container) container.style.display = 'block';
                if (banCount) banCount.textContent = `${activeBans.length} active ban${activeBans.length !== 1 ? 's' : ''}`;
                if (statBans) statBans.textContent = activeBans.length;
                renderFail2banBans(activeBans);
            } else {
                if (noBans) noBans.style.display = 'block';
                if (banCount) banCount.textContent = '0 active bans';
                if (statBans) statBans.textContent = '0';
            }
        } else {
            if (noBans) noBans.style.display = 'block';
            if (banCount) banCount.textContent = '0 active bans';
            if (statBans) statBans.textContent = '0';
        }
    } catch (error) {
        console.error('Error loading fail2ban bans:', error);
        if (loading) loading.style.display = 'none';
        if (noBans) {
            noBans.style.display = 'block';
            noBans.innerHTML = '<div style="color: #D13438;">Error loading fail2ban data</div>';
        }
    }
}

async function filterActiveBans(bans) {
    // Get recent unbans to filter out
    try {
        // Build API URL with agent filter if server is selected
        let apiUrl = '/api/dashboard/fail2ban/events?action=unban&time_range=24h&page_size=100';
        if (currentAgentId) {
            apiUrl += `&agent_id=${encodeURIComponent(currentAgentId)}`;
        }

        const response = await fetch(apiUrl);
        const data = await response.json();

        if (data.success && data.events) {
            const unbannedIPs = new Set(data.events.map(e => e.ip_address));
            // Return bans that haven't been unbanned
            return bans.filter(ban => !unbannedIPs.has(ban.ip_address));
        }
    } catch (e) {
        console.error('Error filtering bans:', e);
    }
    return bans;
}

function renderFail2banBans(bans) {
    const container = document.getElementById('f2bBansList');
    if (!container) return;

    container.innerHTML = bans.map(ban => {
        const timeAgo = ban.reported_at ? formatTimeAgo(ban.reported_at) : 'Unknown';
        const agent = ban.agent_hostname || ban.agent_uuid || 'Unknown agent';

        // Calculate duration and expiry
        const bantime = ban.bantime_seconds || 3600; // Default 1 hour
        const durationStr = formatDuration(bantime);
        const expiryInfo = calculateExpiry(ban.reported_at, bantime);

        return `
            <div class="f2b-ban-card">
                <div class="f2b-ban-icon">🔒</div>
                <div class="f2b-ban-details">
                    <div class="f2b-ban-ip clickable-ip" onclick="showBannedIpDetails('${ban.ip_address}')" title="Click to view details">
                        ${ban.ip_address}
                        <span class="ip-details-hint">ℹ️</span>
                    </div>
                    <div class="f2b-ban-meta">
                        <span>📍 ${ban.jail_name}</span>
                        <span>❌ ${ban.failures || 0} failures</span>
                        <span>🖥️ ${agent}</span>
                        <span>⏱️ ${timeAgo}</span>
                    </div>
                    <div class="f2b-ban-meta" style="margin-top: 4px;">
                        <span class="f2b-duration ${expiryInfo.class}">
                            ⏳ ${durationStr} ban
                        </span>
                        <span style="color: ${expiryInfo.color}">
                            ${expiryInfo.text}
                        </span>
                    </div>
                </div>
                <div style="display: flex; flex-direction: column; gap: 4px;">
                    <button class="f2b-unban-btn" onclick="unbanIP('${ban.ip_address}', '${ban.jail_name}')">
                        🔓 Unban
                    </button>
                    <button class="f2b-escalate-btn" onclick="escalateToUFW('${ban.ip_address}')" title="Permanently block via UFW">
                        ⬆️ UFW
                    </button>
                </div>
            </div>
        `;
    }).join('');
}

// Format duration in human readable form
function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return `${Math.floor(seconds / 86400)}d`;
}

// Calculate expiry time and status
function calculateExpiry(reportedAt, bantimeSeconds) {
    if (!reportedAt || !bantimeSeconds) {
        return { text: 'Unknown expiry', class: '', color: 'var(--text-secondary)' };
    }

    const banStart = new Date(reportedAt);
    const expiryTime = new Date(banStart.getTime() + bantimeSeconds * 1000);
    const now = new Date();
    const remainingMs = expiryTime - now;

    if (remainingMs <= 0) {
        return { text: '⚠️ Expired (pending unban)', class: 'expiring-soon', color: '#d97706' };
    }

    const remainingMins = Math.floor(remainingMs / 60000);
    const remainingHours = Math.floor(remainingMs / 3600000);

    if (remainingMins < 10) {
        return { text: `🔥 Expires in ${remainingMins}m`, class: 'expiring-soon', color: '#d97706' };
    } else if (remainingHours < 1) {
        return { text: `Expires in ${remainingMins}m`, class: '', color: 'var(--text-secondary)' };
    } else {
        return { text: `Expires in ${remainingHours}h ${remainingMins % 60}m`, class: '', color: 'var(--text-secondary)' };
    }
}

// Switch fail2ban sub-tabs
function switchF2bSubtab(subtab) {
    // Update tab buttons
    document.querySelectorAll('.f2b-subtab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.subtab === subtab);
    });

    // Show/hide content
    document.querySelectorAll('.f2b-subtab-content').forEach(content => {
        content.style.display = 'none';
    });

    const activeContent = document.getElementById(`f2b-subtab-${subtab}`);
    if (activeContent) {
        activeContent.style.display = 'block';
    }

    // Load data for the tab
    if (subtab === 'history') {
        loadF2bHistory();
    } else if (subtab === 'threats') {
        loadF2bThreats();
    }
}

// Load fail2ban stats
async function loadF2bStats() {
    try {
        const response = await fetch('/api/dashboard/fail2ban/stats');
        const data = await response.json();

        if (data.success && data.stats) {
            const s = data.stats;
            const active = document.getElementById('f2bStatActive');
            const total = document.getElementById('f2bStatTotal');
            const repeat = document.getElementById('f2bStatRepeat');
            const escalated = document.getElementById('f2bStatEscalated');

            if (active) active.textContent = s.active_bans || 0;
            if (total) total.textContent = s.total_bans || 0;
            if (repeat) repeat.textContent = s.repeat_offenders || 0;
            if (escalated) escalated.textContent = s.escalated_to_ufw || 0;
        }
    } catch (e) {
        console.error('Error loading fail2ban stats:', e);
    }
}

// Load fail2ban history
async function loadF2bHistory() {
    const historyList = document.getElementById('f2bHistoryList');
    const loading = document.getElementById('f2bHistoryLoading');
    const rangeSelect = document.getElementById('f2bHistoryRange');

    if (!historyList) return;

    const timeRange = rangeSelect ? rangeSelect.value : '24h';

    if (loading) loading.style.display = 'block';
    historyList.innerHTML = '';

    try {
        const response = await fetch(`/api/dashboard/fail2ban/events?time_range=${timeRange}&page_size=100`);
        const data = await response.json();

        if (loading) loading.style.display = 'none';

        if (data.success && data.events && data.events.length > 0) {
            historyList.innerHTML = data.events.map(event => {
                const isBan = event.action === 'ban';
                const timeStr = event.reported_at ? formatTimeAgo(event.reported_at) : 'Unknown';
                const durationStr = event.bantime_seconds ? formatDuration(event.bantime_seconds) : '-';

                return `
                    <div class="f2b-history-item ${event.action}">
                        <div class="f2b-history-icon">${isBan ? '🔒' : '🔓'}</div>
                        <div class="f2b-history-details">
                            <div class="f2b-history-ip">${event.ip_address}</div>
                            <div class="f2b-history-meta">
                                ${isBan ? `❌ ${event.failures || 0} failures` : '✅ Released'}
                                • ${event.jail_name}
                                ${isBan && event.bantime_seconds ? `• ${durationStr} ban` : ''}
                                • ${event.agent_hostname || 'Unknown'}
                            </div>
                        </div>
                        <div class="f2b-history-time">${timeStr}</div>
                    </div>
                `;
            }).join('');
        } else {
            historyList.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-secondary);">No events in this time range</div>';
        }
    } catch (e) {
        console.error('Error loading fail2ban history:', e);
        if (loading) loading.style.display = 'none';
        historyList.innerHTML = '<div style="text-align: center; padding: 30px; color: #dc2626;">Error loading history</div>';
    }
}

// Load fail2ban threat analysis
async function loadF2bThreats() {
    const threatList = document.getElementById('f2bThreatList');
    const noThreats = document.getElementById('f2bNoThreats');

    if (!threatList) return;

    try {
        // Get recent bans with their threat analysis
        const response = await fetch('/api/dashboard/fail2ban/events?action=ban&time_range=7d&page_size=20');
        const data = await response.json();

        if (!data.success || !data.events || data.events.length === 0) {
            if (noThreats) noThreats.style.display = 'block';
            threatList.innerHTML = '';
            return;
        }

        if (noThreats) noThreats.style.display = 'none';

        // Fetch threat analysis for each IP
        const threatsHtml = await Promise.all(data.events.slice(0, 10).map(async (event) => {
            try {
                const analysisRes = await fetch(`/api/demo/ip-analysis/${event.ip_address}`);
                const analysis = await analysisRes.json();

                if (!analysis.success) {
                    return renderThreatCard(event, null);
                }

                return renderThreatCard(event, analysis.analysis);
            } catch (e) {
                return renderThreatCard(event, null);
            }
        }));

        threatList.innerHTML = threatsHtml.join('');

    } catch (e) {
        console.error('Error loading threat analysis:', e);
        threatList.innerHTML = '<div style="text-align: center; padding: 30px; color: #dc2626;">Error loading threat data</div>';
    }
}

// Render threat card
function renderThreatCard(event, analysis) {
    const composite = analysis?.composite_risk || {};
    const threat = analysis?.threat_intel || {};
    const ml = analysis?.ml_predictions || {};

    const score = composite.overall_score || ml.risk_score || 0;
    const level = score >= 70 ? 'critical' : score >= 40 ? 'high' : 'medium';

    // Build threat factors
    const factors = [];
    if (threat.is_tor_exit) factors.push('🧅 Tor Exit Node');
    if (threat.is_vpn) factors.push('🔒 VPN/Proxy');
    if (threat.abuseipdb_score > 50) factors.push(`⚠️ AbuseIPDB: ${threat.abuseipdb_score}%`);
    if (event.failures > 5) factors.push(`❌ ${event.failures} failures`);
    if (ml.is_anomaly) factors.push('📊 Anomaly detected');

    const factorsText = factors.length > 0 ? factors.join(' • ') : 'Limited data available';
    const recommendation = score >= 70 ? 'Recommend permanent UFW block' :
                          score >= 40 ? 'Monitor closely' : 'Standard fail2ban handling';

    return `
        <div class="f2b-threat-card ${level}">
            <div class="f2b-threat-score ${level}">${Math.round(score)}</div>
            <div class="f2b-threat-details">
                <div class="f2b-threat-ip">${event.ip_address}</div>
                <div class="f2b-threat-factors">${factorsText}</div>
                <div class="f2b-threat-factors" style="margin-top: 4px; font-style: italic;">
                    💡 ${recommendation}
                </div>
            </div>
            ${score >= 60 ? `
                <button class="f2b-escalate-btn" onclick="escalateToUFW('${event.ip_address}')">
                    ⬆️ Block via UFW
                </button>
            ` : ''}
        </div>
    `;
}

// Escalate ban to permanent UFW block
async function escalateToUFW(ip) {
    if (!confirm(`Permanently block ${ip} via UFW firewall?\n\nThis will create a persistent firewall rule that survives reboots.`)) {
        return;
    }

    try {
        // Use the manual block endpoint with permanent duration
        const response = await fetch('/api/dashboard/blocking/blocks/manual', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip_address: ip,
                reason: 'Escalated from fail2ban - high threat',
                duration_minutes: 0  // 0 = permanent
            })
        });

        const data = await response.json();

        if (data.success) {
            alert(`${ip} has been permanently blocked via UFW`);
            loadFail2banBans();
            loadF2bStats();
        } else if (data.message && data.message.includes('already blocked')) {
            alert(`${ip} is already blocked`);
        } else {
            alert(`Failed to block IP: ${data.error || data.message || 'Unknown error'}`);
        }
    } catch (e) {
        console.error('Error escalating to UFW:', e);
        alert('Error escalating to UFW: ' + e.message);
    }
}

// Show IP details modal for banned IP
async function showBannedIpDetails(ip) {
    if (!ip) return;

    // Show loading state
    showFirewallModal(ip, `
        <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
            <div class="ip-loading-spinner"></div>
            <div style="margin-top: 12px;">Analyzing IP...</div>
        </div>
    `);

    try {
        // Fetch comprehensive IP analysis
        const response = await fetch(`/api/demo/ip-analysis/${ip}`);
        const data = await response.json();

        if (!data.success) {
            throw new Error(data.error || 'Failed to load analysis');
        }

        const analysis = data.analysis || {};
        const geo = analysis.geoip || {};
        const threat = analysis.threat_intel || {};
        const ml = analysis.ml_predictions || {};
        const behavior = analysis.behavioral_analysis || {};
        const composite = analysis.composite_risk || {};
        const history = analysis.history || {};

        // Risk level styling
        const riskScore = composite.overall_score || ml.risk_score || 0;
        const riskLevel = riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'warning' : 'low';
        const riskColor = riskScore >= 70 ? '#dc2626' : riskScore >= 40 ? '#f59e0b' : '#10b981';

        // Build content
        let content = `
            <div class="ip-modal-rich">
                <!-- Risk Score Header -->
                <div class="ip-risk-header" style="border-left-color: ${riskColor}">
                    <div class="ip-risk-score" style="color: ${riskColor}">${Math.round(riskScore)}</div>
                    <div class="ip-risk-label">
                        <span class="ip-risk-level ${riskLevel}">${riskLevel.toUpperCase()} RISK</span>
                        ${ml.threat_type ? `<span class="ip-threat-type">${ml.threat_type}</span>` : ''}
                    </div>
                </div>

                <!-- Quick Stats Grid -->
                <div class="ip-stats-grid">
                    <div class="ip-stat-box">
                        <div class="ip-stat-icon">📍</div>
                        <div class="ip-stat-info">
                            <div class="ip-stat-value">${geo.country || 'Unknown'}</div>
                            <div class="ip-stat-label">${geo.city || ''}</div>
                        </div>
                    </div>
                    <div class="ip-stat-box">
                        <div class="ip-stat-icon">🛡️</div>
                        <div class="ip-stat-info">
                            <div class="ip-stat-value">${threat.abuseipdb_score || 0}%</div>
                            <div class="ip-stat-label">AbuseIPDB</div>
                        </div>
                    </div>
                    <div class="ip-stat-box">
                        <div class="ip-stat-icon">🤖</div>
                        <div class="ip-stat-info">
                            <div class="ip-stat-value">${ml.ml_available ? Math.round(ml.risk_score || 0) + '%' : 'N/A'}</div>
                            <div class="ip-stat-label">ML Score</div>
                        </div>
                    </div>
                    <div class="ip-stat-box">
                        <div class="ip-stat-icon">❌</div>
                        <div class="ip-stat-info">
                            <div class="ip-stat-value">${history.failed_attempts || 0}</div>
                            <div class="ip-stat-label">Failures</div>
                        </div>
                    </div>
                </div>

                <!-- Threat Indicators -->
                <div class="ip-indicators">
                    ${geo.is_tor ? '<span class="ip-tag danger">TOR</span>' : ''}
                    ${geo.is_vpn ? '<span class="ip-tag warning">VPN</span>' : ''}
                    ${geo.is_proxy ? '<span class="ip-tag warning">Proxy</span>' : ''}
                    ${geo.is_datacenter ? '<span class="ip-tag neutral">Datacenter</span>' : ''}
                    ${ml.is_anomaly ? '<span class="ip-tag danger">Anomaly</span>' : ''}
                    ${threat.abuseipdb_reports > 0 ? `<span class="ip-tag warning">${threat.abuseipdb_reports} Reports</span>` : ''}
                </div>

                <!-- Behavior Summary -->
                ${behavior.pattern_summary ? `
                <div class="ip-behavior">
                    <div class="ip-section-title">Behavior Pattern</div>
                    <div class="ip-behavior-text">${behavior.pattern_summary}</div>
                </div>
                ` : ''}

                <!-- ISP Info -->
                <div class="ip-isp">
                    <span class="ip-isp-label">ISP:</span>
                    <span class="ip-isp-value">${geo.isp || 'Unknown'}</span>
                    ${geo.asn ? `<span class="ip-asn">ASN ${geo.asn}</span>` : ''}
                </div>

                <!-- Actions -->
                <div class="ip-modal-actions">
                    <button class="ip-btn-unban" onclick="closeFirewallModal(); unbanIP('${ip}', 'sshd')">
                        Unban
                    </button>
                    <button class="ip-btn-close" onclick="closeFirewallModal()">
                        Close
                    </button>
                </div>
            </div>
        `;

        showFirewallModal(ip, content);

    } catch (error) {
        console.error('Error loading IP details:', error);
        showFirewallModal(ip, `
            <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
                <div style="font-size: 24px; margin-bottom: 8px;">⚠️</div>
                <div>Could not load analysis</div>
                <button class="ip-btn-close" style="margin-top: 16px;" onclick="closeFirewallModal()">Close</button>
            </div>
        `);
    }
}

// Simple modal for firewall page
function showFirewallModal(title, content) {
    // Remove existing modal
    const existing = document.getElementById('firewallIpModal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'firewallIpModal';
    modal.className = 'fw-modal-overlay';
    modal.innerHTML = `
        <div class="fw-modal">
            <div class="fw-modal-header">
                <h3>${title}</h3>
                <button class="fw-modal-close" onclick="closeFirewallModal()">&times;</button>
            </div>
            <div class="fw-modal-body">
                ${content}
            </div>
        </div>
    `;

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeFirewallModal();
    });

    // Close on Escape
    document.addEventListener('keydown', function escHandler(e) {
        if (e.key === 'Escape') {
            closeFirewallModal();
            document.removeEventListener('keydown', escHandler);
        }
    });

    document.body.appendChild(modal);
}

function closeFirewallModal() {
    const modal = document.getElementById('firewallIpModal');
    if (modal) modal.remove();
}

async function unbanIP(ip, jail) {
    if (!confirm(`Unban IP ${ip} from ${jail}?`)) return;

    try {
        // Send unban command to agent via fail2ban
        const response = await fetch('/api/dashboard/fail2ban/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip_address: ip,
                jail: jail
            })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`Unban command sent for ${ip}`, 'success');
            // Reload the bans list
            setTimeout(() => loadFail2banBans(), 1000);
        } else {
            showNotification(`Error: ${data.error || 'Failed to unban'}`, 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

async function quickBlockIP() {
    const ip = document.getElementById('quickBlockIP').value.trim();
    const method = document.getElementById('quickBlockMethod').value;
    const duration = parseInt(document.getElementById('quickBlockDuration').value);
    const msgEl = document.getElementById('quickBlockMessage');

    if (!ip) {
        showQuickBlockMessage('Please enter an IP address', 'error');
        return;
    }

    // Validate IP format
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
        showQuickBlockMessage('Invalid IP address format', 'error');
        return;
    }

    showQuickBlockMessage('Blocking IP...', 'info');

    try {
        if (method === 'ufw') {
            // Block via UFW
            if (!currentAgentId) {
                showQuickBlockMessage('Please select a server first for UFW blocking', 'error');
                return;
            }

            const response = await fetch(`/api/agents/${currentAgentId}/ufw/quick-action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action_type: 'block_ip',
                    ip: ip
                })
            });

            const data = await response.json();

            if (data.success) {
                showQuickBlockMessage(`IP ${ip} blocked via UFW`, 'success');
                document.getElementById('quickBlockIP').value = '';
                // Refresh UFW data
                if (currentAgentId) loadUFWData(currentAgentId);
            } else {
                showQuickBlockMessage(`Error: ${data.error}`, 'error');
            }
        } else {
            // Block via fail2ban
            const response = await fetch('/api/dashboard/fail2ban/ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip_address: ip,
                    jail: 'sshd',
                    bantime: duration,
                    reason: 'Manual block from dashboard'
                })
            });

            const data = await response.json();

            if (data.success) {
                showQuickBlockMessage(`IP ${ip} blocked via fail2ban`, 'success');
                document.getElementById('quickBlockIP').value = '';
                // Refresh fail2ban data
                loadFail2banBans();
            } else {
                showQuickBlockMessage(`Error: ${data.error}`, 'error');
            }
        }
    } catch (error) {
        showQuickBlockMessage(`Error: ${error.message}`, 'error');
    }
}

function showQuickBlockMessage(message, type) {
    const el = document.getElementById('quickBlockMessage');
    if (!el) return;

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

// Initialize
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFirewallPage);
} else {
    initFirewallPage();
}

// Expose functions globally for inline onclick handlers
window.showBannedIpDetails = showBannedIpDetails;
window.showFirewallModal = showFirewallModal;
window.closeFirewallModal = closeFirewallModal;
window.switchF2bSubtab = switchF2bSubtab;
window.loadF2bHistory = loadF2bHistory;
window.loadF2bThreats = loadF2bThreats;
window.escalateToUFW = escalateToUFW;
window.loadF2bStats = loadF2bStats;
