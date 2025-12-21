/**
 * SSH Guardian v3.0 - UFW Firewall Management
 * Easy-to-use interface for UFW (Uncomplicated Firewall) operations
 */

// Module state
window.currentAgentId = window.currentAgentId || null;
let ufwData = null;
let currentAgentIp = null;
let currentAgentData = null;
let recentLogsData = [];
let showAdvanced = false;

// Safe cache indicator update (may not exist on all pages)
function updateCacheIndicator(endpoint, fromCache) {
    const indicator = document.querySelector(`[data-cache-endpoint="${endpoint}"]`);
    if (indicator) {
        indicator.classList.remove('loading', 'cached', 'fresh', 'error', 'stale');
        indicator.classList.add(fromCache ? 'cached' : 'fresh');
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

async function initFirewallPage() {
    setupFirewallEventListeners();
    // Wait for agents to load - this will auto-select an agent and trigger data loading
    await loadAgentsForFirewall();
    // If no agent was auto-selected, still load fail2ban to show "select agent" message
    if (!window.currentAgentId) {
        loadFail2banBans();
        loadF2bStats();
    }
}

function setupFirewallEventListeners() {
    const agentSelector = document.getElementById('firewallAgentSelector');
    if (agentSelector) {
        agentSelector.addEventListener('change', function() {
            const agentId = this.value;
            const syncBtn = document.getElementById('syncNowBtn');
            if (agentId) {
                window.currentAgentId = agentId;
                const selectedOption = this.options[this.selectedIndex];
                currentAgentIp = selectedOption.dataset.ip || null;
                if (syncBtn) syncBtn.style.display = 'inline-block';
                // Save selection for persistence
                localStorage.setItem('firewall_selected_agent', agentId);
                loadAgentDetails(agentId);
                loadUFWData(agentId);
                loadRecentLogs(agentId);
                // Also reload Fail2ban with agent filter
                if (typeof reloadAllF2bData === 'function') {
                    reloadAllF2bData();
                }
            } else {
                window.currentAgentId = null;
                if (syncBtn) syncBtn.style.display = 'none';
                localStorage.removeItem('firewall_selected_agent');
                showNoAgentSelected();
                // Reload Fail2ban without agent filter (show all)
                if (typeof reloadAllF2bData === 'function') {
                    reloadAllF2bData();
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
            if (!selector) return;
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

async function loadUFWData(agentId, forceRefresh = false) {
    showFirewallContent();
    showLoadingStates();

    try {
        // Load fail2ban IPs first for F2B markers in UFW rules
        if (typeof loadFail2banIPs === 'function') {
            await loadFail2banIPs();
        }

        // Always use the LIVE endpoint for real-time UFW data from agent
        const url = `/api/agents/${agentId}/ufw/live`;
        const response = await fetch(url);
        const data = await response.json();

        if (data.success && data.has_data) {
            ufwData = data;

            // Sort rules by rule_index descending (newest/highest index first)
            const sortedRules = [...(data.rules || [])].sort((a, b) => b.rule_index - a.rule_index);

            // Update stats
            updateTopUFWStats(data.state, sortedRules);
            if (typeof updateUFWStats === 'function') {
                updateUFWStats(data.state, sortedRules);
            }

            renderUFWRules(sortedRules);
            renderListeningPorts(data.listening_ports || []);

            if (showAdvanced) {
                renderAdvancedRules(sortedRules);
            }

            updateCacheIndicator('firewall', false);

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

function loadFirewallPage(forceRefresh = false) {
    if (window.currentAgentId) {
        loadAgentDetails(window.currentAgentId);
        loadUFWData(window.currentAgentId, forceRefresh);
        loadRecentLogs(window.currentAgentId);
    }
    loadFail2banBans();
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
    if (indicator) indicator.style.background = isOnline ? TC.successDark : TC.danger;

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
    if (!window.currentAgentId) return;

    try {
        const response = await fetch(`/api/agents/${window.currentAgentId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Agent approved successfully!', 'success');
            const approvalEl = document.getElementById('agentApprovalStatus');
            if (approvalEl) approvalEl.style.display = 'none';
            loadAgentDetails(window.currentAgentId);
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
    if (!window.currentAgentId) {
        showNotification('Please select a server first', 'error');
        return;
    }

    // Use global sync indicator if available
    if (typeof executeUfwSync === 'function') {
        await executeUfwSync(window.currentAgentId);
        return;
    }

    // Fallback to original implementation
    const btn = document.getElementById('syncNowBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="sync-spinning" style="display: inline-block;">🔄</span> Syncing...';
    btn.disabled = true;

    try {
        const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/request-sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Sync request sent! Waiting for agent response...', 'success');

            // Reload data after a short delay with force refresh
            setTimeout(async () => {
                await loadUFWData(window.currentAgentId, true);

                // Also reload blocked IPs as they include UFW DENY rules
                if (typeof loadBlockedIPs === 'function') {
                    loadBlockedIPs();
                }
            }, 3000);
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

    if (loadingEl) loadingEl.style.display = 'block';
    if (containerEl) containerEl.style.display = 'none';
    if (noLogsEl) noLogsEl.style.display = 'none';

    try {
        const response = await fetch(`/api/dashboard/events/list?agent_id=${agentId}&limit=100`);
        const data = await response.json();

        if (loadingEl) loadingEl.style.display = 'none';

        if (data.success && data.events && data.events.length > 0) {
            recentLogsData = data.events;
            renderRecentLogs(data.events);
            if (containerEl) containerEl.style.display = 'block';
        } else {
            if (noLogsEl) noLogsEl.style.display = 'block';
        }
    } catch (error) {
        console.error('Error loading recent logs:', error);
        if (loadingEl) loadingEl.innerHTML = `<span style="color: ${TC.danger};">Error loading logs</span>`;
    }
}

function renderRecentLogs(events) {
    const container = document.getElementById('recentLogsList');
    if (!container) return;

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
        fwStatus.style.color = TC.danger;
    }
    if (fwAllowed) fwAllowed.textContent = '-';
    if (fwBlocked) fwBlocked.textContent = '-';
    if (fwSync) fwSync.textContent = 'Never';
}

function showFirewallError(error) {
    const loading = document.getElementById('simpleRulesLoading');
    if (loading) {
        loading.innerHTML = `<div style="color: ${TC.danger};">Error: ${error}</div>`;
    }
}

function updateTopUFWStats(state, rules) {
    // Ensure we have valid data
    state = state || {};
    rules = rules || [];

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
        fwStatus.style.color = isActive ? TC.successDark : TC.danger;
    }
    if (fwAllowed) fwAllowed.textContent = allowCount;
    if (fwBlocked) fwBlocked.textContent = denyCount;

    // Update UFW toggle button state
    updateUFWToggleButton(isActive);

    // Update last sync time for UFW
    const lastSyncDisplay = document.getElementById('lastSyncDisplay');
    const lastSyncUFW = document.getElementById('lastSyncUFW');

    if (state.last_sync) {
        // Server timestamps are in server timezone (+08:00)
        let syncTime = String(state.last_sync).replace(' ', 'T');
        if (!syncTime.endsWith('Z') && !syncTime.includes('+') && !syncTime.match(/T\d{2}:\d{2}:\d{2}-/)) {
            syncTime += '+08:00';
        }
        const syncDate = new Date(syncTime);
        const timeAgo = formatTimeAgo(syncDate);
        if (fwSync) fwSync.textContent = timeAgo;
        if (lastSyncUFW) lastSyncUFW.textContent = timeAgo;
        if (lastSyncDisplay) lastSyncDisplay.style.display = 'block';

        // Update global sync state
        if (typeof setLastSync === 'function') {
            setLastSync('ufw', syncDate);
        }
    } else {
        if (fwSync) fwSync.textContent = 'Never';
        if (lastSyncUFW) lastSyncUFW.textContent = 'Never';
        if (lastSyncDisplay) lastSyncDisplay.style.display = 'block';
    }

    // Update default policies display if exists
    const defaultIn = document.getElementById('stat-fw-default-in');
    const defaultOut = document.getElementById('stat-fw-default-out');
    if (defaultIn) defaultIn.textContent = state.default_incoming || 'deny';
    if (defaultOut) defaultOut.textContent = state.default_outgoing || 'allow';
}

// ============================================================================
// GLOBAL EXPORTS (for onclick handlers in HTML)
// ============================================================================
window.requestFirewallSync = requestFirewallSync;
window.loadFirewallPage = loadFirewallPage;
window.loadUFWData = loadUFWData;
window.loadAgentDetails = loadAgentDetails;
window.approveAgentFromFirewall = approveAgentFromFirewall;
window.initFirewallPage = initFirewallPage;
window.loadAgentsForFirewall = loadAgentsForFirewall;
window.loadRecentLogs = loadRecentLogs;
window.renderRecentLogs = renderRecentLogs;
window.filterRecentLogs = filterRecentLogs;
window.updateTopUFWStats = updateTopUFWStats;
window.showNoAgentSelected = showNoAgentSelected;
window.showFirewallContent = showFirewallContent;
window.showLoadingStates = showLoadingStates;
window.showNoFirewallData = showNoFirewallData;
window.showFirewallError = showFirewallError;
window.updateAgentHealthDisplay = updateAgentHealthDisplay;
