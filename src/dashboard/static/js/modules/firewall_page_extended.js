/**
 * SSH Guardian v3.0 - Firewall Page Extended Features
 * Listening ports, system users, suggestions, firewall operations, templates
 */

// ============================================================================
// LISTENING PORTS
// ============================================================================

async function loadListeningPorts(agentId) {
    // Check if elements exist (they may not exist in firewall_simple.html)
    const portsLoading = document.getElementById('portsLoading');
    const portsTableContainer = document.getElementById('portsTableContainer');
    const noPorts = document.getElementById('noPorts');

    if (!portsLoading) {
        // Elements don't exist in this page, skip loading
        return;
    }

    try {
        portsLoading.style.display = 'block';
        if (portsTableContainer) portsTableContainer.style.display = 'none';
        if (noPorts) noPorts.style.display = 'none';

        const response = await fetch(`/api/agents/${agentId}/listening-ports`);
        const data = await response.json();

        if (data.success) {
            renderListeningPorts(data.ports, data.protected_count);
        }
    } catch (error) {
        console.error('Error loading ports:', error);
    }
}

function renderListeningPorts(ports, protectedCount) {
    // Check if elements exist (they may not exist in firewall_simple.html)
    const portsLoading = document.getElementById('portsLoading');
    const listeningPortsCount = document.getElementById('listeningPortsCount');
    const protectedPortsCountEl = document.getElementById('protectedPortsCount');
    const portsTableContainer = document.getElementById('portsTableContainer');
    const noPorts = document.getElementById('noPorts');

    // If main elements don't exist, skip rendering (different page template)
    if (!portsLoading && !portsTableContainer) {
        return;
    }

    if (portsLoading) portsLoading.style.display = 'none';
    if (listeningPortsCount) listeningPortsCount.textContent = ports?.length || 0;
    if (protectedPortsCountEl) protectedPortsCountEl.textContent = protectedCount || 0;

    if (!ports || ports.length === 0) {
        if (noPorts) noPorts.style.display = 'block';
        if (portsTableContainer) portsTableContainer.style.display = 'none';
        return;
    }

    if (portsTableContainer) portsTableContainer.style.display = 'block';
    if (noPorts) noPorts.style.display = 'none';

    const tbody = document.getElementById('portsTableBody');
    if (!tbody) return;

    tbody.innerHTML = ports.map(port => `
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 10px 12px; font-weight: 600; font-family: monospace;">${port.port}</td>
            <td style="padding: 10px 12px; text-transform: uppercase;">${port.protocol}</td>
            <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${port.address}</td>
            <td style="padding: 10px 12px;">${port.process_name || '-'}</td>
            <td style="padding: 10px 12px;">${port.user || '-'}</td>
            <td style="padding: 10px 12px;">
                ${port.is_protected ?
                    `<span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; background: ${TC.primaryBg}; color: ${TC.primary};">Protected</span>` :
                    '<span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; background: var(--surface); color: var(--text-secondary);">Normal</span>'
                }
            </td>
            <td style="padding: 10px 12px; text-align: center;">
                ${!isLocalhostAgent ? `
                    ${!port.is_protected ? `
                        <button onclick="addToProtected(${port.port}, '${port.process_name || 'Unknown'}')" style="
                            padding: 4px 8px;
                            background: ${TC.primaryBg};
                            color: ${TC.primary};
                            border: none;
                            border-radius: 2px;
                            cursor: pointer;
                            font-size: 11px;
                        ">Protect</button>
                    ` : ''}
                    <button onclick="createRuleForPort(${port.port}, '${port.protocol}')" style="
                        padding: 4px 8px;
                        background: ${TC.successBg};
                        color: ${TC.successDark};
                        border: none;
                        border-radius: 2px;
                        cursor: pointer;
                        font-size: 11px;
                        margin-left: 4px;
                    ">Add Rule</button>
                ` : '-'}
            </td>
        </tr>
    `).join('');
}

async function addToProtected(port, serviceName) {
    if (!currentAgentId) return;

    if (isLocalhostAgent) {
        showNotification('Cannot modify protected ports for localhost agents (View Only mode)', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/agents/${currentAgentId}/protected-ports`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ port, service_name: serviceName })
        });

        const data = await response.json();
        if (data.success) {
            showNotification('Port added to protected list', 'success');
            loadListeningPorts(currentAgentId);
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error adding protected port', 'error');
    }
}

function createRuleForPort(port, protocol) {
    // Switch to rules tab and pre-fill the form
    switchFirewallTab('rules');
    document.getElementById('addRuleForm').style.display = 'block';
    document.getElementById('ruleProtocol').value = protocol;
    document.getElementById('ruleDport').value = port;
    document.getElementById('ruleTarget').value = 'ACCEPT';
}

// ============================================================================
// SYSTEM USERS
// ============================================================================

async function loadSystemUsers(agentId) {
    try {
        document.getElementById('usersLoading').style.display = 'block';
        document.getElementById('usersTableContainer').style.display = 'none';
        document.getElementById('noUsers').style.display = 'none';

        const loginOnly = document.getElementById('usersFilter').value === 'login';
        const url = `/api/agents/${agentId}/system-users${loginOnly ? '?login_enabled=true' : ''}`;
        const response = await fetch(url);
        const data = await response.json();

        if (data.success) {
            renderSystemUsers(data.users, data.login_enabled_count);
        }
    } catch (error) {
        console.error('Error loading users:', error);
    }
}

function renderSystemUsers(users, loginCount) {
    document.getElementById('usersLoading').style.display = 'none';
    document.getElementById('loginUsersCount').textContent = loginCount || 0;

    if (!users || users.length === 0) {
        document.getElementById('noUsers').style.display = 'block';
        document.getElementById('usersTableContainer').style.display = 'none';
        return;
    }

    document.getElementById('usersTableContainer').style.display = 'block';
    document.getElementById('noUsers').style.display = 'none';

    const tbody = document.getElementById('usersTableBody');
    tbody.innerHTML = users.map(user => `
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 10px 12px; font-weight: 500;">${user.username}</td>
            <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${user.uid}</td>
            <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${user.home_dir}</td>
            <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${user.shell}</td>
            <td style="padding: 10px 12px; font-size: 12px;">${(user.groups || []).slice(0, 3).join(', ')}${user.groups && user.groups.length > 3 ? '...' : ''}</td>
            <td style="padding: 10px 12px; font-size: 12px;">${user.last_login || 'Never'}</td>
            <td style="padding: 10px 12px;">
                ${user.is_system_user ?
                    '<span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; background: var(--surface); color: var(--text-secondary);">System</span>' :
                    `<span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; background: ${TC.successBg}; color: ${TC.successDark};">User</span>`
                }
            </td>
        </tr>
    `).join('');
}

// ============================================================================
// SUGGESTIONS
// ============================================================================

async function loadSuggestions(agentId) {
    try {
        document.getElementById('suggestionsLoading').style.display = 'block';
        document.getElementById('suggestionsContainer').style.display = 'none';
        document.getElementById('noSuggestions').style.display = 'none';

        const priority = document.getElementById('suggestionsFilter').value;
        let url = `/api/agents/${agentId}/suggestions?status=pending`;
        if (priority !== 'all') {
            url += `&priority=${priority}`;
        }

        const response = await fetch(url);
        const data = await response.json();

        if (data.success) {
            renderSuggestions(data.suggestions, data.high_priority);
        }
    } catch (error) {
        console.error('Error loading suggestions:', error);
    }
}

function renderSuggestions(suggestions, highPriorityCount) {
    document.getElementById('suggestionsLoading').style.display = 'none';
    document.getElementById('pendingSuggestionsCount').textContent = suggestions.length;

    // Update badge
    const badge = document.getElementById('suggestionsCount');
    if (suggestions.length > 0) {
        badge.textContent = suggestions.length;
        badge.style.display = 'inline';
    } else {
        badge.style.display = 'none';
    }

    if (!suggestions || suggestions.length === 0) {
        document.getElementById('noSuggestions').style.display = 'block';
        document.getElementById('suggestionsContainer').style.display = 'none';
        return;
    }

    document.getElementById('suggestionsContainer').style.display = 'block';
    document.getElementById('noSuggestions').style.display = 'none';

    const container = document.getElementById('suggestionsList');
    container.innerHTML = suggestions.map(s => `
        <div style="background: var(--background); padding: 16px; border-radius: 4px; border: 1px solid var(--border); border-left: 4px solid ${getPriorityColor(s.priority)};">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                <div>
                    <span style="padding: 2px 8px; border-radius: 2px; font-size: 10px; font-weight: 600; text-transform: uppercase; ${getPriorityStyle(s.priority)}">${s.priority}</span>
                    <span style="margin-left: 8px; font-size: 12px; color: var(--text-secondary);">${s.suggestion_type}</span>
                </div>
                <span style="font-size: 11px; color: var(--text-secondary);">${formatTimeAgo(s.created_at)}</span>
            </div>
            <h4 style="font-size: 14px; font-weight: 600; margin-bottom: 8px;">${s.title}</h4>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">${s.description || ''}</p>
            ${s.rule ? `
                <div style="background: var(--surface); padding: 8px 12px; border-radius: 2px; font-family: monospace; font-size: 11px; margin-bottom: 16px; overflow-x: auto;">
                    ${JSON.stringify(s.rule)}
                </div>
            ` : ''}
            <div style="display: flex; gap: 8px;">
                <button onclick="applySuggestion(${s.id})" style="
                    padding: 6px 16px;
                    background: var(--azure-blue);
                    color: white;
                    border: none;
                    border-radius: 2px;
                    cursor: pointer;
                    font-size: 12px;
                ">Apply</button>
                <button onclick="dismissSuggestion(${s.id})" style="
                    padding: 6px 16px;
                    background: var(--surface);
                    border: 1px solid var(--border);
                    border-radius: 2px;
                    cursor: pointer;
                    font-size: 12px;
                ">Dismiss</button>
            </div>
        </div>
    `).join('');
}

function getPriorityColor(priority) {
    switch (priority) {
        case 'high': return TC.danger;
        case 'medium': return TC.warning;
        case 'low': return TC.successDark;
        default: return 'var(--border)';
    }
}

function getPriorityStyle(priority) {
    switch (priority) {
        case 'high': return `background: ${TC.dangerBg}; color: ${TC.danger};`;
        case 'medium': return `background: ${TC.warningBg}; color: ${TC.warningDark};`;
        case 'low': return `background: ${TC.successBg}; color: ${TC.successDark};`;
        default: return 'background: var(--surface); color: var(--text-secondary);';
    }
}

async function applySuggestion(suggestionId) {
    if (!currentAgentId) return;

    try {
        const response = await fetch(`/api/agents/${currentAgentId}/suggestions/${suggestionId}/apply`, {
            method: 'POST'
        });

        const data = await response.json();
        if (data.success) {
            showNotification('Suggestion applied - command queued', 'success');
            loadSuggestions(currentAgentId);
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error applying suggestion', 'error');
    }
}

async function dismissSuggestion(suggestionId) {
    if (!currentAgentId) return;

    if (!confirm('Dismiss this suggestion?')) return;

    try {
        const response = await fetch(`/api/agents/${currentAgentId}/suggestions/${suggestionId}/dismiss`, {
            method: 'POST'
        });

        const data = await response.json();
        if (data.success) {
            showNotification('Suggestion dismissed', 'info');
            loadSuggestions(currentAgentId);
        } else {
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error dismissing suggestion', 'error');
    }
}

// ============================================================================
// ACTIONS
// ============================================================================

async function submitNewRule() {
    if (!currentAgentId) return;

    const params = {
        table: document.getElementById('ruleTable').value,
        chain: document.getElementById('ruleChain').value,
        target: document.getElementById('ruleTarget').value,
        protocol: document.getElementById('ruleProtocol').value,
        source: document.getElementById('ruleSource').value || undefined,
        destination: document.getElementById('ruleDestination').value || undefined,
        dport: document.getElementById('ruleDport').value || undefined,
        in_interface: document.getElementById('ruleInInterface').value || undefined,
        position: document.getElementById('rulePosition').value || undefined,
        comment: document.getElementById('ruleComment').value || undefined
    };

    // Remove undefined values
    Object.keys(params).forEach(key => {
        if (params[key] === undefined || params[key] === '') {
            delete params[key];
        }
    });

    await executeFirewallCommand('add_rule', params);
}

async function deleteRule(table, chain, ruleNum) {
    if (!currentAgentId) return;

    if (!confirm(`Delete rule #${ruleNum} from ${chain} in ${table} table?`)) {
        return;
    }

    await executeFirewallCommand('delete_rule', { table, chain, rule_num: ruleNum });
}

async function submitPortForward() {
    if (!currentAgentId) return;

    const params = {
        external_port: parseInt(document.getElementById('pfExternalPort').value),
        internal_ip: document.getElementById('pfInternalIP').value,
        internal_port: parseInt(document.getElementById('pfInternalPort').value),
        protocol: document.getElementById('pfProtocol').value,
        interface: document.getElementById('pfInterface').value || undefined
    };

    if (!params.external_port || !params.internal_ip || !params.internal_port) {
        showMessage('addPFMessage', 'Please fill all required fields', 'error');
        return;
    }

    await executeFirewallCommand('add_port_forward', params);
    document.getElementById('addPortForwardForm').style.display = 'none';
}

async function removePortForward(externalPort, internalIP, internalPort, protocol) {
    if (!currentAgentId) return;

    if (!confirm(`Remove port forward ${externalPort} -> ${internalIP}:${internalPort}?`)) {
        return;
    }

    await executeFirewallCommand('remove_port_forward', {
        external_port: externalPort,
        internal_ip: internalIP,
        internal_port: internalPort,
        protocol: protocol
    });
}

async function changeChainPolicy(chain, policy) {
    if (!currentAgentId) return;

    // Block modifications for localhost agents
    if (isLocalhostAgent) {
        showNotification('Cannot modify firewall rules for localhost agents (View Only mode)', 'error');
        return;
    }

    // Skip if no policy selected (default option)
    if (!policy) return;

    if (!['ACCEPT', 'DROP'].includes(policy.toUpperCase())) {
        showNotification('Invalid policy. Use ACCEPT or DROP.', 'error');
        return;
    }

    if (!confirm(`Set ${chain} policy to ${policy}? This will affect all traffic on this chain.`)) {
        return;
    }

    await executeFirewallCommand('set_policy', {
        chain: chain,
        policy: policy.toUpperCase()
    });
}

async function triggerFirewallSync(agentId) {
    // This would need a special endpoint to force immediate sync
    // For now, just reload the data
    showNotification('Refreshing firewall data...', 'info');
    await loadFirewallData(agentId);
}

async function saveFirewallRules(agentId) {
    if (!confirm('Save current iptables rules to persist across reboots?')) {
        return;
    }

    await executeFirewallCommand('save_rules', {
        filepath: '/etc/iptables/rules.v4'
    });
}

async function executeFirewallCommand(action, params) {
    if (!currentAgentId) return;

    // Block all modifications for localhost agents
    if (isLocalhostAgent) {
        showNotification('Cannot execute commands on localhost agents (View Only mode)', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/agents/${currentAgentId}/firewall/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action, params })
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`Command queued: ${action}`, 'success');
            // Reload data after a short delay to see the command in history
            setTimeout(() => loadFirewallData(currentAgentId), 1000);
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        console.error('Error executing command:', error);
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// ============================================================================
// TEMPLATES
// ============================================================================

async function showTemplatesModal() {
    // For now, show hardcoded templates. Later this would fetch from API.
    const templates = [
        { name: 'Allow SSH', desc: 'Allow incoming SSH on port 22', action: 'add_rule', params: { table: 'filter', chain: 'INPUT', protocol: 'tcp', dport: '22', target: 'ACCEPT' } },
        { name: 'Allow HTTP', desc: 'Allow incoming HTTP on port 80', action: 'add_rule', params: { table: 'filter', chain: 'INPUT', protocol: 'tcp', dport: '80', target: 'ACCEPT' } },
        { name: 'Allow HTTPS', desc: 'Allow incoming HTTPS on port 443', action: 'add_rule', params: { table: 'filter', chain: 'INPUT', protocol: 'tcp', dport: '443', target: 'ACCEPT' } },
        { name: 'Allow Established', desc: 'Allow established connections', action: 'add_rule', params: { table: 'filter', chain: 'INPUT', state: 'ESTABLISHED,RELATED', target: 'ACCEPT' } },
        { name: 'Allow Loopback', desc: 'Allow loopback interface', action: 'add_rule', params: { table: 'filter', chain: 'INPUT', in_interface: 'lo', target: 'ACCEPT' } },
        { name: 'Drop All Input', desc: 'Set INPUT policy to DROP', action: 'set_policy', params: { chain: 'INPUT', policy: 'DROP' } }
    ];

    const container = document.getElementById('templatesList');
    container.innerHTML = templates.map(t => `
        <div style="background: var(--background); padding: 16px; border-radius: 4px; border: 1px solid var(--border); cursor: pointer;" onclick="applyTemplate('${t.action}', ${JSON.stringify(t.params).replace(/"/g, '&quot;')})">
            <div style="font-weight: 600; margin-bottom: 4px;">${t.name}</div>
            <div style="font-size: 12px; color: var(--text-secondary);">${t.desc}</div>
        </div>
    `).join('');

    document.getElementById('templatesModal').style.display = 'flex';
}

async function applyTemplate(action, params) {
    document.getElementById('templatesModal').style.display = 'none';
    await executeFirewallCommand(action, params);
}

// ============================================================================
// HELPERS
// ============================================================================

function clearAddRuleForm() {
    const fields = ['ruleTable', 'ruleChain', 'ruleTarget', 'ruleProtocol', 'ruleSource',
                    'ruleDestination', 'ruleDport', 'ruleInInterface', 'rulePosition', 'ruleComment'];
    const defaults = ['filter', 'INPUT', 'ACCEPT', 'all', '', '', '', '', '', ''];
    fields.forEach((id, i) => {
        const el = document.getElementById(id);
        if (el) el.value = defaults[i];
    });
}

function showMessage(elementId, message, type) {
    const el = document.getElementById(elementId);
    if (!el) {
        window.showToast?.(message || elementId, type === 'error' ? 'error' : 'success');
        return;
    }
    el.style.display = 'block';
    el.textContent = message;
    el.style.background = type === 'error' ? TC.dangerBg : TC.successBg;
    el.style.color = type === 'error' ? TC.danger : TC.successDark;
    setTimeout(() => { if (el) el.style.display = 'none'; }, 5000);
}

function formatTimeAgo(dateInput) {
    if (window.TimeSettings?.isLoaded()) return window.TimeSettings.relative(dateInput);
    // Server timestamps are in +08:00 (Asia/Kuala_Lumpur)
    let ts = String(dateInput).replace(' ', 'T');
    if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
    const date = dateInput instanceof Date ? dateInput : new Date(ts);
    const diff = Math.floor((new Date() - date) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
}

// formatDateTime - use shared utility from utils.js
const formatDateTime = window.formatLocalDateTime;

function showNotification(message, type) {
    window.showToast?.(message, type) || alert(message);
}

function updateCacheIndicator(endpoint, fromCache) {
    const indicator = document.querySelector(`[data-cache-endpoint="${endpoint}"]`);
    if (indicator) {
        indicator.classList.remove('loading', 'cached', 'fresh', 'error', 'stale');
        indicator.classList.add(fromCache ? 'cached' : 'fresh');
        const text = indicator.querySelector('.cache-indicator-text');
        if (text) text.textContent = fromCache ? 'Cached' : 'Fresh';
        const refreshBtn = indicator.querySelector('.cache-refresh-btn');
        if (refreshBtn) { refreshBtn.classList.remove('spinning'); refreshBtn.disabled = false; }
    }
    if (typeof CacheManager !== 'undefined') CacheManager?.updateStatus?.(endpoint, fromCache);
}
