/**
 * SSH Guardian v3.0 - Firewall Management Page Module
 * Handles iptables rule viewing and management
 */

let currentAgentId = null;
let firewallData = null;
let currentAgentIp = null;
let isLocalhostAgent = false;

// ============================================================================
// INITIALIZATION
// ============================================================================

function initFirewallPage() {
    // Load agents for selector
    loadAgentsForFirewall();

    // Setup event listeners
    setupFirewallEventListeners();
}

function setupFirewallEventListeners() {
    // Agent selector
    const agentSelector = document.getElementById('firewallAgentSelector');
    if (agentSelector) {
        agentSelector.addEventListener('change', function() {
            const agentId = this.value;
            if (agentId) {
                currentAgentId = agentId;
                // Get agent IP from the selected option's data attribute
                const selectedOption = this.options[this.selectedIndex];
                currentAgentIp = selectedOption.dataset.ip || null;
                isLocalhostAgent = isLocalhost(currentAgentIp);
                loadFirewallData(agentId);
            } else {
                currentAgentId = null;
                currentAgentIp = null;
                isLocalhostAgent = false;
                showNoAgentSelected();
            }
        });
    }

    // Tab navigation
    document.querySelectorAll('.fw-tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            switchFirewallTab(this.dataset.tab);
        });
    });

    // Filter changes
    ['filterTable', 'filterChain', 'filterTarget'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', applyRulesFilter);
        }
    });

    // Action buttons
    setupActionButtons();
}

function setupActionButtons() {
    // Sync Now
    const syncBtn = document.getElementById('syncFirewallNow');
    if (syncBtn) {
        syncBtn.addEventListener('click', () => {
            if (currentAgentId) {
                triggerFirewallSync(currentAgentId);
            }
        });
    }

    // Save Rules
    const saveBtn = document.getElementById('saveFirewallRules');
    if (saveBtn) {
        saveBtn.addEventListener('click', () => {
            if (currentAgentId) {
                saveFirewallRules(currentAgentId);
            }
        });
    }

    // Add Rule Form
    const showAddRuleBtn = document.getElementById('showAddRuleForm');
    if (showAddRuleBtn) {
        showAddRuleBtn.addEventListener('click', () => {
            document.getElementById('addRuleForm').style.display = 'block';
        });
    }

    const cancelAddRuleBtn = document.getElementById('cancelAddRule');
    if (cancelAddRuleBtn) {
        cancelAddRuleBtn.addEventListener('click', () => {
            document.getElementById('addRuleForm').style.display = 'none';
            clearAddRuleForm();
        });
    }

    const submitAddRuleBtn = document.getElementById('submitAddRule');
    if (submitAddRuleBtn) {
        submitAddRuleBtn.addEventListener('click', submitNewRule);
    }

    // Templates Modal
    const showTemplatesBtn = document.getElementById('showTemplates');
    if (showTemplatesBtn) {
        showTemplatesBtn.addEventListener('click', showTemplatesModal);
    }

    const closeTemplatesBtn = document.getElementById('closeTemplatesModal');
    if (closeTemplatesBtn) {
        closeTemplatesBtn.addEventListener('click', () => {
            document.getElementById('templatesModal').style.display = 'none';
        });
    }

    // Port Forward Form
    const showPFBtn = document.getElementById('showAddPortForward');
    if (showPFBtn) {
        showPFBtn.addEventListener('click', () => {
            document.getElementById('addPortForwardForm').style.display = 'block';
        });
    }

    const cancelPFBtn = document.getElementById('cancelPortForward');
    if (cancelPFBtn) {
        cancelPFBtn.addEventListener('click', () => {
            document.getElementById('addPortForwardForm').style.display = 'none';
        });
    }

    const submitPFBtn = document.getElementById('submitPortForward');
    if (submitPFBtn) {
        submitPFBtn.addEventListener('click', submitPortForward);
    }

    // Extended tabs filters
    const portsFilter = document.getElementById('portsFilter');
    if (portsFilter) {
        portsFilter.addEventListener('change', () => {
            if (currentAgentId) loadListeningPorts(currentAgentId);
        });
    }

    const usersFilter = document.getElementById('usersFilter');
    if (usersFilter) {
        usersFilter.addEventListener('change', () => {
            if (currentAgentId) loadSystemUsers(currentAgentId);
        });
    }

    const suggestionsFilter = document.getElementById('suggestionsFilter');
    if (suggestionsFilter) {
        suggestionsFilter.addEventListener('change', () => {
            if (currentAgentId) loadSuggestions(currentAgentId);
        });
    }

    const refreshSuggestionsBtn = document.getElementById('refreshSuggestions');
    if (refreshSuggestionsBtn) {
        refreshSuggestionsBtn.addEventListener('click', () => {
            if (currentAgentId) loadSuggestions(currentAgentId);
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
            selector.innerHTML = '<option value="">-- Select an agent --</option>';

            data.agents.forEach(agent => {
                const option = document.createElement('option');
                option.value = agent.id;
                option.dataset.ip = agent.ip_address_primary || '';
                const ipDisplay = agent.ip_address_primary || agent.agent_id;
                const isLocal = isLocalhost(agent.ip_address_primary);
                option.textContent = `${agent.hostname} (${ipDisplay})${isLocal ? ' [View Only]' : ''}`;
                if (agent.status === 'online') {
                    option.textContent += ' - Online';
                }
                selector.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

// Helper function to check if IP is localhost
function isLocalhost(ip) {
    if (!ip) return false;
    return ip === '127.0.0.1' || ip === 'localhost' || ip === '::1';
}

async function loadFirewallData(agentId) {
    console.log('[Firewall] Loading data for agent:', agentId);
    showFirewallContent();
    showLoadingStates();

    try {
        const response = await fetch(`/api/agents/${agentId}/firewall`);
        console.log('[Firewall] Response status:', response.status);
        const data = await response.json();
        console.log('[Firewall] Data received:', data.success, 'has_data:', data.has_data, 'rules_flat:', data.rules_flat?.length);

        if (data.success) {
            firewallData = data;

            if (data.has_data) {
                console.log('[Firewall] Rendering data...');
                updateFirewallStats(data.state);
                updateChainPolicies(data.state);
                console.log('[Firewall] Rendering rules table with', data.rules_flat?.length, 'rules');
                renderRulesTable(data.rules_flat || []);
                renderPortForwards(data.port_forwards || []);
                renderInterfaces(data.interfaces || []);
                renderCommandHistory(data.recent_commands || []);
                console.log('[Firewall] Render complete');

                // Enable action buttons (except for localhost agents)
                document.getElementById('syncFirewallNow').disabled = false;
                document.getElementById('saveFirewallRules').disabled = isLocalhostAgent;

                // Hide/show action buttons based on agent type
                updateActionButtonsVisibility();

                // Update cache indicator
                updateCacheIndicator('firewall', data.from_cache);
            } else {
                console.log('[Firewall] No data available');
                showNoFirewallData();
            }
        } else {
            console.log('[Firewall] Error:', data.error);
            showFirewallError(data.error);
        }
    } catch (error) {
        console.error('[Firewall] Error loading firewall data:', error);
        showFirewallError(error.message);

        // Set cache indicator to error state
        const indicator = document.querySelector('[data-cache-endpoint="firewall"]');
        if (indicator) {
            indicator.classList.remove('loading', 'cached', 'fresh', 'stale');
            indicator.classList.add('error');
            const text = indicator.querySelector('.cache-indicator-text');
            if (text) text.textContent = 'Error';
            const refreshBtn = indicator.querySelector('.cache-refresh-btn');
            if (refreshBtn) {
                refreshBtn.classList.remove('spinning');
                refreshBtn.disabled = false;
            }
        }
    }
}

function loadFirewallPage() {
    if (currentAgentId) {
        loadFirewallData(currentAgentId);
    }
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
    document.getElementById('rulesLoading').style.display = 'block';
    document.getElementById('rulesTableContainer').style.display = 'none';
    document.getElementById('portForwardsLoading').style.display = 'block';
    document.getElementById('portForwardsTableContainer').style.display = 'none';
    document.getElementById('interfacesLoading').style.display = 'block';
    document.getElementById('interfacesContainer').style.display = 'none';
    document.getElementById('commandsLoading').style.display = 'block';
    document.getElementById('commandsTableContainer').style.display = 'none';

    // Set cache indicator to loading state
    const indicator = document.querySelector('[data-cache-endpoint="firewall"]');
    if (indicator) {
        indicator.classList.remove('cached', 'fresh', 'error', 'stale');
        indicator.classList.add('loading');
        const text = indicator.querySelector('.cache-indicator-text');
        if (text) text.textContent = 'Loading...';
        const refreshBtn = indicator.querySelector('.cache-refresh-btn');
        if (refreshBtn) {
            refreshBtn.classList.add('spinning');
            refreshBtn.disabled = true;
        }
    }
}

function showNoFirewallData() {
    document.getElementById('rulesLoading').innerHTML = `
        <div style="font-size: 32px; margin-bottom: 12px;">📋</div>
        <p>No firewall data available for this agent.</p>
        <p style="font-size: 12px; margin-top: 8px;">The agent may not have sent firewall data yet, or firewall collection may be disabled.</p>
    `;
}

function showFirewallError(error) {
    document.getElementById('rulesError').style.display = 'block';
    document.getElementById('rulesError').textContent = `Error: ${error}`;
    document.getElementById('rulesLoading').style.display = 'none';
}

function updateActionButtonsVisibility() {
    // Hide or show action buttons based on whether agent is localhost
    const addRuleBtn = document.getElementById('showAddRuleForm');
    const templatesBtn = document.getElementById('showTemplates');
    const addPortForwardBtn = document.getElementById('showAddPortForward');
    const saveBtn = document.getElementById('saveFirewallRules');

    if (isLocalhostAgent) {
        // Disable/hide action buttons for localhost
        if (addRuleBtn) {
            addRuleBtn.style.display = 'none';
        }
        if (templatesBtn) {
            templatesBtn.style.display = 'none';
        }
        if (addPortForwardBtn) {
            addPortForwardBtn.style.display = 'none';
        }
        if (saveBtn) {
            saveBtn.style.display = 'none';
        }
    } else {
        // Show action buttons for remote agents
        if (addRuleBtn) {
            addRuleBtn.style.display = '';
        }
        if (templatesBtn) {
            templatesBtn.style.display = '';
        }
        if (addPortForwardBtn) {
            addPortForwardBtn.style.display = '';
        }
        if (saveBtn) {
            saveBtn.style.display = '';
        }
    }
}

function updateFirewallStats(state) {
    const status = state.status || {};

    document.getElementById('stat-fw-status').textContent =
        status.iptables_active ? 'Active' : 'Inactive';
    document.getElementById('stat-fw-status').style.color =
        status.iptables_active ? '#107C10' : '#D13438';

    document.getElementById('stat-fw-rules').textContent =
        state.rules_count || status.total_rules || 0;

    document.getElementById('stat-fw-forwards').textContent =
        state.port_forwards_count || status.port_forwards_count || 0;

    if (state.last_sync) {
        const lastSync = new Date(state.last_sync);
        document.getElementById('stat-fw-sync').textContent = formatTimeAgo(lastSync);
    } else {
        document.getElementById('stat-fw-sync').textContent = 'Never';
    }
}

function updateChainPolicies(state) {
    const status = state.status || {};
    const policiesContainer = document.getElementById('chainPolicies');

    const policies = [
        { name: 'INPUT', policy: status.default_input_policy || 'UNKNOWN' },
        { name: 'OUTPUT', policy: status.default_output_policy || 'UNKNOWN' },
        { name: 'FORWARD', policy: status.default_forward_policy || 'UNKNOWN' }
    ];

    policiesContainer.innerHTML = policies.map(p => `
        <div style="background: var(--background); padding: 16px; border-radius: 4px; border: 1px solid var(--border);">
            <div style="font-weight: 600; margin-bottom: 8px;">${p.name}</div>
            <div style="display: flex; align-items: center; gap: 8px;">
                <span class="policy-badge policy-${p.policy.toLowerCase()}" style="
                    padding: 4px 12px;
                    border-radius: 2px;
                    font-size: 12px;
                    font-weight: 600;
                    ${getPolicyStyle(p.policy)}
                ">${p.policy}</span>
                ${!isLocalhostAgent ? `
                    <select onchange="changeChainPolicy('${p.name}', this.value)" style="
                        padding: 4px 8px;
                        background: var(--surface);
                        border: 1px solid var(--border);
                        border-radius: 2px;
                        font-size: 11px;
                        cursor: pointer;
                    ">
                        <option value="">Change to...</option>
                        <option value="ACCEPT" ${p.policy === 'ACCEPT' ? 'disabled' : ''}>ACCEPT</option>
                        <option value="DROP" ${p.policy === 'DROP' ? 'disabled' : ''}>DROP</option>
                    </select>
                ` : `
                    <span style="font-size: 11px; color: var(--text-secondary);">(View Only)</span>
                `}
            </div>
        </div>
    `).join('');
}

function getPolicyStyle(policy) {
    switch (policy.toUpperCase()) {
        case 'ACCEPT':
            return 'background: rgba(16, 124, 16, 0.1); color: #107C10;';
        case 'DROP':
            return 'background: rgba(209, 52, 56, 0.1); color: #D13438;';
        case 'REJECT':
            return 'background: rgba(255, 185, 0, 0.1); color: #CC9400;';
        default:
            return 'background: var(--surface); color: var(--text-secondary);';
    }
}

function switchFirewallTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.fw-tab-btn').forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
            btn.style.borderBottom = '2px solid var(--azure-blue)';
            btn.style.color = 'var(--text-primary)';
        } else {
            btn.classList.remove('active');
            btn.style.borderBottom = 'none';
            btn.style.color = 'var(--text-secondary)';
        }
    });

    // Show/hide tab content
    document.querySelectorAll('.fw-tab-content').forEach(content => {
        content.style.display = 'none';
    });
    document.getElementById(`fw-tab-${tabName}`).style.display = 'block';

    // Load data for the new tab if needed
    if (currentAgentId) {
        switch (tabName) {
            case 'ports':
                loadListeningPorts(currentAgentId);
                break;
            case 'users':
                loadSystemUsers(currentAgentId);
                break;
            case 'suggestions':
                loadSuggestions(currentAgentId);
                break;
        }
    }
}

// ============================================================================
// RULES TABLE
// ============================================================================

function renderRulesTable(rules) {
    const loadingEl = document.getElementById('rulesLoading');
    const containerEl = document.getElementById('rulesTableContainer');
    const gridEl = document.getElementById('rulesGrid');

    console.log('[Firewall] renderRulesTable - Elements found:', {
        loading: !!loadingEl,
        container: !!containerEl,
        grid: !!gridEl
    });

    if (!loadingEl || !containerEl || !gridEl) {
        console.error('[Firewall] Missing DOM elements!');
        return;
    }

    // Hide loading, show container
    loadingEl.style.display = 'none';
    containerEl.style.display = 'block';

    console.log('[Firewall] After style update - loading display:', loadingEl.style.display, 'container display:', containerEl.style.display);

    if (!rules || rules.length === 0) {
        gridEl.innerHTML = `
            <div style="padding: 40px; text-align: center; color: var(--text-secondary);">
                No rules found
            </div>
        `;
        return;
    }

    // Generate the entire table HTML
    const tableHTML = `
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
            <thead>
                <tr style="background: var(--background); border-bottom: 2px solid var(--border);">
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Table</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Chain</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">#</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Target</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Protocol</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Source</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Destination</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Ports</th>
                    <th style="padding: 12px; text-align: left; font-weight: 600;">Packets</th>
                    <th style="padding: 12px; text-align: center; font-weight: 600;">Actions</th>
                </tr>
            </thead>
            <tbody>
                ${rules.map(rule => `
                    <tr style="border-bottom: 1px solid var(--border);" data-table="${rule.table_name}" data-chain="${rule.chain}" data-target="${rule.target}">
                        <td style="padding: 10px 12px;">
                            <span style="padding: 2px 8px; background: var(--background); border-radius: 2px; font-size: 11px;">${rule.table_name}</span>
                        </td>
                        <td style="padding: 10px 12px; font-weight: 500;">${rule.chain}</td>
                        <td style="padding: 10px 12px;">${rule.rule_num}</td>
                        <td style="padding: 10px 12px;">
                            <span style="padding: 2px 8px; border-radius: 2px; font-size: 12px; ${getTargetStyle(rule.target)}">${rule.target}</span>
                        </td>
                        <td style="padding: 10px 12px;">${rule.protocol || 'all'}</td>
                        <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${rule.source_ip || '0.0.0.0/0'}</td>
                        <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${rule.destination_ip || '0.0.0.0/0'}</td>
                        <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${rule.ports || '-'}</td>
                        <td style="padding: 10px 12px; font-size: 12px;">${formatPacketCount(rule.packets_count)}</td>
                        <td style="padding: 10px 12px; text-align: center;">
                            ${!isLocalhostAgent ? `
                                <button onclick="deleteRule('${rule.table_name}', '${rule.chain}', ${rule.rule_num})" style="
                                    padding: 4px 8px;
                                    background: rgba(209, 52, 56, 0.1);
                                    color: #D13438;
                                    border: none;
                                    border-radius: 2px;
                                    cursor: pointer;
                                    font-size: 11px;
                                " title="Delete rule">Delete</button>
                            ` : '-'}
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;

    gridEl.innerHTML = tableHTML;
    console.log('[Firewall] Table rendered with', rules.length, 'rows');
}

function getTargetStyle(target) {
    switch (target.toUpperCase()) {
        case 'ACCEPT':
            return 'background: rgba(16, 124, 16, 0.1); color: #107C10;';
        case 'DROP':
            return 'background: rgba(209, 52, 56, 0.1); color: #D13438;';
        case 'REJECT':
            return 'background: rgba(255, 185, 0, 0.1); color: #CC9400;';
        case 'LOG':
            return 'background: rgba(0, 120, 212, 0.1); color: #0078D4;';
        case 'DNAT':
        case 'SNAT':
        case 'MASQUERADE':
            return 'background: rgba(135, 100, 184, 0.1); color: #8764B8;';
        default:
            return 'background: var(--surface); color: var(--text-secondary);';
    }
}

function formatPacketCount(count) {
    if (!count) return '0';
    if (count >= 1000000) return (count / 1000000).toFixed(1) + 'M';
    if (count >= 1000) return (count / 1000).toFixed(1) + 'K';
    return count.toString();
}

function applyRulesFilter() {
    const filterTable = document.getElementById('filterTable').value;
    const filterChain = document.getElementById('filterChain').value;
    const filterTarget = document.getElementById('filterTarget').value;

    const rows = document.querySelectorAll('#rulesGrid tr[data-table]');

    rows.forEach(row => {
        let show = true;

        if (filterTable && row.dataset.table !== filterTable) show = false;
        if (filterChain && row.dataset.chain !== filterChain) show = false;
        if (filterTarget && row.dataset.target !== filterTarget) show = false;

        row.style.display = show ? '' : 'none';
    });
}

// ============================================================================
// PORT FORWARDS
// ============================================================================

function renderPortForwards(portForwards) {
    document.getElementById('portForwardsLoading').style.display = 'none';

    if (!portForwards || portForwards.length === 0) {
        document.getElementById('noPortForwards').style.display = 'block';
        document.getElementById('portForwardsTableContainer').style.display = 'none';
        return;
    }

    document.getElementById('portForwardsTableContainer').style.display = 'block';
    document.getElementById('noPortForwards').style.display = 'none';

    const tbody = document.getElementById('portForwardsTableBody');
    tbody.innerHTML = portForwards.map(pf => `
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 10px 12px; font-weight: 500;">${pf.external_port}</td>
            <td style="padding: 10px 12px; font-family: monospace;">${pf.internal_ip}</td>
            <td style="padding: 10px 12px;">${pf.internal_port}</td>
            <td style="padding: 10px 12px; text-transform: uppercase;">${pf.protocol}</td>
            <td style="padding: 10px 12px;">${pf.interface || '-'}</td>
            <td style="padding: 10px 12px;">
                <span style="padding: 2px 8px; border-radius: 2px; font-size: 12px; ${pf.is_enabled ? 'background: rgba(16, 124, 16, 0.1); color: #107C10;' : 'background: var(--surface); color: var(--text-secondary);'}">
                    ${pf.is_enabled ? 'Active' : 'Disabled'}
                </span>
            </td>
            <td style="padding: 10px 12px; text-align: center;">
                ${!isLocalhostAgent ? `
                    <button onclick="removePortForward(${pf.external_port}, '${pf.internal_ip}', ${pf.internal_port}, '${pf.protocol}')" style="
                        padding: 4px 8px;
                        background: rgba(209, 52, 56, 0.1);
                        color: #D13438;
                        border: none;
                        border-radius: 2px;
                        cursor: pointer;
                        font-size: 11px;
                    ">Remove</button>
                ` : '-'}
            </td>
        </tr>
    `).join('');
}

// ============================================================================
// INTERFACES
// ============================================================================

function renderInterfaces(interfaces) {
    document.getElementById('interfacesLoading').style.display = 'none';
    document.getElementById('interfacesContainer').style.display = 'block';

    const container = document.getElementById('interfacesGrid');

    if (!interfaces || interfaces.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 20px;">No interface data available</p>';
        return;
    }

    container.innerHTML = interfaces.map(iface => {
        const addresses = iface.addresses || [];
        const ipv4 = addresses.filter(a => a.family === 'inet' || a.family === 'inet4');
        const ipv6 = addresses.filter(a => a.family === 'inet6');

        return `
            <div style="background: var(--background); padding: 16px; border-radius: 4px; border: 1px solid var(--border);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <span style="font-weight: 600; font-size: 14px;">${iface.interface_name}</span>
                    <span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; ${iface.state === 'UP' ? 'background: rgba(16, 124, 16, 0.1); color: #107C10;' : 'background: var(--surface); color: var(--text-secondary);'}">
                        ${iface.state || 'unknown'}
                    </span>
                </div>
                ${iface.mac_address ? `<div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">MAC: ${iface.mac_address}</div>` : ''}
                ${ipv4.length > 0 ? `
                    <div style="margin-top: 8px;">
                        <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">IPv4:</div>
                        ${ipv4.map(a => `<div style="font-family: monospace; font-size: 13px;">${a.ip}${a.prefix ? '/' + a.prefix : ''}</div>`).join('')}
                    </div>
                ` : ''}
                ${ipv6.length > 0 ? `
                    <div style="margin-top: 8px;">
                        <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">IPv6:</div>
                        ${ipv6.map(a => `<div style="font-family: monospace; font-size: 11px; word-break: break-all;">${a.ip}${a.prefix ? '/' + a.prefix : ''}</div>`).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    }).join('');
}

// ============================================================================
// COMMAND HISTORY
// ============================================================================

function renderCommandHistory(commands) {
    document.getElementById('commandsLoading').style.display = 'none';

    if (!commands || commands.length === 0) {
        document.getElementById('noCommands').style.display = 'block';
        document.getElementById('commandsTableContainer').style.display = 'none';
        return;
    }

    document.getElementById('commandsTableContainer').style.display = 'block';
    document.getElementById('noCommands').style.display = 'none';

    const tbody = document.getElementById('commandsTableBody');
    tbody.innerHTML = commands.map(cmd => `
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 10px 12px; font-size: 12px;">${formatDateTime(cmd.created_at)}</td>
            <td style="padding: 10px 12px; font-weight: 500;">${cmd.action}</td>
            <td style="padding: 10px 12px; font-size: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis;">
                <code style="font-size: 11px;">${JSON.stringify(cmd.params || {})}</code>
            </td>
            <td style="padding: 10px 12px;">
                <span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; ${getStatusStyle(cmd.status)}">
                    ${cmd.status}
                </span>
            </td>
            <td style="padding: 10px 12px; font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                ${cmd.result_message || '-'}
            </td>
        </tr>
    `).join('');
}

function getStatusStyle(status) {
    switch (status) {
        case 'completed':
            return 'background: rgba(16, 124, 16, 0.1); color: #107C10;';
        case 'failed':
            return 'background: rgba(209, 52, 56, 0.1); color: #D13438;';
        case 'pending':
            return 'background: rgba(255, 185, 0, 0.1); color: #CC9400;';
        case 'sent':
            return 'background: rgba(0, 120, 212, 0.1); color: #0078D4;';
        default:
            return 'background: var(--surface); color: var(--text-secondary);';
    }
}

// ============================================================================
// LISTENING PORTS
// ============================================================================

async function loadListeningPorts(agentId) {
    try {
        document.getElementById('portsLoading').style.display = 'block';
        document.getElementById('portsTableContainer').style.display = 'none';
        document.getElementById('noPorts').style.display = 'none';

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
    document.getElementById('portsLoading').style.display = 'none';
    document.getElementById('listeningPortsCount').textContent = ports.length;
    document.getElementById('protectedPortsCount').textContent = protectedCount || 0;

    if (!ports || ports.length === 0) {
        document.getElementById('noPorts').style.display = 'block';
        document.getElementById('portsTableContainer').style.display = 'none';
        return;
    }

    document.getElementById('portsTableContainer').style.display = 'block';
    document.getElementById('noPorts').style.display = 'none';

    const tbody = document.getElementById('portsTableBody');
    tbody.innerHTML = ports.map(port => `
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 10px 12px; font-weight: 600; font-family: monospace;">${port.port}</td>
            <td style="padding: 10px 12px; text-transform: uppercase;">${port.protocol}</td>
            <td style="padding: 10px 12px; font-family: monospace; font-size: 12px;">${port.address}</td>
            <td style="padding: 10px 12px;">${port.process_name || '-'}</td>
            <td style="padding: 10px 12px;">${port.user || '-'}</td>
            <td style="padding: 10px 12px;">
                ${port.is_protected ?
                    '<span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; background: rgba(0, 120, 212, 0.1); color: #0078D4;">Protected</span>' :
                    '<span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; background: var(--surface); color: var(--text-secondary);">Normal</span>'
                }
            </td>
            <td style="padding: 10px 12px; text-align: center;">
                ${!isLocalhostAgent ? `
                    ${!port.is_protected ? `
                        <button onclick="addToProtected(${port.port}, '${port.process_name || 'Unknown'}')" style="
                            padding: 4px 8px;
                            background: rgba(0, 120, 212, 0.1);
                            color: #0078D4;
                            border: none;
                            border-radius: 2px;
                            cursor: pointer;
                            font-size: 11px;
                        ">Protect</button>
                    ` : ''}
                    <button onclick="createRuleForPort(${port.port}, '${port.protocol}')" style="
                        padding: 4px 8px;
                        background: rgba(16, 124, 16, 0.1);
                        color: #107C10;
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
                    '<span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; background: rgba(16, 124, 16, 0.1); color: #107C10;">User</span>'
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
                <span style="font-size: 11px; color: var(--text-secondary);">${formatTimeAgo(new Date(s.created_at))}</span>
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
        case 'high': return '#D13438';
        case 'medium': return '#FFB900';
        case 'low': return '#107C10';
        default: return 'var(--border)';
    }
}

function getPriorityStyle(priority) {
    switch (priority) {
        case 'high': return 'background: rgba(209, 52, 56, 0.1); color: #D13438;';
        case 'medium': return 'background: rgba(255, 185, 0, 0.1); color: #CC9400;';
        case 'low': return 'background: rgba(16, 124, 16, 0.1); color: #107C10;';
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
    document.getElementById('ruleTable').value = 'filter';
    document.getElementById('ruleChain').value = 'INPUT';
    document.getElementById('ruleTarget').value = 'ACCEPT';
    document.getElementById('ruleProtocol').value = 'all';
    document.getElementById('ruleSource').value = '';
    document.getElementById('ruleDestination').value = '';
    document.getElementById('ruleDport').value = '';
    document.getElementById('ruleInInterface').value = '';
    document.getElementById('rulePosition').value = '';
    document.getElementById('ruleComment').value = '';
}

function showMessage(elementId, message, type) {
    const el = document.getElementById(elementId);
    el.style.display = 'block';
    el.textContent = message;
    el.style.background = type === 'error' ? 'rgba(209, 52, 56, 0.1)' : 'rgba(16, 124, 16, 0.1)';
    el.style.color = type === 'error' ? '#D13438' : '#107C10';

    setTimeout(() => {
        el.style.display = 'none';
    }, 5000);
}

function formatTimeAgo(date) {
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
}

function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    return date.toLocaleString();
}

function showNotification(message, type) {
    // Use existing notification system if available
    if (typeof window.showToast === 'function') {
        window.showToast(message, type);
    } else {
        alert(message);
    }
}

function updateCacheIndicator(endpoint, fromCache) {
    const indicator = document.querySelector(`[data-cache-endpoint="${endpoint}"]`);
    if (indicator) {
        // Remove all state classes
        indicator.classList.remove('loading', 'cached', 'fresh', 'error', 'stale');

        // Add the appropriate class
        if (fromCache) {
            indicator.classList.add('cached');
        } else {
            indicator.classList.add('fresh');
        }

        const text = indicator.querySelector('.cache-indicator-text');
        if (text) {
            text.textContent = fromCache ? 'Cached' : 'Fresh';
        }

        // Stop spinning the refresh button
        const refreshBtn = indicator.querySelector('.cache-refresh-btn');
        if (refreshBtn) {
            refreshBtn.classList.remove('spinning');
            refreshBtn.disabled = false;
        }
    }

    // Also update via CacheManager if available
    if (typeof CacheManager !== 'undefined' && CacheManager.updateStatus) {
        CacheManager.updateStatus(endpoint, fromCache);
    }
}

// Initialize when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFirewallPage);
} else {
    initFirewallPage();
}
