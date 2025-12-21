/**
 * SSH Guardian v3.0 - Firewall Management Page Module
 * Handles iptables rule viewing and management
 */

// Variables currentAgentId, currentAgentIp, isLocalhostAgent are defined in firewall_simple.js
// which loads before this file. We only need firewallData locally.
let firewallData = null;

// ============================================================================
// INITIALIZATION (for iptables extended page - prefixed to avoid conflicts)
// ============================================================================

function initIptablesPage() {
    // Load agents for selector
    iptablesLoadAgents();

    // Setup event listeners
    setupIptablesEventListeners();
}

function setupIptablesEventListeners() {
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
                isLocalhostAgent = iptablesIsLocalhost(currentAgentIp);
                iptablesLoadData(agentId);
            } else {
                currentAgentId = null;
                currentAgentIp = null;
                isLocalhostAgent = false;
                iptablesShowNoAgentSelected();
            }
        });
    }

    // Tab navigation for extended firewall page (.fw-tab-btn elements)
    document.querySelectorAll('.fw-tab-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            switchFirewallExtendedTab(this.dataset.tab);
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
            const form = document.getElementById('addRuleForm');
            if (form) form.style.display = 'block';
        });
    }

    const cancelAddRuleBtn = document.getElementById('cancelAddRule');
    if (cancelAddRuleBtn) {
        cancelAddRuleBtn.addEventListener('click', () => {
            const form = document.getElementById('addRuleForm');
            if (form) form.style.display = 'none';
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
            const modal = document.getElementById('templatesModal');
            if (modal) modal.style.display = 'none';
        });
    }

    // Port Forward Form
    const showPFBtn = document.getElementById('showAddPortForward');
    if (showPFBtn) {
        showPFBtn.addEventListener('click', () => {
            const form = document.getElementById('addPortForwardForm');
            if (form) form.style.display = 'block';
        });
    }

    const cancelPFBtn = document.getElementById('cancelPortForward');
    if (cancelPFBtn) {
        cancelPFBtn.addEventListener('click', () => {
            const form = document.getElementById('addPortForwardForm');
            if (form) form.style.display = 'none';
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

async function iptablesLoadAgents() {
    try {
        const response = await fetch('/api/agents/list');
        const data = await response.json();

        if (data.success && data.agents) {
            const selector = document.getElementById('firewallAgentSelector');
            if (!selector) return; // Element doesn't exist in this page
            selector.innerHTML = '<option value="">-- Select an agent --</option>';

            data.agents.forEach(agent => {
                const option = document.createElement('option');
                option.value = agent.id;
                option.dataset.ip = agent.ip_address_primary || '';
                const ipDisplay = agent.ip_address_primary || agent.agent_id;
                const isLocal = iptablesIsLocalhost(agent.ip_address_primary);
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

// Helper function to check if IP is localhost (prefixed to avoid conflicts)
function iptablesIsLocalhost(ip) {
    if (!ip) return false;
    return ip === '127.0.0.1' || ip === 'localhost' || ip === '::1';
}

async function iptablesLoadData(agentId) {
    console.log('[Iptables] Loading data for agent:', agentId);
    iptablesShowFirewallContent();
    iptablesShowLoadingStates();

    try {
        const response = await fetch(`/api/agents/${agentId}/firewall`);
        console.log('[Firewall] Response status:', response.status);
        const data = await response.json();
        console.log('[Firewall] Data received:', data.success, 'has_data:', data.has_data, 'rules_flat:', data.rules_flat?.length);

        if (data.success) {
            firewallData = data;

            if (data.has_data) {
                console.log('[Firewall] Rendering data...');
                iptablesUpdateFirewallStats(data.state);
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
                iptablesShowNoFirewallData();
            }
        } else {
            console.log('[Firewall] Error:', data.error);
            iptablesShowFirewallError(data.error);
        }
    } catch (error) {
        console.error('[Firewall] Error loading firewall data:', error);
        iptablesShowFirewallError(error.message);

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

async function iptablesLoadPage() {
    // Ensure TimeSettings is loaded for proper date/time formatting
    if (window.TimeSettings && !window.TimeSettings.isLoaded()) {
        await window.TimeSettings.load();
    }

    if (currentAgentId) {
        iptablesLoadData(currentAgentId);
    }
}

// ============================================================================
// UI UPDATES (for iptables extended page - prefixed to avoid conflicts with firewall_simple.js)
// ============================================================================

function iptablesShowNoAgentSelected() {
    const noAgent = document.getElementById('firewallNoAgent');
    const content = document.getElementById('firewallContent');
    if (noAgent) noAgent.style.display = 'block';
    if (content) content.style.display = 'none';
}

function iptablesShowFirewallContent() {
    const noAgent = document.getElementById('firewallNoAgent');
    const content = document.getElementById('firewallContent');
    if (noAgent) noAgent.style.display = 'none';
    if (content) content.style.display = 'block';
}

function iptablesShowLoadingStates() {
    // These elements are for the iptables extended page
    const rulesLoading = document.getElementById('rulesLoading');
    const rulesTableContainer = document.getElementById('rulesTableContainer');
    const portForwardsLoading = document.getElementById('portForwardsLoading');
    const portForwardsTableContainer = document.getElementById('portForwardsTableContainer');
    const interfacesLoading = document.getElementById('interfacesLoading');
    const interfacesContainer = document.getElementById('interfacesContainer');
    const commandsLoading = document.getElementById('commandsLoading');
    const commandsTableContainer = document.getElementById('commandsTableContainer');

    if (rulesLoading) rulesLoading.style.display = 'block';
    if (rulesTableContainer) rulesTableContainer.style.display = 'none';
    if (portForwardsLoading) portForwardsLoading.style.display = 'block';
    if (portForwardsTableContainer) portForwardsTableContainer.style.display = 'none';
    if (interfacesLoading) interfacesLoading.style.display = 'block';
    if (interfacesContainer) interfacesContainer.style.display = 'none';
    if (commandsLoading) commandsLoading.style.display = 'block';
    if (commandsTableContainer) commandsTableContainer.style.display = 'none';

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

function iptablesShowNoFirewallData() {
    const rulesLoading = document.getElementById('rulesLoading');
    if (rulesLoading) {
        rulesLoading.innerHTML = `
            <div style="font-size: 32px; margin-bottom: 12px;">📋</div>
            <p>No firewall data available for this agent.</p>
            <p style="font-size: 12px; margin-top: 8px;">The agent may not have sent firewall data yet, or firewall collection may be disabled.</p>
        `;
    }
}

function iptablesShowFirewallError(error) {
    const rulesError = document.getElementById('rulesError');
    const rulesLoading = document.getElementById('rulesLoading');
    if (rulesError) {
        rulesError.style.display = 'block';
        rulesError.textContent = `Error: ${error}`;
    }
    if (rulesLoading) rulesLoading.style.display = 'none';
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

function iptablesUpdateFirewallStats(state) {
    const status = state.status || {};

    const statStatus = document.getElementById('stat-fw-status');
    const statRules = document.getElementById('stat-fw-rules');
    const statForwards = document.getElementById('stat-fw-forwards');
    const statSync = document.getElementById('stat-fw-sync');

    if (statStatus) {
        statStatus.textContent = status.iptables_active ? 'Active' : 'Inactive';
        statStatus.style.color = status.iptables_active ? TC.successDark : TC.danger;
    }

    if (statRules) {
        statRules.textContent = state.rules_count || status.total_rules || 0;
    }

    if (statForwards) {
        statForwards.textContent = state.port_forwards_count || status.port_forwards_count || 0;
    }

    if (statSync) {
        if (state.last_sync) {
            const lastSync = new Date(state.last_sync);
            statSync.textContent = formatTimeAgo(lastSync);
        } else {
            statSync.textContent = 'Never';
        }
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
            return `background: ${TC.successBg}; color: ${TC.successDark};`;
        case 'DROP':
            return `background: ${TC.dangerBg}; color: ${TC.danger};`;
        case 'REJECT':
            return `background: ${TC.warningBg}; color: ${TC.warningDark};`;
        default:
            return 'background: var(--surface); color: var(--text-secondary);';
    }
}

// Note: switchFirewallTab is defined in firewall_inline.js for firewall_simple.html
// This function is for the extended iptables firewall page (different DOM structure)
function switchFirewallExtendedTab(tabName) {
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
    const tabContent = document.getElementById(`fw-tab-${tabName}`);
    if (tabContent) tabContent.style.display = 'block';

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
                                    background: ${TC.dangerBg};
                                    color: ${TC.danger};
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
            return `background: ${TC.successBg}; color: ${TC.successDark};`;
        case 'DROP':
            return `background: ${TC.dangerBg}; color: ${TC.danger};`;
        case 'REJECT':
            return `background: ${TC.warningBg}; color: ${TC.warningDark};`;
        case 'LOG':
            return `background: ${TC.primaryBg}; color: ${TC.primary};`;
        case 'DNAT':
        case 'SNAT':
        case 'MASQUERADE':
            return `background: ${TC.purpleBg}; color: ${TC.purple};`;
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
    const loading = document.getElementById('portForwardsLoading');
    const noData = document.getElementById('noPortForwards');
    const container = document.getElementById('portForwardsTableContainer');
    const tbody = document.getElementById('portForwardsTableBody');

    // Elements may not exist in firewall_simple.html template
    if (!loading && !container) return;

    if (loading) loading.style.display = 'none';

    if (!portForwards || portForwards.length === 0) {
        if (noData) noData.style.display = 'block';
        if (container) container.style.display = 'none';
        return;
    }

    if (container) container.style.display = 'block';
    if (noData) noData.style.display = 'none';
    if (!tbody) return;
    tbody.innerHTML = portForwards.map(pf => `
        <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 10px 12px; font-weight: 500;">${pf.external_port}</td>
            <td style="padding: 10px 12px; font-family: monospace;">${pf.internal_ip}</td>
            <td style="padding: 10px 12px;">${pf.internal_port}</td>
            <td style="padding: 10px 12px; text-transform: uppercase;">${pf.protocol}</td>
            <td style="padding: 10px 12px;">${pf.interface || '-'}</td>
            <td style="padding: 10px 12px;">
                <span style="padding: 2px 8px; border-radius: 2px; font-size: 12px; ${pf.is_enabled ? `background: ${TC.successBg}; color: ${TC.successDark};` : 'background: var(--surface); color: var(--text-secondary);'}">
                    ${pf.is_enabled ? 'Active' : 'Disabled'}
                </span>
            </td>
            <td style="padding: 10px 12px; text-align: center;">
                ${!isLocalhostAgent ? `
                    <button onclick="removePortForward(${pf.external_port}, '${pf.internal_ip}', ${pf.internal_port}, '${pf.protocol}')" style="
                        padding: 4px 8px;
                        background: ${TC.dangerBg};
                        color: ${TC.danger};
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
    const loading = document.getElementById('interfacesLoading');
    const containerWrap = document.getElementById('interfacesContainer');
    const container = document.getElementById('interfacesGrid');

    // Elements may not exist in firewall_simple.html template
    if (!loading && !containerWrap) return;

    if (loading) loading.style.display = 'none';
    if (containerWrap) containerWrap.style.display = 'block';
    if (!container) return;

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
                    <span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; ${iface.state === 'UP' ? `background: ${TC.successBg}; color: ${TC.successDark};` : 'background: var(--surface); color: var(--text-secondary);'}">
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
    const loading = document.getElementById('commandsLoading');
    const noData = document.getElementById('noCommands');
    const container = document.getElementById('commandsTableContainer');
    const tbody = document.getElementById('commandsTableBody');

    // Elements may not exist in firewall_simple.html template
    if (!loading && !container) return;

    if (loading) loading.style.display = 'none';

    if (!commands || commands.length === 0) {
        if (noData) noData.style.display = 'block';
        if (container) container.style.display = 'none';
        return;
    }

    if (container) container.style.display = 'block';
    if (noData) noData.style.display = 'none';
    if (!tbody) return;
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
            return `background: ${TC.successBg}; color: ${TC.successDark};`;
        case 'failed':
            return `background: ${TC.dangerBg}; color: ${TC.danger};`;
        case 'pending':
            return `background: ${TC.warningBg}; color: ${TC.warningDark};`;
        case 'sent':
            return `background: ${TC.primaryBg}; color: ${TC.primary};`;
        default:
            return 'background: var(--surface); color: var(--text-secondary);';
    }
}


// Note: Extended features (listening ports, system users, suggestions, operations, templates) are now in firewall_page_extended.js

// Note: initFirewallPage() is called by dashboard_modular.html when navigating to firewall page
// Auto-init removed to prevent early initialization before all dependencies (firewall_inline.js) are loaded
