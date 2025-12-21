/**
 * SSH Guardian v3.0 - Simulation Target Management
 * Agent simulation setup, enabling/disabling, API key management
 * Extracted from simulation.js for better maintainability
 */

/**
 * Format timestamp using TimeSettings or browser fallback
 */
function formatSimTargetTime(timestamp) {
    if (!timestamp) return 'Never tested';
    if (window.TimeSettings?.isLoaded()) {
        return 'Last tested: ' + window.TimeSettings.formatFull(timestamp);
    }
    // Fallback - parse server timezone then display in browser TZ
    let ts = String(timestamp).replace(' ', 'T');
    if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
    return 'Last tested: ' + new Date(ts).toLocaleString();
}

// ========================
// TARGET SERVER MANAGEMENT
// ========================

let targetManagementModal = null;

// Open Target Management Modal - Shows all agents with simulation status
function showAddTargetModal() {
    // Remove existing modal if any
    if (targetManagementModal) {
        targetManagementModal.remove();
    }

    targetManagementModal = document.createElement('div');
    targetManagementModal.id = 'target-management-modal';
    targetManagementModal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000;';

    targetManagementModal.innerHTML = `
        <div style="background: var(--surface); border-radius: 8px; max-width: 700px; width: 95%; max-height: 85vh; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.15); display: flex; flex-direction: column;">
            <!-- Header -->
            <div style="padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: var(--surface);">
                <div>
                    <h3 style="margin: 0 0 4px 0; font-size: 16px; font-weight: 600; color: var(--text-primary);">
                        Simulation Targets
                    </h3>
                    <p style="margin: 0; font-size: 12px; color: var(--text-secondary);">Enable simulation on registered agents</p>
                </div>
                <button onclick="closeTargetModal()" style="background: none; border: none; font-size: 20px; cursor: pointer; color: var(--text-secondary); padding: 4px; line-height: 1;">×</button>
            </div>

            <!-- Content Area -->
            <div id="target-modal-content" style="flex: 1; overflow-y: auto; padding: 16px; background: var(--surface);">
                <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
                    <div class="scenario-spinner" style="margin: 0 auto 12px;"></div>
                    <div style="font-size: 13px;">Loading agents...</div>
                </div>
            </div>
        </div>
    `;

    // Close on backdrop click
    targetManagementModal.addEventListener('click', (e) => {
        if (e.target === targetManagementModal) {
            closeTargetModal();
        }
    });

    document.body.appendChild(targetManagementModal);
    loadAgentsForSimulation();
}

function closeTargetModal() {
    if (targetManagementModal) {
        targetManagementModal.remove();
        targetManagementModal = null;
    }
    loadScenarioTargets(); // Refresh dropdown
}

// Load agents with their simulation status
async function loadAgentsForSimulation() {
    const container = document.getElementById('target-modal-content');

    try {
        const response = await fetch('/api/live-sim/targets/from-agents', { credentials: 'same-origin' });
        const data = await response.json();

        if (!data.success) {
            container.innerHTML = `<div style="text-align: center; padding: 40px; color: ${TC.danger}; font-size: 13px;">Error: ${data.error}</div>`;
            return;
        }

        if (data.agents.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 48px 20px;">
                    <div style="font-size: 48px; margin-bottom: 12px; opacity: 0.6;">📡</div>
                    <h4 style="margin: 0 0 6px 0; font-size: 15px; font-weight: 600; color: var(--text-primary);">No Agents Registered</h4>
                    <p style="margin: 0; font-size: 12px; color: var(--text-secondary);">Register an SSH Guardian agent first to enable simulation targets.</p>
                </div>
            `;
            return;
        }

        const enabledCount = data.agents.filter(a => a.sim_enabled).length;

        container.innerHTML = `
            <div style="margin-bottom: 12px; font-size: 12px; color: var(--text-hint);">
                ${enabledCount} of ${data.agents.length} agent(s) enabled for simulation
            </div>
            <div id="agents-list-container">
                ${data.agents.map(a => renderAgentCard(a)).join('')}
            </div>
        `;
    } catch (error) {
        container.innerHTML = `<div style="text-align: center; padding: 40px; color: ${TC.danger}; font-size: 13px;">Failed to load agents: ${error.message}</div>`;
    }
}

// Render a single agent card with simulation status
function renderAgentCard(agent) {
    const name = agent.display_name || agent.hostname;
    const statusColor = agent.agent_status === 'online' ? TC.success : agent.agent_status === 'offline' ? TC.danger : 'var(--text-hint)';
    const statusIcon = agent.agent_status === 'online' ? '●' : '○';
    const isLocal = agent.is_local;

    // Simulation status
    const simEnabled = agent.sim_enabled;
    const simStatusColor = agent.test_status === 'success' ? TC.success : agent.test_status === 'failed' ? TC.danger : 'var(--text-hint)';
    const simStatusText = agent.test_status === 'success' ? 'Ready' : agent.test_status === 'failed' ? 'Failed' : 'Not Tested';

    // Local badge
    const localBadge = isLocal ? `<span style="padding: 2px 6px; border-radius: 2px; font-size: 10px; font-weight: 600; background: ${TC.primaryBg}; color: ${TC.primary};">LOCAL</span>` : '';

    if (simEnabled) {
        // For local targets, show simplified info (no port/key needed)
        const connectionInfo = isLocal
            ? `<span style="color: var(--text-secondary);">Direct write to auth.log</span>`
            : `${escapeHtml(agent.ip_address_primary || 'N/A')}:${agent.sim_port || 5001}`;

        // For local targets, hide Config and Key buttons
        const buttons = isLocal
            ? `
                <button onclick="testAgentSimulation(${agent.agent_id})" title="Test Write Access" style="padding: 6px 10px; background: var(--surface); border: 1px solid var(--border); border-radius: 2px; cursor: pointer; font-size: 12px; color: var(--text-primary);">
                    Test
                </button>
                <button onclick="disableAgentSimulation(${agent.agent_id}, '${escapeHtml(name)}')" title="Disable Simulation" style="padding: 6px 10px; background: var(--surface); border: 1px solid ${TC.danger}; border-radius: 2px; cursor: pointer; font-size: 12px; color: ${TC.danger};">
                    Disable
                </button>
            `
            : `
                <button onclick="testAgentSimulation(${agent.agent_id})" title="Test Connection" style="padding: 6px 10px; background: var(--surface); border: 1px solid var(--border); border-radius: 2px; cursor: pointer; font-size: 12px; color: var(--text-primary);">
                    Test
                </button>
                <button onclick="showAgentSimConfig(${agent.agent_id}, '${escapeHtml(name)}', ${agent.sim_port || 5001})" title="Configure" style="padding: 6px 10px; background: var(--surface); border: 1px solid var(--border); border-radius: 2px; cursor: pointer; font-size: 12px; color: var(--text-primary);">
                    Config
                </button>
                <button onclick="showAgentApiKey(${agent.agent_id}, '${escapeHtml(name)}', '${agent.api_key}')" title="View API Key" style="padding: 6px 10px; background: var(--surface); border: 1px solid var(--border); border-radius: 2px; cursor: pointer; font-size: 12px; color: var(--text-primary);">
                    Key
                </button>
                <button onclick="disableAgentSimulation(${agent.agent_id}, '${escapeHtml(name)}')" title="Disable Simulation" style="padding: 6px 10px; background: var(--surface); border: 1px solid ${TC.danger}; border-radius: 2px; cursor: pointer; font-size: 12px; color: ${TC.danger};">
                    Disable
                </button>
            `;

        return `
            <div class="agent-card" style="padding: 14px 16px; background: var(--background); border-radius: 4px; border: 1px solid var(--border); margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 12px;">
                    <div style="flex: 1; min-width: 0;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap;">
                            <span style="color: ${statusColor}; font-size: 10px;">${statusIcon}</span>
                            <span style="font-weight: 600; font-size: 14px; color: var(--text-primary);">${escapeHtml(name)}</span>
                            ${localBadge}
                            <span style="padding: 2px 6px; border-radius: 2px; font-size: 10px; font-weight: 600; background: ${TC.successBg}; color: ${TC.success};">
                                SIM ENABLED
                            </span>
                            <span style="padding: 2px 6px; border-radius: 2px; font-size: 10px; font-weight: 500; background: ${simStatusColor}15; color: ${simStatusColor};">
                                ${simStatusText}
                            </span>
                        </div>
                        <div style="font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; color: var(--azure-blue); margin-bottom: 4px;">
                            ${connectionInfo}
                        </div>
                        <div style="font-size: 11px; color: var(--text-hint);">
                            ${formatSimTargetTime(agent.last_tested_at)}
                        </div>
                    </div>
                    <div style="display: flex; gap: 4px; flex-shrink: 0;">
                        ${buttons}
                    </div>
                </div>
            </div>
        `;
    } else {
        return `
            <div class="agent-card" style="padding: 14px 16px; background: var(--background); border-radius: 4px; border: 1px solid var(--border); margin-bottom: 8px; opacity: 0.8;">
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px;">
                    <div style="flex: 1; min-width: 0;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px; flex-wrap: wrap;">
                            <span style="color: ${statusColor}; font-size: 10px;">${statusIcon}</span>
                            <span style="font-weight: 600; font-size: 14px; color: var(--text-primary);">${escapeHtml(name)}</span>
                            ${localBadge}
                            <span style="padding: 2px 6px; border-radius: 2px; font-size: 10px; font-weight: 500; background: var(--background); color: var(--text-hint); border: 1px solid var(--border);">
                                Not Configured
                            </span>
                        </div>
                        <div style="font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; color: var(--text-secondary);">
                            ${isLocal ? 'Local machine (direct write)' : escapeHtml(agent.ip_address_primary || 'No IP')}
                        </div>
                    </div>
                    <button onclick="enableAgentSimulation(${agent.agent_id}, '${escapeHtml(name)}', '${escapeHtml(agent.ip_address_primary || '')}', ${isLocal})" style="padding: 8px 14px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 12px;">
                        Enable Simulation
                    </button>
                </div>
            </div>
        `;
    }
}

// Enable simulation for an agent
async function enableAgentSimulation(agentId, name, ip, isLocal = false) {
    if (isLocal) {
        // LOCAL AGENT: No port/API key needed, just confirm
        const dialog = document.createElement('div');
        dialog.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1001;';

        dialog.innerHTML = `
            <div style="background: var(--surface); border-radius: 4px; padding: 20px; max-width: 400px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
                <h3 style="margin: 0 0 4px 0; font-size: 15px; font-weight: 600; color: var(--text-primary);">Enable Local Simulation</h3>
                <p style="margin: 0 0 16px 0; font-size: 12px; color: var(--text-secondary);">${escapeHtml(name)}</p>

                <div style="padding: 12px; background: ${TC.primaryBg}; border: 1px solid ${TC.primary}; border-radius: 4px; margin-bottom: 16px;">
                    <div style="font-weight: 600; font-size: 13px; color: ${TC.primary}; margin-bottom: 4px;">Local Agent Detected</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">
                        This agent is on the same machine as the dashboard. Simulation will write directly to <code>/var/log/auth.log</code> without needing a separate receiver or API key.
                    </div>
                </div>

                <div id="enable-sim-error" style="display: none; padding: 10px 12px; background: ${TC.dangerBg}; border: 1px solid ${TC.danger}; border-radius: 4px; color: ${TC.danger}; margin-bottom: 14px; font-size: 12px;"></div>

                <div style="display: flex; gap: 10px; justify-content: flex-end;">
                    <button onclick="this.closest('[style*=fixed]').remove()" style="padding: 8px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 13px; color: var(--text-primary);">
                        Cancel
                    </button>
                    <button id="enable-sim-btn" onclick="confirmEnableLocalSimulation(${agentId}, '${escapeHtml(name)}', '${escapeHtml(ip)}', this)" style="padding: 8px 16px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 13px;">
                        Enable Local Simulation
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(dialog);
        return;
    }

    // REMOTE AGENT: Show port configuration dialog
    const dialog = document.createElement('div');
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1001;';

    dialog.innerHTML = `
        <div style="background: var(--surface); border-radius: 4px; padding: 20px; max-width: 400px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
            <h3 style="margin: 0 0 4px 0; font-size: 15px; font-weight: 600; color: var(--text-primary);">Enable Remote Simulation</h3>
            <p style="margin: 0 0 16px 0; font-size: 12px; color: var(--text-secondary);">Configure simulation receiver for "${escapeHtml(name)}"</p>

            <div id="enable-sim-error" style="display: none; padding: 10px 12px; background: ${TC.dangerBg}; border: 1px solid ${TC.danger}; border-radius: 4px; color: ${TC.danger}; margin-bottom: 14px; font-size: 12px;"></div>

            <div style="margin-bottom: 14px;">
                <label style="display: block; margin-bottom: 4px; font-weight: 600; font-size: 12px; color: var(--text-secondary);">IP Address *</label>
                <input id="enable-sim-ip" type="text" value="${escapeHtml(ip)}" placeholder="e.g., 192.168.1.100"
                    style="width: 100%; padding: 9px 12px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; background: var(--surface); color: var(--text-primary); box-sizing: border-box;">
                <div style="font-size: 11px; color: var(--text-hint); margin-top: 4px;">Change if different from agent's registered IP</div>
            </div>

            <div style="margin-bottom: 16px;">
                <label style="display: block; margin-bottom: 4px; font-weight: 600; font-size: 12px; color: var(--text-secondary);">Receiver Port *</label>
                <input id="enable-sim-port" type="number" value="5001" placeholder="5001"
                    style="width: 100%; padding: 9px 12px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; background: var(--surface); color: var(--text-primary); box-sizing: border-box;">
                <div style="font-size: 11px; color: var(--text-hint); margin-top: 4px;">Port where simulation receiver will listen</div>
            </div>

            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button onclick="this.closest('[style*=fixed]').remove()" style="padding: 8px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 13px; color: var(--text-primary);">
                    Cancel
                </button>
                <button id="enable-sim-btn" onclick="confirmEnableSimulation(${agentId}, '${escapeHtml(name)}', this)" style="padding: 8px 16px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 13px;">
                    Enable & Generate Key
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(dialog);
}

// Enable local simulation (no port/API key needed)
async function confirmEnableLocalSimulation(agentId, name, ip, btn) {
    btn.disabled = true;
    btn.textContent = 'Enabling...';
    const errorEl = document.getElementById('enable-sim-error');

    try {
        const response = await fetch(`/api/live-sim/targets/enable-agent/${agentId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ ip_address: ip, port: 0 })  // port 0 indicates local
        });

        const data = await response.json();

        if (data.success) {
            btn.closest('[style*=fixed]').remove();
            showToast(`Local simulation enabled for ${name}`, 'success');
            loadAgentsForSimulation();
        } else {
            errorEl.textContent = data.error || 'Failed to enable simulation';
            errorEl.style.display = 'block';
            btn.disabled = false;
            btn.textContent = 'Enable Local Simulation';
        }
    } catch (error) {
        errorEl.textContent = 'Network error';
        errorEl.style.display = 'block';
        btn.disabled = false;
        btn.textContent = 'Enable Local Simulation';
    }
}

async function confirmEnableSimulation(agentId, name, btn) {
    const ip = document.getElementById('enable-sim-ip').value.trim();
    const port = parseInt(document.getElementById('enable-sim-port').value) || 5001;
    const errorEl = document.getElementById('enable-sim-error');

    // Validate IP
    if (!ip) {
        errorEl.textContent = 'IP address is required';
        errorEl.style.display = 'block';
        return;
    }

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
        errorEl.textContent = 'Invalid IP address format';
        errorEl.style.display = 'block';
        return;
    }

    if (port < 1 || port > 65535) {
        errorEl.textContent = 'Port must be between 1 and 65535';
        errorEl.style.display = 'block';
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Enabling...';
    errorEl.style.display = 'none';

    try {
        const response = await fetch(`/api/live-sim/targets/enable-agent/${agentId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ ip_address: ip, port: port })
        });

        const data = await response.json();

        if (data.success) {
            // Close enable dialog
            btn.closest('[style*=fixed]').remove();
            // Show API key dialog
            showNewApiKeyDialog(name, data.api_key, data.ip_address, data.port);
            // Refresh agent list
            loadAgentsForSimulation();
        } else {
            errorEl.textContent = data.error;
            errorEl.style.display = 'block';
        }
    } catch (error) {
        errorEl.textContent = 'Failed to enable simulation: ' + error.message;
        errorEl.style.display = 'block';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Enable & Generate Key';
    }
}

// Disable simulation for an agent
async function disableAgentSimulation(agentId, name) {
    if (!confirm(`Disable simulation for "${name}"?\n\nThis will remove the simulation target and invalidate the API key.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/live-sim/targets/disable-agent/${agentId}`, {
            method: 'POST',
            credentials: 'same-origin'
        });

        const data = await response.json();

        if (data.success) {
            showToast('Simulation disabled', 'success');
            loadAgentsForSimulation();
        } else {
            showToast(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast('Failed to disable simulation', 'error');
    }
}

// Test agent simulation connection (tests both health AND API key)
async function testAgentSimulation(agentId) {
    showToast('Testing connection and API key...', 'info');

    try {
        // Use the dedicated test-agent endpoint
        const response = await fetch(`/api/live-sim/targets/test-agent/${agentId}`, {
            method: 'POST',
            credentials: 'same-origin'
        });
        const data = await response.json();

        if (data.success) {
            showToast(`${data.target_name}: Connection and API key verified!`, 'success');
        } else {
            // Show detailed error message
            let errorMsg = data.message || 'Unknown error';
            if (data.api_key_valid === false && data.health_data) {
                // Server is reachable but API key is wrong
                errorMsg = `API key mismatch: ${errorMsg}`;
            }
            showToast(`Test failed: ${errorMsg}`, 'error');
        }

        loadAgentsForSimulation(); // Refresh to show updated status
    } catch (error) {
        showToast('Failed to test connection', 'error');
    }
}

// Show agent simulation configuration
function showAgentSimConfig(agentId, name, currentPort) {
    const dialog = document.createElement('div');
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1001;';

    dialog.innerHTML = `
        <div style="background: var(--surface); border-radius: 4px; padding: 20px; max-width: 400px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
            <h3 style="margin: 0 0 4px 0; font-size: 15px; font-weight: 600; color: var(--text-primary);">Configure Simulation</h3>
            <p style="margin: 0 0 16px 0; font-size: 12px; color: var(--text-secondary);">${escapeHtml(name)}</p>

            <div id="config-sim-error" style="display: none; padding: 10px 12px; background: ${TC.dangerBg}; border: 1px solid ${TC.danger}; border-radius: 4px; color: ${TC.danger}; margin-bottom: 14px; font-size: 12px;"></div>

            <div style="margin-bottom: 16px;">
                <label style="display: block; margin-bottom: 4px; font-weight: 600; font-size: 12px; color: var(--text-secondary);">Receiver Port</label>
                <input id="config-sim-port" type="number" value="${currentPort}" placeholder="5001"
                    style="width: 100%; padding: 9px 12px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; background: var(--surface); color: var(--text-primary); box-sizing: border-box;">
            </div>

            <div style="display: flex; gap: 10px; justify-content: flex-end;">
                <button onclick="this.closest('[style*=fixed]').remove()" style="padding: 8px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 13px; color: var(--text-primary);">
                    Cancel
                </button>
                <button id="config-sim-btn" onclick="saveAgentSimConfig(${agentId}, this)" style="padding: 8px 16px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 13px;">
                    Save
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(dialog);
}

async function saveAgentSimConfig(agentId, btn) {
    const port = parseInt(document.getElementById('config-sim-port').value) || 5001;
    const errorEl = document.getElementById('config-sim-error');

    if (port < 1 || port > 65535) {
        errorEl.textContent = 'Port must be between 1 and 65535';
        errorEl.style.display = 'block';
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Saving...';
    errorEl.style.display = 'none';

    try {
        const response = await fetch(`/api/live-sim/targets/update-agent/${agentId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ port })
        });

        const data = await response.json();

        if (data.success) {
            btn.closest('[style*=fixed]').remove();
            showToast('Configuration saved', 'success');
            loadAgentsForSimulation();
        } else {
            errorEl.textContent = data.error;
            errorEl.style.display = 'block';
        }
    } catch (error) {
        errorEl.textContent = 'Failed to save: ' + error.message;
        errorEl.style.display = 'block';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Save';
    }
}

// Show API key for agent
function showAgentApiKey(agentId, name, apiKey) {
    const dialog = document.createElement('div');
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1001;';

    dialog.innerHTML = `
        <div style="background: var(--surface); border-radius: 4px; padding: 20px; max-width: 480px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                <h3 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">API Key - ${escapeHtml(name)}</h3>
                <button onclick="this.closest('[style*=fixed]').remove()" style="background: none; border: none; font-size: 18px; cursor: pointer; color: var(--text-secondary); padding: 0;">×</button>
            </div>

            <div style="background: var(--background); border-radius: 4px; padding: 12px; margin-bottom: 12px;">
                <div style="display: flex; gap: 6px;">
                    <input type="text" value="${apiKey}" readonly
                        style="flex: 1; padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; background: var(--surface); color: var(--text-primary);">
                    <button onclick="copyApiKeyFromInput(this)" style="padding: 8px 12px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 12px;">
                        Copy
                    </button>
                </div>
            </div>

            <div style="display: flex; gap: 8px;">
                <button onclick="this.closest('[style*=fixed]').remove()" style="flex: 1; padding: 8px; background: var(--surface); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 12px; color: var(--text-primary);">
                    Close
                </button>
                <button onclick="regenerateAgentApiKey(${agentId}, '${escapeHtml(name)}', this)" style="flex: 1; padding: 8px; background: ${TC.warningBg}; border: 1px solid ${TC.warning}; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 12px; color: ${TC.warning};">
                    Regenerate Key
                </button>
            </div>
        </div>
    `;

    document.body.appendChild(dialog);
}

// Regenerate API key for agent
async function regenerateAgentApiKey(agentId, name, btn) {
    if (!confirm(`Regenerate API key for "${name}"?\n\nThe old key will stop working immediately.`)) {
        return;
    }

    btn.disabled = true;
    btn.textContent = 'Regenerating...';

    try {
        const response = await fetch(`/api/live-sim/targets/regenerate-key-agent/${agentId}`, {
            method: 'POST',
            credentials: 'same-origin'
        });
        const data = await response.json();

        if (data.success) {
            btn.closest('[style*=fixed]').remove();
            showNewApiKeyDialog(name + ' (regenerated)', data.api_key);
            loadAgentsForSimulation();
        } else {
            showToast(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showToast('Failed to regenerate key', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Regenerate Key';
    }
}

// Show API key dialog for new target (with optional connection info)
function showNewApiKeyDialog(name, apiKey, ip = null, port = null) {
    const dialog = document.createElement('div');
    dialog.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1001;';

    const connectionInfo = ip ? `
        <div style="background: var(--background); border-radius: 4px; padding: 10px 12px; margin-bottom: 12px; font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; color: var(--azure-blue);">
            ${escapeHtml(ip)}:${port || 5001}
        </div>
    ` : '';

    dialog.innerHTML = `
        <div style="background: var(--surface); border-radius: 4px; padding: 20px; max-width: 480px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.15);">
            <div style="text-align: center; margin-bottom: 16px;">
                <div style="font-size: 36px; margin-bottom: 8px;">🔑</div>
                <h3 style="margin: 0 0 4px 0; font-size: 15px; font-weight: 600; color: ${TC.success};">Simulation Enabled!</h3>
                <p style="margin: 0; font-size: 12px; color: var(--text-secondary);">"${escapeHtml(name)}" is ready for simulation.</p>
            </div>

            ${connectionInfo}

            <div style="background: var(--background); border-radius: 4px; padding: 12px; margin-bottom: 12px;">
                <label style="display: block; margin-bottom: 6px; font-weight: 600; font-size: 11px; color: var(--text-hint);">API KEY (save this securely)</label>
                <div style="display: flex; gap: 6px;">
                    <input id="new-api-key-input" type="text" value="${apiKey}" readonly
                        style="flex: 1; padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; font-family: 'Consolas', 'Monaco', monospace; font-size: 12px; background: var(--surface); color: var(--text-primary);">
                    <button onclick="copyApiKeyFromInput(this)" style="padding: 8px 12px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 12px;">
                        Copy
                    </button>
                </div>
            </div>

            <div style="background: ${TC.warningBg}; border: 1px solid ${TC.warning}; border-radius: 4px; padding: 10px; margin-bottom: 16px;">
                <div style="font-weight: 600; font-size: 12px; color: ${TC.warning}; margin-bottom: 2px;">Important</div>
                <div style="font-size: 11px; color: var(--text-primary);">
                    Save this API key securely. Use it when installing the simulation receiver on the target server.
                </div>
            </div>

            <button onclick="this.closest('[style*=fixed]').remove(); showToast('Simulation enabled', 'success');" style="width: 100%; padding: 10px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: 13px;">
                Got it, I've saved the key
            </button>
        </div>
    `;

    document.body.appendChild(dialog);
}

// Copy API key to clipboard
function copyApiKey(apiKey) {
    // Handle both direct calls and event-based calls
    const textToCopy = apiKey || '';

    if (!textToCopy) {
        showToast('No API key to copy', 'error');
        return;
    }

    // Try modern clipboard API first
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textToCopy).then(() => {
            showToast('API key copied to clipboard', 'success');
        }).catch((err) => {
            console.error('Clipboard API failed:', err);
            fallbackCopy(textToCopy);
        });
    } else {
        fallbackCopy(textToCopy);
    }
}

// Fallback copy method for older browsers or when clipboard API fails
function fallbackCopy(text) {
    try {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.left = '-9999px';
        textarea.style.top = '0';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();

        const successful = document.execCommand('copy');
        document.body.removeChild(textarea);

        if (successful) {
            showToast('API key copied to clipboard', 'success');
        } else {
            showToast('Failed to copy - please copy manually', 'error');
        }
    } catch (err) {
        console.error('Fallback copy failed:', err);
        showToast('Failed to copy - please copy manually', 'error');
    }
}

// Copy from input field next to button
function copyApiKeyFromInput(btn) {
    const input = btn.parentElement.querySelector('input');
    if (input && input.value) {
        copyApiKey(input.value);
    }
}

// Note: escapeHtml is provided by firewall_utils.js (window.escapeHtml)

// Make functions globally available
window.showAddTargetModal = showAddTargetModal;
window.closeTargetModal = closeTargetModal;
window.loadAgentsForSimulation = loadAgentsForSimulation;
window.renderAgentCard = renderAgentCard;
window.enableAgentSimulation = enableAgentSimulation;
window.confirmEnableLocalSimulation = confirmEnableLocalSimulation;
window.confirmEnableSimulation = confirmEnableSimulation;
window.disableAgentSimulation = disableAgentSimulation;
window.testAgentSimulation = testAgentSimulation;
window.showAgentSimConfig = showAgentSimConfig;
window.saveAgentSimConfig = saveAgentSimConfig;
window.showAgentApiKey = showAgentApiKey;
window.regenerateAgentApiKey = regenerateAgentApiKey;
window.showNewApiKeyDialog = showNewApiKeyDialog;
window.copyApiKey = copyApiKey;
window.copyApiKeyFromInput = copyApiKeyFromInput;
