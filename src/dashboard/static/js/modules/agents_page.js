/**
 * Agent Management Page Module
 * Handles agent listing, stats, and management actions
 */

// Load agents page data
async function loadAgentsPage() {
    await Promise.all([
        loadAgentStats(),
        loadAgentsList()
    ]);

    // Initialize search after first load
    if (typeof initAgentSearch === 'function') {
        initAgentSearch();
    }
}

// Load agent statistics
async function loadAgentStats() {
    try {
        const response = await fetch('/api/agents/stats');
        const data = await response.json();

        if (data.success) {
            const stats = data.stats;
            document.getElementById('stat-total-agents').textContent = stats.total_agents;
            document.getElementById('stat-online-agents').textContent = stats.online_agents;
            document.getElementById('stat-approved-agents').textContent = stats.approved_agents;
            document.getElementById('stat-total-events').textContent = stats.total_events_from_agents.toLocaleString();
        }
    } catch (error) {
        console.error('Error loading agent stats:', error);
    }
}

// Load agents list
async function loadAgentsList() {
    try {
        const response = await fetch('/api/agents/list');
        const data = await response.json();

        const container = document.getElementById('agents-container');

        if (!data.success) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">⚠️</div>
                    <div class="empty-state-title">Error Loading Agents</div>
                    <div class="empty-state-description">${data.error || 'Unknown error'}</div>
                </div>
            `;
            return;
        }

        if (data.agents.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">🤖</div>
                    <div class="empty-state-title">No Agents Registered</div>
                    <div class="empty-state-description">Deploy agents on remote servers to start collecting SSH logs</div>
                </div>
            `;
            return;
        }

        // Store agents for search/filter functionality
        if (typeof storeAgentsForSearch === 'function') {
            storeAgentsForSearch(data.agents);
        }

        // Render agent cards
        container.innerHTML = data.agents.map(agent => createAgentCard(agent)).join('');

    } catch (error) {
        console.error('Error loading agents:', error);
        document.getElementById('agents-container').innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">❌</div>
                <div class="empty-state-title">Connection Error</div>
                <div class="empty-state-description">Failed to load agents. Please try again.</div>
            </div>
        `;
    }
}

// Create agent card HTML
function createAgentCard(agent) {
    const isOnline = agent.status === 'online' && agent.last_heartbeat;
    const statusClass = isOnline ? 'online' : 'offline';
    const statusText = isOnline ? 'Online' : 'Offline';

    const lastHeartbeat = agent.last_heartbeat
        ? (typeof formatLocalDateTime === 'function' ? formatLocalDateTime(agent.last_heartbeat) : new Date(agent.last_heartbeat).toLocaleString())
        : 'Never';

    return `
        <div class="agent-card">
            <div class="agent-card-header">
                <div class="agent-hostname">${escapeHtml(agent.hostname || agent.agent_id)}</div>
                <div class="agent-status-badge ${statusClass}">${statusText}</div>
            </div>

            <div class="agent-details">
                <div class="agent-detail-row">
                    <span class="agent-detail-label">Agent ID:</span>
                    <span class="agent-detail-value">${escapeHtml(agent.agent_id)}</span>
                </div>
                <div class="agent-detail-row">
                    <span class="agent-detail-label">IP Address:</span>
                    <span class="agent-detail-value">${escapeHtml(agent.ip_address_primary || 'N/A')}</span>
                </div>
                <div class="agent-detail-row">
                    <span class="agent-detail-label">Version:</span>
                    <span class="agent-detail-value">${escapeHtml(agent.version || 'N/A')}</span>
                </div>
                <div class="agent-detail-row">
                    <span class="agent-detail-label">Environment:</span>
                    <span class="agent-detail-value">${escapeHtml(agent.environment || 'N/A')}</span>
                </div>
                <div class="agent-detail-row">
                    <span class="agent-detail-label">Events Sent:</span>
                    <span class="agent-detail-value">${agent.total_events_sent.toLocaleString()}</span>
                </div>
                <div class="agent-detail-row">
                    <span class="agent-detail-label">Last Heartbeat:</span>
                    <span class="agent-detail-value">${lastHeartbeat}</span>
                </div>
                <div class="agent-detail-row">
                    <span class="agent-detail-label">Status:</span>
                    <span class="agent-detail-value">
                        ${agent.is_approved ? '✅ Approved' : '⏳ Pending Approval'}
                        ${agent.is_active ? '' : ' (Inactive)'}
                    </span>
                </div>
            </div>

            <div class="agent-actions">
                ${!agent.is_approved ? `
                    <button class="btn-approve" onclick="approveAgent(${agent.id})">
                        ✓ Approve
                    </button>
                ` : ''}
                ${agent.is_active ? `
                    <button class="btn-deactivate" onclick="deactivateAgent(${agent.id})">
                        ✗ Deactivate
                    </button>
                ` : `
                    <button class="btn-activate" onclick="activateAgent(${agent.id})">
                        ✓ Activate
                    </button>
                `}
                <button class="btn-view-details" onclick="viewAgentDetails(${agent.id})">
                    👁 Details
                </button>
            </div>
        </div>
    `;
}

// Approve agent
async function approveAgent(agentId) {
    if (!confirm('Approve this agent? It will be able to send logs to the server.')) {
        return;
    }

    try {
        const response = await fetch(`/api/agents/${agentId}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            alert('✅ Agent approved successfully');
            loadAgentsPage(); // Reload
        } else {
            alert('❌ Failed to approve agent: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error approving agent:', error);
        alert('❌ Error approving agent. Please try again.');
    }
}

// Activate agent
async function activateAgent(agentId) {
    if (!confirm('Activate this agent? It will be able to resume sending logs.')) {
        return;
    }

    try {
        const response = await fetch(`/api/agents/${agentId}/activate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            alert('✅ Agent activated successfully');
            loadAgentsPage(); // Reload
        } else {
            alert('❌ Failed to activate agent: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error activating agent:', error);
        alert('❌ Error activating agent. Please try again.');
    }
}

// Deactivate agent
async function deactivateAgent(agentId) {
    if (!confirm('Deactivate this agent? It will stop sending logs.')) {
        return;
    }

    try {
        const response = await fetch(`/api/agents/${agentId}/deactivate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            alert('✅ Agent deactivated successfully');
            loadAgentsPage(); // Reload
        } else {
            alert('❌ Failed to deactivate agent: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deactivating agent:', error);
        alert('❌ Error deactivating agent. Please try again.');
    }
}

// View agent details
function viewAgentDetails(agentId) {
    // Use the agent details modal if available
    if (typeof openAgentDetailsModal === 'function') {
        openAgentDetailsModal(agentId);
    } else {
        alert('Agent details view not available');
    }
}

// HTML escape function
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Auto-refresh every 30 seconds when on agents page
setInterval(() => {
    const agentsPage = document.getElementById('page-agents');
    if (agentsPage && agentsPage.style.display !== 'none') {
        loadAgentsPage();
    }
}, 30000);
