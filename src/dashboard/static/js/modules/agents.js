// Agent Management Module

async function loadAgents() {
    try {
        const response = await fetch('/api/agents/list');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();

        if (data.success) {
            displayAgents(data.agents);
        }
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

function displayAgents(agents) {
    const container = document.getElementById('agents-container');
    if (!container) return;

    if (agents.length === 0) {
        container.innerHTML = '<div class="empty-state">No agents registered</div>';
        return;
    }

    const html = agents.map(agent => `
        <div class="agent-card ${agent.status}">
            <div class="agent-header">
                <h3>${agent.hostname}</h3>
                <span class="agent-status ${agent.status}">${agent.status}</span>
            </div>
            <div class="agent-details">
                <p><strong>Agent ID:</strong> ${agent.agent_id}</p>
                <p><strong>Last Heartbeat:</strong> ${agent.last_heartbeat || 'Never'}</p>
                <p><strong>Events Sent:</strong> ${agent.total_events_sent}</p>
                <p><strong>Health:</strong> ${agent.health_status}</p>
            </div>
            <div class="agent-actions">
                ${!agent.is_approved ? `<button onclick="approveAgent(${agent.id})" class="btn-primary">Approve</button>` : ''}
                ${agent.is_active ? `<button onclick="deactivateAgent(${agent.id})" class="btn-secondary">Deactivate</button>` : ''}
            </div>
        </div>
    `).join('');

    container.innerHTML = html;
}

async function approveAgent(agentId) {
    if (!confirm('Approve this agent?')) return;

    try {
        const response = await fetch(`/api/agents/${agentId}/approve`, {
            method: 'POST'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();

        if (data.success) {
            alert('Agent approved successfully');
            loadAgents();
            loadAgentStats();
        } else {
            alert('Failed to approve agent: ' + data.error);
        }
    } catch (error) {
        console.error('Error approving agent:', error);
        alert('Error approving agent');
    }
}

async function deactivateAgent(agentId) {
    if (!confirm('Deactivate this agent?')) return;

    try {
        const response = await fetch(`/api/agents/${agentId}/deactivate`, {
            method: 'POST'
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();

        if (data.success) {
            alert('Agent deactivated successfully');
            loadAgents();
            loadAgentStats();
        } else {
            alert('Failed to deactivate agent: ' + data.error);
        }
    } catch (error) {
        console.error('Error deactivating agent:', error);
        alert('Error deactivating agent');
    }
}

async function loadAgentStats() {
    try {
        const response = await fetch('/api/agents/stats');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();

        if (data.success) {
            displayAgentStats(data.stats);
        }
    } catch (error) {
        console.error('Error loading agent stats:', error);
    }
}

function displayAgentStats(stats) {
    const container = document.getElementById('agent-stats');
    if (!container) return;

    container.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Agents</div>
            <div class="stat-value">${stats.total_agents}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Online</div>
            <div class="stat-value">${stats.online_agents}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Active</div>
            <div class="stat-value">${stats.active_agents}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Approved</div>
            <div class="stat-value">${stats.approved_agents}</div>
        </div>
    `;
}

// Initialize agents page when loaded
if (document.getElementById('page-agents')) {
    loadAgents();
    loadAgentStats();

    // Auto-refresh every 30 seconds
    setInterval(() => {
        loadAgents();
        loadAgentStats();
    }, 30000);
}
