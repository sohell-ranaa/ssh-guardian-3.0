/**
 * Agent Management Page Module
 * Handles agent listing, stats, and management actions
 */

// Load agents page data
async function loadAgentsPage() {
    // Ensure styles are injected
    injectAgentModalStyles();

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
        ? (window.TimeSettings?.isLoaded() ? window.TimeSettings.formatShort(agent.last_heartbeat) : new Date(agent.last_heartbeat).toLocaleString())
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
                <button class="btn-delete" onclick="confirmDeleteAgent(${agent.id}, '${escapeHtml(agent.hostname || agent.agent_id)}')" title="Delete agent permanently">
                    🗑 Delete
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

// Confirm delete agent with type-to-confirm security
function confirmDeleteAgent(agentId, hostname) {
    injectAgentModalStyles();

    // Remove existing modals
    document.querySelectorAll('.agent-modal-overlay').forEach(el => el.remove());

    const overlay = document.createElement('div');
    overlay.className = 'agent-modal-overlay';

    const modal = document.createElement('div');
    modal.className = 'agent-modal';

    modal.innerHTML = `
        <div class="agent-modal-header danger">
            <h3 class="agent-modal-title">
                <span style="font-size: 20px;">⚠️</span>
                Delete Agent Permanently
            </h3>
            <button class="agent-modal-close" title="Close">&times;</button>
        </div>
        <div class="agent-modal-body">
            <p style="margin: 0 0 16px 0; color: var(--text-primary); font-size: 14px; line-height: 1.5;">
                You are about to <strong>permanently delete</strong> the agent:
            </p>
            <div style="background: linear-gradient(135deg, var(--hover-bg, #f5f5f5) 0%, var(--surface, #fafafa) 100%); padding: 16px; border-radius: 8px; font-family: 'SF Mono', 'Consolas', monospace; font-size: 18px; font-weight: 600; text-align: center; margin-bottom: 20px; border: 1px solid var(--border);">
                ${escapeHtml(hostname)}
            </div>
            <div style="background: rgba(209, 52, 56, 0.08); border: 1px solid rgba(209, 52, 56, 0.2); border-radius: 6px; padding: 12px 14px; margin-bottom: 20px;">
                <div style="display: flex; align-items: flex-start; gap: 10px;">
                    <span style="font-size: 16px;">🚫</span>
                    <div style="color: #A4262C; font-size: 13px; line-height: 1.5;">
                        <p style="margin: 0 0 8px 0;"><strong>This action cannot be undone.</strong></p>
                        <p style="margin: 0;">The following will be permanently deleted:</p>
                        <ul style="margin: 8px 0 0 0; padding-left: 20px;">
                            <li>All heartbeat history</li>
                            <li>All log batch records</li>
                            <li>All firewall rules and commands</li>
                            <li>All security suggestions</li>
                            <li>The agent registration</li>
                        </ul>
                    </div>
                </div>
            </div>
            <div>
                <label style="font-size: 13px; font-weight: 600; display: block; margin-bottom: 6px; color: var(--text-primary);">
                    Type the hostname to confirm deletion:
                </label>
                <input type="text" id="confirmDeleteAgentInput" class="agent-delete-confirm-input" placeholder="Enter ${hostname}" autocomplete="off">
            </div>
        </div>
        <div class="agent-modal-footer">
            <button class="agent-modal-btn agent-modal-btn-secondary modal-cancel-btn">Cancel</button>
            <button id="confirmDeleteAgentBtn" class="agent-modal-btn agent-modal-btn-danger" disabled>
                <span style="display: flex; align-items: center; gap: 6px;">
                    🗑️ Delete Permanently
                </span>
            </button>
        </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    const confirmInput = modal.querySelector('#confirmDeleteAgentInput');
    const confirmBtn = modal.querySelector('#confirmDeleteAgentBtn');

    const closeModal = () => {
        overlay.style.animation = 'agentModalFadeIn 0.15s ease-out reverse';
        modal.style.animation = 'agentModalSlideIn 0.15s ease-out reverse';
        setTimeout(() => {
            overlay.remove();
            document.body.style.overflow = '';
        }, 140);
    };

    // Enable button only when hostname matches
    confirmInput.oninput = () => {
        const matches = confirmInput.value.trim() === hostname;
        confirmBtn.disabled = !matches;
        confirmInput.classList.remove('error', 'success');
        if (confirmInput.value.trim()) {
            confirmInput.classList.add(matches ? 'success' : 'error');
        }
    };

    // Delete action
    confirmBtn.onclick = async () => {
        if (confirmInput.value.trim() !== hostname) return;

        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<span style="display: flex; align-items: center; gap: 6px;"><span class="agent-loading-spinner"></span> Deleting...</span>';

        try {
            const response = await fetch(`/api/agents/${agentId}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                closeModal();
                showAgentNotification(`Agent "${hostname}" deleted successfully`, 'success');
                setTimeout(() => loadAgentsPage(), 500);
            } else {
                showAgentNotification(`Failed to delete: ${data.error || 'Unknown error'}`, 'error');
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = '<span style="display: flex; align-items: center; gap: 6px;">🗑️ Delete Permanently</span>';
            }
        } catch (error) {
            console.error('Error deleting agent:', error);
            showAgentNotification('Error deleting agent', 'error');
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '<span style="display: flex; align-items: center; gap: 6px;">🗑️ Delete Permanently</span>';
        }
    };

    // Close handlers
    modal.querySelector('.agent-modal-close').onclick = closeModal;
    modal.querySelector('.modal-cancel-btn').onclick = closeModal;
    overlay.onclick = (e) => {
        if (e.target === overlay) closeModal();
    };

    // ESC to close
    const keyHandler = (e) => {
        if (e.key === 'Escape') {
            closeModal();
            document.removeEventListener('keydown', keyHandler);
        }
    };
    document.addEventListener('keydown', keyHandler);

    // Focus input
    setTimeout(() => confirmInput.focus(), 100);
}

// Inject agent modal styles
function injectAgentModalStyles() {
    if (document.getElementById('agent-modal-styles')) return;

    const style = document.createElement('style');
    style.id = 'agent-modal-styles';
    style.textContent = `
        .agent-modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            width: 100vw;
            height: 100vh;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            display: flex;
            align-items: flex-start;
            justify-content: center;
            z-index: 10000;
            padding: 60px 20px 20px 20px;
            overflow-y: auto;
            animation: agentModalFadeIn 0.2s ease-out;
            box-sizing: border-box;
        }

        @keyframes agentModalFadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes agentModalSlideIn {
            from {
                opacity: 0;
                transform: translateY(-20px) scale(0.98);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        .agent-modal {
            background: var(--card-bg, #ffffff);
            border-radius: 8px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(0, 0, 0, 0.05);
            max-width: 520px;
            width: 100%;
            animation: agentModalSlideIn 0.25s ease-out;
            margin: 0 auto 40px auto;
            flex-shrink: 0;
        }

        .agent-modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border, #e0e0e0);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface, #fafafa);
            border-radius: 8px 8px 0 0;
        }

        .agent-modal-header.danger {
            background: linear-gradient(135deg, #D13438 0%, #A4262C 100%);
        }

        .agent-modal-header.danger .agent-modal-title {
            color: white;
        }

        .agent-modal-header.danger .agent-modal-close {
            color: rgba(255,255,255,0.8);
        }

        .agent-modal-header.danger .agent-modal-close:hover {
            color: white;
            background: rgba(255,255,255,0.1);
        }

        .agent-modal-title {
            font-size: 17px;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary, #323130);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .agent-modal-close {
            background: none;
            border: none;
            font-size: 22px;
            cursor: pointer;
            color: var(--text-secondary, #605E5C);
            padding: 0;
            width: 36px;
            height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
            transition: all 0.15s ease;
        }

        .agent-modal-close:hover {
            background: var(--hover-bg, #f0f0f0);
            color: var(--text-primary, #323130);
        }

        .agent-modal-body {
            padding: 24px;
        }

        .agent-modal-footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border, #e0e0e0);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            background: var(--surface, #fafafa);
            border-radius: 0 0 8px 8px;
        }

        .agent-modal-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
        }

        .agent-modal-btn-secondary {
            background: var(--surface, #f0f0f0);
            color: var(--text-primary, #323130);
            border: 1px solid var(--border, #e0e0e0);
        }

        .agent-modal-btn-secondary:hover {
            background: var(--hover-bg, #e8e8e8);
        }

        .agent-modal-btn-danger {
            background: #D13438;
            color: white;
        }

        .agent-modal-btn-danger:hover:not(:disabled) {
            background: #C42B30;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(209, 52, 56, 0.3);
        }

        .agent-modal-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .agent-delete-confirm-input {
            width: 100%;
            padding: 12px 14px;
            border: 2px solid var(--border, #e0e0e0);
            border-radius: 6px;
            font-size: 15px;
            font-family: 'SF Mono', 'Consolas', monospace;
            transition: all 0.2s ease;
            box-sizing: border-box;
        }

        .agent-delete-confirm-input:focus {
            outline: none;
            border-color: var(--azure-blue, #0078D4);
            box-shadow: 0 0 0 3px rgba(0, 120, 212, 0.1);
        }

        .agent-delete-confirm-input.error {
            border-color: #D13438;
            box-shadow: 0 0 0 3px rgba(209, 52, 56, 0.1);
        }

        .agent-delete-confirm-input.success {
            border-color: #107C10;
            box-shadow: 0 0 0 3px rgba(16, 124, 16, 0.1);
        }

        .agent-loading-spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255,255,255,0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: agentSpin 0.8s linear infinite;
        }

        @keyframes agentSpin {
            to { transform: rotate(360deg); }
        }

        /* Delete button styling */
        .btn-delete {
            padding: 8px 12px;
            border: 1px solid #D13438;
            background: transparent;
            color: #D13438;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 500;
            transition: all 0.15s ease;
        }

        .btn-delete:hover {
            background: #D13438;
            color: white;
        }

        @media (max-width: 600px) {
            .agent-modal-overlay {
                padding: 20px 10px;
            }
        }
    `;
    document.head.appendChild(style);
}

// Show notification for agent actions
function showAgentNotification(message, type = 'info') {
    const colors = {
        success: '#107C10',
        error: '#D13438',
        info: '#0078D4',
        warning: '#FFB900'
    };

    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        padding: 16px 24px;
        background: ${colors[type]};
        color: white;
        border-radius: 4px;
        font-size: 14px;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: agentNotifSlideIn 0.3s ease;
    `;
    notification.textContent = message;

    // Add animation keyframes if not present
    if (!document.getElementById('agent-notif-styles')) {
        const style = document.createElement('style');
        style.id = 'agent-notif-styles';
        style.textContent = `
            @keyframes agentNotifSlideIn {
                from { transform: translateX(400px); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes agentNotifSlideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(400px); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    }

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'agentNotifSlideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Auto-refresh every 30 seconds when on agents page
setInterval(() => {
    const agentsPage = document.getElementById('page-agents');
    if (agentsPage && agentsPage.style.display !== 'none') {
        loadAgentsPage();
    }
}, 30000);

// Inject styles immediately when script loads
injectAgentModalStyles();
