/**
 * SSH Guardian v3.0 - Agents Module
 * Unified module for agents page, details modal, search, and management
 * Uses global escapeHtml() from utils.js and btn classes from buttons.css
 */

(function() {
    'use strict';

    // ===========================================
    // Constants
    // ===========================================
    const HEARTBEAT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
    const AUTO_REFRESH_INTERVAL = 30000; // 30 seconds

    // ===========================================
    // State
    // ===========================================
    let allAgents = [];
    let refreshTimer = null;

    // ===========================================
    // Utility Functions
    // ===========================================

    /**
     * Check if agent is online based on last heartbeat
     */
    function isAgentOnline(agent) {
        if (!agent.last_heartbeat) return false;
        const hbTime = parseTimestamp(agent.last_heartbeat);
        if (!hbTime) return false;
        return (Date.now() - hbTime) < HEARTBEAT_TIMEOUT_MS;
    }

    /**
     * Parse timestamp string to milliseconds
     * Server timestamps are in server timezone (+08:00)
     */
    function parseTimestamp(ts) {
        if (!ts) return null;
        let str = String(ts).replace(' ', 'T');
        // Add server timezone if no timezone info
        if (!str.endsWith('Z') && !str.includes('+') && !str.match(/T\d{2}:\d{2}:\d{2}-/)) {
            str += '+08:00';
        }
        const d = new Date(str);
        return isNaN(d.getTime()) ? null : d.getTime();
    }

    // formatDateTime - use shared utility from utils.js
    const formatDateTime = window.formatLocalDateTime;

    /**
     * Get time ago string from timestamp
     */
    function getTimeAgo(ts) {
        if (!ts) return 'Never';
        const hbTime = parseTimestamp(ts);
        if (!hbTime) return 'Invalid';

        const diff = Date.now() - hbTime;
        if (diff < 0) return 'Future?';

        const mins = Math.floor(diff / 60000);
        const hours = Math.floor(mins / 60);
        const days = Math.floor(hours / 24);

        if (mins < 1) return 'Just now';
        if (mins < 60) return `${mins}m ago`;
        if (hours < 24) return `${hours}h ${mins % 60}m ago`;
        return `${days}d ago`;
    }

    /**
     * Format number with locale
     */
    function formatNumber(n) {
        return (n || 0).toLocaleString();
    }

    /**
     * Get IP address from agent (handles schema differences)
     */
    function getAgentIP(agent) {
        return agent.ip_address || agent.ip_address_primary || 'N/A';
    }

    // Use global toast from toast.js
    const showToast = window.showToast || function(msg) { console.log(msg); };

    // ===========================================
    // Page Loading
    // ===========================================

    /**
     * Load agents page data
     */
    async function loadAgentsPage() {
        await Promise.all([loadAgentStats(), loadAgentsList()]);
        initSearchListeners();
    }

    /**
     * Load agent statistics
     */
    async function loadAgentStats() {
        try {
            const response = await fetch('/api/agents/stats');
            const data = await response.json();

            if (data.success) {
                const s = data.stats;
                setText('stat-total-agents', s.total_agents);
                setText('stat-online-agents', s.online_agents);
                setText('stat-approved-agents', s.approved_agents);
                setText('stat-total-events', formatNumber(s.total_events));
            }
        } catch (error) {
            console.error('Error loading agent stats:', error);
        }
    }

    function setText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    /**
     * Load agents list
     */
    async function loadAgentsList() {
        const container = document.getElementById('agents-container');
        if (!container) return;

        try {
            const response = await fetch('/api/agents/list');
            const data = await response.json();

            if (!data.success) {
                container.innerHTML = renderEmptyState('Error Loading Agents', data.error || 'Unknown error', 'warning');
                return;
            }

            if (data.agents.length === 0) {
                container.innerHTML = renderEmptyState('No Agents Registered',
                    'Deploy agents on remote servers to start collecting SSH logs', 'robot');
                return;
            }

            allAgents = data.agents;
            renderAgents(allAgents);
        } catch (error) {
            console.error('Error loading agents:', error);
            container.innerHTML = renderEmptyState('Connection Error', 'Failed to load agents. Please try again.', 'error');
        }
    }

    function renderEmptyState(title, desc, icon) {
        const icons = { warning: '⚠️', robot: '🤖', error: '❌', search: '🔍' };
        return `
            <div class="agent-empty-state" style="grid-column: 1 / -1;">
                <div class="agent-empty-state-icon">${icons[icon] || '📋'}</div>
                <div class="agent-empty-state-title">${escapeHtml(title)}</div>
                <div class="agent-empty-state-desc">${escapeHtml(desc)}</div>
            </div>
        `;
    }

    /**
     * Render agents grid
     */
    function renderAgents(agents) {
        const container = document.getElementById('agents-container');
        if (!container) return;

        if (agents.length === 0) {
            container.innerHTML = renderEmptyState('No Agents Found', 'Try adjusting your search or filters', 'search');
            return;
        }

        container.innerHTML = agents.map(renderAgentCard).join('');
    }

    /**
     * Create agent card HTML
     */
    function renderAgentCard(agent) {
        const online = isAgentOnline(agent);
        const statusClass = online ? 'online' : 'offline';
        const statusText = online ? 'Online' : 'Offline';
        const hostname = agent.hostname || agent.agent_id;
        const initial = hostname.charAt(0).toUpperCase();
        const lastHb = getTimeAgo(agent.last_heartbeat);

        return `
            <div class="agent-card">
                <div class="agent-card-header">
                    <div class="agent-card-title">
                        <div class="agent-card-avatar ${statusClass}">${initial}</div>
                        <span class="agent-card-name">${escapeHtml(hostname)}</span>
                    </div>
                    <span class="agent-status-pill ${statusClass}">${statusText}</span>
                </div>
                <div class="agent-card-body">
                    <div class="agent-card-row">
                        <span class="agent-card-label">Agent ID</span>
                        <span class="agent-card-value mono">${escapeHtml(agent.agent_id)}</span>
                    </div>
                    <div class="agent-card-row">
                        <span class="agent-card-label">IP Address</span>
                        <span class="agent-card-value">${escapeHtml(getAgentIP(agent))}</span>
                    </div>
                    <div class="agent-card-row">
                        <span class="agent-card-label">Version</span>
                        <span class="agent-card-value">${escapeHtml(agent.version || 'N/A')}</span>
                    </div>
                    <div class="agent-card-row">
                        <span class="agent-card-label">Environment</span>
                        <span class="agent-card-value">${escapeHtml(agent.environment || 'production')}</span>
                    </div>
                    <div class="agent-card-row">
                        <span class="agent-card-label">Events Sent</span>
                        <span class="agent-card-value">${formatNumber(agent.total_events_sent)}</span>
                    </div>
                    <div class="agent-card-row">
                        <span class="agent-card-label">Last Heartbeat</span>
                        <span class="agent-card-value">${lastHb}</span>
                    </div>
                    <div class="agent-card-row">
                        <span class="agent-card-label">Status</span>
                        <span class="agent-card-value">
                            ${agent.is_approved ? '<span class="agent-badge approved">Approved</span>' : '<span class="agent-badge pending">Pending</span>'}
                            ${!agent.is_active ? '<span class="agent-badge inactive">Inactive</span>' : ''}
                        </span>
                    </div>
                </div>
                <div class="agent-card-footer">
                    ${!agent.is_approved ? `<button class="btn btn-success btn-sm" onclick="approveAgent(${agent.id})">Approve</button>` : ''}
                    ${agent.is_active
                        ? `<button class="btn btn-secondary btn-sm" onclick="deactivateAgent(${agent.id})">Deactivate</button>`
                        : `<button class="btn btn-success btn-sm" onclick="activateAgent(${agent.id})">Activate</button>`
                    }
                    <button class="btn btn-primary btn-sm" onclick="openAgentDetailsModal(${agent.id})">Details</button>
                </div>
            </div>
        `;
    }

    // ===========================================
    // Search & Filter
    // ===========================================

    function initSearchListeners() {
        const searchInput = document.getElementById('agent-search-input');
        const statusFilter = document.getElementById('agent-status-filter');
        const envFilter = document.getElementById('agent-environment-filter');

        if (searchInput && !searchInput.dataset.initialized) {
            searchInput.addEventListener('input', filterAgents);
            searchInput.dataset.initialized = 'true';
        }
        if (statusFilter && !statusFilter.dataset.initialized) {
            statusFilter.addEventListener('change', filterAgents);
            statusFilter.dataset.initialized = 'true';
        }
        if (envFilter && !envFilter.dataset.initialized) {
            envFilter.addEventListener('change', filterAgents);
            envFilter.dataset.initialized = 'true';
        }
    }

    function filterAgents() {
        const search = (document.getElementById('agent-search-input')?.value || '').toLowerCase();
        const status = document.getElementById('agent-status-filter')?.value || 'all';
        const env = document.getElementById('agent-environment-filter')?.value || 'all';

        const filtered = allAgents.filter(agent => {
            // Search match
            const matchSearch = !search ||
                (agent.hostname || '').toLowerCase().includes(search) ||
                (agent.agent_id || '').toLowerCase().includes(search) ||
                getAgentIP(agent).toLowerCase().includes(search) ||
                (agent.display_name || '').toLowerCase().includes(search);

            // Status match
            const online = isAgentOnline(agent);
            const matchStatus = status === 'all' ||
                (status === 'online' && online) ||
                (status === 'offline' && !online) ||
                (status === 'approved' && agent.is_approved) ||
                (status === 'pending' && !agent.is_approved);

            // Environment match
            const matchEnv = env === 'all' || agent.environment === env;

            return matchSearch && matchStatus && matchEnv;
        });

        renderAgents(filtered);
        updateFilterStats(filtered.length, allAgents.length);
    }

    function updateFilterStats(shown, total) {
        const el = document.getElementById('agent-filter-stats');
        if (el) {
            el.textContent = shown === total
                ? `Showing all ${total} agents`
                : `Showing ${shown} of ${total} agents`;
        }
    }

    function clearAgentFilters() {
        const searchInput = document.getElementById('agent-search-input');
        const statusFilter = document.getElementById('agent-status-filter');
        const envFilter = document.getElementById('agent-environment-filter');

        if (searchInput) searchInput.value = '';
        if (statusFilter) statusFilter.value = 'all';
        if (envFilter) envFilter.value = 'all';

        filterAgents();
    }

    // ===========================================
    // Agent Actions
    // ===========================================

    async function approveAgent(agentId) {
        if (!confirm('Approve this agent? It will be able to send logs to the server.')) return;
        await agentAction(agentId, 'approve', 'Agent approved successfully');
    }

    async function activateAgent(agentId) {
        if (!confirm('Activate this agent? It will resume sending logs.')) return;
        await agentAction(agentId, 'activate', 'Agent activated successfully');
    }

    async function deactivateAgent(agentId) {
        if (!confirm('Deactivate this agent? It will stop sending logs.')) return;
        await agentAction(agentId, 'deactivate', 'Agent deactivated successfully');
    }

    async function agentAction(agentId, action, successMsg) {
        try {
            const response = await fetch(`/api/agents/${agentId}/${action}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();

            if (data.success) {
                showToast(successMsg, 'success');
                loadAgentsPage();
            } else {
                showToast(`Failed: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (error) {
            console.error(`Error ${action} agent:`, error);
            showToast(`Error ${action} agent`, 'error');
        }
    }

    // ===========================================
    // Agent Details Modal
    // ===========================================

    async function openAgentDetailsModal(agentId) {
        const modal = document.getElementById('agent-details-modal');
        const content = document.getElementById('agent-details-content');

        if (!modal || !content) return;

        modal.classList.add('active');
        content.innerHTML = `
            <div class="agent-modal-loading">
                <div class="agent-modal-spinner"></div>
                <div>Loading agent details...</div>
            </div>
        `;

        try {
            const response = await fetch(`/api/agents/${agentId}`);
            const data = await response.json();

            if (!data.success) {
                content.innerHTML = renderModalError(data.error || 'Failed to load agent');
                return;
            }

            content.innerHTML = renderAgentDetails(data.agent, data.recent_heartbeats, data.recent_batches);
        } catch (error) {
            console.error('Error loading agent details:', error);
            content.innerHTML = renderModalError('Failed to connect to server');
        }
    }

    function closeAgentDetailsModal() {
        const modal = document.getElementById('agent-details-modal');
        if (modal) modal.classList.remove('active');
    }

    function renderModalError(msg) {
        return `
            <div class="agent-modal-error">
                <div class="agent-modal-error-icon">!</div>
                <div class="agent-modal-error-title">Error</div>
                <div class="agent-modal-error-msg">${escapeHtml(msg)}</div>
            </div>
        `;
    }

    /**
     * Render full agent details
     */
    function renderAgentDetails(agent, heartbeats, batches) {
        const online = isAgentOnline(agent);
        const statusClass = online ? 'online' : 'offline';
        const statusText = online ? 'Online' : 'Offline';
        const hostname = agent.hostname || agent.agent_id;
        const initial = hostname.charAt(0).toUpperCase();
        const latestHb = heartbeats?.[0] || null;

        // Get metrics from latest heartbeat
        // v3.1 uses cpu_usage, v3.0 used cpu_percent
        const cpu = latestHb?.cpu_usage ?? latestHb?.cpu_percent ?? null;
        const mem = latestHb?.memory_usage ?? latestHb?.memory_percent ?? null;
        const disk = latestHb?.disk_usage ?? latestHb?.disk_percent ?? null;

        return `
            <!-- Header -->
            <div class="agent-detail-header">
                <div class="agent-detail-info">
                    <div class="agent-detail-avatar ${statusClass}">${initial}</div>
                    <div>
                        <div class="agent-detail-name">${escapeHtml(hostname)}</div>
                        <div class="agent-detail-meta">
                            <span class="status-dot ${statusClass}"></span>
                            <span>${statusText}</span>
                            <span class="sep">|</span>
                            <span>${escapeHtml(getAgentIP(agent))}</span>
                            <span class="sep">|</span>
                            <span>v${escapeHtml(agent.version || '?')}</span>
                        </div>
                    </div>
                </div>
                <div class="agent-detail-badges">
                    ${agent.is_approved ? '<span class="agent-badge approved">Approved</span>' : '<span class="agent-badge pending">Pending</span>'}
                    ${!agent.is_active ? '<span class="agent-badge inactive">Inactive</span>' : ''}
                </div>
            </div>

            <!-- Metrics -->
            <div class="agent-metrics-grid">
                <div class="agent-metric-card">
                    <div class="agent-metric-icon cpu">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="4" y="4" width="16" height="16" rx="2"/>
                            <rect x="9" y="9" width="6" height="6"/>
                        </svg>
                    </div>
                    <div>
                        <div class="agent-metric-value">${cpu !== null ? cpu.toFixed(1) + '%' : '--'}</div>
                        <div class="agent-metric-label">CPU</div>
                    </div>
                </div>
                <div class="agent-metric-card">
                    <div class="agent-metric-icon memory">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="2" y="6" width="20" height="12" rx="2"/>
                            <line x1="6" y1="10" x2="6" y2="14"/>
                            <line x1="10" y1="10" x2="10" y2="14"/>
                            <line x1="14" y1="10" x2="14" y2="14"/>
                            <line x1="18" y1="10" x2="18" y2="14"/>
                        </svg>
                    </div>
                    <div>
                        <div class="agent-metric-value">${mem !== null ? mem.toFixed(1) + '%' : '--'}</div>
                        <div class="agent-metric-label">Memory</div>
                    </div>
                </div>
                <div class="agent-metric-card">
                    <div class="agent-metric-icon disk">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <ellipse cx="12" cy="5" rx="9" ry="3"/>
                            <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                            <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                        </svg>
                    </div>
                    <div>
                        <div class="agent-metric-value">${disk !== null ? disk.toFixed(1) + '%' : '--'}</div>
                        <div class="agent-metric-label">Disk</div>
                    </div>
                </div>
                <div class="agent-metric-card">
                    <div class="agent-metric-icon heartbeat">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M22 12h-4l-3 9L9 3l-3 9H2"/>
                        </svg>
                    </div>
                    <div>
                        <div class="agent-metric-value">${getTimeAgo(agent.last_heartbeat)}</div>
                        <div class="agent-metric-label">Last Heartbeat</div>
                    </div>
                </div>
            </div>

            <!-- Agent Information -->
            <div class="agent-section">
                <div class="agent-section-title">Agent Information</div>
                <div class="agent-info-grid">
                    <div class="agent-info-item">
                        <span class="agent-info-label">Agent ID</span>
                        <span class="agent-info-value mono">${escapeHtml(agent.agent_id)}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">UUID</span>
                        <span class="agent-info-value mono">${escapeHtml(agent.agent_uuid || 'N/A')}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">Environment</span>
                        <span class="agent-info-value">${escapeHtml(agent.environment || 'production')}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">Type</span>
                        <span class="agent-info-value">${escapeHtml(agent.agent_type || 'standard')}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">Events Sent</span>
                        <span class="agent-info-value">${formatNumber(agent.total_events_sent)}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">Heartbeat Interval</span>
                        <span class="agent-info-value">${agent.heartbeat_interval_sec || 60}s</span>
                    </div>
                </div>
            </div>

            <!-- API Key -->
            <div class="agent-section">
                <div class="agent-section-title">API Key</div>
                <div class="agent-apikey-box">
                    <code>${escapeHtml(agent.api_key || 'Not assigned')}</code>
                    ${agent.api_key ? `<button class="btn btn-primary btn-sm" onclick="copyToClipboard('${escapeHtml(agent.api_key)}', this)">Copy</button>` : ''}
                </div>
            </div>

            <!-- Recent Heartbeats -->
            <div class="agent-section">
                <div class="agent-section-title">Recent Heartbeats</div>
                ${renderHeartbeatsTable(heartbeats)}
            </div>

            <!-- Recent Batches -->
            <div class="agent-section">
                <div class="agent-section-title">Recent Log Batches</div>
                ${renderBatchesTable(batches)}
            </div>

            <!-- Timestamps -->
            <div class="agent-section">
                <div class="agent-section-title">Timestamps</div>
                <div class="agent-info-grid cols-2">
                    <div class="agent-info-item">
                        <span class="agent-info-label">Created</span>
                        <span class="agent-info-value">${formatDateTime(agent.created_at)}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">Updated</span>
                        <span class="agent-info-value">${formatDateTime(agent.updated_at)}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">Approved</span>
                        <span class="agent-info-value">${formatDateTime(agent.approved_at)}</span>
                    </div>
                    <div class="agent-info-item">
                        <span class="agent-info-label">Last Restart</span>
                        <span class="agent-info-value">${formatDateTime(agent.last_restart_at)}</span>
                    </div>
                </div>
            </div>

            <!-- Danger Zone -->
            <div class="agent-section agent-danger-zone">
                <div class="agent-section-title">Danger Zone</div>
                <p>Permanently delete this agent and all associated data.</p>
                <button class="btn btn-danger btn-sm" onclick="closeAgentDetailsModal(); setTimeout(() => confirmDeleteAgent(${agent.id}, '${escapeHtml(hostname).replace(/'/g, "\\'")}'), 200);">
                    Delete Agent
                </button>
            </div>
        `;
    }

    function renderHeartbeatsTable(heartbeats) {
        if (!heartbeats || heartbeats.length === 0) {
            return '<div class="agent-empty-state" style="padding: 24px;">No heartbeats recorded</div>';
        }

        const rows = heartbeats.slice(0, 10).map(hb => {
            const cpu = hb.cpu_usage ?? hb.cpu_percent;
            const mem = hb.memory_usage ?? hb.memory_percent;
            const disk = hb.disk_usage ?? hb.disk_percent;
            return `
                <tr>
                    <td>${formatDateTime(hb.heartbeat_timestamp || hb.timestamp)}</td>
                    <td>${cpu != null ? cpu.toFixed(1) + '%' : '--'}</td>
                    <td>${mem != null ? mem.toFixed(1) + '%' : '--'}</td>
                    <td>${disk != null ? disk.toFixed(1) + '%' : '--'}</td>
                </tr>
            `;
        }).join('');

        return `
            <div class="agent-table-scroll">
                <table class="agent-data-table">
                    <thead><tr><th>Timestamp</th><th>CPU</th><th>Memory</th><th>Disk</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    function renderBatchesTable(batches) {
        if (!batches || batches.length === 0) {
            return '<div class="agent-empty-state" style="padding: 24px;">No log batches recorded</div>';
        }

        const rows = batches.slice(0, 10).map(b => {
            const status = b.status || b.processing_status || 'unknown';
            const statusClass = status === 'completed' ? 'status-ok' : 'status-warn';
            return `
                <tr>
                    <td>${formatDateTime(b.created_at || b.received_at)}</td>
                    <td>${b.events_count || b.batch_size || 0}</td>
                    <td>${b.events_processed || b.events_created || 0}</td>
                    <td class="${statusClass}">${status}</td>
                </tr>
            `;
        }).join('');

        return `
            <div class="agent-table-scroll">
                <table class="agent-data-table">
                    <thead><tr><th>Received</th><th>Events</th><th>Processed</th><th>Status</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    // ===========================================
    // Delete Confirmation
    // ===========================================

    function confirmDeleteAgent(agentId, hostname) {
        // Remove existing delete modals
        document.querySelectorAll('.agent-delete-modal').forEach(el => el.remove());

        const modal = document.createElement('div');
        modal.className = 'agent-delete-modal';
        modal.innerHTML = `
            <div class="agent-delete-content">
                <div class="agent-delete-header">
                    <h3>Delete Agent Permanently</h3>
                    <button class="agent-modal-close">&times;</button>
                </div>
                <div class="agent-delete-body">
                    <p style="margin: 0 0 16px; color: var(--text-primary); font-size: 14px;">
                        You are about to <strong>permanently delete</strong> the agent:
                    </p>
                    <div class="agent-delete-name">${escapeHtml(hostname)}</div>
                    <div class="agent-delete-warning">
                        <p><strong>This action cannot be undone.</strong></p>
                        <p>The following will be permanently deleted:</p>
                        <ul>
                            <li>All heartbeat history</li>
                            <li>All log batch records</li>
                            <li>All firewall rules and commands</li>
                            <li>The agent registration</li>
                        </ul>
                    </div>
                    <label class="agent-delete-confirm-label">Type the hostname to confirm:</label>
                    <input type="text" class="agent-delete-input" placeholder="Enter ${hostname}" autocomplete="off">
                </div>
                <div class="agent-delete-footer">
                    <button class="btn btn-secondary cancel-btn">Cancel</button>
                    <button class="btn btn-danger delete-btn" disabled>Delete Permanently</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        document.body.style.overflow = 'hidden';

        const input = modal.querySelector('.agent-delete-input');
        const deleteBtn = modal.querySelector('.delete-btn');
        const cancelBtn = modal.querySelector('.cancel-btn');
        const closeBtn = modal.querySelector('.agent-modal-close');

        const closeModal = () => {
            modal.style.animation = 'fadeIn 0.15s ease-out reverse';
            setTimeout(() => {
                modal.remove();
                document.body.style.overflow = '';
            }, 140);
        };

        input.addEventListener('input', () => {
            const matches = input.value.trim() === hostname;
            deleteBtn.disabled = !matches;
            input.classList.remove('error', 'success');
            if (input.value.trim()) {
                input.classList.add(matches ? 'success' : 'error');
            }
        });

        deleteBtn.addEventListener('click', async () => {
            if (input.value.trim() !== hostname) return;

            deleteBtn.disabled = true;
            deleteBtn.innerHTML = '<span class="agent-modal-spinner" style="width:14px;height:14px;margin-right:8px;"></span>Deleting...';

            try {
                const response = await fetch(`/api/agents/${agentId}`, { method: 'DELETE' });
                const data = await response.json();

                if (data.success) {
                    closeModal();
                    showToast(`Agent "${hostname}" deleted successfully`, 'success');
                    setTimeout(loadAgentsPage, 500);
                } else {
                    showToast(`Failed: ${data.error || 'Unknown error'}`, 'error');
                    deleteBtn.disabled = false;
                    deleteBtn.textContent = 'Delete Permanently';
                }
            } catch (error) {
                console.error('Error deleting agent:', error);
                showToast('Error deleting agent', 'error');
                deleteBtn.disabled = false;
                deleteBtn.textContent = 'Delete Permanently';
            }
        });

        closeBtn.addEventListener('click', closeModal);
        cancelBtn.addEventListener('click', closeModal);
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });

        const keyHandler = (e) => {
            if (e.key === 'Escape') {
                closeModal();
                document.removeEventListener('keydown', keyHandler);
            }
        };
        document.addEventListener('keydown', keyHandler);

        setTimeout(() => input.focus(), 100);
    }

    // ===========================================
    // Clipboard
    // ===========================================

    // Use global copyToClipboard from simulation.js

    // ===========================================
    // Auto Refresh
    // ===========================================

    function startAutoRefresh() {
        stopAutoRefresh();
        refreshTimer = setInterval(() => {
            const page = document.getElementById('page-agents');
            if (page && page.style.display !== 'none') {
                loadAgentsPage();
            }
        }, AUTO_REFRESH_INTERVAL);
    }

    function stopAutoRefresh() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
            refreshTimer = null;
        }
    }

    // ===========================================
    // Keyboard handler
    // ===========================================

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeAgentDetailsModal();
    });

    // ===========================================
    // Export to global scope
    // ===========================================

    window.loadAgentsPage = loadAgentsPage;
    window.clearAgentFilters = clearAgentFilters;
    window.openAgentDetailsModal = openAgentDetailsModal;
    window.closeAgentDetailsModal = closeAgentDetailsModal;
    window.approveAgent = approveAgent;
    window.activateAgent = activateAgent;
    window.deactivateAgent = deactivateAgent;
    window.confirmDeleteAgent = confirmDeleteAgent;

    // Start auto-refresh
    startAutoRefresh();

})();
