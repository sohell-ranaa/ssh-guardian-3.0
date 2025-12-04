/**
 * Agent Details Module
 * Handles displaying detailed agent information in a modal
 */

// Open agent details modal
async function openAgentDetailsModal(agentId) {
    const modal = document.getElementById('agent-details-modal');
    const content = document.getElementById('agent-details-content');

    // Show modal with loading state
    modal.style.display = 'flex';
    content.innerHTML = '<div class="loading-message">Loading agent details...</div>';

    try {
        const response = await fetch(`/api/agents/${agentId}`);
        const data = await response.json();

        if (!data.success) {
            content.innerHTML = `
                <div class="modal-empty-state">
                    <div>⚠️ Failed to load agent details</div>
                    <div>${data.error || 'Unknown error'}</div>
                </div>
            `;
            return;
        }

        // Render agent details
        content.innerHTML = renderAgentDetails(data.agent, data.recent_heartbeats, data.recent_batches);

    } catch (error) {
        console.error('Error loading agent details:', error);
        content.innerHTML = `
            <div class="modal-empty-state">
                <div>❌ Connection Error</div>
                <div>Failed to load agent details. Please try again.</div>
            </div>
        `;
    }
}

// Close agent details modal
function closeAgentDetailsModal() {
    const modal = document.getElementById('agent-details-modal');
    modal.style.display = 'none';
}

// Render agent details
function renderAgentDetails(agent, heartbeats, batches) {
    const systemInfo = agent.system_info ? JSON.parse(agent.system_info) : null;

    return `
        <!-- Basic Information -->
        <div class="detail-section">
            <div class="detail-section-title">Basic Information</div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-item-label">Hostname</div>
                    <div class="detail-item-value">${escapeHtml(agent.hostname)}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Display Name</div>
                    <div class="detail-item-value">${escapeHtml(agent.display_name || 'N/A')}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Agent ID</div>
                    <div class="detail-item-value"><code>${escapeHtml(agent.agent_id)}</code></div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Agent UUID</div>
                    <div class="detail-item-value"><code>${escapeHtml(agent.agent_uuid)}</code></div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">IP Address</div>
                    <div class="detail-item-value">${escapeHtml(agent.ip_address_primary || 'N/A')}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Version</div>
                    <div class="detail-item-value">${escapeHtml(agent.version || 'N/A')}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Environment</div>
                    <div class="detail-item-value">${escapeHtml(agent.environment || 'N/A')}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Agent Type</div>
                    <div class="detail-item-value">${escapeHtml(agent.agent_type || 'N/A')}</div>
                </div>
            </div>
        </div>

        <!-- Status Information -->
        <div class="detail-section">
            <div class="detail-section-title">Status</div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-item-label">Status</div>
                    <div class="detail-item-value">
                        <span class="status-badge ${agent.status === 'online' ? 'success' : 'error'}">
                            ${escapeHtml(agent.status || 'unknown').toUpperCase()}
                        </span>
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Health Status</div>
                    <div class="detail-item-value">
                        <span class="status-badge ${
                            agent.health_status === 'healthy' ? 'success' :
                            agent.health_status === 'degraded' ? 'warning' : 'error'
                        }">
                            ${escapeHtml(agent.health_status || 'unknown').toUpperCase()}
                        </span>
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Approval Status</div>
                    <div class="detail-item-value">${agent.is_approved ? '✅ Approved' : '⏳ Pending'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Active Status</div>
                    <div class="detail-item-value">${agent.is_active ? '✅ Active' : '❌ Inactive'}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Last Heartbeat</div>
                    <div class="detail-item-value">
                        ${agent.last_heartbeat ? formatLocalDateTime(agent.last_heartbeat) : 'Never'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Missed Heartbeats</div>
                    <div class="detail-item-value">${agent.consecutive_missed_heartbeats || 0}</div>
                </div>
            </div>
        </div>

        <!-- Statistics -->
        <div class="detail-section">
            <div class="detail-section-title">Statistics</div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-item-label">Total Events Sent</div>
                    <div class="detail-item-value">${(agent.total_events_sent || 0).toLocaleString()}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Total Uptime</div>
                    <div class="detail-item-value">${formatUptime(agent.total_uptime_seconds || 0)}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Restart Count</div>
                    <div class="detail-item-value">${agent.restart_count || 0}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Heartbeat Interval</div>
                    <div class="detail-item-value">${agent.heartbeat_interval_sec || 60}s</div>
                </div>
            </div>
        </div>

        ${systemInfo ? renderSystemInfo(systemInfo) : ''}

        <!-- Recent Heartbeats -->
        <div class="detail-section">
            <div class="detail-section-title">Recent Heartbeats (Last 10)</div>
            ${renderHeartbeats(heartbeats)}
        </div>

        <!-- Recent Batches -->
        <div class="detail-section">
            <div class="detail-section-title">Recent Log Batches (Last 10)</div>
            ${renderBatches(batches)}
        </div>

        <!-- Timestamps -->
        <div class="detail-section">
            <div class="detail-section-title">Timestamps</div>
            <div class="detail-grid">
                <div class="detail-item">
                    <div class="detail-item-label">Created At</div>
                    <div class="detail-item-value">
                        ${agent.created_at ? formatLocalDateTime(agent.created_at) : 'N/A'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Updated At</div>
                    <div class="detail-item-value">
                        ${agent.updated_at ? formatLocalDateTime(agent.updated_at) : 'N/A'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Approved At</div>
                    <div class="detail-item-value">
                        ${agent.approved_at ? formatLocalDateTime(agent.approved_at) : 'N/A'}
                    </div>
                </div>
                <div class="detail-item">
                    <div class="detail-item-label">Last Restart</div>
                    <div class="detail-item-value">
                        ${agent.last_restart_at ? formatLocalDateTime(agent.last_restart_at) : 'N/A'}
                    </div>
                </div>
            </div>
        </div>
    `;
}

// Render system info section
function renderSystemInfo(systemInfo) {
    return `
        <div class="detail-section">
            <div class="detail-section-title">System Information</div>
            <div class="detail-grid">
                ${systemInfo.os ? `
                    <div class="detail-item">
                        <div class="detail-item-label">Operating System</div>
                        <div class="detail-item-value">${escapeHtml(systemInfo.os)}</div>
                    </div>
                ` : ''}
                ${systemInfo.kernel ? `
                    <div class="detail-item">
                        <div class="detail-item-label">Kernel</div>
                        <div class="detail-item-value">${escapeHtml(systemInfo.kernel)}</div>
                    </div>
                ` : ''}
                ${systemInfo.cpu_count ? `
                    <div class="detail-item">
                        <div class="detail-item-label">CPU Count</div>
                        <div class="detail-item-value">${systemInfo.cpu_count}</div>
                    </div>
                ` : ''}
                ${systemInfo.total_memory ? `
                    <div class="detail-item">
                        <div class="detail-item-label">Total Memory</div>
                        <div class="detail-item-value">${systemInfo.total_memory}</div>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

// Render heartbeats table
function renderHeartbeats(heartbeats) {
    if (!heartbeats || heartbeats.length === 0) {
        return '<div class="modal-empty-state">No recent heartbeats</div>';
    }

    return `
        <table class="heartbeat-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Health Status</th>
                    <th>CPU %</th>
                    <th>Memory %</th>
                    <th>Disk %</th>
                </tr>
            </thead>
            <tbody>
                ${heartbeats.slice(0, 10).map(hb => `
                    <tr>
                        <td>${formatLocalDateTime(hb.heartbeat_timestamp || hb.timestamp)}</td>
                        <td>
                            <span class="status-badge ${
                                hb.health_status === 'healthy' ? 'success' :
                                hb.health_status === 'degraded' ? 'warning' : 'error'
                            }">
                                ${escapeHtml(hb.health_status || 'unknown').toUpperCase()}
                            </span>
                        </td>
                        <td>${hb.cpu_usage_percent ? hb.cpu_usage_percent.toFixed(1) : 'N/A'}</td>
                        <td>${hb.memory_usage_percent ? hb.memory_usage_percent.toFixed(1) : 'N/A'}</td>
                        <td>${hb.disk_usage_percent ? hb.disk_usage_percent.toFixed(1) : 'N/A'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Render batches table
function renderBatches(batches) {
    if (!batches || batches.length === 0) {
        return '<div class="modal-empty-state">No recent log batches</div>';
    }

    return `
        <table class="batch-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Batch Size</th>
                    <th>Created</th>
                    <th>Failed</th>
                    <th>Status</th>
                    <th>Duration (ms)</th>
                </tr>
            </thead>
            <tbody>
                ${batches.slice(0, 10).map(batch => `
                    <tr>
                        <td>${formatLocalDateTime(batch.received_at)}</td>
                        <td>${batch.batch_size}</td>
                        <td>${batch.events_created}</td>
                        <td>${batch.events_failed || 0}</td>
                        <td>
                            <span class="status-badge ${
                                batch.processing_status === 'completed' ? 'success' :
                                batch.processing_status === 'processing' ? 'warning' : 'error'
                            }">
                                ${escapeHtml(batch.processing_status || 'unknown').toUpperCase()}
                            </span>
                        </td>
                        <td>${batch.processing_duration_ms || 'N/A'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// Format uptime seconds to human readable
function formatUptime(seconds) {
    if (seconds === 0) return '0 seconds';

    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);

    return parts.join(' ') || '< 1m';
}

// HTML escape function (reuse from agents_page.js if available)
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeAgentDetailsModal();
    }
});
