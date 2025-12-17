/**
 * Blocked IPs Page Module
 * Handles IP blocks management, manual block/unblock operations
 */

// Load Blocked IPs page data
async function loadBlockedIPsPage() {
    // Load agents list for dropdown first
    await loadAgentsForBlockFilter();
    await loadIPBlocks();
    setupBlockFilters();
    setupManualBlockForm();
    setupManualUnblockForm();
    setupFormToggles();
    setupRefreshButton();
}

// Load agents for the agent filter dropdown (agent-based blocking)
async function loadAgentsForBlockFilter() {
    try {
        const response = await fetch('/api/agents/list');
        const data = await response.json();

        if (!data.agents) return;

        const agentFilter = document.getElementById('blockAgentFilter');
        if (!agentFilter) return;

        // Clear existing options except "All Agents"
        agentFilter.innerHTML = '<option value="">All Agents (Global)</option>';

        // Add agents
        (data.agents || []).forEach(agent => {
            const option = document.createElement('option');
            option.value = agent.id;
            option.textContent = agent.display_name || agent.hostname || `Agent ${agent.id}`;
            agentFilter.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading agents for filter:', error);
    }
}

// Current agent filter for agent-based blocking
let currentAgentFilter = '';

// Load all IP blocks
async function loadIPBlocks() {
    const loadingEl = document.getElementById('blocksLoading');
    const tableEl = document.getElementById('blocksTable');
    const errorEl = document.getElementById('blocksError');

    try {
        // Show loading
        loadingEl.style.display = 'block';
        tableEl.style.display = 'none';
        errorEl.style.display = 'none';

        // Build API URL with agent filter if set
        let apiUrl = '/api/dashboard/blocking/blocks/list';
        if (currentAgentFilter) {
            apiUrl += `?agent_id=${encodeURIComponent(currentAgentFilter)}`;
        }

        // Use fetchWithCache if available to track cache status
        let data;
        if (typeof fetchWithCache === 'function') {
            data = await fetchWithCache(apiUrl, 'blocking');
        } else {
            const response = await fetch(apiUrl);
            data = await response.json();
        }

        if (!data.success || !data.blocks || data.blocks.length === 0) {
            loadingEl.style.display = 'none';
            tableEl.innerHTML = '<div class="empty-state-small">No IP blocks found</div>';
            tableEl.style.display = 'block';
            return;
        }

        // Build table
        const tableBody = document.getElementById('blocksTableBody');

        // Collect unique agents for filter dropdown
        const uniqueAgents = new Set();
        data.blocks.forEach(block => {
            const agentName = block.agent_name || 'Manual Block';
            uniqueAgents.add(agentName);
        });

        tableBody.innerHTML = data.blocks.map(block => {
            const statusBadge = block.is_active
                ? '<span style="padding: 4px 12px; background: #D13438; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Active</span>'
                : '<span style="padding: 4px 12px; background: #10b981; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Expired</span>';

            const sourceBadge = getSourceBadge(block.source);

            const expiresAt = block.unblock_at
                ? formatLocalDateTime(block.unblock_at)
                : 'Permanent';

            // Use ip_address field from API
            const ipAddress = block.ip_address;

            // Agent name from API (already includes fallback to 'Manual Block')
            const agentName = escapeHtml(block.agent_name || 'Manual Block');

            // Location from API response
            const locationText = block.location && block.location.country
                ? `${block.location.city || 'Unknown'}, ${block.location.country}`
                : '';

            // Action buttons based on status
            let actionButtons = '';
            if (block.is_active) {
                actionButtons = `
                    <button
                        onclick="unblockIPFromTable('${escapeHtml(ipAddress)}', ${block.id})"
                        style="padding: 6px 12px; background: #107C10; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 12px;"
                        title="Unblock IP"
                    >
                        Unblock
                    </button>`;
            } else {
                actionButtons = `
                    <button
                        onclick="reblockIPFromTable('${escapeHtml(ipAddress)}')"
                        style="padding: 6px 12px; border: 1px solid #D13438; background: var(--surface); color: #D13438; border-radius: 3px; cursor: pointer; font-size: 12px;"
                        title="Block IP again"
                    >
                        Block Again
                    </button>`;
            }

            return `
                <tr style="border-bottom: 1px solid var(--border-light);" data-ip="${escapeHtml(ipAddress)}" data-agent="${agentName}" data-source="${escapeHtml(block.source)}" data-is-active="${block.is_active}">
                    <td style="padding: 10px; font-family: monospace; font-weight: 600; font-size: 13px;">
                        ${escapeHtml(ipAddress)}
                    </td>
                    <td style="padding: 10px; font-size: 13px;">
                        ${agentName}
                    </td>
                    <td style="padding: 10px; text-align: center; font-size: 13px;" class="ip-attempts-cell" data-ip="${escapeHtml(ipAddress)}">
                        ${block.failed_attempts && block.failed_attempts > 0 ? `<span style="font-weight: 600; color: #D13438;">${block.failed_attempts}</span>` : '<span style="color: var(--text-secondary);">-</span>'}
                    </td>
                    <td style="padding: 10px; font-size: 13px;" class="ip-location-cell" data-ip="${escapeHtml(ipAddress)}">
                        ${locationText ? escapeHtml(locationText) : '<span style="color: var(--text-secondary);">...</span>'}
                    </td>
                    <td style="padding: 10px; font-size: 13px; max-width: 250px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(block.reason || 'No reason specified')}">
                        ${escapeHtml(block.reason || 'No reason specified')}
                    </td>
                    <td style="padding: 10px;">${sourceBadge}</td>
                    <td style="padding: 10px; font-size: 13px; white-space: nowrap;">
                        ${formatLocalDateTime(block.blocked_at)}
                    </td>
                    <td style="padding: 10px; font-size: 13px; white-space: nowrap;">
                        ${expiresAt}
                    </td>
                    <td style="padding: 10px; text-align: center;">${statusBadge}</td>
                    <td style="padding: 10px; text-align: center; white-space: nowrap;">
                        ${actionButtons}
                    </td>
                </tr>
            `;
        }).join('');

        // Populate agent filter dropdown
        populateAgentFilter(uniqueAgents);

        // Enrich location data asynchronously
        enrichBlocksLocationData();

        // Show table
        loadingEl.style.display = 'none';
        tableEl.style.display = 'block';

        // Update stats
        updateBlockStats(data.blocks);

    } catch (error) {
        console.error('Error loading IP blocks:', error);
        loadingEl.style.display = 'none';
        errorEl.style.display = 'block';
    }
}

// Get badge for block source
function getSourceBadge(source) {
    const badges = {
        'manual': '<span style="padding: 4px 8px; background: #0078D4; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">MANUAL</span>',
        'rule_based': '<span style="padding: 4px 8px; background: #8764B8; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">RULE</span>',
        'ml_threshold': '<span style="padding: 4px 8px; background: #CA5010; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">ML</span>',
        'api_reputation': '<span style="padding: 4px 8px; background: #D13438; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">API</span>',
        'anomaly_detection': '<span style="padding: 4px 8px; background: #FFB900; color: #323130; border-radius: 3px; font-size: 11px; font-weight: 600;">ANOMALY</span>'
    };
    return badges[source] || '<span style="padding: 4px 8px; background: #8A8886; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">UNKNOWN</span>';
}

// Update block statistics
function updateBlockStats(blocks) {
    const activeBlocks = blocks.filter(b => b.is_active).length;
    const totalBlocks = blocks.length;
    const ruleBlocks = blocks.filter(b => b.source === 'rule_based').length;
    const manualBlocks = blocks.filter(b => b.source === 'manual').length;
    const expiredBlocks = blocks.filter(b => !b.is_active).length;

    // Update stat cards
    const statActiveEl = document.getElementById('stat-active-blocks');
    const statTotalEl = document.getElementById('stat-total-blocks');
    const statRuleEl = document.getElementById('stat-rule-blocks');
    const statManualEl = document.getElementById('stat-manual-blocks');
    const statExpiredEl = document.getElementById('stat-expired-blocks');

    if (statActiveEl) statActiveEl.textContent = activeBlocks.toLocaleString();
    if (statTotalEl) statTotalEl.textContent = totalBlocks.toLocaleString();
    if (statRuleEl) statRuleEl.textContent = ruleBlocks.toLocaleString();
    if (statManualEl) statManualEl.textContent = manualBlocks.toLocaleString();
    if (statExpiredEl) statExpiredEl.textContent = expiredBlocks.toLocaleString();
}

// Setup form toggle buttons
function setupFormToggles() {
    const showBlockFormBtn = document.getElementById('showManualBlockForm');
    const showUnblockFormBtn = document.getElementById('showManualUnblockForm');
    const cancelBlockFormBtn = document.getElementById('cancelBlockForm');
    const cancelUnblockFormBtn = document.getElementById('cancelUnblockForm');

    const blockForm = document.getElementById('manualBlockForm');
    const unblockForm = document.getElementById('manualUnblockForm');

    if (showBlockFormBtn && blockForm) {
        showBlockFormBtn.onclick = () => {
            blockForm.style.display = 'block';
            if (unblockForm) unblockForm.style.display = 'none';
        };
    }

    if (showUnblockFormBtn && unblockForm) {
        showUnblockFormBtn.onclick = () => {
            unblockForm.style.display = 'block';
            if (blockForm) blockForm.style.display = 'none';
        };
    }

    if (cancelBlockFormBtn && blockForm) {
        cancelBlockFormBtn.onclick = () => {
            blockForm.style.display = 'none';
        };
    }

    if (cancelUnblockFormBtn && unblockForm) {
        cancelUnblockFormBtn.onclick = () => {
            unblockForm.style.display = 'none';
        };
    }
}

// Setup refresh button
function setupRefreshButton() {
    const refreshBtn = document.getElementById('refreshBlocks');
    if (refreshBtn) {
        refreshBtn.onclick = () => loadIPBlocks();
    }
}

// Setup manual block form
function setupManualBlockForm() {
    const form = document.getElementById('manualBlockForm');
    if (!form) return;

    const submitBtn = document.getElementById('submitBlockIp');
    if (submitBtn) {
        submitBtn.onclick = async (e) => {
            e.preventDefault();

            const ipAddress = document.getElementById('blockIpAddress').value.trim();
            const reason = document.getElementById('blockReason').value.trim();
            const duration = parseInt(document.getElementById('blockDuration').value);

            if (!ipAddress) {
                showBlockNotification('Please enter an IP address', 'error');
                return;
            }

            if (!reason) {
                showBlockNotification('Please enter a reason', 'error');
                return;
            }

            try {
                const response = await fetch('/api/dashboard/blocking/blocks/manual', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        reason: reason,
                        duration_minutes: duration
                    })
                });

                const data = await response.json();

                if (data.success) {
                    showBlockNotification(`IP ${ipAddress} blocked successfully`, 'success');
                    // Clear form
                    document.getElementById('blockIpAddress').value = '';
                    document.getElementById('blockReason').value = '';
                    document.getElementById('blockDuration').value = '1440';
                    // Hide form
                    form.style.display = 'none';
                    // Reload blocks
                    setTimeout(() => loadIPBlocks(), 1000);
                } else {
                    showBlockNotification(`Failed to block IP: ${data.error || 'Unknown error'}`, 'error');
                }
            } catch (error) {
                console.error('Error blocking IP:', error);
                showBlockNotification('Error blocking IP', 'error');
            }
        };
    }
}

// Setup manual unblock form
function setupManualUnblockForm() {
    const form = document.getElementById('manualUnblockForm');
    if (!form) return;

    const submitBtn = document.getElementById('submitUnblockIp');
    if (submitBtn) {
        submitBtn.onclick = async (e) => {
            e.preventDefault();

            const ipAddress = document.getElementById('unblockIpAddress').value.trim();
            const reason = document.getElementById('unblockReason').value.trim();

            if (!ipAddress) {
                showBlockNotification('Please enter an IP address', 'error');
                return;
            }

            const success = await unblockIPAddress(ipAddress, reason);
            if (success && form) {
                form.style.display = 'none';
            }
        };
    }
}

// Unblock IP from table row
async function unblockIPFromTable(ipAddress, blockId) {
    if (!confirm(`Are you sure you want to unblock IP: ${ipAddress}?`)) {
        return;
    }

    await unblockIPAddress(ipAddress, 'Unblocked from dashboard');
}

// Re-block IP from table row (for previously unblocked IPs)
async function reblockIPFromTable(ipAddress) {
    if (!confirm(`Are you sure you want to block IP: ${ipAddress} again?`)) {
        return;
    }

    try {
        const response = await fetch('/api/dashboard/blocking/blocks/manual', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip_address: ipAddress,
                reason: 'Re-blocked from IP Blocks page',
                duration_minutes: 1440
            })
        });

        const data = await response.json();

        if (data.success) {
            showBlockNotification(`IP ${ipAddress} blocked successfully`, 'success');
            // Reload blocks
            setTimeout(() => loadIPBlocks(), 1000);
        } else {
            showBlockNotification(`Failed to block IP: ${data.message || data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error blocking IP:', error);
        showBlockNotification('Error blocking IP', 'error');
    }
}

// Unblock IP address
async function unblockIPAddress(ipAddress, reason) {
    try {
        const response = await fetch('/api/dashboard/blocking/blocks/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip_address: ipAddress,
                reason: reason || 'Manually unblocked from dashboard'
            })
        });

        const data = await response.json();

        if (data.success) {
            showBlockNotification(`IP ${ipAddress} unblocked successfully`, 'success');
            // Clear unblock form if it exists
            const unblockForm = document.getElementById('unblockIpAddress');
            if (unblockForm) {
                unblockForm.value = '';
                const reasonField = document.getElementById('unblockReason');
                if (reasonField) reasonField.value = '';
            }
            // Reload blocks
            setTimeout(() => loadIPBlocks(), 1000);
            return true;
        } else {
            showBlockNotification(`Failed to unblock IP: ${data.error || 'Unknown error'}`, 'error');
            return false;
        }
    } catch (error) {
        console.error('Error unblocking IP:', error);
        showBlockNotification('Error unblocking IP', 'error');
        return false;
    }
}

// Populate agent filter dropdown
function populateAgentFilter(uniqueAgents) {
    const agentFilter = document.getElementById('blockAgentFilter');
    if (!agentFilter) return;

    // Keep current selection
    const currentValue = agentFilter.value;

    // Clear and rebuild options
    agentFilter.innerHTML = '<option value="">All Agents</option>';

    // Sort agents alphabetically
    const sortedAgents = Array.from(uniqueAgents).sort();

    sortedAgents.forEach(agent => {
        const option = document.createElement('option');
        option.value = agent;
        option.textContent = agent;
        agentFilter.appendChild(option);
    });

    // Restore selection if it still exists
    if (currentValue && sortedAgents.includes(currentValue)) {
        agentFilter.value = currentValue;
    }
}

// Setup filter functionality
function setupBlockFilters() {
    const agentFilter = document.getElementById('blockAgentFilter');
    const sourceFilter = document.getElementById('blockSourceFilter');
    const statusFilter = document.getElementById('blockStatusFilter');

    // Agent filter triggers server-side reload (agent-based blocking)
    if (agentFilter) {
        agentFilter.onchange = async () => {
            currentAgentFilter = agentFilter.value;
            // Reload data from server with new agent filter
            await loadIPBlocks();
        };
    }

    // Source and status filters are client-side only
    if (sourceFilter) {
        sourceFilter.onchange = applyBlockFilters;
    }

    if (statusFilter) {
        statusFilter.onchange = applyBlockFilters;
    }
}

// Apply filters to block table (client-side filtering for source and status)
function applyBlockFilters() {
    const sourceFilter = document.getElementById('blockSourceFilter')?.value || '';
    const statusFilter = document.getElementById('blockStatusFilter')?.value || '';

    const rows = document.querySelectorAll('#blocksTableBody tr');

    rows.forEach(row => {
        let showRow = true;

        // Get source from data attribute
        const rowSource = row.getAttribute('data-source') || '';

        // Get status from data attribute
        const isActive = row.getAttribute('data-is-active') === 'true';

        // Apply source filter
        if (sourceFilter && rowSource !== sourceFilter) {
            showRow = false;
        }

        // Apply status filter (values are "true" or "false" as strings)
        if (statusFilter) {
            if (statusFilter === 'true' && !isActive) {
                showRow = false;
            } else if (statusFilter === 'false' && isActive) {
                showRow = false;
            }
        }

        row.style.display = showRow ? '' : 'none';
    });
}

// Show notification
function showBlockNotification(message, type = 'info') {
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
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add animation styles if not already present
if (!document.getElementById('block-notification-styles')) {
    const style = document.createElement('style');
    style.id = 'block-notification-styles';
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(400px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}

// Enrich location data for blocked IPs using FreeIPAPI
async function enrichBlocksLocationData() {
    const locationCells = document.querySelectorAll('.ip-location-cell');
    if (locationCells.length === 0) return;

    // Get unique IPs
    const uniqueIps = new Set();
    locationCells.forEach(cell => {
        const ip = cell.getAttribute('data-ip');
        if (ip) uniqueIps.add(ip);
    });

    // Fetch info for each IP (limit concurrent requests)
    for (const ip of uniqueIps) {
        try {
            const response = await fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ip)}`);
            const data = await response.json();

            // Update all cells for this IP
            const cells = document.querySelectorAll(`.ip-location-cell[data-ip="${ip}"]`);
            cells.forEach(cell => {
                if (data.success) {
                    const flagImg = data.country_code && data.country_code !== 'N/A'
                        ? `<img src="https://flagcdn.com/20x15/${data.country_code.toLowerCase()}.png" alt="${data.country_code}" style="vertical-align: middle; margin-right: 6px;">`
                        : '';
                    const locationText = data.is_private
                        ? 'Private Network'
                        : `${data.city || 'Unknown'}, ${data.country || 'Unknown'}`;
                    cell.innerHTML = `${flagImg}<span>${escapeHtml(locationText)}</span>`;
                } else {
                    cell.innerHTML = '<span style="color: var(--text-secondary);">Unknown</span>';
                }
            });
        } catch (error) {
            console.error(`Error fetching location for ${ip}:`, error);
            const cells = document.querySelectorAll(`.ip-location-cell[data-ip="${ip}"]`);
            cells.forEach(cell => {
                cell.innerHTML = '<span style="color: var(--text-secondary);">Error</span>';
            });
        }
    }
}

// Show IP Details Modal (self-contained version)
async function showBlockIpDetails(ipAddress) {
    if (!ipAddress) {
        showBlockNotification('No IP address provided', 'error');
        return;
    }

    // Show loading modal
    showBlockModal('Loading...', `
        <div style="text-align: center; padding: 40px;">
            <div style="font-size: 24px; margin-bottom: 16px;">⏳</div>
            <p>Loading details for ${escapeHtml(ipAddress)}...</p>
        </div>
    `);

    try {
        // Fetch IP status and geolocation info in parallel
        const [statusResponse, geoResponse] = await Promise.all([
            fetch(`/api/dashboard/event-actions/ip-status/${encodeURIComponent(ipAddress)}`),
            fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ipAddress)}`)
        ]);

        const status = await statusResponse.json();
        const geoInfo = await geoResponse.json();

        // Build status badges
        const statusBadges = [];
        if (status && status.is_blocked) {
            statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #D83B01; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Blocked</span>');
        }
        if (status && status.is_whitelisted) {
            statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #107C10; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Whitelisted</span>');
        }
        if (status && status.is_watched) {
            statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #FFB900; color: #323130; border-radius: 3px; font-size: 11px; margin-right: 5px;">Watched</span>');
        }
        if (geoInfo && geoInfo.is_proxy) {
            statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #8764B8; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Proxy/VPN</span>');
        }
        if (statusBadges.length === 0) {
            statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #605E5C; color: white; border-radius: 3px; font-size: 11px;">No Special Status</span>');
        }

        // Build geolocation section
        let geoSection = '';
        if (geoInfo && geoInfo.success) {
            const flagImg = geoInfo.country_code && geoInfo.country_code !== 'N/A'
                ? `<img src="https://flagcdn.com/24x18/${geoInfo.country_code.toLowerCase()}.png" alt="${geoInfo.country_code}" style="vertical-align: middle; margin-right: 6px;">`
                : '';

            geoSection = `
                <div class="ip-detail-section">
                    <div class="ip-detail-section-title">Geolocation</div>
                    <div class="ip-detail-grid">
                        <div>
                            <div class="ip-detail-item-label">Country</div>
                            <div class="ip-detail-item-value">${flagImg}${escapeHtml(geoInfo.country || 'Unknown')} (${escapeHtml(geoInfo.country_code || 'N/A')})</div>
                        </div>
                        <div>
                            <div class="ip-detail-item-label">City</div>
                            <div class="ip-detail-item-value">${escapeHtml(geoInfo.city || 'Unknown')}</div>
                        </div>
                        <div>
                            <div class="ip-detail-item-label">Region</div>
                            <div class="ip-detail-item-value">${escapeHtml(geoInfo.region || 'Unknown')}</div>
                        </div>
                        <div>
                            <div class="ip-detail-item-label">Timezone</div>
                            <div class="ip-detail-item-value">${escapeHtml(geoInfo.timezone || 'N/A')}</div>
                        </div>
                    </div>
                </div>
                <div class="ip-detail-section">
                    <div class="ip-detail-section-title">Network</div>
                    <div class="ip-detail-grid">
                        <div>
                            <div class="ip-detail-item-label">ISP / Organization</div>
                            <div class="ip-detail-item-value">${escapeHtml(geoInfo.isp || 'Unknown')}</div>
                        </div>
                        <div>
                            <div class="ip-detail-item-label">ASN</div>
                            <div class="ip-detail-item-value">AS${escapeHtml(geoInfo.asn || 'N/A')}</div>
                        </div>
                        <div>
                            <div class="ip-detail-item-label">Coordinates</div>
                            <div class="ip-detail-item-value">${geoInfo.latitude || 0}, ${geoInfo.longitude || 0}</div>
                        </div>
                        <div>
                            <div class="ip-detail-item-label">Continent</div>
                            <div class="ip-detail-item-value">${escapeHtml(geoInfo.continent || 'Unknown')}</div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            geoSection = `
                <div class="ip-detail-section">
                    <div style="text-align: center; color: var(--text-secondary); padding: 12px;">
                        Geolocation info unavailable
                    </div>
                </div>
            `;
        }

        const content = `
            <div style="display: grid; gap: 20px;">
                <div>
                    <div class="ip-detail-item-label">IP Address</div>
                    <div style="font-family: 'SF Mono', 'Consolas', monospace; font-size: 22px; font-weight: 600; color: var(--text-primary);">${escapeHtml(ipAddress)}</div>
                </div>
                <div>
                    <div class="ip-detail-item-label" style="margin-bottom: 8px;">Status</div>
                    <div>${statusBadges.join('')}</div>
                </div>
                <div class="ip-detail-grid">
                    <div class="ip-stat-box">
                        <div class="ip-stat-value" style="color: #0078D4;">${status?.notes_count || 0}</div>
                        <div class="ip-stat-label">Notes</div>
                    </div>
                    <div class="ip-stat-box">
                        <div class="ip-stat-value" style="color: #F7630C;">${status?.reports_count || 0}</div>
                        <div class="ip-stat-label">Reports</div>
                    </div>
                </div>
                ${geoSection}
            </div>
        `;

        showBlockModal(`IP Details: ${ipAddress}`, content, { icon: '<span style="font-size: 20px; margin-right: 6px;">🌐</span>' });

    } catch (error) {
        console.error('Error loading IP details:', error);
        showBlockModal('Error', `
            <div style="text-align: center; padding: 20px; color: #D13438;">
                <div style="font-size: 24px; margin-bottom: 12px;">❌</div>
                <p>Error loading IP details</p>
            </div>
        `);
    }
}

// Inject modal styles if not present
function injectBlockModalStyles() {
    if (document.getElementById('block-modal-styles')) return;

    const style = document.createElement('style');
    style.id = 'block-modal-styles';
    style.textContent = `
        .block-modal-overlay {
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
            animation: blockModalFadeIn 0.2s ease-out;
            box-sizing: border-box;
        }

        @keyframes blockModalFadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes blockModalSlideIn {
            from {
                opacity: 0;
                transform: translateY(-20px) scale(0.98);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        .block-modal {
            background: var(--card-bg, #ffffff);
            border-radius: 8px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(0, 0, 0, 0.05);
            max-width: 520px;
            width: 100%;
            animation: blockModalSlideIn 0.25s ease-out;
            margin: 0 auto 40px auto;
            flex-shrink: 0;
        }

        .block-modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border, #e0e0e0);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface, #fafafa);
            border-radius: 8px 8px 0 0;
        }

        .block-modal-title {
            font-size: 17px;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary, #323130);
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .block-modal-close {
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

        .block-modal-close:hover {
            background: var(--hover-bg, #f0f0f0);
            color: var(--text-primary, #323130);
        }

        .block-modal-body {
            padding: 24px;
        }

        .block-modal-footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border, #e0e0e0);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            background: var(--surface, #fafafa);
            border-radius: 0 0 8px 8px;
        }

        .block-modal-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.15s ease;
        }

        .block-modal-btn-primary {
            background: var(--azure-blue, #0078D4);
            color: white;
        }

        .block-modal-btn-primary:hover {
            background: #106EBE;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(0, 120, 212, 0.3);
        }

        .block-modal-btn-secondary {
            background: var(--surface, #f0f0f0);
            color: var(--text-primary, #323130);
            border: 1px solid var(--border, #e0e0e0);
        }

        .block-modal-btn-secondary:hover {
            background: var(--hover-bg, #e8e8e8);
        }

        .block-modal-btn-danger {
            background: #D13438;
            color: white;
        }

        .block-modal-btn-danger:hover:not(:disabled) {
            background: #C42B30;
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(209, 52, 56, 0.3);
        }

        .block-modal-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        /* IP Details specific styles */
        .ip-detail-section {
            border-top: 1px solid var(--border, #e0e0e0);
            padding-top: 16px;
            margin-top: 16px;
        }

        .ip-detail-section-title {
            font-size: 11px;
            color: var(--text-secondary, #605E5C);
            margin-bottom: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }

        .ip-detail-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 14px;
        }

        .ip-detail-item-label {
            font-size: 11px;
            color: var(--text-secondary, #605E5C);
            margin-bottom: 2px;
        }

        .ip-detail-item-value {
            font-size: 13px;
            font-weight: 500;
            color: var(--text-primary, #323130);
        }

        .ip-stat-box {
            background: var(--hover-bg, #f5f5f5);
            padding: 14px;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.15s ease;
        }

        .ip-stat-box:hover {
            transform: translateY(-2px);
        }

        .ip-stat-value {
            font-size: 28px;
            font-weight: 700;
        }

        .ip-stat-label {
            font-size: 12px;
            color: var(--text-secondary, #605E5C);
            margin-top: 2px;
        }

        /* Delete confirmation specific */
        .delete-confirm-input {
            width: 100%;
            padding: 12px 14px;
            border: 2px solid var(--border, #e0e0e0);
            border-radius: 6px;
            font-size: 15px;
            font-family: 'SF Mono', 'Consolas', monospace;
            transition: all 0.2s ease;
        }

        .delete-confirm-input:focus {
            outline: none;
            border-color: var(--azure-blue, #0078D4);
            box-shadow: 0 0 0 3px rgba(0, 120, 212, 0.1);
        }

        .delete-confirm-input.error {
            border-color: #D13438;
            box-shadow: 0 0 0 3px rgba(209, 52, 56, 0.1);
        }

        .delete-confirm-input.success {
            border-color: #107C10;
            box-shadow: 0 0 0 3px rgba(16, 124, 16, 0.1);
        }

        @media (max-width: 600px) {
            .block-modal-overlay {
                padding: 20px 10px;
            }
            .ip-detail-grid {
                grid-template-columns: 1fr;
            }
        }
    `;
    document.head.appendChild(style);
}

// Show Block Modal (improved design)
function showBlockModal(title, content, options = {}) {
    injectBlockModalStyles();

    // Remove existing modals
    document.querySelectorAll('.block-modal-overlay').forEach(el => el.remove());

    const overlay = document.createElement('div');
    overlay.className = 'block-modal-overlay';

    const modal = document.createElement('div');
    modal.className = 'block-modal';

    const titleIcon = options.icon || '';

    modal.innerHTML = `
        <div class="block-modal-header">
            <h3 class="block-modal-title">${titleIcon}${escapeHtml(title)}</h3>
            <button class="block-modal-close" title="Close">&times;</button>
        </div>
        <div class="block-modal-body">${content}</div>
        <div class="block-modal-footer">
            <button class="block-modal-btn block-modal-btn-primary modal-close-action">Close</button>
        </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Prevent body scroll
    document.body.style.overflow = 'hidden';

    const closeModal = () => {
        overlay.style.animation = 'blockModalFadeIn 0.15s ease-out reverse';
        modal.style.animation = 'blockModalSlideIn 0.15s ease-out reverse';
        setTimeout(() => {
            overlay.remove();
            document.body.style.overflow = '';
        }, 140);
    };

    // Close handlers
    modal.querySelector('.block-modal-close').onclick = closeModal;
    modal.querySelector('.modal-close-action').onclick = closeModal;
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

    return { overlay, modal, closeModal };
}

// Disable block (unblock but keep record)
async function disableBlockFromTable(ipAddress, blockId) {
    if (!confirm(`Disable block for IP: ${ipAddress}?\n\nThis will unblock the IP but keep the record for reference.`)) {
        return;
    }

    await unblockIPAddress(ipAddress, 'Disabled from IP Blocks page');
}

// Confirm delete with type-to-confirm (improved design)
function confirmDeleteBlock(ipAddress, blockId) {
    injectBlockModalStyles();

    // Remove existing modals
    document.querySelectorAll('.block-modal-overlay').forEach(el => el.remove());

    const overlay = document.createElement('div');
    overlay.className = 'block-modal-overlay';

    const modal = document.createElement('div');
    modal.className = 'block-modal';

    modal.innerHTML = `
        <div class="block-modal-header" style="background: linear-gradient(135deg, #D13438 0%, #A4262C 100%);">
            <h3 class="block-modal-title" style="color: white;">
                <span style="font-size: 20px;">⚠️</span>
                Delete Block Record
            </h3>
            <button class="block-modal-close" style="color: rgba(255,255,255,0.8);" title="Close">&times;</button>
        </div>
        <div class="block-modal-body">
            <p style="margin: 0 0 16px 0; color: var(--text-primary); font-size: 14px; line-height: 1.5;">
                You are about to <strong>permanently delete</strong> the block record for:
            </p>
            <div style="background: linear-gradient(135deg, var(--hover-bg, #f5f5f5) 0%, var(--surface, #fafafa) 100%); padding: 16px; border-radius: 8px; font-family: 'SF Mono', 'Consolas', monospace; font-size: 18px; font-weight: 600; text-align: center; margin-bottom: 20px; border: 1px solid var(--border);">
                ${escapeHtml(ipAddress)}
            </div>
            <div style="background: rgba(209, 52, 56, 0.08); border: 1px solid rgba(209, 52, 56, 0.2); border-radius: 6px; padding: 12px 14px; margin-bottom: 20px;">
                <div style="display: flex; align-items: flex-start; gap: 10px;">
                    <span style="font-size: 16px;">🚫</span>
                    <p style="margin: 0; color: #A4262C; font-size: 13px; line-height: 1.5;">
                        This action <strong>cannot be undone</strong>. The IP will be unblocked and all associated block history will be permanently removed.
                    </p>
                </div>
            </div>
            <div>
                <label style="font-size: 13px; font-weight: 600; display: block; margin-bottom: 6px; color: var(--text-primary);">
                    Type the IP address to confirm deletion:
                </label>
                <input type="text" id="confirmDeleteInput" class="delete-confirm-input" placeholder="Enter ${ipAddress}" autocomplete="off">
            </div>
        </div>
        <div class="block-modal-footer">
            <button class="block-modal-btn block-modal-btn-secondary modal-cancel-btn">Cancel</button>
            <button id="confirmDeleteBtn" class="block-modal-btn block-modal-btn-danger" disabled>
                <span style="display: flex; align-items: center; gap: 6px;">
                    🗑️ Delete Permanently
                </span>
            </button>
        </div>
    `;

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    const confirmInput = modal.querySelector('#confirmDeleteInput');
    const confirmBtn = modal.querySelector('#confirmDeleteBtn');

    const closeModal = () => {
        overlay.style.animation = 'blockModalFadeIn 0.15s ease-out reverse';
        modal.style.animation = 'blockModalSlideIn 0.15s ease-out reverse';
        setTimeout(() => {
            overlay.remove();
            document.body.style.overflow = '';
        }, 140);
    };

    // Enable button only when IP matches
    confirmInput.oninput = () => {
        const matches = confirmInput.value.trim() === ipAddress;
        confirmBtn.disabled = !matches;
        confirmInput.classList.remove('error', 'success');
        if (confirmInput.value.trim()) {
            confirmInput.classList.add(matches ? 'success' : 'error');
        }
    };

    // Delete action
    confirmBtn.onclick = async () => {
        if (confirmInput.value.trim() !== ipAddress) return;

        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<span style="display: flex; align-items: center; gap: 6px;"><span class="loading-spinner-small"></span> Deleting...</span>';

        try {
            const response = await fetch(`/api/dashboard/blocking/blocks/${blockId}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                closeModal();
                showBlockNotification(`Block record for ${ipAddress} deleted successfully`, 'success');
                setTimeout(() => loadIPBlocks(), 500);
            } else {
                showBlockNotification(`Failed to delete: ${data.error || 'Unknown error'}`, 'error');
                confirmBtn.disabled = false;
                confirmBtn.innerHTML = '<span style="display: flex; align-items: center; gap: 6px;">🗑️ Delete Permanently</span>';
            }
        } catch (error) {
            console.error('Error deleting block:', error);
            showBlockNotification('Error deleting block record', 'error');
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '<span style="display: flex; align-items: center; gap: 6px;">🗑️ Delete Permanently</span>';
        }
    };

    // Close handlers
    modal.querySelector('.block-modal-close').onclick = closeModal;
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
