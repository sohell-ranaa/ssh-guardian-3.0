/**
 * Blocked IPs Page Module
 * Handles IP blocks management, manual block/unblock operations
 */

// Load Blocked IPs page data
async function loadBlockedIPsPage() {
    await loadIPBlocks();
    setupBlockFilters();
    setupManualBlockForm();
    setupManualUnblockForm();
    setupFormToggles();
    setupRefreshButton();
}

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

        // Use fetchWithCache if available to track cache status
        let data;
        if (typeof fetchWithCache === 'function') {
            data = await fetchWithCache('/api/dashboard/blocking/blocks/list', 'blocking');
        } else {
            const response = await fetch('/api/dashboard/blocking/blocks/list');
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
        tableBody.innerHTML = data.blocks.map(block => {
            const statusBadge = block.is_active
                ? '<span style="padding: 4px 12px; background: #D13438; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Active</span>'
                : '<span style="padding: 4px 12px; background: #107C10; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Unblocked</span>';

            const sourceBadge = getSourceBadge(block.source || block.block_source);

            const unblockTime = block.unblock_at
                ? formatLocalDateTime(block.unblock_at)
                : (block.auto_unblock ? 'Auto' : 'Manual');

            // Use ip_address field from API (not ip_address_text)
            const ipAddress = block.ip_address || block.ip_address_text;

            const actionButton = block.is_active
                ? `<button
                    onclick="unblockIPFromTable('${escapeHtml(ipAddress)}', ${block.id})"
                    style="padding: 6px 12px; border: 1px solid #107C10; background: var(--surface); color: #107C10; border-radius: 3px; cursor: pointer; font-size: 12px;"
                    title="Unblock IP"
                >
                    Unblock
                </button>`
                : `<button
                    onclick="reblockIPFromTable('${escapeHtml(ipAddress)}')"
                    style="padding: 6px 12px; border: 1px solid #D13438; background: var(--surface); color: #D13438; border-radius: 3px; cursor: pointer; font-size: 12px;"
                    title="Block IP again"
                >
                    Block Again
                </button>`;

            // View Details button
            const viewDetailsBtn = `<button
                onclick="if(typeof showIpDetails === 'function') showIpDetails('${escapeHtml(ipAddress)}')"
                style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); color: var(--text-primary); border-radius: 3px; cursor: pointer; font-size: 12px; margin-right: 8px;"
                title="View IP Details"
            >
                Details
            </button>`;

            return `
                <tr style="border-bottom: 1px solid var(--border-light);" data-ip="${escapeHtml(ipAddress)}">
                    <td style="padding: 12px; font-size: 13px; font-weight: 600; font-family: 'Courier New', monospace;">
                        ${escapeHtml(ipAddress)}
                    </td>
                    <td style="padding: 12px; font-size: 12px;" class="ip-location-cell" data-ip="${escapeHtml(ipAddress)}">
                        <span class="location-loading" style="color: var(--text-secondary);">Loading...</span>
                    </td>
                    <td style="padding: 12px; font-size: 12px;">
                        ${escapeHtml(block.reason || block.block_reason || 'No reason specified')}
                    </td>
                    <td style="padding: 12px;">${sourceBadge}</td>
                    <td style="padding: 12px; font-size: 12px;">
                        ${formatLocalDateTime(block.blocked_at)}
                    </td>
                    <td style="padding: 12px; font-size: 12px;">
                        ${unblockTime}
                    </td>
                    <td style="padding: 12px; text-align: center;">${statusBadge}</td>
                    <td style="padding: 12px; text-align: right;">
                        ${viewDetailsBtn}${actionButton}
                    </td>
                </tr>
            `;
        }).join('');

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

    const statsEl = document.getElementById('blockStatsContainer');
    if (statsEl) {
        statsEl.innerHTML = `
            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                <div style="padding: 12px 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Active Blocks</div>
                    <div style="font-size: 24px; font-weight: 700; color: #D13438; margin-top: 4px;">${activeBlocks}</div>
                </div>
                <div style="padding: 12px 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Total Blocks</div>
                    <div style="font-size: 24px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">${totalBlocks}</div>
                </div>
            </div>
        `;
    }
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

// Setup filter functionality
function setupBlockFilters() {
    const sourceFilter = document.getElementById('blockSourceFilter');
    const statusFilter = document.getElementById('blockStatusFilter');

    if (sourceFilter) {
        sourceFilter.onchange = applyBlockFilters;
    }

    if (statusFilter) {
        statusFilter.onchange = applyBlockFilters;
    }
}

// Apply filters to block table
function applyBlockFilters() {
    const sourceFilter = document.getElementById('blockSourceFilter')?.value || '';
    const statusFilter = document.getElementById('blockStatusFilter')?.value || '';

    const rows = document.querySelectorAll('#blocksTableBody tr');

    rows.forEach(row => {
        let showRow = true;

        // Get source from badge text (column index 3)
        const sourceBadge = row.cells[3]?.textContent.trim().toLowerCase();

        // Get status from badge (column index 6)
        const statusBadge = row.cells[6]?.textContent.trim().toLowerCase();

        // Apply source filter
        if (sourceFilter && !sourceBadge.includes(sourceFilter.toLowerCase())) {
            showRow = false;
        }

        // Apply status filter (values are "true" or "false" as strings)
        if (statusFilter) {
            if (statusFilter === 'true' && !statusBadge.includes('active')) {
                showRow = false;
            } else if (statusFilter === 'false' && !statusBadge.includes('unblocked')) {
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
