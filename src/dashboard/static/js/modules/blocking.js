/**
 * Blocking Module
 * Handles IP blocking functionality for SSH Guardian
 */

(function() {
    'use strict';

    let currentBlocksPage = 0;
    const blocksPageSize = 50;

    /**
     * Load blocked IPs list
     */
    window.loadBlocks = async function() {
        const blockSourceFilter = document.getElementById('blockSourceFilter');
        const blockStatusFilter = document.getElementById('blockStatusFilter');

        const blockSource = blockSourceFilter ? blockSourceFilter.value : '';
        const isActive = blockStatusFilter ? blockStatusFilter.value : '';

        const params = new URLSearchParams({
            limit: blocksPageSize,
            offset: currentBlocksPage * blocksPageSize
        });

        if (blockSource) params.append('source', blockSource);
        if (isActive) params.append('is_active', isActive);

        try {
            const response = await fetch(`/api/dashboard/blocking/blocks?${params}`);
            const data = await response.json();

            if (data.success) {
                renderBlocksTable(data.blocks, data.pagination);
            } else {
                console.error('Failed to load blocks:', data.error);
            }
        } catch (error) {
            console.error('Error loading blocks:', error);
        }
    };

    /**
     * Render blocks table
     */
    function renderBlocksTable(blocks, pagination) {
        const tbody = document.getElementById('blocksTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';

        if (blocks.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 40px; color: var(--text-secondary);">No blocked IPs found</td></tr>';
            return;
        }

        blocks.forEach(block => {
            const row = document.createElement('tr');
            row.style.borderBottom = '1px solid var(--border)';

            const isActive = block.is_active;
            const statusBadge = isActive
                ? '<span style="background: #D83B01; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px;">ACTIVE</span>'
                : '<span style="background: #605E5C; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px;">EXPIRED</span>';

            row.innerHTML = `
                <td style="padding: 12px; font-family: monospace;">${escapeHtml(block.ip_address)}</td>
                <td style="padding: 12px; font-size: 12px;">${escapeHtml(block.reason || 'N/A')}</td>
                <td style="padding: 12px; font-size: 12px;">${escapeHtml(block.source || 'manual')}</td>
                <td style="padding: 12px; font-size: 12px;">${formatTimestamp(block.blocked_at)}</td>
                <td style="padding: 12px; font-size: 12px;">${block.unblock_at ? formatTimestamp(block.unblock_at) : 'Permanent'}</td>
                <td style="padding: 12px;">${statusBadge}</td>
                <td style="padding: 12px;">
                    ${isActive ? `<button onclick="quickUnblock('${escapeHtml(block.ip_address)}')" style="padding: 4px 8px; border: 1px solid var(--border); background: #107C10; color: white; border-radius: 2px; cursor: pointer; font-size: 11px;">Unblock</button>` : ''}
                </td>
            `;
            tbody.appendChild(row);
        });

        // Update pagination info
        if (pagination) {
            const infoEl = document.getElementById('blocksInfo');
            if (infoEl) {
                infoEl.textContent = `Showing ${pagination.offset + 1}-${Math.min(pagination.offset + blocksPageSize, pagination.total)} of ${pagination.total} blocks`;
            }
        }
    }

    /**
     * Quick block an IP address
     */
    window.quickBlock = async function(ipAddress, reason = 'Blocked from events view') {
        if (!ipAddress) {
            console.error('No IP address provided');
            return;
        }

        if (!confirm(`Block IP ${ipAddress}?\n\nReason: ${reason}`)) {
            return;
        }

        try {
            const response = await fetch('/api/dashboard/blocking/blocks/manual', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip_address: ipAddress,
                    reason: reason,
                    duration_minutes: 1440
                })
            });

            const data = await response.json();

            if (data.success) {
                alert(`IP ${ipAddress} blocked successfully!\n\nBlock ID: ${data.block_id}\nUnblock at: ${new Date(data.unblock_at).toLocaleString()}`);

                // Refresh blocks page if we're on it
                const currentHash = window.location.hash.substring(1);
                if (currentHash === 'ip-blocks') {
                    if (typeof loadBlockedIPsPage === 'function') {
                        loadBlockedIPsPage();
                    }
                }
            } else {
                if (data.message && data.message.includes('already blocked')) {
                    const viewBlock = confirm(`IP ${ipAddress} is already blocked!\n\nBlock ID: ${data.block_id}\n\nWould you like to view blocked IPs?`);
                    if (viewBlock) {
                        window.location.hash = 'ip-blocks';
                        if (typeof showPage === 'function') {
                            showPage('ip-blocks');
                        }
                    }
                } else {
                    alert(`Failed to block IP: ${data.message || data.error || 'Unknown error'}`);
                }
            }
        } catch (error) {
            console.error('Error blocking IP:', error);
            alert('Error blocking IP. Please try again.');
        }
    };

    /**
     * Quick unblock an IP address
     */
    window.quickUnblock = async function(ipAddress) {
        if (!ipAddress) {
            console.error('No IP address provided');
            return;
        }

        if (!confirm(`Unblock IP ${ipAddress}?`)) {
            return;
        }

        try {
            const response = await fetch('/api/dashboard/blocking/blocks/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip_address: ipAddress
                })
            });

            const data = await response.json();

            if (data.success) {
                alert(`IP ${ipAddress} unblocked successfully!`);

                // Refresh blocks page if we're on it
                const currentHash = window.location.hash.substring(1);
                if (currentHash === 'ip-blocks') {
                    if (typeof loadBlockedIPsPage === 'function') {
                        loadBlockedIPsPage();
                    }
                }
            } else {
                alert(`Failed to unblock IP: ${data.message || data.error || 'Unknown error'}`);
            }
        } catch (error) {
            console.error('Error unblocking IP:', error);
            alert('Error unblocking IP. Please try again.');
        }
    };

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Format timestamp for display
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        // Use TimeSettings if available
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.formatFull(timestamp);
        }
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

})();
