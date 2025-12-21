/**
 * Blocked IPs - Core Module
 * Data loading and table rendering
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};

    // Defensive fallbacks for utility functions
    const escapeHtml = window.escapeHtml || function(text) {
        if (text === null || text === undefined) return '';
        const str = String(text);
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return str.replace(/[&<>"']/g, m => map[m]);
    };
    const formatLocalDateTime = window.formatLocalDateTime || function(dateStr) {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toLocaleString();
    };
    const TC = window.TC || {
        primary: '#0078D4', primaryDark: '#004C87', danger: '#D13438',
        success: '#107C10', successDark: '#0B6A0B', warning: '#FFB900',
        purple: '#8764B8', textSecondary: '#605E5C', orangeDark: '#CA5010', primaryHover: '#106EBE'
    };

    BlockedIPs.Core = {
        /**
         * Load all IP blocks from API
         */
        async loadIPBlocks() {
            const loadingEl = document.getElementById('blocksLoading');
            const tableEl = document.getElementById('blocksTable');
            const errorEl = document.getElementById('blocksError');

            try {
                if (loadingEl) loadingEl.style.display = 'block';
                if (tableEl) tableEl.style.display = 'none';
                if (errorEl) errorEl.style.display = 'none';

                let apiUrl = '/api/dashboard/blocking/blocks/list';
                if (BlockedIPs.state.currentAgentFilter) {
                    apiUrl += `?agent_id=${encodeURIComponent(BlockedIPs.state.currentAgentFilter)}`;
                }

                let data;
                if (typeof fetchWithCache === 'function') {
                    data = await fetchWithCache(apiUrl, 'blocking');
                } else {
                    const response = await fetch(apiUrl);
                    data = await response.json();
                }

                if (!data.success || !data.blocks || data.blocks.length === 0) {
                    if (loadingEl) loadingEl.style.display = 'none';
                    if (tableEl) {
                        tableEl.innerHTML = '<div class="empty-state-small">No IP blocks found</div>';
                        tableEl.style.display = 'block';
                    }
                    return;
                }

                BlockedIPs.state.blocks = data.blocks;
                this.renderTable(data.blocks);

                if (loadingEl) loadingEl.style.display = 'none';
                if (tableEl) tableEl.style.display = 'block';

                // Enrich location data asynchronously
                BlockedIPs.UI.enrichLocations(data.blocks);

            } catch (error) {
                console.error('Error loading IP blocks:', error);
                if (loadingEl) loadingEl.style.display = 'none';
                if (errorEl) {
                    errorEl.innerHTML = `<p>Error loading IP blocks: ${escapeHtml(error.message)}</p>`;
                    errorEl.style.display = 'block';
                }
            }
        },

        /**
         * Render blocks table
         */
        renderTable(blocks) {
            const tableBody = document.getElementById('blocksTableBody');
            if (!tableBody) return;

            // Collect unique agents for filter
            const uniqueAgents = new Set();
            blocks.forEach(block => {
                const agentName = block.agent_name || 'Manual Block';
                uniqueAgents.add(agentName);
            });

            tableBody.innerHTML = blocks.map(block => this.renderRow(block)).join('');

            // Update stats
            BlockedIPs.UI.updateStats(blocks);

            // Populate agent filter
            BlockedIPs.Filters.populateAgentDropdown(Array.from(uniqueAgents));
        },

        /**
         * Render single table row
         */
        renderRow(block) {
            const statusBadge = block.is_active
                ? `<span style="padding: 4px 12px; background: ${TC.danger}; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Active</span>`
                : `<span style="padding: 4px 12px; background: ${TC.success}; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Expired</span>`;

            const sourceBadge = BlockedIPs.UI.getSourceBadge(block.source);
            const expiresAt = block.unblock_at ? formatLocalDateTime(block.unblock_at) : 'Permanent';
            const agentName = block.agent_name || 'Manual';
            const scopeBadge = block.agent_id
                ? `<span style="padding: 2px 8px; background: ${TC.purple}; color: white; border-radius: 3px; font-size: 10px;">Agent: ${escapeHtml(agentName)}</span>`
                : `<span style="padding: 2px 8px; background: ${TC.primary}; color: white; border-radius: 3px; font-size: 10px;">Global</span>`;

            const actions = block.is_active
                ? `<button class="btn btn-sm btn-secondary" onclick="disableBlockFromTable('${escapeHtml(block.ip_address)}', ${block.id})" title="Unblock IP">Unblock</button>`
                : `<button class="btn btn-sm btn-warning" onclick="reblockIPFromTable('${escapeHtml(block.ip_address)}')" title="Re-block IP">Re-block</button>`;

            return `
                <tr data-block-id="${block.id}" data-ip="${escapeHtml(block.ip_address)}" data-agent="${escapeHtml(agentName)}" data-source="${escapeHtml(block.source || '')}">
                    <td>
                        <a href="#" onclick="showBlockIpDetails('${escapeHtml(block.ip_address)}'); return false;" style="font-weight: 600; color: ${TC.primary};">
                            ${escapeHtml(block.ip_address)}
                        </a>
                    </td>
                    <td class="ip-location-cell" data-ip="${escapeHtml(block.ip_address)}">
                        <span style="color: var(--text-secondary);">Loading...</span>
                    </td>
                    <td>${statusBadge}</td>
                    <td>${sourceBadge}</td>
                    <td>${escapeHtml(block.reason || 'No reason provided')}</td>
                    <td>${formatLocalDateTime(block.blocked_at)}</td>
                    <td>${expiresAt}</td>
                    <td>${scopeBadge}</td>
                    <td>${actions}</td>
                </tr>
            `;
        }
    };
})();
