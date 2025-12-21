/**
 * SSH Guardian v3.0 - Firewall Inline Blocked IPs
 * Blocked IPs tab functionality
 */
(function() {
    'use strict';

    let allBlockedIPs = [];

    // Reconcile ip_blocks with real UFW/fail2ban status before loading
    async function reconcileBlockedIPs() {
        console.log('[BlockedIPs] Starting reconciliation with UFW/fail2ban...');
        try {
            const agentId = window.currentAgentId || null;
            const response = await fetch('/api/dashboard/blocking/reconcile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ agent_id: agentId })
            });
            const data = await response.json();
            if (data.success && data.reconciled_count > 0) {
                console.log(`[BlockedIPs] Reconciled ${data.reconciled_count} IPs`);
                showNotification('info', `Synced: ${data.reconciled_count} IPs updated from UFW/fail2ban`);
            }
            return data;
        } catch (err) {
            console.error('[BlockedIPs] Reconciliation error:', err);
            return { success: false, error: err.message };
        }
    }

    async function loadBlockedIPs() {
        const loading = document.getElementById('blockedIPsLoading');
        const container = document.getElementById('blockedIPsContainer');
        const list = document.getElementById('blockedIPsList');
        const noBlocked = document.getElementById('noBlockedIPs');

        if (!loading || !container || !list || !noBlocked) return;

        loading.style.display = 'block';
        container.style.display = 'none';
        noBlocked.style.display = 'none';

        let apiUrl = '/api/dashboard/blocking/real-blocks?limit=200';
        if (window.currentAgentId) apiUrl += `&agent_id=${encodeURIComponent(window.currentAgentId)}`;

        const searchInput = document.getElementById('blockedIPSearch');
        if (searchInput?.value.trim()) apiUrl += `&search=${encodeURIComponent(searchInput.value.trim())}`;

        fetch(apiUrl)
            .then(r => r.json())
            .then(data => {
                loading.style.display = 'none';
                if (data.success && data.blocks?.length > 0) {
                    allBlockedIPs = data.blocks.map(b => ({
                        id: b.id, ip_address: b.ip_address, source: b.source,
                        block_type: b.block_type, reason: b.reason, blocked_at: b.blocked_at,
                        agent_name: b.agent_name || 'Unknown', agent_id: b.agent_id,
                        rule_index: b.rule_index, jail_name: b.jail_name, failures: b.failures
                    }));
                    updateBlockedIPsStats(data);
                    renderBlockedIPs(allBlockedIPs);
                    container.style.display = 'block';
                } else {
                    noBlocked.style.display = 'block';
                    updateBlockedIPsStats({ ufw_count: 0, fail2ban_count: 0, total: 0 });
                }
            })
            .catch(err => {
                loading.style.display = 'none';
                noBlocked.style.display = 'block';
                console.error('Error loading blocked IPs:', err);
            });
    }

    function searchBlockedIPs() {
        loadBlockedIPs();
    }

    function updateBlockedIPsStats(data) {
        const total = data.total || 0;
        const ufw = data.ufw_count || 0;
        const fail2ban = data.fail2ban_count || 0;

        const totalEl = document.getElementById('blockedStatTotal');
        const f2bEl = document.getElementById('blockedStatFail2ban');
        const ufwEl = document.getElementById('blockedStatUFW');
        const mlEl = document.getElementById('blockedStatML');

        if (totalEl) totalEl.textContent = total;
        if (f2bEl) f2bEl.textContent = fail2ban;
        if (ufwEl) ufwEl.textContent = ufw;
        if (mlEl) mlEl.textContent = '-';  // ML not applicable for real blocks
    }

    function renderBlockedIPs(blocks) {
        const list = document.getElementById('blockedIPsList');
        const noBlocked = document.getElementById('noBlockedIPs');
        const container = document.getElementById('blockedIPsContainer');

        if (!list) {
            console.error('blockedIPsList element not found');
            return;
        }

        if (blocks.length === 0) {
            list.innerHTML = '';
            if (noBlocked) noBlocked.style.display = 'block';
            if (container) container.style.display = 'none';
            return;
        }

        if (noBlocked) noBlocked.style.display = 'none';
        if (container) container.style.display = 'block';

        try {
            // Add table header
            const headerHtml = `
                <div class="blocked-ip-header">
                    <div class="blocked-col-ip">IP Address</div>
                    <div class="blocked-col-source">Source</div>
                    <div class="blocked-col-server">Server</div>
                    <div class="blocked-col-reason">Reason</div>
                    <div class="blocked-col-time">Blocked</div>
                </div>
            `;

            const rowsHtml = blocks.map(b => {
                const source = b.source || 'unknown';
                const sourceLabel = b.block_type || (source === 'ufw' ? 'UFW' : source === 'fail2ban' ? 'Fail2ban' : source);

                const blockedAt = b.blocked_at ? formatTimeAgo(b.blocked_at) : 'Unknown';
                const reason = b.reason || 'No reason specified';
                const serverName = b.agent_name || 'Unknown';
                const ipAddress = b.ip_address || 'Unknown IP';

                // Source icon based on type
                const sourceIcon = source === 'ufw' ? '🛡️' : source === 'fail2ban' ? '🔒' : '🚫';

                // Truncate reason for display (longer now)
                const truncatedReason = reason.length > 50 ? reason.substring(0, 50) + '...' : reason;

                return `
                    <div class="blocked-ip-row"
                         onclick="showRealBlockDetail('${escapeHtml(ipAddress)}', '${source}', ${b.agent_id || 'null'}, ${b.rule_index || 'null'})">
                        <div class="blocked-col-ip">
                            <span class="blocked-ip-icon ${escapeHtml(source)}">${sourceIcon}</span>
                            <span class="blocked-ip-address">${escapeHtml(ipAddress)}</span>
                        </div>
                        <div class="blocked-col-source">
                            <span class="blocked-source-badge ${escapeHtml(source)}">${escapeHtml(sourceLabel)}</span>
                        </div>
                        <div class="blocked-col-server">
                            <span class="blocked-server-name">${escapeHtml(serverName)}</span>
                        </div>
                        <div class="blocked-col-reason" title="${escapeHtml(reason)}">
                            <span class="blocked-reason-text">${escapeHtml(truncatedReason)}</span>
                        </div>
                        <div class="blocked-col-time">
                            <span class="blocked-time-text">${blockedAt}</span>
                        </div>
                    </div>
                `;
            }).join('');

            list.innerHTML = headerHtml + rowsHtml;
        } catch (err) {
            console.error('Error rendering blocked IPs:', err);
            list.innerHTML = '<div class="blocked-ip-error">Error rendering blocked IPs. Check console.</div>';
        }
    }

    function filterBlockedIPs() {
        const filter = document.getElementById('blockedSourceFilter').value;

        if (filter === 'all') {
            renderBlockedIPs(allBlockedIPs);
        } else {
            const filtered = allBlockedIPs.filter(b => b.source === filter);
            renderBlockedIPs(filtered);
        }
    }

    function unblockIP(ip, blockId) {
        if (!confirm(`Unblock IP address ${ip}?`)) return;

        fetch('/api/dashboard/blocking/blocks/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ip, reason: 'Manual unblock from dashboard' })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showNotification('success', `Unblocked ${ip}`);
                loadBlockedIPs();
            } else {
                showNotification('error', data.error || 'Failed to unblock IP');
            }
        })
        .catch(err => {
            showNotification('error', 'Error unblocking IP');
            console.error(err);
        });
    }

    // Expose allBlockedIPs for other modules
    window.getAllBlockedIPs = function() { return allBlockedIPs; };

    // Global exports
    window.reconcileBlockedIPs = reconcileBlockedIPs;
    window.loadBlockedIPs = loadBlockedIPs;
    window.searchBlockedIPs = searchBlockedIPs;
    window.renderBlockedIPs = renderBlockedIPs;
    window.filterBlockedIPs = filterBlockedIPs;
    window.unblockIP = unblockIP;
})();
