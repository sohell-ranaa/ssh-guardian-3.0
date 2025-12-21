/**
 * SSH Guardian v3.0 - Firewall Fail2ban Module
 * Handles Fail2ban integration, bans, history, and threat analysis
 * Dependencies: Requires window.currentAgentId from firewall_core.js
 */

// ============================================================================
// FAIL2BAN INTEGRATION
// ============================================================================

async function loadFail2banBans() {
    const loading = document.getElementById('f2bBansLoading');
    const container = document.getElementById('f2bBansContainer');
    const noBans = document.getElementById('f2bNoBans');

    if (loading) loading.style.display = 'block';
    if (container) container.style.display = 'none';
    if (noBans) noBans.style.display = 'none';

    try {
        if (!window.currentAgentId) {
            if (loading) loading.style.display = 'none';
            if (noBans) {
                noBans.style.display = 'block';
                noBans.innerHTML = '<div style="color: var(--text-secondary);">Select an agent to view fail2ban bans</div>';
            }
            updateFail2banCounts(0);
            return;
        }

        // Load UFW blocked IPs first for marker display
        await loadUFWBlockedIPs();

        const apiUrl = `/api/agents/${window.currentAgentId}/fail2ban/live`;
        const response = await fetch(apiUrl);
        const data = await response.json();

        if (loading) loading.style.display = 'none';

        if (data.success && data.bans && data.bans.length > 0) {
            const activeBans = data.bans.filter(ban => !ban.is_expired);
            if (activeBans.length > 0) {
                if (container) container.style.display = 'block';
                updateFail2banCounts(activeBans.length);
                renderFail2banBans(data.bans);
            } else {
                if (noBans) noBans.style.display = 'block';
                updateFail2banCounts(0);
            }
        } else {
            if (noBans) noBans.style.display = 'block';
            updateFail2banCounts(0);
        }

        // Update last sync time
        const lastSyncF2B = document.getElementById('lastSyncF2B');
        const lastSyncDisplay = document.getElementById('lastSyncDisplay');
        if (lastSyncF2B) {
            lastSyncF2B.textContent = 'Just now';
            if (typeof setLastSync === 'function') setLastSync('fail2ban', new Date());
        }
        if (lastSyncDisplay) lastSyncDisplay.style.display = 'block';
    } catch (error) {
        console.error('Error loading fail2ban bans:', error);
        if (loading) loading.style.display = 'none';
        if (noBans) {
            noBans.style.display = 'block';
            noBans.innerHTML = `<div style="color: ${TC.danger};">Error loading fail2ban data</div>`;
        }
    }
}

// Update all fail2ban count displays
function updateFail2banCounts(count) {
    const banCountEl = document.getElementById('f2bBanCount');
    const statBans = document.getElementById('stat-f2b-bans');
    const statActive = document.getElementById('f2bStatActive');

    if (banCountEl) banCountEl.textContent = `${count} active ban${count !== 1 ? 's' : ''}`;
    if (statBans) statBans.textContent = count;
    if (statActive) statActive.textContent = count;
}

function renderFail2banBans(bans) {
    const container = document.getElementById('f2bBansList');
    if (!container) return;

    // Filter out expired bans and sort by remaining time (most urgent first)
    const activeBans = bans.filter(ban => !ban.is_expired);
    const sortedBans = [...activeBans].sort((a, b) => {
        return (a.remaining_seconds || 0) - (b.remaining_seconds || 0);
    });

    if (sortedBans.length === 0) {
        container.innerHTML = '<div class="f2b-empty">No active bans</div>';
        return;
    }

    container.innerHTML = sortedBans.map(ban => {
        const timeAgo = ban.banned_at ? formatTimeAgo(ban.banned_at) : 'Unknown';
        const agentId = ban.agent_id || window.currentAgentId;
        const isInUFW = ufwBlockedIPs.has(ban.ip_address);

        // Timing info
        const bantime = ban.bantime_seconds || 0;
        const durationStr = bantime > 0 ? formatDuration(bantime) : 'Permanent';
        const remainingMins = ban.remaining_minutes || 0;
        const remainingStr = remainingMins > 0 ? `${remainingMins}m left` : 'Expiring soon';
        const banCount = ban.ban_count || 1;

        // Color based on remaining time
        let remainingClass = 'f2b-time-safe';
        if (remainingMins <= 5) remainingClass = 'f2b-time-critical';
        else if (remainingMins <= 15) remainingClass = 'f2b-time-warning';

        // UFW badge
        const ufwBadge = isInUFW
            ? `<span style="background: ${TC.successBg}; color: ${TC.teal}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 6px;" title="Also blocked in UFW">🛡️ UFW</span>`
            : '';

        // Action buttons - show different UFW button based on status
        const ufwButton = isInUFW
            ? `<span style="padding: 4px 8px; background: ${TC.successBg}; color: ${TC.teal}; border-radius: 4px; font-size: 11px;">✓ In UFW</span>`
            : `<button class="f2b-escalate-btn" onclick="escalateToUFW('${ban.ip_address}', ${agentId})" title="Permanently block via UFW">⬆️ UFW</button>`;

        return `
            <div class="f2b-ban-card">
                <div class="f2b-ban-icon">${isInUFW ? '🛡️' : '🔒'}</div>
                <div class="f2b-ban-details">
                    <div class="f2b-ban-ip clickable-ip" onclick="showBannedIpDetails('${ban.ip_address}')" title="Click to view details">
                        ${ban.ip_address} ${ufwBadge}
                        <span class="ip-details-hint">ℹ️</span>
                    </div>
                    <div class="f2b-ban-meta">
                        <span>📍 ${ban.jail_name}</span>
                        <span>❌ ${ban.failures || 0} failures</span>
                        <span>🔄 ${banCount}x banned</span>
                    </div>
                    <div class="f2b-ban-meta" style="margin-top: 4px;">
                        <span>⏱️ Banned ${timeAgo}</span>
                        <span>⏳ ${durationStr} ban</span>
                    </div>
                    <div class="f2b-ban-timing">
                        <span class="f2b-remaining ${remainingClass}">⏰ ${remainingStr}</span>
                    </div>
                </div>
                <div style="display: flex; flex-direction: column; gap: 4px;">
                    <button class="f2b-unban-btn" onclick="sendUnbanCommand(${agentId}, '${ban.ip_address}', '${ban.jail_name}')" title="Unban from fail2ban">🔓 Unban</button>
                    ${ufwButton}
                </div>
            </div>
        `;
    }).join('');
}

// Format duration in human readable form
function formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return `${Math.floor(seconds / 86400)}d`;
}

// Debounce timer for reload
let _f2bReloadTimer = null;

// Reload all fail2ban data (called when server selection changes)
// Debounced to prevent rapid concurrent API calls
function reloadAllF2bData() {
    // Clear any pending reload
    if (_f2bReloadTimer) {
        clearTimeout(_f2bReloadTimer);
    }

    // Debounce: wait 150ms before actually reloading
    _f2bReloadTimer = setTimeout(() => {
        _f2bReloadTimer = null;
        _doReloadAllF2bData();
    }, 150);
}

// Internal function that does the actual reload
function _doReloadAllF2bData() {
    loadFail2banBans();
    loadF2bStats();

    // Also reload the currently active sub-tab content
    const activeTab = document.querySelector('.f2b-subtab.active');
    if (activeTab) {
        const subtab = activeTab.dataset.subtab;
        if (subtab === 'history') {
            loadF2bHistory();
        }
    }
}

// Switch fail2ban sub-tabs
function switchF2bSubtab(subtab) {
    // Update tab buttons
    document.querySelectorAll('.f2b-subtab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.subtab === subtab);
    });

    // Show/hide content
    document.querySelectorAll('.f2b-subtab-content').forEach(content => {
        content.style.display = 'none';
    });

    const activeContent = document.getElementById(`f2b-subtab-${subtab}`);
    if (activeContent) {
        activeContent.style.display = 'block';
    }

    // Load data for the tab
    if (subtab === 'active') {
        loadFail2banBans();
        loadF2bStats();
    } else if (subtab === 'history') {
        loadF2bHistory();
    }
}

// Load fail2ban stats
async function loadF2bStats() {
    try {
        // Build API URL with agent filter if server is selected
        let apiUrl = '/api/dashboard/fail2ban/stats';
        if (window.currentAgentId) {
            apiUrl += `?agent_id=${encodeURIComponent(window.currentAgentId)}`;
        }

        const response = await fetch(apiUrl);
        const data = await response.json();

        if (data.success && data.stats) {
            const s = data.stats;
            const active = document.getElementById('f2bStatActive');
            const total = document.getElementById('f2bStatTotal');
            const repeat = document.getElementById('f2bStatRepeat');
            const escalated = document.getElementById('f2bStatEscalated');

            if (active) active.textContent = s.active_bans || 0;
            if (total) total.textContent = s.total_bans || 0;
            if (repeat) repeat.textContent = s.repeat_offenders || 0;
            if (escalated) escalated.textContent = s.escalated_to_ufw || 0;
        }
    } catch (e) {
        console.error('Error loading fail2ban stats:', e);
    }
}

// Cache for UFW blocked IPs (to show markers)
let ufwBlockedIPs = new Set();

// Load UFW blocked IPs for marker display
async function loadUFWBlockedIPs() {
    if (!window.currentAgentId) return;
    try {
        const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/live`);
        const data = await response.json();
        ufwBlockedIPs.clear();
        if (data.success && data.rules) {
            data.rules.forEach(rule => {
                // Check both from and from_ip fields (API may use either)
                const fromIp = rule.from_ip || rule.from;
                if (rule.action === 'DENY' && fromIp && fromIp !== 'Anywhere') {
                    ufwBlockedIPs.add(fromIp);
                }
            });
        }
    } catch (e) {
        console.error('Error loading UFW IPs:', e);
    }
}

// Check if IP is blocked in UFW (for external use)
function isIpInUFW(ip) {
    return ufwBlockedIPs.has(ip);
}

// Load fail2ban history
async function loadF2bHistory() {
    const historyList = document.getElementById('f2bHistoryList');
    const loading = document.getElementById('f2bHistoryLoading');
    const rangeSelect = document.getElementById('f2bHistoryRange');

    if (!historyList) return;

    const timeRange = rangeSelect ? rangeSelect.value : '24h';

    if (loading) loading.style.display = 'block';
    historyList.innerHTML = '';

    // Load UFW blocked IPs for marker display
    await loadUFWBlockedIPs();

    try {
        let apiUrl = `/api/dashboard/fail2ban/events?time_range=${timeRange}&page_size=100`;
        if (window.currentAgentId) {
            apiUrl += `&agent_id=${encodeURIComponent(window.currentAgentId)}`;
        }

        const response = await fetch(apiUrl);
        const data = await response.json();

        if (loading) loading.style.display = 'none';

        if (data.success && data.events && data.events.length > 0) {
            historyList.innerHTML = data.events.map(event => {
                const timeStr = event.reported_at ? formatTimeAgo(event.reported_at) : 'Unknown';
                const banCount = event.ban_count || 0;
                const unbanCount = event.unban_count || 0;
                const isInUFW = ufwBlockedIPs.has(event.ip_address);
                const agentId = event.agent_id || window.currentAgentId;

                // Badges
                const countBadge = banCount > 1
                    ? `<span style="background: ${TC.dangerBg}; color: ${TC.danger}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 6px;">×${banCount}</span>`
                    : '';
                const ufwBadge = isInUFW
                    ? `<span style="background: ${TC.successBg}; color: ${TC.teal}; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-left: 6px;" title="Permanently blocked in UFW">🛡️ UFW</span>`
                    : '';

                // UFW button (only show if not already in UFW)
                const ufwBtn = !isInUFW && agentId
                    ? `<button class="f2b-escalate-btn-sm" onclick="event.stopPropagation(); escalateToUFW('${event.ip_address}', ${agentId})" title="Block permanently via UFW">⬆️</button>`
                    : '';

                return `
                    <div class="f2b-history-item" style="display: flex; align-items: center; gap: 10px;">
                        <div class="f2b-history-icon">${isInUFW ? '🛡️' : '🔒'}</div>
                        <div class="f2b-history-details" style="flex: 1;">
                            <div class="f2b-history-ip clickable-ip" onclick="showBannedIpDetails('${event.ip_address}')" title="Click to view details" style="cursor: pointer;">
                                ${event.ip_address} ${countBadge} ${ufwBadge}
                                <span class="ip-details-hint" style="opacity: 0.5; font-size: 12px; margin-left: 4px;">ℹ️</span>
                            </div>
                            <div class="f2b-history-meta">
                                ❌ ${event.failures || 0} failures
                                • ${event.jail_name}
                                ${unbanCount > 0 ? `• 🔓 ${unbanCount} unbans` : ''}
                                • ${event.agent_hostname || 'Unknown'}
                            </div>
                        </div>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            ${ufwBtn}
                            <div class="f2b-history-time">${timeStr}</div>
                        </div>
                    </div>
                `;
            }).join('');

            if (data.pages > 1) {
                historyList.innerHTML += `
                    <div style="text-align: center; padding: 10px; color: var(--text-secondary); font-size: 12px;">
                        Page ${data.page} of ${data.pages} (${data.total} unique IPs)
                    </div>
                `;
            }
        } else {
            historyList.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-secondary);">No events in this time range</div>';
        }
    } catch (e) {
        console.error('Error loading fail2ban history:', e);
        if (loading) loading.style.display = 'none';
        historyList.innerHTML = `<div style="text-align: center; padding: 30px; color: ${TC.danger};">Error loading history</div>`;
    }
}

// Note: initFirewallPage() is called by dashboard_modular.html when navigating to firewall page
// Auto-init removed to prevent early initialization before all dependencies are loaded

// Expose functions globally for inline onclick handlers
window.switchF2bSubtab = switchF2bSubtab;
window.loadF2bHistory = loadF2bHistory;
window.loadF2bStats = loadF2bStats;
window.loadFail2banBans = loadFail2banBans;
window.reloadAllF2bData = reloadAllF2bData;
window.loadUFWBlockedIPs = loadUFWBlockedIPs;
window.isIpInUFW = isIpInUFW;
