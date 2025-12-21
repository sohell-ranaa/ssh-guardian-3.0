/**
 * SSH Guardian v3.0 - Firewall UFW Command Queue
 * Manages pending UFW commands and polling
 */
(function() {
    'use strict';

    // Track pending commands
    window.ufwCommandQueue = [];
    window.ufwQueuePolling = null;

    function addToCommandQueue(commandId, commandText, status = 'pending') {
        const queue = window.ufwCommandQueue;

        // Don't add duplicates
        if (queue.some(c => c.id === commandId)) return;

        queue.unshift({
            id: commandId,
            command: commandText,
            status: status,
            timestamp: new Date()
        });

        // Keep max 10 items
        if (queue.length > 10) queue.pop();

        renderCommandQueue();
        showCommandQueuePanel(true);
        startQueuePolling();
    }

    function updateCommandStatus(commandId, status, message = '') {
        const queue = window.ufwCommandQueue;
        const cmd = queue.find(c => c.id === commandId);
        if (cmd) {
            cmd.status = status;
            cmd.message = message;
            renderCommandQueue();

            // If completed or failed, refresh the rules list
            if (status === 'completed' || status === 'failed') {
                if (typeof updateUFWSyncText === 'function') {
                    updateUFWSyncText('Refreshing...');
                }

                if (window.currentAgentId) {
                    setTimeout(() => {
                        const refreshPromise = typeof loadUFWData === 'function'
                            ? loadUFWData(window.currentAgentId, true)
                            : (typeof window.loadUFWData === 'function'
                                ? window.loadUFWData(window.currentAgentId, true)
                                : (typeof loadFirewallPage === 'function'
                                    ? loadFirewallPage(true)
                                    : Promise.resolve()));

                        Promise.resolve(refreshPromise).finally(() => {
                            if (typeof hideUFWSyncIndicator === 'function') {
                                hideUFWSyncIndicator();
                            }
                        });
                    }, 500);
                } else {
                    if (typeof hideUFWSyncIndicator === 'function') {
                        hideUFWSyncIndicator();
                    }
                }
            }
        }

        // Hide panel if all completed
        const pending = queue.filter(c => c.status === 'pending');
        if (pending.length === 0) {
            stopQueuePolling();
            setTimeout(() => {
                const stillPending = window.ufwCommandQueue.filter(c => c.status === 'pending');
                if (stillPending.length === 0) {
                    showCommandQueuePanel(false);
                }
            }, 3000);
        }
    }

    function renderCommandQueue() {
        const panel = document.getElementById('ufwCommandQueue');
        const list = document.getElementById('ufwQueueList');
        const countBadge = document.getElementById('ufwQueueCount');

        if (!panel || !list) return;

        const queue = window.ufwCommandQueue;
        const pendingCount = queue.filter(c => c.status === 'pending').length;

        if (countBadge) countBadge.textContent = pendingCount;

        list.innerHTML = queue.map(cmd => {
            const statusIcon = cmd.status === 'pending' ? '⏳' :
                              cmd.status === 'completed' ? '✅' : '❌';
            const statusText = cmd.status === 'pending' ? 'Pending...' :
                              cmd.status === 'completed' ? 'Done' : 'Failed';
            const timeAgo = getTimeAgo(cmd.timestamp);

            return `
                <div class="queue-item ${cmd.status}">
                    <span class="status-icon">${statusIcon}</span>
                    <span class="command-text">${_escapeHtml(cmd.command)}</span>
                    <span class="status-text">${statusText}</span>
                    <span style="font-size: 10px; color: var(--text-hint);">${timeAgo}</span>
                </div>
            `;
        }).join('');
    }

    function showCommandQueuePanel(show) {
        const panel = document.getElementById('ufwCommandQueue');
        if (panel) {
            panel.style.display = show ? 'block' : 'none';
        }
    }

    function clearCompletedCommands() {
        window.ufwCommandQueue = window.ufwCommandQueue.filter(c => c.status === 'pending');
        renderCommandQueue();
        if (window.ufwCommandQueue.length === 0) {
            showCommandQueuePanel(false);
        }
    }

    function startQueuePolling() {
        if (window.ufwQueuePolling) return;

        window.ufwQueuePolling = setInterval(async () => {
            const pending = window.ufwCommandQueue.filter(c => c.status === 'pending');
            if (pending.length === 0) {
                stopQueuePolling();
                return;
            }
            await checkPendingCommands();
        }, 2000);
    }

    function stopQueuePolling() {
        if (window.ufwQueuePolling) {
            clearInterval(window.ufwQueuePolling);
            window.ufwQueuePolling = null;
        }
    }

    async function checkPendingCommands() {
        if (!window.currentAgentId) return;

        try {
            const resp = await fetch(`/api/agents/${window.currentAgentId}/ufw?force=true`);
            const data = await resp.json();

            if (data.recent_commands) {
                const recentMap = new Map(data.recent_commands.map(c => [c.command_uuid, c]));

                window.ufwCommandQueue.forEach(cmd => {
                    if (cmd.status === 'pending') {
                        const serverCmd = recentMap.get(cmd.id);
                        if (serverCmd) {
                            if (serverCmd.status === 'completed') {
                                updateCommandStatus(cmd.id, 'completed', serverCmd.result_message);
                            } else if (serverCmd.status === 'failed') {
                                updateCommandStatus(cmd.id, 'failed', serverCmd.result_message);
                            }
                        }
                    }
                });
            }
        } catch (e) {
            console.error('Error checking command status:', e);
        }
    }

    function getTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 5) return 'just now';
        if (seconds < 60) return `${seconds}s ago`;
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}m ago`;
        return `${Math.floor(minutes / 60)}h ago`;
    }

    function _escapeHtml(text) {
        if (window.escapeHtml) return window.escapeHtml(text);
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }

    // Global exports
    window.addToCommandQueue = addToCommandQueue;
    window.updateCommandStatus = updateCommandStatus;
    window.checkPendingCommands = checkPendingCommands;
    window.clearCompletedCommands = clearCompletedCommands;
    window.showCommandQueuePanel = showCommandQueuePanel;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW Sync Indicator
 * UFW sync indicator utilities
 */
(function() {
    'use strict';

    function showUFWSyncIndicator(text = 'Syncing...') {
        const indicator = document.getElementById('ufwSyncIndicator');
        const textEl = indicator?.querySelector('.ufw-sync-text');
        if (indicator) {
            indicator.style.display = 'inline-flex';
            if (textEl) textEl.textContent = text;
        }
    }

    function hideUFWSyncIndicator() {
        const indicator = document.getElementById('ufwSyncIndicator');
        if (indicator) {
            indicator.style.display = 'none';
        }
    }

    function updateUFWSyncText(text) {
        const indicator = document.getElementById('ufwSyncIndicator');
        const textEl = indicator?.querySelector('.ufw-sync-text');
        if (textEl) textEl.textContent = text;
    }

    function updateUFWRuleCount(count) {
        const countEl = document.getElementById('ufwRuleCount');
        if (countEl) {
            countEl.textContent = `${count} rule${count !== 1 ? 's' : ''}`;
        }
    }

    // Global exports
    window.showUFWSyncIndicator = showUFWSyncIndicator;
    window.hideUFWSyncIndicator = hideUFWSyncIndicator;
    window.updateUFWSyncText = updateUFWSyncText;
    window.updateUFWRuleCount = updateUFWRuleCount;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW Rules View
 * Renders UFW rules list with filtering
 */
(function() {
    'use strict';

    // Cache for fail2ban IPs
    let fail2banIPs = new Set();

    async function loadFail2banIPs() {
        if (!window.currentAgentId) return;
        try {
            const response = await fetch(`/api/dashboard/fail2ban/events?agent_id=${window.currentAgentId}&time_range=30d&page_size=500`);
            const data = await response.json();
            fail2banIPs.clear();
            if (data.success && data.events) {
                data.events.forEach(event => fail2banIPs.add(event.ip_address));
            }
        } catch (e) {
            console.error('Error loading F2B IPs:', e);
        }
    }

    function renderUFWRules(rules) {
        rules = rules || [];

        const loading = document.getElementById('simpleRulesLoading');
        const noRules = document.getElementById('noRulesMessage');
        const rulesContainer = document.getElementById('simpleRulesContainer');
        const container = document.getElementById('simpleRulesList');

        if (loading) loading.style.display = 'none';
        if (typeof updateUFWRuleCount === 'function') updateUFWRuleCount(rules.length);

        if (rules.length === 0) {
            if (noRules) noRules.style.display = 'block';
            if (rulesContainer) rulesContainer.style.display = 'none';
            return;
        }

        if (rulesContainer) rulesContainer.style.display = 'block';
        if (noRules) noRules.style.display = 'none';
        if (!container) return;

        container.innerHTML = rules.map(rule => {
            const isAllow = rule.action === 'ALLOW';
            const isLimit = rule.action === 'LIMIT';
            const isDeny = !isAllow && !isLimit;
            const icon = isAllow ? '✅' : (isLimit ? '⏱️' : '🚫');
            const badgeClass = isAllow ? 'allow' : (isLimit ? 'limit' : 'block');
            const action = rule.action;

            const port = rule.to_port || 'Any';
            const protocol = rule.protocol || '';
            const from = rule.from_ip === 'Anywhere' ? '' : rule.from_ip;

            const isFromF2B = isDeny && from && fail2banIPs.has(from);

            let description = '';
            if (port !== 'Any' && port !== '') {
                description += `Port ${port}`;
                if (protocol) description += `/${protocol.toUpperCase()}`;
            } else {
                description = 'All ports';
            }

            let ipDisplay = '';
            if (from) {
                const f2bBadge = isFromF2B
                    ? `<span style="background: ${TC.dangerBg}; color: ${TC.danger}; padding: 1px 5px; border-radius: 3px; font-size: 9px; font-weight: 600; margin-left: 4px;" title="Has Fail2ban history">F2B</span>`
                    : '';
                ipDisplay = `<span class="ufw-rule-ip ${isFromF2B ? 'clickable-ip' : ''}" ${isFromF2B ? `onclick="showUFWIpDetails('${from}')" style="cursor: pointer;"` : ''} title="${isFromF2B ? 'Click to view fail2ban history' : ''}">${from}${f2bBadge}</span>`;
                description += ` from `;
            }

            return `
                <div class="simple-rule-card" data-type="${badgeClass}" data-rule-index="${rule.rule_index}" data-from-ip="${from || ''}">
                    <div class="rule-icon">${icon}</div>
                    <div class="rule-details">
                        <div class="rule-title">${description}${ipDisplay}</div>
                    </div>
                    <span class="rule-badge ${badgeClass}">${action}</span>
                    <button class="rule-delete-btn" onclick="deleteUFWRule(${rule.rule_index})">🗑️</button>
                </div>
            `;
        }).join('');
    }

    function renderSimpleRules(rules) {
        renderUFWRules(rules);
    }

    function filterSimpleRules() {
        const filter = document.getElementById('filterRuleType')?.value || 'all';
        const searchInput = document.getElementById('ufwRuleSearch');
        const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';
        const cards = document.querySelectorAll('.simple-rule-card');

        cards.forEach(card => {
            const type = card.dataset.type;
            const ruleText = card.textContent.toLowerCase();

            let matchesType = filter === 'all' ||
                (filter === 'allow' && type === 'allow') ||
                (filter === 'deny' && (type === 'block' || type === 'deny'));

            let matchesSearch = !searchTerm || ruleText.includes(searchTerm);

            if (matchesType && matchesSearch) {
                card.style.display = 'flex';
            } else {
                card.style.display = 'none';
            }
        });
    }

    function updateUFWStats(state, rules) {
        const statusEl = document.getElementById('ufwStatStatus');
        if (statusEl) {
            const isActive = state?.ufw_status === 'active';
            statusEl.textContent = isActive ? '🟢 Active' : '🔴 Inactive';
            statusEl.style.color = isActive ? TC.successDark : TC.danger;
        }

        const totalEl = document.getElementById('ufwStatTotalRules');
        if (totalEl) {
            totalEl.textContent = rules?.length || 0;
        }

        const allowEl = document.getElementById('ufwStatAllowRules');
        if (allowEl && rules) {
            const allowCount = rules.filter(r => r.action === 'ALLOW').length;
            allowEl.textContent = allowCount;
        }

        const denyEl = document.getElementById('ufwStatDenyRules');
        if (denyEl && rules) {
            const denyCount = rules.filter(r => r.action === 'DENY' || r.action === 'REJECT').length;
            denyEl.textContent = denyCount;
        }

        const syncEl = document.getElementById('ufwStatLastSync');
        if (syncEl && state?.last_sync) {
            syncEl.textContent = formatTimeAgo(state.last_sync);
        }
    }

    // Global exports
    window.loadFail2banIPs = loadFail2banIPs;
    window.renderUFWRules = renderUFWRules;
    window.renderSimpleRules = renderSimpleRules;
    window.filterSimpleRules = filterSimpleRules;
    window.updateUFWStats = updateUFWStats;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW Listening Ports
 * Renders listening ports view
 */
(function() {
    'use strict';

    function renderListeningPorts(ports) {
        const container = document.getElementById('interfacesGrid');
        if (!container) return;

        if (!ports || ports.length === 0) {
            container.innerHTML = '<p style="color: var(--text-secondary);">No listening ports detected</p>';
            return;
        }

        container.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px;">
                ${ports.slice(0, 12).map(port => {
                    const isProtected = port.is_protected;
                    return `
                        <div style="background: var(--background); padding: 10px 14px; border-radius: 4px; border: 1px solid var(--border); ${isProtected ? `border-left: 3px solid ${TC.successDark};` : ''}">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-weight: 600; font-size: 16px;">${port.port}</span>
                                <span style="font-size: 11px; color: var(--text-secondary);">${port.protocol.toUpperCase()}</span>
                            </div>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
                                ${port.process_name || 'unknown'}
                            </div>
                            ${isProtected ? `<span style="font-size: 10px; color: ${TC.successDark};">Protected</span>` : ''}
                        </div>
                    `;
                }).join('')}
            </div>
            ${ports.length > 12 ? `<p style="color: var(--text-secondary); margin-top: 10px; font-size: 12px;">+ ${ports.length - 12} more ports</p>` : ''}
        `;
    }

    // Global exports
    window.renderListeningPorts = renderListeningPorts;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW Toggles
 * Toggle functions and advanced view
 */
(function() {
    'use strict';

    let showAdvanced = false;

    function toggleCustomPort(select) {
        const customInput = document.getElementById('simpleRuleCustomPort');
        if (customInput) {
            customInput.style.display = select.value === 'custom' ? 'inline-block' : 'none';
        }
    }

    function toggleAdvancedView() {
        showAdvanced = !showAdvanced;
        const section = document.getElementById('advancedViewSection');
        if (!section) return;

        if (showAdvanced) {
            section.style.display = 'block';
            if (typeof ufwData !== 'undefined' && ufwData) {
                renderAdvancedRules(ufwData.rules || []);
            }
        } else {
            section.style.display = 'none';
        }
    }

    function renderAdvancedRules(rules) {
        const container = document.getElementById('advancedRulesGrid');
        if (!container) return;

        if (!rules || rules.length === 0) {
            container.innerHTML = '<p style="text-align: center; padding: 20px; color: var(--text-secondary);">No rules found</p>';
            return;
        }

        container.innerHTML = `
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                    <tr style="background: var(--background); border-bottom: 2px solid var(--border);">
                        <th style="padding: 10px; text-align: left;">#</th>
                        <th style="padding: 10px; text-align: left;">Action</th>
                        <th style="padding: 10px; text-align: left;">Dir</th>
                        <th style="padding: 10px; text-align: left;">To Port</th>
                        <th style="padding: 10px; text-align: left;">Protocol</th>
                        <th style="padding: 10px; text-align: left;">From</th>
                        <th style="padding: 10px; text-align: left;">IPv6</th>
                    </tr>
                </thead>
                <tbody>
                    ${rules.map(rule => `
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 8px 10px;">${rule.rule_index}</td>
                            <td style="padding: 8px 10px;">
                                <span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; ${getActionStyle(rule.action)}">${rule.action}</span>
                            </td>
                            <td style="padding: 8px 10px;">${rule.direction}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${rule.to_port || 'Any'}</td>
                            <td style="padding: 8px 10px;">${rule.protocol || 'all'}</td>
                            <td style="padding: 8px 10px; font-family: monospace; font-size: 11px;">${rule.from_ip || 'Anywhere'}</td>
                            <td style="padding: 8px 10px;">${rule.is_v6 ? 'Yes' : 'No'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    function getActionStyle(action) {
        switch (action?.toUpperCase()) {
            case 'ALLOW': return `background: ${TC.successBg}; color: ${TC.successDark};`;
            case 'DENY': return `background: ${TC.dangerBg}; color: ${TC.danger};`;
            case 'REJECT': return `background: ${TC.warningBg}; color: ${TC.warningDark};`;
            case 'LIMIT': return `background: ${TC.primaryBg}; color: ${TC.primary};`;
            default: return 'background: var(--surface); color: var(--text-secondary);';
        }
    }

    function getTargetStyle(target) {
        return getActionStyle(target);
    }

    // Global exports
    window.toggleCustomPort = toggleCustomPort;
    window.toggleAdvancedView = toggleAdvancedView;
    window.renderAdvancedRules = renderAdvancedRules;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW IP Details
 * IP details modal for UFW rules with fail2ban history
 */
(function() {
    'use strict';

    async function showUFWIpDetails(ip) {
        if (!ip) return;

        // Use the existing F2B IP modal if available
        if (typeof showBannedIpDetails === 'function') {
            showBannedIpDetails(ip);
            return;
        }

        // Fallback: Create a simple modal
        const modalId = 'ufw-ip-detail-modal';
        let modal = document.getElementById(modalId);
        if (modal) modal.remove();

        modal = document.createElement('div');
        modal.id = modalId;
        modal.className = 'event-detail-modal-overlay';
        modal.innerHTML = `
            <div class="event-detail-modal" style="max-width: 600px;">
                <div class="event-detail-modal-header">
                    <h3>IP Details: ${ip}</h3>
                    <button class="event-detail-modal-close" onclick="document.getElementById('${modalId}').remove()">&times;</button>
                </div>
                <div class="event-detail-modal-body" style="padding: 20px;">
                    <div style="text-align: center; padding: 30px;">
                        <div class="fw-spinner-lg"></div>
                        <div style="margin-top: 12px; color: var(--text-secondary);">Loading IP data...</div>
                    </div>
                </div>
            </div>
        `;
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);

        try {
            const [f2bResponse, geoResponse, blockResponse] = await Promise.all([
                fetch(`/api/dashboard/fail2ban/events?ip=${encodeURIComponent(ip)}&limit=20`).catch(() => ({ ok: false })),
                fetch(`/api/geoip/lookup/${encodeURIComponent(ip)}`).catch(() => ({ ok: false })),
                fetch(`/api/dashboard/blocking/history?ip=${encodeURIComponent(ip)}&limit=10`).catch(() => ({ ok: false }))
            ]);

            const f2bData = f2bResponse.ok ? await f2bResponse.json() : { events: [] };
            const geoData = geoResponse.ok ? await geoResponse.json() : {};
            const blockData = blockResponse.ok ? await blockResponse.json() : { events: [] };

            const events = f2bData.events || [];
            const location = geoData.location || geoData || {};
            const blockEvents = blockData.events || [];

            const banCount = events.filter(e => e.action === 'ban' || e.event_type === 'ban').length;
            const totalFailures = events.reduce((sum, e) => sum + (e.failures || 0), 0);

            const body = modal.querySelector('.event-detail-modal-body');
            body.innerHTML = `
                <div style="margin-bottom: 16px;">
                    <div style="font-size: 20px; font-weight: 700; font-family: monospace; margin-bottom: 4px;">${ip}</div>
                    <div style="color: var(--text-secondary);">
                        ${location.country || 'Unknown'} ${location.city ? '• ' + location.city : ''} • ${location.isp || location.org || 'Unknown ISP'}
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px;">
                    <div style="background: var(--surface); padding: 12px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: ${TC.danger};">${banCount}</div>
                        <div style="font-size: 11px; color: var(--text-secondary);">F2B Bans</div>
                    </div>
                    <div style="background: var(--surface); padding: 12px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: ${TC.orange};">${totalFailures}</div>
                        <div style="font-size: 11px; color: var(--text-secondary);">Failures</div>
                    </div>
                    <div style="background: var(--surface); padding: 12px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: ${TC.teal};">${blockEvents.length}</div>
                        <div style="font-size: 11px; color: var(--text-secondary);">Block Events</div>
                    </div>
                </div>

                <div style="font-weight: 600; margin-bottom: 8px;">Fail2ban History</div>
                <div style="max-height: 200px; overflow-y: auto; background: var(--surface); border-radius: 6px; padding: 8px; margin-bottom: 16px;">
                    ${events.length > 0 ? events.slice(0, 10).map(e => {
                        const icon = (e.action === 'ban' || e.event_type === 'ban') ? '🔒' : '🔓';
                        const action = (e.action === 'ban' || e.event_type === 'ban') ? 'Banned' : 'Unbanned';
                        const time = e.timestamp || e.reported_at;
                        return `
                            <div style="display: flex; align-items: center; gap: 10px; padding: 8px; border-bottom: 1px solid var(--border);">
                                <span>${icon}</span>
                                <span style="flex: 1;">${action} from <strong>${e.jail_name || 'sshd'}</strong></span>
                                ${e.failures ? `<span style="color: var(--text-secondary);">${e.failures} failures</span>` : ''}
                                <span style="color: var(--text-secondary); font-size: 12px;">${time ? formatTimeAgo(time) : ''}</span>
                            </div>
                        `;
                    }).join('') : '<div style="padding: 16px; text-align: center; color: var(--text-secondary);">No fail2ban events</div>'}
                </div>

                <div style="font-weight: 600; margin-bottom: 8px;">Blocking History</div>
                <div style="max-height: 150px; overflow-y: auto; background: var(--surface); border-radius: 6px; padding: 8px;">
                    ${blockEvents.length > 0 ? blockEvents.map(e => `
                        <div style="display: flex; align-items: center; gap: 10px; padding: 8px; border-bottom: 1px solid var(--border);">
                            <span>${e.event_type === 'escalate' ? '⬆️' : '🛡️'}</span>
                            <span style="flex: 1;">${e.event_type === 'escalate' ? 'Escalated to UFW' : 'Blocked'} via ${e.block_source || 'UFW'}</span>
                            <span style="color: var(--text-secondary); font-size: 12px;">${e.created_at ? formatTimeAgo(e.created_at) : ''}</span>
                        </div>
                    `).join('') : '<div style="padding: 16px; text-align: center; color: var(--text-secondary);">No blocking events</div>'}
                </div>
            `;
        } catch (error) {
            const body = modal.querySelector('.event-detail-modal-body');
            body.innerHTML = `
                <div style="text-align: center; padding: 30px; color: var(--text-secondary);">
                    <div style="font-size: 24px; margin-bottom: 8px;">⚠️</div>
                    <div>Failed to load IP details</div>
                    <div style="font-size: 12px; margin-top: 8px;">${error.message}</div>
                </div>
            `;
        }
    }

    // Global exports
    window.showUFWIpDetails = showUFWIpDetails;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW Drag and Drop
 * Rule reordering via drag and drop
 */
(function() {
    'use strict';

    let draggedElement = null;
    let draggedIndex = null;

    function initDragAndDrop() {
        const container = document.getElementById('simpleRulesList');
        if (!container) return;

        const cards = container.querySelectorAll('.simple-rule-card');
        cards.forEach(card => {
            card.addEventListener('dragstart', handleDragStart);
            card.addEventListener('dragover', handleDragOver);
            card.addEventListener('drop', handleDrop);
            card.addEventListener('dragend', handleDragEnd);
            card.addEventListener('dragenter', handleDragEnter);
            card.addEventListener('dragleave', handleDragLeave);
        });
    }

    function handleDragStart(e) {
        draggedElement = this;
        draggedIndex = parseInt(this.dataset.ruleIndex);
        this.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', this.dataset.ruleIndex);
    }

    function handleDragOver(e) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
    }

    function handleDragEnter(e) {
        e.preventDefault();
        if (this !== draggedElement) {
            this.classList.add('drag-over');
        }
    }

    function handleDragLeave(e) {
        this.classList.remove('drag-over');
    }

    function handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();

        this.classList.remove('drag-over');

        if (draggedElement !== this) {
            const targetIndex = parseInt(this.dataset.ruleIndex);
            const sourceIndex = draggedIndex;

            if (sourceIndex !== targetIndex) {
                if (confirm(`Move rule #${sourceIndex} to position #${targetIndex}?`)) {
                    reorderUFWRules(sourceIndex, targetIndex);
                }
            }
        }

        return false;
    }

    function handleDragEnd(e) {
        this.classList.remove('dragging');
        document.querySelectorAll('.simple-rule-card').forEach(card => {
            card.classList.remove('drag-over');
        });
        draggedElement = null;
        draggedIndex = null;
    }

    async function reorderUFWRules(fromIndex, toIndex) {
        if (!window.currentAgentId) return;

        showUFWMessage('Reordering rules... This may take a moment.', 'info');

        try {
            const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/reorder`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    from_index: fromIndex,
                    to_index: toIndex
                })
            });

            const data = await response.json();

            if (data.success) {
                showUFWMessage('Reorder command queued! Syncing...', 'success');
                if (typeof showNotification === 'function') {
                    showNotification('UFW rules reorder queued', 'success');
                }
                await fetch(`/api/agents/${window.currentAgentId}/ufw/request-sync`, { method: 'POST' });
                if (typeof pollForUpdate === 'function') {
                    pollForUpdate(window.currentAgentId);
                }
            } else {
                showUFWMessage(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            showUFWMessage(`Error: ${error.message}`, 'error');
        }
    }

    // Global exports
    window.initDragAndDrop = initDragAndDrop;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW Actions
 * UFW command execution, quick actions, rule management
 */
(function() {
    'use strict';

    async function quickAction(action) {
        if (!window.currentAgentId) {
            showNotification('Please select a server first', 'error');
            return;
        }

        let actionType = '';
        let params = {};
        let confirmMsg = '';

        switch (action) {
            case 'allow-ssh':
                actionType = 'allow_port';
                params = { port: 22, protocol: 'tcp' };
                confirmMsg = 'Allow SSH (port 22) from anywhere?';
                break;
            case 'allow-http':
                if (confirm('Allow HTTP (80) and HTTPS (443) from anywhere?')) {
                    await executeUFWQuickAction('allow_port', { port: 80, protocol: 'tcp' });
                    await executeUFWQuickAction('allow_port', { port: 443, protocol: 'tcp' });
                    return;
                }
                return;
            case 'allow-mysql':
                actionType = 'allow_port';
                params = { port: 3306, protocol: 'tcp' };
                confirmMsg = 'Allow MySQL (port 3306) from anywhere? Consider restricting to specific IPs for security.';
                break;
            case 'limit-ssh':
                actionType = 'limit_port';
                params = { port: 22, protocol: 'tcp' };
                confirmMsg = 'Enable SSH rate limiting (brute force protection)?';
                break;
            case 'enable':
                actionType = 'enable';
                confirmMsg = 'Enable UFW firewall?';
                break;
            case 'disable':
                actionType = 'disable';
                confirmMsg = 'WARNING: This will disable the firewall completely. Are you sure?';
                break;
        }

        if (confirmMsg && confirm(confirmMsg)) {
            await executeUFWQuickAction(actionType, params);
        }
    }

    function updateUFWToggleButton(isActive) {
        const toggleBtn = document.getElementById('ufwToggleBtn');
        if (!toggleBtn) return;

        const icon = toggleBtn.querySelector('.toggle-icon');
        const text = toggleBtn.querySelector('.toggle-text');

        if (isActive) {
            toggleBtn.setAttribute('data-status', 'active');
            if (icon) icon.textContent = '🛡️';
            if (text) text.textContent = 'UFW Active';
        } else {
            toggleBtn.setAttribute('data-status', 'inactive');
            if (icon) icon.textContent = '⚠️';
            if (text) text.textContent = 'UFW Disabled';
        }
    }

    async function toggleUFW() {
        if (!window.currentAgentId) {
            showNotification('Please select a server first', 'error');
            return;
        }

        const toggleBtn = document.getElementById('ufwToggleBtn');
        const currentStatus = toggleBtn?.getAttribute('data-status');

        if (currentStatus === 'unknown') {
            showNotification('UFW status is loading, please wait...', 'warning');
            return;
        }

        const isCurrentlyActive = currentStatus === 'active';
        const action = isCurrentlyActive ? 'disable' : 'enable';
        const confirmMsg = isCurrentlyActive
            ? 'WARNING: This will disable the firewall completely. Are you sure?'
            : 'Enable UFW firewall?';

        if (confirm(confirmMsg)) {
            const text = toggleBtn?.querySelector('.toggle-text');
            const icon = toggleBtn?.querySelector('.toggle-icon');
            if (text) text.textContent = 'Processing...';
            if (icon) icon.textContent = '⏳';
            toggleBtn?.setAttribute('data-status', 'unknown');

            await executeUFWQuickAction(action, {});
        }
    }

    async function addSimpleRule() {
        if (!window.currentAgentId) {
            showUFWMessage('Please select a server first', 'error');
            return;
        }

        const action = document.getElementById('simpleRuleAction')?.value;
        const protocol = document.getElementById('simpleRuleProtocol')?.value || 'tcp';
        let port = document.getElementById('simpleRulePort')?.value;
        let source = document.getElementById('simpleRuleCustomSource')?.value?.trim();

        if (port === 'custom') {
            port = document.getElementById('simpleRuleCustomPort')?.value?.trim();
            if (!port) {
                showUFWMessage('Please enter a custom port', 'error');
                return;
            }
        }

        let actionType;
        const params = { protocol: protocol === 'all' ? 'tcp' : protocol };

        if (source) {
            actionType = action === 'ACCEPT' ? 'allow_ip' : 'block_ip';
            params.ip = source;
            if (port && port !== 'any') params.port = port;
        } else if (port && port !== 'any') {
            actionType = action === 'ACCEPT' ? 'allow_port' : 'deny_port';
            params.port = port;
        } else {
            showUFWMessage('Please specify a port or source IP', 'error');
            return;
        }

        await executeUFWQuickAction(actionType, params);
    }

    async function deleteUFWRule(ruleIndex) {
        if (!window.currentAgentId) return;
        if (!confirm(`Remove UFW rule #${ruleIndex}?`)) return;
        await executeUFWQuickAction('delete_rule', { rule_number: ruleIndex });
    }

    async function deleteSimpleRule(table, chain, ruleNum) {
        await deleteUFWRule(ruleNum);
    }

    async function executeUFWQuickAction(actionType, params = {}) {
        if (typeof window.showGlobalSync === 'function') {
            window.showGlobalSync('ufw', `Executing ${actionType.replace('_', ' ')}...`);
        } else {
            showUFWSyncIndicator('Executing...');
        }

        try {
            const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/quick-action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action_type: actionType, ...params })
            });

            const data = await response.json();

            if (data.executed) {
                if (data.success) {
                    if (typeof window.completeSyncOperation === 'function') {
                        window.completeSyncOperation(true, data.message || 'Done');
                    } else {
                        hideUFWSyncIndicator();
                        showUFWMessage(data.message || 'Command executed', 'success');
                        if (typeof window.loadUFWData === 'function' && window.currentAgentId) {
                            setTimeout(() => window.loadUFWData(window.currentAgentId, true), 500);
                        }
                    }
                } else {
                    if (typeof window.completeSyncOperation === 'function') {
                        window.completeSyncOperation(false, data.message || 'Command failed');
                    } else {
                        hideUFWSyncIndicator();
                        showUFWMessage(`Error: ${data.message || 'Command failed'}`, 'error');
                    }
                }
            } else if (data.success) {
                addToCommandQueue(data.command_id, data.ufw_command, 'pending');
                if (typeof window.updateSyncProgress === 'function') {
                    window.updateSyncProgress('Waiting for agent...', 'info');
                } else {
                    updateUFWSyncText('Waiting for agent...');
                    showUFWMessage('Command queued', 'success');
                }
                await fetch(`/api/agents/${window.currentAgentId}/ufw/request-sync`, { method: 'POST' });
                pollCommandCompletion(data.command_id);
            } else {
                if (typeof window.completeSyncOperation === 'function') {
                    window.completeSyncOperation(false, data.error || 'Unknown error');
                } else {
                    hideUFWSyncIndicator();
                    showUFWMessage(`Error: ${data.error}`, 'error');
                }
            }
        } catch (error) {
            if (typeof window.completeSyncOperation === 'function') {
                window.completeSyncOperation(false, error.message);
            } else {
                hideUFWSyncIndicator();
                showUFWMessage(`Error: ${error.message}`, 'error');
            }
        }
    }

    async function pollCommandCompletion(commandId, attempts = 0) {
        if (attempts > 30) return;

        const cmd = window.ufwCommandQueue.find(c => c.id === commandId);
        if (!cmd || cmd.status !== 'pending') return;

        setTimeout(async () => {
            try {
                const resp = await fetch(`/api/agents/${window.currentAgentId}/ufw?force=true`);
                const data = await resp.json();

                if (data.recent_commands) {
                    const serverCmd = data.recent_commands.find(c => c.command_uuid === commandId);
                    if (serverCmd) {
                        if (serverCmd.status === 'completed') {
                            updateCommandStatus(commandId, 'completed', serverCmd.result_message);
                            return;
                        } else if (serverCmd.status === 'failed') {
                            updateCommandStatus(commandId, 'failed', serverCmd.result_message);
                            return;
                        }
                    }
                }
                pollCommandCompletion(commandId, attempts + 1);
            } catch (e) {
                pollCommandCompletion(commandId, attempts + 1);
            }
        }, 1000);
    }

    function pollForUpdate(agentId, attempts = 0) {
        if (attempts > 10) {
            if (typeof window.loadUFWData === 'function') {
                window.loadUFWData(agentId, true);
            }
            return;
        }
        setTimeout(async () => {
            try {
                const resp = await fetch(`/api/agents/${agentId}/ufw`);
                const data = await resp.json();
                if (data.success && data.has_data) {
                    if (typeof window.loadUFWData === 'function') {
                        window.loadUFWData(agentId, true);
                    }
                } else {
                    pollForUpdate(agentId, attempts + 1);
                }
            } catch (e) {
                pollForUpdate(agentId, attempts + 1);
            }
        }, 1000);
    }

    async function executeUFWCommand(commandType, params) {
        showUFWSyncIndicator('Adding rule...');

        try {
            const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command_type: commandType, params })
            });

            const data = await response.json();

            if (data.success) {
                const cmdText = data.ufw_command || `ufw ${commandType}`;
                addToCommandQueue(data.command_id, cmdText, 'pending');
                showUFWMessage('Command queued', 'success');
                updateUFWSyncText('Waiting for agent...');
                await fetch(`/api/agents/${window.currentAgentId}/ufw/request-sync`, { method: 'POST' });
                pollCommandCompletion(data.command_id);
            } else {
                hideUFWSyncIndicator();
                showUFWMessage(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            hideUFWSyncIndicator();
            showUFWMessage(`Error: ${error.message}`, 'error');
        }
    }

    async function executeFirewallCommand(action, params) {
        let commandType = action;
        if (action === 'add_rule') {
            commandType = params.target === 'ACCEPT' ? 'allow' : 'deny';
        } else if (action === 'delete_rule') {
            return deleteUFWRule(params.rule_num);
        }
        return executeUFWCommand(commandType, params);
    }

    function showUFWMessage(message, type) {
        if (window.syncState?.isActive) return;

        if (typeof window.showToast === 'function') {
            window.showToast(message, type === 'error' ? 'error' : (type === 'info' ? 'info' : 'success'));
            return;
        }
        const el = document.getElementById('addRuleMessage');
        if (!el) return;
        el.style.display = 'block';
        el.textContent = message;
        el.style.background = type === 'error' ? TC.dangerBg :
                              type === 'success' ? TC.successBg : TC.primaryBg;
        el.style.color = type === 'error' ? TC.danger : type === 'success' ? TC.successDark : TC.primary;
        if (type !== 'error') setTimeout(() => { if (el) el.style.display = 'none'; }, 3000);
    }

    function showNotification(message, type) {
        if (typeof window.showToast === 'function') window.showToast(message, type);
    }

    // Global exports
    window.quickAction = quickAction;
    window.toggleUFW = toggleUFW;
    window.updateUFWToggleButton = updateUFWToggleButton;
    window.addSimpleRule = addSimpleRule;
    window.deleteUFWRule = deleteUFWRule;
    window.deleteSimpleRule = deleteSimpleRule;
    window.executeUFWQuickAction = executeUFWQuickAction;
    window.showUFWMessage = showUFWMessage;
})();
/**
 * SSH Guardian v3.0 - Firewall UFW Index
 * Module initialization
 */
(function() {
    'use strict';
    console.log('[Firewall UFW] Module initialized');
})();
