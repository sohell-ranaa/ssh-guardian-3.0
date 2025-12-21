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
