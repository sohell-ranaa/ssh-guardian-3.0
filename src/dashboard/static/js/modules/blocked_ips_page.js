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
        primary: '#0078D4',
        primaryDark: '#004C87',
        danger: '#D13438',
        success: '#107C10',
        successDark: '#0B6A0B',
        warning: '#FFB900',
        purple: '#8764B8',
        textSecondary: '#605E5C',
        textPrimary: '#323130',
        orangeDark: '#CA5010',
        primaryHover: '#106EBE'
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
/**
 * Blocked IPs - UI Module
 * UI helpers, badges, notifications, location enrichment
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml || ((t) => t == null ? '' : String(t).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[m]));
    const TC = window.TC || { primary:'#0078D4', danger:'#D13438', success:'#107C10', warning:'#FFB900', purple:'#8764B8', textSecondary:'#605E5C', orangeDark:'#CA5010' };

    BlockedIPs.UI = {
        /**
         * Get source badge HTML
         */
        getSourceBadge(source) {
            const sourceStyles = {
                'auto': { bg: TC.danger, icon: '🤖', label: 'Auto' },
                'manual': { bg: TC.primary, icon: '👤', label: 'Manual' },
                'fail2ban': { bg: TC.warning, icon: '🛡️', label: 'Fail2ban' },
                'firewall': { bg: TC.purple, icon: '🔥', label: 'Firewall' },
                'ml': { bg: TC.orangeDark, icon: '🧠', label: 'ML' }
            };

            const style = sourceStyles[source?.toLowerCase()] || { bg: TC.textSecondary, icon: '❓', label: source || 'Unknown' };

            return `<span style="padding: 4px 10px; background: ${style.bg}; color: white; border-radius: 3px; font-size: 11px; font-weight: 500;">
                ${style.icon} ${style.label}
            </span>`;
        },

        /**
         * Update block statistics
         */
        updateStats(blocks) {
            const total = blocks.length;
            const active = blocks.filter(b => b.is_active).length;
            const expired = blocks.filter(b => !b.is_active).length;
            const permanent = blocks.filter(b => !b.unblock_at).length;

            const totalEl = document.getElementById('stat-blocks-total');
            const activeEl = document.getElementById('stat-blocks-active');
            const expiredEl = document.getElementById('stat-blocks-expired');
            const permanentEl = document.getElementById('stat-blocks-permanent');

            if (totalEl) totalEl.textContent = total;
            if (activeEl) activeEl.textContent = active;
            if (expiredEl) expiredEl.textContent = expired;
            if (permanentEl) permanentEl.textContent = permanent;
        },

        /**
         * Show notification
         */
        notify(message, type = 'info') {
            if (typeof window.showToast === 'function') {
                window.showToast(message, type);
            } else {
                console.log(`[${type.toUpperCase()}] ${message}`);
            }
        },

        /**
         * Enrich blocks with location data
         */
        async enrichLocations(blocks) {
            const uniqueIPs = [...new Set(blocks.map(b => b.ip_address))];

            for (const ip of uniqueIPs) {
                try {
                    const response = await fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ip)}`);
                    const data = await response.json();

                    const cells = document.querySelectorAll(`.ip-location-cell[data-ip="${ip}"]`);
                    cells.forEach(cell => {
                        if (data.success) {
                            const flagImg = data.country_code && data.country_code !== 'N/A'
                                ? `<img src="https://flagcdn.com/16x12/${data.country_code.toLowerCase()}.png" alt="${data.country_code}" style="vertical-align: middle; margin-right: 6px;">`
                                : '';
                            const locationText = data.country_code === 'N/A'
                                ? 'Unknown Location'
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
    };
})();
/**
 * Blocked IPs - Filters Module
 * Search, filter, and agent dropdown functionality
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml;

    BlockedIPs.Filters = {
        /**
         * Load agents for filter dropdown
         */
        async loadAgentsForDropdown() {
            try {
                const response = await fetch('/api/agents/list');
                const data = await response.json();

                if (!data.agents) return;

                const agentFilter = document.getElementById('blockAgentFilter');
                if (!agentFilter) return;

                agentFilter.innerHTML = '<option value="">All Agents (Global)</option>';

                (data.agents || []).forEach(agent => {
                    const option = document.createElement('option');
                    option.value = agent.id;
                    option.textContent = agent.display_name || agent.hostname || `Agent ${agent.id}`;
                    agentFilter.appendChild(option);
                });

                BlockedIPs.state.agents = data.agents;
            } catch (error) {
                console.error('Error loading agents for filter:', error);
            }
        },

        /**
         * Populate agent filter from blocks data
         */
        populateAgentDropdown(uniqueAgents) {
            const filterSelect = document.getElementById('blockSourceAgentFilter');
            if (!filterSelect) return;

            const currentValue = filterSelect.value;
            filterSelect.innerHTML = '<option value="">All Sources</option>';

            uniqueAgents.sort().forEach(agent => {
                const option = document.createElement('option');
                option.value = agent;
                option.textContent = agent;
                filterSelect.appendChild(option);
            });

            filterSelect.value = currentValue;
        },

        /**
         * Setup all filters
         */
        setupAll() {
            this.setupSearchFilter();
            this.setupAgentFilter();
            this.setupSourceFilter();
            this.setupStatusFilter();
        },

        /**
         * Setup search filter
         */
        setupSearchFilter() {
            const searchInput = document.getElementById('blockSearchFilter');
            if (!searchInput) return;

            let debounceTimer;
            searchInput.addEventListener('input', () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => this.applyFilters(), 300);
            });
        },

        /**
         * Setup agent filter
         */
        setupAgentFilter() {
            const agentFilter = document.getElementById('blockAgentFilter');
            if (!agentFilter) return;

            agentFilter.addEventListener('change', () => {
                BlockedIPs.state.currentAgentFilter = agentFilter.value;
                BlockedIPs.Core.loadIPBlocks();
            });
        },

        /**
         * Setup source filter
         */
        setupSourceFilter() {
            const sourceFilter = document.getElementById('blockSourceAgentFilter');
            if (!sourceFilter) return;

            sourceFilter.addEventListener('change', () => this.applyFilters());
        },

        /**
         * Setup status filter
         */
        setupStatusFilter() {
            const statusFilter = document.getElementById('blockStatusFilter');
            if (!statusFilter) return;

            statusFilter.addEventListener('change', () => this.applyFilters());
        },

        /**
         * Apply all filters to table
         */
        applyFilters() {
            const searchValue = (document.getElementById('blockSearchFilter')?.value || '').toLowerCase();
            const sourceValue = document.getElementById('blockSourceAgentFilter')?.value || '';
            const statusValue = document.getElementById('blockStatusFilter')?.value || '';

            const rows = document.querySelectorAll('#blocksTableBody tr');

            rows.forEach(row => {
                const ip = row.dataset.ip?.toLowerCase() || '';
                const agent = row.dataset.agent || '';
                const source = row.dataset.source?.toLowerCase() || '';
                const isActive = row.querySelector('[style*="background: var(--color-danger)"]') ||
                                 row.querySelector('[style*="background: rgb(209, 52, 56)"]');

                let show = true;

                // Search filter
                if (searchValue && !ip.includes(searchValue)) {
                    show = false;
                }

                // Source/Agent filter
                if (sourceValue && agent !== sourceValue) {
                    show = false;
                }

                // Status filter
                if (statusValue === 'active' && !isActive) {
                    show = false;
                } else if (statusValue === 'expired' && isActive) {
                    show = false;
                }

                row.style.display = show ? '' : 'none';
            });
        }
    };
})();
/**
 * Blocked IPs - Forms Module
 * Manual block/unblock forms and form toggles
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};

    BlockedIPs.Forms = {
        /**
         * Setup all forms
         */
        setupAll() {
            this.setupFormToggles();
            this.setupManualBlockForm();
            this.setupManualUnblockForm();
            this.setupRefreshButton();
        },

        /**
         * Setup form section toggles
         */
        setupFormToggles() {
            const toggles = document.querySelectorAll('[data-toggle-form]');
            toggles.forEach(toggle => {
                toggle.addEventListener('click', () => {
                    const formId = toggle.dataset.toggleForm;
                    const formSection = document.getElementById(formId);
                    if (formSection) {
                        const isVisible = formSection.style.display !== 'none';
                        formSection.style.display = isVisible ? 'none' : 'block';
                        toggle.classList.toggle('active', !isVisible);
                    }
                });
            });
        },

        /**
         * Setup manual block form
         */
        setupManualBlockForm() {
            const form = document.getElementById('manualBlockForm');
            if (!form) return;

            form.addEventListener('submit', async (e) => {
                e.preventDefault();

                const ipInput = document.getElementById('blockIpAddress');
                const reasonInput = document.getElementById('blockReason');
                const durationSelect = document.getElementById('blockDuration');
                const agentSelect = document.getElementById('blockAgentFilter');
                const submitBtn = form.querySelector('button[type="submit"]');

                const ip = ipInput?.value?.trim();
                const reason = reasonInput?.value?.trim() || 'Manual block from dashboard';
                const duration = parseInt(durationSelect?.value) || 0;
                const agentId = agentSelect?.value || null;

                if (!ip) {
                    BlockedIPs.UI.notify('Please enter an IP address', 'error');
                    return;
                }

                // Validate IP format
                if (!window.isValidIPv4 || !window.isValidIPv4(ip)) {
                    BlockedIPs.UI.notify('Invalid IP address format', 'error');
                    return;
                }

                try {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Blocking...';

                    const payload = {
                        ip_address: ip,
                        reason: reason,
                        duration_hours: duration || null
                    };

                    if (agentId) {
                        payload.agent_id = agentId;
                    }

                    const response = await fetch('/api/dashboard/blocking/blocks/manual', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    const data = await response.json();

                    if (data.success) {
                        BlockedIPs.UI.notify(`IP ${ip} has been blocked`, 'success');
                        form.reset();
                        BlockedIPs.Core.loadIPBlocks();
                    } else {
                        BlockedIPs.UI.notify(`Failed to block IP: ${data.error || 'Unknown error'}`, 'error');
                    }
                } catch (error) {
                    console.error('Error blocking IP:', error);
                    BlockedIPs.UI.notify(`Error blocking IP: ${error.message}`, 'error');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Block IP';
                }
            });
        },

        /**
         * Setup manual unblock form
         */
        setupManualUnblockForm() {
            const form = document.getElementById('manualUnblockForm');
            if (!form) return;

            form.addEventListener('submit', async (e) => {
                e.preventDefault();

                const ipInput = document.getElementById('unblockIpAddress');
                const reasonInput = document.getElementById('unblockReason');
                const submitBtn = form.querySelector('button[type="submit"]');

                const ip = ipInput?.value?.trim();
                const reason = reasonInput?.value?.trim() || 'Manual unblock from dashboard';

                if (!ip) {
                    BlockedIPs.UI.notify('Please enter an IP address', 'error');
                    return;
                }

                try {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Unblocking...';

                    const response = await fetch('/api/dashboard/blocking/blocks/unblock', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            ip_address: ip,
                            reason: reason
                        })
                    });

                    const data = await response.json();

                    if (data.success) {
                        BlockedIPs.UI.notify(`IP ${ip} has been unblocked`, 'success');
                        form.reset();
                        BlockedIPs.Core.loadIPBlocks();
                    } else {
                        BlockedIPs.UI.notify(`Failed to unblock IP: ${data.error || 'Unknown error'}`, 'error');
                    }
                } catch (error) {
                    console.error('Error unblocking IP:', error);
                    BlockedIPs.UI.notify(`Error unblocking IP: ${error.message}`, 'error');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Unblock IP';
                }
            });
        },

        /**
         * Setup refresh button
         */
        setupRefreshButton() {
            const refreshBtn = document.getElementById('refreshBlocksBtn');
            if (!refreshBtn) return;

            refreshBtn.addEventListener('click', () => {
                BlockedIPs.Core.loadIPBlocks();
            });
        }
    };
})();
/**
 * Blocked IPs - Modal Module
 * IP details modal and styling
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml || ((t) => t == null ? '' : String(t).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[m]));
    const formatLocalDateTime = window.formatLocalDateTime || ((d) => d ? new Date(d).toLocaleString() : 'N/A');
    const TC = window.TC || { primary:'#0078D4', primaryDark:'#004C87', primaryHover:'#106EBE', danger:'#D13438', success:'#107C10', successDark:'#0B6A0B', warning:'#FFB900', purple:'#8764B8', textSecondary:'#605E5C', textPrimary:'#323130' };

    BlockedIPs.Modal = {
        stylesInjected: false,

        /**
         * Fetch with timeout helper
         */
        async fetchWithTimeout(url, timeoutMs = 5000) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
            try {
                const response = await fetch(url, { signal: controller.signal });
                clearTimeout(timeoutId);
                return response;
            } catch (e) {
                clearTimeout(timeoutId);
                throw e;
            }
        },

        /**
         * Show IP details modal
         */
        async showDetails(ipAddress) {
            if (!ipAddress) {
                BlockedIPs.UI.notify('No IP address provided', 'error');
                return;
            }

            // Show loading modal
            this.show('Loading...', `
                <div style="text-align: center; padding: 40px;">
                    <div style="font-size: 24px; margin-bottom: 16px;">⏳</div>
                    <p>Loading details for ${escapeHtml(ipAddress)}...</p>
                </div>
            `);

            // Fetch data with timeouts - don't fail if one API is slow
            let status = { success: false };
            let geoInfo = { success: false };

            try {
                const results = await Promise.allSettled([
                    this.fetchWithTimeout(`/api/dashboard/event-actions/ip-status/${encodeURIComponent(ipAddress)}`, 5000)
                        .then(r => r.json()),
                    // Use threat-intel endpoint which checks database first (much faster than external APIs)
                    this.fetchWithTimeout(`/api/threat-intel/lookup/${encodeURIComponent(ipAddress)}`, 5000)
                        .then(r => r.json())
                        .then(r => {
                            // Map threat-intel response to geoInfo format
                            if (r.success && r.data) {
                                return {
                                    success: true,
                                    country: r.data.country_name,
                                    country_code: r.data.country_code,
                                    city: r.data.city,
                                    region: r.data.region,
                                    isp: r.data.isp || r.data.asn_org,
                                    asn: r.data.asn,
                                    is_proxy: r.data.is_proxy || r.data.is_vpn || r.data.is_tor,
                                    is_private: false,
                                    from_cache: r.from_cache,
                                    // Threat intel data
                                    threat_level: r.data.threat_level,
                                    abuseipdb_score: r.data.abuseipdb_score,
                                    abuseipdb_reports: r.data.abuseipdb_reports,
                                    is_tor: r.data.is_tor,
                                    is_vpn: r.data.is_vpn,
                                    is_datacenter: r.data.is_datacenter
                                };
                            }
                            return r;
                        })
                ]);

                if (results[0].status === 'fulfilled') status = results[0].value;
                if (results[1].status === 'fulfilled') geoInfo = results[1].value;

                const content = this.buildDetailsContent(ipAddress, status, geoInfo);
                this.show(`IP Details: ${ipAddress}`, content, { icon: '🔍 ' });

            } catch (error) {
                console.error('Error loading IP details:', error);
                // Still show what we have
                const content = this.buildDetailsContent(ipAddress, status, geoInfo);
                this.show(`IP Details: ${ipAddress}`, content, { icon: '🔍 ' });
            }
        },

        /**
         * Build details modal content
         */
        buildDetailsContent(ipAddress, status, geoInfo) {
            // Status badges
            const statusBadges = [];
            if (status?.is_blocked) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.danger}; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Blocked</span>`);
            }
            if (status?.is_whitelisted) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.successDark}; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Whitelisted</span>`);
            }
            if (status?.is_watched) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.warning}; color: ${TC.textPrimary}; border-radius: 3px; font-size: 11px; margin-right: 5px;">Watched</span>`);
            }
            if (geoInfo?.is_proxy) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.purple}; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Proxy/VPN</span>`);
            }
            if (statusBadges.length === 0) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.textSecondary}; color: white; border-radius: 3px; font-size: 11px;">No Special Status</span>`);
            }

            // Geolocation section
            let geoSection = '';
            if (geoInfo?.success) {
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
                        </div>
                    </div>
                `;

                // Add threat intel section if we have data
                if (geoInfo.threat_level || geoInfo.abuseipdb_score !== undefined) {
                    const threatColor = geoInfo.threat_level === 'critical' || geoInfo.threat_level === 'high' ? TC.danger :
                                        geoInfo.threat_level === 'medium' ? '#f59e0b' : TC.success;
                    const abuseScore = geoInfo.abuseipdb_score || 0;
                    const abuseColor = abuseScore >= 70 ? TC.danger : abuseScore >= 40 ? '#f59e0b' : TC.success;

                    const networkFlags = [];
                    if (geoInfo.is_tor) networkFlags.push('<span style="background:#7c3aed;color:white;padding:2px 6px;border-radius:3px;font-size:10px;margin-right:4px;">TOR</span>');
                    if (geoInfo.is_vpn) networkFlags.push('<span style="background:#2563eb;color:white;padding:2px 6px;border-radius:3px;font-size:10px;margin-right:4px;">VPN</span>');
                    if (geoInfo.is_datacenter) networkFlags.push('<span style="background:#64748b;color:white;padding:2px 6px;border-radius:3px;font-size:10px;margin-right:4px;">Datacenter</span>');
                    if (geoInfo.is_proxy) networkFlags.push('<span style="background:#8b5cf6;color:white;padding:2px 6px;border-radius:3px;font-size:10px;margin-right:4px;">Proxy</span>');

                    geoSection += `
                    <div class="ip-detail-section">
                        <div class="ip-detail-section-title">Threat Intelligence</div>
                        <div class="ip-detail-grid">
                            <div>
                                <div class="ip-detail-item-label">Threat Level</div>
                                <div class="ip-detail-item-value"><span style="color:${threatColor};font-weight:600;">${escapeHtml((geoInfo.threat_level || 'unknown').toUpperCase())}</span></div>
                            </div>
                            <div>
                                <div class="ip-detail-item-label">AbuseIPDB Score</div>
                                <div class="ip-detail-item-value"><span style="color:${abuseColor};font-weight:600;">${abuseScore}%</span> (${geoInfo.abuseipdb_reports || 0} reports)</div>
                            </div>
                            ${networkFlags.length > 0 ? `
                            <div style="grid-column: span 2;">
                                <div class="ip-detail-item-label">Network Flags</div>
                                <div class="ip-detail-item-value">${networkFlags.join('')}</div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    `;
                }
            }

            return `
                <div class="ip-detail-content">
                    <div class="ip-detail-header">
                        <div class="ip-detail-ip">${escapeHtml(ipAddress)}</div>
                        <div class="ip-detail-status">${statusBadges.join('')}</div>
                    </div>
                    ${geoSection}
                </div>
            `;
        },

        /**
         * Show modal
         */
        show(title, content, options = {}) {
            this.injectStyles();

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
            document.body.style.overflow = 'hidden';

            const closeModal = () => {
                overlay.style.animation = 'blockModalFadeIn 0.15s ease-out reverse';
                modal.style.animation = 'blockModalSlideIn 0.15s ease-out reverse';
                setTimeout(() => {
                    overlay.remove();
                    document.body.style.overflow = '';
                }, 140);
            };

            modal.querySelector('.block-modal-close').onclick = closeModal;
            modal.querySelector('.modal-close-action').onclick = closeModal;
            overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };

            const keyHandler = (e) => {
                if (e.key === 'Escape') {
                    closeModal();
                    document.removeEventListener('keydown', keyHandler);
                }
            };
            document.addEventListener('keydown', keyHandler);

            return { overlay, modal, closeModal };
        },

        /**
         * Inject modal styles
         */
        injectStyles() {
            if (this.stylesInjected) return;
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
                    background: rgba(0, 0, 0, 0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 10000;
                    animation: blockModalFadeIn 0.2s ease-out;
                }
                .block-modal {
                    background: var(--surface);
                    border-radius: 8px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                    max-width: 600px;
                    width: 90%;
                    max-height: 85vh;
                    overflow: hidden;
                    animation: blockModalSlideIn 0.2s ease-out;
                }
                .block-modal-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 16px 20px;
                    background: linear-gradient(135deg, ${TC.primary} 0%, ${TC.primaryDark} 100%);
                    color: white;
                }
                .block-modal-title {
                    margin: 0;
                    font-size: 16px;
                    font-weight: 600;
                }
                .block-modal-close {
                    background: none;
                    border: none;
                    color: rgba(255, 255, 255, 0.8);
                    font-size: 24px;
                    cursor: pointer;
                    padding: 0;
                    line-height: 1;
                }
                .block-modal-close:hover { color: white; }
                .block-modal-body {
                    padding: 20px;
                    max-height: 60vh;
                    overflow-y: auto;
                }
                .block-modal-footer {
                    padding: 16px 20px;
                    border-top: 1px solid var(--border);
                    display: flex;
                    justify-content: flex-end;
                }
                .block-modal-btn {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    font-size: 13px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.15s;
                }
                .block-modal-btn-primary {
                    background: ${TC.primary};
                    color: white;
                }
                .block-modal-btn-primary:hover { background: ${TC.primaryHover}; }
                .block-modal-btn-secondary {
                    background: var(--background);
                    color: var(--text-primary);
                    border: 1px solid var(--border);
                }
                .block-modal-btn-secondary:hover { background: var(--border); }

                .ip-detail-content { }
                .ip-detail-header {
                    text-align: center;
                    padding-bottom: 16px;
                    border-bottom: 1px solid var(--border);
                    margin-bottom: 16px;
                }
                .ip-detail-ip {
                    font-size: 24px;
                    font-weight: 700;
                    font-family: var(--font-mono);
                    margin-bottom: 8px;
                }
                .ip-detail-status { }
                .ip-detail-section {
                    margin-bottom: 16px;
                    padding: 16px;
                    background: var(--background);
                    border-radius: 6px;
                }
                .ip-detail-section-title {
                    font-size: 13px;
                    font-weight: 600;
                    color: var(--text-secondary);
                    margin-bottom: 12px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                .ip-detail-grid {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 12px;
                }
                .ip-detail-item-label {
                    font-size: 11px;
                    color: var(--text-hint);
                    margin-bottom: 2px;
                }
                .ip-detail-item-value {
                    font-size: 13px;
                    color: var(--text-primary);
                }

                @keyframes blockModalFadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                @keyframes blockModalSlideIn {
                    from { transform: translateY(-20px); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }

                @media (max-width: 600px) {
                    .block-modal { width: 95%; }
                    .ip-detail-grid { grid-template-columns: 1fr; }
                }
            `;
            document.head.appendChild(style);
            this.stylesInjected = true;
        }
    };
})();
/**
 * Blocked IPs - Actions Module
 * Block/Unblock/Delete operations
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml || ((t) => t == null ? '' : String(t).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[m]));
    const TC = window.TC || { primary:'#0078D4', danger:'#D13438', success:'#107C10', warning:'#FFB900', purple:'#8764B8', textSecondary:'#605E5C' };

    BlockedIPs.Actions = {
        /**
         * Unblock IP from table
         */
        async unblock(ipAddress, blockId) {
            if (!confirm(`Unblock IP: ${ipAddress}?`)) return;
            await this.unblockIP(ipAddress, 'Unblocked from IP Blocks page');
        },

        /**
         * Re-block a previously unblocked IP
         */
        async reblock(ipAddress) {
            if (!confirm(`Re-block IP: ${ipAddress}?`)) return;

            try {
                const response = await fetch('/api/dashboard/blocking/blocks/manual', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        reason: 'Re-blocked from IP Blocks page',
                        duration_hours: 24
                    })
                });

                const data = await response.json();

                if (data.success) {
                    BlockedIPs.UI.notify(`IP ${ipAddress} has been re-blocked`, 'success');
                    BlockedIPs.Core.loadIPBlocks();
                } else {
                    BlockedIPs.UI.notify(`Failed to re-block IP: ${data.error || 'Unknown error'}`, 'error');
                }
            } catch (error) {
                console.error('Error re-blocking IP:', error);
                BlockedIPs.UI.notify(`Error re-blocking IP: ${error.message}`, 'error');
            }
        },

        /**
         * Disable block (unblock but keep record)
         */
        async disable(ipAddress, blockId) {
            if (!confirm(`Disable block for IP: ${ipAddress}?\n\nThis will unblock the IP but keep the record for reference.`)) {
                return;
            }
            await this.unblockIP(ipAddress, 'Disabled from IP Blocks page');
        },

        /**
         * Unblock IP address
         */
        async unblockIP(ipAddress, reason) {
            try {
                const response = await fetch('/api/dashboard/blocking/blocks/unblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        reason: reason || 'Unblocked from dashboard'
                    })
                });

                const data = await response.json();

                if (data.success) {
                    BlockedIPs.UI.notify(`IP ${ipAddress} has been unblocked`, 'success');
                    BlockedIPs.Core.loadIPBlocks();
                } else {
                    BlockedIPs.UI.notify(`Failed to unblock IP: ${data.error || 'Unknown error'}`, 'error');
                }
            } catch (error) {
                console.error('Error unblocking IP:', error);
                BlockedIPs.UI.notify(`Error unblocking IP: ${error.message}`, 'error');
            }
        },

        /**
         * Show delete confirmation modal
         */
        confirmDelete(ipAddress, blockId) {
            BlockedIPs.Modal.injectStyles();

            document.querySelectorAll('.block-modal-overlay').forEach(el => el.remove());

            const overlay = document.createElement('div');
            overlay.className = 'block-modal-overlay';

            const modal = document.createElement('div');
            modal.className = 'block-modal';

            modal.innerHTML = `
                <div class="block-modal-header" style="background: linear-gradient(135deg, ${TC.danger} 0%, ${TC.danger} 100%);">
                    <h3 class="block-modal-title" style="color: white;">
                        <span style="font-size: 20px;">⚠️</span>
                        Delete Block Record
                    </h3>
                    <button class="block-modal-close" style="color: rgba(255,255,255,0.8);" title="Close">&times;</button>
                </div>
                <div class="block-modal-body" style="padding: 24px;">
                    <p style="margin-bottom: 16px;">This will <strong>permanently delete</strong> the block record for:</p>
                    <div style="background: var(--background); padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 16px; margin-bottom: 16px;">
                        ${escapeHtml(ipAddress)}
                    </div>
                    <p style="color: ${TC.danger}; margin-bottom: 16px;">⚠️ This action cannot be undone.</p>
                    <p style="margin-bottom: 8px;">Type the IP address to confirm:</p>
                    <input type="text" id="deleteConfirmInput" class="form-control" placeholder="Enter IP address" style="margin-bottom: 16px;">
                </div>
                <div class="block-modal-footer" style="justify-content: flex-end; gap: 10px;">
                    <button class="block-modal-btn block-modal-btn-secondary modal-cancel">Cancel</button>
                    <button class="block-modal-btn" id="confirmDeleteBtn" style="background: ${TC.danger}; color: white; opacity: 0.5; pointer-events: none;">Delete Record</button>
                </div>
            `;

            overlay.appendChild(modal);
            document.body.appendChild(overlay);
            document.body.style.overflow = 'hidden';

            const input = modal.querySelector('#deleteConfirmInput');
            const deleteBtn = modal.querySelector('#confirmDeleteBtn');

            input.addEventListener('input', () => {
                if (input.value === ipAddress) {
                    deleteBtn.style.opacity = '1';
                    deleteBtn.style.pointerEvents = 'auto';
                } else {
                    deleteBtn.style.opacity = '0.5';
                    deleteBtn.style.pointerEvents = 'none';
                }
            });

            const closeModal = () => {
                overlay.remove();
                document.body.style.overflow = '';
            };

            modal.querySelector('.block-modal-close').onclick = closeModal;
            modal.querySelector('.modal-cancel').onclick = closeModal;
            overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };

            deleteBtn.onclick = async () => {
                if (input.value === ipAddress) {
                    closeModal();
                    await this.deleteFromDB(ipAddress, blockId);
                }
            };

            input.focus();
        },

        /**
         * Delete block record from database
         */
        async deleteFromDB(ipAddress, blockId) {
            try {
                const response = await fetch(`/api/dashboard/blocking/blocks/${blockId}`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' }
                });

                const data = await response.json();

                if (data.success) {
                    BlockedIPs.UI.notify(`Block record for ${ipAddress} has been deleted`, 'success');
                    BlockedIPs.Core.loadIPBlocks();
                } else {
                    BlockedIPs.UI.notify(`Failed to delete record: ${data.error || 'Unknown error'}`, 'error');
                }
            } catch (error) {
                console.error('Error deleting block record:', error);
                BlockedIPs.UI.notify(`Error deleting record: ${error.message}`, 'error');
            }
        }
    };
})();
/**
 * Blocked IPs Module - Entry Point
 * Modular structure for IP blocking management
 *
 * Sub-modules:
 * - core.js: Data loading and table rendering
 * - actions.js: Block/unblock operations
 * - filters.js: Search and filter functionality
 * - forms.js: Manual block/unblock forms
 * - modal.js: IP details modal
 * - ui.js: UI helpers and notifications
 */

(function() {
    'use strict';

    // Create namespace
    window.BlockedIPs = window.BlockedIPs || {};

    // Module state
    BlockedIPs.state = {
        currentAgentFilter: '',
        blocks: [],
        agents: []
    };

    // Main page loader - called from HTML
    window.loadBlockedIPsPage = async function() {
        try {
            await BlockedIPs.Filters.loadAgentsForDropdown();
            await BlockedIPs.Core.loadIPBlocks();
            BlockedIPs.Filters.setupAll();
            BlockedIPs.Forms.setupAll();
        } catch (error) {
            console.error('Error loading Blocked IPs page:', error);
        }
    };

    // Re-export commonly used functions to window for backward compatibility
    window.showBlockIpDetails = (ip) => BlockedIPs.Modal.showDetails(ip);
    window.unblockIPFromTable = (ip, id) => BlockedIPs.Actions.unblock(ip, id);
    window.reblockIPFromTable = (ip) => BlockedIPs.Actions.reblock(ip);
    window.disableBlockFromTable = (ip, id) => BlockedIPs.Actions.disable(ip, id);
    window.confirmDeleteBlock = (ip, id) => BlockedIPs.Actions.confirmDelete(ip, id);

})();
