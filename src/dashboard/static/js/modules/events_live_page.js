/**
 * Events Live Page Module
 * Handles real-time SSH authentication events display
 */

(function() {
    'use strict';

    let currentPage = 0;
    const pageSize = 50;
    let autoRefreshInterval = null;
    let autoRefreshEnabled = false;
    const AUTO_REFRESH_DELAY = 30000; // 30 seconds

    /**
     * Escape HTML to prevent XSS attacks
     */
    function escapeHtml(text) {
        if (text === null || text === undefined) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    /**
     * Load and display Events Live page
     */
    window.loadEventsLivePage = async function() {
        try {
            // Ensure TimeSettings is loaded for proper date/time formatting
            if (window.TimeSettings && !window.TimeSettings.isLoaded()) {
                await window.TimeSettings.load();
            }

            // Reset pagination
            currentPage = 0;

            // Load events data
            await loadEvents();

            // Setup event listeners
            setupEventsEventListeners();

            // Start auto-refresh if enabled
            if (autoRefreshEnabled) {
                startAutoRefresh();
            }

        } catch (error) {
            console.error('Error loading Events Live page:', error);
        }
    };

    /**
     * Start auto-refresh for live events
     */
    function startAutoRefresh() {
        stopAutoRefresh(); // Clear any existing interval
        autoRefreshInterval = setInterval(() => {
            if (document.getElementById('page-events-live')?.style.display !== 'none') {
                loadEvents(true);  // Force refresh to get live data
            }
        }, AUTO_REFRESH_DELAY);
        autoRefreshEnabled = true;
        updateAutoRefreshButton();
    }

    /**
     * Stop auto-refresh
     */
    function stopAutoRefresh() {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
        }
        autoRefreshEnabled = false;
        updateAutoRefreshButton();
    }

    /**
     * Toggle auto-refresh
     */
    window.toggleAutoRefresh = function() {
        if (autoRefreshEnabled) {
            stopAutoRefresh();
        } else {
            startAutoRefresh();
        }
    };

    /**
     * Update auto-refresh button state
     */
    function updateAutoRefreshButton() {
        const btn = document.getElementById('autoRefreshToggle');
        if (btn) {
            if (autoRefreshEnabled) {
                btn.innerHTML = '⏸ Pause';
                btn.style.background = '#107C10';
                btn.title = 'Click to pause auto-refresh (refreshes every 30s)';
            } else {
                btn.innerHTML = '▶ Live';
                btn.style.background = 'var(--azure-blue)';
                btn.title = 'Click to enable auto-refresh';
            }
        }
    }

    /**
     * Load events from API
     * @param {boolean} forceRefresh - If true, bypass cache to get fresh data
     */
    async function loadEvents(forceRefresh = false) {
        const searchInput = document.getElementById('eventSearch');
        const typeFilter = document.getElementById('eventTypeFilter');
        const threatFilter = document.getElementById('threatLevelFilter');
        const agentFilter = document.getElementById('agentFilter');

        const search = searchInput ? searchInput.value : '';
        const eventType = typeFilter ? typeFilter.value : '';
        const threatLevel = threatFilter ? threatFilter.value : '';
        const agentId = agentFilter ? agentFilter.value : '';

        const params = new URLSearchParams({
            limit: pageSize,
            offset: currentPage * pageSize
        });

        // Add nocache param to bypass server cache if force refresh
        if (forceRefresh) {
            params.append('nocache', '1');
        }

        if (search) params.append('search', search);
        if (eventType) params.append('event_type', eventType);
        if (threatLevel) params.append('threat_level', threatLevel);
        if (agentId) params.append('agent_id', agentId);

        // Show loading
        const loadingEl = document.getElementById('eventsLoading');
        const tableEl = document.getElementById('eventsTable');
        const errorEl = document.getElementById('eventsError');

        if (loadingEl) loadingEl.style.display = 'block';
        if (tableEl) tableEl.style.display = 'none';
        if (errorEl) errorEl.style.display = 'none';

        try {
            // Use fetchWithCache if available to track cache status
            let data;
            const url = `/api/dashboard/events/list?${params}`;
            console.log('[LiveEvents] Fetching:', url);

            if (typeof fetchWithCache === 'function') {
                data = await fetchWithCache(url, 'events');
            } else {
                const response = await fetch(url);
                data = await response.json();
            }

            console.log('[LiveEvents] Response:', data ? `success=${data.success}, events=${data.events?.length}` : 'null');

            if (!data || !data.success) {
                throw new Error(data?.error || 'Failed to load events');
            }

            const tbody = document.getElementById('eventsTableBody');
            if (!tbody) return;

            tbody.innerHTML = '';

            if (data.events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 40px; color: var(--text-secondary);">No events found</td></tr>';
            } else {
                data.events.forEach(event => {
                    const row = document.createElement('tr');
                    row.style.borderBottom = '1px solid var(--border)';

                    const location = event.location ?
                        `${escapeHtml(event.location.city) || 'Unknown'}, ${escapeHtml(event.location.country) || ''}` :
                        'Unknown';

                    const flags = [];
                    if (event.location?.is_proxy) flags.push('Proxy');
                    if (event.location?.is_vpn) flags.push('VPN');
                    if (event.location?.is_tor) flags.push('Tor');

                    const threatInfo = event.threat ? `
                        <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                            ${event.threat.abuseipdb_score ? `Abuse: ${escapeHtml(event.threat.abuseipdb_score)} | ` : ''}
                            ${event.threat.virustotal_detections ? `VT: ${escapeHtml(event.threat.virustotal_detections)}` : ''}
                        </div>
                    ` : '';

                    // Create safe onclick handler using data attributes
                    const safeIp = escapeHtml(event.ip);
                    const safeEventType = escapeHtml(event.event_type);
                    const safeReason = `Blocked from Live Events - ${safeEventType} attempt`;

                    row.innerHTML = `
                        <td style="padding: 12px; font-size: 12px;">${formatTimestamp(event.timestamp)}</td>
                        <td style="padding: 12px;">
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span class="ip-status-indicator" data-ip="${safeIp}" style="width: 8px; height: 8px; border-radius: 50%; background: #605E5C; display: inline-block;" title="Checking status..."></span>
                                <div style="font-family: monospace; font-size: 13px;">${safeIp}</div>
                            </div>
                            ${flags.length > 0 ? `<div style="font-size: 10px; color: var(--text-secondary); margin-top: 4px; margin-left: 16px;">${flags.join(' ')}</div>` : ''}
                        </td>
                        <td style="padding: 12px; font-size: 12px;" class="location-cell" data-ip="${safeIp}">
                            ${event.location?.country_code ? getFlagImage(event.location.country_code) : ''}
                            ${location}
                            ${event.location?.isp ? `<div style="font-size: 11px; color: var(--text-secondary);">${escapeHtml(event.location.isp)}</div>` : ''}
                        </td>
                        <td style="padding: 12px; font-family: monospace; font-size: 13px;">${escapeHtml(event.username)}</td>
                        <td style="padding: 12px;">${getStatusBadge(event.event_type)}</td>
                        <td style="padding: 12px;">
                            ${getThreatBadge(event.threat?.level)}
                            ${threatInfo}
                        </td>
                        <td style="padding: 12px; font-size: 12px;">
                            ${event.agent ? `<div style="font-weight: 500;">${escapeHtml(event.agent.name)}</div>` : ''}
                            Server: ${escapeHtml(event.server) || 'N/A'}<br>
                            Method: ${escapeHtml(event.auth_method) || 'N/A'}
                        </td>
                        <td style="padding: 12px;">
                            <div style="display: flex; gap: 4px; align-items: center;">
                                <button class="block-ip-btn" data-ip="${safeIp}" data-reason="${safeReason}" style="padding: 4px 8px; border: 1px solid var(--border); background: #D83B01; color: white; border-radius: 2px; cursor: pointer; font-size: 11px;">
                                    Block IP
                                </button>
                                <div class="event-actions-dropdown" style="position: relative;">
                                    <button class="actions-menu-btn" data-ip="${safeIp}" data-event-id="${event.id}" style="padding: 4px 10px; border: 1px solid var(--border); background: var(--background); color: var(--text-primary); border-radius: 4px; cursor: pointer; font-size: 11px;">
                                        Actions ▼
                                    </button>
                                </div>
                            </div>
                        </td>
                    `;
                    tbody.appendChild(row);
                });

                // Attach event listeners to block buttons and action buttons safely
                attachBlockButtonListeners();
                attachActionButtonListeners();

                // Update IP status indicators
                updateIpStatusIndicators();

                // Enrich any events missing location data using FreeIPAPI
                enrichMissingLocationData();
            }

            // Update pagination
            const { total, offset, has_more } = data.pagination;
            const infoEl = document.getElementById('eventsInfo');
            const prevBtn = document.getElementById('prevPage');
            const nextBtn = document.getElementById('nextPage');

            if (infoEl) infoEl.textContent = `Showing ${offset + 1}-${Math.min(offset + pageSize, total)} of ${total} events`;
            if (prevBtn) prevBtn.disabled = currentPage === 0;
            if (nextBtn) nextBtn.disabled = !has_more;

            // Show table
            if (loadingEl) loadingEl.style.display = 'none';
            if (tableEl) tableEl.style.display = 'block';

        } catch (error) {
            console.error('[LiveEvents] Error loading events:', error);
            if (loadingEl) loadingEl.style.display = 'none';
            if (errorEl) {
                errorEl.textContent = `Error loading events: ${error.message}`;
                errorEl.style.display = 'block';
            }
        }
    }

    /**
     * Attach event listeners to block buttons (prevents XSS via onclick)
     */
    function attachBlockButtonListeners() {
        const buttons = document.querySelectorAll('.block-ip-btn');
        buttons.forEach(btn => {
            btn.addEventListener('click', function() {
                const ip = this.getAttribute('data-ip');
                const reason = this.getAttribute('data-reason');
                if (ip && typeof quickBlock === 'function') {
                    quickBlock(ip, reason);
                }
            });
        });
    }

    /**
     * Attach event listeners to action menu buttons (prevents XSS via onclick)
     */
    function attachActionButtonListeners() {
        const buttons = document.querySelectorAll('.actions-menu-btn');
        buttons.forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                const ip = this.getAttribute('data-ip');
                const eventId = this.getAttribute('data-event-id');
                if (ip && typeof showIpActions === 'function') {
                    showIpActions(ip, eventId, this);
                }
            });
        });
    }

    /**
     * Update IP status indicators for all visible IPs
     */
    async function updateIpStatusIndicators() {
        // Get all unique IPs from current table
        const indicators = document.querySelectorAll('.ip-status-indicator');
        const uniqueIps = new Set();

        indicators.forEach(indicator => {
            const ip = indicator.getAttribute('data-ip');
            if (ip) uniqueIps.add(ip);
        });

        if (uniqueIps.size === 0) return;

        try {
            // Batch check IP statuses
            for (const ip of uniqueIps) {
                // Check if IP is in any list
                const [blockStatus, whitelistStatus, watchlistStatus] = await Promise.all([
                    checkIpInList(ip, 'blocklist'),
                    checkIpInList(ip, 'whitelist'),
                    checkIpInList(ip, 'watchlist')
                ]);

                // Update all indicators for this IP
                const ipIndicators = document.querySelectorAll(`.ip-status-indicator[data-ip="${ip}"]`);
                ipIndicators.forEach(indicator => {
                    if (blockStatus) {
                        indicator.style.background = '#D83B01'; // Red for blocked
                        indicator.title = 'IP is blocked';
                    } else if (whitelistStatus) {
                        indicator.style.background = '#107C10'; // Green for whitelisted
                        indicator.title = 'IP is whitelisted';
                    } else if (watchlistStatus) {
                        indicator.style.background = '#FFB900'; // Yellow for watched
                        indicator.title = 'IP is on watchlist';
                    } else {
                        indicator.style.background = '#605E5C'; // Gray for unknown/clean
                        indicator.title = 'No special status';
                    }
                });
            }
        } catch (error) {
            console.error('Error updating IP status indicators:', error);
        }
    }

    /**
     * Check if IP exists in a specific list
     */
    async function checkIpInList(ip, listType) {
        try {
            let endpoint = '';
            switch(listType) {
                case 'blocklist':
                    endpoint = '/api/dashboard/firewall/blocklist';
                    break;
                case 'whitelist':
                    endpoint = '/api/dashboard/firewall/whitelist';
                    break;
                case 'watchlist':
                    endpoint = '/api/dashboard/watchlist';
                    break;
                default:
                    return false;
            }

            const response = await fetch(`${endpoint}?search=${encodeURIComponent(ip)}`);
            const data = await response.json();

            if (!data.success) return false;

            // Check if IP exists in the results
            const items = data.items || data.watchlist || [];
            return items.some(item => item.ip === ip);
        } catch (error) {
            console.error(`Error checking ${listType} for IP ${ip}:`, error);
            return false;
        }
    }

    /**
     * Format timestamp for display using saved time settings
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        // Use TimeSettings module if available for consistent formatting
        if (window.TimeSettings && window.TimeSettings.isLoaded()) {
            return window.TimeSettings.format(timestamp, 'short');
        }
        // Fallback to browser locale
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

    /**
     * Get flag image from country code (using flagcdn.com for consistency)
     */
    function getFlagImage(countryCode) {
        if (!countryCode || countryCode === 'N/A') return '';
        const code = countryCode.toLowerCase();
        return `<img src="https://flagcdn.com/16x12/${code}.png"
                     srcset="https://flagcdn.com/32x24/${code}.png 2x"
                     width="16" height="12"
                     alt="${countryCode}"
                     style="vertical-align: middle; margin-right: 4px;"
                     onerror="this.style.display='none'">`;
    }

    /**
     * Get flag emoji from country code (fallback)
     */
    function getFlagEmoji(countryCode) {
        if (!countryCode) return '';
        const codePoints = countryCode
            .toUpperCase()
            .split('')
            .map(char => 127397 + char.charCodeAt());
        return String.fromCodePoint(...codePoints);
    }

    /**
     * Fetch IP geolocation info from FreeIPAPI
     */
    async function fetchIpLocationInfo(ip) {
        try {
            const response = await fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ip)}`);
            if (!response.ok) return null;
            const data = await response.json();
            if (data.success) {
                return data;
            }
            return null;
        } catch (error) {
            console.error(`Error fetching IP info for ${ip}:`, error);
            return null;
        }
    }

    /**
     * Enrich events missing location data with FreeIPAPI
     */
    async function enrichMissingLocationData() {
        // Find table rows that need location enrichment
        const rows = document.querySelectorAll('#eventsTableBody tr');
        const enrichmentNeeded = [];

        rows.forEach(row => {
            const locationCell = row.querySelector('td:nth-child(3)');
            const ipCell = row.querySelector('.ip-status-indicator');

            if (locationCell && ipCell) {
                const ip = ipCell.getAttribute('data-ip');
                const locationText = locationCell.textContent.trim();

                // Check if location is missing or "Unknown"
                if (ip && (locationText.includes('Unknown, Unknown') || locationText === 'Unknown')) {
                    enrichmentNeeded.push({ ip, cell: locationCell });
                }
            }
        });

        // Enrich each IP missing location (limit concurrent requests)
        for (const item of enrichmentNeeded) {
            const info = await fetchIpLocationInfo(item.ip);
            if (info && info.success && !info.is_private) {
                const flag = getFlagImage(info.country_code);
                const location = `${info.city || 'Unknown'}, ${info.country || ''}`;
                const isp = info.isp ? `<div style="font-size: 11px; color: var(--text-secondary);">${escapeHtml(info.isp)}</div>` : '';

                item.cell.innerHTML = `${flag}${escapeHtml(location)}${isp}`;
            }
        }
    }

    /**
     * Get status badge HTML
     */
    function getStatusBadge(eventType) {
        const safeType = escapeHtml(eventType);
        const badges = {
            'failed': '<span style="background: #D83B01; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">FAILED</span>',
            'successful': '<span style="background: #107C10; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">SUCCESS</span>',
            'invalid': '<span style="background: #605E5C; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">INVALID</span>'
        };
        return badges[eventType] || `<span style="background: #605E5C; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">${safeType?.toUpperCase() || 'UNKNOWN'}</span>`;
    }

    /**
     * Get threat level badge HTML
     */
    function getThreatBadge(level) {
        const badges = {
            'clean': '<span style="background: #107C10; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">CLEAN</span>',
            'low': '<span style="background: #FFB900; color: #323130; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">LOW</span>',
            'medium': '<span style="background: #FF8C00; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">MEDIUM</span>',
            'high': '<span style="background: #D83B01; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">HIGH</span>',
            'critical': '<span style="background: #A80000; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">CRITICAL</span>'
        };
        return badges[level] || '<span style="background: #605E5C; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">UNKNOWN</span>';
    }

    /**
     * Setup event listeners
     */
    function setupEventsEventListeners() {
        // Refresh button - force cache bypass to get fresh data
        const refreshBtn = document.getElementById('refreshEvents');
        if (refreshBtn) {
            refreshBtn.onclick = () => {
                currentPage = 0;
                loadEvents(true);  // Force refresh, bypass cache
            };
        }

        // Auto-refresh toggle
        const autoRefreshBtn = document.getElementById('autoRefreshToggle');
        if (autoRefreshBtn) {
            autoRefreshBtn.onclick = toggleAutoRefresh;
        }

        // Search on Enter
        const searchInput = document.getElementById('eventSearch');
        if (searchInput) {
            searchInput.onkeyup = (e) => {
                if (e.key === 'Enter') {
                    currentPage = 0;
                    loadEvents();
                }
            };
        }

        // Event type filter
        const typeFilter = document.getElementById('eventTypeFilter');
        if (typeFilter) {
            typeFilter.onchange = () => {
                currentPage = 0;
                loadEvents();
            };
        }

        // Threat level filter
        const threatFilter = document.getElementById('threatLevelFilter');
        if (threatFilter) {
            threatFilter.onchange = () => {
                currentPage = 0;
                loadEvents();
            };
        }

        // Agent filter
        const agentFilter = document.getElementById('agentFilter');
        if (agentFilter) {
            agentFilter.onchange = () => {
                currentPage = 0;
                loadEvents();
            };
        }

        // Previous page
        const prevBtn = document.getElementById('prevPage');
        if (prevBtn) {
            prevBtn.onclick = () => {
                if (currentPage > 0) {
                    currentPage--;
                    loadEvents();
                }
            };
        }

        // Next page
        const nextBtn = document.getElementById('nextPage');
        if (nextBtn) {
            nextBtn.onclick = () => {
                currentPage++;
                loadEvents();
            };
        }
    }

    // Cleanup when navigating away
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.substring(1);
        if (hash !== 'events-live') {
            stopAutoRefresh();
        }
    });

})();
