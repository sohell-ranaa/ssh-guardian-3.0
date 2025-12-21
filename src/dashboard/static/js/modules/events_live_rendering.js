/**
 * Events Live Rendering Module
 * Event loading, rendering, IP status, utilities
 * Extracted from events_live_page.js for better maintainability
 */

(function() {
    'use strict';

    // Reference to shared state from events_live_page.js
    function getState() {
        return window.eventsLiveState || { currentPage: 0, pageSize: 50 };
    }

    /**
     * Load events from API
     * @param {boolean} forceRefresh - If true, bypass cache to get fresh data
     */
    async function loadEvents(forceRefresh = false) {
        // Ensure TimeSettings is loaded before rendering
        if (window.TimeSettings && !window.TimeSettings.isLoaded()) {
            await window.TimeSettings.load();
        }

        const state = getState();
        const currentPage = state.currentPage;
        const pageSize = state.pageSize;

        const searchInput = document.getElementById('eventSearch');
        const ipFilter = document.getElementById('ipFilter');
        const typeFilter = document.getElementById('eventTypeFilter');
        const threatFilter = document.getElementById('threatLevelFilter');
        const agentFilter = document.getElementById('agentFilter');
        const timeRangeFilter = document.getElementById('timeRangeFilter');

        const search = searchInput ? searchInput.value : '';
        const ipFilterValue = ipFilter ? ipFilter.value : '';
        const eventType = typeFilter ? typeFilter.value : '';
        const threatLevel = threatFilter ? threatFilter.value : '';
        const agentId = agentFilter ? agentFilter.value : '';
        const timeRange = timeRangeFilter ? timeRangeFilter.value : 'last_30_days';

        const params = new URLSearchParams({
            limit: pageSize,
            offset: currentPage * pageSize
        });

        if (forceRefresh) {
            params.append('nocache', '1');
        }

        if (search) params.append('search', search);
        if (ipFilterValue) params.append('ip', ipFilterValue);
        if (eventType) params.append('event_type', eventType);
        if (threatLevel) params.append('threat_level', threatLevel);
        if (agentId) params.append('agent_id', agentId);
        if (timeRange) params.append('time_range', timeRange);

        const loadingEl = document.getElementById('eventsLoading');
        const tableEl = document.getElementById('eventsTable');
        const errorEl = document.getElementById('eventsError');

        if (loadingEl) loadingEl.style.display = 'block';
        if (tableEl) tableEl.style.display = 'none';
        if (errorEl) errorEl.style.display = 'none';

        try {
            let data;
            const url = `/api/dashboard/events/list?${params}`;

            if (typeof fetchWithCache === 'function') {
                data = await fetchWithCache(url, 'events');
            } else {
                const response = await fetch(url);
                data = await response.json();
            }

            if (!data || !data.success) {
                throw new Error(data?.error || 'Failed to load events');
            }

            // Update overview statistics (pass pagination for accurate total)
            updateOverviewStats(data.events || [], data.pagination);

            const tbody = document.getElementById('eventsTableBody');
            if (!tbody) return;

            tbody.innerHTML = '';

            if (data.events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="events-empty-state">No events found</td></tr>';
            } else {
                data.events.forEach(event => {
                    const row = document.createElement('tr');
                    row.className = 'events-table-row';

                    const location = event.location ?
                        `${escapeHtml(event.location.city) || 'Unknown'}, ${escapeHtml(event.location.country) || ''}` :
                        'Unknown';

                    const flags = [];
                    if (event.location?.is_proxy) flags.push('Proxy');
                    if (event.location?.is_vpn) flags.push('VPN');
                    if (event.location?.is_tor) flags.push('Tor');

                    const threatInfo = event.threat ? `
                        <div class="threat-info">
                            ${event.threat.abuseipdb_score ? `Abuse: ${escapeHtml(event.threat.abuseipdb_score)} | ` : ''}
                            ${event.threat.virustotal_detections ? `VT: ${escapeHtml(event.threat.virustotal_detections)}` : ''}
                        </div>
                    ` : '';

                    // Create safe onclick handler using data attributes
                    const safeIp = escapeHtml(event.ip);
                    const safeEventType = escapeHtml(event.event_type);
                    const safeReason = `Blocked from Live Events - ${safeEventType} attempt`;

                    // Get agent/server display
                    const agentDisplay = event.agent?.name || event.agent?.hostname || 'Unknown Agent';
                    const serverDisplay = escapeHtml(event.server) || 'N/A';

                    row.innerHTML = `
                        <td class="events-table-cell">${formatTimestamp(event.timestamp)}</td>
                        <td class="events-table-cell">
                            <div class="ip-display-container">
                                <span class="ip-status-indicator" data-ip="${safeIp}" title="Checking status..."></span>
                                <div class="ip-address-text">${safeIp}</div>
                            </div>
                            ${flags.length > 0 ? `<div class="ip-flags">${flags.join(' ')}</div>` : ''}
                        </td>
                        <td class="events-table-cell location-cell" data-ip="${safeIp}">
                            ${event.location?.country_code ? getFlagImage(event.location.country_code) : ''}
                            ${location}
                            ${event.location?.isp ? `<div class="location-isp">${escapeHtml(event.location.isp)}</div>` : ''}
                        </td>
                        <td class="events-table-cell events-table-cell--mono">${escapeHtml(event.username)}</td>
                        <td class="events-table-cell">${getStatusBadge(event.event_type)}</td>
                        <td class="events-table-cell">
                            ${getThreatBadge(event.threat?.level)}
                            ${threatInfo}
                        </td>
                        <td class="events-table-cell">
                            <div class="agent-name">${escapeHtml(agentDisplay)}</div>
                            <div class="agent-server">${serverDisplay}</div>
                        </td>
                        <td class="events-table-cell">
                            <button class="view-details-btn" data-event='${JSON.stringify(event).replace(/'/g, "&#39;")}'>
                                View Details
                            </button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });

                // Attach event listeners to view details buttons
                attachViewDetailsListeners();

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
     * Attach event listeners to view details buttons
     */
    function attachViewDetailsListeners() {
        const buttons = document.querySelectorAll('.view-details-btn');
        buttons.forEach(btn => {
            btn.addEventListener('click', function() {
                try {
                    const eventData = JSON.parse(this.getAttribute('data-event'));
                    showEventDetailsModal(eventData);
                } catch (e) {
                    console.error('Error parsing event data:', e);
                }
            });
        });
    }

    // Store overview stats to persist across pagination
    let overviewStatsCache = null;

    /**
     * Update overview statistics based on current filtered events and pagination
     * Only updates on first page load (page 0) to show accurate totals
     */
    function updateOverviewStats(events, pagination) {
        const totalEl = document.getElementById('overviewTotal');
        const failedEl = document.getElementById('overviewFailed');
        const successfulEl = document.getElementById('overviewSuccessful');
        const uniqueIPsEl = document.getElementById('overviewUniqueIPs');
        const highThreatEl = document.getElementById('overviewHighThreat');

        // Only calculate stats on first page to get accurate overview
        // On subsequent pages, keep the cached stats
        const currentPage = getState().currentPage;
        if (currentPage > 0 && overviewStatsCache) {
            // Use cached stats for pagination
            if (totalEl) totalEl.textContent = overviewStatsCache.total.toLocaleString();
            if (failedEl) failedEl.textContent = overviewStatsCache.failed.toLocaleString();
            if (successfulEl) successfulEl.textContent = overviewStatsCache.successful.toLocaleString();
            if (uniqueIPsEl) uniqueIPsEl.textContent = overviewStatsCache.uniqueIPs.toLocaleString();
            if (highThreatEl) highThreatEl.textContent = overviewStatsCache.highThreat.toLocaleString();
            return;
        }

        if (!events || events.length === 0) {
            overviewStatsCache = { total: 0, failed: 0, successful: 0, uniqueIPs: 0, highThreat: 0 };
            if (totalEl) totalEl.textContent = '0';
            if (failedEl) failedEl.textContent = '0';
            if (successfulEl) successfulEl.textContent = '0';
            if (uniqueIPsEl) uniqueIPsEl.textContent = '0';
            if (highThreatEl) highThreatEl.textContent = '0';
            return;
        }

        // Use pagination total for total count (accurate for filtered results)
        const total = pagination?.total || events.length;
        const failed = events.filter(e => e.event_type === 'failed').length;
        const successful = events.filter(e => e.event_type === 'successful').length;
        const uniqueIPs = new Set(events.map(e => e.ip)).size;
        const highThreat = events.filter(e => {
            const level = e.threat?.level || e.threat_level;
            return level === 'high' || level === 'critical';
        }).length;

        // Cache the stats
        overviewStatsCache = { total, failed, successful, uniqueIPs, highThreat };

        // Update DOM
        if (totalEl) totalEl.textContent = total.toLocaleString();
        if (failedEl) failedEl.textContent = failed.toLocaleString();
        if (successfulEl) successfulEl.textContent = successful.toLocaleString();
        if (uniqueIPsEl) uniqueIPsEl.textContent = uniqueIPs.toLocaleString();
        if (highThreatEl) highThreatEl.textContent = highThreat.toLocaleString();
    }

    // Cache for IP status checks to avoid redundant API calls
    const ipStatusCache = new Map();
    const IP_STATUS_CACHE_TTL = 60000; // 1 minute cache

    /**
     * Update IP status indicators for all visible IPs
     * Optimized: Fetches all lists once and checks locally
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
            // Fetch all lists once (much more efficient than per-IP queries)
            const [blockData, whitelistData, watchlistData] = await Promise.all([
                fetchListData('/api/dashboard/blocking/blocks/list'),
                fetchListData('/api/dashboard/blocking/whitelist'),
                fetchListData('/api/dashboard/blocking/watchlist')
            ]);

            // Create lookup sets for fast checking
            const blockedIps = new Set(blockData.map(item => item.ip_address || item.ip));
            const whitelistedIps = new Set(whitelistData.map(item => item.ip_address || item.ip));
            const watchedIps = new Set(watchlistData.map(item => item.ip_address || item.ip));

            // Update all indicators based on the fetched lists
            uniqueIps.forEach(ip => {
                const ipIndicators = document.querySelectorAll(`.ip-status-indicator[data-ip="${ip}"]`);
                ipIndicators.forEach(indicator => {
                    // Remove all status classes first
                    indicator.classList.remove('ip-status-indicator--blocked', 'ip-status-indicator--whitelisted', 'ip-status-indicator--watched', 'ip-status-indicator--clean');

                    if (blockedIps.has(ip)) {
                        indicator.classList.add('ip-status-indicator--blocked');
                        indicator.title = 'IP is blocked';
                    } else if (whitelistedIps.has(ip)) {
                        indicator.classList.add('ip-status-indicator--whitelisted');
                        indicator.title = 'IP is whitelisted';
                    } else if (watchedIps.has(ip)) {
                        indicator.classList.add('ip-status-indicator--watched');
                        indicator.title = 'IP is on watchlist';
                    } else {
                        indicator.classList.add('ip-status-indicator--clean');
                        indicator.title = 'No special status';
                    }
                });
            });
        } catch (error) {
            console.error('Error updating IP status indicators:', error);
        }
    }

    /**
     * Fetch list data with caching
     */
    async function fetchListData(endpoint) {
        // Check cache first
        const cacheKey = endpoint;
        const cached = ipStatusCache.get(cacheKey);
        if (cached && (Date.now() - cached.timestamp) < IP_STATUS_CACHE_TTL) {
            return cached.data;
        }

        try {
            const response = await fetch(`${endpoint}?limit=1000`);
            const data = await response.json();

            if (!data.success) return [];

            // Get items from response (different endpoints use different field names)
            const items = data.blocks || data.items || data.watchlist || [];

            // Cache the result
            ipStatusCache.set(cacheKey, {
                data: items,
                timestamp: Date.now()
            });

            return items;
        } catch (error) {
            console.error(`Error fetching ${endpoint}:`, error);
            return [];
        }
    }

    /**
     * Format timestamp for display using user's timezone and format settings
     * Uses TimeSettings module for consistent formatting across the application
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';

        // Use TimeSettings module for consistent formatting with user preferences
        if (window.TimeSettings && window.TimeSettings.isLoaded()) {
            return window.TimeSettings.formatFull(timestamp);
        }

        // Fallback: Parse server timezone (+08:00) then display in browser's native timezone
        try {
            let ts = String(timestamp).replace(' ', 'T');
            if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
            const date = new Date(ts);
            if (isNaN(date.getTime())) return 'Invalid Date';
            return date.toLocaleString();
        } catch (e) {
            return String(timestamp);
        }
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
                     class="flag-image"
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
                const isp = info.isp ? `<div class="location-isp">${escapeHtml(info.isp)}</div>` : '';

                item.cell.innerHTML = `${flag}${escapeHtml(location)}${isp}`;
            }
        }
    }

    /**
     * Get status badge HTML - uses CSS classes from events_live.css
     */
    function getStatusBadge(eventType) {
        const safeType = escapeHtml(eventType);
        const badges = {
            'failed': '<span class="status-badge status-badge--failed">FAILED</span>',
            'successful': '<span class="status-badge status-badge--success">SUCCESS</span>',
            'invalid': '<span class="status-badge status-badge--invalid">INVALID</span>'
        };
        return badges[eventType] || `<span class="status-badge status-badge--unknown">${safeType?.toUpperCase() || 'UNKNOWN'}</span>`;
    }

    /**
     * Get threat level badge HTML - uses CSS classes from events_live.css
     */
    function getThreatBadge(level) {
        const badges = {
            'clean': '<span class="threat-badge threat-badge--clean">CLEAN</span>',
            'low': '<span class="threat-badge threat-badge--low">LOW</span>',
            'medium': '<span class="threat-badge threat-badge--medium">MEDIUM</span>',
            'high': '<span class="threat-badge threat-badge--high">HIGH</span>',
            'critical': '<span class="threat-badge threat-badge--critical">CRITICAL</span>'
        };
        return badges[level] || '<span class="threat-badge threat-badge--unknown">UNKNOWN</span>';
    }

    /**
     * Setup event listeners
     */
    function setupEventsEventListeners() {
        const state = getState();

        // Refresh button - force cache bypass to get fresh data
        const refreshBtn = document.getElementById('refreshEvents');
        if (refreshBtn) {
            refreshBtn.onclick = () => {
                window.eventsLiveState.currentPage = 0;
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
                    window.eventsLiveState.currentPage = 0;
                    loadEvents();
                }
            };
        }

        // IP Filter on Enter
        const ipFilter = document.getElementById('ipFilter');
        if (ipFilter) {
            ipFilter.onkeyup = (e) => {
                if (e.key === 'Enter') {
                    window.eventsLiveState.currentPage = 0;
                    loadEvents();
                }
            };
        }

        // Event type filter
        const typeFilter = document.getElementById('eventTypeFilter');
        if (typeFilter) {
            typeFilter.onchange = () => {
                window.eventsLiveState.currentPage = 0;
                loadEvents();
            };
        }

        // Threat level filter
        const threatFilter = document.getElementById('threatLevelFilter');
        if (threatFilter) {
            threatFilter.onchange = () => {
                window.eventsLiveState.currentPage = 0;
                loadEvents();
            };
        }

        // Agent filter
        const agentFilter = document.getElementById('agentFilter');
        if (agentFilter) {
            agentFilter.onchange = () => {
                window.eventsLiveState.currentPage = 0;
                loadEvents();
            };
        }

        // Time range filter
        const timeRangeFilter = document.getElementById('timeRangeFilter');
        if (timeRangeFilter) {
            timeRangeFilter.onchange = () => {
                window.eventsLiveState.currentPage = 0;
                loadEvents();
            };
        }

        // Previous page
        const prevBtn = document.getElementById('prevPage');
        if (prevBtn) {
            prevBtn.onclick = () => {
                const state = getState();
                if (state.currentPage > 0) {
                    window.eventsLiveState.currentPage = state.currentPage - 1;
                    loadEvents();
                }
            };
        }

        // Next page
        const nextBtn = document.getElementById('nextPage');
        if (nextBtn) {
            nextBtn.onclick = () => {
                const state = getState();
                window.eventsLiveState.currentPage = state.currentPage + 1;
                loadEvents();
            };
        }
    }

    // Cleanup when navigating away
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.substring(1);
        if (hash !== 'events-live') {
            if (typeof window.stopAutoRefresh === 'function') {
                window.stopAutoRefresh();
            }
        }
    });

    // Export functions needed by events_live_page.js
    window.loadEvents = loadEvents;
    window.setupEventsEventListeners = setupEventsEventListeners;
    window.formatTimestamp = formatTimestamp;
    window.attachViewDetailsListeners = attachViewDetailsListeners;
    window.updateOverviewStats = updateOverviewStats;
    window.updateIpStatusIndicators = updateIpStatusIndicators;
    window.getStatusBadge = getStatusBadge;
    window.getThreatBadge = getThreatBadge;
    window.getFlagImage = getFlagImage;
    window.getFlagEmoji = getFlagEmoji;

})();
