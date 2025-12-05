/**
 * Events Live Page Module
 * Handles real-time SSH authentication events display
 */

(function() {
    'use strict';

    let currentPage = 0;
    const pageSize = 50;

    /**
     * Load and display Events Live page
     */
    window.loadEventsLivePage = async function() {
        console.log('Loading Events Live page...');

        try {
            // Reset pagination
            currentPage = 0;

            // Load events data
            await loadEvents();

            // Setup event listeners
            setupEventsEventListeners();

        } catch (error) {
            console.error('Error loading Events Live page:', error);
        }
    };

    /**
     * Load events from API
     */
    async function loadEvents() {
        const searchInput = document.getElementById('eventSearch');
        const typeFilter = document.getElementById('eventTypeFilter');
        const threatFilter = document.getElementById('threatLevelFilter');

        const search = searchInput ? searchInput.value : '';
        const eventType = typeFilter ? typeFilter.value : '';
        const threatLevel = threatFilter ? threatFilter.value : '';

        const params = new URLSearchParams({
            limit: pageSize,
            offset: currentPage * pageSize
        });

        if (search) params.append('search', search);
        if (eventType) params.append('event_type', eventType);
        if (threatLevel) params.append('threat_level', threatLevel);

        // Show loading
        const loadingEl = document.getElementById('eventsLoading');
        const tableEl = document.getElementById('eventsTable');
        const errorEl = document.getElementById('eventsError');

        if (loadingEl) loadingEl.style.display = 'block';
        if (tableEl) tableEl.style.display = 'none';
        if (errorEl) errorEl.style.display = 'none';

        try {
            const response = await fetch(`/api/dashboard/events/list?${params}`);
            const data = await response.json();

            if (!data.success) {
                throw new Error('Failed to load events');
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
                        `${event.location.city || 'Unknown'}, ${event.location.country || ''}` :
                        'Unknown';

                    const flags = [];
                    if (event.location?.is_proxy) flags.push('Proxy');
                    if (event.location?.is_vpn) flags.push('VPN');
                    if (event.location?.is_tor) flags.push('Tor');

                    const threatInfo = event.threat ? `
                        <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">
                            ${event.threat.abuseipdb_score ? `Abuse: ${event.threat.abuseipdb_score} | ` : ''}
                            ${event.threat.virustotal_detections ? `VT: ${event.threat.virustotal_detections}` : ''}
                        </div>
                    ` : '';

                    row.innerHTML = `
                        <td style="padding: 12px; font-size: 12px;">${formatTimestamp(event.timestamp)}</td>
                        <td style="padding: 12px;">
                            <div style="font-family: monospace; font-size: 13px;">${event.ip}</div>
                            ${flags.length > 0 ? `<div style="font-size: 10px; color: var(--text-secondary); margin-top: 4px;">${flags.join(' ')}</div>` : ''}
                        </td>
                        <td style="padding: 12px; font-size: 12px;">
                            ${event.location?.country_code ? `<span style="font-size: 16px;">${getFlagEmoji(event.location.country_code)}</span> ` : ''}
                            ${location}
                            ${event.location?.isp ? `<div style="font-size: 11px; color: var(--text-secondary);">${event.location.isp}</div>` : ''}
                        </td>
                        <td style="padding: 12px; font-family: monospace; font-size: 13px;">${event.username}</td>
                        <td style="padding: 12px;">${getStatusBadge(event.event_type)}</td>
                        <td style="padding: 12px;">
                            ${getThreatBadge(event.threat?.level)}
                            ${threatInfo}
                        </td>
                        <td style="padding: 12px; font-size: 12px;">
                            Server: ${event.server || 'N/A'}<br>
                            Method: ${event.auth_method || 'N/A'}
                        </td>
                        <td style="padding: 12px;">
                            <button onclick="quickBlock('${event.ip}', 'Blocked from Live Events - ${event.event_type} attempt')" style="padding: 4px 8px; border: 1px solid var(--border); background: #D83B01; color: white; border-radius: 2px; cursor: pointer; font-size: 11px;">
                                Block IP
                            </button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
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
            console.error('Error loading events:', error);
            if (loadingEl) loadingEl.style.display = 'none';
            if (errorEl) errorEl.style.display = 'block';
        }
    }

    /**
     * Format timestamp for display
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        return date.toLocaleString();
    }

    /**
     * Get flag emoji from country code
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
     * Get status badge HTML
     */
    function getStatusBadge(eventType) {
        const badges = {
            'failed': '<span style="background: #D83B01; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">FAILED</span>',
            'successful': '<span style="background: #107C10; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">SUCCESS</span>',
            'invalid': '<span style="background: #605E5C; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">INVALID</span>'
        };
        return badges[eventType] || `<span style="background: #605E5C; color: white; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600;">${eventType?.toUpperCase() || 'UNKNOWN'}</span>`;
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
        // Refresh button
        const refreshBtn = document.getElementById('refreshEvents');
        if (refreshBtn) {
            refreshBtn.onclick = () => {
                currentPage = 0;
                loadEvents();
            };
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

})();
