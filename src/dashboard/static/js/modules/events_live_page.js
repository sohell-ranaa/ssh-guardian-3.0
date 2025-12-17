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

            // Check for specific event ID in URL (from notification click)
            const eventId = getEventIdFromUrl();
            if (eventId) {
                // Load and show specific event details
                await loadSpecificEvent(eventId);
            } else {
                // Load events data normally
                await loadEvents();
            }

            // Setup event listeners
            setupEventsEventListeners();

            // Start auto-refresh if enabled (but not if viewing specific event)
            if (autoRefreshEnabled && !eventId) {
                startAutoRefresh();
            }

        } catch (error) {
            console.error('Error loading Events Live page:', error);
        }
    };

    /**
     * Get event ID from URL query parameter
     */
    function getEventIdFromUrl() {
        const hash = window.location.hash;
        if (hash.includes('?')) {
            const queryString = hash.split('?')[1];
            const params = new URLSearchParams(queryString);
            return params.get('event');
        }
        return null;
    }

    /**
     * Load and display a specific event by ID
     */
    async function loadSpecificEvent(eventId) {
        const loadingEl = document.getElementById('eventsLoading');
        const tableEl = document.getElementById('eventsTable');
        const errorEl = document.getElementById('eventsError');

        if (loadingEl) loadingEl.style.display = 'block';
        if (tableEl) tableEl.style.display = 'none';
        if (errorEl) errorEl.style.display = 'none';

        try {
            // Ensure TimeSettings is loaded for proper date/time formatting in modal
            if (window.TimeSettings && !window.TimeSettings.isLoaded()) {
                await window.TimeSettings.load();
            }

            // Fetch the specific event
            const response = await fetch(`/api/dashboard/events/${eventId}`);
            const data = await response.json();

            if (!data || !data.success) {
                // Event not found, fall back to normal list
                console.warn(`Event ${eventId} not found, loading all events`);
                await loadEvents();
                return;
            }

            const event = data.data || data.event;
            if (!event) {
                await loadEvents();
                return;
            }

            // Show the event details modal
            showEventDetailsModal(event);

            // Also load the normal events list in the background
            await loadEvents();

        } catch (error) {
            console.error('Error loading specific event:', error);
            // Fall back to loading all events
            await loadEvents();
        }
    }

    /**
     * Show event details in a modal
     */
    function showEventDetailsModal(event) {
        // Remove existing modal
        const existingModal = document.getElementById('event-detail-modal');
        if (existingModal) existingModal.remove();

        const location = event.location ?
            `${escapeHtml(event.location.city) || 'Unknown'}, ${escapeHtml(event.location.country) || 'Unknown'}` :
            'Unknown';

        const flags = [];
        if (event.location?.is_proxy) flags.push('Proxy');
        if (event.location?.is_vpn) flags.push('VPN');
        if (event.location?.is_tor) flags.push('Tor');
        if (event.location?.is_datacenter) flags.push('Datacenter');

        // Get agent info
        const agentName = event.agent?.name || event.agent?.hostname || 'Unknown Agent';
        const agentId = event.agent?.id || null;

        const modal = document.createElement('div');
        modal.id = 'event-detail-modal';
        modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';
        modal.onclick = (e) => {
            if (e.target === modal) {
                modal.remove();
                // Clean up URL
                window.location.hash = 'events-live';
            }
        };

        modal.innerHTML = `
            <div style="background: var(--surface); border-radius: 8px; width: 600px; max-width: 90vw; max-height: 90vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div style="padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                    <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: var(--text-primary);">Event Details #${event.id}</h2>
                    <button onclick="this.closest('#event-detail-modal').remove(); window.location.hash='events-live';" style="background: none; border: none; cursor: pointer; font-size: 24px; color: var(--text-secondary); line-height: 1;">&times;</button>
                </div>
                <div style="padding: 20px;">
                    <!-- Agent/Server Info Banner -->
                    <div style="background: var(--background); border-radius: 6px; padding: 12px 16px; margin-bottom: 20px; border-left: 4px solid var(--azure-blue);">
                        <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">Agent / Server</div>
                        <div style="font-size: 15px; font-weight: 600; color: var(--text-primary);">${escapeHtml(agentName)}</div>
                        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">${escapeHtml(event.server) || 'N/A'}</div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
                        <div>
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">IP Address</label>
                            <div style="font-family: monospace; font-size: 14px; color: var(--text-primary);">${escapeHtml(event.ip)}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Username</label>
                            <div style="font-family: monospace; font-size: 14px; color: var(--text-primary);">${escapeHtml(event.username) || 'N/A'}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Event Type</label>
                            ${getStatusBadge(event.event_type)}
                        </div>
                        <div>
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Threat Level</label>
                            ${getThreatBadge(event.threat?.level || event.threat_level)}
                        </div>
                        <div>
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Timestamp</label>
                            <div style="color: var(--text-primary);">${formatTimestamp(event.timestamp)}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Auth Method</label>
                            <div style="color: var(--text-primary);">${escapeHtml(event.auth_method) || 'N/A'}</div>
                        </div>
                        <div style="grid-column: span 2;">
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Location</label>
                            <div style="color: var(--text-primary);">${location}</div>
                            ${flags.length > 0 ? `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">${flags.join(' | ')}</div>` : ''}
                        </div>
                    </div>

                    ${event.threat ? `
                        <div style="margin-bottom: 20px; padding: 12px; background: var(--background); border-radius: 4px;">
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 8px;">Threat Intelligence</label>
                            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; font-size: 13px;">
                                ${event.threat.abuseipdb_score !== undefined && event.threat.abuseipdb_score !== null ? `<div><strong>AbuseIPDB:</strong> ${event.threat.abuseipdb_score}%</div>` : ''}
                                ${event.threat.virustotal_positives !== undefined && event.threat.virustotal_positives !== null ? `<div><strong>VirusTotal:</strong> ${event.threat.virustotal_positives}/${event.threat.virustotal_total || '?'} detections</div>` : ''}
                                ${event.threat.confidence !== undefined && event.threat.confidence !== null ? `<div><strong>Confidence:</strong> ${event.threat.confidence}%</div>` : ''}
                            </div>
                        </div>
                    ` : ''}

                    ${event.ml_risk_score !== undefined && event.ml_risk_score !== null ? `
                        <div style="margin-bottom: 20px; padding: 12px; background: var(--background); border-radius: 4px;">
                            <label style="font-size: 12px; color: var(--text-secondary); display: block; margin-bottom: 8px;">ML Analysis</label>
                            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; font-size: 13px;">
                                <div><strong>Risk Score:</strong> ${event.ml_risk_score}/100</div>
                                ${event.ml_threat_type ? `<div><strong>Threat Type:</strong> ${escapeHtml(event.ml_threat_type)}</div>` : ''}
                                ${event.is_anomaly ? `<div><strong>Anomaly:</strong> Yes</div>` : ''}
                            </div>
                        </div>
                    ` : ''}

                    <div style="display: flex; gap: 8px; justify-content: flex-end; padding-top: 16px; border-top: 1px solid var(--border);">
                        <button onclick="blockIPFromModal('${escapeHtml(event.ip)}', ${agentId || 'null'})" style="padding: 8px 16px; background: rgba(200, 80, 60, 0.15); color: #c8503c; border: 1px solid rgba(200, 80, 60, 0.3); border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 500;">
                            Block IP
                        </button>
                        <button onclick="this.closest('#event-detail-modal').remove(); window.location.hash='events-live';" style="padding: 8px 16px; background: var(--background); color: var(--text-primary); border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 13px;">
                            Close
                        </button>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    /**
     * Block IP from the modal - includes agent_id for agent-based blocking
     */
    window.blockIPFromModal = async function(ip, agentId) {
        if (!confirm(`Block IP address ${ip}?`)) return;

        try {
            const payload = {
                ip_address: ip,
                reason: 'Blocked from event details',
                block_type: 'manual',
                duration_minutes: 1440 // 24 hours default
            };

            // Add agent_id if provided (agent-based blocking)
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
                // Close the modal
                const modal = document.getElementById('event-detail-modal');
                if (modal) modal.remove();

                // Show notification
                showBlockSuccessNotification(`IP ${ip} has been blocked successfully.`);

                // Navigate to Firewall & Blocking -> Blocked IPs tab
                window.location.hash = 'blocked-ips';
            } else {
                alert(`Failed to block IP: ${data.error || data.message}`);
            }
        } catch (error) {
            console.error('Error blocking IP:', error);
            alert('Failed to block IP. Please try again.');
        }
    };

    /**
     * Show success notification for block action
     */
    function showBlockSuccessNotification(message) {
        const notification = document.createElement('div');
        notification.style.cssText = `
            position: fixed;
            top: 80px;
            right: 20px;
            padding: 16px 24px;
            background: #388e3c;
            color: white;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10001;
            animation: slideInRight 0.3s ease;
        `;
        notification.textContent = message;
        document.body.appendChild(notification);

        setTimeout(() => {
            notification.style.animation = 'slideOutRight 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }

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
                btn.innerHTML = '⏸';
                btn.style.background = '#107C10';
                btn.title = 'Pause auto-refresh (refreshes every 30s)';
            } else {
                btn.innerHTML = '▶';
                btn.style.background = 'var(--azure-blue)';
                btn.title = 'Enable auto-refresh';
            }
        }
    }

    /**
     * Load events from API
     * @param {boolean} forceRefresh - If true, bypass cache to get fresh data
     */
    async function loadEvents(forceRefresh = false) {
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

        // Add nocache param to bypass server cache if force refresh
        if (forceRefresh) {
            params.append('nocache', '1');
        }

        if (search) params.append('search', search);
        if (ipFilterValue) params.append('ip', ipFilterValue);
        if (eventType) params.append('event_type', eventType);
        if (threatLevel) params.append('threat_level', threatLevel);
        if (agentId) params.append('agent_id', agentId);
        if (timeRange) params.append('time_range', timeRange);

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

            // Update overview statistics (pass pagination for accurate total)
            updateOverviewStats(data.events || [], data.pagination);

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

                    // Get agent/server display
                    const agentDisplay = event.agent?.name || event.agent?.hostname || 'Unknown Agent';
                    const serverDisplay = escapeHtml(event.server) || 'N/A';

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
                            <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 2px;">${escapeHtml(agentDisplay)}</div>
                            <div style="font-size: 11px; color: var(--text-secondary);">${serverDisplay}</div>
                        </td>
                        <td style="padding: 12px;">
                            <button class="view-details-btn" data-event='${JSON.stringify(event).replace(/'/g, "&#39;")}' style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); color: var(--text-primary); border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: 500;">
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
                    endpoint = '/api/dashboard/blocking/blocks/list';
                    break;
                case 'whitelist':
                    endpoint = '/api/dashboard/blocking/whitelist';
                    break;
                case 'watchlist':
                    endpoint = '/api/dashboard/blocking/watchlist';
                    break;
                default:
                    return false;
            }

            const response = await fetch(`${endpoint}?search=${encodeURIComponent(ip)}`);
            const data = await response.json();

            if (!data.success) return false;

            // Check if IP exists in the results
            // Different endpoints return different field names
            const items = data.blocks || data.items || data.watchlist || [];
            return items.some(item => item.ip_address === ip || item.ip === ip);
        } catch (error) {
            console.error(`Error checking ${listType} for IP ${ip}:`, error);
            return false;
        }
    }

    /**
     * Format timestamp for display using user's timezone and format settings
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';

        // Use TimeSettings module for consistent formatting with user preferences
        if (window.TimeSettings && window.TimeSettings.isLoaded()) {
            return window.TimeSettings.formatFull(timestamp);
        }

        // Fallback if TimeSettings not loaded yet
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
     * Get status badge HTML - muted/offshade colors
     */
    function getStatusBadge(eventType) {
        const safeType = escapeHtml(eventType);
        const badges = {
            'failed': '<span style="background: rgba(200, 80, 60, 0.15); color: #c8503c; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(200, 80, 60, 0.3);">FAILED</span>',
            'successful': '<span style="background: rgba(56, 142, 60, 0.15); color: #388e3c; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(56, 142, 60, 0.3);">SUCCESS</span>',
            'invalid': '<span style="background: rgba(117, 117, 117, 0.15); color: #757575; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(117, 117, 117, 0.3);">INVALID</span>'
        };
        return badges[eventType] || `<span style="background: rgba(117, 117, 117, 0.15); color: #757575; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(117, 117, 117, 0.3);">${safeType?.toUpperCase() || 'UNKNOWN'}</span>`;
    }

    /**
     * Get threat level badge HTML - muted/offshade colors
     */
    function getThreatBadge(level) {
        const badges = {
            'clean': '<span style="background: rgba(56, 142, 60, 0.15); color: #388e3c; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(56, 142, 60, 0.3);">CLEAN</span>',
            'low': '<span style="background: rgba(251, 192, 45, 0.2); color: #b8860b; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(251, 192, 45, 0.4);">LOW</span>',
            'medium': '<span style="background: rgba(245, 124, 0, 0.15); color: #e65100; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(245, 124, 0, 0.3);">MEDIUM</span>',
            'high': '<span style="background: rgba(200, 80, 60, 0.15); color: #c8503c; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(200, 80, 60, 0.3);">HIGH</span>',
            'critical': '<span style="background: rgba(183, 28, 28, 0.15); color: #b71c1c; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(183, 28, 28, 0.3);">CRITICAL</span>'
        };
        return badges[level] || '<span style="background: rgba(117, 117, 117, 0.15); color: #757575; padding: 4px 8px; border-radius: 2px; font-size: 11px; font-weight: 600; border: 1px solid rgba(117, 117, 117, 0.3);">UNKNOWN</span>';
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

        // IP Filter on Enter
        const ipFilter = document.getElementById('ipFilter');
        if (ipFilter) {
            ipFilter.onkeyup = (e) => {
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

        // Time range filter
        const timeRangeFilter = document.getElementById('timeRangeFilter');
        if (timeRangeFilter) {
            timeRangeFilter.onchange = () => {
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
