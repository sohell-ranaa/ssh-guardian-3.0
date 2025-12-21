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

    // escapeHtml - use global from utils.js
    const escapeHtml = window.escapeHtml;

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
     * Show event details in a modal - redesigned to match blocked IP detail modal
     */
    async function showEventDetailsModal(event) {
        // Remove existing modal
        const existingModal = document.getElementById('event-detail-modal');
        if (existingModal) existingModal.remove();

        // Get agent info
        const agentName = event.agent?.name || event.agent?.hostname || 'Unknown Agent';
        const agentId = event.agent?.agent_id || null;  // Use agent_id string for API calls
        const ipAddress = event.ip || 'N/A';

        // Check if IP is already blocked
        let isBlocked = false;
        let blockSource = '';
        try {
            const response = await fetch(`/api/dashboard/blocking/real-blocks?search=${encodeURIComponent(ipAddress)}&limit=5`);
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.blocks && data.blocks.length > 0) {
                    // Check for exact IP match
                    const block = data.blocks.find(b => b.ip_address === ipAddress);
                    if (block) {
                        isBlocked = true;
                        blockSource = block.source === 'ufw' ? 'UFW' : block.source === 'fail2ban' ? 'Fail2ban' : block.source;
                    }
                }
            }
        } catch (e) {
            console.log('Could not check block status:', e);
        }

        const modal = document.createElement('div');
        modal.id = 'event-detail-modal';
        modal.className = 'event-detail-modal-overlay';
        modal.onclick = (e) => {
            if (e.target === modal) {
                modal.remove();
                window.location.hash = 'events-live';
            }
        };

        // Build the modal content
        const content = buildEventDetailContent(event, agentName, agentId, ipAddress);

        // Build block button or blocked badge
        const blockButtonHtml = isBlocked
            ? `<span class="event-modal-badge blocked" style="display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; background: ${TC.successBg}; color: ${TC.successDark}; border-radius: 4px; font-weight: 600;">
                    ✅ Blocked via ${escapeHtml(blockSource)}
               </span>`
            : `<button class="event-modal-btn danger" onclick="openBlockIPModalFromEvent('${escapeHtml(event.ip)}', '${agentId || ''}', '${escapeHtml(agentName)}')">
                    🚫 Block IP
               </button>`;

        modal.innerHTML = `
            <div class="event-detail-modal" style="max-width: 700px;">
                <div class="event-detail-modal-header">
                    <h3>Event Investigation: ${escapeHtml(ipAddress)}</h3>
                    <button class="event-detail-modal-close" onclick="this.closest('#event-detail-modal').remove(); window.location.hash='events-live';">&times;</button>
                </div>
                <div class="event-detail-modal-body">${content}</div>
                <div class="event-detail-modal-footer">
                    ${blockButtonHtml}
                    <button class="event-modal-btn primary" onclick="this.closest('#event-detail-modal').remove(); window.location.hash='events-live';">
                        Close
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        document.body.style.overflow = 'hidden';

        // Close on Escape
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                const modal = document.getElementById('event-detail-modal');
                if (modal) {
                    modal.remove();
                    window.location.hash = 'events-live';
                }
                document.removeEventListener('keydown', escHandler);
                document.body.style.overflow = '';
            }
        };
        document.addEventListener('keydown', escHandler);
    }

    /**
     * Build event detail content - matches blocked IP detail modal style
     */
    function buildEventDetailContent(event, agentName, agentId, ipAddress) {
        const threat = event.threat || {};
        const location = event.location || {};
        const riskScore = event.ml_risk_score || 0;

        // Helper function for score class
        function getScoreClass(score) {
            if (score >= 80) return 'critical';
            if (score >= 60) return 'high';
            if (score >= 40) return 'moderate';
            return 'low';
        }

        // Status badges
        const eventTypeBadge = event.event_type === 'successful'
            ? '<span class="detail-badge success">Successful</span>'
            : event.event_type === 'failed'
            ? '<span class="detail-badge critical">Failed</span>'
            : `<span class="detail-badge">${escapeHtml(event.event_type)}</span>`;

        const threatLevelBadge = threat.level
            ? `<span class="detail-badge ${threat.level === 'clean' ? 'success' : threat.level === 'suspicious' ? 'warning' : threat.level === 'malicious' ? 'critical' : ''}">${threat.level}</span>`
            : '';

        // GeoIP section
        const geoSection = location.country || location.city ? `
            <div class="detail-section">
                <div class="detail-section-title">📍 Location</div>
                <div class="detail-grid">
                    <div><span class="detail-label">Country:</span> ${escapeHtml(location.country || 'Unknown')} ${location.country_code ? `(${location.country_code})` : ''}</div>
                    <div><span class="detail-label">City:</span> ${escapeHtml(location.city || 'Unknown')}</div>
                    <div><span class="detail-label">ISP:</span> ${escapeHtml(location.isp || 'Unknown')}</div>
                    <div><span class="detail-label">ASN:</span> ${location.asn || 'N/A'}</div>
                </div>
                ${location.is_proxy || location.is_vpn || location.is_tor || location.is_datacenter ? `
                    <div style="margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap;">
                        ${location.is_proxy ? '<span class="detail-badge warning">Proxy</span>' : ''}
                        ${location.is_vpn ? '<span class="detail-badge warning">VPN</span>' : ''}
                        ${location.is_tor ? '<span class="detail-badge critical">Tor</span>' : ''}
                        ${location.is_datacenter ? '<span class="detail-badge info">Datacenter</span>' : ''}
                    </div>
                ` : ''}
            </div>
        ` : '';

        // Threat Intelligence section
        const abuseScore = threat.abuseipdb_score || 0;
        const vtPositives = threat.virustotal_positives || 0;
        const vtTotal = threat.virustotal_total || 0;
        const shodanPorts = threat.shodan_ports || [];
        const shodanVulns = threat.shodan_vulns || [];

        // Shodan section (if data exists)
        const shodanSection = (shodanPorts.length > 0 || shodanVulns.length > 0) ? `
            <div class="threat-intel-item" style="grid-column: span 2;">
                <div class="threat-intel-label">Shodan</div>
                <div style="font-size: 12px; margin-top: 4px;">
                    ${shodanPorts.length > 0 ? `<span>Ports: ${shodanPorts.slice(0, 8).join(', ')}${shodanPorts.length > 8 ? '...' : ''}</span>` : ''}
                    ${shodanVulns.length > 0 ? `<span style="color: ${TC.danger}; margin-left: 12px;">⚠️ ${shodanVulns.length} vulns</span>` : ''}
                </div>
            </div>
        ` : '';

        const threatSection = `
            <div class="detail-section">
                <div class="detail-section-title" style="display: flex; justify-content: space-between; align-items: center;">
                    <span>🔍 Threat Intelligence</span>
                    <button onclick="refreshThreatIntel('${escapeHtml(ipAddress)}')" class="event-modal-btn secondary" style="padding: 4px 10px; font-size: 11px;">
                        🔄 Refresh Intel
                    </button>
                </div>
                <div class="threat-intel-grid" id="threat-intel-grid-${escapeHtml(ipAddress).replace(/\./g, '-')}">
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">AbuseIPDB Score</div>
                        <div class="threat-intel-value ${getScoreClass(abuseScore)}">${abuseScore}%</div>
                        <div class="threat-intel-bar">
                            <div class="threat-intel-bar-fill ${getScoreClass(abuseScore)}" style="width: ${abuseScore}%"></div>
                        </div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">VirusTotal</div>
                        <div class="threat-intel-value ${vtPositives > 0 ? 'critical' : 'low'}">${vtPositives}/${vtTotal}</div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">Reports</div>
                        <div class="threat-intel-value">${threat.abuseipdb_reports || 0}</div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">Threat Level</div>
                        <div class="threat-intel-value">${threatLevelBadge || '<span class="detail-badge">Unknown</span>'}</div>
                    </div>
                    ${shodanSection}
                </div>
            </div>
        `;

        // Event Details section
        const eventSection = `
            <div class="detail-section">
                <div class="detail-section-title">📊 Event Details</div>
                <div class="behavioral-grid">
                    <div class="behavioral-item">
                        <span class="behavioral-label">Username</span>
                        <span class="behavioral-value">${escapeHtml(event.username || 'N/A')}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Event Type</span>
                        <span class="behavioral-value">${eventTypeBadge}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Auth Method</span>
                        <span class="behavioral-value">${escapeHtml(event.auth_method || 'N/A')}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Port</span>
                        <span class="behavioral-value">${event.port || 22}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Timestamp</span>
                        <span class="behavioral-value">${formatTimestamp(event.timestamp)}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Is Anomaly</span>
                        <span class="behavioral-value">${event.is_anomaly ? `<span style="color:${TC.danger};">Yes</span>` : `<span style="color:${TC.teal};">No</span>`}</span>
                    </div>
                </div>
            </div>
        `;

        // ML Assessment section
        const mlSection = `
            <div class="detail-section">
                <div class="detail-section-title">🤖 ML Risk Assessment</div>
                <div class="ml-contribution-box">
                    <div class="ml-score-circle ${getScoreClass(riskScore)}">
                        <span class="ml-score-value">${riskScore}</span>
                        <span class="ml-score-label">Risk Score</span>
                    </div>
                    <div class="ml-details">
                        <div class="ml-detail-row">
                            <span>Risk Level:</span>
                            <span class="detail-badge ${getScoreClass(riskScore)}">${getScoreClass(riskScore).charAt(0).toUpperCase() + getScoreClass(riskScore).slice(1)}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>Confidence:</span>
                            <span class="ml-confidence">${threat.confidence ? (parseFloat(threat.confidence) * 100).toFixed(0) + '%' : 'N/A'}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>ML Threat Type:</span>
                            <span>${event.ml_threat_type || 'None detected'}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Event Summary section
        const summarySection = `
            <div class="detail-section">
                <div class="detail-section-title">📋 Event Summary</div>
                <div class="justification-box">
                    <div class="justification-reason">
                        <strong>Status:</strong> ${event.event_type === 'successful' ? 'This login was successful.' : event.event_type === 'failed' ? 'This login attempt failed.' : 'Login event recorded.'}
                    </div>
                    <div class="justification-meta">
                        <span>Event ID: #${event.id}</span>
                        <span>UUID: ${event.event_uuid ? event.event_uuid.substring(0, 8) + '...' : event.uuid ? event.uuid.substring(0, 8) + '...' : 'N/A'}</span>
                    </div>
                </div>
            </div>
        `;

        return `
            <div class="block-detail-body">
                <!-- Header -->
                <div class="detail-header-section">
                    <div class="detail-ip-display">
                        <span class="detail-ip-address">${escapeHtml(ipAddress)}</span>
                        ${eventTypeBadge}
                        ${threatLevelBadge}
                    </div>
                    <div class="detail-meta-row">
                        <span>👤 ${escapeHtml(event.username || 'Unknown')}</span>
                        <span>🖥️ Agent: ${escapeHtml(agentName)}</span>
                    </div>
                </div>

                ${geoSection}
                ${threatSection}
                ${eventSection}
                ${mlSection}
                ${summarySection}
            </div>
        `;
    }

    // Modal styles are now in /static/css/pages/events_live.css

    /**
     * Open the Block IP modal from Live Events - uses same modal as Firewall page
     * Pre-fills the IP address and agent from the event
     */
    window.openBlockIPModalFromEvent = function(ip, agentId, agentName) {
        // Close the event detail modal first
        const eventModal = document.getElementById('event-detail-modal');
        if (eventModal) {
            eventModal.remove();
            document.body.style.overflow = '';
        }

        // Navigate to Firewall page
        window.location.hash = 'firewall';

        // Wait for page to load, then open Block IP modal with pre-filled data
        setTimeout(() => {
            // Check if showBlockIPModal exists (from firewall_inline.js)
            if (typeof showBlockIPModal === 'function') {
                // Pass IP, agent ID, and agent name - the modal will display them
                showBlockIPModal(ip, agentId, agentName);
            } else {
                console.error('showBlockIPModal function not found. Make sure firewall_inline.js is loaded.');
                alert('Unable to open Block IP modal. Please try again from the Firewall page.');
            }
        }, 200);
    };

    /**
     * Refresh threat intelligence for an IP by calling the enrich endpoint
     */
    window.refreshThreatIntel = async function(ipAddress) {
        const gridId = `threat-intel-grid-${ipAddress.replace(/\./g, '-')}`;
        const grid = document.getElementById(gridId);
        if (!grid) return;

        // Show loading state
        const originalContent = grid.innerHTML;
        grid.innerHTML = `<div style="text-align: center; padding: 20px; color: ${TC.textSecondary};">🔄 Fetching fresh threat intel...</div>`;

        try {
            // Call the threat intel lookup endpoint
            const response = await fetch(`/api/threat-intel/lookup/${encodeURIComponent(ipAddress)}`);
            const data = await response.json();

            if (data.success && data.data) {
                const threat = data.data;
                const abuseScore = threat.abuseipdb_score || 0;
                const vtPositives = threat.virustotal_positives || 0;
                const vtTotal = threat.virustotal_total || 0;
                const shodanPorts = threat.shodan_ports ? (Array.isArray(threat.shodan_ports) ? threat.shodan_ports : JSON.parse(threat.shodan_ports || '[]')) : [];
                const shodanVulns = threat.shodan_vulns ? (Array.isArray(threat.shodan_vulns) ? threat.shodan_vulns : JSON.parse(threat.shodan_vulns || '[]')) : [];

                function getScoreClass(score) {
                    if (score >= 80) return 'critical';
                    if (score >= 60) return 'high';
                    if (score >= 40) return 'moderate';
                    return 'low';
                }

                const threatLevel = threat.threat_level || threat.overall_threat_level || 'unknown';
                const threatBadgeClass = threatLevel === 'clean' ? 'success' :
                                        threatLevel === 'low' ? 'low' :
                                        threatLevel === 'medium' ? 'warning' :
                                        threatLevel === 'high' ? 'high' :
                                        threatLevel === 'critical' ? 'critical' : '';

                const shodanSection = (shodanPorts.length > 0 || shodanVulns.length > 0) ? `
                    <div class="threat-intel-item" style="grid-column: span 2;">
                        <div class="threat-intel-label">Shodan</div>
                        <div style="font-size: 12px; margin-top: 4px;">
                            ${shodanPorts.length > 0 ? `<span>Ports: ${shodanPorts.slice(0, 8).join(', ')}${shodanPorts.length > 8 ? '...' : ''}</span>` : ''}
                            ${shodanVulns.length > 0 ? `<span style="color: ${TC.danger}; margin-left: 12px;">⚠️ ${shodanVulns.length} vulns</span>` : ''}
                        </div>
                    </div>
                ` : '';

                grid.innerHTML = `
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">AbuseIPDB Score</div>
                        <div class="threat-intel-value ${getScoreClass(abuseScore)}">${abuseScore}%</div>
                        <div class="threat-intel-bar">
                            <div class="threat-intel-bar-fill ${getScoreClass(abuseScore)}" style="width: ${abuseScore}%"></div>
                        </div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">VirusTotal</div>
                        <div class="threat-intel-value ${vtPositives > 0 ? 'critical' : 'low'}">${vtPositives}/${vtTotal}</div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">Reports</div>
                        <div class="threat-intel-value">${threat.abuseipdb_reports || 0}</div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">Threat Level</div>
                        <div class="threat-intel-value"><span class="detail-badge ${threatBadgeClass}">${threatLevel}</span></div>
                    </div>
                    ${shodanSection}
                `;

                showNotification('Threat intelligence refreshed successfully', 'success');
            } else {
                grid.innerHTML = originalContent;
                showNotification(data.error || 'Failed to refresh threat intel', 'error');
            }
        } catch (error) {
            console.error('Error refreshing threat intel:', error);
            grid.innerHTML = originalContent;
            showNotification('Failed to refresh threat intel: ' + error.message, 'error');
        }
    };

    /**
     * Show success notification for block action
     */
    function showBlockSuccessNotification(message) {
        const notification = document.createElement('div');
        notification.className = 'block-success-notification';
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
                btn.style.background = TC.successDark;
                btn.title = 'Pause auto-refresh (refreshes every 30s)';
            } else {
                btn.innerHTML = '▶';
                btn.style.background = 'var(--azure-blue)';
                btn.title = 'Enable auto-refresh';
            }
        }
    }


    // Export stopAutoRefresh for events_live_rendering.js
    window.stopAutoRefresh = stopAutoRefresh;

    // Export shared state and functions for events_live_rendering.js
    window.eventsLiveState = {
        get currentPage() { return currentPage; },
        set currentPage(v) { currentPage = v; },
        pageSize: pageSize
    };
    window.escapeHtml = escapeHtml;
    window.showEventDetailsModal = showEventDetailsModal;

    // Note: Event loading, rendering, and utilities are now in events_live_rendering.js

})();
