/**
 * SSH Guardian v3.0 - Firewall Inline Logins
 * Successful logins tab functionality
 */
(function() {
    'use strict';

    let currentLoginsPageFW = 1;
    const LOGINS_PAGE_SIZE_FW = 25;

    async function loadSuccessfulLoginsFirewall(page = 1) {
        currentLoginsPageFW = page;
        const loadingEl = document.getElementById('loginsLoading');
        const containerEl = document.getElementById('loginsContainer');
        const noLoginsEl = document.getElementById('noLogins');
        const paginationEl = document.getElementById('loginsPagination');
        const tbodyEl = document.getElementById('fwLoginsTableBody');

        if (loadingEl) loadingEl.style.display = 'block';
        if (noLoginsEl) noLoginsEl.style.display = 'none';
        if (tbodyEl) tbodyEl.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 30px; color: var(--text-secondary);">Loading...</td></tr>';

        try {
            const params = new URLSearchParams();
            params.append('event_type', 'successful');
            params.append('limit', LOGINS_PAGE_SIZE_FW);
            params.append('offset', (page - 1) * LOGINS_PAGE_SIZE_FW);
            if (window.currentAgentId) params.append('agent_id', window.currentAgentId);

            const timeFilter = document.getElementById('loginTimeFilter')?.value;
            if (timeFilter) {
                const now = new Date();
                let startDate;
                if (timeFilter === '24h') startDate = new Date(now - 24 * 60 * 60 * 1000);
                else if (timeFilter === '7d') startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
                else if (timeFilter === '30d') startDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
                if (startDate) params.append('start_date', startDate.toISOString().split('T')[0]);
            }

            const searchFilter = document.getElementById('loginSearchFilter')?.value?.trim();
            if (searchFilter) params.append('search', searchFilter);

            const response = await fetch(`/api/dashboard/events/list?${params.toString()}`);
            const data = await response.json();

            if (loadingEl) loadingEl.style.display = 'none';
            if (!data.success) throw new Error(data.error || 'Failed to load logins');

            const events = data.events || [];
            const pagination = data.pagination || { total: events.length };

            if (events.length === 0) {
                if (noLoginsEl) noLoginsEl.style.display = 'block';
                if (containerEl) containerEl.style.display = 'none';
                if (paginationEl) paginationEl.style.display = 'none';
                updateLoginStats([], pagination);
            } else {
                renderSuccessfulLoginsFirewall(events);
                updateLoginsPagination(pagination);
                updateLoginStats(events, pagination);
                if (noLoginsEl) noLoginsEl.style.display = 'none';
                if (containerEl) containerEl.style.display = 'block';
                if (paginationEl) paginationEl.style.display = 'flex';
            }
        } catch (error) {
            console.error('Error loading logins:', error);
            if (loadingEl) loadingEl.style.display = 'none';
            if (noLoginsEl) {
                const titleEl = noLoginsEl.querySelector('p:first-of-type');
                const msgEl = noLoginsEl.querySelector('p:last-of-type');
                if (titleEl) titleEl.textContent = 'Error Loading Logins';
                if (msgEl) msgEl.textContent = error.message;
                noLoginsEl.style.display = 'block';
            }
        }
    }

    function renderSuccessfulLoginsFirewall(events) {
        const tbody = document.getElementById('fwLoginsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';
        events.forEach(event => {
            const riskScore = event.ml_risk_score || event.risk_score || 0;
            const riskClass = riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 40 ? 'moderate' : 'low';
            const loc = event.location || event.geoip || {};
            const locationStr = (loc?.city || loc?.country) ?
                ((loc.city || '') + (loc.city && loc.country ? ', ' : '') + (loc.country || '')) : 'Unknown';
            const ipAddress = event.ip || event.ip_address || 'N/A';
            const username = event.username || 'Unknown';
            const timeStr = event.timestamp ? formatTimeAgo(event.timestamp) : 'N/A';

            const tr = document.createElement('tr');
            tr.style.cssText = 'border-bottom: 1px solid var(--border); cursor: pointer;';
            tr.onclick = () => showLoginDetailModalFW(event.id);
            tr.innerHTML = `
                <td style="padding: 10px; font-weight: 500;">${username}</td>
                <td style="padding: 10px; font-family: monospace; font-size: 12px;">${ipAddress}</td>
                <td style="padding: 10px; font-size: 12px; color: var(--text-secondary);">${locationStr}</td>
                <td style="padding: 10px; text-align: center;"><span class="risk-badge ${riskClass}" style="padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">${riskScore}</span></td>
                <td style="padding: 10px; font-size: 12px;">${timeStr}</td>
                <td style="padding: 10px; text-align: center;"><span style="padding: 2px 8px; background: rgba(16, 185, 129, 0.15); color: ${TC.teal}; border-radius: 4px; font-size: 11px; font-weight: 600;">Success</span></td>`;
            tbody.appendChild(tr);
        });

        // Add risk badge styles if not present
        if (!document.getElementById('risk-badge-styles')) {
            const style = document.createElement('style');
            style.id = 'risk-badge-styles';
            style.textContent = `
                .risk-badge.critical { background: rgba(209, 52, 56, 0.15); color: ${TC.danger}; }
                .risk-badge.high { background: rgba(255, 140, 0, 0.15); color: ${TC.orange}; }
                .risk-badge.moderate { background: rgba(255, 185, 0, 0.15); color: ${TC.warningDark}; }
                .risk-badge.low { background: rgba(16, 185, 129, 0.15); color: ${TC.teal}; }
            `;
            document.head.appendChild(style);
        }
    }

    function updateLoginsPagination(pagination) {
        const infoEl = document.getElementById('loginsInfo');
        const prevBtn = document.getElementById('prevLoginsPage');
        const nextBtn = document.getElementById('nextLoginsPage');

        const total = pagination.total || 0;
        const start = (currentLoginsPageFW - 1) * LOGINS_PAGE_SIZE_FW + 1;
        const end = Math.min(currentLoginsPageFW * LOGINS_PAGE_SIZE_FW, total);

        if (infoEl) {
            infoEl.textContent = total > 0 ? `Showing ${start}-${end} of ${total}` : 'No logins found';
        }

        if (prevBtn) prevBtn.disabled = currentLoginsPageFW <= 1;
        if (nextBtn) nextBtn.disabled = end >= total;
    }

    function updateLoginStats(events, pagination) {
        const total = pagination?.total || events.length;

        // Count unique users and IPs from current page (approximate)
        const uniqueUsers = new Set(events.map(e => e.username)).size;
        const uniqueIPs = new Set(events.map(e => e.ip || e.ip_address)).size;

        // Today's logins (from current page data)
        const today = new Date().toDateString();
        const todayLogins = events.filter(e => {
            const eventDate = new Date(e.timestamp);
            return eventDate.toDateString() === today;
        }).length;

        document.getElementById('loginStatTotal').textContent = total.toLocaleString();
        document.getElementById('loginStatUniqueUsers').textContent = uniqueUsers.toLocaleString();
        document.getElementById('loginStatUniqueIPs').textContent = uniqueIPs.toLocaleString();
        document.getElementById('loginStatToday').textContent = todayLogins.toLocaleString();
    }

    async function showLoginDetailModalFW(eventId) {
        showFWDetailModal('Loading...', `
            <div style="text-align: center; padding: 40px;">
                <div class="loading-spinner"></div>
                <p style="margin-top: 16px; color: var(--text-secondary);">Loading login details...</p>
            </div>
        `);

        try {
            const response = await fetch(`/api/dashboard/events/${eventId}`);
            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Failed to load event');
            }

            const event = data.data || data.event;
            renderLoginDetailModal(event);

        } catch (error) {
            console.error('Error loading login details:', error);
            showFWDetailModal('Error', `
                <div style="text-align: center; padding: 20px; color: ${TC.danger};">
                    <p>Error loading login details: ${error.message}</p>
                </div>
            `);
        }
    }

    function renderLoginDetailModal(event) {
        const riskScore = event.ml_risk_score || event.risk_score || 0;
        const riskClass = getScoreClass(riskScore);
        const geoip = event.location || event.geoip || {};
        const threat = event.threat || {};
        const agent = event.agent || {};
        const ipAddress = event.ip || event.ip_address || 'N/A';

        // Status badge
        const statusBadge = '<span class="detail-badge success">Successful Login</span>';

        // Auth method badge
        const authBadge = event.auth_method
            ? `<span class="detail-badge info">${escapeHtml(event.auth_method)}</span>`
            : '';

        // GeoIP section
        const geoSection = geoip && (geoip.country || geoip.city) ? `
            <div class="detail-section">
                <div class="detail-section-title">📍 Location</div>
                <div class="detail-grid">
                    <div><span class="detail-label">Country:</span> ${escapeHtml(geoip.country || 'Unknown')} ${geoip.country_code ? `(${geoip.country_code})` : ''}</div>
                    <div><span class="detail-label">City:</span> ${escapeHtml(geoip.city || 'Unknown')}</div>
                    <div><span class="detail-label">ISP:</span> ${escapeHtml(geoip.isp || 'Unknown')}</div>
                    <div><span class="detail-label">ASN:</span> ${geoip.asn || 'N/A'}</div>
                </div>
            </div>
        ` : '';

        // Threat Intelligence section
        const abuseScore = threat.abuseipdb_score || 0;
        const vtPositives = threat.virustotal_positives || 0;
        const vtTotal = threat.virustotal_total || 0;
        const threatLevel = threat.level || 'unknown';
        const threatSection = `
            <div class="detail-section">
                <div class="detail-section-title">🔍 Threat Intelligence</div>
                <div class="threat-intel-grid">
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
                        <div class="threat-intel-label">Reports (30 days)</div>
                        <div class="threat-intel-value">${threat.abuseipdb_reports || 0}</div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">Threat Level</div>
                        <div class="threat-intel-value">
                            <span class="detail-badge ${threatLevel === 'clean' ? 'success' : threatLevel === 'suspicious' ? 'warning' : threatLevel === 'malicious' ? 'critical' : ''}">${threatLevel}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Login Details section
        const loginSection = `
            <div class="detail-section">
                <div class="detail-section-title">🔐 Login Details</div>
                <div class="behavioral-grid">
                    <div class="behavioral-item">
                        <span class="behavioral-label">Username</span>
                        <span class="behavioral-value">${escapeHtml(event.username || 'Unknown')}</span>
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
                        <span class="behavioral-label">Server</span>
                        <span class="behavioral-value">${escapeHtml(event.server || agent.hostname || 'Unknown')}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Login Time</span>
                        <span class="behavioral-value">${event.timestamp ? formatTimeAgo(event.timestamp) : 'N/A'}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Is Anomaly</span>
                        <span class="behavioral-value">${event.is_anomaly ? `<span style="color:${TC.danger};">Yes</span>` : `<span style="color:${TC.teal};">No</span>`}</span>
                    </div>
                </div>
            </div>
        `;

        // ML Contribution section
        const mlSection = `
            <div class="detail-section">
                <div class="detail-section-title">🤖 ML Risk Assessment</div>
                <div class="ml-contribution-box">
                    <div class="ml-score-circle ${riskClass}">
                        <span class="ml-score-value">${riskScore}</span>
                        <span class="ml-score-label">Risk Score</span>
                    </div>
                    <div class="ml-details">
                        <div class="ml-detail-row">
                            <span>Risk Level:</span>
                            <span class="detail-badge ${riskClass}">${riskClass.charAt(0).toUpperCase() + riskClass.slice(1)}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>Confidence:</span>
                            <span class="ml-confidence">${threat.confidence ? (parseFloat(threat.confidence) * 100).toFixed(0) + '%' : 'N/A'}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>ML Threat Type:</span>
                            <span>${event.ml_threat_type || 'None detected'}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>Event Type:</span>
                            <span style="font-weight: 600; color: ${TC.teal};">Successful Login</span>
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
                        <strong>Status:</strong> This login was successful and has been logged for security monitoring.
                    </div>
                    <div class="justification-meta">
                        <span>Event ID: #${event.id}</span>
                        <span>UUID: ${event.event_uuid ? event.event_uuid.substring(0, 8) + '...' : 'N/A'}</span>
                    </div>
                </div>
            </div>
        `;

        const content = `
            <div class="block-detail-body">
                <!-- Header -->
                <div class="detail-header-section">
                    <div class="detail-ip-display">
                        <span class="detail-ip-address">${escapeHtml(ipAddress)}</span>
                        ${statusBadge}
                        ${authBadge}
                    </div>
                    <div class="detail-meta-row">
                        <span>👤 ${escapeHtml(event.username || 'Unknown')}</span>
                        <span>Agent: ${escapeHtml(agent.hostname || event.server || 'Unknown')}</span>
                    </div>
                </div>

                ${geoSection}
                ${threatSection}
                ${loginSection}
                ${mlSection}
                ${summarySection}
            </div>
        `;

        showFWDetailModal(`Login Investigation: ${ipAddress}`, content, { width: '700px' });
    }

    // Helper function
    function getScoreClass(score) {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 40) return 'moderate';
        return 'low';
    }

    // Expose for pagination navigation
    window.loadLoginsPageFW = function(page) {
        loadSuccessfulLoginsFirewall(page);
    };

    window.prevLoginsPageFW = function() {
        if (currentLoginsPageFW > 1) loadSuccessfulLoginsFirewall(currentLoginsPageFW - 1);
    };

    window.nextLoginsPageFW = function() {
        loadSuccessfulLoginsFirewall(currentLoginsPageFW + 1);
    };

    // Global exports
    window.loadSuccessfulLoginsFirewall = loadSuccessfulLoginsFirewall;
    window.showLoginDetailModalFW = showLoginDetailModalFW;
})();
