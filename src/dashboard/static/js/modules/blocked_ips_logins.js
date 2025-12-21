/**
 * SSH Guardian v3.0 - Successful Logins Tab Functionality
 * Extracted from blocked_ips_page.js for better maintainability
 *
 * Dependencies: blocked_ips_page.js (for showBlockNotification, injectBlockModalStyles)
 */

// ============================================================================
// SUCCESSFUL LOGINS TAB FUNCTIONALITY
// ============================================================================

let currentLoginsPage = 1;
const LOGINS_PAGE_SIZE = 25;
let loginsDataCache = null;

/**
 * Switch between Blocked IPs and Successful Logins tabs
 */
function switchIPTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.ip-tab-btn').forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.classList.add('active');
            btn.style.color = 'var(--azure-blue)';
            btn.style.fontWeight = '600';
            btn.style.borderBottomColor = 'var(--azure-blue)';
        } else {
            btn.classList.remove('active');
            btn.style.color = 'var(--text-secondary)';
            btn.style.fontWeight = '500';
            btn.style.borderBottomColor = 'transparent';
        }
    });

    // Show/hide tab content
    document.querySelectorAll('.ip-tab-content').forEach(content => {
        content.style.display = 'none';
    });

    const tabContent = document.getElementById(`tab-${tabName}`);
    if (tabContent) {
        tabContent.style.display = 'block';
    }

    // Load data for the tab
    if (tabName === 'successful-logins') {
        loadSuccessfulLogins();
        populateLoginAgentFilter();
    }
}

/**
 * Populate agent filter for logins tab
 */
async function populateLoginAgentFilter() {
    const select = document.getElementById('loginAgentFilter');
    if (!select || select.options.length > 1) return;

    try {
        const response = await fetch('/api/agents/list');
        const data = await response.json();
        const agents = data.data?.agents || data.data || [];

        agents.forEach(agent => {
            const option = document.createElement('option');
            option.value = agent.id;
            option.textContent = agent.hostname || agent.agent_uuid?.slice(0, 12) || `Agent ${agent.id}`;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Error loading agents for filter:', error);
    }
}

/**
 * Load successful logins data
 */
async function loadSuccessfulLogins(page = 1) {
    currentLoginsPage = page;

    const loadingEl = document.getElementById('loginsLoading');
    const tableEl = document.getElementById('loginsTable');
    const errorEl = document.getElementById('loginsError');

    if (loadingEl) loadingEl.style.display = 'block';
    if (tableEl) tableEl.style.display = 'none';
    if (errorEl) errorEl.style.display = 'none';

    try {
        // Build query params
        const params = new URLSearchParams();
        params.append('event_type', 'Accepted');
        params.append('limit', LOGINS_PAGE_SIZE);
        params.append('offset', (page - 1) * LOGINS_PAGE_SIZE);

        const agentFilter = document.getElementById('loginAgentFilter')?.value;
        if (agentFilter) {
            params.append('agent_id', agentFilter);
        }

        const timeFilter = document.getElementById('loginTimeFilter')?.value;
        if (timeFilter) {
            const now = new Date();
            let startDate;
            if (timeFilter === '24h') startDate = new Date(now - 24 * 60 * 60 * 1000);
            else if (timeFilter === '7d') startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
            else if (timeFilter === '30d') startDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
            if (startDate) {
                params.append('start_date', startDate.toISOString().split('T')[0]);
            }
        }

        const searchFilter = document.getElementById('loginSearchFilter')?.value?.trim();
        if (searchFilter) {
            params.append('search', searchFilter);
        }

        const response = await fetch(`/api/events/list?${params.toString()}`);
        const data = await response.json();

        if (!data.success && !data.data) {
            throw new Error(data.error || 'Failed to load logins');
        }

        const events = data.data?.events || [];
        const pagination = data.data?.pagination || { total: events.length };

        loginsDataCache = { events, pagination };

        renderSuccessfulLogins(events, pagination);
        updateLoginsStats(events, pagination);

        if (loadingEl) loadingEl.style.display = 'none';
        if (tableEl) tableEl.style.display = 'block';

    } catch (error) {
        console.error('Error loading successful logins:', error);
        if (loadingEl) loadingEl.style.display = 'none';
        if (errorEl) {
            errorEl.style.display = 'block';
            errorEl.textContent = `Error: ${error.message}`;
        }
    }
}

/**
 * Render successful logins table
 */
function renderSuccessfulLogins(events, pagination) {
    const tbody = document.getElementById('loginsTableBody');
    if (!tbody) return;

    if (events.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="padding: 40px; text-align: center; color: var(--text-secondary);">
                    No successful logins found for the selected filters
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = events.map(event => {
        const riskScore = event.composite_risk_score || event.ml_risk_score || 0;
        const riskClass = riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'warning' : 'success';
        const riskBg = riskScore >= 70 ? TC.danger : riskScore >= 40 ? TC.warning : TC.successDark;

        const location = event.country_name
            ? `${event.city || ''} ${event.country_name}`.trim()
            : 'Unknown';

        const countryCode = event.country_code?.toLowerCase();
        const flagImg = countryCode
            ? `<img src="https://flagcdn.com/16x12/${countryCode}.png" alt="" style="margin-right: 6px; vertical-align: middle;">`
            : '';

        return `
            <tr style="border-bottom: 1px solid var(--border-light); cursor: pointer; transition: background 0.15s ease;"
                onclick="showLoginDetailModal(${event.id})"
                onmouseover="this.style.background='var(--hover-bg, #f5f5f5)'"
                onmouseout="this.style.background=''">
                <td style="padding: 10px; font-weight: 500;">
                    ${escapeHtml(event.target_username || 'unknown')}
                </td>
                <td style="padding: 10px; font-family: monospace; font-size: 12px;">
                    ${escapeHtml(event.source_ip || event.source_ip_text || 'N/A')}
                </td>
                <td style="padding: 10px; font-size: 12px;">
                    ${escapeHtml(event.agent_hostname || 'Unknown')}
                </td>
                <td style="padding: 10px; font-size: 12px;">
                    ${flagImg}${escapeHtml(location)}
                </td>
                <td style="padding: 10px; text-align: center;">
                    <span style="display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; background: ${riskBg}; color: white;">
                        ${Math.round(riskScore)}%
                    </span>
                </td>
                <td style="padding: 10px; font-size: 12px; color: var(--text-secondary);">
                    ${formatLoginTime(event.event_timestamp || event.timestamp)}
                </td>
                <td style="padding: 10px; text-align: center;">
                    <span style="display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 600; background: ${TC.successDark}; color: white;">
                        SUCCESS
                    </span>
                </td>
            </tr>
        `;
    }).join('');

    // Update pagination
    updateLoginsPagination(pagination);
}

/**
 * Update logins stats
 */
function updateLoginsStats(events, pagination) {
    const total = pagination?.total || events.length;
    const totalEl = document.getElementById('stat-total-logins');
    if (totalEl) totalEl.textContent = total.toLocaleString();

    // Count unique users and IPs from current page (approximation)
    const uniqueUsers = new Set(events.map(e => e.target_username)).size;
    const uniqueIPs = new Set(events.map(e => e.source_ip || e.source_ip_text)).size;

    const usersEl = document.getElementById('stat-unique-users');
    const ipsEl = document.getElementById('stat-unique-ips');
    if (usersEl) usersEl.textContent = uniqueUsers;
    if (ipsEl) ipsEl.textContent = uniqueIPs;

    // Today's logins (approximation from current filter)
    const today = new Date().toDateString();
    const todayLogins = events.filter(e => {
        const eventDate = new Date(e.event_timestamp || e.timestamp);
        return eventDate.toDateString() === today;
    }).length;
    const todayEl = document.getElementById('stat-today-logins');
    if (todayEl) todayEl.textContent = todayLogins;
}

/**
 * Update logins pagination
 */
function updateLoginsPagination(pagination) {
    const total = pagination?.total || 0;
    const showing = Math.min(currentLoginsPage * LOGINS_PAGE_SIZE, total);
    const start = ((currentLoginsPage - 1) * LOGINS_PAGE_SIZE) + 1;

    const infoEl = document.getElementById('loginsInfo');
    if (infoEl) {
        infoEl.textContent = `Showing ${start}-${showing} of ${total} logins`;
    }

    const prevBtn = document.getElementById('prevLoginsPage');
    const nextBtn = document.getElementById('nextLoginsPage');

    if (prevBtn) prevBtn.disabled = currentLoginsPage <= 1;
    if (nextBtn) nextBtn.disabled = showing >= total;
}

/**
 * Format login timestamp
 */
function formatLoginTime(timestamp) {
    if (!timestamp) return 'Unknown';
    if (window.TimeSettings?.isLoaded()) {
        return window.TimeSettings.formatFull(timestamp);
    }
    try {
        // Server timestamps are in +08:00 (Asia/Kuala_Lumpur)
        let dateStr = String(timestamp).replace(' ', 'T');
        if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.match(/T\d{2}:\d{2}:\d{2}-/)) {
            dateStr += '+08:00';
        }
        const date = new Date(dateStr);
        return date.toLocaleString();
    } catch {
        return timestamp;
    }
}

/**
 * Show login detail modal
 */
async function showLoginDetailModal(eventId) {
    // Use functions from blocked_ips_page.js if available
    if (typeof injectBlockModalStyles === 'function') injectBlockModalStyles();
    injectBlockDetailStyles();

    // Remove existing modals
    document.querySelectorAll('.block-modal-overlay').forEach(el => el.remove());

    // Show loading modal
    const loadingOverlay = document.createElement('div');
    loadingOverlay.className = 'block-modal-overlay';
    loadingOverlay.innerHTML = `
        <div class="block-modal" style="max-width: 650px;">
            <div class="block-modal-header" style="background: linear-gradient(135deg, ${TC.successDark} 0%, ${TC.successDark} 100%);">
                <h3 class="block-modal-title" style="color: white;">Loading Login Details...</h3>
                <button class="block-modal-close" style="color: rgba(255,255,255,0.8);">&times;</button>
            </div>
            <div class="block-modal-body" style="text-align: center; padding: 60px;">
                <div class="loading-spinner"></div>
                <p style="margin-top: 16px; color: var(--text-secondary);">Loading event details...</p>
            </div>
        </div>
    `;
    document.body.appendChild(loadingOverlay);
    document.body.style.overflow = 'hidden';

    loadingOverlay.querySelector('.block-modal-close').onclick = () => {
        loadingOverlay.remove();
        document.body.style.overflow = '';
    };

    try {
        // Fetch event details
        const response = await fetch(`/api/events/list?event_id=${eventId}`);
        const data = await response.json();

        loadingOverlay.remove();

        const events = data.data?.events || [];
        if (events.length === 0) {
            if (typeof showBlockNotification === 'function') {
                showBlockNotification('Event not found', 'error');
            }
            document.body.style.overflow = '';
            return;
        }

        const event = events[0];
        showLoginDetailModalContent(event);

    } catch (error) {
        console.error('Error loading login details:', error);
        loadingOverlay.remove();
        document.body.style.overflow = '';
        if (typeof showBlockNotification === 'function') {
            showBlockNotification('Error loading login details', 'error');
        }
    }
}

/**
 * Display the login detail modal content
 */
function showLoginDetailModalContent(event) {
    const overlay = document.createElement('div');
    overlay.className = 'block-modal-overlay';

    const riskScore = event.composite_risk_score || event.ml_risk_score || 0;
    const riskClass = riskScore >= 70 ? 'critical' : riskScore >= 40 ? 'high' : riskScore >= 20 ? 'moderate' : 'low';

    const location = event.country_name
        ? `${event.city || ''}, ${event.country_name}`.trim()
        : 'Unknown';

    const countryCode = event.country_code?.toLowerCase();
    const flagImg = countryCode
        ? `<img src="https://flagcdn.com/20x15/${countryCode}.png" alt="" style="vertical-align: middle; margin-right: 6px;">`
        : '';

    overlay.innerHTML = `
        <div class="block-modal block-detail-modal" style="max-width: 650px;">
            <div class="block-modal-header" style="background: linear-gradient(135deg, ${TC.successDark} 0%, ${TC.successDark} 100%);">
                <h3 class="block-modal-title" style="color: white;">
                    Successful Login Details
                </h3>
                <button class="block-modal-close" style="color: rgba(255,255,255,0.8);">&times;</button>
            </div>
            <div class="block-modal-body block-detail-body">
                <!-- Header Section -->
                <div class="detail-header-section">
                    <div class="detail-ip-display">
                        <span class="detail-ip-address">${escapeHtml(event.target_username || 'unknown')}</span>
                        <span class="detail-badge success">SUCCESSFUL</span>
                    </div>
                    <div class="detail-meta-row">
                        <span>IP: <code style="background: var(--surface); padding: 2px 6px; border-radius: 3px;">${escapeHtml(event.source_ip || event.source_ip_text || 'N/A')}</code></span>
                        <span>${flagImg}${escapeHtml(location)}</span>
                        <span>Agent: ${escapeHtml(event.agent_hostname || 'Unknown')}</span>
                    </div>
                </div>

                <!-- Login Details Section -->
                <div class="detail-section">
                    <div class="detail-section-title">
                        <span class="section-icon">📋</span>
                        Login Information
                    </div>
                    <div class="behavioral-grid" style="grid-template-columns: repeat(3, 1fr);">
                        <div class="behavioral-stat">
                            <div class="behavioral-value">${formatLoginTime(event.event_timestamp || event.timestamp)}</div>
                            <div class="behavioral-label">Login Time</div>
                        </div>
                        <div class="behavioral-stat">
                            <div class="behavioral-value">${escapeHtml(event.auth_method || 'password')}</div>
                            <div class="behavioral-label">Auth Method</div>
                        </div>
                        <div class="behavioral-stat">
                            <div class="behavioral-value">${event.source_port || 'N/A'}</div>
                            <div class="behavioral-label">Source Port</div>
                        </div>
                    </div>
                </div>

                <!-- Risk Assessment Section -->
                <div class="detail-section">
                    <div class="detail-section-title">
                        <span class="section-icon">⚠️</span>
                        Risk Assessment
                        <span class="detail-badge ${riskClass}" style="margin-left: 10px;">${Math.round(riskScore)}% RISK</span>
                    </div>
                    <div class="ml-contribution-box">
                        <div class="ml-main-score">
                            <div class="ml-score-circle ${riskClass}">
                                <span class="score-value">${Math.round(riskScore)}</span>
                                <span class="score-label">Risk</span>
                            </div>
                        </div>
                        <div class="ml-breakdown">
                            <div class="ml-breakdown-item">
                                <span class="breakdown-label">ML Risk Score</span>
                                <div class="breakdown-bar">
                                    <div class="breakdown-fill ${getScoreClassLocal(event.ml_risk_score || 0)}" style="width: ${event.ml_risk_score || 0}%"></div>
                                </div>
                                <span class="breakdown-value">${Math.round(event.ml_risk_score || 0)}%</span>
                            </div>
                            <div class="ml-breakdown-item">
                                <span class="breakdown-label">Anomaly Score</span>
                                <div class="breakdown-bar">
                                    <div class="breakdown-fill ${getScoreClassLocal(event.anomaly_score || 0)}" style="width: ${event.anomaly_score || 0}%"></div>
                                </div>
                                <span class="breakdown-value">${Math.round(event.anomaly_score || 0)}%</span>
                            </div>
                            <div class="ml-breakdown-item">
                                <span class="breakdown-label">Reputation Score</span>
                                <div class="breakdown-bar">
                                    <div class="breakdown-fill ${getScoreClassLocal(event.reputation_score || 0)}" style="width: ${event.reputation_score || 0}%"></div>
                                </div>
                                <span class="breakdown-value">${Math.round(event.reputation_score || 0)}%</span>
                            </div>
                        </div>
                    </div>
                    ${riskScore < 30 ? `
                        <div class="ml-contribution-summary" style="background: linear-gradient(135deg, rgba(16, 124, 16, 0.1) 0%, rgba(11, 92, 11, 0.1) 100%);">
                            <span class="section-icon">✅</span>
                            This login appears to be <strong>legitimate</strong> based on behavioral analysis
                        </div>
                    ` : `
                        <div class="ml-contribution-summary" style="background: linear-gradient(135deg, rgba(255, 185, 0, 0.1) 0%, rgba(217, 119, 6, 0.1) 100%);">
                            <span class="section-icon">⚠️</span>
                            This login has <strong>elevated risk indicators</strong> - review recommended
                        </div>
                    `}
                </div>

                <!-- ISP/Network Section -->
                ${event.isp || event.asn ? `
                <div class="detail-section">
                    <div class="detail-section-title">
                        <span class="section-icon">🌐</span>
                        Network Information
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                        <div>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">ISP</div>
                            <div style="font-weight: 500;">${escapeHtml(event.isp || 'Unknown')}</div>
                        </div>
                        <div>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">ASN</div>
                            <div style="font-weight: 500;">${escapeHtml(event.asn || 'Unknown')}</div>
                        </div>
                    </div>
                </div>
                ` : ''}
            </div>
            <div class="block-modal-footer">
                <button class="block-modal-btn block-modal-btn-secondary" onclick="window.location.hash='events-live?event=${event.id}'">
                    View in Events
                </button>
                <button class="block-modal-btn block-modal-btn-primary modal-close-action">Close</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    const closeModal = () => {
        overlay.style.animation = 'blockModalFadeIn 0.15s ease-out reverse';
        setTimeout(() => {
            overlay.remove();
            document.body.style.overflow = '';
        }, 140);
    };

    overlay.querySelector('.block-modal-close').onclick = closeModal;
    overlay.querySelector('.modal-close-action').onclick = closeModal;
    overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };

    document.addEventListener('keydown', function escHandler(e) {
        if (e.key === 'Escape') {
            closeModal();
            document.removeEventListener('keydown', escHandler);
        }
    });
}

function getScoreClassLocal(score) {
    return score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'moderate' : 'low';
}

/**
 * Inject styles for the detail modal
 */
function injectBlockDetailStyles() {
    if (document.getElementById('block-detail-styles')) return;

    const style = document.createElement('style');
    style.id = 'block-detail-styles';
    style.textContent = `
        .block-detail-body {
            max-height: 70vh;
            overflow-y: auto;
        }

        .detail-header-section {
            background: var(--surface, #fafafa);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }

        .detail-ip-display {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
        }

        .detail-ip-address {
            font-family: 'SF Mono', 'Consolas', monospace;
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
        }

        .detail-meta-row {
            display: flex;
            gap: 20px;
            font-size: 13px;
            color: var(--text-secondary);
        }

        .detail-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .detail-badge.critical { background: ${TC.danger}; color: white; }
        .detail-badge.high { background: ${TC.orange}; color: white; }
        .detail-badge.moderate { background: ${TC.warning}; color: ${TC.textPrimary}; }
        .detail-badge.success { background: ${TC.successDark}; color: white; }
        .detail-badge.info { background: ${TC.primary}; color: white; }
        .detail-badge.low { background: ${TC.textSecondary}; color: white; }

        .detail-section {
            background: var(--card-bg, white);
            border: 1px solid var(--border, #e0e0e0);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }

        .detail-section-title {
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .section-icon {
            font-size: 16px;
        }

        .behavioral-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }

        .behavioral-stat {
            background: var(--surface);
            border-radius: 8px;
            padding: 14px;
            text-align: center;
        }

        .behavioral-value {
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
        }

        .behavioral-label {
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 4px;
        }

        .ml-contribution-box {
            display: flex;
            gap: 24px;
            align-items: center;
        }

        .ml-main-score {
            flex-shrink: 0;
        }

        .ml-score-circle {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: var(--surface);
            border: 4px solid;
        }

        .ml-score-circle.critical { border-color: ${TC.danger}; }
        .ml-score-circle.high { border-color: ${TC.orange}; }
        .ml-score-circle.moderate { border-color: ${TC.warning}; }
        .ml-score-circle.low { border-color: ${TC.successDark}; }

        .score-value {
            font-size: 32px;
            font-weight: 700;
        }

        .score-label {
            font-size: 11px;
            color: var(--text-secondary);
        }

        .ml-breakdown {
            flex: 1;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .ml-breakdown-item {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .breakdown-label {
            width: 120px;
            font-size: 12px;
            color: var(--text-secondary);
        }

        .breakdown-bar {
            flex: 1;
            height: 8px;
            background: var(--surface);
            border-radius: 4px;
            overflow: hidden;
        }

        .breakdown-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .breakdown-fill.critical { background: ${TC.danger}; }
        .breakdown-fill.high { background: ${TC.orange}; }
        .breakdown-fill.moderate { background: ${TC.warning}; }
        .breakdown-fill.low { background: ${TC.successDark}; }

        .breakdown-value {
            width: 40px;
            font-size: 12px;
            font-weight: 600;
            text-align: right;
        }

        .ml-contribution-summary {
            margin-top: 16px;
            padding: 12px 16px;
            border-radius: 6px;
            font-size: 13px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border);
            border-top-color: var(--azure-blue, #0078D4);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @media (max-width: 600px) {
            .behavioral-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .ml-contribution-box {
                flex-direction: column;
            }
            .detail-meta-row {
                flex-direction: column;
                gap: 8px;
            }
        }
    `;
    document.head.appendChild(style);
}

// Make functions globally available
window.switchIPTab = switchIPTab;
window.loadSuccessfulLogins = loadSuccessfulLogins;
window.showLoginDetailModal = showLoginDetailModal;
window.populateLoginAgentFilter = populateLoginAgentFilter;
window.injectBlockDetailStyles = injectBlockDetailStyles;
