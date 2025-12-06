/**
 * IP Statistics Page Module
 * Handles display and interaction for IP statistics
 */

(function() {
    'use strict';

    let ipStatsCurrentPage = 1;
    let ipStatsCurrentLimit = 20;
    let ipStatsCurrentSort = 'last_seen';
    let ipStatsCurrentOrder = 'desc';
    let ipStatsCurrentFilters = {};

    /**
     * Load and display IP statistics page
     */
    window.loadIPStatsPage = async function() {
    try {
        // Load summary statistics
        await loadIPStatsSummary();

        // Load IP statistics table
        await loadIPStatsTable();

        // Setup event listeners
        setupIPStatsEventListeners();

    } catch (error) {
        console.error('Error loading IP Statistics page:', error);
        showNotification('Failed to load IP statistics', 'error');
    }
    };

    /**
     * Load summary statistics
     */
    async function loadIPStatsSummary() {
    try {
        // Use fetchWithCache if available to track cache status
        let data;
        if (typeof fetchWithCache === 'function') {
            data = await fetchWithCache('/api/dashboard/ip-stats/summary', 'ip_stats');
        } else {
            const response = await fetch('/api/dashboard/ip-stats/summary');
            data = await response.json();
        }

        if (data.success) {
            const summary = data.data.summary;
            const riskDist = data.data.risk_distribution;

            // Update summary cards
            document.getElementById('ip-stats-total-ips').textContent =
                summary.total_ips?.toLocaleString() || '0';

            document.getElementById('ip-stats-total-events').textContent =
                summary.total_events?.toLocaleString() || '0';

            document.getElementById('ip-stats-failed-events').textContent =
                summary.total_failed_events?.toLocaleString() || '0';

            document.getElementById('ip-stats-blocked-ips').textContent =
                summary.currently_blocked_count?.toLocaleString() || '0';

            // Update risk distribution
            const totalRisk = (riskDist.high || 0) + (riskDist.medium || 0) + (riskDist.low || 0);
            if (totalRisk > 0) {
                document.getElementById('ip-stats-high-risk').textContent =
                    `${riskDist.high || 0} (${Math.round((riskDist.high || 0) / totalRisk * 100)}%)`;
                document.getElementById('ip-stats-medium-risk').textContent =
                    `${riskDist.medium || 0} (${Math.round((riskDist.medium || 0) / totalRisk * 100)}%)`;
                document.getElementById('ip-stats-low-risk').textContent =
                    `${riskDist.low || 0} (${Math.round((riskDist.low || 0) / totalRisk * 100)}%)`;
            }

            // Update top countries table
            if (data.data.top_countries && data.data.top_countries.length > 0) {
                const tbody = document.getElementById('ip-stats-top-countries-body');
                tbody.innerHTML = data.data.top_countries.map(country => `
                    <tr>
                        <td>${country.country_code ? `<span class="flag-icon">${getFlagEmoji(country.country_code)}</span>` : ''} ${country.country_name || 'Unknown'}</td>
                        <td>${country.ip_count?.toLocaleString() || '0'}</td>
                        <td>${country.total_failed_events?.toLocaleString() || '0'}</td>
                    </tr>
                `).join('');
            }
        }

    } catch (error) {
        console.error('Error loading summary:', error);
    }
}

/**
 * Load IP statistics table
 */
async function loadIPStatsTable() {
    try {
        // Build query parameters
        const params = new URLSearchParams({
            page: ipStatsCurrentPage,
            limit: ipStatsCurrentLimit,
            sort: ipStatsCurrentSort,
            order: ipStatsCurrentOrder,
            ...ipStatsCurrentFilters
        });

        // Use fetchWithCache if available to track cache status
        let data;
        if (typeof fetchWithCache === 'function') {
            data = await fetchWithCache(`/api/dashboard/ip-stats/list?${params}`, 'ip_stats');
        } else {
            const response = await fetch(`/api/dashboard/ip-stats/list?${params}`);
            data = await response.json();
        }

        if (data.success) {
            renderIPStatsTable(data.data);
            renderIPStatsPagination(data.pagination);
        } else {
            throw new Error(data.error || 'Failed to load IP statistics');
        }

    } catch (error) {
        console.error('Error loading IP statistics table:', error);
        showNotification('Failed to load IP statistics table', 'error');
    }
}

/**
 * Render IP statistics table
 */
function renderIPStatsTable(stats) {
    const tbody = document.getElementById('ip-stats-table-body');

    if (stats.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="10" class="no-data">
                    <div class="no-data-message">
                        <span class="no-data-icon">📊</span>
                        <p>No IP statistics found</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = stats.map(stat => {
        const avgRiskScore = stat.avg_risk_score ? parseFloat(stat.avg_risk_score) : 0;
        const riskClass = getRiskClass(avgRiskScore);
        const riskLabel = getRiskLabel(avgRiskScore);
        const blockedBadge = stat.currently_blocked ?
            '<span class="badge badge-danger">Blocked</span>' : '';

        return `
            <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 12px;">
                    <a href="#" class="ip-link" data-ip="${stat.ip_address_text}" style="color: var(--primary); text-decoration: none;">${stat.ip_address_text}</a>
                    ${blockedBadge}
                </td>
                <td style="padding: 12px;">${stat.country_code ? `<span class="flag-icon">${getFlagEmoji(stat.country_code)}</span>` : ''} ${stat.country_name || 'Unknown'}</td>
                <td style="padding: 12px;">${stat.total_events?.toLocaleString() || '0'}</td>
                <td style="padding: 12px;">${stat.failed_events?.toLocaleString() || '0'}</td>
                <td style="padding: 12px;">${stat.successful_events?.toLocaleString() || '0'}</td>
                <td style="padding: 12px;">${stat.unique_servers || '0'}</td>
                <td style="padding: 12px;">
                    <span class="risk-badge risk-${riskClass}" style="padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">
                        ${avgRiskScore.toFixed(1)} - ${riskLabel}
                    </span>
                </td>
                <td style="padding: 12px;">${stat.anomaly_count || '0'}</td>
                <td style="padding: 12px;">${stat.times_blocked || '0'}</td>
                <td style="padding: 12px;">${formatDateTime(stat.last_seen)}</td>
            </tr>
        `;
    }).join('');

    // Setup click handlers for IP links
    document.querySelectorAll('.ip-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const ip = e.target.getAttribute('data-ip');
            showIPDetailsModal(ip);
        });
    });
}

/**
 * Render pagination
 */
function renderIPStatsPagination(pagination) {
    const container = document.getElementById('ip-stats-pagination');
    const { page, pages, total } = pagination;

    if (pages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '<div class="pagination">';

    // Previous button
    if (page > 1) {
        html += `<button class="pagination-btn" data-page="${page - 1}">← Previous</button>`;
    }

    // Page numbers
    const startPage = Math.max(1, page - 2);
    const endPage = Math.min(pages, page + 2);

    if (startPage > 1) {
        html += `<button class="pagination-btn" data-page="1">1</button>`;
        if (startPage > 2) html += `<span class="pagination-ellipsis">...</span>`;
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `<button class="pagination-btn ${i === page ? 'active' : ''}" data-page="${i}">${i}</button>`;
    }

    if (endPage < pages) {
        if (endPage < pages - 1) html += `<span class="pagination-ellipsis">...</span>`;
        html += `<button class="pagination-btn" data-page="${pages}">${pages}</button>`;
    }

    // Next button
    if (page < pages) {
        html += `<button class="pagination-btn" data-page="${page + 1}">Next →</button>`;
    }

    html += '</div>';
    html += `<div class="pagination-info">Showing page ${page} of ${pages} (${total} total)</div>`;

    container.innerHTML = html;

    // Setup click handlers
    container.querySelectorAll('.pagination-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            ipStatsCurrentPage = parseInt(btn.getAttribute('data-page'));
            loadIPStatsTable();
        });
    });
}

/**
 * Show IP details modal
 */
async function showIPDetailsModal(ip) {
    try {
        const response = await fetch(`/api/dashboard/ip-stats/${ip}`);
        const data = await response.json();

        if (data.success) {
            const stat = data.data.statistics;
            const events = data.data.recent_events;
            const history = data.data.blocking_history;

            // Build modal content
            const modalContent = `
                <div class="ip-details-modal">
                    <h3>IP Address: ${ip}</h3>

                    <div class="ip-details-grid">
                        <div class="ip-detail-section">
                            <h4>Location</h4>
                            <p><strong>Country:</strong> ${stat.country_name || 'Unknown'}</p>
                            <p><strong>City:</strong> ${stat.city || 'Unknown'}</p>
                            <p><strong>Region:</strong> ${stat.region || 'Unknown'}</p>
                        </div>

                        <div class="ip-detail-section">
                            <h4>Statistics</h4>
                            <p><strong>Total Events:</strong> ${stat.total_events?.toLocaleString() || '0'}</p>
                            <p><strong>Failed Events:</strong> ${stat.failed_events?.toLocaleString() || '0'}</p>
                            <p><strong>Successful Events:</strong> ${stat.successful_events?.toLocaleString() || '0'}</p>
                            <p><strong>Unique Servers:</strong> ${stat.unique_servers || '0'}</p>
                            <p><strong>Unique Usernames:</strong> ${stat.unique_usernames || '0'}</p>
                        </div>

                        <div class="ip-detail-section">
                            <h4>Risk Assessment</h4>
                            <p><strong>Avg Risk Score:</strong> ${stat.avg_risk_score ? parseFloat(stat.avg_risk_score).toFixed(1) : '0.0'}</p>
                            <p><strong>Max Risk Score:</strong> ${stat.max_risk_score || '0'}</p>
                            <p><strong>Threat Level:</strong> ${stat.overall_threat_level || 'Unknown'}</p>
                            <p><strong>Anomaly Count:</strong> ${stat.anomaly_count || '0'}</p>
                        </div>

                        <div class="ip-detail-section">
                            <h4>Blocking Info</h4>
                            <p><strong>Times Blocked:</strong> ${stat.times_blocked || '0'}</p>
                            <p><strong>Currently Blocked:</strong> ${stat.currently_blocked ? 'Yes' : 'No'}</p>
                            <p><strong>Last Blocked:</strong> ${formatDateTime(stat.last_blocked_at)}</p>
                        </div>
                    </div>

                    ${events.length > 0 ? `
                        <div class="ip-detail-section">
                            <h4>Recent Events</h4>
                            <table class="detail-table">
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>Username</th>
                                        <th>Server</th>
                                        <th>Risk</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${events.map(event => `
                                        <tr>
                                            <td>${event.event_type}</td>
                                            <td>${event.username || '-'}</td>
                                            <td>${event.server_name || '-'}</td>
                                            <td>${event.risk_score || '-'}</td>
                                            <td>${formatDateTime(event.event_timestamp)}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}

                    ${history.length > 0 ? `
                        <div class="ip-detail-section">
                            <h4>Blocking History</h4>
                            <table class="detail-table">
                                <thead>
                                    <tr>
                                        <th>Action</th>
                                        <th>Source</th>
                                        <th>Reason</th>
                                        <th>Time</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${history.map(action => `
                                        <tr>
                                            <td><span class="badge badge-${action.action_type === 'blocked' ? 'danger' : 'success'}">${action.action_type}</span></td>
                                            <td>${action.action_source}</td>
                                            <td>${action.reason || '-'}</td>
                                            <td>${formatDateTime(action.created_at)}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    ` : ''}
                </div>
            `;

            showModal('IP Statistics Details', modalContent);
        }

    } catch (error) {
        console.error('Error loading IP details:', error);
        showNotification('Failed to load IP details', 'error');
    }
}

/**
 * Setup event listeners
 */
function setupIPStatsEventListeners() {
    // Search
    const searchInput = document.getElementById('ip-stats-search');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                ipStatsCurrentFilters.search = e.target.value;
                ipStatsCurrentPage = 1;
                loadIPStatsTable();
            }, 500);
        });
    }

    // Risk level filter
    const riskFilter = document.getElementById('ip-stats-risk-filter');
    if (riskFilter) {
        riskFilter.addEventListener('change', (e) => {
            if (e.target.value) {
                ipStatsCurrentFilters.risk_level = e.target.value;
            } else {
                delete ipStatsCurrentFilters.risk_level;
            }
            ipStatsCurrentPage = 1;
            loadIPStatsTable();
        });
    }

    // Blocked filter
    const blockedFilter = document.getElementById('ip-stats-blocked-filter');
    if (blockedFilter) {
        blockedFilter.addEventListener('change', (e) => {
            if (e.target.value) {
                ipStatsCurrentFilters.blocked = e.target.value;
            } else {
                delete ipStatsCurrentFilters.blocked;
            }
            ipStatsCurrentPage = 1;
            loadIPStatsTable();
        });
    }

    // Sort
    const sortSelect = document.getElementById('ip-stats-sort');
    if (sortSelect) {
        sortSelect.addEventListener('change', (e) => {
            ipStatsCurrentSort = e.target.value;
            ipStatsCurrentPage = 1;
            loadIPStatsTable();
        });
    }

    // Refresh button
    const refreshBtn = document.getElementById('ip-stats-refresh-btn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            loadIPStatsSummary();
            loadIPStatsTable();
            showNotification('IP statistics refreshed', 'success');
        });
    }
}

/**
 * Helper: Get risk class
 */
function getRiskClass(score) {
    if (!score) return 'low';
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

/**
 * Helper: Get risk label
 */
function getRiskLabel(score) {
    if (!score) return 'Low';
    if (score >= 70) return 'High';
    if (score >= 40) return 'Medium';
    return 'Low';
}

/**
 * Helper: Get flag emoji
 */
function getFlagEmoji(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
}

/**
 * Helper: Format date time
 */
function formatDateTime(dateString) {
    if (!dateString) return '-';
    // Use TimeSettings if available
    if (window.TimeSettings?.isLoaded()) {
        return window.TimeSettings.formatFull(dateString);
    }
    const date = new Date(dateString);
    return date.toLocaleString();
}

})();
