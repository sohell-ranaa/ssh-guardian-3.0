/**
 * Events Analysis Page Module
 * Handles display and interaction for auth events analysis
 */

(function() {
    'use strict';

    let eventsCurrentPage = 1;
    let eventsCurrentLimit = 20;
    let eventsCurrentSort = 'timestamp';
    let eventsCurrentOrder = 'desc';
    let eventsCurrentFilters = {};

    /**
     * Load and display Events Analysis page
     */
    window.loadEventsAnalysisPage = async function() {
        console.log('Loading Events Analysis page...');

        try {
            // Load summary statistics
            await loadEventsSummary();

            // Load events table
            await loadEventsTable();

            // Load timeline chart
            await loadEventsTimeline();

            // Setup event listeners
            setupEventsEventListeners();

        } catch (error) {
            console.error('Error loading Events Analysis page:', error);
            showNotification('Failed to load events analysis', 'error');
        }
    };

    /**
     * Load summary statistics
     */
    async function loadEventsSummary() {
        try {
            const response = await fetch('/api/dashboard/events-analysis/summary');
            const data = await response.json();

            if (data.success) {
                const summary = data.data.summary;
                const riskDist = data.data.risk_distribution;
                const eventsByType = data.data.events_by_type;

                // Update summary cards
                document.getElementById('events-total-count').textContent =
                    summary.total_events?.toLocaleString() || '0';

                document.getElementById('events-failed-count').textContent =
                    summary.failed_count?.toLocaleString() || '0';

                document.getElementById('events-anomaly-count').textContent =
                    summary.anomaly_count?.toLocaleString() || '0';

                document.getElementById('events-blocked-count').textContent =
                    summary.blocked_count?.toLocaleString() || '0';

                // Update additional metrics
                document.getElementById('events-unique-ips').textContent =
                    summary.unique_ips?.toLocaleString() || '0';

                document.getElementById('events-unique-usernames').textContent =
                    summary.unique_usernames?.toLocaleString() || '0';

                const avgRisk = summary.avg_risk_score ? parseFloat(summary.avg_risk_score).toFixed(1) : '0.0';
                document.getElementById('events-avg-risk').textContent = avgRisk;

                // Update risk distribution
                const totalRisk = (riskDist.high || 0) + (riskDist.medium || 0) + (riskDist.low || 0);
                if (totalRisk > 0) {
                    document.getElementById('events-high-risk').textContent =
                        `${riskDist.high || 0} (${Math.round((riskDist.high || 0) / totalRisk * 100)}%)`;
                    document.getElementById('events-medium-risk').textContent =
                        `${riskDist.medium || 0} (${Math.round((riskDist.medium || 0) / totalRisk * 100)}%)`;
                    document.getElementById('events-low-risk').textContent =
                        `${riskDist.low || 0} (${Math.round((riskDist.low || 0) / totalRisk * 100)}%)`;
                }

                // Update top failure reasons
                if (data.data.top_failure_reasons && data.data.top_failure_reasons.length > 0) {
                    const tbody = document.getElementById('events-failure-reasons-body');
                    tbody.innerHTML = data.data.top_failure_reasons.map(reason => `
                        <tr>
                            <td style="padding: 8px;">${reason.failure_reason}</td>
                            <td style="padding: 8px;">${reason.count?.toLocaleString() || '0'}</td>
                        </tr>
                    `).join('');
                }

                // Update top usernames
                if (data.data.top_usernames && data.data.top_usernames.length > 0) {
                    const tbody = document.getElementById('events-top-usernames-body');
                    tbody.innerHTML = data.data.top_usernames.map(user => `
                        <tr>
                            <td style="padding: 8px;">${user.target_username}</td>
                            <td style="padding: 8px;">${user.count?.toLocaleString() || '0'}</td>
                            <td style="padding: 8px;">${user.failed_count?.toLocaleString() || '0'}</td>
                        </tr>
                    `).join('');
                }
            }

        } catch (error) {
            console.error('Error loading summary:', error);
        }
    }

    /**
     * Load events table
     */
    async function loadEventsTable() {
        try {
            // Build query parameters
            const params = new URLSearchParams({
                page: eventsCurrentPage,
                limit: eventsCurrentLimit,
                sort: eventsCurrentSort,
                order: eventsCurrentOrder,
                ...eventsCurrentFilters
            });

            const response = await fetch(`/api/dashboard/events-analysis/list?${params}`);
            const data = await response.json();

            if (data.success) {
                renderEventsTable(data.data);
                renderEventsPagination(data.pagination);
            } else {
                throw new Error(data.error || 'Failed to load events');
            }

        } catch (error) {
            console.error('Error loading events table:', error);
            showNotification('Failed to load events table', 'error');
        }
    }

    /**
     * Render events table
     */
    function renderEventsTable(events) {
        const tbody = document.getElementById('events-table-body');

        if (events.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" class="no-data">
                        <div class="no-data-message">
                            <span class="no-data-icon">📋</span>
                            <p>No events found</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = events.map(event => {
            const riskScore = event.ml_risk_score ? parseFloat(event.ml_risk_score) : 0;
            const riskClass = getRiskClass(riskScore);
            const eventTypeClass = getEventTypeClass(event.event_type);
            const anomalyBadge = event.is_anomaly ?
                '<span class="badge badge-warning">Anomaly</span>' : '';

            return `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px;">
                        <a href="#" class="event-link" data-event-id="${event.id}"
                           style="color: var(--primary); text-decoration: none;">
                            ${formatDateTime(event.timestamp)}
                        </a>
                    </td>
                    <td style="padding: 12px;">
                        <span class="event-type-badge event-type-${eventTypeClass}"
                              style="padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">
                            ${event.event_type}
                        </span>
                    </td>
                    <td style="padding: 12px;">${event.source_ip_text || '-'}</td>
                    <td style="padding: 12px;">${event.country_code ? `<span class="flag-icon">${getFlagEmoji(event.country_code)}</span>` : ''} ${event.country_name || 'Unknown'}</td>
                    <td style="padding: 12px;">${event.target_username || '-'}</td>
                    <td style="padding: 12px;">${event.target_server || '-'}</td>
                    <td style="padding: 12px;">
                        <span class="risk-badge risk-${riskClass}"
                              style="padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500;">
                            ${riskScore.toFixed(1)}
                        </span>
                    </td>
                    <td style="padding: 12px;">${event.auth_method || '-'}</td>
                    <td style="padding: 12px;">${anomalyBadge}</td>
                </tr>
            `;
        }).join('');

        // Setup click handlers for event links
        document.querySelectorAll('.event-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const eventId = e.target.getAttribute('data-event-id');
                showEventDetailsModal(eventId);
            });
        });
    }

    /**
     * Render pagination
     */
    function renderEventsPagination(pagination) {
        const container = document.getElementById('events-pagination');
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
                eventsCurrentPage = parseInt(btn.getAttribute('data-page'));
                loadEventsTable();
            });
        });
    }

    /**
     * Load events timeline
     */
    async function loadEventsTimeline() {
        try {
            const response = await fetch('/api/dashboard/events-analysis/timeline?interval=day&days=7');
            const data = await response.json();

            if (data.success && data.data.timeline.length > 0) {
                renderTimelineChart(data.data.timeline);
            }

        } catch (error) {
            console.error('Error loading timeline:', error);
        }
    }

    /**
     * Render timeline chart (simple text-based for now)
     */
    function renderTimelineChart(timeline) {
        const container = document.getElementById('events-timeline-chart');

        if (!container) return;

        // Simple table representation with better styling
        let html = '<table class="timeline-table" style="width: 100%; border-collapse: collapse; background: var(--background);">';
        html += '<thead><tr style="background: var(--surface); border-bottom: 2px solid var(--border);">';
        html += '<th style="padding: 12px; text-align: left; font-weight: 600; color: var(--text-primary);">Date</th>';
        html += '<th style="padding: 12px; text-align: center; font-weight: 600; color: var(--text-primary);">Total</th>';
        html += '<th style="padding: 12px; text-align: center; font-weight: 600; color: var(--text-primary);">Failed</th>';
        html += '<th style="padding: 12px; text-align: center; font-weight: 600; color: var(--text-primary);">Successful</th>';
        html += '<th style="padding: 12px; text-align: center; font-weight: 600; color: var(--text-primary);">Anomalies</th>';
        html += '</tr></thead><tbody>';

        timeline.forEach(point => {
            // Format date nicely
            const formattedDate = formatTimelineDate(point.time_period);

            html += '<tr style="border-bottom: 1px solid var(--border);">';
            html += `<td style="padding: 12px;">${formattedDate}</td>`;
            html += `<td style="padding: 12px; text-align: center; font-weight: 500;">${point.total_events || 0}</td>`;
            html += `<td style="padding: 12px; text-align: center; color: #ef4444;">${point.failed || 0}</td>`;
            html += `<td style="padding: 12px; text-align: center; color: #10b981;">${point.successful || 0}</td>`;
            html += `<td style="padding: 12px; text-align: center; color: #f59e0b;">${point.anomalies || 0}</td>`;
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    /**
     * Helper: Format timeline date
     */
    function formatTimelineDate(dateString) {
        if (!dateString) return '-';

        try {
            // Handle different date formats from SQL
            const date = new Date(dateString);

            // Format as "Mon, Dec 4"
            const options = { weekday: 'short', month: 'short', day: 'numeric' };
            return date.toLocaleDateString('en-US', options);
        } catch (e) {
            return dateString;
        }
    }

    /**
     * Show event details modal
     */
    async function showEventDetailsModal(eventId) {
        try {
            const response = await fetch(`/api/dashboard/events-analysis/${eventId}`);
            const data = await response.json();

            if (data.success) {
                const event = data.data.event;
                const relatedEvents = data.data.related_events;

                // Build modal content
                const modalContent = `
                    <div class="event-details-modal">
                        <h3>Event Details #${event.id}</h3>

                        <div class="event-details-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                            <div class="event-detail-section">
                                <h4>Event Information</h4>
                                <p><strong>Type:</strong> ${event.event_type}</p>
                                <p><strong>Timestamp:</strong> ${formatDateTime(event.timestamp)}</p>
                                <p><strong>Auth Method:</strong> ${event.auth_method || 'Unknown'}</p>
                                <p><strong>Failure Reason:</strong> ${event.failure_reason || '-'}</p>
                            </div>

                            <div class="event-detail-section">
                                <h4>Source Information</h4>
                                <p><strong>IP Address:</strong> ${event.source_ip_text}</p>
                                <p><strong>Country:</strong> ${event.country_name || 'Unknown'}</p>
                                <p><strong>City:</strong> ${event.city || 'Unknown'}</p>
                                <p><strong>Region:</strong> ${event.region || 'Unknown'}</p>
                            </div>

                            <div class="event-detail-section">
                                <h4>Target Information</h4>
                                <p><strong>Server:</strong> ${event.target_server || 'Unknown'}</p>
                                <p><strong>Username:</strong> ${event.target_username || '-'}</p>
                                <p><strong>Port:</strong> ${event.target_port || '-'}</p>
                            </div>

                            <div class="event-detail-section">
                                <h4>Risk Assessment</h4>
                                <p><strong>ML Risk Score:</strong> ${event.ml_risk_score || '0'}</p>
                                <p><strong>Threat Type:</strong> ${event.ml_threat_type || 'Unknown'}</p>
                                <p><strong>Is Anomaly:</strong> ${event.is_anomaly ? 'Yes' : 'No'}</p>
                                <p><strong>Was Blocked:</strong> ${event.was_blocked ? 'Yes' : 'No'}</p>
                            </div>
                        </div>

                        ${event.anomaly_reasons ? `
                            <div class="event-detail-section">
                                <h4>Anomaly Reasons</h4>
                                <p>${JSON.stringify(event.anomaly_reasons, null, 2)}</p>
                            </div>
                        ` : ''}

                        ${event.raw_log_line ? `
                            <div class="event-detail-section">
                                <h4>Raw Log Line</h4>
                                <pre style="background: var(--card-background); padding: 10px; border-radius: 4px; overflow-x: auto;">${event.raw_log_line}</pre>
                            </div>
                        ` : ''}

                        ${relatedEvents.length > 0 ? `
                            <div class="event-detail-section">
                                <h4>Related Events from Same IP</h4>
                                <table class="detail-table">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>Type</th>
                                            <th>Username</th>
                                            <th>Risk</th>
                                            <th>Time</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${relatedEvents.map(relEvent => `
                                            <tr>
                                                <td>${relEvent.id}</td>
                                                <td>${relEvent.event_type}</td>
                                                <td>${relEvent.target_username || '-'}</td>
                                                <td>${relEvent.ml_risk_score || '-'}</td>
                                                <td>${formatDateTime(relEvent.timestamp)}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        ` : ''}
                    </div>
                `;

                showModal('Event Details', modalContent);
            }

        } catch (error) {
            console.error('Error loading event details:', error);
            showNotification('Failed to load event details', 'error');
        }
    }

    /**
     * Setup event listeners
     */
    function setupEventsEventListeners() {
        // Search
        const searchInput = document.getElementById('events-search');
        if (searchInput) {
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    eventsCurrentFilters.search = e.target.value;
                    eventsCurrentPage = 1;
                    loadEventsTable();
                }, 500);
            });
        }

        // Event type filter
        const typeFilter = document.getElementById('events-type-filter');
        if (typeFilter) {
            typeFilter.addEventListener('change', (e) => {
                if (e.target.value) {
                    eventsCurrentFilters.event_type = e.target.value;
                } else {
                    delete eventsCurrentFilters.event_type;
                }
                eventsCurrentPage = 1;
                loadEventsTable();
            });
        }

        // Risk level filter
        const riskFilter = document.getElementById('events-risk-filter');
        if (riskFilter) {
            riskFilter.addEventListener('change', (e) => {
                if (e.target.value) {
                    eventsCurrentFilters.risk_level = e.target.value;
                } else {
                    delete eventsCurrentFilters.risk_level;
                }
                eventsCurrentPage = 1;
                loadEventsTable();
            });
        }

        // Anomaly filter
        const anomalyFilter = document.getElementById('events-anomaly-filter');
        if (anomalyFilter) {
            anomalyFilter.addEventListener('change', (e) => {
                if (e.target.value) {
                    eventsCurrentFilters.anomaly = e.target.value;
                } else {
                    delete eventsCurrentFilters.anomaly;
                }
                eventsCurrentPage = 1;
                loadEventsTable();
            });
        }

        // Sort
        const sortSelect = document.getElementById('events-sort');
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                eventsCurrentSort = e.target.value;
                eventsCurrentPage = 1;
                loadEventsTable();
            });
        }

        // Refresh button
        const refreshBtn = document.getElementById('events-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                loadEventsSummary();
                loadEventsTable();
                loadEventsTimeline();
                showNotification('Events refreshed', 'success');
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
     * Helper: Get event type class
     */
    function getEventTypeClass(eventType) {
        const typeMap = {
            'failed': 'danger',
            'successful': 'success',
            'invalid': 'warning'
        };
        return typeMap[eventType] || 'default';
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
        const date = new Date(dateString);
        return date.toLocaleString();
    }

})();
