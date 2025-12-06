/**
 * Events Analysis Page Module
 * Handles display and interaction for auth events analysis
 * With proper cache indicator integration
 */

(function() {
    'use strict';

    const CACHE_ENDPOINT = 'events_analysis';

    let eventsCurrentPage = 1;
    let eventsCurrentLimit = 20;
    let eventsCurrentSort = 'timestamp';
    let eventsCurrentOrder = 'desc';
    let eventsCurrentFilters = {};
    let listenersSetup = false;

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
     * Load and display Events Analysis page
     */
    window.loadEventsAnalysisPage = async function() {
        console.log('Loading Events Analysis page...');

        // Reset listeners flag when page loads (for SPA navigation)
        listenersSetup = false;

        // Set loading state
        if (typeof CacheManager !== 'undefined') {
            CacheManager.setLoading(CACHE_ENDPOINT);
        }

        // Show loading, hide error
        showLoadingState();

        const startTime = performance.now();

        try {
            // Load all data in parallel for faster page load
            const [summaryResult, eventsResult, timelineResult] = await Promise.all([
                loadEventsSummary(),
                loadEventsTable(),
                loadEventsTimeline()
            ]);

            // Calculate load time
            const loadTime = Math.round(performance.now() - startTime);

            // Determine if any data came from cache
            const fromCache = summaryResult?.fromCache || eventsResult?.fromCache || timelineResult?.fromCache;

            // Update cache indicator
            if (typeof CacheManager !== 'undefined') {
                CacheManager.updateStatus(CACHE_ENDPOINT, fromCache, loadTime);
                CacheManager.clearLoading(CACHE_ENDPOINT);
            }

            // Setup event listeners
            setupEventsEventListeners();

            // Hide loading state
            hideLoadingState();

            console.log(`Events Analysis loaded in ${loadTime}ms (from_cache: ${fromCache})`);

        } catch (error) {
            console.error('Error loading Events Analysis page:', error);

            if (typeof CacheManager !== 'undefined') {
                CacheManager.setError(CACHE_ENDPOINT, 'Failed to load events analysis');
            }

            showErrorState('Failed to load events analysis. Please try again.');

            if (typeof showNotification === 'function') {
                showNotification('Failed to load events analysis', 'error');
            }
        }
    };

    /**
     * Show loading state
     */
    function showLoadingState() {
        const errorEl = document.getElementById('events-analysis-error');
        if (errorEl) errorEl.style.display = 'none';
    }

    /**
     * Hide loading state
     */
    function hideLoadingState() {
        const errorEl = document.getElementById('events-analysis-error');
        if (errorEl) errorEl.style.display = 'none';
    }

    /**
     * Show error state
     */
    function showErrorState(message) {
        const errorEl = document.getElementById('events-analysis-error');
        if (errorEl) {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }
    }

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

                // Update summary cards
                updateElement('events-total-count', formatNumber(summary.total_events));
                updateElement('events-failed-count', formatNumber(summary.failed_count));
                updateElement('events-anomaly-count', formatNumber(summary.anomaly_count));
                updateElement('events-blocked-count', formatNumber(summary.blocked_count));

                // Update additional metrics
                updateElement('events-unique-ips', formatNumber(summary.unique_ips));
                updateElement('events-unique-usernames', formatNumber(summary.unique_usernames));

                const avgRisk = summary.avg_risk_score ? parseFloat(summary.avg_risk_score).toFixed(1) : '0.0';
                updateElement('events-avg-risk', avgRisk);

                // Update risk distribution
                const totalRisk = (riskDist.high || 0) + (riskDist.medium || 0) + (riskDist.low || 0);
                if (totalRisk > 0) {
                    updateElement('events-high-risk', `${formatNumber(riskDist.high || 0)} (${Math.round((riskDist.high || 0) / totalRisk * 100)}%)`);
                    updateElement('events-medium-risk', `${formatNumber(riskDist.medium || 0)} (${Math.round((riskDist.medium || 0) / totalRisk * 100)}%)`);
                    updateElement('events-low-risk', `${formatNumber(riskDist.low || 0)} (${Math.round((riskDist.low || 0) / totalRisk * 100)}%)`);
                }

                // Update top failure reasons (with HTML escaping)
                if (data.data.top_failure_reasons && data.data.top_failure_reasons.length > 0) {
                    const tbody = document.getElementById('events-failure-reasons-body');
                    if (tbody) {
                        tbody.innerHTML = data.data.top_failure_reasons.map(reason => `
                            <tr style="border-bottom: 1px solid var(--border);">
                                <td style="padding: 8px;">${escapeHtml(reason.failure_reason)}</td>
                                <td style="padding: 8px;">${formatNumber(reason.count)}</td>
                            </tr>
                        `).join('');
                    }
                } else {
                    const tbody = document.getElementById('events-failure-reasons-body');
                    if (tbody) {
                        tbody.innerHTML = '<tr><td colspan="2" style="padding: 20px; text-align: center; color: var(--text-secondary);">No failure reasons found</td></tr>';
                    }
                }

                // Update top usernames (with HTML escaping)
                if (data.data.top_usernames && data.data.top_usernames.length > 0) {
                    const tbody = document.getElementById('events-top-usernames-body');
                    if (tbody) {
                        tbody.innerHTML = data.data.top_usernames.map(user => `
                            <tr style="border-bottom: 1px solid var(--border);">
                                <td style="padding: 8px; font-family: monospace;">${escapeHtml(user.target_username)}</td>
                                <td style="padding: 8px;">${formatNumber(user.count)}</td>
                                <td style="padding: 8px;">${formatNumber(user.failed_count)}</td>
                            </tr>
                        `).join('');
                    }
                } else {
                    const tbody = document.getElementById('events-top-usernames-body');
                    if (tbody) {
                        tbody.innerHTML = '<tr><td colspan="3" style="padding: 20px; text-align: center; color: var(--text-secondary);">No usernames found</td></tr>';
                    }
                }

                return { success: true, fromCache: data.from_cache === true };
            }

            return { success: false, fromCache: false };

        } catch (error) {
            console.error('Error loading summary:', error);
            return { success: false, fromCache: false };
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
                order: eventsCurrentOrder
            });

            // Add filters
            Object.entries(eventsCurrentFilters).forEach(([key, value]) => {
                if (value) params.append(key, value);
            });

            const response = await fetch(`/api/dashboard/events-analysis/list?${params}`);
            const data = await response.json();

            if (data.success) {
                renderEventsTable(data.data);
                renderEventsPagination(data.pagination);
                return { success: true, fromCache: data.from_cache === true };
            } else {
                throw new Error(data.error || 'Failed to load events');
            }

        } catch (error) {
            console.error('Error loading events table:', error);
            const tbody = document.getElementById('events-table-body');
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="9" style="padding: 20px; text-align: center; color: #D13438;">Error loading events</td></tr>';
            }
            return { success: false, fromCache: false };
        }
    }

    /**
     * Render events table (with XSS protection)
     */
    function renderEventsTable(events) {
        const tbody = document.getElementById('events-table-body');
        if (!tbody) return;

        if (!events || events.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="padding: 40px; text-align: center; color: var(--text-secondary);">
                        No events found
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = events.map(event => {
            const riskScore = event.ml_risk_score ? parseFloat(event.ml_risk_score) : 0;
            const riskClass = getRiskClass(riskScore);
            const riskColor = getRiskColor(riskClass);
            const eventTypeColor = getEventTypeColor(event.event_type);
            const anomalyBadge = event.is_anomaly ?
                '<span style="background: #E6A502; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">Anomaly</span>' : '';

            // Escape all user-provided data
            const safeIp = escapeHtml(event.source_ip_text);
            const safeUsername = escapeHtml(event.target_username);
            const safeServer = escapeHtml(event.target_server);
            const safeCountry = escapeHtml(event.country_name);
            const safeAuthMethod = escapeHtml(event.auth_method);
            const safeEventType = escapeHtml(event.event_type);

            return `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px;">
                        <a href="#" class="event-link" data-event-id="${event.id}"
                           style="color: var(--azure-blue); text-decoration: none; font-size: 12px;">
                            ${formatDateTime(event.timestamp)}
                        </a>
                    </td>
                    <td style="padding: 12px;">
                        <span style="background: ${eventTypeColor}; color: white; padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; text-transform: uppercase;">
                            ${safeEventType}
                        </span>
                    </td>
                    <td style="padding: 12px; font-family: monospace; font-size: 13px;">${safeIp || '-'}</td>
                    <td style="padding: 12px; font-size: 12px;">
                        ${event.country_code ? `<span style="font-size: 16px;">${getFlagEmoji(event.country_code)}</span> ` : ''}
                        ${safeCountry || 'Unknown'}
                    </td>
                    <td style="padding: 12px; font-family: monospace; font-size: 13px;">${safeUsername || '-'}</td>
                    <td style="padding: 12px; font-size: 12px;">${safeServer || '-'}</td>
                    <td style="padding: 12px;">
                        <span style="background: ${riskColor}; color: white; padding: 4px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;">
                            ${riskScore.toFixed(1)}
                        </span>
                    </td>
                    <td style="padding: 12px; font-size: 12px;">${safeAuthMethod || '-'}</td>
                    <td style="padding: 12px;">${anomalyBadge}</td>
                </tr>
            `;
        }).join('');

        // Setup click handlers for event links using event delegation
        attachEventLinkListeners();
    }

    /**
     * Attach event link listeners using event delegation (prevents memory leaks)
     */
    function attachEventLinkListeners() {
        const tbody = document.getElementById('events-table-body');
        if (!tbody) return;

        // Remove old listener if exists
        tbody.removeEventListener('click', handleEventLinkClick);
        // Add new listener
        tbody.addEventListener('click', handleEventLinkClick);
    }

    /**
     * Handle event link clicks
     */
    function handleEventLinkClick(e) {
        const link = e.target.closest('.event-link');
        if (link) {
            e.preventDefault();
            const eventId = link.getAttribute('data-event-id');
            if (eventId) {
                showEventDetailsModal(eventId);
            }
        }
    }

    /**
     * Render pagination
     */
    function renderEventsPagination(pagination) {
        const container = document.getElementById('events-pagination');
        if (!container) return;

        const { page, pages, total } = pagination;

        if (pages <= 1) {
            container.innerHTML = `<div style="color: var(--text-secondary); font-size: 13px;">Total: ${formatNumber(total)} events</div>`;
            return;
        }

        let html = '<div style="display: flex; gap: 8px; align-items: center;">';

        // Previous button
        if (page > 1) {
            html += `<button class="pagination-btn" data-page="${page - 1}" style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 13px;">← Previous</button>`;
        }

        // Page numbers
        const startPage = Math.max(1, page - 2);
        const endPage = Math.min(pages, page + 2);

        if (startPage > 1) {
            html += `<button class="pagination-btn" data-page="1" style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 13px;">1</button>`;
            if (startPage > 2) html += `<span style="padding: 0 8px; color: var(--text-secondary);">...</span>`;
        }

        for (let i = startPage; i <= endPage; i++) {
            const isActive = i === page;
            html += `<button class="pagination-btn" data-page="${i}" style="padding: 6px 12px; border: 1px solid ${isActive ? 'var(--azure-blue)' : 'var(--border)'}; background: ${isActive ? 'var(--azure-blue)' : 'var(--surface)'}; color: ${isActive ? 'white' : 'inherit'}; border-radius: 3px; cursor: pointer; font-size: 13px;">${i}</button>`;
        }

        if (endPage < pages) {
            if (endPage < pages - 1) html += `<span style="padding: 0 8px; color: var(--text-secondary);">...</span>`;
            html += `<button class="pagination-btn" data-page="${pages}" style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 13px;">${pages}</button>`;
        }

        // Next button
        if (page < pages) {
            html += `<button class="pagination-btn" data-page="${page + 1}" style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 13px;">Next →</button>`;
        }

        html += '</div>';
        html += `<div style="color: var(--text-secondary); font-size: 13px; margin-top: 8px;">Page ${page} of ${pages} (${formatNumber(total)} total)</div>`;

        container.innerHTML = html;

        // Setup click handlers using event delegation
        container.removeEventListener('click', handlePaginationClick);
        container.addEventListener('click', handlePaginationClick);
    }

    /**
     * Handle pagination clicks
     */
    function handlePaginationClick(e) {
        const btn = e.target.closest('.pagination-btn');
        if (btn) {
            eventsCurrentPage = parseInt(btn.getAttribute('data-page'));
            loadEventsTable();
        }
    }

    /**
     * Load events timeline
     */
    async function loadEventsTimeline() {
        try {
            const response = await fetch('/api/dashboard/events-analysis/timeline?interval=day&days=7');
            const data = await response.json();

            if (data.success && data.data.timeline && data.data.timeline.length > 0) {
                renderTimelineChart(data.data.timeline);
                return { success: true, fromCache: data.from_cache === true };
            } else {
                const container = document.getElementById('events-timeline-chart');
                if (container) {
                    container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">No timeline data available</p>';
                }
            }

            return { success: true, fromCache: data.from_cache === true };

        } catch (error) {
            console.error('Error loading timeline:', error);
            const container = document.getElementById('events-timeline-chart');
            if (container) {
                container.innerHTML = '<p style="text-align: center; color: #D13438; padding: 20px;">Error loading timeline</p>';
            }
            return { success: false, fromCache: false };
        }
    }

    /**
     * Render timeline chart as a visual bar chart
     */
    function renderTimelineChart(timeline) {
        const container = document.getElementById('events-timeline-chart');
        if (!container) return;

        // Find max value for scaling
        const maxTotal = Math.max(...timeline.map(p => p.total_events || 0), 1);

        let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';

        timeline.forEach(point => {
            const formattedDate = formatTimelineDate(point.time_period);
            const total = point.total_events || 0;
            const failed = point.failed || 0;
            const successful = point.successful || 0;
            const anomalies = point.anomalies || 0;

            const barWidth = Math.max((total / maxTotal) * 100, 2);
            const failedWidth = total > 0 ? (failed / total) * 100 : 0;
            const successWidth = total > 0 ? (successful / total) * 100 : 0;

            html += `
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div style="width: 80px; font-size: 12px; color: var(--text-secondary); text-align: right;">${formattedDate}</div>
                    <div style="flex: 1; height: 24px; background: var(--background); border-radius: 3px; overflow: hidden; position: relative;">
                        <div style="position: absolute; left: 0; top: 0; height: 100%; width: ${barWidth}%; display: flex;">
                            <div style="height: 100%; width: ${successWidth}%; background: #10b981;" title="Successful: ${successful}"></div>
                            <div style="height: 100%; width: ${failedWidth}%; background: #ef4444;" title="Failed: ${failed}"></div>
                        </div>
                    </div>
                    <div style="width: 120px; font-size: 11px; color: var(--text-secondary);">
                        <span style="color: var(--text-primary); font-weight: 500;">${formatNumber(total)}</span>
                        ${anomalies > 0 ? `<span style="color: #f59e0b; margin-left: 4px;">(${anomalies} anom)</span>` : ''}
                    </div>
                </div>
            `;
        });

        html += '</div>';

        // Add legend
        html += `
            <div style="display: flex; gap: 16px; margin-top: 12px; justify-content: center; font-size: 11px;">
                <div style="display: flex; align-items: center; gap: 4px;">
                    <div style="width: 12px; height: 12px; background: #10b981; border-radius: 2px;"></div>
                    <span>Successful</span>
                </div>
                <div style="display: flex; align-items: center; gap: 4px;">
                    <div style="width: 12px; height: 12px; background: #ef4444; border-radius: 2px;"></div>
                    <span>Failed</span>
                </div>
                <div style="display: flex; align-items: center; gap: 4px;">
                    <div style="width: 12px; height: 12px; background: #f59e0b; border-radius: 2px;"></div>
                    <span>Anomalies</span>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    /**
     * Helper: Format timeline date
     */
    function formatTimelineDate(dateString) {
        if (!dateString) return '-';

        try {
            const date = new Date(dateString);
            const options = { weekday: 'short', month: 'short', day: 'numeric' };
            return date.toLocaleDateString('en-US', options);
        } catch (e) {
            return String(dateString);
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
                const relatedEvents = data.data.related_events || [];

                // Build modal content with escaped data
                const modalContent = `
                    <div style="max-height: 70vh; overflow-y: auto;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
                            <div style="background: var(--background); padding: 16px; border-radius: 4px;">
                                <h4 style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-secondary);">Event Information</h4>
                                <p style="margin: 4px 0;"><strong>Type:</strong> ${escapeHtml(event.event_type)}</p>
                                <p style="margin: 4px 0;"><strong>Timestamp:</strong> ${formatDateTime(event.timestamp)}</p>
                                <p style="margin: 4px 0;"><strong>Auth Method:</strong> ${escapeHtml(event.auth_method) || 'Unknown'}</p>
                                <p style="margin: 4px 0;"><strong>Failure Reason:</strong> ${escapeHtml(event.failure_reason) || '-'}</p>
                            </div>

                            <div style="background: var(--background); padding: 16px; border-radius: 4px;">
                                <h4 style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-secondary);">Source Information</h4>
                                <p style="margin: 4px 0;"><strong>IP Address:</strong> ${escapeHtml(event.source_ip_text)}</p>
                                <p style="margin: 4px 0;"><strong>Country:</strong> ${escapeHtml(event.country_name) || 'Unknown'}</p>
                                <p style="margin: 4px 0;"><strong>City:</strong> ${escapeHtml(event.city) || 'Unknown'}</p>
                                <p style="margin: 4px 0;"><strong>Region:</strong> ${escapeHtml(event.region) || 'Unknown'}</p>
                            </div>

                            <div style="background: var(--background); padding: 16px; border-radius: 4px;">
                                <h4 style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-secondary);">Target Information</h4>
                                <p style="margin: 4px 0;"><strong>Server:</strong> ${escapeHtml(event.target_server) || 'Unknown'}</p>
                                <p style="margin: 4px 0;"><strong>Username:</strong> ${escapeHtml(event.target_username) || '-'}</p>
                                <p style="margin: 4px 0;"><strong>Port:</strong> ${escapeHtml(event.target_port) || '-'}</p>
                            </div>

                            <div style="background: var(--background); padding: 16px; border-radius: 4px;">
                                <h4 style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-secondary);">Risk Assessment</h4>
                                <p style="margin: 4px 0;"><strong>ML Risk Score:</strong> ${event.ml_risk_score || '0'}</p>
                                <p style="margin: 4px 0;"><strong>Threat Type:</strong> ${escapeHtml(event.ml_threat_type) || 'Unknown'}</p>
                                <p style="margin: 4px 0;"><strong>Is Anomaly:</strong> ${event.is_anomaly ? 'Yes' : 'No'}</p>
                                <p style="margin: 4px 0;"><strong>Was Blocked:</strong> ${event.was_blocked ? 'Yes' : 'No'}</p>
                            </div>
                        </div>

                        ${event.anomaly_reasons ? `
                            <div style="background: var(--background); padding: 16px; border-radius: 4px; margin-bottom: 20px;">
                                <h4 style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-secondary);">Anomaly Reasons</h4>
                                <pre style="margin: 0; font-size: 12px; white-space: pre-wrap; word-break: break-word;">${escapeHtml(typeof event.anomaly_reasons === 'string' ? event.anomaly_reasons : JSON.stringify(event.anomaly_reasons, null, 2))}</pre>
                            </div>
                        ` : ''}

                        ${event.raw_log_line ? `
                            <div style="background: var(--background); padding: 16px; border-radius: 4px; margin-bottom: 20px;">
                                <h4 style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-secondary);">Raw Log Line</h4>
                                <pre style="margin: 0; font-size: 11px; white-space: pre-wrap; word-break: break-word; font-family: monospace;">${escapeHtml(event.raw_log_line)}</pre>
                            </div>
                        ` : ''}

                        ${relatedEvents.length > 0 ? `
                            <div style="background: var(--background); padding: 16px; border-radius: 4px;">
                                <h4 style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-secondary);">Related Events from Same IP (Last 10)</h4>
                                <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
                                    <thead>
                                        <tr style="border-bottom: 1px solid var(--border);">
                                            <th style="padding: 8px; text-align: left;">ID</th>
                                            <th style="padding: 8px; text-align: left;">Type</th>
                                            <th style="padding: 8px; text-align: left;">Username</th>
                                            <th style="padding: 8px; text-align: left;">Risk</th>
                                            <th style="padding: 8px; text-align: left;">Time</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${relatedEvents.map(relEvent => `
                                            <tr style="border-bottom: 1px solid var(--border);">
                                                <td style="padding: 8px;">${relEvent.id}</td>
                                                <td style="padding: 8px;">${escapeHtml(relEvent.event_type)}</td>
                                                <td style="padding: 8px;">${escapeHtml(relEvent.target_username) || '-'}</td>
                                                <td style="padding: 8px;">${relEvent.ml_risk_score || '-'}</td>
                                                <td style="padding: 8px;">${formatDateTime(relEvent.timestamp)}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        ` : ''}
                    </div>
                `;

                // Try to show modal, fallback to alert if not available
                if (typeof showModal === 'function') {
                    showModal(`Event Details #${event.id}`, modalContent);
                } else {
                    // Fallback: create simple modal
                    showSimpleModal(`Event Details #${event.id}`, modalContent);
                }
            } else {
                throw new Error(data.error || 'Event not found');
            }

        } catch (error) {
            console.error('Error loading event details:', error);
            if (typeof showNotification === 'function') {
                showNotification('Failed to load event details', 'error');
            } else {
                alert('Failed to load event details');
            }
        }
    }

    /**
     * Simple modal fallback
     */
    function showSimpleModal(title, content) {
        // Remove existing modal
        const existingModal = document.getElementById('simple-modal-overlay');
        if (existingModal) existingModal.remove();

        const overlay = document.createElement('div');
        overlay.id = 'simple-modal-overlay';
        overlay.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';

        overlay.innerHTML = `
            <div style="background: var(--surface, #fff); border-radius: 8px; max-width: 800px; width: 90%; max-height: 90vh; overflow: hidden; box-shadow: 0 4px 24px rgba(0,0,0,0.2);">
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--border, #eee);">
                    <h3 style="margin: 0; font-size: 18px;">${escapeHtml(title)}</h3>
                    <button id="simple-modal-close" style="background: none; border: none; font-size: 24px; cursor: pointer; color: var(--text-secondary, #666);">&times;</button>
                </div>
                <div style="padding: 20px; overflow-y: auto; max-height: calc(90vh - 60px);">
                    ${content}
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        // Close handlers
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.remove();
        });
        document.getElementById('simple-modal-close').addEventListener('click', () => overlay.remove());
    }

    /**
     * Setup event listeners
     */
    function setupEventsEventListeners() {
        // Prevent duplicate listeners only within same page load
        if (listenersSetup) return;
        listenersSetup = true;

        // Search with debounce
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
                loadEventsAnalysisPage();
            });
        }
    }

    /**
     * Helper: Update element text content safely
     */
    function updateElement(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    /**
     * Helper: Format number with locale
     */
    function formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return Number(num).toLocaleString();
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
     * Helper: Get risk color
     */
    function getRiskColor(riskClass) {
        const colors = {
            'high': '#D13438',
            'medium': '#E6A502',
            'low': '#2EA44F'
        };
        return colors[riskClass] || colors.low;
    }

    /**
     * Helper: Get event type color
     */
    function getEventTypeColor(eventType) {
        const colors = {
            'failed': '#D13438',
            'successful': '#2EA44F',
            'invalid': '#605E5C'
        };
        return colors[eventType] || colors.invalid;
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
        try {
            // Use TimeSettings if available
            if (window.TimeSettings?.isLoaded()) {
                return window.TimeSettings.formatFull(dateString);
            }
            const date = new Date(dateString);
            return date.toLocaleString();
        } catch (e) {
            return String(dateString);
        }
    }

})();
