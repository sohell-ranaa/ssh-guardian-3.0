/**
 * Events Timeline Page Module
 * Handles display and interaction for events timeline visualization
 */

(function() {
    'use strict';

    const CACHE_ENDPOINT = 'events_timeline';

    let currentInterval = 'day';
    let currentDays = 7;
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
     * Safe notification helper
     */
    function notify(message, type) {
        if (typeof showNotification === 'function') {
            showNotification(message, type);
        } else {
            console.log(`[${type}] ${message}`);
        }
    }

    /**
     * Load and display Events Timeline page
     */
    window.loadEventsTimelinePage = async function() {
        console.log('Loading Events Timeline page...');

        // Reset listeners flag for SPA navigation
        listenersSetup = false;

        // Set loading state
        showLoadingState();

        if (typeof CacheManager !== 'undefined') {
            CacheManager.setLoading(CACHE_ENDPOINT);
        }

        const startTime = performance.now();

        try {
            // Load timeline data
            const result = await loadTimelineData();

            // Calculate load time
            const loadTime = Math.round(performance.now() - startTime);

            // Update cache indicator
            if (typeof CacheManager !== 'undefined') {
                CacheManager.updateStatus(CACHE_ENDPOINT, result.fromCache, loadTime);
                CacheManager.clearLoading(CACHE_ENDPOINT);
            }

            // Setup event listeners
            setupTimelineEventListeners();

            // Hide loading, show content
            hideLoadingState();

            console.log(`Events Timeline loaded in ${loadTime}ms (from_cache: ${result.fromCache})`);

        } catch (error) {
            console.error('Error loading Events Timeline page:', error);
            showErrorState('Failed to load timeline data. Please try again.');

            if (typeof CacheManager !== 'undefined') {
                CacheManager.setError(CACHE_ENDPOINT, 'Failed to load');
            }

            notify('Failed to load events timeline', 'error');
        }
    };

    /**
     * Show loading state
     */
    function showLoadingState() {
        const loadingEl = document.getElementById('timeline-loading');
        const contentEl = document.getElementById('timeline-content');
        const errorEl = document.getElementById('timeline-error');

        if (loadingEl) loadingEl.style.display = 'block';
        if (contentEl) contentEl.style.display = 'none';
        if (errorEl) errorEl.style.display = 'none';
    }

    /**
     * Hide loading state
     */
    function hideLoadingState() {
        const loadingEl = document.getElementById('timeline-loading');
        const contentEl = document.getElementById('timeline-content');
        const errorEl = document.getElementById('timeline-error');

        if (loadingEl) loadingEl.style.display = 'none';
        if (contentEl) contentEl.style.display = 'block';
        if (errorEl) errorEl.style.display = 'none';
    }

    /**
     * Show error state
     */
    function showErrorState(message) {
        const loadingEl = document.getElementById('timeline-loading');
        const contentEl = document.getElementById('timeline-content');
        const errorEl = document.getElementById('timeline-error');

        if (loadingEl) loadingEl.style.display = 'none';
        if (contentEl) contentEl.style.display = 'none';
        if (errorEl) {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }
    }

    /**
     * Load timeline data
     */
    async function loadTimelineData() {
        try {
            const response = await fetch(`/api/dashboard/events-analysis/timeline?interval=${currentInterval}&days=${currentDays}`);
            const data = await response.json();

            if (data.success) {
                renderTimelineVisualization(data.data.timeline, data.data.interval);
                renderTimelineTable(data.data.timeline);
                return { success: true, fromCache: data.from_cache === true };
            } else {
                throw new Error(data.error || 'Failed to load timeline');
            }

        } catch (error) {
            console.error('Error loading timeline data:', error);
            throw error;
        }
    }

    /**
     * Render timeline visualization (bar chart)
     */
    function renderTimelineVisualization(timeline, interval) {
        const container = document.getElementById('timeline-chart-container');

        if (!container) return;

        if (!timeline || timeline.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 40px;">No timeline data available</p>';
            return;
        }

        // Find max value for scaling
        const maxValue = Math.max(...timeline.map(t => t.total_events || 0), 1);

        let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';

        timeline.forEach(point => {
            const total = point.total_events || 0;
            const failed = point.failed || 0;
            const successful = point.successful || 0;
            const invalid = point.invalid || 0;
            const anomalies = point.anomalies || 0;

            // Calculate percentages for stacked bar
            const failedPercent = total > 0 ? (failed / total) * 100 : 0;
            const successfulPercent = total > 0 ? (successful / total) * 100 : 0;
            const invalidPercent = total > 0 ? (invalid / total) * 100 : 0;

            // Calculate bar width relative to max
            const barWidth = Math.max((total / maxValue) * 100, 2);

            const formattedDate = escapeHtml(formatTimelineDate(point.time_period, interval));

            html += `
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div style="min-width: 120px; font-size: 13px; color: var(--text-secondary);">
                        ${formattedDate}
                    </div>
                    <div style="flex: 1; position: relative;">
                        <div style="display: flex; height: 32px; background: var(--background); border-radius: 4px; overflow: hidden; width: ${barWidth}%; min-width: 2px;">
                            ${successful > 0 ? `<div style="width: ${successfulPercent}%; background: #10b981;" title="Successful: ${successful.toLocaleString()}"></div>` : ''}
                            ${failed > 0 ? `<div style="width: ${failedPercent}%; background: #ef4444;" title="Failed: ${failed.toLocaleString()}"></div>` : ''}
                            ${invalid > 0 ? `<div style="width: ${invalidPercent}%; background: #6b7280;" title="Invalid: ${invalid.toLocaleString()}"></div>` : ''}
                        </div>
                        ${anomalies > 0 ? `<div style="position: absolute; right: -8px; top: 50%; transform: translateY(-50%); width: 6px; height: 6px; background: #f59e0b; border-radius: 50%;" title="Anomalies: ${anomalies.toLocaleString()}"></div>` : ''}
                    </div>
                    <div style="min-width: 80px; text-align: right; font-weight: 600; font-size: 14px;">
                        ${total.toLocaleString()}
                        ${anomalies > 0 ? `<span style="color: #f59e0b; font-size: 11px; margin-left: 4px;">(${anomalies})</span>` : ''}
                    </div>
                </div>
            `;
        });

        html += '</div>';

        // Add legend
        html += `
            <div style="display: flex; justify-content: center; gap: 24px; margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border); flex-wrap: wrap;">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div style="width: 16px; height: 16px; background: #10b981; border-radius: 2px;"></div>
                    <span style="font-size: 13px; color: var(--text-secondary);">Successful</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div style="width: 16px; height: 16px; background: #ef4444; border-radius: 2px;"></div>
                    <span style="font-size: 13px; color: var(--text-secondary);">Failed</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div style="width: 16px; height: 16px; background: #6b7280; border-radius: 2px;"></div>
                    <span style="font-size: 13px; color: var(--text-secondary);">Invalid</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div style="width: 6px; height: 6px; background: #f59e0b; border-radius: 50%;"></div>
                    <span style="font-size: 13px; color: var(--text-secondary);">Anomalies</span>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    /**
     * Render timeline data table
     */
    function renderTimelineTable(timeline) {
        const tbody = document.getElementById('timeline-table-body');

        if (!tbody) return;

        if (!timeline || timeline.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="padding: 40px; text-align: center; color: var(--text-secondary);">
                        No timeline data available
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = timeline.map(point => {
            const formattedDate = escapeHtml(formatTimelineDate(point.time_period, currentInterval));
            const avgRisk = point.avg_risk_score ? parseFloat(point.avg_risk_score).toFixed(1) : '0.0';
            const riskColor = getRiskColor(parseFloat(avgRisk));

            return `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px; font-weight: 500;">${formattedDate}</td>
                    <td style="padding: 12px; text-align: center; font-weight: 600;">${(point.total_events || 0).toLocaleString()}</td>
                    <td style="padding: 12px; text-align: center; color: #ef4444; font-weight: 500;">${(point.failed || 0).toLocaleString()}</td>
                    <td style="padding: 12px; text-align: center; color: #10b981; font-weight: 500;">${(point.successful || 0).toLocaleString()}</td>
                    <td style="padding: 12px; text-align: center; color: #6b7280;">${(point.invalid || 0).toLocaleString()}</td>
                    <td style="padding: 12px; text-align: center; color: #f59e0b; font-weight: 500;">${(point.anomalies || 0).toLocaleString()}</td>
                    <td style="padding: 12px; text-align: center;">
                        <span style="background: ${riskColor}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;">${avgRisk}</span>
                    </td>
                </tr>
            `;
        }).join('');
    }

    /**
     * Get risk color based on score
     */
    function getRiskColor(score) {
        if (score >= 70) return '#ef4444';
        if (score >= 40) return '#f59e0b';
        return '#10b981';
    }

    /**
     * Setup event listeners (with guard against duplicates)
     */
    function setupTimelineEventListeners() {
        if (listenersSetup) return;
        listenersSetup = true;

        // Interval selector
        const intervalSelect = document.getElementById('timeline-interval');
        if (intervalSelect) {
            intervalSelect.addEventListener('change', handleIntervalChange);
        }

        // Days selector
        const daysSelect = document.getElementById('timeline-days');
        if (daysSelect) {
            daysSelect.addEventListener('change', handleDaysChange);
        }

        // Refresh button
        const refreshBtn = document.getElementById('timeline-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', handleRefresh);
        }
    }

    /**
     * Handle interval change
     */
    function handleIntervalChange(e) {
        currentInterval = e.target.value;

        // Validate combination - limit hourly to max 7 days
        const daysSelect = document.getElementById('timeline-days');
        if (currentInterval === 'hour' && currentDays > 7) {
            currentDays = 7;
            if (daysSelect) daysSelect.value = '7';
            notify('Hourly view limited to 7 days for performance', 'info');
        }

        showLoadingState();
        loadTimelineData()
            .then(() => hideLoadingState())
            .catch(err => showErrorState('Failed to load timeline'));
    }

    /**
     * Handle days change
     */
    function handleDaysChange(e) {
        currentDays = parseInt(e.target.value);

        // Validate combination - limit hourly to max 7 days
        if (currentInterval === 'hour' && currentDays > 7) {
            const intervalSelect = document.getElementById('timeline-interval');
            currentInterval = 'day';
            if (intervalSelect) intervalSelect.value = 'day';
            notify('Switched to daily view for longer time ranges', 'info');
        }

        showLoadingState();
        loadTimelineData()
            .then(() => hideLoadingState())
            .catch(err => showErrorState('Failed to load timeline'));
    }

    /**
     * Handle refresh
     */
    function handleRefresh() {
        showLoadingState();
        loadTimelineData()
            .then(() => {
                hideLoadingState();
                notify('Timeline refreshed', 'success');
            })
            .catch(err => showErrorState('Failed to refresh timeline'));
    }

    /**
     * Helper: Format timeline date based on interval
     */
    function formatTimelineDate(dateString, interval) {
        if (!dateString) return '-';

        try {
            // Handle YEARWEEK format (e.g., "202449" or 202449)
            if (interval === 'week') {
                const str = String(dateString);
                if (/^\d{6}$/.test(str)) {
                    const year = parseInt(str.substring(0, 4));
                    const week = parseInt(str.substring(4, 6));
                    return `Week ${week}, ${year}`;
                }
            }

            // Handle hour format (e.g., "2024-12-05 14:00:00")
            if (interval === 'hour') {
                const date = new Date(dateString);
                if (!isNaN(date.getTime())) {
                    return date.toLocaleString('en-US', {
                        month: 'short',
                        day: 'numeric',
                        hour: 'numeric',
                        minute: '2-digit'
                    });
                }
            }

            // Handle day format
            const date = new Date(dateString);
            if (!isNaN(date.getTime())) {
                return date.toLocaleDateString('en-US', {
                    weekday: 'short',
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric'
                });
            }

            // Fallback - return as is
            return String(dateString);

        } catch (e) {
            return String(dateString);
        }
    }

})();
