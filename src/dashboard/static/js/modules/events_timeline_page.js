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
    let timelineChart = null;

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
            const response = await fetch(`/api/dashboard/events/timeline?interval=${currentInterval}&days=${currentDays}`);
            const data = await response.json();

            if (data.success) {
                updateSummaryStats(data.data.timeline);
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
     * Update summary statistics
     */
    function updateSummaryStats(timeline) {
        if (!timeline || timeline.length === 0) {
            document.getElementById('timeline-stat-total').textContent = '0';
            document.getElementById('timeline-stat-failed').textContent = '0';
            document.getElementById('timeline-stat-successful').textContent = '0';
            document.getElementById('timeline-stat-anomalies').textContent = '0';
            return;
        }

        // Calculate totals - parse as integers to avoid string concatenation
        let totalEvents = 0;
        let totalFailed = 0;
        let totalSuccessful = 0;
        let totalAnomalies = 0;

        timeline.forEach(point => {
            totalEvents += parseInt(point.total_events) || 0;
            totalFailed += parseInt(point.failed) || 0;
            totalSuccessful += parseInt(point.successful) || 0;
            totalAnomalies += parseInt(point.anomalies) || 0;
        });

        // Update UI
        document.getElementById('timeline-stat-total').textContent = totalEvents.toLocaleString();
        document.getElementById('timeline-stat-failed').textContent = totalFailed.toLocaleString();
        document.getElementById('timeline-stat-successful').textContent = totalSuccessful.toLocaleString();
        document.getElementById('timeline-stat-anomalies').textContent = totalAnomalies.toLocaleString();
    }

    /**
     * Render timeline visualization (line chart with Chart.js)
     */
    function renderTimelineVisualization(timeline, interval) {
        const canvas = document.getElementById('timeline-chart');

        if (!canvas) return;

        if (!timeline || timeline.length === 0) {
            const container = canvas.parentElement;
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 40px;">No timeline data available</p>';
            return;
        }

        // Destroy existing chart
        if (timelineChart) {
            timelineChart.destroy();
        }

        // Reverse timeline to show chronological order (oldest to newest)
        const reversedTimeline = [...timeline].reverse();

        // Prepare data
        const labels = reversedTimeline.map(point => formatTimelineDate(point.time_period, interval));
        const totalData = reversedTimeline.map(point => parseInt(point.total_events) || 0);
        const failedData = reversedTimeline.map(point => parseInt(point.failed) || 0);
        const successfulData = reversedTimeline.map(point => parseInt(point.successful) || 0);
        const anomaliesData = reversedTimeline.map(point => parseInt(point.anomalies) || 0);

        // Create chart
        const ctx = canvas.getContext('2d');
        timelineChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Total Events',
                        data: totalData,
                        borderColor: '#0078D4',
                        backgroundColor: 'rgba(0, 120, 212, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 4,
                        pointHoverRadius: 6,
                        hidden: false
                    },
                    {
                        label: 'Failed',
                        data: failedData,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: false,
                        pointRadius: 4,
                        pointHoverRadius: 6,
                        hidden: false
                    },
                    {
                        label: 'Successful',
                        data: successfulData,
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: false,
                        pointRadius: 4,
                        pointHoverRadius: 6,
                        hidden: false
                    },
                    {
                        label: 'Anomalies',
                        data: anomaliesData,
                        borderColor: '#f59e0b',
                        backgroundColor: 'rgba(245, 158, 11, 0.1)',
                        borderWidth: 2,
                        tension: 0.4,
                        fill: false,
                        pointRadius: 4,
                        pointHoverRadius: 6,
                        hidden: false
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(0, 0, 0, 0.8)',
                        padding: 12,
                        titleFont: {
                            size: 14,
                            weight: 'bold'
                        },
                        bodyFont: {
                            size: 13
                        },
                        bodySpacing: 6,
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + context.parsed.y.toLocaleString();
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.05)'
                        },
                        ticks: {
                            maxRotation: 45,
                            minRotation: 0,
                            font: {
                                size: 11
                            }
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            display: true,
                            color: 'rgba(0, 0, 0, 0.05)'
                        },
                        ticks: {
                            font: {
                                size: 11
                            },
                            callback: function(value) {
                                return value.toLocaleString();
                            }
                        }
                    }
                }
            }
        });

        // Setup toggle checkboxes
        setupChartToggles();
    }

    /**
     * Setup chart toggle checkboxes
     */
    function setupChartToggles() {
        const toggles = [
            { id: 'chart-show-total', datasetIndex: 0 },
            { id: 'chart-show-failed', datasetIndex: 1 },
            { id: 'chart-show-successful', datasetIndex: 2 },
            { id: 'chart-show-anomalies', datasetIndex: 3 }
        ];

        toggles.forEach(toggle => {
            const checkbox = document.getElementById(toggle.id);
            if (checkbox && !checkbox.hasAttribute('data-listener-attached')) {
                checkbox.setAttribute('data-listener-attached', 'true');
                checkbox.addEventListener('change', function() {
                    if (timelineChart) {
                        timelineChart.data.datasets[toggle.datasetIndex].hidden = !this.checked;
                        timelineChart.update();
                    }
                });
            }
        });
    }

    /**
     * Render timeline data table
     */
    function renderTimelineTable(timeline) {
        const tbody = document.getElementById('timeline-table-body');
        const rowCountEl = document.getElementById('timeline-row-count');

        if (!tbody) return;

        if (!timeline || timeline.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" style="padding: 40px; text-align: center; color: var(--text-secondary);">
                        No timeline data available
                    </td>
                </tr>
            `;
            if (rowCountEl) rowCountEl.textContent = '0';
            return;
        }

        // Update row count
        if (rowCountEl) rowCountEl.textContent = timeline.length.toLocaleString();

        tbody.innerHTML = timeline.map((point, index) => {
            const formattedDate = escapeHtml(formatTimelineDate(point.time_period, currentInterval));
            const avgRisk = point.avg_risk_score ? parseFloat(point.avg_risk_score).toFixed(1) : '0.0';
            const riskColor = getRiskColor(parseFloat(avgRisk));

            // Calculate trend (compare with previous period)
            let trendIndicator = '';
            if (index < timeline.length - 1) {
                const prevTotal = timeline[index + 1].total_events || 0;
                const currentTotal = point.total_events || 0;
                const change = currentTotal - prevTotal;
                const changePercent = prevTotal > 0 ? ((change / prevTotal) * 100).toFixed(0) : 0;

                if (change > 0) {
                    trendIndicator = `<span style="color: #ef4444; font-size: 11px;">▲ ${changePercent}%</span>`;
                } else if (change < 0) {
                    trendIndicator = `<span style="color: #10b981; font-size: 11px;">▼ ${Math.abs(changePercent)}%</span>`;
                } else {
                    trendIndicator = `<span style="color: var(--text-secondary); font-size: 11px;">━ 0%</span>`;
                }
            } else {
                trendIndicator = `<span style="color: var(--text-secondary); font-size: 11px;">━</span>`;
            }

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
                    <td style="padding: 12px; text-align: center;">${trendIndicator}</td>
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
                    return `Week ${week}`;
                }
            }

            // Parse the date
            const date = new Date(dateString);
            if (isNaN(date.getTime())) {
                return String(dateString);
            }

            // Format based on interval
            if (interval === 'hour') {
                // Format: "Dec 6, 2PM"
                return date.toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    hour: 'numeric'
                });
            } else if (interval === 'day') {
                // Format: "Dec 6"
                return date.toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric'
                });
            } else {
                // Week or default: "Dec 6"
                return date.toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric'
                });
            }

        } catch (e) {
            return String(dateString);
        }
    }

})();
