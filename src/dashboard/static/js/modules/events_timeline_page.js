/**
 * Events Timeline Page Module
 * Handles display and interaction for events timeline visualization
 * v3.1: Optimized with CSS classes, improved performance, removed inline styles
 */

(function() {
    'use strict';

    // ===================================
    // Configuration
    // ===================================
    const CONFIG = {
        CACHE_ENDPOINT: 'events_timeline',
        CHART_COLORS: {
            total: TC.primary,
            failed: TC.danger,
            successful: TC.teal,
            anomalies: TC.orange
        },
        MAX_HOURLY_DAYS: 7,
        MAX_DAYS: 90
    };

    // ===================================
    // State
    // ===================================
    let state = {
        interval: 'day',
        days: 7,
        listenersSetup: false,
        chart: null
    };

    // ===================================
    // Utilities
    // ===================================
    const escapeHtml = window.escapeHtml || (str => String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])));

    function notify(message, type) {
        if (typeof showNotification === 'function') {
            showNotification(message, type);
        } else {
            console.log(`[${type}] ${message}`);
        }
    }

    function formatNumber(num) {
        return (parseInt(num) || 0).toLocaleString();
    }

    // ===================================
    // DOM Helpers
    // ===================================
    const DOM = {
        get: id => document.getElementById(id),
        setText: (id, text) => {
            const el = document.getElementById(id);
            if (el) el.textContent = text;
        },
        show: id => {
            const el = document.getElementById(id);
            if (el) el.style.display = 'block';
        },
        hide: id => {
            const el = document.getElementById(id);
            if (el) el.style.display = 'none';
        }
    };

    // ===================================
    // UI State Management
    // ===================================
    function showLoadingState() {
        DOM.show('timeline-loading');
        DOM.hide('timeline-content');
        DOM.hide('timeline-error');
    }

    function hideLoadingState() {
        DOM.hide('timeline-loading');
        DOM.show('timeline-content');
        DOM.hide('timeline-error');
    }

    function showErrorState(message) {
        DOM.hide('timeline-loading');
        DOM.hide('timeline-content');
        const errorEl = DOM.get('timeline-error');
        if (errorEl) {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }
    }

    // ===================================
    // Main Entry Point
    // ===================================
    window.loadEventsTimelinePage = async function() {
        // Reset listeners flag for SPA navigation
        state.listenersSetup = false;
        showLoadingState();

        if (typeof CacheManager !== 'undefined') {
            CacheManager.setLoading(CONFIG.CACHE_ENDPOINT);
        }

        const startTime = performance.now();

        try {
            const result = await loadTimelineData();
            const loadTime = Math.round(performance.now() - startTime);

            if (typeof CacheManager !== 'undefined') {
                CacheManager.updateStatus(CONFIG.CACHE_ENDPOINT, result.fromCache, loadTime);
                CacheManager.clearLoading(CONFIG.CACHE_ENDPOINT);
            }

            setupEventListeners();
            hideLoadingState();

            console.log(`Events Timeline loaded in ${loadTime}ms (from_cache: ${result.fromCache})`);

        } catch (error) {
            console.error('Error loading Events Timeline page:', error);
            showErrorState('Failed to load timeline data. Please try again.');

            if (typeof CacheManager !== 'undefined') {
                CacheManager.setError(CONFIG.CACHE_ENDPOINT, 'Failed to load');
            }

            notify('Failed to load events timeline', 'error');
        }
    };

    // ===================================
    // Data Loading
    // ===================================
    async function loadTimelineData() {
        const url = `/api/dashboard/events/timeline?interval=${state.interval}&days=${state.days}`;
        const response = await fetch(url);
        const data = await response.json();

        if (!data.success) {
            throw new Error(data.error || 'Failed to load timeline');
        }

        const timeline = data.data?.timeline || [];
        const interval = data.data?.interval || state.interval;

        updateSummaryStats(timeline);
        renderChart(timeline, interval);
        renderTable(timeline);

        return { success: true, fromCache: data.from_cache === true };
    }

    // ===================================
    // Summary Stats
    // ===================================
    function updateSummaryStats(timeline) {
        if (!timeline || timeline.length === 0) {
            DOM.setText('timeline-stat-total', '0');
            DOM.setText('timeline-stat-failed', '0');
            DOM.setText('timeline-stat-successful', '0');
            DOM.setText('timeline-stat-anomalies', '0');
            return;
        }

        let totals = { events: 0, failed: 0, successful: 0, anomalies: 0 };

        timeline.forEach(point => {
            totals.events += parseInt(point.total_events) || 0;
            totals.failed += parseInt(point.failed) || 0;
            totals.successful += parseInt(point.successful) || 0;
            totals.anomalies += parseInt(point.anomalies) || 0;
        });

        DOM.setText('timeline-stat-total', formatNumber(totals.events));
        DOM.setText('timeline-stat-failed', formatNumber(totals.failed));
        DOM.setText('timeline-stat-successful', formatNumber(totals.successful));
        DOM.setText('timeline-stat-anomalies', formatNumber(totals.anomalies));
    }

    // ===================================
    // Chart Rendering
    // ===================================
    function renderChart(timeline, interval) {
        const canvas = DOM.get('timeline-chart');
        if (!canvas) return;

        if (!timeline || timeline.length === 0) {
            const container = canvas.parentElement;
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 40px;">No timeline data available</p>';
            return;
        }

        // Destroy existing chart
        if (state.chart) {
            state.chart.destroy();
            state.chart = null;
        }

        // Reverse timeline to show chronological order
        const reversedTimeline = [...timeline].reverse();

        // Prepare data
        const labels = reversedTimeline.map(p => formatTimelineDate(p.time_period, interval));
        const datasets = [
            createDataset('Total Events', reversedTimeline.map(p => parseInt(p.total_events) || 0), CONFIG.CHART_COLORS.total, true),
            createDataset('Failed', reversedTimeline.map(p => parseInt(p.failed) || 0), CONFIG.CHART_COLORS.failed, false),
            createDataset('Successful', reversedTimeline.map(p => parseInt(p.successful) || 0), CONFIG.CHART_COLORS.successful, false),
            createDataset('Anomalies', reversedTimeline.map(p => parseInt(p.anomalies) || 0), CONFIG.CHART_COLORS.anomalies, false)
        ];

        // Create chart
        const ctx = canvas.getContext('2d');
        state.chart = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets },
            options: getChartOptions()
        });

        setupChartToggles();
    }

    function createDataset(label, data, color, fill) {
        return {
            label,
            data,
            borderColor: color,
            backgroundColor: fill ? `${color}1A` : 'transparent', // 1A = 10% opacity
            borderWidth: 2,
            tension: 0.4,
            fill,
            pointRadius: 4,
            pointHoverRadius: 6,
            hidden: false
        };
    }

    function getChartOptions() {
        return {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: { size: 14, weight: 'bold' },
                    bodyFont: { size: 13 },
                    bodySpacing: 6,
                    callbacks: {
                        label: ctx => `${ctx.dataset.label}: ${ctx.parsed.y.toLocaleString()}`
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: true, color: 'rgba(0, 0, 0, 0.05)' },
                    ticks: { maxRotation: 45, minRotation: 0, font: { size: 11 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { display: true, color: 'rgba(0, 0, 0, 0.05)' },
                    ticks: { font: { size: 11 }, callback: v => v.toLocaleString() }
                }
            }
        };
    }

    function setupChartToggles() {
        const toggles = [
            { id: 'chart-show-total', index: 0 },
            { id: 'chart-show-failed', index: 1 },
            { id: 'chart-show-successful', index: 2 },
            { id: 'chart-show-anomalies', index: 3 }
        ];

        toggles.forEach(({ id, index }) => {
            const checkbox = DOM.get(id);
            if (checkbox && !checkbox.hasAttribute('data-listener')) {
                checkbox.setAttribute('data-listener', 'true');
                checkbox.addEventListener('change', function() {
                    if (state.chart) {
                        state.chart.data.datasets[index].hidden = !this.checked;
                        state.chart.update();
                    }
                });
            }
        });
    }

    // ===================================
    // Table Rendering
    // ===================================
    function renderTable(timeline) {
        const tbody = DOM.get('timeline-table-body');
        if (!tbody) return;

        DOM.setText('timeline-row-count', timeline?.length || 0);

        if (!timeline || timeline.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="padding: 40px; text-align: center; color: var(--text-secondary);">No timeline data available</td></tr>';
            return;
        }

        tbody.innerHTML = timeline.map((point, index) => {
            const formattedDate = escapeHtml(formatTimelineDate(point.time_period, state.interval));
            const avgRisk = point.avg_risk_score ? parseFloat(point.avg_risk_score).toFixed(1) : '0.0';
            const riskColor = getRiskColor(parseFloat(avgRisk));
            const trend = calculateTrend(point, timeline[index + 1]);

            return `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px; font-weight: 500;">${formattedDate}</td>
                    <td style="padding: 12px; text-align: center; font-weight: 600;">${formatNumber(point.total_events)}</td>
                    <td style="padding: 12px; text-align: center; color: ${TC.danger}; font-weight: 500;">${formatNumber(point.failed)}</td>
                    <td style="padding: 12px; text-align: center; color: ${TC.teal}; font-weight: 500;">${formatNumber(point.successful)}</td>
                    <td style="padding: 12px; text-align: center; color: ${TC.textSecondary};">${formatNumber(point.invalid)}</td>
                    <td style="padding: 12px; text-align: center; color: ${TC.orange}; font-weight: 500;">${formatNumber(point.anomalies)}</td>
                    <td style="padding: 12px; text-align: center;">
                        <span style="background: ${riskColor}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: 600;">${avgRisk}</span>
                    </td>
                    <td style="padding: 12px; text-align: center;">${trend}</td>
                </tr>
            `;
        }).join('');
    }

    function getRiskColor(score) {
        if (score >= 70) return TC.danger;
        if (score >= 40) return TC.orange;
        return TC.teal;
    }

    function calculateTrend(current, previous) {
        if (!previous) {
            return '<span style="color: var(--text-secondary); font-size: 11px;">━</span>';
        }

        const currentTotal = current.total_events || 0;
        const prevTotal = previous.total_events || 0;
        const change = currentTotal - prevTotal;
        const changePercent = prevTotal > 0 ? Math.abs((change / prevTotal) * 100).toFixed(0) : 0;

        if (change > 0) {
            return `<span style="color: ${TC.danger}; font-size: 11px;">▲ ${changePercent}%</span>`;
        } else if (change < 0) {
            return `<span style="color: ${TC.teal}; font-size: 11px;">▼ ${changePercent}%</span>`;
        }
        return '<span style="color: var(--text-secondary); font-size: 11px;">━ 0%</span>';
    }

    // ===================================
    // Date Formatting
    // ===================================
    function formatTimelineDate(dateString, interval) {
        if (!dateString) return '-';

        try {
            // Handle YEARWEEK format (e.g., "202449")
            if (interval === 'week') {
                const str = String(dateString);
                if (/^\d{6}$/.test(str)) {
                    const week = parseInt(str.substring(4, 6));
                    return `Week ${week}`;
                }
            }

            const date = new Date(dateString);
            if (isNaN(date.getTime())) return String(dateString);

            const options = interval === 'hour'
                ? { month: 'short', day: 'numeric', hour: 'numeric' }
                : { month: 'short', day: 'numeric' };

            return date.toLocaleString('en-US', options);

        } catch (e) {
            return String(dateString);
        }
    }

    // ===================================
    // Event Listeners
    // ===================================
    function setupEventListeners() {
        if (state.listenersSetup) return;
        state.listenersSetup = true;

        // Interval selector
        const intervalSelect = DOM.get('timeline-interval');
        if (intervalSelect) {
            intervalSelect.addEventListener('change', handleIntervalChange);
        }

        // Days selector
        const daysSelect = DOM.get('timeline-days');
        if (daysSelect) {
            daysSelect.addEventListener('change', handleDaysChange);
        }

        // Refresh button
        const refreshBtn = DOM.get('timeline-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', handleRefresh);
        }
    }

    function handleIntervalChange(e) {
        state.interval = e.target.value;

        // Limit hourly to max 7 days
        if (state.interval === 'hour' && state.days > CONFIG.MAX_HOURLY_DAYS) {
            state.days = CONFIG.MAX_HOURLY_DAYS;
            const daysSelect = DOM.get('timeline-days');
            if (daysSelect) daysSelect.value = String(CONFIG.MAX_HOURLY_DAYS);
            notify('Hourly view limited to 7 days for performance', 'info');
        }

        reloadData();
    }

    function handleDaysChange(e) {
        state.days = parseInt(e.target.value);

        // Limit hourly to max 7 days
        if (state.interval === 'hour' && state.days > CONFIG.MAX_HOURLY_DAYS) {
            state.interval = 'day';
            const intervalSelect = DOM.get('timeline-interval');
            if (intervalSelect) intervalSelect.value = 'day';
            notify('Switched to daily view for longer time ranges', 'info');
        }

        reloadData();
    }

    function handleRefresh() {
        reloadData().then(() => notify('Timeline refreshed', 'success'));
    }

    async function reloadData() {
        showLoadingState();
        try {
            await loadTimelineData();
            hideLoadingState();
        } catch (err) {
            showErrorState('Failed to load timeline');
        }
    }

})();
