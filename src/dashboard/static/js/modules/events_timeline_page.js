/**
 * Events Timeline Page Module
 * Handles display and interaction for events timeline visualization
 */

(function() {
    'use strict';

    let currentInterval = 'day';
    let currentDays = 7;

    /**
     * Load and display Events Timeline page
     */
    window.loadEventsTimelinePage = async function() {
        console.log('Loading Events Timeline page...');

        try {
            // Load timeline data
            await loadTimelineData();

            // Setup event listeners
            setupTimelineEventListeners();

        } catch (error) {
            console.error('Error loading Events Timeline page:', error);
            showNotification('Failed to load events timeline', 'error');
        }
    };

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
            } else {
                throw new Error(data.error || 'Failed to load timeline');
            }

        } catch (error) {
            console.error('Error loading timeline data:', error);
            showNotification('Failed to load timeline data', 'error');
        }
    }

    /**
     * Render timeline visualization (bar chart)
     */
    function renderTimelineVisualization(timeline, interval) {
        const container = document.getElementById('timeline-chart-container');

        if (!container || timeline.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 40px;">No timeline data available</p>';
            return;
        }

        // Find max value for scaling
        const maxValue = Math.max(...timeline.map(t => t.total_events || 0));

        let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';

        timeline.forEach(point => {
            const total = point.total_events || 0;
            const failed = point.failed || 0;
            const successful = point.successful || 0;
            const anomalies = point.anomalies || 0;

            // Calculate percentages for stacked bar
            const failedPercent = total > 0 ? (failed / total) * 100 : 0;
            const successfulPercent = total > 0 ? (successful / total) * 100 : 0;
            const anomalyPercent = total > 0 ? (anomalies / total) * 100 : 0;

            // Calculate bar width relative to max
            const barWidth = maxValue > 0 ? (total / maxValue) * 100 : 0;

            const formattedDate = formatTimelineDate(point.time_period);

            html += `
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div style="min-width: 120px; font-size: 13px; color: var(--text-secondary);">
                        ${formattedDate}
                    </div>
                    <div style="flex: 1; position: relative;">
                        <div style="display: flex; height: 32px; background: var(--surface); border-radius: 4px; overflow: hidden; width: ${barWidth}%; min-width: 2px;">
                            ${failed > 0 ? `<div style="width: ${failedPercent}%; background: #ef4444;" title="Failed: ${failed}"></div>` : ''}
                            ${successful > 0 ? `<div style="width: ${successfulPercent}%; background: #10b981;" title="Successful: ${successful}"></div>` : ''}
                            ${anomalies > 0 ? `<div style="width: ${anomalyPercent}%; background: #f59e0b;" title="Anomalies: ${anomalies}"></div>` : ''}
                        </div>
                    </div>
                    <div style="min-width: 60px; text-align: right; font-weight: 600; font-size: 14px;">
                        ${total.toLocaleString()}
                    </div>
                </div>
            `;
        });

        html += '</div>';

        // Add legend
        html += `
            <div style="display: flex; justify-content: center; gap: 24px; margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border);">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div style="width: 16px; height: 16px; background: #ef4444; border-radius: 2px;"></div>
                    <span style="font-size: 13px; color: var(--text-secondary);">Failed</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div style="width: 16px; height: 16px; background: #10b981; border-radius: 2px;"></div>
                    <span style="font-size: 13px; color: var(--text-secondary);">Successful</span>
                </div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div style="width: 16px; height: 16px; background: #f59e0b; border-radius: 2px;"></div>
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

        if (timeline.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="no-data">
                        <div class="no-data-message">
                            <span class="no-data-icon">📊</span>
                            <p>No timeline data found</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = timeline.map(point => {
            const formattedDate = formatTimelineDate(point.time_period);
            const avgRisk = point.avg_risk_score ? parseFloat(point.avg_risk_score).toFixed(1) : '0.0';

            return `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px;">${formattedDate}</td>
                    <td style="padding: 12px; text-align: center; font-weight: 500;">${point.total_events || 0}</td>
                    <td style="padding: 12px; text-align: center; color: #ef4444;">${point.failed || 0}</td>
                    <td style="padding: 12px; text-align: center; color: #10b981;">${point.successful || 0}</td>
                    <td style="padding: 12px; text-align: center; color: #6b7280;">${point.invalid || 0}</td>
                    <td style="padding: 12px; text-align: center; color: #f59e0b;">${point.anomalies || 0}</td>
                    <td style="padding: 12px; text-align: center;">${avgRisk}</td>
                </tr>
            `;
        }).join('');
    }

    /**
     * Setup event listeners
     */
    function setupTimelineEventListeners() {
        // Interval selector
        const intervalSelect = document.getElementById('timeline-interval');
        if (intervalSelect) {
            intervalSelect.addEventListener('change', (e) => {
                currentInterval = e.target.value;
                loadTimelineData();
            });
        }

        // Days selector
        const daysSelect = document.getElementById('timeline-days');
        if (daysSelect) {
            daysSelect.addEventListener('change', (e) => {
                currentDays = parseInt(e.target.value);
                loadTimelineData();
            });
        }

        // Refresh button
        const refreshBtn = document.getElementById('timeline-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                loadTimelineData();
                showNotification('Timeline refreshed', 'success');
            });
        }
    }

    /**
     * Helper: Format timeline date
     */
    function formatTimelineDate(dateString) {
        if (!dateString) return '-';

        try {
            const date = new Date(dateString);
            const options = { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' };
            return date.toLocaleDateString('en-US', options);
        } catch (e) {
            return dateString;
        }
    }

})();
