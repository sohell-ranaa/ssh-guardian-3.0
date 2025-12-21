/**
 * Trends Reports Page Module
 * Handles display and interaction for security trends analysis
 */

(function() {
    'use strict';

    // State
    let selectedDays = 30;
    let eventsChart = null;
    let riskChart = null;
    let countryChart = null;

    /**
     * Load and display Trends Reports page
     */
    window.loadTrendsReportsPage = async function() {
        try {
            // Set default period selector
            const periodSelect = document.getElementById('trends-period-select');
            if (periodSelect) {
                periodSelect.value = selectedDays;
            }

            // Load all trends data
            await loadTrendsData();

        } catch (error) {
            console.error('Error loading Trends Reports page:', error);
            showNotification('Failed to load trends data', 'error');
        }
    };

    /**
     * Handle period change
     */
    window.onTrendsPeriodChange = function(days) {
        selectedDays = parseInt(days);
        loadTrendsData();
    };

    /**
     * Refresh trends data
     */
    window.refreshTrends = function() {
        loadTrendsData();
    };

    /**
     * Load all trends data
     */
    async function loadTrendsData() {
        try {
            await Promise.all([
                loadTrendsOverview(),
                loadEventsTimeline(),
                loadPeriodComparison(),
                loadTopAttackers(),
                loadCountryTrends(),
                loadUsernameTrends(),
                loadRiskDistribution()
            ]);
        } catch (error) {
            console.error('Error loading trends data:', error);
        }
    }

    /**
     * Load trends overview
     */
    async function loadTrendsOverview() {
        try {
            // Use fetchWithCache if available to track cache status
            let data;
            if (typeof fetchWithCache === 'function') {
                data = await fetchWithCache(`/api/dashboard/trends-reports/overview?days=${selectedDays}`, 'trends');
            } else {
                const response = await fetch(`/api/dashboard/trends-reports/overview?days=${selectedDays}`);
                data = await response.json();
            }

            if (data.success) {
                renderOverviewStats(data.totals, data.period);
            }
        } catch (error) {
            console.error('Error loading trends overview:', error);
        }
    }

    /**
     * Render overview stats
     */
    function renderOverviewStats(totals, period) {
        document.getElementById('trends-total-events').textContent = formatNumber(totals.total_events);
        document.getElementById('trends-total-detail').textContent =
            `${formatNumber(totals.avg_daily_events || 0)} avg/day over ${totals.days_with_data} days`;

        document.getElementById('trends-failed-events').textContent = formatNumber(totals.failed_events);
        document.getElementById('trends-failed-detail').textContent =
            `${formatNumber(totals.avg_daily_failed || 0)} avg/day`;

        document.getElementById('trends-high-risk').textContent = formatNumber(totals.high_risk_events);
        document.getElementById('trends-high-risk-detail').textContent =
            `${totals.anomalies} anomalies detected`;

        // Calculate percentage
        const failRate = totals.total_events > 0
            ? Math.round((totals.failed_events / totals.total_events) * 100)
            : 0;
        document.getElementById('trends-fail-rate').textContent = `${failRate}%`;
        document.getElementById('trends-fail-rate-detail').textContent = 'Failure rate';
    }

    /**
     * Load events timeline
     */
    async function loadEventsTimeline() {
        try {
            const granularity = selectedDays <= 7 ? 'hourly' : 'daily';
            const response = await fetch(`/api/dashboard/trends-reports/events-timeline?days=${selectedDays}&granularity=${granularity}`);
            const data = await response.json();

            if (data.success) {
                renderEventsChart(data.timeline, granularity);
            }
        } catch (error) {
            console.error('Error loading events timeline:', error);
        }
    }

    /**
     * Render events chart
     */
    function renderEventsChart(timeline, granularity) {
        const ctx = document.getElementById('trends-events-chart');
        if (!ctx) return;

        if (eventsChart) {
            eventsChart.destroy();
        }

        const labels = timeline.map(d => {
            if (granularity === 'hourly') {
                return d.time_bucket.split(' ')[1] || d.time_bucket;
            }
            return formatDateLabel(d.time_bucket);
        });

        eventsChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Failed',
                        data: timeline.map(d => d.failed),
                        borderColor: TC.danger,
                        backgroundColor: TC.dangerBg,
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'Successful',
                        data: timeline.map(d => d.successful),
                        borderColor: TC.success,
                        backgroundColor: TC.successBg,
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top' }
                },
                scales: {
                    x: { grid: { display: false } },
                    y: { beginAtZero: true, ticks: { precision: 0 } }
                },
                interaction: {
                    intersect: false,
                    mode: 'index'
                }
            }
        });
    }

    /**
     * Load period comparison
     */
    async function loadPeriodComparison() {
        try {
            const compDays = Math.min(selectedDays, 30);
            const response = await fetch(`/api/dashboard/trends-reports/period-comparison?days=${compDays}`);
            const data = await response.json();

            if (data.success) {
                renderPeriodComparison(data.comparison);
            }
        } catch (error) {
            console.error('Error loading period comparison:', error);
        }
    }

    /**
     * Render period comparison
     */
    function renderPeriodComparison(comparison) {
        const container = document.getElementById('trends-comparison-container');
        if (!container) return;

        const renderChange = (change) => {
            const icon = change >= 0 ? '↑' : '↓';
            const color = change >= 0 ? TC.danger : TC.success;
            return `<span style="color: ${color};">${icon} ${Math.abs(change)}%</span>`;
        };

        container.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px;">
                <div style="text-align: center; padding: 12px; background: var(--background); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary);">Events</div>
                    <div style="font-size: 20px; font-weight: 600;">${formatNumber(comparison.current_period.total_events)}</div>
                    <div style="font-size: 11px;">${renderChange(comparison.changes.total_events)}</div>
                </div>
                <div style="text-align: center; padding: 12px; background: var(--background); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary);">Failed</div>
                    <div style="font-size: 20px; font-weight: 600; color: ${TC.danger};">${formatNumber(comparison.current_period.failed_events)}</div>
                    <div style="font-size: 11px;">${renderChange(comparison.changes.failed_events)}</div>
                </div>
                <div style="text-align: center; padding: 12px; background: var(--background); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary);">Unique IPs</div>
                    <div style="font-size: 20px; font-weight: 600; color: ${TC.warning};">${formatNumber(comparison.current_period.unique_ips)}</div>
                    <div style="font-size: 11px;">${renderChange(comparison.changes.unique_ips)}</div>
                </div>
                <div style="text-align: center; padding: 12px; background: var(--background); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary);">High Risk</div>
                    <div style="font-size: 20px; font-weight: 600; color: ${TC.danger};">${formatNumber(comparison.current_period.high_risk)}</div>
                    <div style="font-size: 11px;">${renderChange(comparison.changes.high_risk)}</div>
                </div>
            </div>
        `;
    }

    /**
     * Load top attackers
     */
    async function loadTopAttackers() {
        try {
            const response = await fetch(`/api/dashboard/trends-reports/top-attackers?days=${selectedDays}&limit=10`);
            const data = await response.json();

            if (data.success) {
                renderTopAttackers(data.attackers);
            }
        } catch (error) {
            console.error('Error loading top attackers:', error);
        }
    }

    /**
     * Render top attackers table
     */
    function renderTopAttackers(attackers) {
        const tbody = document.getElementById('trends-attackers-tbody');
        if (!tbody) return;

        if (attackers.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align: center; padding: 24px; color: var(--text-hint);">
                        ✅ No attack data for this period
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = attackers.map((attacker, index) => `
            <tr>
                <td><span class="badge badge-secondary">#${index + 1}</span></td>
                <td>
                    <code style="color: ${TC.primary};">${attacker.ip}</code>
                    ${attacker.country ? `<br><small style="color: var(--text-hint);">${attacker.country}</small>` : ''}
                </td>
                <td><strong>${formatNumber(attacker.total_attempts)}</strong></td>
                <td>${attacker.active_days} days</td>
                <td>${attacker.unique_usernames}</td>
                <td><span class="risk-badge ${getRiskBadgeClass(attacker.max_risk)}">${attacker.max_risk}</span></td>
            </tr>
        `).join('');
    }

    /**
     * Load country trends
     */
    async function loadCountryTrends() {
        try {
            const response = await fetch(`/api/dashboard/trends-reports/country-trends?days=${selectedDays}&limit=8`);
            const data = await response.json();

            if (data.success) {
                renderCountryChart(data.countries);
                renderCountryTable(data.countries);
            }
        } catch (error) {
            console.error('Error loading country trends:', error);
        }
    }

    /**
     * Render country chart
     */
    function renderCountryChart(countries) {
        const ctx = document.getElementById('trends-country-chart');
        if (!ctx) return;

        if (countryChart) {
            countryChart.destroy();
        }

        if (countries.length === 0) return;

        const colors = [
            TC.primary, TC.danger, TC.warning, TC.success, TC.purple,
            TC.teal, TC.orange, TC.successDark
        ];

        countryChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: countries.map(c => c.country || 'Unknown'),
                datasets: [{
                    data: countries.map(c => c.total_attempts),
                    backgroundColor: colors.slice(0, countries.length),
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { boxWidth: 12, padding: 6, font: { size: 10 } }
                    }
                }
            }
        });
    }

    /**
     * Render country table
     */
    function renderCountryTable(countries) {
        const tbody = document.getElementById('trends-country-tbody');
        if (!tbody) return;

        if (countries.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; padding: 24px; color: var(--text-hint);">
                        No country data
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = countries.slice(0, 6).map(country => `
            <tr>
                <td>
                    ${country.country_code ? `<span style="margin-right: 4px;">${getFlagEmoji(country.country_code)}</span>` : ''}
                    ${country.country || 'Unknown'}
                </td>
                <td>${formatNumber(country.total_attempts)}</td>
                <td>${formatNumber(country.unique_ips)}</td>
                <td><span class="risk-badge ${getRiskBadgeClass(country.avg_risk)}">${country.avg_risk}</span></td>
            </tr>
        `).join('');
    }

    /**
     * Load username trends
     */
    async function loadUsernameTrends() {
        try {
            const response = await fetch(`/api/dashboard/trends-reports/username-trends?days=${selectedDays}&limit=8`);
            const data = await response.json();

            if (data.success) {
                renderUsernameTrends(data.usernames);
            }
        } catch (error) {
            console.error('Error loading username trends:', error);
        }
    }

    /**
     * Render username trends
     */
    function renderUsernameTrends(usernames) {
        const tbody = document.getElementById('trends-usernames-tbody');
        if (!tbody) return;

        if (usernames.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="4" style="text-align: center; padding: 24px; color: var(--text-hint);">
                        No username data
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = usernames.map(u => `
            <tr>
                <td><code>${u.username}</code></td>
                <td>${formatNumber(u.total_attempts)}</td>
                <td>${formatNumber(u.unique_ips)}</td>
                <td>${u.active_days} days</td>
            </tr>
        `).join('');
    }

    /**
     * Load risk distribution
     */
    async function loadRiskDistribution() {
        try {
            const response = await fetch(`/api/dashboard/trends-reports/risk-distribution?days=${selectedDays}`);
            const data = await response.json();

            if (data.success) {
                renderRiskChart(data.daily_distribution, data.totals);
            }
        } catch (error) {
            console.error('Error loading risk distribution:', error);
        }
    }

    /**
     * Render risk chart
     */
    function renderRiskChart(dailyData, totals) {
        const ctx = document.getElementById('trends-risk-chart');
        if (!ctx) return;

        if (riskChart) {
            riskChart.destroy();
        }

        if (dailyData.length === 0) return;

        riskChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: dailyData.map(d => formatDateLabel(d.date)),
                datasets: [
                    {
                        label: 'Critical',
                        data: dailyData.map(d => d.critical),
                        backgroundColor: TC.danger,
                        stack: 'risk'
                    },
                    {
                        label: 'High',
                        data: dailyData.map(d => d.high),
                        backgroundColor: TC.warning,
                        stack: 'risk'
                    },
                    {
                        label: 'Medium',
                        data: dailyData.map(d => d.medium),
                        backgroundColor: TC.primary,
                        stack: 'risk'
                    },
                    {
                        label: 'Low',
                        data: dailyData.map(d => d.low),
                        backgroundColor: TC.success,
                        stack: 'risk'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'top' }
                },
                scales: {
                    x: { stacked: true, grid: { display: false } },
                    y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }
                }
            }
        });

        // Update totals display
        const totalsEl = document.getElementById('trends-risk-totals');
        if (totalsEl) {
            totalsEl.innerHTML = `
                <span class="badge badge-danger" style="margin-right: 8px;">Critical: ${totals.critical}</span>
                <span class="badge badge-warning" style="margin-right: 8px;">High: ${totals.high}</span>
                <span class="badge badge-info" style="margin-right: 8px;">Medium: ${totals.medium}</span>
                <span class="badge badge-success">Low: ${totals.low}</span>
            `;
        }
    }

    // Utility functions
    function getRiskBadgeClass(risk) {
        if (risk >= 80) return 'risk-high';
        if (risk >= 60) return 'risk-medium';
        return 'risk-low';
    }

    function formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return Number(num).toLocaleString();
    }

    function formatDateLabel(dateStr) {
        if (!dateStr) return '';
        const date = new Date(dateStr + 'T00:00:00');
        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    }

    function getFlagEmoji(countryCode) {
        if (!countryCode) return '';
        try {
            const codePoints = countryCode
                .toUpperCase()
                .split('')
                .map(char => 127397 + char.charCodeAt());
            return String.fromCodePoint(...codePoints);
        } catch (e) {
            return '';
        }
    }

})();
