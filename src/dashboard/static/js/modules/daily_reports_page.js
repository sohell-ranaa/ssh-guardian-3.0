/**
 * Daily Reports Page Module
 * Handles display and interaction for daily security reports
 */

(function() {
    'use strict';

    // State
    let reportDate = new Date().toISOString().split('T')[0];
    let hourlyChart = null;
    let threatTypesChart = null;
    let geoChart = null;

    /**
     * Load and display Daily Reports page
     */
    window.loadDailyReportsPage = async function() {
        try {
            // Set date picker
            const datePicker = document.getElementById('report-date-picker');
            if (datePicker) {
                datePicker.value = reportDate;
                datePicker.max = new Date().toISOString().split('T')[0];
            }

            // Load available dates
            await loadAvailableDates();

            // Load report data
            await loadDailyReport();

        } catch (error) {
            console.error('Error loading Daily Reports page:', error);
            showNotification('Failed to load daily reports', 'error');
        }
    };

    /**
     * Load available dates with data
     */
    async function loadAvailableDates() {
        try {
            const response = await fetch('/api/dashboard/daily-reports/available-dates?limit=30');
            const data = await response.json();

            if (data.success && data.dates.length > 0) {
                const dateList = document.getElementById('available-dates-list');
                if (dateList) {
                    dateList.innerHTML = data.dates.slice(0, 5).map(d => `
                        <button onclick="selectReportDate('${d.date}')"
                                style="padding: 4px 8px; background: var(--surface); border: 1px solid var(--border); border-radius: 2px; cursor: pointer; font-size: 12px;">
                            ${formatDateShort(d.date)}
                            <span class="badge badge-info" style="margin-left: 4px;">${formatNumber(d.event_count)}</span>
                        </button>
                    `).join('');
                }
            } else {
                const dateList = document.getElementById('available-dates-list');
                if (dateList) {
                    dateList.innerHTML = '<span style="color: var(--text-hint); font-size: 12px;">No data available</span>';
                }
            }
        } catch (error) {
            console.error('Error loading available dates:', error);
        }
    }

    /**
     * Select a report date
     */
    window.selectReportDate = function(date) {
        reportDate = date;
        const datePicker = document.getElementById('report-date-picker');
        if (datePicker) {
            datePicker.value = date;
        }
        loadDailyReport();
    };

    /**
     * Handle date picker change
     */
    window.onReportDateChange = function(date) {
        reportDate = date;
        loadDailyReport();
    };

    /**
     * Refresh report
     */
    window.refreshDailyReport = function() {
        loadDailyReport();
    };

    /**
     * Load all daily report data
     */
    async function loadDailyReport() {
        try {
            // Load all data in parallel
            await Promise.all([
                loadDailySummary(),
                loadHourlyBreakdown(),
                loadTopThreats(),
                loadGeographicBreakdown(),
                loadTargetedUsernames(),
                loadThreatTypes(),
                loadDailyComparison()
            ]);
        } catch (error) {
            console.error('Error loading daily report:', error);
            showNotification('Failed to load daily report', 'error');
        }
    }

    /**
     * Load daily summary
     */
    async function loadDailySummary() {
        try {
            const response = await fetch(`/api/dashboard/daily-reports/summary?date=${reportDate}`);
            const data = await response.json();

            if (data.success) {
                const summary = data.summary;

                // Update stat cards
                document.getElementById('report-total-events').textContent = formatNumber(summary.total_events);
                document.getElementById('report-events-detail').textContent =
                    `${formatNumber(summary.failed_logins)} failed / ${formatNumber(summary.successful_logins)} success`;

                const highRisk = (summary.risk_breakdown.critical || 0) + (summary.risk_breakdown.high || 0);
                document.getElementById('report-high-risk').textContent = formatNumber(highRisk);
                document.getElementById('report-risk-detail').textContent =
                    `${summary.risk_breakdown.critical} critical, ${summary.risk_breakdown.high} high`;

                document.getElementById('report-unique-ips').textContent = formatNumber(summary.unique_ips);
                document.getElementById('report-blocked-detail').textContent = `${formatNumber(summary.blocked_ips)} blocked`;

                document.getElementById('report-anomalies').textContent = formatNumber(summary.anomalies);
                document.getElementById('report-risk-score').textContent = `Avg Risk: ${summary.avg_risk_score}`;
            }
        } catch (error) {
            console.error('Error loading daily summary:', error);
        }
    }

    /**
     * Load hourly breakdown
     */
    async function loadHourlyBreakdown() {
        try {
            const response = await fetch(`/api/dashboard/daily-reports/hourly-breakdown?date=${reportDate}`);
            const data = await response.json();

            if (data.success) {
                renderHourlyChart(data.hourly_data);
            }
        } catch (error) {
            console.error('Error loading hourly breakdown:', error);
        }
    }

    /**
     * Render hourly chart
     */
    function renderHourlyChart(hourlyData) {
        const ctx = document.getElementById('hourly-chart');
        if (!ctx) return;

        // Destroy existing chart
        if (hourlyChart) {
            hourlyChart.destroy();
        }

        hourlyChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: hourlyData.map(d => d.hour_label),
                datasets: [
                    {
                        label: 'Failed',
                        data: hourlyData.map(d => d.failed),
                        backgroundColor: TC.dangerBg,
                        borderColor: TC.danger,
                        borderWidth: 1
                    },
                    {
                        label: 'Successful',
                        data: hourlyData.map(d => d.successful),
                        backgroundColor: TC.successBg,
                        borderColor: TC.success,
                        borderWidth: 1
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
                    x: { stacked: false, grid: { display: false } },
                    y: { beginAtZero: true, ticks: { precision: 0 } }
                }
            }
        });
    }

    /**
     * Load top threats
     */
    async function loadTopThreats() {
        try {
            const response = await fetch(`/api/dashboard/daily-reports/top-threats?date=${reportDate}&limit=10`);
            const data = await response.json();

            if (data.success) {
                renderTopThreats(data.top_threats);
            }
        } catch (error) {
            console.error('Error loading top threats:', error);
        }
    }

    /**
     * Render top threats table
     */
    function renderTopThreats(threats) {
        const tbody = document.getElementById('top-threats-tbody');
        if (!tbody) return;

        if (threats.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; padding: 24px; color: var(--text-hint);">
                        ✅ No threats recorded for this date
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = threats.map((threat, index) => `
            <tr>
                <td><span class="badge badge-secondary">#${index + 1}</span></td>
                <td><code style="color: ${TC.primary};">${threat.ip}</code></td>
                <td>
                    ${threat.country || 'Unknown'}
                    ${threat.city ? `<span style="color: var(--text-hint);">(${threat.city})</span>` : ''}
                </td>
                <td><strong>${formatNumber(threat.attempt_count)}</strong></td>
                <td>${threat.unique_usernames}</td>
                <td><span class="risk-badge ${getRiskBadgeClass(threat.max_risk)}">${threat.max_risk}</span></td>
                <td style="color: var(--text-hint);">${threat.threat_type || 'Unknown'}</td>
            </tr>
        `).join('');
    }

    /**
     * Load geographic breakdown
     */
    async function loadGeographicBreakdown() {
        try {
            const response = await fetch(`/api/dashboard/daily-reports/geographic?date=${reportDate}&limit=10`);
            const data = await response.json();

            if (data.success) {
                renderGeographicChart(data.countries);
                renderGeographicTable(data.countries);
            }
        } catch (error) {
            console.error('Error loading geographic breakdown:', error);
        }
    }

    /**
     * Render geographic chart
     */
    function renderGeographicChart(countries) {
        const ctx = document.getElementById('geo-chart');
        if (!ctx) return;

        // Destroy existing chart
        if (geoChart) {
            geoChart.destroy();
        }

        if (countries.length === 0) {
            return;
        }

        const colors = [
            TC.primary, TC.danger, TC.warning, TC.success, TC.purple,
            TC.teal, TC.orange, TC.successDark, TC.pink, TC.textSecondary
        ];

        geoChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: countries.map(c => c.country || 'Unknown'),
                datasets: [{
                    data: countries.map(c => c.attempt_count),
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
                        labels: { boxWidth: 12, padding: 8, font: { size: 11 } }
                    }
                }
            }
        });
    }

    /**
     * Render geographic table
     */
    function renderGeographicTable(countries) {
        const tbody = document.getElementById('geo-table-tbody');
        if (!tbody) return;

        if (countries.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" style="text-align: center; padding: 24px; color: var(--text-hint);">
                        No geographic data
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = countries.map(country => `
            <tr>
                <td>
                    ${country.country_code ? `<span style="margin-right: 4px;">${getFlagEmoji(country.country_code)}</span>` : ''}
                    <strong>${country.country || 'Unknown'}</strong>
                </td>
                <td>${formatNumber(country.attempt_count)}</td>
                <td>${formatNumber(country.unique_ips)}</td>
                <td>${formatNumber(country.anomalies)}</td>
                <td><span class="risk-badge ${getRiskBadgeClass(country.avg_risk)}">${country.avg_risk}</span></td>
            </tr>
        `).join('');
    }

    /**
     * Load targeted usernames
     */
    async function loadTargetedUsernames() {
        try {
            const response = await fetch(`/api/dashboard/daily-reports/usernames?date=${reportDate}&limit=10`);
            const data = await response.json();

            if (data.success) {
                renderTargetedUsernames(data.usernames);
            }
        } catch (error) {
            console.error('Error loading targeted usernames:', error);
        }
    }

    /**
     * Render targeted usernames
     */
    function renderTargetedUsernames(usernames) {
        const tbody = document.getElementById('usernames-tbody');
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
                <td>${formatNumber(u.attempt_count)}</td>
                <td>${formatNumber(u.unique_ips)}</td>
                <td><span class="risk-badge ${getRiskBadgeClass(u.avg_risk)}">${u.avg_risk}</span></td>
            </tr>
        `).join('');
    }

    /**
     * Load threat types breakdown
     */
    async function loadThreatTypes() {
        try {
            const response = await fetch(`/api/dashboard/daily-reports/threat-types?date=${reportDate}`);
            const data = await response.json();

            if (data.success) {
                renderThreatTypesChart(data.threat_types);
            }
        } catch (error) {
            console.error('Error loading threat types:', error);
        }
    }

    /**
     * Render threat types chart
     */
    function renderThreatTypesChart(threatTypes) {
        const ctx = document.getElementById('threat-types-chart');
        if (!ctx) return;

        // Destroy existing chart
        if (threatTypesChart) {
            threatTypesChart.destroy();
        }

        if (threatTypes.length === 0) {
            return;
        }

        const colors = [
            TC.danger, TC.warning, TC.primary, TC.success, TC.purple, TC.teal
        ];

        threatTypesChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: threatTypes.map(t => t.threat_type),
                datasets: [{
                    label: 'Count',
                    data: threatTypes.map(t => t.count),
                    backgroundColor: colors.slice(0, threatTypes.length),
                    borderWidth: 0
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 } }
                }
            }
        });
    }

    /**
     * Load daily comparison
     */
    async function loadDailyComparison() {
        try {
            const response = await fetch(`/api/dashboard/daily-reports/comparison?date=${reportDate}`);
            const data = await response.json();

            if (data.success) {
                renderComparison(data.comparison);
            }
        } catch (error) {
            console.error('Error loading comparison:', error);
        }
    }

    /**
     * Render comparison
     */
    function renderComparison(comparison) {
        const renderChange = (value, prevValue, change) => {
            const icon = change >= 0 ? '↑' : '↓';
            const color = change >= 0 ? TC.danger : TC.success;
            return `vs ${formatNumber(prevValue)} yesterday <span style="color: ${color};">${icon} ${Math.abs(change)}%</span>`;
        };

        document.getElementById('comp-events-current').textContent = formatNumber(comparison.current.total_events);
        document.getElementById('comp-events-change').innerHTML = renderChange(
            comparison.current.total_events,
            comparison.previous.total_events,
            comparison.changes.total_events
        );

        document.getElementById('comp-risk-current').textContent = formatNumber(comparison.current.high_risk);
        document.getElementById('comp-risk-change').innerHTML = renderChange(
            comparison.current.high_risk,
            comparison.previous.high_risk,
            comparison.changes.high_risk
        );

        document.getElementById('comp-ips-current').textContent = formatNumber(comparison.current.unique_ips);
        document.getElementById('comp-ips-change').innerHTML = renderChange(
            comparison.current.unique_ips,
            comparison.previous.unique_ips,
            comparison.changes.unique_ips
        );
    }

    /**
     * Export report to CSV
     */
    window.exportDailyReport = async function() {
        showNotification('Generating CSV export...', 'info');

        try {
            // Fetch all data
            const [summary, threats, geo, usernames] = await Promise.all([
                fetch(`/api/dashboard/daily-reports/summary?date=${reportDate}`).then(r => r.json()),
                fetch(`/api/dashboard/daily-reports/top-threats?date=${reportDate}&limit=50`).then(r => r.json()),
                fetch(`/api/dashboard/daily-reports/geographic?date=${reportDate}&limit=50`).then(r => r.json()),
                fetch(`/api/dashboard/daily-reports/usernames?date=${reportDate}&limit=50`).then(r => r.json())
            ]);

            // Build CSV content
            let csv = `SSH Guardian v3.0 Daily Report - ${reportDate}\n\n`;

            // Summary section
            csv += `SUMMARY\n`;
            csv += `Total Events,${summary.summary.total_events}\n`;
            csv += `Failed Logins,${summary.summary.failed_logins}\n`;
            csv += `Successful Logins,${summary.summary.successful_logins}\n`;
            csv += `Unique IPs,${summary.summary.unique_ips}\n`;
            csv += `Blocked IPs,${summary.summary.blocked_ips}\n`;
            csv += `Anomalies,${summary.summary.anomalies}\n`;
            csv += `Avg Risk Score,${summary.summary.avg_risk_score}\n\n`;

            // Top threats section
            csv += `TOP THREATS\n`;
            csv += `IP,Country,City,Attempts,Unique Usernames,Max Risk,Threat Type\n`;
            threats.top_threats.forEach(t => {
                csv += `${t.ip},${t.country || ''},${t.city || ''},${t.attempt_count},${t.unique_usernames},${t.max_risk},${t.threat_type || ''}\n`;
            });
            csv += `\n`;

            // Geographic section
            csv += `GEOGRAPHIC BREAKDOWN\n`;
            csv += `Country,Attempts,Unique IPs,Anomalies,Avg Risk\n`;
            geo.countries.forEach(c => {
                csv += `${c.country},${c.attempt_count},${c.unique_ips},${c.anomalies},${c.avg_risk}\n`;
            });
            csv += `\n`;

            // Usernames section
            csv += `TARGETED USERNAMES\n`;
            csv += `Username,Attempts,Unique IPs,Avg Risk\n`;
            usernames.usernames.forEach(u => {
                csv += `${u.username},${u.attempt_count},${u.unique_ips},${u.avg_risk}\n`;
            });

            // Download
            const blob = new Blob([csv], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `ssh-guardian-daily-report-${reportDate}.csv`;
            a.click();
            window.URL.revokeObjectURL(url);

            showNotification('Report exported successfully', 'success');
        } catch (error) {
            console.error('Error exporting report:', error);
            showNotification('Failed to export report', 'error');
        }
    };

    /**
     * Print report
     */
    window.printDailyReport = function() {
        window.print();
    };

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

    function formatDateShort(dateStr) {
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
