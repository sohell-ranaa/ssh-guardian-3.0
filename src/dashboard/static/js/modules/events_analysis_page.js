/**
 * Events Analysis Page Module - Enhanced with Charts, Geography, AI Recommendations
 * Handles comprehensive event analysis with caching support
 */

(function() {
    'use strict';

    const CACHE_ENDPOINT = 'events_analysis';

    // State management
    let eventsCurrentPage = 1;
    let eventsCurrentLimit = 20;
    let eventsFilters = {
        dateRange: '7d',
        eventType: '',
        threatLevel: '',
        country: '',
        agent: '',
        search: ''
    };
    let listenersSetup = false;
    let chartInstances = {};

    // escapeHtml - use global from utils.js
    const escapeHtml = window.escapeHtml;

    /**
     * Format number with commas
     */
    function formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return parseInt(num).toLocaleString();
    }

    /**
     * Load and display Events Analysis page
     */
    window.loadEventsAnalysisPage = async function() {
        listenersSetup = false;

        if (typeof CacheManager !== 'undefined') {
            CacheManager.setLoading(CACHE_ENDPOINT);
        }

        showLoadingState();
        const startTime = performance.now();

        try {
            // Load all data in parallel
            await Promise.all([
                loadSummaryMetrics(),
                loadGeographyData(),
                loadTopAttackers(),
                loadAIRecommendations(),
                loadAttackPatterns(),
                loadTargetedUsernames(),
                loadEventsTable()
            ]);

            const loadTime = Math.round(performance.now() - startTime);

            if (typeof CacheManager !== 'undefined') {
                CacheManager.updateStatus(CACHE_ENDPOINT, false, loadTime);
                CacheManager.clearLoading(CACHE_ENDPOINT);
            }

            setupEventListeners();
            hideLoadingState();

            console.log(`Events Analysis loaded in ${loadTime}ms`);

        } catch (error) {
            console.error('Error loading Events Analysis page:', error);
            if (typeof CacheManager !== 'undefined') {
                CacheManager.setError(CACHE_ENDPOINT, 'Failed to load events analysis');
            }
            showErrorState('Failed to load events analysis. Please try again.');
        }
    };

    /**
     * Show/hide loading and error states
     */
    function showLoadingState() {
        const errorEl = document.getElementById('events-analysis-error');
        if (errorEl) errorEl.style.display = 'none';
    }

    function hideLoadingState() {
        const errorEl = document.getElementById('events-analysis-error');
        if (errorEl) errorEl.style.display = 'none';
    }

    function showErrorState(message) {
        const errorEl = document.getElementById('events-analysis-error');
        if (errorEl) {
            errorEl.textContent = message;
            errorEl.style.display = 'block';
        }
    }

    /**
     * Build query string from filters
     */
    function buildQueryString() {
        const params = new URLSearchParams();
        if (eventsFilters.dateRange) params.append('date_range', eventsFilters.dateRange);
        if (eventsFilters.eventType) params.append('event_type', eventsFilters.eventType);
        if (eventsFilters.threatLevel) params.append('threat_level', eventsFilters.threatLevel);
        if (eventsFilters.country) params.append('country', eventsFilters.country);
        if (eventsFilters.agent) params.append('agent', eventsFilters.agent);
        if (eventsFilters.search) params.append('search', eventsFilters.search);
        return params.toString();
    }

    /**
     * Load summary metrics
     */
    async function loadSummaryMetrics() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/summary?${query}`);
            const data = await response.json();

            if (data.success) {
                const summary = data.data.summary || {};

                updateElement('events-total-count', formatNumber(summary.total_events || 0));
                updateElement('events-failed-count', formatNumber(summary.failed_count || 0));
                updateElement('events-success-count', formatNumber(summary.successful_count || 0));
                updateElement('events-unique-ips', formatNumber(summary.unique_ips || 0));

                // Calculate high risk IPs from risk distribution
                const riskDist = data.data.risk_distribution || {};
                updateElement('events-high-risk', formatNumber(riskDist.high || 0));

                // Countries count - estimate from geography data if available
                updateElement('events-countries-count', '-');

                // Update trend indicators (simple placeholders for now)
                updateElement('events-total-change', 'Loading...');
                updateElement('events-failed-change', 'Loading...');
                updateElement('events-success-change', 'Loading...');
                updateElement('events-ips-change', 'Loading...');
                updateElement('events-threat-change', 'Loading...');

                // Load countries and agents for filters separately
                loadFilterOptions();
            }
        } catch (error) {
            console.error('Error loading summary metrics:', error);
        }
    }

    /**
     * Load filter dropdown options
     */
    async function loadFilterOptions() {
        try {
            // Load countries for filter
            const geoResponse = await fetch('/api/dashboard/events-analysis/geography');
            const geoData = await geoResponse.json();
            if (geoData.success) {
                populateCountryFilter(geoData.data.countries || []);
                updateElement('events-countries-count', formatNumber((geoData.data.countries || []).length));
            }

            // Load agents for filter
            const agentsResponse = await fetch('/api/agents/list');
            const agentsData = await agentsResponse.json();
            if (agentsData.success) {
                populateAgentFilter(agentsData.agents || []);
            }
        } catch (error) {
            console.error('Error loading filter options:', error);
        }
    }

    /**
     * Format trend indicator
     */
    function formatTrend(change) {
        if (!change) return 'No data';
        const num = parseFloat(change);
        if (num > 0) return `↑ ${num.toFixed(1)}% vs previous period`;
        if (num < 0) return `↓ ${Math.abs(num).toFixed(1)}% vs previous period`;
        return '→ No change';
    }

    /**
     * Populate country filter
     */
    function populateCountryFilter(countries) {
        const select = document.getElementById('events-country-filter');
        if (!select) return;

        select.innerHTML = '<option value="">All Countries</option>';
        countries.forEach(country => {
            const option = document.createElement('option');
            option.value = country.code || country.name;
            option.textContent = `${country.flag || ''} ${country.name} (${country.count})`;
            select.appendChild(option);
        });
    }

    /**
     * Populate agent filter
     */
    function populateAgentFilter(agents) {
        const select = document.getElementById('events-agent-filter');
        if (!select) return;

        select.innerHTML = '<option value="">All Agents</option>';
        agents.forEach(agent => {
            const option = document.createElement('option');
            option.value = agent.id;
            const displayName = agent.display_name || agent.hostname || agent.agent_id || `Agent ${agent.id}`;
            option.textContent = displayName;
            select.appendChild(option);
        });
    }

    /**
     * Load geography data
     */
    async function loadGeographyData() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/geography?${query}`);
            const data = await response.json();

            if (data.success) {
                renderGeographyList(data.data.countries || []);
            }
        } catch (error) {
            console.error('Error loading geography data:', error);
            updateElement('events-geography-list', '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">Error loading data</p>');
        }
    }

    /**
     * Render geography list
     */
    function renderGeographyList(countries) {
        const container = document.getElementById('events-geography-list');
        if (!container) return;

        if (countries.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">No data available</p>';
            return;
        }

        let html = '';
        countries.forEach((country, index) => {
            const percentage = country.percentage || 0;
            const barColor = index === 0 ? TC.danger : index === 1 ? TC.warning : TC.primary;

            html += `
                <div style="margin-bottom: 16px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 13px;">
                        <span style="font-weight: 500;">${country.flag || '🌍'} ${escapeHtml(country.name)}</span>
                        <span style="color: var(--text-secondary);">${formatNumber(country.count)} events (${percentage.toFixed(1)}%)</span>
                    </div>
                    <div style="background: var(--background); height: 8px; border-radius: 4px; overflow: hidden;">
                        <div style="background: ${barColor}; height: 100%; width: ${percentage}%; transition: width 0.3s;"></div>
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;
    }

    /**
     * Load top attackers
     */
    async function loadTopAttackers() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/top-ips?${query}`);
            const data = await response.json();

            if (data.success) {
                renderTopAttackers(data.data.ips || []);
            }
        } catch (error) {
            console.error('Error loading top attackers:', error);
            updateElement('events-top-ips-list', '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">Error loading data</p>');
        }
    }

    /**
     * Render top attackers list
     */
    function renderTopAttackers(ips) {
        const container = document.getElementById('events-top-ips-list');
        if (!container) return;

        if (ips.length === 0) {
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">No data available</p>';
            return;
        }

        let html = '<div style="display: grid; gap: 12px;">';
        ips.forEach(ip => {
            const threatColor = getThreatColor(ip.threat_level);
            html += `
                <div style="padding: 12px; background: var(--background); border-radius: 4px; border-left: 3px solid ${threatColor};">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div>
                            <div style="font-weight: 600; font-size: 14px; margin-bottom: 4px;">${escapeHtml(ip.ip_address)}</div>
                            <div style="font-size: 12px; color: var(--text-secondary);">
                                ${ip.country_flag || '🌍'} ${escapeHtml(ip.country || 'Unknown')}
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 18px; font-weight: 600; color: ${threatColor};">${formatNumber(ip.count)}</div>
                            <div style="font-size: 11px; color: var(--text-secondary);">attempts</div>
                        </div>
                    </div>
                    <div style="margin-top: 8px; font-size: 11px;">
                        <span style="background: ${threatColor}; color: white; padding: 2px 8px; border-radius: 2px;">${escapeHtml(ip.threat_level || 'Unknown')}</span>
                        ${ip.is_blocked ? `<span style="background: ${TC.danger}; color: white; padding: 2px 8px; border-radius: 2px; margin-left: 4px;">BLOCKED</span>` : ''}
                    </div>
                </div>
            `;
        });
        html += '</div>';

        container.innerHTML = html;
    }

    /**
     * Get threat level color
     */
    function getThreatColor(level) {
        const colors = {
            'critical': TC.danger,
            'high': TC.orange,
            'medium': TC.warning,
            'low': TC.warningDark,
            'clean': TC.successDark
        };
        return colors[(level || '').toLowerCase()] || TC.textSecondary;
    }

    /**
     * Load AI recommendations
     */
    async function loadAIRecommendations() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/recommendations?${query}`);
            const data = await response.json();

            if (data.success) {
                renderAIRecommendations(data.data.recommendations || []);
            }
        } catch (error) {
            console.error('Error loading AI recommendations:', error);
            renderAIRecommendations([]);
        }
    }

    /**
     * Render AI recommendations
     */
    function renderAIRecommendations(recommendations) {
        const container = document.getElementById('events-ai-recommendations');
        if (!container) return;

        if (recommendations.length === 0) {
            container.innerHTML = `
                <div style="background: var(--background); padding: 12px; border-radius: 4px; border: 1px solid var(--border);">
                    <div style="font-weight: 500; margin-bottom: 4px; color: ${TC.successDark};">✅ All Clear</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">No critical security recommendations at this time</div>
                </div>
            `;
            return;
        }

        let html = '';
        recommendations.forEach(rec => {
            const icon = rec.priority === 'critical' ? '🚨' : rec.priority === 'high' ? '⚠️' : '💡';
            const borderColor = rec.priority === 'critical' ? TC.danger : rec.priority === 'high' ? TC.orange : TC.primary;
            html += `
                <div style="background: var(--background); padding: 12px; border-radius: 4px; border-left: 3px solid ${borderColor}; border: 1px solid var(--border); border-left: 3px solid ${borderColor};">
                    <div style="font-weight: 500; margin-bottom: 4px; color: var(--text-primary);">${icon} ${escapeHtml(rec.title)}</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">${escapeHtml(rec.description)}</div>
                    ${rec.action ? `<div style="margin-top: 8px;"><button style="background: var(--azure-blue); border: none; color: white; padding: 6px 12px; border-radius: 3px; cursor: pointer; font-size: 12px;">${escapeHtml(rec.action)}</button></div>` : ''}
                </div>
            `;
        });

        container.innerHTML = html;
    }

    /**
     * Load and render event timeline chart
     */
    async function loadEventTimeline() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/timeline?${query}`);
            const data = await response.json();

            if (data.success) {
                renderTimelineChart(data.data.timeline || []);
            }
        } catch (error) {
            console.error('Error loading timeline:', error);
        }
    }

    /**
     * Render timeline chart
     */
    function renderTimelineChart(timeline) {
        const canvas = document.getElementById('events-timeline-chart');
        if (!canvas) return;

        // Destroy existing chart
        if (chartInstances.timeline) {
            chartInstances.timeline.destroy();
        }

        const labels = timeline.map(t => t.date || t.label);
        const failed = timeline.map(t => t.failed || 0);
        const successful = timeline.map(t => t.successful || 0);

        chartInstances.timeline = new Chart(canvas, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Failed',
                        data: failed,
                        borderColor: TC.danger,
                        backgroundColor: TC.dangerBg,
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Successful',
                        data: successful,
                        borderColor: TC.successDark,
                        backgroundColor: TC.successBg,
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }

    /**
     * Load and render threat distribution pie chart
     */
    async function loadThreatDistribution() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/threat-distribution?${query}`);
            const data = await response.json();

            if (data.success) {
                renderThreatPieChart(data.data.distribution || {});
            }
        } catch (error) {
            console.error('Error loading threat distribution:', error);
        }
    }

    /**
     * Render threat distribution pie chart
     */
    function renderThreatPieChart(distribution) {
        const canvas = document.getElementById('events-threat-pie-chart');
        if (!canvas) return;

        if (chartInstances.threatPie) {
            chartInstances.threatPie.destroy();
        }

        const labels = Object.keys(distribution);
        const values = Object.values(distribution);
        const colors = labels.map(label => getThreatColor(label));

        chartInstances.threatPie = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 2,
                    borderColor: TC.surface
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }

    /**
     * Load attack patterns (failure reasons)
     */
    async function loadAttackPatterns() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/attack-patterns?${query}`);
            const data = await response.json();

            if (data.success) {
                renderAttackPatterns(data.data.patterns || []);
            }
        } catch (error) {
            console.error('Error loading attack patterns:', error);
        }
    }

    /**
     * Render attack patterns table
     */
    function renderAttackPatterns(patterns) {
        const tbody = document.getElementById('events-failure-reasons-body');
        if (!tbody) return;

        if (patterns.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="padding: 20px; text-align: center; color: var(--text-secondary);">No data available</td></tr>';
            return;
        }

        const total = patterns.reduce((sum, p) => sum + (p.count || 0), 0);

        let html = '';
        patterns.forEach(pattern => {
            const percentage = total > 0 ? ((pattern.count / total) * 100).toFixed(1) : 0;

            html += `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px;">${escapeHtml(pattern.reason || 'Unknown')}</td>
                    <td style="padding: 12px;">${formatNumber(pattern.count)}</td>
                    <td style="padding: 12px;">${percentage}%</td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }

    /**
     * Load targeted usernames
     */
    async function loadTargetedUsernames() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events-analysis/top-usernames?${query}`);
            const data = await response.json();

            if (data.success) {
                renderTargetedUsernames(data.data.usernames || []);
            }
        } catch (error) {
            console.error('Error loading usernames:', error);
        }
    }

    /**
     * Render targeted usernames table
     */
    function renderTargetedUsernames(usernames) {
        const tbody = document.getElementById('events-top-usernames-body');
        if (!tbody) return;

        if (usernames.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="padding: 20px; text-align: center; color: var(--text-secondary);">No data available</td></tr>';
            return;
        }

        let html = '';
        usernames.forEach(user => {
            const successRate = user.total > 0 ? ((user.successful / user.total) * 100).toFixed(1) : 0;
            const rateColor = successRate > 50 ? TC.successDark : successRate > 20 ? TC.warning : TC.danger;

            html += `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px; font-weight: 500;">${escapeHtml(user.username)}</td>
                    <td style="padding: 12px;">${formatNumber(user.total)}</td>
                    <td style="padding: 12px; color: ${TC.danger};">${formatNumber(user.failed)}</td>
                    <td style="padding: 12px; color: ${rateColor};">${successRate}%</td>
                    <td style="padding: 12px;">${formatNumber(user.unique_ips)}</td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }


    // Export shared state and functions for events_analysis_table.js
    window.eventsAnalysisState = {
        get currentPage() { return eventsCurrentPage; },
        set currentPage(val) { eventsCurrentPage = val; },
        get currentLimit() { return eventsCurrentLimit; },
        set currentLimit(val) { eventsCurrentLimit = val; },
        get filters() { return eventsFilters; },
        set filters(val) { eventsFilters = val; }
    };
    window.buildQueryString = buildQueryString;

    // Note: Events table, pagination, and event listeners are now in events_analysis_table.js

})();
