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
        console.log('Loading Enhanced Events Analysis page...');

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
            const barColor = index === 0 ? '#D83B01' : index === 1 ? '#E6A502' : '#0078D4';

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
                        ${ip.is_blocked ? '<span style="background: #D83B01; color: white; padding: 2px 8px; border-radius: 2px; margin-left: 4px;">BLOCKED</span>' : ''}
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
            'critical': '#A80000',
            'high': '#D83B01',
            'medium': '#E6A502',
            'low': '#FFB900',
            'clean': '#107C10'
        };
        return colors[(level || '').toLowerCase()] || '#605E5C';
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
                    <div style="font-weight: 500; margin-bottom: 4px; color: #107C10;">✅ All Clear</div>
                    <div style="font-size: 12px; color: var(--text-secondary);">No critical security recommendations at this time</div>
                </div>
            `;
            return;
        }

        let html = '';
        recommendations.forEach(rec => {
            const icon = rec.priority === 'critical' ? '🚨' : rec.priority === 'high' ? '⚠️' : '💡';
            const borderColor = rec.priority === 'critical' ? '#A80000' : rec.priority === 'high' ? '#D83B01' : '#0078D4';
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
                        borderColor: '#D83B01',
                        backgroundColor: 'rgba(216, 59, 1, 0.1)',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'Successful',
                        data: successful,
                        borderColor: '#107C10',
                        backgroundColor: 'rgba(16, 124, 16, 0.1)',
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
                    borderColor: '#ffffff'
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
            const rateColor = successRate > 50 ? '#107C10' : successRate > 20 ? '#E6A502' : '#D83B01';

            html += `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px; font-weight: 500;">${escapeHtml(user.username)}</td>
                    <td style="padding: 12px;">${formatNumber(user.total)}</td>
                    <td style="padding: 12px; color: #D83B01;">${formatNumber(user.failed)}</td>
                    <td style="padding: 12px; color: ${rateColor};">${successRate}%</td>
                    <td style="padding: 12px;">${formatNumber(user.unique_ips)}</td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }

    /**
     * Load events table
     */
    async function loadEventsTable() {
        try {
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events/list?${query}&limit=${eventsCurrentLimit}&offset=${(eventsCurrentPage - 1) * eventsCurrentLimit}`);
            const data = await response.json();

            if (data.success) {
                renderEventsTable(data.events || []);
                renderPagination(data.pagination || {});
            }
        } catch (error) {
            console.error('Error loading events table:', error);
        }
    }

    /**
     * Render events table
     */
    function renderEventsTable(events) {
        const tbody = document.getElementById('events-table-body');
        if (!tbody) return;

        if (events.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="padding: 20px; text-align: center; color: var(--text-secondary);">No events found</td></tr>';
            return;
        }

        let html = '';
        events.forEach(event => {
            const typeColor = event.event_type === 'failed' ? '#D83B01' : '#107C10';
            const threatColor = getThreatColor(event.threat_level);

            html += `
                <tr style="border-bottom: 1px solid var(--border);">
                    <td style="padding: 12px; font-size: 12px;">${escapeHtml(formatTimestamp(event.timestamp))}</td>
                    <td style="padding: 12px;">
                        <span style="padding: 4px 8px; background: ${typeColor}; color: white; border-radius: 2px; font-size: 11px;">
                            ${escapeHtml(event.event_type || 'Unknown')}
                        </span>
                    </td>
                    <td style="padding: 12px; font-family: monospace; font-size: 12px;">${escapeHtml(event.source_ip || 'N/A')}</td>
                    <td style="padding: 12px;">${event.country_flag || '🌍'} ${escapeHtml(event.country || 'Unknown')}</td>
                    <td style="padding: 12px; font-weight: 500;">${escapeHtml(event.username || 'N/A')}</td>
                    <td style="padding: 12px; font-size: 12px;">${escapeHtml(event.agent_name || 'N/A')}</td>
                    <td style="padding: 12px;">
                        <span style="padding: 4px 8px; background: ${threatColor}; color: white; border-radius: 2px; font-size: 11px;">
                            ${escapeHtml(event.threat_level || 'Unknown')}
                        </span>
                    </td>
                    <td style="padding: 12px;">
                        <button onclick="analyzeEventsIP('${escapeHtml(event.source_ip)}')" style="padding: 4px 8px; background: var(--azure-blue); color: white; border: none; border-radius: 2px; cursor: pointer; font-size: 11px;">
                            Analyze
                        </button>
                    </td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }

    /**
     * Render pagination
     */
    function renderPagination(pagination) {
        const info = document.getElementById('events-pagination-info');
        const prevBtn = document.getElementById('events-prev-page');
        const nextBtn = document.getElementById('events-next-page');

        if (info) {
            const start = ((eventsCurrentPage - 1) * eventsCurrentLimit) + 1;
            const end = Math.min(start + eventsCurrentLimit - 1, pagination.total || 0);
            info.textContent = `Showing ${start}-${end} of ${formatNumber(pagination.total || 0)} events`;
        }

        if (prevBtn) {
            prevBtn.disabled = eventsCurrentPage === 1;
            prevBtn.style.opacity = eventsCurrentPage === 1 ? '0.5' : '1';
        }

        if (nextBtn) {
            nextBtn.disabled = !pagination.has_more;
            nextBtn.style.opacity = !pagination.has_more ? '0.5' : '1';
        }
    }

    /**
     * Format timestamp
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        const date = new Date(timestamp);
        return date.toLocaleString(undefined, {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    }

    /**
     * Update element content safely
     */
    function updateElement(id, content) {
        const el = document.getElementById(id);
        if (el) {
            if (typeof content === 'string') {
                el.innerHTML = content;
            } else {
                el.textContent = content;
            }
        }
    }

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        if (listenersSetup) return;
        listenersSetup = true;

        // Filter buttons
        const applyBtn = document.getElementById('events-apply-filters');
        const clearBtn = document.getElementById('events-clear-filters');
        const refreshBtn = document.getElementById('events-refresh-btn');
        const exportBtn = document.getElementById('events-export-btn');

        if (applyBtn) {
            applyBtn.addEventListener('click', applyFilters);
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', clearFilters);
        }

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => loadEventsAnalysisPage());
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', exportReport);
        }

        // Pagination
        const prevBtn = document.getElementById('events-prev-page');
        const nextBtn = document.getElementById('events-next-page');

        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                if (eventsCurrentPage > 1) {
                    eventsCurrentPage--;
                    loadEventsTable();
                }
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                eventsCurrentPage++;
                loadEventsTable();
            });
        }

        // Per page selector
        const perPageSelect = document.getElementById('events-per-page');
        if (perPageSelect) {
            perPageSelect.addEventListener('change', (e) => {
                eventsCurrentLimit = parseInt(e.target.value);
                eventsCurrentPage = 1;
                loadEventsTable();
            });
        }

        // Tab switching
        const tabs = document.querySelectorAll('.analysis-tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetTab = tab.dataset.tab;
                switchTab(targetTab);
            });
        });
    }

    /**
     * Apply filters
     */
    async function applyFilters() {
        eventsFilters = {
            dateRange: document.getElementById('events-date-range')?.value || '7d',
            eventType: document.getElementById('events-type-filter')?.value || '',
            threatLevel: document.getElementById('events-threat-filter')?.value || '',
            country: document.getElementById('events-country-filter')?.value || '',
            agent: document.getElementById('events-agent-filter')?.value || '',
            search: document.getElementById('events-search')?.value || ''
        };

        eventsCurrentPage = 1;
        await loadEventsAnalysisPage();
    }

    /**
     * Clear filters
     */
    async function clearFilters() {
        document.getElementById('events-date-range').value = '7d';
        document.getElementById('events-type-filter').value = '';
        document.getElementById('events-threat-filter').value = '';
        document.getElementById('events-country-filter').value = '';
        document.getElementById('events-agent-filter').value = '';
        document.getElementById('events-search').value = '';

        eventsFilters = {
            dateRange: '7d',
            eventType: '',
            threatLevel: '',
            country: '',
            agent: '',
            search: ''
        };

        eventsCurrentPage = 1;
        await loadEventsAnalysisPage();
    }

    /**
     * Switch between analysis tabs
     */
    function switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.analysis-tab').forEach(tab => {
            if (tab.dataset.tab === tabName) {
                tab.classList.add('active');
            } else {
                tab.classList.remove('active');
            }
        });

        // Update tab content
        document.querySelectorAll('.analysis-tab-content').forEach(content => {
            content.style.display = 'none';
        });

        const targetContent = document.getElementById(`tab-${tabName}`);
        if (targetContent) {
            targetContent.style.display = 'block';
        }
    }

    /**
     * Export report
     */
    function exportReport() {
        if (typeof showToast === 'function') {
            showToast('Export feature coming soon', 'info');
        } else {
            alert('Export feature coming soon');
        }
    }

    /**
     * Analyze IP - integrates with existing IP analysis modal
     */
    window.analyzeEventsIP = function(ip) {
        if (typeof window.showFullIPAnalysis === 'function') {
            window.showFullIPAnalysis(ip);
        } else if (typeof window.showIPAnalysis === 'function') {
            window.showIPAnalysis(ip);
        } else {
            // Fallback: show loading and fetch IP analysis
            if (typeof showCenteredLoader === 'function') {
                const loader = showCenteredLoader(`Analyzing ${ip}...`);
                fetch(`/api/demo/ip-analysis/${encodeURIComponent(ip)}`)
                    .then(response => response.json())
                    .then(data => {
                        loader.remove();
                        if (data.success) {
                            alert(`IP Analysis for ${ip}:\nRisk Score: ${data.composite_risk?.overall_score || 'N/A'}\nThreat Level: ${data.composite_risk?.threat_level || 'N/A'}`);
                        } else {
                            alert('Failed to analyze IP');
                        }
                    })
                    .catch(error => {
                        loader.remove();
                        console.error('Error:', error);
                        alert('Error analyzing IP');
                    });
            } else {
                alert(`Analyzing IP: ${ip}\n(Full analysis feature loading...)`);
            }
        }
    };

})();
