/**
 * Events Analysis Table Module
 * Events table rendering, pagination, event listeners, UI actions
 * Extracted from events_analysis_page.js for better maintainability
 */

(function() {
    'use strict';

    // State accessors - shared with events_analysis_page.js via window.eventsAnalysisState
    function getState() { return window.eventsAnalysisState || { currentPage: 1, currentLimit: 20, filters: {} }; }
    function buildQueryString() { return window.buildQueryString ? window.buildQueryString() : ''; }

    /**
     * Load events table
     */
    async function loadEventsTable() {
        try {
            const state = getState();
            const query = buildQueryString();
            const response = await fetch(`/api/dashboard/events/list?${query}&limit=${state.currentLimit}&offset=${(state.currentPage - 1) * state.currentLimit}`);
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
            const typeColor = event.event_type === 'failed' ? TC.danger : TC.successDark;
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
            const start = ((getState().currentPage - 1) * getState().currentLimit) + 1;
            const end = Math.min(start + getState().currentLimit - 1, pagination.total || 0);
            info.textContent = `Showing ${start}-${end} of ${formatNumber(pagination.total || 0)} events`;
        }

        if (prevBtn) {
            prevBtn.disabled = getState().currentPage === 1;
            prevBtn.style.opacity = getState().currentPage === 1 ? '0.5' : '1';
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
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.formatFull(timestamp);
        }
        // Fallback - parse server timezone then display in browser TZ
        let ts = String(timestamp).replace(' ', 'T');
        if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
        const date = new Date(ts);
        return date.toLocaleString();
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
                if (window.eventsAnalysisState.currentPage > 1) {
                    window.eventsAnalysisState.currentPage--;
                    loadEventsTable();
                }
            });
        }

        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                window.eventsAnalysisState.currentPage++;
                loadEventsTable();
            });
        }

        // Per page selector
        const perPageSelect = document.getElementById('events-per-page');
        if (perPageSelect) {
            perPageSelect.addEventListener('change', (e) => {
                window.eventsAnalysisState.currentLimit = parseInt(e.target.value);
                window.eventsAnalysisState.currentPage = 1;
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
        window.eventsAnalysisState.filters = {
            dateRange: document.getElementById('events-date-range')?.value || '7d',
            eventType: document.getElementById('events-type-filter')?.value || '',
            threatLevel: document.getElementById('events-threat-filter')?.value || '',
            country: document.getElementById('events-country-filter')?.value || '',
            agent: document.getElementById('events-agent-filter')?.value || '',
            search: document.getElementById('events-search')?.value || ''
        };

        window.eventsAnalysisState.currentPage = 1;
        await window.loadEventsAnalysisPage();
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

        window.eventsAnalysisState.filters = {
            dateRange: '7d',
            eventType: '',
            threatLevel: '',
            country: '',
            agent: '',
            search: ''
        };

        window.eventsAnalysisState.currentPage = 1;
        await window.loadEventsAnalysisPage();
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


    // Export functions needed by events_analysis_page.js
    window.loadEventsTable = loadEventsTable;
    window.renderEventsTable = renderEventsTable;
    window.renderPagination = renderPagination;
    window.formatTimestampAnalysis = formatTimestamp;
    window.setupEventListeners = setupEventListeners;
    window.applyFilters = applyFilters;
    window.clearFilters = clearFilters;
    window.switchAnalysisTab = switchTab;
    window.exportReport = exportReport;

})();
