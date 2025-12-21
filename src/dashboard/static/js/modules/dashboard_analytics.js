/**
 * SSH Guardian v3.0 - Dashboard Analytics Page Module
 * Analytics charts and statistics display
 * Extracted from dashboard_analytics.html for better maintainability
 */

// Dashboard Analytics Module
const DashboardAnalytics = {
    charts: {},

    init() {
        this.loadStats();
        this.loadTopAttackingIPs();
        this.loadAgentStatus();
        this.loadRecentHighRiskEvents();
        this.initCharts();
    },

    async loadStats() {
        try {
            // Fetch stats in parallel
            const [eventsRes, blocksRes] = await Promise.all([
                fetch('/api/events/list?limit=1').catch(() => null),
                fetch('/api/dashboard/blocking/blocks/list?is_active=true').catch(() => null)
            ]);

            if (eventsRes?.ok) {
                const data = await eventsRes.json();
                const total = data.data?.pagination?.total || 0;
                document.getElementById('analytics-total-events').textContent = this.formatNumber(total);
                document.getElementById('dashboard-total-events').textContent = this.formatNumber(total);
            }

            if (blocksRes?.ok) {
                const data = await blocksRes.json();
                const count = data.data?.length || 0;
                document.getElementById('analytics-blocked-ips').textContent = count;
            }

            // Get failed logins
            const failedRes = await fetch('/api/events/list?event_type=Failed&limit=1').catch(() => null);
            if (failedRes?.ok) {
                const data = await failedRes.json();
                const failed = data.data?.pagination?.total || 0;
                document.getElementById('analytics-failed-logins').textContent = this.formatNumber(failed);
                document.getElementById('dashboard-threats').textContent = this.formatNumber(failed);
            }

            // Get successful logins
            const successRes = await fetch('/api/events/list?event_type=Accepted&limit=1').catch(() => null);
            if (successRes?.ok) {
                const data = await successRes.json();
                const success = data.data?.pagination?.total || 0;
                document.getElementById('analytics-successful-logins').textContent = this.formatNumber(success);
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    },

    async loadTopAttackingIPs() {
        const container = document.getElementById('top-attacking-ips');
        try {
            const response = await fetch('/api/events/list?event_type=Failed&limit=100');
            if (!response.ok) throw new Error('Failed to load');

            const data = await response.json();
            const events = data.data?.events || [];

            // Count by IP
            const ipCounts = {};
            events.forEach(event => {
                const ip = event.source_ip;
                ipCounts[ip] = (ipCounts[ip] || 0) + 1;
            });

            // Sort and get top 5
            const topIPs = Object.entries(ipCounts)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);

            if (topIPs.length === 0) {
                container.innerHTML = '<div class="loading-placeholder"><span>No attacking IPs today</span></div>';
                return;
            }

            container.innerHTML = topIPs.map(([ip, count], index) => `
                <div class="top-list-item">
                    <div class="top-list-rank">${index + 1}</div>
                    <div class="top-list-content">
                        <div class="top-list-ip">${ip}</div>
                        <div class="top-list-info">Failed attempts</div>
                    </div>
                    <div class="top-list-count">${count}</div>
                </div>
            `).join('');
        } catch (error) {
            container.innerHTML = '<div class="loading-placeholder"><span>Failed to load data</span></div>';
        }
    },

    async loadAgentStatus() {
        const container = document.getElementById('agent-status-grid');
        try {
            const response = await fetch('/api/agents/list');
            if (!response.ok) throw new Error('Failed to load');

            const data = await response.json();
            const agents = data.data?.agents || data.data || [];

            if (agents.length === 0) {
                container.innerHTML = '<div class="loading-placeholder"><span>No agents registered</span></div>';
                return;
            }

            container.innerHTML = agents.slice(0, 6).map(agent => `
                <div class="agent-status-item">
                    <div class="agent-status-indicator ${agent.status || 'offline'}"></div>
                    <div class="agent-status-name">${agent.hostname || agent.agent_uuid?.slice(0, 8) || 'Unknown'}</div>
                    <div class="agent-status-events">${agent.event_count || 0} events</div>
                </div>
            `).join('');
        } catch (error) {
            container.innerHTML = '<div class="loading-placeholder"><span>Failed to load agents</span></div>';
        }
    },

    async loadRecentHighRiskEvents() {
        const container = document.getElementById('recent-high-risk-events');
        try {
            const response = await fetch('/api/events/list?limit=5');
            if (!response.ok) throw new Error('Failed to load');

            const data = await response.json();
            const events = data.data?.events || [];

            if (events.length === 0) {
                container.innerHTML = '<div class="loading-placeholder"><span>No recent events</span></div>';
                return;
            }

            container.innerHTML = events.map(event => {
                const riskClass = (event.composite_risk_score || 0) > 70 ? 'high' :
                                  (event.composite_risk_score || 0) > 40 ? 'medium' : 'low';
                const iconClass = event.event_type === 'Failed' ? 'failed' :
                                  event.event_type === 'Accepted' ? 'success' : 'blocked';
                const icon = event.event_type === 'Failed' ? '&#9888;' :
                             event.event_type === 'Accepted' ? '&#10003;' : '&#128274;';

                return `
                    <div class="activity-item">
                        <div class="activity-icon ${iconClass}">${icon}</div>
                        <div class="activity-content">
                            <div class="activity-title">${event.event_type} - ${event.username || 'unknown'}</div>
                            <div class="activity-meta">${event.source_ip} - ${event.agent_hostname || 'Unknown Agent'}</div>
                        </div>
                        <div class="activity-time">${this.formatTime(event.event_timestamp)}</div>
                        <div class="activity-risk ${riskClass}">${Math.round(event.composite_risk_score || 0)}%</div>
                    </div>
                `;
            }).join('');
        } catch (error) {
            container.innerHTML = '<div class="loading-placeholder"><span>Failed to load events</span></div>';
        }
    },

    initCharts() {
        // Events Timeline Chart
        const timelineCtx = document.getElementById('events-timeline-chart')?.getContext('2d');
        if (timelineCtx) {
            this.charts.timeline = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => `${i}:00`),
                    datasets: [{
                        label: 'Failed',
                        data: Array.from({length: 24}, () => Math.floor(Math.random() * 50)),
                        borderColor: TC.danger,
                        backgroundColor: TC.dangerBg,
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Successful',
                        data: Array.from({length: 24}, () => Math.floor(Math.random() * 20)),
                        borderColor: TC.successDark,
                        backgroundColor: TC.successBg,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top' }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }

        // Event Types Pie Chart
        const typesCtx = document.getElementById('event-types-chart')?.getContext('2d');
        if (typesCtx) {
            this.charts.types = new Chart(typesCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Failed', 'Successful', 'Invalid User'],
                    datasets: [{
                        data: [65, 25, 10],
                        backgroundColor: [TC.danger, TC.successDark, TC.warning]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
        }

        // Geographic Distribution Chart
        const geoCtx = document.getElementById('geo-distribution-chart')?.getContext('2d');
        if (geoCtx) {
            this.charts.geo = new Chart(geoCtx, {
                type: 'bar',
                data: {
                    labels: ['US', 'CN', 'RU', 'DE', 'BR', 'Other'],
                    datasets: [{
                        label: 'Events',
                        data: [120, 89, 75, 45, 32, 156],
                        backgroundColor: TC.primary
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }
    },

    updateTimelineRange(range) {
        console.log('Updating timeline range to:', range);
        // TODO: Fetch data for selected range and update chart
    },

    formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    },

    formatTime(timestamp) {
        if (!timestamp) return '--';
        // Use TimeSettings for proper timezone handling
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.relative(timestamp);
        }
        // Server timestamps are in server timezone (+08:00)
        let dateStr = String(timestamp).replace(' ', 'T');
        if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.match(/T\d{2}:\d{2}:\d{2}-/)) {
            dateStr += '+08:00';
        }
        const date = new Date(dateStr);
        const now = new Date();
        const diff = now - date;

        if (diff < 0) return 'Just now';
        if (diff < 60000) return 'Just now';
        if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
        if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
        return date.toLocaleDateString();
    }
};

// Load function for page navigation
function loadDashboardAnalytics() {
    DashboardAnalytics.init();
}

// Export for global access
window.DashboardAnalytics = DashboardAnalytics;
window.loadDashboardAnalytics = loadDashboardAnalytics;
