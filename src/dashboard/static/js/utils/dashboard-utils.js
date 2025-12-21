/**
 * SSH Guardian v3.0 - Dashboard Shared Utilities
 * Common utility functions used across multiple dashboard pages
 */

window.DashboardUtils = {
    /**
     * Escape HTML to prevent XSS
     * @param {string} str - String to escape
     * @returns {string} - Escaped HTML string
     */
    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    },

    /**
     * Get country flag emoji from country code
     * @param {string} countryCode - Two-letter country code
     * @returns {string} - Flag emoji
     */
    getCountryFlag(countryCode) {
        if (!countryCode) return '';
        return String.fromCodePoint(
            ...countryCode.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0))
        );
    },

    /**
     * Generate IP tags HTML (TOR, VPN, Proxy)
     * @param {object} location - Location object with is_tor, is_vpn, is_proxy
     * @returns {string} - HTML string with tags
     */
    generateIpTags(location) {
        if (!location) return '';
        const tags = [
            location.is_tor && 'tor',
            location.is_vpn && 'vpn',
            location.is_proxy && 'proxy'
        ].filter(Boolean);

        if (!tags.length) return '';
        return `<div class="c-tags">${tags.map(t =>
            `<span class="c-tag ${t}">${t.toUpperCase()}</span>`
        ).join('')}</div>`;
    },

    /**
     * Generate IP tags HTML (inline version for modals)
     * @param {object} location - Location object
     * @returns {string} - HTML string with tags
     */
    generateIpTagsInline(location) {
        if (!location) return '';
        const tags = [
            location.is_tor && '<span class="c-tag tor">TOR</span>',
            location.is_vpn && '<span class="c-tag vpn">VPN</span>',
            location.is_proxy && '<span class="c-tag proxy">PROXY</span>'
        ].filter(Boolean);
        return tags.join(' ');
    },

    /**
     * Format datetime using TimeSettings or fallback
     * @param {string} timestamp - Timestamp string
     * @returns {string} - Formatted datetime
     */
    formatDateTime(timestamp) {
        if (!timestamp) return '-';
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.formatFull(timestamp);
        }
        // Fallback: browser's native timezone
        let ts = String(timestamp).replace(' ', 'T');
        if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return timestamp;
        return d.toLocaleString();
    },

    /**
     * Format time only
     * @param {string} timestamp - Timestamp string
     * @returns {string} - Formatted time
     */
    formatTimeOnly(timestamp) {
        if (!timestamp) return '-';
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.format(timestamp, 'time');
        }
        let ts = String(timestamp).replace(' ', 'T');
        if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return timestamp;
        return d.toLocaleTimeString();
    },

    /**
     * Format full datetime with specific format
     * @param {string} timestamp - Timestamp string
     * @returns {string} - Formatted datetime
     */
    formatFullDateTime(timestamp) {
        if (!timestamp) return '-';
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.format(timestamp, 'full');
        }
        let ts = String(timestamp).replace(' ', 'T');
        if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return timestamp;
        return d.toLocaleString('en-US', {
            month: 'short', day: 'numeric', year: 'numeric',
            hour: 'numeric', minute: '2-digit', second: '2-digit', hour12: true
        });
    },

    /**
     * Get date in local timezone (YYYY-MM-DD format)
     * @param {string} timestamp - Timestamp string
     * @returns {string|null} - Date string or null
     */
    getDateInTimezone(timestamp) {
        if (!timestamp) return null;
        let ts = String(timestamp).replace(' ', 'T');
        if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return null;
        return d.toLocaleDateString('en-CA');
    },

    /**
     * Format date with day name
     * @param {string} dateStr - Date string (YYYY-MM-DD)
     * @returns {string} - Formatted date
     */
    formatDateWithDay(dateStr) {
        if (!dateStr) return '';
        const dt = new Date(dateStr + 'T12:00:00');
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        return `${days[dt.getDay()]}, ${months[dt.getMonth()]} ${dt.getDate()}`;
    },

    /**
     * Check if time is unusual (before 7am or after 10pm)
     * @param {string} timestamp - Timestamp string
     * @returns {boolean} - True if unusual time
     */
    isUnusualTime(timestamp) {
        if (!timestamp) return false;
        let ts = String(timestamp).replace(' ', 'T');
        if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
        const d = new Date(ts);
        if (isNaN(d.getTime())) return false;
        const hour = d.getHours();
        return hour < 7 || hour >= 22;
    },

    /**
     * Calculate days since a timestamp
     * @param {string} timestamp - Timestamp string
     * @returns {number} - Number of days (minimum 1)
     */
    daysSince(timestamp) {
        if (!timestamp) return 1;
        return Math.max(1, Math.ceil((new Date() - new Date(timestamp)) / 86400000));
    },

    /**
     * Get risk level from score
     * @param {number} score - Risk score (0-100)
     * @returns {string} - Risk level text
     */
    getRiskLevel(score) {
        if (score >= 80) return 'CRITICAL';
        if (score >= 60) return 'HIGH';
        if (score >= 40) return 'MEDIUM';
        return 'LOW';
    },

    /**
     * Get risk CSS class from score
     * @param {number} score - Risk score (0-100)
     * @returns {string} - CSS class name
     */
    getRiskClass(score) {
        if (score >= 80) return 'crit';
        if (score >= 60) return 'high';
        if (score >= 40) return 'med';
        return 'low';
    },

    /**
     * Get risk color from score
     * @param {number} score - Risk score (0-100)
     * @returns {string} - Hex color
     */
    getRiskColor(score) {
        if (score >= 80) return '#991b1b';
        if (score >= 60) return '#dc2626';
        if (score >= 40) return '#d97706';
        return '#16a34a';
    },

    /**
     * Get threat level color
     * @param {string} level - Threat level (critical, high, medium, low, clean)
     * @returns {string} - Hex color
     */
    getThreatColor(level) {
        const colors = {
            critical: '#991b1b',
            high: '#dc2626',
            medium: '#d97706',
            low: '#16a34a',
            clean: '#16a34a'
        };
        return colors[level?.toLowerCase()] || '#6b7280';
    },

    /**
     * Render risk bar HTML
     * @param {number} score - Risk score (0-100)
     * @param {string} cssClass - CSS class for fill
     * @returns {string} - HTML string
     */
    renderRiskBar(score, cssClass) {
        return `<div class="c-risk">
            <span>${Math.round(score)}</span>
            <div class="c-risk-bar">
                <div class="c-risk-fill ${cssClass}" style="width:${score}%"></div>
            </div>
        </div>`;
    },

    /**
     * Detect threat type based on data
     * @param {object} data - Event data with failed_count, success_count, unique_users
     * @returns {string} - Threat type description
     */
    detectThreatType(data) {
        if (data.failed_count > 50 && data.unique_users > 10) return 'Brute Force';
        if (data.unique_users > 20) return 'Credential Stuffing';
        if (data.failed_count > 0 && data.success_count > 0) return 'Mixed';
        if (data.failed_count > 10) return 'Password Guess';
        return data.success_count > 0 ? 'Legitimate' : 'Recon';
    },

    /**
     * Detect attack pattern based on data
     * @param {object} data - Event data
     * @returns {string} - Pattern description
     */
    detectPattern(data) {
        const rate = data.event_count / Math.max(1, this.daysSince(data.first_timestamp));
        if (rate > 50) return 'High Velocity';
        if (rate > 10) return 'Moderate';
        if (data.unique_users > 5) return 'User Enum';
        return 'Low & Slow';
    },

    /**
     * Generate recommendations based on data
     * @param {object} data - Event data
     * @returns {string} - HTML string with recommendations
     */
    generateRecommendations(data) {
        const recs = [];
        const risk = data.max_risk_score || 0;
        const loc = data.location || {};

        if (risk >= 70) {
            recs.push({ type: 'crit', icon: '🚨', msg: 'Block immediately' });
        }
        if (data.failed_count > 50) {
            recs.push({ type: 'crit', icon: '🔒', msg: 'Brute force - Rate limit' });
        }
        if (loc.is_tor || loc.is_vpn || loc.is_proxy) {
            recs.push({ type: 'warn', icon: '⚠️', msg: 'Anonymous network - Monitor' });
        }
        if (data.unique_users > 10) {
            recs.push({ type: 'warn', icon: '👥', msg: 'Multi-user attack' });
        }
        if (data.success_count > 0 && data.failed_count > 0) {
            recs.push({ type: 'warn', icon: '🔍', msg: 'Verify successful logins' });
        }
        if (!recs.length) {
            recs.push({ type: 'info', icon: '✅', msg: 'No immediate threats' });
        }

        return recs.map(r =>
            `<div class="m-rec ${r.type}"><span>${r.icon}</span><span>${r.msg}</span></div>`
        ).join('');
    },

    /**
     * Debounce function execution
     * @param {function} func - Function to debounce
     * @param {number} wait - Wait time in ms
     * @returns {function} - Debounced function
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
};

// Shorthand alias
window.DU = window.DashboardUtils;
