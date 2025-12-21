/**
 * Blocked IPs - UI Module
 * UI helpers, badges, notifications, location enrichment
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml || ((t) => t == null ? '' : String(t).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[m]));
    const TC = window.TC || { primary:'#0078D4', danger:'#D13438', success:'#107C10', warning:'#FFB900', purple:'#8764B8', textSecondary:'#605E5C', orangeDark:'#CA5010' };

    BlockedIPs.UI = {
        /**
         * Get source badge HTML
         */
        getSourceBadge(source) {
            const sourceStyles = {
                'auto': { bg: TC.danger, icon: '🤖', label: 'Auto' },
                'manual': { bg: TC.primary, icon: '👤', label: 'Manual' },
                'fail2ban': { bg: TC.warning, icon: '🛡️', label: 'Fail2ban' },
                'firewall': { bg: TC.purple, icon: '🔥', label: 'Firewall' },
                'ml': { bg: TC.orangeDark, icon: '🧠', label: 'ML' }
            };

            const style = sourceStyles[source?.toLowerCase()] || { bg: TC.textSecondary, icon: '❓', label: source || 'Unknown' };

            return `<span style="padding: 4px 10px; background: ${style.bg}; color: white; border-radius: 3px; font-size: 11px; font-weight: 500;">
                ${style.icon} ${style.label}
            </span>`;
        },

        /**
         * Update block statistics
         */
        updateStats(blocks) {
            const total = blocks.length;
            const active = blocks.filter(b => b.is_active).length;
            const expired = blocks.filter(b => !b.is_active).length;
            const permanent = blocks.filter(b => !b.unblock_at).length;

            const totalEl = document.getElementById('stat-blocks-total');
            const activeEl = document.getElementById('stat-blocks-active');
            const expiredEl = document.getElementById('stat-blocks-expired');
            const permanentEl = document.getElementById('stat-blocks-permanent');

            if (totalEl) totalEl.textContent = total;
            if (activeEl) activeEl.textContent = active;
            if (expiredEl) expiredEl.textContent = expired;
            if (permanentEl) permanentEl.textContent = permanent;
        },

        /**
         * Show notification
         */
        notify(message, type = 'info') {
            if (typeof window.showToast === 'function') {
                window.showToast(message, type);
            } else {
                console.log(`[${type.toUpperCase()}] ${message}`);
            }
        },

        /**
         * Enrich blocks with location data
         */
        async enrichLocations(blocks) {
            const uniqueIPs = [...new Set(blocks.map(b => b.ip_address))];

            for (const ip of uniqueIPs) {
                try {
                    const response = await fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ip)}`);
                    const data = await response.json();

                    const cells = document.querySelectorAll(`.ip-location-cell[data-ip="${ip}"]`);
                    cells.forEach(cell => {
                        if (data.success) {
                            const flagImg = data.country_code && data.country_code !== 'N/A'
                                ? `<img src="https://flagcdn.com/16x12/${data.country_code.toLowerCase()}.png" alt="${data.country_code}" style="vertical-align: middle; margin-right: 6px;">`
                                : '';
                            const locationText = data.country_code === 'N/A'
                                ? 'Unknown Location'
                                : `${data.city || 'Unknown'}, ${data.country || 'Unknown'}`;
                            cell.innerHTML = `${flagImg}<span>${escapeHtml(locationText)}</span>`;
                        } else {
                            cell.innerHTML = '<span style="color: var(--text-secondary);">Unknown</span>';
                        }
                    });
                } catch (error) {
                    console.error(`Error fetching location for ${ip}:`, error);
                    const cells = document.querySelectorAll(`.ip-location-cell[data-ip="${ip}"]`);
                    cells.forEach(cell => {
                        cell.innerHTML = '<span style="color: var(--text-secondary);">Error</span>';
                    });
                }
            }
        }
    };
})();
