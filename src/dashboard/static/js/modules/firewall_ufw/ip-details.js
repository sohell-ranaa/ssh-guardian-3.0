/**
 * SSH Guardian v3.0 - Firewall UFW IP Details
 * IP details modal for UFW rules with fail2ban history
 */
(function() {
    'use strict';

    async function showUFWIpDetails(ip) {
        if (!ip) return;

        // Use the existing F2B IP modal if available
        if (typeof showBannedIpDetails === 'function') {
            showBannedIpDetails(ip);
            return;
        }

        // Fallback: Create a simple modal
        const modalId = 'ufw-ip-detail-modal';
        let modal = document.getElementById(modalId);
        if (modal) modal.remove();

        modal = document.createElement('div');
        modal.id = modalId;
        modal.className = 'event-detail-modal-overlay';
        modal.innerHTML = `
            <div class="event-detail-modal" style="max-width: 600px;">
                <div class="event-detail-modal-header">
                    <h3>IP Details: ${ip}</h3>
                    <button class="event-detail-modal-close" onclick="document.getElementById('${modalId}').remove()">&times;</button>
                </div>
                <div class="event-detail-modal-body" style="padding: 20px;">
                    <div style="text-align: center; padding: 30px;">
                        <div class="fw-spinner-lg"></div>
                        <div style="margin-top: 12px; color: var(--text-secondary);">Loading IP data...</div>
                    </div>
                </div>
            </div>
        `;
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };
        document.body.appendChild(modal);

        try {
            const [f2bResponse, geoResponse, blockResponse] = await Promise.all([
                fetch(`/api/dashboard/fail2ban/events?ip=${encodeURIComponent(ip)}&limit=20`).catch(() => ({ ok: false })),
                fetch(`/api/geoip/lookup/${encodeURIComponent(ip)}`).catch(() => ({ ok: false })),
                fetch(`/api/dashboard/blocking/history?ip=${encodeURIComponent(ip)}&limit=10`).catch(() => ({ ok: false }))
            ]);

            const f2bData = f2bResponse.ok ? await f2bResponse.json() : { events: [] };
            const geoData = geoResponse.ok ? await geoResponse.json() : {};
            const blockData = blockResponse.ok ? await blockResponse.json() : { events: [] };

            const events = f2bData.events || [];
            const location = geoData.location || geoData || {};
            const blockEvents = blockData.events || [];

            const banCount = events.filter(e => e.action === 'ban' || e.event_type === 'ban').length;
            const totalFailures = events.reduce((sum, e) => sum + (e.failures || 0), 0);

            const body = modal.querySelector('.event-detail-modal-body');
            body.innerHTML = `
                <div style="margin-bottom: 16px;">
                    <div style="font-size: 20px; font-weight: 700; font-family: monospace; margin-bottom: 4px;">${ip}</div>
                    <div style="color: var(--text-secondary);">
                        ${location.country || 'Unknown'} ${location.city ? '• ' + location.city : ''} • ${location.isp || location.org || 'Unknown ISP'}
                    </div>
                </div>

                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px;">
                    <div style="background: var(--surface); padding: 12px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: ${TC.danger};">${banCount}</div>
                        <div style="font-size: 11px; color: var(--text-secondary);">F2B Bans</div>
                    </div>
                    <div style="background: var(--surface); padding: 12px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: ${TC.orange};">${totalFailures}</div>
                        <div style="font-size: 11px; color: var(--text-secondary);">Failures</div>
                    </div>
                    <div style="background: var(--surface); padding: 12px; border-radius: 6px; text-align: center;">
                        <div style="font-size: 24px; font-weight: 700; color: ${TC.teal};">${blockEvents.length}</div>
                        <div style="font-size: 11px; color: var(--text-secondary);">Block Events</div>
                    </div>
                </div>

                <div style="font-weight: 600; margin-bottom: 8px;">Fail2ban History</div>
                <div style="max-height: 200px; overflow-y: auto; background: var(--surface); border-radius: 6px; padding: 8px; margin-bottom: 16px;">
                    ${events.length > 0 ? events.slice(0, 10).map(e => {
                        const icon = (e.action === 'ban' || e.event_type === 'ban') ? '🔒' : '🔓';
                        const action = (e.action === 'ban' || e.event_type === 'ban') ? 'Banned' : 'Unbanned';
                        const time = e.timestamp || e.reported_at;
                        return `
                            <div style="display: flex; align-items: center; gap: 10px; padding: 8px; border-bottom: 1px solid var(--border);">
                                <span>${icon}</span>
                                <span style="flex: 1;">${action} from <strong>${e.jail_name || 'sshd'}</strong></span>
                                ${e.failures ? `<span style="color: var(--text-secondary);">${e.failures} failures</span>` : ''}
                                <span style="color: var(--text-secondary); font-size: 12px;">${time ? formatTimeAgo(time) : ''}</span>
                            </div>
                        `;
                    }).join('') : '<div style="padding: 16px; text-align: center; color: var(--text-secondary);">No fail2ban events</div>'}
                </div>

                <div style="font-weight: 600; margin-bottom: 8px;">Blocking History</div>
                <div style="max-height: 150px; overflow-y: auto; background: var(--surface); border-radius: 6px; padding: 8px;">
                    ${blockEvents.length > 0 ? blockEvents.map(e => `
                        <div style="display: flex; align-items: center; gap: 10px; padding: 8px; border-bottom: 1px solid var(--border);">
                            <span>${e.event_type === 'escalate' ? '⬆️' : '🛡️'}</span>
                            <span style="flex: 1;">${e.event_type === 'escalate' ? 'Escalated to UFW' : 'Blocked'} via ${e.block_source || 'UFW'}</span>
                            <span style="color: var(--text-secondary); font-size: 12px;">${e.created_at ? formatTimeAgo(e.created_at) : ''}</span>
                        </div>
                    `).join('') : '<div style="padding: 16px; text-align: center; color: var(--text-secondary);">No blocking events</div>'}
                </div>
            `;
        } catch (error) {
            const body = modal.querySelector('.event-detail-modal-body');
            body.innerHTML = `
                <div style="text-align: center; padding: 30px; color: var(--text-secondary);">
                    <div style="font-size: 24px; margin-bottom: 8px;">⚠️</div>
                    <div>Failed to load IP details</div>
                    <div style="font-size: 12px; margin-top: 8px;">${error.message}</div>
                </div>
            `;
        }
    }

    // Global exports
    window.showUFWIpDetails = showUFWIpDetails;
})();
