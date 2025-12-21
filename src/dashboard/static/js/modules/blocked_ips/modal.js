/**
 * Blocked IPs - Modal Module
 * IP details modal and styling
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml || ((t) => t == null ? '' : String(t).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[m]));
    const formatLocalDateTime = window.formatLocalDateTime || ((d) => d ? new Date(d).toLocaleString() : 'N/A');
    const TC = window.TC || { primary:'#0078D4', primaryDark:'#004C87', primaryHover:'#106EBE', danger:'#D13438', success:'#107C10', successDark:'#0B6A0B', warning:'#FFB900', purple:'#8764B8', textSecondary:'#605E5C', textPrimary:'#323130' };

    BlockedIPs.Modal = {
        stylesInjected: false,

        /**
         * Show IP details modal
         */
        async showDetails(ipAddress) {
            if (!ipAddress) {
                BlockedIPs.UI.notify('No IP address provided', 'error');
                return;
            }

            // Show loading modal
            this.show('Loading...', `
                <div style="text-align: center; padding: 40px;">
                    <div style="font-size: 24px; margin-bottom: 16px;">⏳</div>
                    <p>Loading details for ${escapeHtml(ipAddress)}...</p>
                </div>
            `);

            try {
                const [statusResponse, geoResponse] = await Promise.all([
                    fetch(`/api/dashboard/event-actions/ip-status/${encodeURIComponent(ipAddress)}`),
                    fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ipAddress)}`)
                ]);

                const status = await statusResponse.json();
                const geoInfo = await geoResponse.json();

                const content = this.buildDetailsContent(ipAddress, status, geoInfo);
                this.show(`IP Details: ${ipAddress}`, content, { icon: '🔍 ' });

            } catch (error) {
                console.error('Error loading IP details:', error);
                this.show('Error', `
                    <div style="text-align: center; padding: 40px; color: ${TC.danger};">
                        <div style="font-size: 24px; margin-bottom: 16px;">❌</div>
                        <p>Error loading IP details: ${escapeHtml(error.message)}</p>
                    </div>
                `);
            }
        },

        /**
         * Build details modal content
         */
        buildDetailsContent(ipAddress, status, geoInfo) {
            // Status badges
            const statusBadges = [];
            if (status?.is_blocked) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.danger}; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Blocked</span>`);
            }
            if (status?.is_whitelisted) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.successDark}; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Whitelisted</span>`);
            }
            if (status?.is_watched) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.warning}; color: ${TC.textPrimary}; border-radius: 3px; font-size: 11px; margin-right: 5px;">Watched</span>`);
            }
            if (geoInfo?.is_proxy) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.purple}; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Proxy/VPN</span>`);
            }
            if (statusBadges.length === 0) {
                statusBadges.push(`<span style="display: inline-block; padding: 4px 8px; background: ${TC.textSecondary}; color: white; border-radius: 3px; font-size: 11px;">No Special Status</span>`);
            }

            // Geolocation section
            let geoSection = '';
            if (geoInfo?.success) {
                const flagImg = geoInfo.country_code && geoInfo.country_code !== 'N/A'
                    ? `<img src="https://flagcdn.com/24x18/${geoInfo.country_code.toLowerCase()}.png" alt="${geoInfo.country_code}" style="vertical-align: middle; margin-right: 6px;">`
                    : '';

                geoSection = `
                    <div class="ip-detail-section">
                        <div class="ip-detail-section-title">Geolocation</div>
                        <div class="ip-detail-grid">
                            <div>
                                <div class="ip-detail-item-label">Country</div>
                                <div class="ip-detail-item-value">${flagImg}${escapeHtml(geoInfo.country || 'Unknown')} (${escapeHtml(geoInfo.country_code || 'N/A')})</div>
                            </div>
                            <div>
                                <div class="ip-detail-item-label">City</div>
                                <div class="ip-detail-item-value">${escapeHtml(geoInfo.city || 'Unknown')}</div>
                            </div>
                            <div>
                                <div class="ip-detail-item-label">Region</div>
                                <div class="ip-detail-item-value">${escapeHtml(geoInfo.region || 'Unknown')}</div>
                            </div>
                            <div>
                                <div class="ip-detail-item-label">Timezone</div>
                                <div class="ip-detail-item-value">${escapeHtml(geoInfo.timezone || 'N/A')}</div>
                            </div>
                        </div>
                    </div>
                    <div class="ip-detail-section">
                        <div class="ip-detail-section-title">Network</div>
                        <div class="ip-detail-grid">
                            <div>
                                <div class="ip-detail-item-label">ISP / Organization</div>
                                <div class="ip-detail-item-value">${escapeHtml(geoInfo.isp || 'Unknown')}</div>
                            </div>
                            <div>
                                <div class="ip-detail-item-label">ASN</div>
                                <div class="ip-detail-item-value">AS${escapeHtml(geoInfo.asn || 'N/A')}</div>
                            </div>
                        </div>
                    </div>
                `;
            }

            return `
                <div class="ip-detail-content">
                    <div class="ip-detail-header">
                        <div class="ip-detail-ip">${escapeHtml(ipAddress)}</div>
                        <div class="ip-detail-status">${statusBadges.join('')}</div>
                    </div>
                    ${geoSection}
                </div>
            `;
        },

        /**
         * Show modal
         */
        show(title, content, options = {}) {
            this.injectStyles();

            document.querySelectorAll('.block-modal-overlay').forEach(el => el.remove());

            const overlay = document.createElement('div');
            overlay.className = 'block-modal-overlay';

            const modal = document.createElement('div');
            modal.className = 'block-modal';

            const titleIcon = options.icon || '';

            modal.innerHTML = `
                <div class="block-modal-header">
                    <h3 class="block-modal-title">${titleIcon}${escapeHtml(title)}</h3>
                    <button class="block-modal-close" title="Close">&times;</button>
                </div>
                <div class="block-modal-body">${content}</div>
                <div class="block-modal-footer">
                    <button class="block-modal-btn block-modal-btn-primary modal-close-action">Close</button>
                </div>
            `;

            overlay.appendChild(modal);
            document.body.appendChild(overlay);
            document.body.style.overflow = 'hidden';

            const closeModal = () => {
                overlay.style.animation = 'blockModalFadeIn 0.15s ease-out reverse';
                modal.style.animation = 'blockModalSlideIn 0.15s ease-out reverse';
                setTimeout(() => {
                    overlay.remove();
                    document.body.style.overflow = '';
                }, 140);
            };

            modal.querySelector('.block-modal-close').onclick = closeModal;
            modal.querySelector('.modal-close-action').onclick = closeModal;
            overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };

            const keyHandler = (e) => {
                if (e.key === 'Escape') {
                    closeModal();
                    document.removeEventListener('keydown', keyHandler);
                }
            };
            document.addEventListener('keydown', keyHandler);

            return { overlay, modal, closeModal };
        },

        /**
         * Inject modal styles
         */
        injectStyles() {
            if (this.stylesInjected) return;
            if (document.getElementById('block-modal-styles')) return;

            const style = document.createElement('style');
            style.id = 'block-modal-styles';
            style.textContent = `
                .block-modal-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0, 0, 0, 0.5);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 10000;
                    animation: blockModalFadeIn 0.2s ease-out;
                }
                .block-modal {
                    background: var(--surface);
                    border-radius: 8px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
                    max-width: 600px;
                    width: 90%;
                    max-height: 85vh;
                    overflow: hidden;
                    animation: blockModalSlideIn 0.2s ease-out;
                }
                .block-modal-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 16px 20px;
                    background: linear-gradient(135deg, ${TC.primary} 0%, ${TC.primaryDark} 100%);
                    color: white;
                }
                .block-modal-title {
                    margin: 0;
                    font-size: 16px;
                    font-weight: 600;
                }
                .block-modal-close {
                    background: none;
                    border: none;
                    color: rgba(255, 255, 255, 0.8);
                    font-size: 24px;
                    cursor: pointer;
                    padding: 0;
                    line-height: 1;
                }
                .block-modal-close:hover { color: white; }
                .block-modal-body {
                    padding: 20px;
                    max-height: 60vh;
                    overflow-y: auto;
                }
                .block-modal-footer {
                    padding: 16px 20px;
                    border-top: 1px solid var(--border);
                    display: flex;
                    justify-content: flex-end;
                }
                .block-modal-btn {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    font-size: 13px;
                    font-weight: 500;
                    cursor: pointer;
                    transition: all 0.15s;
                }
                .block-modal-btn-primary {
                    background: ${TC.primary};
                    color: white;
                }
                .block-modal-btn-primary:hover { background: ${TC.primaryHover}; }
                .block-modal-btn-secondary {
                    background: var(--background);
                    color: var(--text-primary);
                    border: 1px solid var(--border);
                }
                .block-modal-btn-secondary:hover { background: var(--border); }

                .ip-detail-content { }
                .ip-detail-header {
                    text-align: center;
                    padding-bottom: 16px;
                    border-bottom: 1px solid var(--border);
                    margin-bottom: 16px;
                }
                .ip-detail-ip {
                    font-size: 24px;
                    font-weight: 700;
                    font-family: var(--font-mono);
                    margin-bottom: 8px;
                }
                .ip-detail-status { }
                .ip-detail-section {
                    margin-bottom: 16px;
                    padding: 16px;
                    background: var(--background);
                    border-radius: 6px;
                }
                .ip-detail-section-title {
                    font-size: 13px;
                    font-weight: 600;
                    color: var(--text-secondary);
                    margin-bottom: 12px;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }
                .ip-detail-grid {
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 12px;
                }
                .ip-detail-item-label {
                    font-size: 11px;
                    color: var(--text-hint);
                    margin-bottom: 2px;
                }
                .ip-detail-item-value {
                    font-size: 13px;
                    color: var(--text-primary);
                }

                @keyframes blockModalFadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                @keyframes blockModalSlideIn {
                    from { transform: translateY(-20px); opacity: 0; }
                    to { transform: translateY(0); opacity: 1; }
                }

                @media (max-width: 600px) {
                    .block-modal { width: 95%; }
                    .ip-detail-grid { grid-template-columns: 1fr; }
                }
            `;
            document.head.appendChild(style);
            this.stylesInjected = true;
        }
    };
})();
