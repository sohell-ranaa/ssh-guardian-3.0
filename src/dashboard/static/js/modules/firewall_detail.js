/**
 * SSH Guardian v3.0 - Firewall IP Detail Modal
 * Investigation details, ML contribution, threat intel display
 * Extracted from firewall_inline.js for better maintainability
 *
 * Dependencies: firewall_utils.js, firewall_inline.js
 */

// ===============================================
// Blocked IP Detail Modal - Investigation & ML Contribution
// ===============================================

async function showBlockedIPDetailModal(blockId, ipAddress) {
    // Show loading modal immediately
    showFWDetailModal('Loading...', `
        <div style="text-align: center; padding: 40px;">
            <div class="loading-spinner"></div>
            <p style="margin-top: 16px; color: var(--text-secondary);">Loading investigation details for ${escapeHtml(ipAddress)}...</p>
        </div>
    `);

    try {
        // Fetch detailed block info from API
        const response = await fetch(`/api/dashboard/blocking/blocks/details/${blockId}`);
        const data = await response.json();

        if (!data.success) {
            showFWDetailModal('Error', `
                <div style="text-align: center; padding: 20px; color: ${TC.danger};">
                    <p>Failed to load block details: ${data.error || 'Unknown error'}</p>
                </div>
            `);
            return;
        }

        // Transform API response to expected format
        const apiBlock = data.block || {};
        const apiThreat = data.threat_intelligence || {};
        const apiBehavior = data.behavioral_analysis || {};
        const apiGeo = data.geolocation || {};

        const block = {
            id: apiBlock.id,
            ip_address: apiBlock.ip_address || ipAddress,
            reason: apiBlock.reason,
            source: apiBlock.source,
            blocked_at: apiBlock.blocked_at,
            expires_at: apiBlock.unblock_at,
            is_active: apiBlock.is_active,
            agent_name: apiBlock.agent || 'Global',
            threat_intel: {
                abuseipdb_score: apiThreat.abuseipdb?.score || 0,
                virustotal_malicious: apiThreat.virustotal?.malicious || 0,
                total_reports: apiThreat.abuseipdb?.reports || 0,
                is_known_threat: (apiThreat.abuseipdb?.score || 0) >= 50
            },
            geoip: {
                country: apiGeo.country,
                country_code: apiGeo.country_code,
                city: apiGeo.city,
                isp: apiGeo.isp,
                asn: apiGeo.asn
            },
            behavioral: {
                failed_attempts: apiBehavior.failed_attempts || 0,
                unique_usernames: apiBehavior.unique_usernames_targeted || 0,
                success_rate: apiBehavior.successful_logins && apiBehavior.total_events
                    ? apiBehavior.successful_logins / apiBehavior.total_events : 0,
                first_seen: apiBehavior.first_seen,
                last_seen: apiBehavior.last_seen,
                attack_pattern: determineAttackPattern(apiBehavior)
            },
            ml_contribution: data.ml_contribution || {},
            justification: data.justification || {},
            blocking_history: data.blocking_history || []
        };

        renderBlockedIPDetailModal(block, ipAddress);

    } catch (error) {
        console.error('Error loading block details:', error);
        showFWDetailModal('Error', `
            <div style="text-align: center; padding: 20px; color: ${TC.danger};">
                <p>Error loading block details</p>
            </div>
        `);
    }
}

function determineAttackPattern(behavior) {
    if (!behavior) return 'Unknown';
    const failed = behavior.failed_attempts || 0;
    const uniqueUsers = behavior.unique_usernames_targeted || 0;

    if (failed >= 20 && uniqueUsers >= 5) return 'Distributed Brute Force';
    if (failed >= 10) return 'Brute Force';
    if (uniqueUsers >= 3) return 'Credential Stuffing';
    if (failed > 0) return 'Password Guessing';
    return 'Unknown';
}

function renderBlockedIPDetailModal(block, ipAddress) {
    const threatIntel = block.threat_intel || {};
    const behavioral = block.behavioral || {};
    const mlContribution = block.ml_contribution || {};
    const justification = block.justification || {};
    const geoip = block.geoip || {};

    // Build header with status
    const statusBadge = block.is_active
        ? '<span class="detail-badge critical">Active Block</span>'
        : '<span class="detail-badge success">Expired</span>';

    const sourceBadges = {
        'manual': '<span class="detail-badge info">Manual</span>',
        'rule_based': '<span class="detail-badge purple">Rule-Based</span>',
        'ml_model': '<span class="detail-badge warning">ML Model</span>',
        'fail2ban': '<span class="detail-badge high">Fail2ban</span>',
        'api_reputation': '<span class="detail-badge critical">API Reputation</span>'
    };
    const sourceBadge = sourceBadges[block.source] || `<span class="detail-badge">${block.source}</span>`;

    // GeoIP section
    const geoSection = geoip.country ? `
        <div class="detail-section">
            <div class="detail-section-title">📍 Location</div>
            <div class="detail-grid">
                <div><span class="detail-label">Country:</span> ${escapeHtml(geoip.country || 'Unknown')} ${geoip.country_code ? `(${geoip.country_code})` : ''}</div>
                <div><span class="detail-label">City:</span> ${escapeHtml(geoip.city || 'Unknown')}</div>
                <div><span class="detail-label">ISP:</span> ${escapeHtml(geoip.isp || 'Unknown')}</div>
                <div><span class="detail-label">ASN:</span> ${geoip.asn || 'N/A'}</div>
            </div>
        </div>
    ` : '';

    // Threat Intelligence section
    const abuseScore = threatIntel.abuseipdb_score || 0;
    const vtMalicious = threatIntel.virustotal_malicious || 0;
    const threatSection = `
        <div class="detail-section">
            <div class="detail-section-title">🔍 Threat Intelligence</div>
            <div class="threat-intel-grid">
                <div class="threat-intel-item">
                    <div class="threat-intel-label">AbuseIPDB Score</div>
                    <div class="threat-intel-value ${getScoreClass(abuseScore)}">${abuseScore}%</div>
                    <div class="threat-intel-bar">
                        <div class="threat-intel-bar-fill ${getScoreClass(abuseScore)}" style="width: ${abuseScore}%"></div>
                    </div>
                </div>
                <div class="threat-intel-item">
                    <div class="threat-intel-label">VirusTotal Detections</div>
                    <div class="threat-intel-value ${vtMalicious > 0 ? 'critical' : 'low'}">${vtMalicious}</div>
                </div>
                <div class="threat-intel-item">
                    <div class="threat-intel-label">Reports (30 days)</div>
                    <div class="threat-intel-value">${threatIntel.total_reports || 0}</div>
                </div>
                <div class="threat-intel-item">
                    <div class="threat-intel-label">Known Threat</div>
                    <div class="threat-intel-value">${threatIntel.is_known_threat ? '<span style="color:${TC.danger};">Yes</span>' : '<span style="color:${TC.teal};">No</span>'}</div>
                </div>
            </div>
        </div>
    `;

    // Behavioral Analysis section
    const behaviorSection = `
        <div class="detail-section">
            <div class="detail-section-title">📊 Behavioral Analysis</div>
            <div class="behavioral-grid">
                <div class="behavioral-item">
                    <span class="behavioral-label">Failed Attempts</span>
                    <span class="behavioral-value" style="color: ${TC.danger};">${behavioral.failed_attempts || 0}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Unique Usernames</span>
                    <span class="behavioral-value">${behavioral.unique_usernames || 0}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Success Rate</span>
                    <span class="behavioral-value">${behavioral.success_rate ? (behavioral.success_rate * 100).toFixed(1) + '%' : '0%'}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">First Seen</span>
                    <span class="behavioral-value">${behavioral.first_seen ? formatTimeAgo(behavioral.first_seen) : 'N/A'}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Last Seen</span>
                    <span class="behavioral-value">${behavioral.last_seen ? formatTimeAgo(behavioral.last_seen) : 'N/A'}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Attack Pattern</span>
                    <span class="behavioral-value">${behavioral.attack_pattern || 'N/A'}</span>
                </div>
            </div>
        </div>
    `;

    // ML Contribution section
    const mlScore = mlContribution.risk_score || 0;
    const mlConfidence = mlContribution.confidence || 0;
    const mlSection = `
        <div class="detail-section">
            <div class="detail-section-title">🤖 ML Contribution</div>
            <div class="ml-contribution-box">
                <div class="ml-score-circle ${getScoreClass(mlScore)}">
                    <span class="ml-score-value">${mlScore}</span>
                    <span class="ml-score-label">Risk Score</span>
                </div>
                <div class="ml-details">
                    <div class="ml-detail-row">
                        <span>Confidence:</span>
                        <span class="ml-confidence">${(mlConfidence * 100).toFixed(0)}%</span>
                    </div>
                    <div class="ml-detail-row">
                        <span>Model Decision:</span>
                        <span>${mlContribution.decision || 'N/A'}</span>
                    </div>
                    <div class="ml-detail-row">
                        <span>ML Contribution:</span>
                        <span style="font-weight: 600; color: var(--azure-blue);">${mlContribution.contribution_percentage || 0}%</span>
                    </div>
                </div>
            </div>
            ${mlContribution.factors && mlContribution.factors.length > 0 ? `
                <div class="ml-factors">
                    <div class="ml-factors-title">Key Risk Factors:</div>
                    ${mlContribution.factors.map(f => `
                        <div class="ml-factor-item">
                            <span class="ml-factor-name">${escapeHtml(f.name || f)}</span>
                            ${f.weight ? `<span class="ml-factor-weight">${(f.weight * 100).toFixed(0)}%</span>` : ''}
                        </div>
                    `).join('')}
                </div>
            ` : ''}
        </div>
    `;

    // Blocking Justification section
    const justificationSection = `
        <div class="detail-section">
            <div class="detail-section-title">⚖️ Blocking Justification</div>
            <div class="justification-box">
                <div class="justification-reason">
                    <strong>Reason:</strong> ${escapeHtml(block.reason || 'No reason specified')}
                </div>
                ${justification.summary ? `
                    <div class="justification-summary">${escapeHtml(justification.summary)}</div>
                ` : ''}
                ${justification.factors && justification.factors.length > 0 ? `
                    <div class="justification-factors">
                        <strong>Contributing Factors:</strong>
                        <ul>
                            ${justification.factors.map(f => {
                                if (typeof f === 'object') {
                                    return `<li><strong>${escapeHtml(f.title || f.name || '')}</strong>: ${escapeHtml(f.description || '')} ${f.severity ? `<span class="detail-badge ${f.severity}">${f.severity}</span>` : ''}</li>`;
                                }
                                return `<li>${escapeHtml(String(f))}</li>`;
                            }).join('')}
                        </ul>
                    </div>
                ` : ''}
                <div class="justification-meta">
                    <span>Blocked: ${block.blocked_at ? formatTimeAgo(block.blocked_at) : 'Unknown'}</span>
                    ${block.expires_at ? `<span>Expires: ${formatFutureTime(block.expires_at)}</span>` : '<span>Permanent</span>'}
                </div>
            </div>
        </div>
    `;

    // Blocking History section
    const historySection = block.blocking_history && block.blocking_history.length > 0 ? `
        <div class="detail-section">
            <div class="detail-section-title">📜 Block/Unblock History</div>
            <div class="blocking-history-list" style="max-height: 200px; overflow-y: auto;">
                ${block.blocking_history.map(h => {
                    const actionIcon = h.action_type === 'blocked' ? '🚫' : (h.action_type === 'unblocked' ? '✅' : '✏️');
                    const actionColor = h.action_type === 'blocked' ? TC.danger : (h.action_type === 'unblocked' ? TC.teal : TC.warning);
                    const sourceLabel = {
                        'system': 'System',
                        'manual': 'Manual',
                        'rule': 'Rule',
                        'api': 'API'
                    }[h.action_source] || h.action_source;
                    return `
                        <div class="history-item" style="display: flex; align-items: flex-start; gap: 12px; padding: 10px; border-bottom: 1px solid var(--border); font-size: 13px;">
                            <span style="font-size: 18px;">${actionIcon}</span>
                            <div style="flex: 1;">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <span style="font-weight: 600; color: ${actionColor}; text-transform: capitalize;">${h.action_type}</span>
                                    <span style="font-size: 11px; color: var(--text-secondary);">${h.created_at ? formatTimeAgo(h.created_at) : 'Unknown'}</span>
                                </div>
                                <div style="color: var(--text-secondary); font-size: 12px; margin-top: 4px;">
                                    ${h.reason ? `<span>${escapeHtml(h.reason)}</span>` : ''}
                                </div>
                                <div style="display: flex; gap: 8px; margin-top: 4px; font-size: 11px;">
                                    <span style="background: var(--surface); padding: 2px 6px; border-radius: 3px;">${sourceLabel}</span>
                                    ${h.performed_by ? `<span>by ${escapeHtml(h.performed_by)}</span>` : ''}
                                    ${h.rule_name ? `<span style="color: var(--azure-blue);">Rule: ${escapeHtml(h.rule_name)}</span>` : ''}
                                </div>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        </div>
    ` : '';

    const content = `
        <div class="block-detail-body">
            <!-- Header -->
            <div class="detail-header-section">
                <div class="detail-ip-display">
                    <span class="detail-ip-address">${escapeHtml(ipAddress)}</span>
                    ${statusBadge}
                    ${sourceBadge}
                </div>
                <div class="detail-meta-row">
                    <span>Agent: ${escapeHtml(block.agent_name || 'Global')}</span>
                    <span>Block ID: #${block.id}</span>
                </div>
            </div>

            ${geoSection}
            ${threatSection}
            ${behaviorSection}
            ${mlSection}
            ${justificationSection}
            ${historySection}
        </div>
    `;

    showFWDetailModal(`Block Investigation: ${ipAddress}`, content, { width: '700px' });
}

function getScoreClass(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'moderate';
    return 'low';
}

function showFWDetailModal(title, content, options = {}) {
    // Inject styles if needed
    injectFWDetailModalStyles();

    // Remove existing modals
    document.querySelectorAll('.fw-detail-modal-overlay').forEach(el => el.remove());

    const overlay = document.createElement('div');
    overlay.className = 'fw-detail-modal-overlay';

    const width = options.width || '600px';

    overlay.innerHTML = `
        <div class="fw-detail-modal" style="max-width: ${width};">
            <div class="fw-detail-modal-header">
                <h3>${escapeHtml(title)}</h3>
                <button class="fw-detail-modal-close" onclick="closeFWDetailModal()">&times;</button>
            </div>
            <div class="fw-detail-modal-body">${content}</div>
            <div class="fw-detail-modal-footer">
                <button class="fw-modal-btn primary" onclick="closeFWDetailModal()">Close</button>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';

    // Close on backdrop click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) closeFWDetailModal();
    });

    // Close on Escape
    const escHandler = (e) => {
        if (e.key === 'Escape') {
            closeFWDetailModal();
            document.removeEventListener('keydown', escHandler);
        }
    };
    document.addEventListener('keydown', escHandler);
}

function closeFWDetailModal() {
    const overlay = document.querySelector('.fw-detail-modal-overlay');
    if (overlay) {
        overlay.style.animation = 'fwModalFadeOut 0.15s ease';
        setTimeout(() => {
            overlay.remove();
            document.body.style.overflow = '';
        }, 140);
    }
}

function injectFWDetailModalStyles() {
    if (document.getElementById('fw-detail-modal-styles')) return;

    const style = document.createElement('style');
    style.id = 'fw-detail-modal-styles';
    style.textContent = `
        .fw-detail-modal-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(0, 0, 0, 0.6);
            backdrop-filter: blur(4px);
            display: flex;
            align-items: flex-start;
            justify-content: center;
            z-index: 10000;
            padding: 60px 20px 20px;
            overflow-y: auto;
            animation: fwModalFadeIn 0.2s ease;
        }

        @keyframes fwModalFadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes fwModalFadeOut {
            from { opacity: 1; }
            to { opacity: 0; }
        }

        .fw-detail-modal {
            background: var(--card-bg, #fff);
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            animation: fwModalSlideIn 0.25s ease;
        }

        @keyframes fwModalSlideIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .fw-detail-modal-header {
            padding: 20px 24px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--surface);
            border-radius: 12px 12px 0 0;
        }

        .fw-detail-modal-header h3 {
            margin: 0;
            font-size: 17px;
            font-weight: 600;
        }

        .fw-detail-modal-close {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: var(--text-secondary);
            padding: 0;
            width: 36px;
            height: 36px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 6px;
        }

        .fw-detail-modal-close:hover {
            background: var(--hover-bg);
        }

        .fw-detail-modal-body {
            padding: 24px;
            max-height: 70vh;
            overflow-y: auto;
        }

        .fw-detail-modal-footer {
            padding: 16px 24px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            background: var(--surface);
            border-radius: 0 0 12px 12px;
        }

        .fw-modal-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }

        .fw-modal-btn.primary {
            background: var(--azure-blue);
            color: white;
        }

        .fw-modal-btn.primary:hover {
            background: var(--azure-hover, #106EBE);
        }

        /* Detail sections */
        .block-detail-body { display: flex; flex-direction: column; gap: 20px; }

        .detail-header-section {
            background: var(--surface);
            padding: 20px;
            border-radius: 8px;
        }

        .detail-ip-display {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .detail-ip-address {
            font-family: 'SF Mono', monospace;
            font-size: 24px;
            font-weight: 700;
        }

        .detail-meta-row {
            margin-top: 8px;
            display: flex;
            gap: 16px;
            font-size: 13px;
            color: var(--text-secondary);
        }

        .detail-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .detail-badge.critical { background: var(--color-danger, #D13438); color: white; }
        .detail-badge.high { background: var(--color-orange, #FF8C00); color: white; }
        .detail-badge.moderate { background: var(--color-warning, #FFB900); color: var(--text-primary, #323130); }
        .detail-badge.success { background: var(--color-success-dark, #107C10); color: white; }
        .detail-badge.info { background: var(--azure-blue, #0078D4); color: white; }
        .detail-badge.purple { background: var(--color-purple, #8764B8); color: white; }
        .detail-badge.warning { background: var(--color-orange, #CA5010); color: white; }
        .detail-badge.low { background: var(--text-secondary, #605E5C); color: white; }

        .detail-section {
            background: var(--surface);
            padding: 16px;
            border-radius: 8px;
        }

        .detail-section-title {
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 12px;
            color: var(--text-primary);
        }

        .detail-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px;
            font-size: 13px;
        }

        .detail-label {
            color: var(--text-secondary);
        }

        /* Threat Intel */
        .threat-intel-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
        }

        .threat-intel-item {
            text-align: center;
        }

        .threat-intel-label {
            font-size: 11px;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }

        .threat-intel-value {
            font-size: 24px;
            font-weight: 700;
        }

        .threat-intel-value.critical { color: ${TC.danger}; }
        .threat-intel-value.high { color: ${TC.orange}; }
        .threat-intel-value.moderate { color: ${TC.warning}; }
        .threat-intel-value.low { color: ${TC.teal}; }

        .threat-intel-bar {
            height: 4px;
            background: var(--border);
            border-radius: 2px;
            margin-top: 6px;
        }

        .threat-intel-bar-fill {
            height: 100%;
            border-radius: 2px;
        }

        .threat-intel-bar-fill.critical { background: ${TC.danger}; }
        .threat-intel-bar-fill.high { background: ${TC.orange}; }
        .threat-intel-bar-fill.moderate { background: ${TC.warning}; }
        .threat-intel-bar-fill.low { background: ${TC.teal}; }

        /* Behavioral */
        .behavioral-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
        }

        .behavioral-item {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }

        .behavioral-label {
            font-size: 11px;
            color: var(--text-secondary);
        }

        .behavioral-value {
            font-size: 14px;
            font-weight: 600;
        }

        /* ML Contribution */
        .ml-contribution-box {
            display: flex;
            gap: 24px;
            align-items: center;
        }

        .ml-score-circle {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }

        .ml-score-circle.critical { background: ${TC.dangerBg}; border: 3px solid ${TC.danger}; }
        .ml-score-circle.high { background: ${TC.warningBg}; border: 3px solid ${TC.orange}; }
        .ml-score-circle.moderate { background: ${TC.warningBg}; border: 3px solid ${TC.warning}; }
        .ml-score-circle.low { background: ${TC.successBg}; border: 3px solid ${TC.teal}; }

        .ml-score-value {
            font-size: 24px;
            font-weight: 700;
        }

        .ml-score-label {
            font-size: 9px;
            text-transform: uppercase;
            color: var(--text-secondary);
        }

        .ml-details {
            flex: 1;
        }

        .ml-detail-row {
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            padding: 4px 0;
            border-bottom: 1px solid var(--border);
        }

        .ml-confidence {
            font-weight: 600;
        }

        .ml-factors {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border);
        }

        .ml-factors-title {
            font-size: 12px;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .ml-factor-item {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            padding: 4px 0;
        }

        .ml-factor-weight {
            color: var(--azure-blue);
            font-weight: 600;
        }

        /* Justification */
        .justification-box {
            font-size: 13px;
        }

        .justification-reason {
            margin-bottom: 12px;
        }

        .justification-summary {
            padding: 12px;
            background: var(--background);
            border-radius: 6px;
            margin-bottom: 12px;
            line-height: 1.5;
        }

        .justification-factors ul {
            margin: 8px 0 0 20px;
            padding: 0;
        }

        .justification-factors li {
            margin: 4px 0;
        }

        .justification-meta {
            display: flex;
            gap: 16px;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 12px;
        }

        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border);
            border-top-color: var(--azure-blue);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @media (max-width: 600px) {
            .threat-intel-grid,
            .behavioral-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .ml-contribution-box {
                flex-direction: column;
            }
        }
    `;
    document.head.appendChild(style);
}


// Export functions globally
window.showBlockedIPDetailModal = showBlockedIPDetailModal;
window.showFWDetailModal = showFWDetailModal;
window.closeFWDetailModal = closeFWDetailModal;
window.injectFWDetailModalStyles = injectFWDetailModalStyles;
