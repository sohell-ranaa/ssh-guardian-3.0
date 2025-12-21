/**
 * SSH Guardian v3.0 - Firewall Inline Block Detail
 * Real block detail modal with threat intel and ML predictions
 */
(function() {
    'use strict';

    // Show detail modal for real blocks (from UFW/fail2ban)
    async function showRealBlockDetail(ipAddress, source, agentId, ruleIndex) {
        const sourceLabel = source === 'ufw' ? 'UFW DENY Rule' : source === 'fail2ban' ? 'Fail2ban Ban' : 'Block';
        const sourceIcon = source === 'ufw' ? '🛡️' : '🔒';
        const sourceBadgeColor = source === 'ufw' ? TC.successDark : TC.primary;

        // Find the block data
        const allBlockedIPs = window.getAllBlockedIPs ? window.getAllBlockedIPs() : [];
        const block = allBlockedIPs.find(b => b.ip_address === ipAddress && b.source === source);
        if (!block) {
            showNotification('error', 'Block details not found');
            return;
        }

        // Show loading state
        showFWDetailModal(`Block Investigation: ${ipAddress}`, `
            <div style="text-align: center; padding: 40px;">
                <div class="loading-spinner"></div>
                <p style="margin-top: 16px; color: var(--text-secondary);">Loading block details for ${escapeHtml(ipAddress)}...</p>
            </div>
        `, { width: '700px' });

        // Helper function for fetch with timeout
        const fetchWithTimeout = async (url, timeoutMs = 8000) => {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
            try {
                const response = await fetch(url, { signal: controller.signal });
                clearTimeout(timeoutId);
                return response;
            } catch (e) {
                clearTimeout(timeoutId);
                throw e;
            }
        };

        // Fetch all data in parallel with timeouts
        let threatData = {};
        let relatedEvents = [];
        let mlPredictions = [];

        const fetchPromises = [
            // Threat intelligence (longer timeout as it may fetch from external APIs)
            fetchWithTimeout(`/api/threat-intel/lookup/${encodeURIComponent(ipAddress)}`, 10000)
                .then(r => r.ok ? r.json() : null)
                .then(data => { if (data?.success && data?.data) threatData = data.data; })
                .catch(e => console.log('Threat intel fetch skipped:', e.name)),

            // Related SSH events
            fetchWithTimeout(`/api/events/list?ip_filter=${encodeURIComponent(ipAddress)}&limit=5`, 5000)
                .then(r => r.ok ? r.json() : null)
                .then(data => { if (data?.success) relatedEvents = data.events || []; })
                .catch(e => console.log('Events fetch skipped:', e.name)),

            // ML predictions
            fetchWithTimeout(`/api/ml/predictions?ip_filter=${encodeURIComponent(ipAddress)}&limit=5`, 5000)
                .then(r => r.ok ? r.json() : null)
                .then(data => { if (data?.success) mlPredictions = data.predictions || []; })
                .catch(e => console.log('ML predictions fetch skipped:', e.name))
        ];

        // Wait for all fetches (with timeout protection)
        await Promise.allSettled(fetchPromises);

        // Format blocked_at using TimeSettings or browser fallback
        let blockedAt = 'Unknown';
        if (block.blocked_at) {
            if (window.TimeSettings?.isLoaded()) {
                blockedAt = window.TimeSettings.formatFull(block.blocked_at);
            } else {
                let ts = String(block.blocked_at).replace(' ', 'T');
                if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
                blockedAt = new Date(ts).toLocaleString();
            }
        }
        const blockedAgo = block.blocked_at ? formatTimeAgo(block.blocked_at) : '';

        // Build modal content
        const content = buildBlockDetailContent(block, ipAddress, source, sourceLabel, sourceIcon, sourceBadgeColor, blockedAt, blockedAgo, threatData, relatedEvents, mlPredictions, ruleIndex);

        showFWDetailModal(`Block Investigation: ${ipAddress}`, content, { width: '700px' });
    }

    function buildBlockDetailContent(block, ipAddress, source, sourceLabel, sourceIcon, sourceBadgeColor, blockedAt, blockedAgo, threatData, relatedEvents, mlPredictions, ruleIndex) {
        // Status badge
        const statusBadge = `<span class="detail-badge high" style="background: rgba(209, 52, 56, 0.15); color: ${TC.danger};">🚫 Blocked</span>`;

        // Source badge
        const sourceBadge = `<span class="detail-badge" style="background: rgba(${source === 'ufw' ? '16, 124, 16' : '0, 120, 212'}, 0.15); color: ${sourceBadgeColor};">${sourceIcon} ${sourceLabel}</span>`;

        // Header section
        const headerSection = `
            <div class="detail-header-section">
                <div class="detail-ip-display">
                    <span class="detail-ip-address">${escapeHtml(ipAddress)}</span>
                    ${statusBadge}
                    ${sourceBadge}
                </div>
                <div class="detail-meta-row">
                    <span>📍 Server: ${escapeHtml(block.agent_name || 'Unknown')}</span>
                    <span>⏱️ Blocked ${blockedAgo}</span>
                </div>
            </div>
        `;

        // Block Details section
        const blockDetailsSection = buildBlockDetailsSection(block, source, sourceLabel, sourceIcon, blockedAt, ruleIndex);

        // Threat Intelligence section
        const threatSection = buildThreatSection(ipAddress, threatData);

        // ML Decision & Analysis section
        const mlSection = buildMLSection(mlPredictions);

        // Related Events section
        const eventsSection = buildEventsSection(relatedEvents);

        // Summary section
        const summarySection = `
            <div class="detail-section">
                <div class="detail-section-title">📝 Block Summary</div>
                <div class="justification-box">
                    <div class="justification-reason">
                        <strong>Status:</strong> This IP is currently blocked via ${sourceLabel} on server "${block.agent_name || 'Unknown'}".
                        ${source === 'fail2ban' ? `The IP was banned after ${block.failures || 0} failed authentication attempts.` : ''}
                        ${source === 'ufw' ? `A UFW DENY rule is active for this IP address.` : ''}
                    </div>
                </div>
            </div>
        `;

        return `
            <div class="block-detail-body">
                ${headerSection}
                ${blockDetailsSection}
                ${threatSection}
                ${mlSection}
                ${eventsSection}
                ${summarySection}
            </div>
        `;
    }

    function buildBlockDetailsSection(block, source, sourceLabel, sourceIcon, blockedAt, ruleIndex) {
        let blockDetailsContent = `
            <div class="behavioral-grid">
                <div class="behavioral-item">
                    <span class="behavioral-label">Block Source</span>
                    <span class="behavioral-value">${escapeHtml(block.block_type || sourceLabel)}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Server</span>
                    <span class="behavioral-value">${escapeHtml(block.agent_name || 'Unknown')}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Blocked At</span>
                    <span class="behavioral-value">${blockedAt}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Reason</span>
                    <span class="behavioral-value">${escapeHtml(block.reason || 'N/A')}</span>
                </div>
        `;

        if (source === 'ufw' && ruleIndex) {
            blockDetailsContent += `
                <div class="behavioral-item">
                    <span class="behavioral-label">UFW Rule #</span>
                    <span class="behavioral-value">${ruleIndex}</span>
                </div>
            `;
        }

        if (source === 'fail2ban') {
            blockDetailsContent += `
                <div class="behavioral-item">
                    <span class="behavioral-label">Jail</span>
                    <span class="behavioral-value">${escapeHtml(block.jail_name || 'sshd')}</span>
                </div>
                <div class="behavioral-item">
                    <span class="behavioral-label">Failures</span>
                    <span class="behavioral-value" style="color: ${TC.danger}; font-weight: 600;">${block.failures || 0}</span>
                </div>
            `;
        }

        blockDetailsContent += `</div>`;

        return `
            <div class="detail-section">
                <div class="detail-section-title">${sourceIcon} Block Details</div>
                ${blockDetailsContent}
            </div>
        `;
    }

    function buildThreatSection(ipAddress, threatData) {
        // Check if IP is private/local (not applicable for threat intel)
        const isPrivateIP = (ip) => {
            const parts = ip.split('.');
            if (parts.length !== 4) return false;
            const first = parseInt(parts[0]);
            const second = parseInt(parts[1]);
            return first === 10 || first === 127 ||
                   (first === 172 && second >= 16 && second <= 31) ||
                   (first === 192 && second === 168);
        };

        const hasData = threatData && (threatData.abuseipdb_score !== undefined || threatData.virustotal_positives !== undefined || threatData.overall_threat_level);

        if (isPrivateIP(ipAddress)) {
            return `
                <div class="detail-section">
                    <div class="detail-section-title">🔍 Threat Intelligence</div>
                    <div style="padding: 16px; text-align: center; color: var(--text-secondary); background: var(--background); border-radius: 6px;">
                        <span style="color: ${TC.textSecondary};">Not applicable for private/local IP address</span>
                    </div>
                </div>
            `;
        }

        if (hasData) {
            const abuseScore = parseInt(threatData.abuseipdb_score) || 0;
            const abuseReports = parseInt(threatData.abuseipdb_reports) || 0;
            const vtPositives = parseInt(threatData.virustotal_positives) || 0;
            const vtTotal = parseInt(threatData.virustotal_total) || 0;
            const threatLevel = threatData.overall_threat_level || 'unknown';
            const threatConfidence = parseFloat(threatData.threat_confidence || 0) * 100;

            const isClean = abuseScore === 0 && vtPositives === 0 && (threatLevel === 'clean' || threatLevel === 'low');

            if (isClean) {
                return `
                    <div class="detail-section">
                        <div class="detail-section-title">🔍 Threat Intelligence</div>
                        <div style="padding: 16px; text-align: center; background: rgba(16, 124, 16, 0.08); border-radius: 6px; border: 1px solid rgba(16, 124, 16, 0.2);">
                            <span style="color: ${TC.successDark}; font-weight: 600;">✅ No threats detected</span>
                            <div style="margin-top: 8px; font-size: 12px; color: var(--text-secondary);">
                                AbuseIPDB: 0/100 | VirusTotal: 0 detections
                            </div>
                        </div>
                    </div>
                `;
            }

            const scoreColor = abuseScore > 50 ? TC.danger : abuseScore > 20 ? TC.warningDark : TC.successDark;
            const levelColor = threatLevel === 'high' || threatLevel === 'critical' ? TC.danger : threatLevel === 'medium' ? TC.warningDark : TC.successDark;

            return `
                <div class="detail-section">
                    <div class="detail-section-title">🔍 Threat Intelligence</div>
                    <div class="behavioral-grid">
                        <div class="behavioral-item">
                            <span class="behavioral-label">AbuseIPDB Score</span>
                            <span class="behavioral-value" style="color: ${scoreColor}; font-weight: 700;">${abuseScore}/100</span>
                        </div>
                        <div class="behavioral-item">
                            <span class="behavioral-label">AbuseIPDB Reports</span>
                            <span class="behavioral-value">${abuseReports}</span>
                        </div>
                        <div class="behavioral-item">
                            <span class="behavioral-label">VirusTotal</span>
                            <span class="behavioral-value" style="${vtPositives > 0 ? 'color: ' + TC.danger + ';' : ''}">${vtPositives}/${vtTotal} detections</span>
                        </div>
                        <div class="behavioral-item">
                            <span class="behavioral-label">Threat Level</span>
                            <span class="behavioral-value" style="color: ${levelColor}; text-transform: uppercase; font-weight: 600;">${threatLevel}</span>
                        </div>
                        <div class="behavioral-item">
                            <span class="behavioral-label">Confidence</span>
                            <span class="behavioral-value">${threatConfidence.toFixed(0)}%</span>
                        </div>
                        ${threatData.abuseipdb_checked_at ? `
                        <div class="behavioral-item">
                            <span class="behavioral-label">Last Checked</span>
                            <span class="behavioral-value">${formatTimeAgo(threatData.abuseipdb_checked_at)}</span>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        }

        return `
            <div class="detail-section">
                <div class="detail-section-title">🔍 Threat Intelligence</div>
                <div style="padding: 16px; text-align: center; color: var(--text-secondary); background: var(--background); border-radius: 6px;">
                    No threat data available for this IP
                </div>
            </div>
        `;
    }

    function buildMLSection(mlPredictions) {
        if (mlPredictions.length > 0) {
            const avgRiskScore = mlPredictions.reduce((sum, p) => sum + (parseInt(p.risk_score) || 0), 0) / mlPredictions.length;
            const anomalyCount = mlPredictions.filter(p => p.is_anomaly).length;
            const highRiskCount = mlPredictions.filter(p => parseInt(p.risk_score) >= 70).length;

            const riskScoreColor = avgRiskScore >= 70 ? TC.danger : avgRiskScore >= 40 ? TC.warningDark : TC.successDark;
            const riskLevel = avgRiskScore >= 70 ? 'HIGH RISK' : avgRiskScore >= 40 ? 'MEDIUM RISK' : 'LOW RISK';

            const predictionsList = mlPredictions.slice(0, 3).map(pred => {
                const predTime = pred.created_at ? formatTimeAgo(pred.created_at) : 'Unknown';
                const riskScore = parseInt(pred.risk_score) || 0;
                const confidence = parseFloat(pred.confidence || 0) * 100;
                const threatType = pred.threat_type || 'normal';
                const isAnomaly = pred.is_anomaly;
                const wasBlocked = pred.was_blocked;

                const riskColor = riskScore >= 70 ? TC.danger : riskScore >= 40 ? TC.warningDark : TC.successDark;
                const typeIcon = isAnomaly ? '⚠️' : threatType === 'normal' ? '✅' : '🔴';

                return `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px 12px; background: var(--background); border-radius: 4px; margin-bottom: 6px; border-left: 3px solid ${riskColor};">
                        <div style="display: flex; flex-direction: column; gap: 2px;">
                            <span style="font-weight: 600;">${typeIcon} Risk Score: <span style="color: ${riskColor};">${riskScore}</span></span>
                            <span style="font-size: 11px; color: var(--text-secondary);">Type: ${escapeHtml(threatType)} | Confidence: ${confidence.toFixed(0)}%${wasBlocked ? ' | Blocked' : ''}</span>
                        </div>
                        <span style="color: var(--text-secondary); font-size: 11px;">${predTime}</span>
                    </div>
                `;
            }).join('');

            return `
                <div class="detail-section">
                    <div class="detail-section-title">🤖 ML Decision & Analysis</div>
                    <div class="behavioral-grid" style="margin-bottom: 12px;">
                        <div class="behavioral-item">
                            <span class="behavioral-label">Average Risk Score</span>
                            <span class="behavioral-value" style="color: ${riskScoreColor}; font-weight: 700;">${avgRiskScore.toFixed(0)}/100</span>
                        </div>
                        <div class="behavioral-item">
                            <span class="behavioral-label">Risk Level</span>
                            <span class="behavioral-value" style="color: ${riskScoreColor}; font-weight: 600;">${riskLevel}</span>
                        </div>
                        <div class="behavioral-item">
                            <span class="behavioral-label">Anomalies Detected</span>
                            <span class="behavioral-value" style="${anomalyCount > 0 ? 'color: ' + TC.danger + ';' : ''}">${anomalyCount} of ${mlPredictions.length}</span>
                        </div>
                        <div class="behavioral-item">
                            <span class="behavioral-label">High Risk Events</span>
                            <span class="behavioral-value" style="${highRiskCount > 0 ? 'color: ' + TC.danger + ';' : ''}">${highRiskCount}</span>
                        </div>
                    </div>
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">Recent Predictions:</div>
                    ${predictionsList}
                </div>
            `;
        }

        return `
            <div class="detail-section">
                <div class="detail-section-title">🤖 ML Decision & Analysis</div>
                <div style="padding: 16px; text-align: center; color: var(--text-secondary); background: var(--background); border-radius: 6px;">
                    No ML predictions available for this IP
                </div>
            </div>
        `;
    }

    function buildEventsSection(relatedEvents) {
        if (relatedEvents.length > 0) {
            const eventsList = relatedEvents.map(evt => {
                const eventTime = evt.timestamp ? formatTimeAgo(evt.timestamp) : 'Unknown';
                const eventType = evt.event_type || 'ssh_event';
                const typeIcon = eventType.includes('fail') ? '❌' : eventType.includes('success') ? '✅' : '📝';
                return `
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: var(--background); border-radius: 4px; margin-bottom: 6px;">
                        <span>${typeIcon} ${escapeHtml(evt.username || 'unknown')}@${escapeHtml(evt.server || 'server')}</span>
                        <span style="color: var(--text-secondary); font-size: 12px;">${eventTime}</span>
                    </div>
                `;
            }).join('');

            return `
                <div class="detail-section">
                    <div class="detail-section-title">📋 Recent SSH Events from this IP</div>
                    ${eventsList}
                </div>
            `;
        }

        return `
            <div class="detail-section">
                <div class="detail-section-title">📋 Recent SSH Events</div>
                <div style="padding: 16px; text-align: center; color: var(--text-secondary); background: var(--background); border-radius: 6px;">
                    No recent SSH events found for this IP
                </div>
            </div>
        `;
    }

    // Global export
    window.showRealBlockDetail = showRealBlockDetail;
})();
