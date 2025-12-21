/**
 * SSH Guardian v3.0 - Firewall Inline Tabs
 * Tab switching functionality
 */
(function() {
    'use strict';

    function switchFirewallTab(tabName) {
        // Hide all tab contents and remove active class
        document.querySelectorAll('.fw-tab-content').forEach(tab => tab.style.display = 'none');
        document.querySelectorAll('.fw-tab').forEach(tab => tab.classList.remove('active'));

        // Show selected tab content
        const tabContent = document.getElementById('tab-' + tabName);
        if (tabContent) tabContent.style.display = 'block';

        // Add active class to selected tab
        const tabButton = document.querySelector(`.fw-tab[data-tab="${tabName}"]`);
        if (tabButton) tabButton.classList.add('active');

        // Load data for specific tabs
        if (tabName === 'fail2ban') {
            (window.loadFail2banBans || loadFail2banBans)?.();
        } else if (tabName === 'blocked') {
            loadBlockedIPs?.();
        } else if (tabName === 'rules') {
            loadBlockingRules?.();
        } else if (tabName === 'logins') {
            (window.loadSuccessfulLoginsFirewall || loadSuccessfulLoginsFirewall)?.();
        } else if (tabName === 'ufw' && window.currentAgentId) {
            (window.loadUFWData || loadUFWData)?.(window.currentAgentId);
        }
    }

    // Global export
    window.switchFirewallTab = switchFirewallTab;
})();
/**
 * SSH Guardian v3.0 - Firewall Inline Activity Panel
 * Recent Activity Slide Panel functionality
 */
(function() {
    'use strict';

    function toggleRecentActivityPanel(event) {
        if (event) {
            event.stopPropagation();
        }
        const panel = document.getElementById('recentActivityPanel');
        const backdrop = document.getElementById('recentActivityBackdrop');

        if (panel.classList.contains('open')) {
            closeRecentActivityPanel();
        } else {
            panel.classList.add('open');
            backdrop.classList.add('open');
            // Use window.currentAgentId from the module's global variable
            if (window.currentAgentId) {
                loadRecentLogs(window.currentAgentId);
            }
        }
    }

    function closeRecentActivityPanel() {
        const panel = document.getElementById('recentActivityPanel');
        const backdrop = document.getElementById('recentActivityBackdrop');
        if (panel) panel.classList.remove('open');
        if (backdrop) backdrop.classList.remove('open');
    }

    // filterRecentLogs - reload logs when filter changes
    function filterRecentLogs() {
        if (window.currentAgentId) {
            loadRecentLogs(window.currentAgentId);
        }
    }

    // Global exports
    window.toggleRecentActivityPanel = toggleRecentActivityPanel;
    window.closeRecentActivityPanel = closeRecentActivityPanel;
    window.filterRecentLogs = filterRecentLogs;
})();
/**
 * SSH Guardian v3.0 - Firewall Inline Blocked IPs
 * Blocked IPs tab functionality
 */
(function() {
    'use strict';

    let allBlockedIPs = [];

    // Reconcile ip_blocks with real UFW/fail2ban status before loading
    async function reconcileBlockedIPs() {
        console.log('[BlockedIPs] Starting reconciliation with UFW/fail2ban...');
        try {
            const agentId = window.currentAgentId || null;
            const response = await fetch('/api/dashboard/blocking/reconcile', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ agent_id: agentId })
            });
            const data = await response.json();
            if (data.success && data.reconciled_count > 0) {
                console.log(`[BlockedIPs] Reconciled ${data.reconciled_count} IPs`);
                showNotification('info', `Synced: ${data.reconciled_count} IPs updated from UFW/fail2ban`);
            }
            return data;
        } catch (err) {
            console.error('[BlockedIPs] Reconciliation error:', err);
            return { success: false, error: err.message };
        }
    }

    async function loadBlockedIPs() {
        const loading = document.getElementById('blockedIPsLoading');
        const container = document.getElementById('blockedIPsContainer');
        const list = document.getElementById('blockedIPsList');
        const noBlocked = document.getElementById('noBlockedIPs');

        if (!loading || !container || !list || !noBlocked) return;

        loading.style.display = 'block';
        container.style.display = 'none';
        noBlocked.style.display = 'none';

        let apiUrl = '/api/dashboard/blocking/real-blocks?limit=200';
        if (window.currentAgentId) apiUrl += `&agent_id=${encodeURIComponent(window.currentAgentId)}`;

        const searchInput = document.getElementById('blockedIPSearch');
        if (searchInput?.value.trim()) apiUrl += `&search=${encodeURIComponent(searchInput.value.trim())}`;

        fetch(apiUrl)
            .then(r => r.json())
            .then(data => {
                loading.style.display = 'none';
                if (data.success && data.blocks?.length > 0) {
                    allBlockedIPs = data.blocks.map(b => ({
                        id: b.id, ip_address: b.ip_address, source: b.source,
                        block_type: b.block_type, reason: b.reason, blocked_at: b.blocked_at,
                        agent_name: b.agent_name || 'Unknown', agent_id: b.agent_id,
                        rule_index: b.rule_index, jail_name: b.jail_name, failures: b.failures
                    }));
                    updateBlockedIPsStats(data);
                    renderBlockedIPs(allBlockedIPs);
                    container.style.display = 'block';
                } else {
                    noBlocked.style.display = 'block';
                    updateBlockedIPsStats({ ufw_count: 0, fail2ban_count: 0, total: 0 });
                }
            })
            .catch(err => {
                loading.style.display = 'none';
                noBlocked.style.display = 'block';
                console.error('Error loading blocked IPs:', err);
            });
    }

    function searchBlockedIPs() {
        loadBlockedIPs();
    }

    function updateBlockedIPsStats(data) {
        const total = data.total || 0;
        const ufw = data.ufw_count || 0;
        const fail2ban = data.fail2ban_count || 0;

        const totalEl = document.getElementById('blockedStatTotal');
        const f2bEl = document.getElementById('blockedStatFail2ban');
        const ufwEl = document.getElementById('blockedStatUFW');
        const mlEl = document.getElementById('blockedStatML');

        if (totalEl) totalEl.textContent = total;
        if (f2bEl) f2bEl.textContent = fail2ban;
        if (ufwEl) ufwEl.textContent = ufw;
        if (mlEl) mlEl.textContent = '-';  // ML not applicable for real blocks
    }

    function renderBlockedIPs(blocks) {
        const list = document.getElementById('blockedIPsList');
        const noBlocked = document.getElementById('noBlockedIPs');
        const container = document.getElementById('blockedIPsContainer');

        if (!list) {
            console.error('blockedIPsList element not found');
            return;
        }

        if (blocks.length === 0) {
            list.innerHTML = '';
            if (noBlocked) noBlocked.style.display = 'block';
            if (container) container.style.display = 'none';
            return;
        }

        if (noBlocked) noBlocked.style.display = 'none';
        if (container) container.style.display = 'block';

        try {
            // Add table header
            const headerHtml = `
                <div class="blocked-ip-header">
                    <div class="blocked-col-ip">IP Address</div>
                    <div class="blocked-col-source">Source</div>
                    <div class="blocked-col-server">Server</div>
                    <div class="blocked-col-reason">Reason</div>
                    <div class="blocked-col-time">Blocked</div>
                </div>
            `;

            const rowsHtml = blocks.map(b => {
                const source = b.source || 'unknown';
                const sourceLabel = b.block_type || (source === 'ufw' ? 'UFW' : source === 'fail2ban' ? 'Fail2ban' : source);

                const blockedAt = b.blocked_at ? formatTimeAgo(b.blocked_at) : 'Unknown';
                const reason = b.reason || 'No reason specified';
                const serverName = b.agent_name || 'Unknown';
                const ipAddress = b.ip_address || 'Unknown IP';

                // Source icon based on type
                const sourceIcon = source === 'ufw' ? '🛡️' : source === 'fail2ban' ? '🔒' : '🚫';

                // Truncate reason for display (longer now)
                const truncatedReason = reason.length > 50 ? reason.substring(0, 50) + '...' : reason;

                return `
                    <div class="blocked-ip-row"
                         onclick="showRealBlockDetail('${escapeHtml(ipAddress)}', '${source}', ${b.agent_id || 'null'}, ${b.rule_index || 'null'})">
                        <div class="blocked-col-ip">
                            <span class="blocked-ip-icon ${escapeHtml(source)}">${sourceIcon}</span>
                            <span class="blocked-ip-address">${escapeHtml(ipAddress)}</span>
                        </div>
                        <div class="blocked-col-source">
                            <span class="blocked-source-badge ${escapeHtml(source)}">${escapeHtml(sourceLabel)}</span>
                        </div>
                        <div class="blocked-col-server">
                            <span class="blocked-server-name">${escapeHtml(serverName)}</span>
                        </div>
                        <div class="blocked-col-reason" title="${escapeHtml(reason)}">
                            <span class="blocked-reason-text">${escapeHtml(truncatedReason)}</span>
                        </div>
                        <div class="blocked-col-time">
                            <span class="blocked-time-text">${blockedAt}</span>
                        </div>
                    </div>
                `;
            }).join('');

            list.innerHTML = headerHtml + rowsHtml;
        } catch (err) {
            console.error('Error rendering blocked IPs:', err);
            list.innerHTML = '<div class="blocked-ip-error">Error rendering blocked IPs. Check console.</div>';
        }
    }

    function filterBlockedIPs() {
        const filter = document.getElementById('blockedSourceFilter').value;

        if (filter === 'all') {
            renderBlockedIPs(allBlockedIPs);
        } else {
            const filtered = allBlockedIPs.filter(b => b.source === filter);
            renderBlockedIPs(filtered);
        }
    }

    function unblockIP(ip, blockId) {
        if (!confirm(`Unblock IP address ${ip}?`)) return;

        fetch('/api/dashboard/blocking/blocks/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ip, reason: 'Manual unblock from dashboard' })
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) {
                showNotification('success', `Unblocked ${ip}`);
                loadBlockedIPs();
            } else {
                showNotification('error', data.error || 'Failed to unblock IP');
            }
        })
        .catch(err => {
            showNotification('error', 'Error unblocking IP');
            console.error(err);
        });
    }

    // Expose allBlockedIPs for other modules
    window.getAllBlockedIPs = function() { return allBlockedIPs; };

    // Global exports
    window.reconcileBlockedIPs = reconcileBlockedIPs;
    window.loadBlockedIPs = loadBlockedIPs;
    window.searchBlockedIPs = searchBlockedIPs;
    window.renderBlockedIPs = renderBlockedIPs;
    window.filterBlockedIPs = filterBlockedIPs;
    window.unblockIP = unblockIP;
})();
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
/**
 * SSH Guardian v3.0 - Firewall Inline Block Modal
 * Block IP modal functionality
 */
(function() {
    'use strict';

    function showBlockIPModal(prefillIp = '', prefillAgentId = '', prefillAgentName = '') {
        const modal = document.getElementById('blockIPModal');
        if (modal) modal.style.display = 'flex';

        // Reset and setup octet inputs
        setIPToOctets(prefillIp);
        setupIPOctetInputs();

        // Reset container border
        const container = document.getElementById('ipInputContainer');
        if (container) container.style.borderColor = 'var(--border)';

        // Update hidden field and validate if prefilled
        const ipInput = document.getElementById('quickBlockIP');
        if (prefillIp) {
            if (ipInput) ipInput.value = prefillIp;
            updateIPContainerState();
        } else {
            if (ipInput) ipInput.value = '';
        }

        const reasonInput = document.getElementById('quickBlockReason');
        const messageEl = document.getElementById('quickBlockMessage');
        if (reasonInput) reasonInput.value = '';
        if (messageEl) messageEl.style.display = 'none';

        // Focus first octet
        setTimeout(() => document.getElementById('ipOctet1')?.focus(), 100);

        // Set agent from context
        const agentIdInput = document.getElementById('quickBlockAgentId');
        const agentDisplay = document.getElementById('quickBlockAgentDisplay');

        // Priority: 1) Passed parameters, 2) Page selector, 3) window.currentAgentId
        if (prefillAgentId && prefillAgentName) {
            agentIdInput.value = prefillAgentId;
            agentDisplay.textContent = prefillAgentName;
        } else {
            // Try page's agent selector
            const pageAgentSelector = document.getElementById('firewallAgentSelector');
            if (pageAgentSelector && pageAgentSelector.value) {
                agentIdInput.value = pageAgentSelector.value;
                const selectedOption = pageAgentSelector.options[pageAgentSelector.selectedIndex];
                agentDisplay.textContent = selectedOption ? selectedOption.text : pageAgentSelector.value;
            } else if (window.currentAgentId) {
                // Use global currentAgentId
                agentIdInput.value = window.currentAgentId;
                // Try to get agent name from cached agents or fetch
                if (window.cachedAgents && window.cachedAgents.length > 0) {
                    const agent = window.cachedAgents.find(a => a.agent_id === window.currentAgentId || a.id == window.currentAgentId);
                    agentDisplay.textContent = agent ? (agent.display_name || agent.hostname || agent.agent_id) : window.currentAgentId;
                } else {
                    // Fetch agent info
                    fetch('/api/agents/list')
                        .then(r => r.json())
                        .then(data => {
                            if (data.success && data.agents) {
                                window.cachedAgents = data.agents;
                                const agent = data.agents.find(a => a.agent_id === window.currentAgentId || a.id == window.currentAgentId);
                                agentDisplay.textContent = agent ? (agent.display_name || agent.hostname || agent.agent_id) : window.currentAgentId;
                            }
                        })
                        .catch(() => {
                            agentDisplay.textContent = window.currentAgentId;
                        });
                    agentDisplay.textContent = 'Loading...';
                }
            } else {
                // No agent selected - try to get first available
                agentIdInput.value = '';
                agentDisplay.textContent = 'Loading...';
                fetch('/api/agents/list')
                    .then(r => r.json())
                    .then(data => {
                        if (data.success && data.agents && data.agents.length > 0) {
                            window.cachedAgents = data.agents;
                            const onlineAgent = data.agents.find(a => a.status === 'online') || data.agents[0];
                            if (onlineAgent) {
                                agentIdInput.value = onlineAgent.agent_id || onlineAgent.id;
                                agentDisplay.textContent = onlineAgent.display_name || onlineAgent.hostname || onlineAgent.agent_id;
                                window.currentAgentId = onlineAgent.agent_id || onlineAgent.id;
                            } else {
                                agentDisplay.textContent = 'No agents available';
                            }
                        } else {
                            agentDisplay.textContent = 'No agents available';
                        }
                    })
                    .catch(() => {
                        agentDisplay.textContent = 'Failed to load agents';
                    });
            }
        }
    }

    function closeBlockIPModal() {
        const modal = document.getElementById('blockIPModal');
        if (modal) modal.style.display = 'none';
    }

    function quickBlockIP() {
        console.log('=== quickBlockIP called ===');

        // Get IP from octet inputs
        const ip = getIPFromOctets();
        console.log('IP from octets:', ip);
        const container = document.getElementById('ipInputContainer');
        const agentId = document.getElementById('quickBlockAgentId').value;
        const agentName = document.getElementById('quickBlockAgentDisplay').textContent;
        const method = document.getElementById('quickBlockMethod').value;
        const duration = parseInt(document.getElementById('quickBlockDuration').value);
        const reason = document.getElementById('quickBlockReason').value.trim() || 'Manual block from dashboard';
        const msgEl = document.getElementById('quickBlockMessage');

        // Check all octets are filled
        if (!ip) {
            msgEl.textContent = 'Please enter a complete IP address';
            msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
            msgEl.style.color = TC.danger;
            msgEl.style.display = 'block';
            if (container) container.style.borderColor = TC.danger;
            document.getElementById('ipOctet1')?.focus();
            return;
        }

        // Require agent - no global blocks allowed
        if (!agentId) {
            msgEl.textContent = 'No agent selected. Please select an agent first.';
            msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
            msgEl.style.color = TC.danger;
            msgEl.style.display = 'block';
            return;
        }

        // Mark as valid
        if (container) container.style.borderColor = TC.successDark;

        msgEl.textContent = `Blocking ${ip} on ${agentName}...`;
        msgEl.style.background = 'rgba(0, 120, 212, 0.1)';
        msgEl.style.color = 'var(--azure-blue)';
        msgEl.style.display = 'block';

        // Convert seconds to minutes for the API
        const durationMinutes = Math.floor(duration / 60);
        const endpoint = method === 'fail2ban' ? '/api/dashboard/fail2ban/ban' : '/api/dashboard/blocking/blocks/manual';
        const payload = method === 'fail2ban'
            ? { ip_address: ip, bantime: duration, reason: reason, agent_id: agentId }
            : { ip_address: ip, reason: reason, duration_minutes: durationMinutes || 1440, agent_id: agentId };

        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(r => r.json())
        .then(data => {
            console.log('Block IP response:', data);
            if (data.success) {
                msgEl.textContent = `Successfully blocked ${ip}`;
                msgEl.style.background = 'rgba(16, 124, 16, 0.1)';
                msgEl.style.color = TC.successDark;

                // Set the agent filter
                if (agentId) {
                    window.currentAgentId = agentId;
                    const pageAgentSelector = document.getElementById('firewallAgentSelector');
                    if (pageAgentSelector) pageAgentSelector.value = agentId;
                }

                // Close modal after brief delay to show success message
                setTimeout(function() {
                    try {
                        // Close the modal
                        const modal = document.getElementById('blockIPModal');
                        if (modal) modal.style.display = 'none';

                        // Try to switch tab and reload
                        const blockedTab = document.querySelector('[data-tab="blocked"]');
                        if (blockedTab) blockedTab.click();
                        if (typeof loadBlockedIPs === 'function') loadBlockedIPs();
                    } catch (e) {
                        console.error('Error after blocking:', e);
                    }
                }, 800);
            } else {
                msgEl.textContent = data.error || 'Failed to block IP';
                msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
                msgEl.style.color = TC.danger;
            }
        })
        .catch(err => {
            console.error('Block IP error:', err);
            msgEl.textContent = 'Error blocking IP: ' + err.message;
            msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
            msgEl.style.color = TC.danger;
        });
    }

    // Global exports
    window.showBlockIPModal = showBlockIPModal;
    window.closeBlockIPModal = closeBlockIPModal;
    window.quickBlockIP = quickBlockIP;
})();
/**
 * SSH Guardian v3.0 - Firewall Inline Logins
 * Successful logins tab functionality
 */
(function() {
    'use strict';

    let currentLoginsPageFW = 1;
    const LOGINS_PAGE_SIZE_FW = 25;

    async function loadSuccessfulLoginsFirewall(page = 1) {
        currentLoginsPageFW = page;
        const loadingEl = document.getElementById('loginsLoading');
        const containerEl = document.getElementById('loginsContainer');
        const noLoginsEl = document.getElementById('noLogins');
        const paginationEl = document.getElementById('loginsPagination');
        const tbodyEl = document.getElementById('fwLoginsTableBody');

        if (loadingEl) loadingEl.style.display = 'block';
        if (noLoginsEl) noLoginsEl.style.display = 'none';
        if (tbodyEl) tbodyEl.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 30px; color: var(--text-secondary);">Loading...</td></tr>';

        try {
            const params = new URLSearchParams();
            params.append('event_type', 'successful');
            params.append('limit', LOGINS_PAGE_SIZE_FW);
            params.append('offset', (page - 1) * LOGINS_PAGE_SIZE_FW);
            if (window.currentAgentId) params.append('agent_id', window.currentAgentId);

            const timeFilter = document.getElementById('loginTimeFilter')?.value;
            if (timeFilter) {
                const now = new Date();
                let startDate;
                if (timeFilter === '24h') startDate = new Date(now - 24 * 60 * 60 * 1000);
                else if (timeFilter === '7d') startDate = new Date(now - 7 * 24 * 60 * 60 * 1000);
                else if (timeFilter === '30d') startDate = new Date(now - 30 * 24 * 60 * 60 * 1000);
                if (startDate) params.append('start_date', startDate.toISOString().split('T')[0]);
            }

            const searchFilter = document.getElementById('loginSearchFilter')?.value?.trim();
            if (searchFilter) params.append('search', searchFilter);

            const response = await fetch(`/api/dashboard/events/list?${params.toString()}`);
            const data = await response.json();

            if (loadingEl) loadingEl.style.display = 'none';
            if (!data.success) throw new Error(data.error || 'Failed to load logins');

            const events = data.events || [];
            const pagination = data.pagination || { total: events.length };

            if (events.length === 0) {
                if (noLoginsEl) noLoginsEl.style.display = 'block';
                if (containerEl) containerEl.style.display = 'none';
                if (paginationEl) paginationEl.style.display = 'none';
                updateLoginStats([], pagination);
            } else {
                renderSuccessfulLoginsFirewall(events);
                updateLoginsPagination(pagination);
                updateLoginStats(events, pagination);
                if (noLoginsEl) noLoginsEl.style.display = 'none';
                if (containerEl) containerEl.style.display = 'block';
                if (paginationEl) paginationEl.style.display = 'flex';
            }
        } catch (error) {
            console.error('Error loading logins:', error);
            if (loadingEl) loadingEl.style.display = 'none';
            if (noLoginsEl) {
                const titleEl = noLoginsEl.querySelector('p:first-of-type');
                const msgEl = noLoginsEl.querySelector('p:last-of-type');
                if (titleEl) titleEl.textContent = 'Error Loading Logins';
                if (msgEl) msgEl.textContent = error.message;
                noLoginsEl.style.display = 'block';
            }
        }
    }

    function renderSuccessfulLoginsFirewall(events) {
        const tbody = document.getElementById('fwLoginsTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';
        events.forEach(event => {
            const riskScore = event.ml_risk_score || event.risk_score || 0;
            const riskClass = riskScore >= 80 ? 'critical' : riskScore >= 60 ? 'high' : riskScore >= 40 ? 'moderate' : 'low';
            const loc = event.location || event.geoip || {};
            const locationStr = (loc?.city || loc?.country) ?
                ((loc.city || '') + (loc.city && loc.country ? ', ' : '') + (loc.country || '')) : 'Unknown';
            const ipAddress = event.ip || event.ip_address || 'N/A';
            const username = event.username || 'Unknown';
            const timeStr = event.timestamp ? formatTimeAgo(event.timestamp) : 'N/A';

            const tr = document.createElement('tr');
            tr.style.cssText = 'border-bottom: 1px solid var(--border); cursor: pointer;';
            tr.onclick = () => showLoginDetailModalFW(event.id);
            tr.innerHTML = `
                <td style="padding: 10px; font-weight: 500;">${username}</td>
                <td style="padding: 10px; font-family: monospace; font-size: 12px;">${ipAddress}</td>
                <td style="padding: 10px; font-size: 12px; color: var(--text-secondary);">${locationStr}</td>
                <td style="padding: 10px; text-align: center;"><span class="risk-badge ${riskClass}" style="padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">${riskScore}</span></td>
                <td style="padding: 10px; font-size: 12px;">${timeStr}</td>
                <td style="padding: 10px; text-align: center;"><span style="padding: 2px 8px; background: rgba(16, 185, 129, 0.15); color: ${TC.teal}; border-radius: 4px; font-size: 11px; font-weight: 600;">Success</span></td>`;
            tbody.appendChild(tr);
        });

        // Add risk badge styles if not present
        if (!document.getElementById('risk-badge-styles')) {
            const style = document.createElement('style');
            style.id = 'risk-badge-styles';
            style.textContent = `
                .risk-badge.critical { background: rgba(209, 52, 56, 0.15); color: ${TC.danger}; }
                .risk-badge.high { background: rgba(255, 140, 0, 0.15); color: ${TC.orange}; }
                .risk-badge.moderate { background: rgba(255, 185, 0, 0.15); color: ${TC.warningDark}; }
                .risk-badge.low { background: rgba(16, 185, 129, 0.15); color: ${TC.teal}; }
            `;
            document.head.appendChild(style);
        }
    }

    function updateLoginsPagination(pagination) {
        const infoEl = document.getElementById('loginsInfo');
        const prevBtn = document.getElementById('prevLoginsPage');
        const nextBtn = document.getElementById('nextLoginsPage');

        const total = pagination.total || 0;
        const start = (currentLoginsPageFW - 1) * LOGINS_PAGE_SIZE_FW + 1;
        const end = Math.min(currentLoginsPageFW * LOGINS_PAGE_SIZE_FW, total);

        if (infoEl) {
            infoEl.textContent = total > 0 ? `Showing ${start}-${end} of ${total}` : 'No logins found';
        }

        if (prevBtn) prevBtn.disabled = currentLoginsPageFW <= 1;
        if (nextBtn) nextBtn.disabled = end >= total;
    }

    function updateLoginStats(events, pagination) {
        const total = pagination?.total || events.length;

        // Count unique users and IPs from current page (approximate)
        const uniqueUsers = new Set(events.map(e => e.username)).size;
        const uniqueIPs = new Set(events.map(e => e.ip || e.ip_address)).size;

        // Today's logins (from current page data)
        const today = new Date().toDateString();
        const todayLogins = events.filter(e => {
            const eventDate = new Date(e.timestamp);
            return eventDate.toDateString() === today;
        }).length;

        document.getElementById('loginStatTotal').textContent = total.toLocaleString();
        document.getElementById('loginStatUniqueUsers').textContent = uniqueUsers.toLocaleString();
        document.getElementById('loginStatUniqueIPs').textContent = uniqueIPs.toLocaleString();
        document.getElementById('loginStatToday').textContent = todayLogins.toLocaleString();
    }

    async function showLoginDetailModalFW(eventId) {
        showFWDetailModal('Loading...', `
            <div style="text-align: center; padding: 40px;">
                <div class="loading-spinner"></div>
                <p style="margin-top: 16px; color: var(--text-secondary);">Loading login details...</p>
            </div>
        `);

        try {
            const response = await fetch(`/api/dashboard/events/${eventId}`);
            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Failed to load event');
            }

            const event = data.data || data.event;
            renderLoginDetailModal(event);

        } catch (error) {
            console.error('Error loading login details:', error);
            showFWDetailModal('Error', `
                <div style="text-align: center; padding: 20px; color: ${TC.danger};">
                    <p>Error loading login details: ${error.message}</p>
                </div>
            `);
        }
    }

    function renderLoginDetailModal(event) {
        const riskScore = event.ml_risk_score || event.risk_score || 0;
        const riskClass = getScoreClass(riskScore);
        const geoip = event.location || event.geoip || {};
        const threat = event.threat || {};
        const agent = event.agent || {};
        const ipAddress = event.ip || event.ip_address || 'N/A';

        // Status badge
        const statusBadge = '<span class="detail-badge success">Successful Login</span>';

        // Auth method badge
        const authBadge = event.auth_method
            ? `<span class="detail-badge info">${escapeHtml(event.auth_method)}</span>`
            : '';

        // GeoIP section
        const geoSection = geoip && (geoip.country || geoip.city) ? `
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
        const abuseScore = threat.abuseipdb_score || 0;
        const vtPositives = threat.virustotal_positives || 0;
        const vtTotal = threat.virustotal_total || 0;
        const threatLevel = threat.level || 'unknown';
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
                        <div class="threat-intel-label">VirusTotal</div>
                        <div class="threat-intel-value ${vtPositives > 0 ? 'critical' : 'low'}">${vtPositives}/${vtTotal}</div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">Reports (30 days)</div>
                        <div class="threat-intel-value">${threat.abuseipdb_reports || 0}</div>
                    </div>
                    <div class="threat-intel-item">
                        <div class="threat-intel-label">Threat Level</div>
                        <div class="threat-intel-value">
                            <span class="detail-badge ${threatLevel === 'clean' ? 'success' : threatLevel === 'suspicious' ? 'warning' : threatLevel === 'malicious' ? 'critical' : ''}">${threatLevel}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Login Details section
        const loginSection = `
            <div class="detail-section">
                <div class="detail-section-title">🔐 Login Details</div>
                <div class="behavioral-grid">
                    <div class="behavioral-item">
                        <span class="behavioral-label">Username</span>
                        <span class="behavioral-value">${escapeHtml(event.username || 'Unknown')}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Auth Method</span>
                        <span class="behavioral-value">${escapeHtml(event.auth_method || 'N/A')}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Port</span>
                        <span class="behavioral-value">${event.port || 22}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Server</span>
                        <span class="behavioral-value">${escapeHtml(event.server || agent.hostname || 'Unknown')}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Login Time</span>
                        <span class="behavioral-value">${event.timestamp ? formatTimeAgo(event.timestamp) : 'N/A'}</span>
                    </div>
                    <div class="behavioral-item">
                        <span class="behavioral-label">Is Anomaly</span>
                        <span class="behavioral-value">${event.is_anomaly ? `<span style="color:${TC.danger};">Yes</span>` : `<span style="color:${TC.teal};">No</span>`}</span>
                    </div>
                </div>
            </div>
        `;

        // ML Contribution section
        const mlSection = `
            <div class="detail-section">
                <div class="detail-section-title">🤖 ML Risk Assessment</div>
                <div class="ml-contribution-box">
                    <div class="ml-score-circle ${riskClass}">
                        <span class="ml-score-value">${riskScore}</span>
                        <span class="ml-score-label">Risk Score</span>
                    </div>
                    <div class="ml-details">
                        <div class="ml-detail-row">
                            <span>Risk Level:</span>
                            <span class="detail-badge ${riskClass}">${riskClass.charAt(0).toUpperCase() + riskClass.slice(1)}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>Confidence:</span>
                            <span class="ml-confidence">${threat.confidence ? (parseFloat(threat.confidence) * 100).toFixed(0) + '%' : 'N/A'}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>ML Threat Type:</span>
                            <span>${event.ml_threat_type || 'None detected'}</span>
                        </div>
                        <div class="ml-detail-row">
                            <span>Event Type:</span>
                            <span style="font-weight: 600; color: ${TC.teal};">Successful Login</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Event Summary section
        const summarySection = `
            <div class="detail-section">
                <div class="detail-section-title">📋 Event Summary</div>
                <div class="justification-box">
                    <div class="justification-reason">
                        <strong>Status:</strong> This login was successful and has been logged for security monitoring.
                    </div>
                    <div class="justification-meta">
                        <span>Event ID: #${event.id}</span>
                        <span>UUID: ${event.event_uuid ? event.event_uuid.substring(0, 8) + '...' : 'N/A'}</span>
                    </div>
                </div>
            </div>
        `;

        const content = `
            <div class="block-detail-body">
                <!-- Header -->
                <div class="detail-header-section">
                    <div class="detail-ip-display">
                        <span class="detail-ip-address">${escapeHtml(ipAddress)}</span>
                        ${statusBadge}
                        ${authBadge}
                    </div>
                    <div class="detail-meta-row">
                        <span>👤 ${escapeHtml(event.username || 'Unknown')}</span>
                        <span>Agent: ${escapeHtml(agent.hostname || event.server || 'Unknown')}</span>
                    </div>
                </div>

                ${geoSection}
                ${threatSection}
                ${loginSection}
                ${mlSection}
                ${summarySection}
            </div>
        `;

        showFWDetailModal(`Login Investigation: ${ipAddress}`, content, { width: '700px' });
    }

    // Helper function
    function getScoreClass(score) {
        if (score >= 80) return 'critical';
        if (score >= 60) return 'high';
        if (score >= 40) return 'moderate';
        return 'low';
    }

    // Expose for pagination navigation
    window.loadLoginsPageFW = function(page) {
        loadSuccessfulLoginsFirewall(page);
    };

    window.prevLoginsPageFW = function() {
        if (currentLoginsPageFW > 1) loadSuccessfulLoginsFirewall(currentLoginsPageFW - 1);
    };

    window.nextLoginsPageFW = function() {
        loadSuccessfulLoginsFirewall(currentLoginsPageFW + 1);
    };

    // Global exports
    window.loadSuccessfulLoginsFirewall = loadSuccessfulLoginsFirewall;
    window.showLoginDetailModalFW = showLoginDetailModalFW;
})();
/**
 * SSH Guardian v3.0 - Firewall Inline Index
 * Module initialization and global exports
 */
(function() {
    'use strict';

    // Module version
    window._fwInlineVersion = '3.0.58';

    // Log initialization
    console.log('[Firewall Inline] Modular version loaded');

    // Note: All functions are exported by their respective modules
    // - tabs.js: switchFirewallTab
    // - activity-panel.js: toggleRecentActivityPanel, closeRecentActivityPanel, filterRecentLogs
    // - blocked-ips.js: loadBlockedIPs, filterBlockedIPs, searchBlockedIPs, unblockIP, reconcileBlockedIPs
    // - block-detail.js: showRealBlockDetail
    // - block-modal.js: showBlockIPModal, closeBlockIPModal, quickBlockIP
    // - logins.js: loadSuccessfulLoginsFirewall, showLoginDetailModalFW

    // Additional exports for backward compatibility
    window.showBlockedIPDetailModal = window.showRealBlockDetail;
})();
