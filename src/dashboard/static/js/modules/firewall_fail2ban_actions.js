/**
 * SSH Guardian v3.0 - Firewall Fail2ban Actions Module
 * Handles threat rendering, IP modals, block/unban actions
 * Dependencies: firewall_fail2ban.js (for loadFail2banBans, loadF2bStats)
 */

// ============================================================================
// THREAT CARD RENDERING
// ============================================================================

// Render threat card
function renderThreatCard(event, analysis) {
    const composite = analysis?.composite_risk || {};
    const threat = analysis?.threat_intel || {};
    const ml = analysis?.ml_predictions || {};

    const score = composite.overall_score || ml.risk_score || 0;
    const level = score >= 70 ? 'critical' : score >= 40 ? 'high' : 'medium';

    // Build threat factors
    const factors = [];
    if (threat.is_tor_exit) factors.push('🧅 Tor Exit Node');
    if (threat.is_vpn) factors.push('🔒 VPN/Proxy');
    if (threat.abuseipdb_score > 50) factors.push(`⚠️ AbuseIPDB: ${threat.abuseipdb_score}%`);
    if (event.failures > 5) factors.push(`❌ ${event.failures} failures`);
    if (ml.is_anomaly) factors.push('📊 Anomaly detected');

    const factorsText = factors.length > 0 ? factors.join(' • ') : 'Limited data available';
    const recommendation = score >= 70 ? 'Recommend permanent UFW block' :
                          score >= 40 ? 'Monitor closely' : 'Standard fail2ban handling';

    return `
        <div class="f2b-threat-card ${level}">
            <div class="f2b-threat-score ${level}">${Math.round(score)}</div>
            <div class="f2b-threat-details">
                <div class="f2b-threat-ip">${event.ip_address}</div>
                <div class="f2b-threat-factors">${factorsText}</div>
                <div class="f2b-threat-factors" style="margin-top: 4px; font-style: italic;">
                    💡 ${recommendation}
                </div>
            </div>
            ${score >= 60 ? `
                <button class="f2b-escalate-btn" onclick="escalateToUFW('${event.ip_address}')">
                    ⬆️ Block via UFW
                </button>
            ` : ''}
        </div>
    `;
}

// ============================================================================
// FAIL2BAN COMMANDS (SEND TO AGENT)
// ============================================================================

/**
 * Send unban command to agent - executes fail2ban-client unbanip
 * Uses global sync indicator for visual feedback
 */
async function sendUnbanCommand(agentId, ipAddress, jailName = 'sshd') {
    if (!agentId) {
        showNotification('No agent selected', 'error');
        return;
    }

    if (!confirm(`Unban ${ipAddress} from fail2ban?\n\nThis will remove the ban and allow connections from this IP.`)) {
        return;
    }

    // Use global sync indicator
    if (typeof executeF2bUnban === 'function') {
        await executeF2bUnban(agentId, ipAddress, jailName);
    } else {
        // Fallback if sync_indicator.js not loaded
        try {
            showNotification(`Unbanning ${ipAddress}...`, 'info');

            const response = await fetch(`/api/agents/${agentId}/fail2ban/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    command_type: 'unban',
                    ip_address: ipAddress,
                    jail_name: jailName
                })
            });

            const data = await response.json();

            if (data.success && data.executed) {
                showNotification(`${ipAddress} unbanned successfully!`, 'success');
                // Refresh the bans list
                if (typeof loadFail2banBans === 'function') {
                    loadFail2banBans();
                }
            } else if (data.success) {
                showNotification(`Unban command queued for agent`, 'success');
            } else {
                showNotification(`Failed: ${data.error || 'Unknown error'}`, 'error');
            }
        } catch (e) {
            console.error('Error sending unban command:', e);
            showNotification('Error: ' + e.message, 'error');
        }
    }
}

// ============================================================================
// UFW ESCALATION
// ============================================================================

/**
 * Escalate ban to permanent UFW block on agent
 * This creates a UFW deny rule that persists beyond fail2ban's bantime
 */
async function escalateToUFW(ip, agentId) {
    if (!agentId) agentId = window.currentAgentId;
    if (!agentId) {
        showNotification('No agent selected for UFW escalation', 'error');
        return;
    }

    if (!confirm(`Permanently block ${ip} via UFW?\n\nThis creates a persistent firewall rule that:\n• Survives fail2ban unbans\n• Survives system reboots\n• Must be manually removed`)) {
        return;
    }

    // Use global sync indicator
    if (typeof window.showGlobalSync === 'function') {
        window.showGlobalSync('ufw', `Blocking ${ip} via UFW...`);
    } else {
        showF2bSyncIndicator('Blocking via UFW...');
    }

    try {
        // Use quick-action endpoint for direct execution
        const response = await fetch(`/api/agents/${agentId}/ufw/quick-action`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action_type: 'block_ip',
                ip: ip,
                from_fail2ban: true
            })
        });

        const data = await response.json();

        if (data.executed && data.success) {
            // Direct execution succeeded
            if (typeof window.completeSyncOperation === 'function') {
                window.completeSyncOperation(true, `${ip} blocked permanently`);
            } else {
                hideF2bSyncIndicator();
                showNotification(`${ip} blocked via UFW`, 'success');
            }
            // Refresh data
            setTimeout(() => {
                if (typeof loadFail2banBans === 'function') loadFail2banBans();
                if (typeof loadUFWData === 'function') loadUFWData(agentId, true);
            }, 500);
        } else if (data.success) {
            // Queued for remote agent
            if (typeof window.completeSyncOperation === 'function') {
                window.completeSyncOperation(true, 'Command queued for agent');
            } else {
                hideF2bSyncIndicator();
                showNotification('UFW block queued for agent', 'success');
            }
        } else {
            if (typeof window.completeSyncOperation === 'function') {
                window.completeSyncOperation(false, data.error || 'Failed');
            } else {
                hideF2bSyncIndicator();
                showNotification(`Failed: ${data.error}`, 'error');
            }
        }
    } catch (e) {
        if (typeof window.completeSyncOperation === 'function') {
            window.completeSyncOperation(false, e.message);
        } else {
            hideF2bSyncIndicator();
            showNotification('Error: ' + e.message, 'error');
        }
    }
}

// ============================================================================
// IP DETAILS MODAL (styled like Live Events modal)
// ============================================================================

/**
 * Show IP details modal for banned IP - styled like Live Events detail modal
 */
async function showBannedIpDetails(ip, banData = null) {
    if (!ip) return;

    // Show loading state
    showF2bIpModal(ip, `
        <div style="text-align: center; padding: 40px;">
            <div class="fw-spinner-lg"></div>
            <div style="margin-top: 16px; color: var(--text-secondary);">Loading IP analysis...</div>
        </div>
    `);

    try {
        // Fetch IP analysis data (threat-intel endpoint removed - not available)
        const [geoResponse, eventsResponse] = await Promise.all([
            fetch(`/api/geoip/lookup/${encodeURIComponent(ip)}`).catch(() => ({ ok: false })),
            fetch(`/api/agents/fail2ban/events?ip=${encodeURIComponent(ip)}&limit=20`).catch(() => ({ ok: false }))
        ]);

        const geoData = geoResponse.ok ? await geoResponse.json() : {};
        const eventsData = eventsResponse.ok ? await eventsResponse.json() : { events: [] };
        const threatData = {}; // Threat intel not available

        // Build modal content
        const content = buildF2bIpDetailContent(ip, banData, geoData, eventsData.events || [], threatData);
        showF2bIpModal(ip, content);

    } catch (error) {
        console.error('Error loading IP details:', error);
        showF2bIpModal(ip, `
            <div style="text-align: center; padding: 40px; color: var(--text-secondary);">
                <div style="font-size: 24px; margin-bottom: 8px;">⚠️</div>
                <div>Could not load IP details</div>
                <div style="margin-top: 8px; font-size: 12px;">${error.message}</div>
            </div>
        `);
    }
}

/**
 * Build the IP detail modal content (matches Live Events style)
 */
function buildF2bIpDetailContent(ip, banData, geo, events, threat) {
    const location = geo.location || geo;
    const countryName = location.country_name || location.country || 'Unknown';
    const cityName = location.city || '';
    const isp = location.isp || location.org || 'Unknown ISP';
    const asn = location.asn || '';

    // Count ban/unban events
    const banCount = events.filter(e => e.event_type === 'ban' || e.action === 'ban').length;
    const unbanCount = events.filter(e => e.event_type === 'unban' || e.action === 'unban').length;
    const totalFailures = events.reduce((sum, e) => sum + (e.failures || 0), 0);

    // Threat indicators
    const threatScore = threat.abuseipdb_score || threat.threat_score || 0;
    const isTor = threat.is_tor || threat.is_tor_exit || false;
    const isVpn = threat.is_vpn || threat.is_proxy || false;
    const isDatacenter = threat.is_datacenter || threat.is_hosting || false;

    // Risk level
    const riskLevel = banCount >= 5 ? 'critical' : banCount >= 3 ? 'high' : banCount >= 2 ? 'moderate' : 'low';
    const riskScore = Math.min(100, banCount * 15 + threatScore * 0.5 + (isTor ? 20 : 0) + (isVpn ? 10 : 0));

    return `
        <!-- Header with IP and Risk Score -->
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; padding-bottom: 16px; border-bottom: 1px solid var(--border);">
            <div>
                <div style="font-size: 24px; font-weight: 700; font-family: monospace;">${ip}</div>
                <div style="color: var(--text-secondary); margin-top: 4px;">
                    ${countryName}${cityName ? ` • ${cityName}` : ''} • ${isp}
                </div>
            </div>
            <div class="f2b-risk-badge ${riskLevel}" style="text-align: center; padding: 12px 20px; border-radius: 8px; min-width: 80px;">
                <div style="font-size: 28px; font-weight: 700;">${Math.round(riskScore)}</div>
                <div style="font-size: 11px; text-transform: uppercase;">${riskLevel} Risk</div>
            </div>
        </div>

        <!-- Stats Grid -->
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px;">
            <div class="f2b-stat-box">
                <div class="f2b-stat-value" style="color: ${TC.danger};">${banCount}</div>
                <div class="f2b-stat-label">Total Bans</div>
            </div>
            <div class="f2b-stat-box">
                <div class="f2b-stat-value" style="color: ${TC.teal};">${unbanCount}</div>
                <div class="f2b-stat-label">Unbans</div>
            </div>
            <div class="f2b-stat-box">
                <div class="f2b-stat-value" style="color: ${TC.orange};">${totalFailures}</div>
                <div class="f2b-stat-label">Total Failures</div>
            </div>
            <div class="f2b-stat-box">
                <div class="f2b-stat-value" style="color: ${TC.purple};">${threatScore}%</div>
                <div class="f2b-stat-label">Abuse Score</div>
            </div>
        </div>

        <!-- Threat Indicators -->
        <div style="margin-bottom: 20px;">
            <div style="font-weight: 600; margin-bottom: 8px;">Threat Indicators</div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                ${isTor ? '<span class="f2b-threat-tag tor">🧅 Tor Exit Node</span>' : ''}
                ${isVpn ? '<span class="f2b-threat-tag vpn">🔒 VPN/Proxy</span>' : ''}
                ${isDatacenter ? '<span class="f2b-threat-tag datacenter">🏢 Datacenter</span>' : ''}
                ${banCount >= 3 ? '<span class="f2b-threat-tag repeat">🔄 Repeat Offender</span>' : ''}
                ${threatScore >= 50 ? '<span class="f2b-threat-tag abuse">⚠️ High Abuse Score</span>' : ''}
                ${!isTor && !isVpn && !isDatacenter && banCount < 3 && threatScore < 50 ? '<span class="f2b-threat-tag clean">✅ No major threats detected</span>' : ''}
            </div>
        </div>

        <!-- Recent Events Timeline -->
        <div style="margin-bottom: 16px;">
            <div style="font-weight: 600; margin-bottom: 8px;">Recent Events</div>
            <div style="max-height: 200px; overflow-y: auto; background: var(--surface); border-radius: 6px; padding: 8px;">
                ${events.length > 0 ? events.slice(0, 10).map(e => {
                    const icon = (e.event_type === 'ban' || e.action === 'ban') ? '🔒' : '🔓';
                    const action = (e.event_type === 'ban' || e.action === 'ban') ? 'Banned' : 'Unbanned';
                    const time = e.timestamp || e.reported_at;
                    const timeStr = time ? formatTimeAgo(time) : 'Unknown';
                    return `
                        <div style="display: flex; align-items: center; gap: 10px; padding: 8px; border-bottom: 1px solid var(--border);">
                            <span>${icon}</span>
                            <span style="flex: 1;">${action} from <strong>${e.jail_name || 'sshd'}</strong></span>
                            ${e.failures ? `<span style="color: var(--text-secondary);">${e.failures} failures</span>` : ''}
                            <span style="color: var(--text-secondary); font-size: 12px;">${timeStr}</span>
                        </div>
                    `;
                }).join('') : '<div style="padding: 20px; text-align: center; color: var(--text-secondary);">No events recorded</div>'}
            </div>
        </div>

        <!-- Network Info -->
        <div style="background: var(--surface); border-radius: 6px; padding: 12px;">
            <div style="font-weight: 600; margin-bottom: 8px;">Network Information</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 13px;">
                <div><span style="color: var(--text-secondary);">Country:</span> ${countryName}</div>
                <div><span style="color: var(--text-secondary);">City:</span> ${cityName || 'Unknown'}</div>
                <div><span style="color: var(--text-secondary);">ISP:</span> ${isp}</div>
                <div><span style="color: var(--text-secondary);">ASN:</span> ${asn || 'Unknown'}</div>
            </div>
        </div>
    `;
}

/**
 * Show the F2B IP detail modal
 */
function showF2bIpModal(ip, content) {
    // Remove existing modal
    const existing = document.getElementById('f2b-ip-detail-modal');
    if (existing) existing.remove();

    // Check if IP is already blocked in UFW
    const isBlocked = typeof isIpInUFW === 'function' && isIpInUFW(ip);

    // Build footer buttons - only show block button if not already blocked
    const blockButton = isBlocked
        ? `<span class="event-modal-btn" style="background: ${TC.successBg}; color: ${TC.teal}; cursor: default;">✓ Already in UFW</span>`
        : `<button class="event-modal-btn danger" onclick="escalateToUFW('${ip}'); closeF2bIpModal();">🛡️ Block via UFW</button>`;

    const modal = document.createElement('div');
    modal.id = 'f2b-ip-detail-modal';
    modal.className = 'event-detail-modal-overlay';
    modal.innerHTML = `
        <div class="event-detail-modal" style="max-width: 700px;">
            <div class="event-detail-modal-header">
                <h3>IP Analysis: ${ip}</h3>
                <button class="event-detail-modal-close" onclick="closeF2bIpModal()">&times;</button>
            </div>
            <div class="event-detail-modal-body">${content}</div>
            <div class="event-detail-modal-footer">
                ${blockButton}
                <button class="event-modal-btn primary" onclick="closeF2bIpModal()">Close</button>
            </div>
        </div>
    `;

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) closeF2bIpModal();
    });

    // Close on Escape
    const escHandler = (e) => {
        if (e.key === 'Escape') {
            closeF2bIpModal();
            document.removeEventListener('keydown', escHandler);
        }
    };
    document.addEventListener('keydown', escHandler);

    document.body.appendChild(modal);
    document.body.style.overflow = 'hidden';
}

function closeF2bIpModal() {
    const modal = document.getElementById('f2b-ip-detail-modal');
    if (modal) {
        modal.remove();
        document.body.style.overflow = '';
    }
}

// ============================================================================
// QUICK BLOCK FUNCTIONALITY
// ============================================================================

async function quickBlockIP() {
    const ip = document.getElementById('quickBlockIP').value.trim();
    const method = document.getElementById('quickBlockMethod').value;
    const duration = parseInt(document.getElementById('quickBlockDuration').value);

    if (!ip) {
        showQuickBlockMessage('Please enter an IP address', 'error');
        return;
    }

    // Validate IP format
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
        showQuickBlockMessage('Invalid IP address format', 'error');
        return;
    }

    showQuickBlockMessage('Blocking IP...', 'info');

    try {
        if (method === 'ufw') {
            // Block via UFW
            if (!window.currentAgentId) {
                showQuickBlockMessage('Please select a server first for UFW blocking', 'error');
                return;
            }

            const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/quick-action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action_type: 'block_ip',
                    ip: ip
                })
            });

            const data = await response.json();

            if (data.success) {
                showQuickBlockMessage(`IP ${ip} blocked via UFW`, 'success');
                document.getElementById('quickBlockIP').value = '';
                // Refresh UFW data
                if (window.currentAgentId && typeof loadUFWData === 'function') {
                    loadUFWData(window.currentAgentId);
                }
            } else {
                showQuickBlockMessage(`Error: ${data.error}`, 'error');
            }
        } else {
            // Block via fail2ban
            const response = await fetch('/api/dashboard/fail2ban/ban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ip_address: ip,
                    jail: 'sshd',
                    bantime: duration,
                    reason: 'Manual block from dashboard'
                })
            });

            const data = await response.json();

            if (data.success) {
                showQuickBlockMessage(`IP ${ip} blocked via fail2ban`, 'success');
                document.getElementById('quickBlockIP').value = '';
                // Refresh fail2ban data
                if (typeof loadFail2banBans === 'function') loadFail2banBans();
            } else {
                showQuickBlockMessage(`Error: ${data.error}`, 'error');
            }
        }
    } catch (error) {
        showQuickBlockMessage(`Error: ${error.message}`, 'error');
    }
}

function showQuickBlockMessage(message, type) {
    const el = document.getElementById('quickBlockMessage');
    if (!el) return;

    el.style.display = 'block';
    el.textContent = message;

    if (type === 'error') {
        el.style.background = TC.dangerBg;
        el.style.color = TC.danger;
    } else if (type === 'success') {
        el.style.background = TC.successBg;
        el.style.color = TC.successDark;
    } else {
        el.style.background = TC.primaryBg;
        el.style.color = TC.primary;
    }

    if (type !== 'error') {
        setTimeout(() => { el.style.display = 'none'; }, 3000);
    }
}

// ============================================================================
// SYNC INDICATOR UTILITIES
// ============================================================================

/**
 * Show the fail2ban sync indicator with custom text
 */
function showF2bSyncIndicator(text = 'Syncing...') {
    const indicator = document.getElementById('f2bSyncIndicator');
    const textEl = indicator?.querySelector('.f2b-sync-text');
    if (indicator) {
        indicator.style.display = 'inline-flex';
        if (textEl) textEl.textContent = text;
    }
}

/**
 * Hide the fail2ban sync indicator
 */
function hideF2bSyncIndicator() {
    const indicator = document.getElementById('f2bSyncIndicator');
    if (indicator) {
        indicator.style.display = 'none';
    }
}

/**
 * Update the sync indicator text
 */
function updateF2bSyncText(text) {
    const indicator = document.getElementById('f2bSyncIndicator');
    const textEl = indicator?.querySelector('.f2b-sync-text');
    if (textEl) textEl.textContent = text;
}

// ============================================================================
// EXPORTS
// ============================================================================

// Expose functions globally for inline onclick handlers
window.renderThreatCard = renderThreatCard;
window.escalateToUFW = escalateToUFW;
window.sendUnbanCommand = sendUnbanCommand;
window.showBannedIpDetails = showBannedIpDetails;
window.showF2bIpModal = showF2bIpModal;
window.closeF2bIpModal = closeF2bIpModal;
window.quickBlockIP = quickBlockIP;
window.showQuickBlockMessage = showQuickBlockMessage;
window.showF2bSyncIndicator = showF2bSyncIndicator;
window.hideF2bSyncIndicator = hideF2bSyncIndicator;
window.updateF2bSyncText = updateF2bSyncText;
