/**
 * Threat Intelligence Page Module
 * Handles threat intelligence lookups and statistics
 */

// Load Threat Intelligence page data
async function loadThreatIntelPage() {
    await Promise.all([
        loadThreatStats(),
        loadHighRiskIPs(),
        loadRecentThreats()
    ]);
}

// Load threat intelligence statistics
async function loadThreatStats() {
    try {
        // Use fetchWithCache if available to track cache status
        let data;
        if (typeof fetchWithCache === 'function') {
            data = await fetchWithCache('/api/threat-intel/stats', 'threat_intel');
        } else {
            const response = await fetch('/api/threat-intel/stats');
            data = await response.json();
        }

        if (data.success && data.stats) {
            const stats = data.stats;
            document.getElementById('stat-total-threats').textContent = stats.total_ips.toLocaleString();

            // Calculate critical and high separately
            const criticalCount = stats.threat_levels?.critical || 0;
            const highCount = stats.high_threat_count || stats.threat_levels?.high || 0;

            const criticalEl = document.getElementById('stat-critical-threat');
            if (criticalEl) {
                criticalEl.textContent = criticalCount.toLocaleString();
            }
            document.getElementById('stat-high-threat').textContent = highCount.toLocaleString();

            const abuseipdb = stats.abuseipdb || {};
            const avgScore = abuseipdb.avg_score ? parseFloat(abuseipdb.avg_score).toFixed(1) : '0.0';
            document.getElementById('stat-avg-score').textContent = avgScore;
            document.getElementById('stat-total-reports').textContent =
                (abuseipdb.total_reports || 0).toLocaleString();
        }
    } catch (error) {
        console.error('Error loading threat stats:', error);
    }
}

// Load threat level distribution
async function loadThreatDistribution() {
    const container = document.getElementById('threat-distribution');

    try {
        const response = await fetch('/api/threat-intel/stats');
        const data = await response.json();

        if (!data.success || !data.stats.threat_levels) {
            container.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-secondary); font-size: 13px;">No distribution data</div>';
            return;
        }

        const levels = data.stats.threat_levels;
        const total = Object.values(levels).reduce((a, b) => a + b, 0);

        if (total === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--text-secondary); font-size: 13px;">No threats tracked yet</div>';
            return;
        }

        const distribution = [
            { level: 'Clean', count: levels.clean || 0, color: '#10b981' },
            { level: 'Low', count: levels.low || 0, color: '#3b82f6' },
            { level: 'Medium', count: levels.medium || 0, color: '#f59e0b' },
            { level: 'High', count: levels.high || 0, color: '#fb923c' },
            { level: 'Critical', count: levels.critical || 0, color: '#ef4444' }
        ].filter(item => item.count > 0);

        container.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 10px;">
                ${distribution.map(item => {
                    const percentage = ((item.count / total) * 100).toFixed(1);
                    return `
                        <div>
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                                <span style="font-size: 13px; font-weight: 500;">${item.level}</span>
                                <span style="font-size: 12px; color: var(--text-secondary);">${item.count.toLocaleString()} (${percentage}%)</span>
                            </div>
                            <div style="height: 8px; background: var(--background); border-radius: 4px; overflow: hidden;">
                                <div style="height: 100%; width: ${percentage}%; background: ${item.color}; transition: width 0.3s ease;"></div>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    } catch (error) {
        console.error('Error loading threat distribution:', error);
        container.innerHTML = '<div style="text-align: center; padding: 20px; color: #D13438; font-size: 13px;">Error loading distribution</div>';
    }
}

// Load high-risk IPs
async function loadHighRiskIPs() {
    const container = document.getElementById('threat-high-risk-list');

    try {
        const response = await fetch('/api/threat-intel/high-risk?limit=10');
        const data = await response.json();

        if (!data.success || !data.data || data.data.length === 0) {
            container.innerHTML = '<div class="empty-state-small">No high-risk IPs found</div>';
            return;
        }

        container.innerHTML = `
            <div class="table-wrapper">
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <th style="text-align: left; padding: 10px; font-weight: 600; font-size: 13px;">IP Address</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Threat Level</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Abuse Score</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Reports</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Confidence</th>
                        <th style="text-align: right; padding: 10px; font-weight: 600; font-size: 13px;">Updated</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.data.map(ip => {
                        const threatBadge = getThreatLevelBadge(ip.overall_threat_level);
                        const confidence = ip.threat_confidence ? (ip.threat_confidence * 100).toFixed(0) + '%' : 'N/A';

                        return `
                            <tr style="border-bottom: 1px solid var(--border-light);">
                                <td style="padding: 10px; font-size: 13px; font-family: monospace;">${escapeHtml(ip.ip_address_text)}</td>
                                <td style="text-align: center; padding: 10px;">${threatBadge}</td>
                                <td style="text-align: center; padding: 10px; font-size: 13px; font-weight: 600;">${ip.abuseipdb_score || 0}</td>
                                <td style="text-align: center; padding: 10px; font-size: 13px;">${ip.abuseipdb_reports || 0}</td>
                                <td style="text-align: center; padding: 10px; font-size: 13px;">${confidence}</td>
                                <td style="text-align: right; padding: 10px; font-size: 13px;">${ip.updated_at ? formatLocalDateTime(ip.updated_at) : 'N/A'}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
            </div>
        `;
    } catch (error) {
        console.error('Error loading high-risk IPs:', error);
        container.innerHTML = '<div class="empty-state-small" style="color: #D13438;">Error loading high-risk IPs</div>';
    }
}

// Load recent threat checks
async function loadRecentThreats() {
    const container = document.getElementById('threat-recent-list');

    try {
        const response = await fetch('/api/threat-intel/recent?limit=15');
        const data = await response.json();

        if (!data.success || !data.data || data.data.length === 0) {
            container.innerHTML = '<div class="empty-state-small">No recent threat checks</div>';
            return;
        }

        container.innerHTML = `
            <div class="table-wrapper">
            <table style="width: 100%; border-collapse: collapse;">
                <thead>
                    <tr style="border-bottom: 1px solid var(--border);">
                        <th style="text-align: left; padding: 10px; font-weight: 600; font-size: 13px;">IP Address</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Threat Level</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Abuse Score</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">Reports</th>
                        <th style="text-align: center; padding: 10px; font-weight: 600; font-size: 13px;">VT Positives</th>
                        <th style="text-align: right; padding: 10px; font-weight: 600; font-size: 13px;">Updated</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.data.map(ip => {
                        const threatBadge = getThreatLevelBadge(ip.overall_threat_level);
                        const vtRatio = ip.virustotal_positives && ip.virustotal_total ?
                            `${ip.virustotal_positives}/${ip.virustotal_total}` : 'N/A';

                        return `
                            <tr style="border-bottom: 1px solid var(--border-light);">
                                <td style="padding: 10px; font-size: 13px; font-family: monospace;">${escapeHtml(ip.ip_address_text)}</td>
                                <td style="text-align: center; padding: 10px;">${threatBadge}</td>
                                <td style="text-align: center; padding: 10px; font-size: 13px; font-weight: 600;">${ip.abuseipdb_score || 0}</td>
                                <td style="text-align: center; padding: 10px; font-size: 13px;">${ip.abuseipdb_reports || 0}</td>
                                <td style="text-align: center; padding: 10px; font-size: 13px;">${vtRatio}</td>
                                <td style="text-align: right; padding: 10px; font-size: 13px;">${ip.updated_at ? formatLocalDateTime(ip.updated_at) : 'N/A'}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
            </div>
        `;
    } catch (error) {
        console.error('Error loading recent threats:', error);
        container.innerHTML = '<div class="empty-state-small" style="color: #D13438;">Error loading recent threat data</div>';
    }
}

// Lookup specific IP threat
async function lookupThreat() {
    const input = document.getElementById('threat-search-input');
    const resultContainer = document.getElementById('threat-lookup-result');
    const ipAddress = input.value.trim();

    if (!ipAddress) {
        resultContainer.innerHTML = '<div style="color: #D13438; font-size: 13px;">Please enter an IP address</div>';
        return;
    }

    resultContainer.innerHTML = '<div class="loading-message">Checking threat level...</div>';

    try {
        const response = await fetch(`/api/threat-intel/lookup/${encodeURIComponent(ipAddress)}`);
        const data = await response.json();

        if (!data.success) {
            // IP not found - offer to enrich it
            resultContainer.innerHTML = `
                <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                    <div style="color: #D13438; font-size: 14px; font-weight: 600; margin-bottom: 8px;">IP Not Found in Database</div>
                    <div style="font-size: 13px; margin-bottom: 16px;">${data.message || data.error || 'This IP has not been checked for threats yet.'}</div>
                    <div style="font-size: 13px; margin-bottom: 12px;">Would you like to check this IP now? This will query AbuseIPDB, VirusTotal, and Shodan.</div>
                    <button
                        onclick="enrichThreat('${escapeHtml(ipAddress)}')"
                        style="padding: 8px 16px; background: var(--azure-blue); color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 13px; font-weight: 600;"
                    >
                        Check Threat Level
                    </button>
                </div>
            `;
            return;
        }

        const threat = data.data;
        const threatBadge = getThreatLevelBadge(threat.overall_threat_level);
        const confidence = threat.threat_confidence ? (threat.threat_confidence * 100).toFixed(0) + '%' : 'N/A';

        resultContainer.innerHTML = `
            <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
                    <div style="font-size: 16px; font-weight: 600; color: var(--azure-blue);">
                        IP: ${escapeHtml(threat.ip_address_text)}
                    </div>
                    ${threatBadge}
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; font-size: 13px;">
                    <div>
                        <div style="font-weight: 600; margin-bottom: 8px; color: var(--azure-blue);">AbuseIPDB</div>
                        <div><strong>Score:</strong> ${threat.abuseipdb_score || 0}/100</div>
                        <div><strong>Confidence:</strong> ${threat.abuseipdb_confidence || 0}%</div>
                        <div><strong>Reports:</strong> ${threat.abuseipdb_reports || 0}</div>
                        <div><strong>Last Reported:</strong> ${threat.abuseipdb_last_reported ? formatLocalDateTime(threat.abuseipdb_last_reported) : 'Never'}</div>
                    </div>
                    <div>
                        <div style="font-weight: 600; margin-bottom: 8px; color: var(--azure-blue);">VirusTotal</div>
                        <div><strong>Positives:</strong> ${threat.virustotal_positives || 0}</div>
                        <div><strong>Total Scans:</strong> ${threat.virustotal_total || 0}</div>
                        <div><strong>Detection Rate:</strong> ${
                            threat.virustotal_positives && threat.virustotal_total ?
                            ((threat.virustotal_positives / threat.virustotal_total) * 100).toFixed(1) + '%' :
                            'N/A'
                        }</div>
                    </div>
                </div>
                <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 13px;">
                    <div><strong>Overall Confidence:</strong> ${confidence}</div>
                    <div style="margin-top: 8px;"><strong>Last Updated:</strong> ${threat.updated_at ? formatLocalDateTime(threat.updated_at) : 'N/A'}</div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error looking up threat:', error);
        resultContainer.innerHTML = `
            <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                <div style="color: #D13438; font-size: 14px;">Connection Error</div>
                <div style="font-size: 13px; margin-top: 8px;">Failed to check threat level. Please try again.</div>
            </div>
        `;
    }
}

// Get threat level badge HTML
function getThreatLevelBadge(level) {
    const levelLower = (level || 'unknown').toLowerCase();
    let color, text;

    switch (levelLower) {
        case 'clean':
            color = '#107C10';
            text = 'Clean';
            break;
        case 'low':
            color = '#FFB900';
            text = 'Low';
            break;
        case 'medium':
            color = '#FF8C00';
            text = 'Medium';
            break;
        case 'high':
            color = '#D83B01';
            text = 'High';
            break;
        case 'critical':
            color = '#D13438';
            text = 'Critical';
            break;
        default:
            color = '#8A8886';
            text = 'Unknown';
    }

    return `<span style="display: inline-block; padding: 4px 12px; background: ${color}; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">${text}</span>`;
}

// Enrich IP with threat intelligence
async function enrichThreat(ipAddress) {
    const resultContainer = document.getElementById('threat-lookup-result');

    resultContainer.innerHTML = '<div class="loading-message">Checking threat level... This may take up to 10 seconds.</div>';

    try {
        const response = await fetch(`/api/threat-intel/enrich/${encodeURIComponent(ipAddress)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            resultContainer.innerHTML = `
                <div style="padding: 20px; background: #E7F5E7; border: 1px solid #107C10; border-radius: 3px;">
                    <div style="color: #107C10; font-size: 14px; font-weight: 600; margin-bottom: 8px;">✅ Threat Check Complete!</div>
                    <div style="font-size: 13px; margin-bottom: 12px;">IP address has been analyzed and threat data saved to database.</div>
                    <button
                        onclick="lookupThreat()"
                        style="padding: 8px 16px; background: var(--azure-blue); color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 13px; font-weight: 600;"
                    >
                        View Threat Details
                    </button>
                </div>
            `;

            // Refresh the page data
            loadThreatIntelPage();
        } else {
            resultContainer.innerHTML = `
                <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                    <div style="color: #D13438; font-size: 14px; font-weight: 600; margin-bottom: 8px;">Threat Check Failed</div>
                    <div style="font-size: 13px;">${data.error || 'Unknown error occurred'}</div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error enriching threat:', error);
        resultContainer.innerHTML = `
            <div style="padding: 20px; background: var(--surface); border: 1px solid var(--border); border-radius: 3px;">
                <div style="color: #D13438; font-size: 14px;">Connection Error</div>
                <div style="font-size: 13px; margin-top: 8px;">Failed to check threat level. Please try again.</div>
            </div>
        `;
    }
}

// Enable Enter key for lookup
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('threat-search-input');
    if (input) {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                lookupThreat();
            }
        });
    }
});
