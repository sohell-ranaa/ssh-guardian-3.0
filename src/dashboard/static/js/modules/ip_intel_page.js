/**
 * SSH Guardian v3.0 - IP Intelligence Page
 * Unified IP analysis: GeoIP, Threat Intel, ML, History
 */

(function() {
    'use strict';

    function getFlag(code) {
        if (!code || code.length !== 2) return '';
        return String.fromCodePoint(...code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0)));
    }

    function getRiskClass(score) {
        if (score >= 70) return 'high';
        if (score >= 40) return 'medium';
        return 'low';
    }

    function getScoreColor(score) {
        if (score >= 70) return TC.danger;
        if (score >= 40) return TC.orange;
        return TC.teal;
    }

    function isPrivateIP(ip) {
        if (!ip) return false;
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        const first = parseInt(parts[0], 10);
        const second = parseInt(parts[1], 10);
        // 10.0.0.0/8
        if (first === 10) return true;
        // 172.16.0.0/12
        if (first === 172 && second >= 16 && second <= 31) return true;
        // 192.168.0.0/16
        if (first === 192 && second === 168) return true;
        // 127.0.0.0/8 (loopback)
        if (first === 127) return true;
        // 169.254.0.0/16 (link-local)
        if (first === 169 && second === 254) return true;
        return false;
    }

    function getPrivateIPType(ip) {
        const parts = ip.split('.');
        const first = parseInt(parts[0], 10);
        const second = parseInt(parts[1], 10);
        if (first === 10) return { range: '10.0.0.0/8', type: 'Class A Private', usage: 'Large private networks' };
        if (first === 172 && second >= 16 && second <= 31) return { range: '172.16.0.0/12', type: 'Class B Private', usage: 'Medium private networks' };
        if (first === 192 && second === 168) return { range: '192.168.0.0/16', type: 'Class C Private', usage: 'Small private networks / Home networks' };
        if (first === 127) return { range: '127.0.0.0/8', type: 'Loopback', usage: 'Local machine communication' };
        if (first === 169 && second === 254) return { range: '169.254.0.0/16', type: 'Link-Local', usage: 'Auto-configured when DHCP fails' };
        return { range: 'Unknown', type: 'Private', usage: 'Internal use' };
    }

    async function loadIPIntelPage() {
        if (window.TimeSettings && !window.TimeSettings.isLoaded()) {
            await window.TimeSettings.load();
        }
        await Promise.all([loadIPIntelStats(), loadIPHistory(1)]);
    }

    async function loadIPIntelStats() {
        try {
            const [statsRes, threatRes] = await Promise.all([
                fetch('/api/dashboard/ip-stats/summary'),
                fetch('/api/threat-intel/stats')
            ]);
            const statsData = await statsRes.json();
            const threatData = await threatRes.json();

            const el = id => document.getElementById(id);

            if (statsData.success && statsData.data) {
                const s = statsData.data.summary;
                if (el('ipi-stat-total')) el('ipi-stat-total').textContent = (s.total_ips || 0).toLocaleString();
                if (el('ipi-stat-blocked')) el('ipi-stat-blocked').textContent = (s.currently_blocked_count || 0).toLocaleString();
            }

            if (threatData.success && threatData.stats) {
                const t = threatData.stats;
                if (el('ipi-stat-high-risk')) el('ipi-stat-high-risk').textContent = (t.high_threat_count || 0).toLocaleString();
                const c = t.classifications || {};
                const threats = (c.proxy_count || 0) + (c.vpn_count || 0) + (c.tor_count || 0);
                if (el('ipi-stat-threats')) el('ipi-stat-threats').textContent = threats.toLocaleString();
            }
        } catch (e) {
            console.error('Stats error:', e);
        }
    }

    async function loadIPHistory(page = 1) {
        const c = document.getElementById('ipi-history-list');
        const p = document.getElementById('ipi-pagination');
        if (!c) return;
        c.innerHTML = '<div class="ipi-loading">Loading...</div>';

        try {
            const search = document.getElementById('ipi-search')?.value || '';
            const riskLevel = document.getElementById('ipi-filter-risk')?.value || '';
            const blocked = document.getElementById('ipi-filter-blocked')?.value || '';

            const params = new URLSearchParams({ page, limit: 20 });
            if (search) params.append('search', search);
            if (riskLevel) params.append('risk_level', riskLevel);
            if (blocked) params.append('blocked', blocked);

            const res = await fetch(`/api/dashboard/ip-stats/list?${params}`);
            const data = await res.json();

            if (!data.success || !data.data?.length) {
                c.innerHTML = '<div class="ipi-empty"><div class="ipi-empty-icon">📭</div><div class="ipi-empty-text">No IP records found</div></div>';
                if (p) p.innerHTML = '';
                return;
            }

            c.innerHTML = `
                <table class="ipi-table">
                    <thead><tr>
                        <th>IP Address</th>
                        <th>Country</th>
                        <th>Events</th>
                        <th>Failed</th>
                        <th>Risk Score</th>
                        <th>Threat Level</th>
                        <th>Status</th>
                        <th style="text-align:right">Last Seen</th>
                    </tr></thead>
                    <tbody>
                        ${data.data.map(ip => {
                            const isPrivate = isPrivateIP(ip.ip_address_text);
                            const riskScore = isPrivate ? 0 : Math.round(ip.avg_risk_score || 0);
                            const riskClass = isPrivate ? 'private' : getRiskClass(riskScore);
                            const countryDisplay = isPrivate ? '<span class="ipi-tag ipi-tag-private">Private</span>' : `<span class="country-cell"><span class="flag">${getFlag(ip.country_code)}</span>${escapeHtml(ip.country_name || 'Unknown')}</span>`;
                            return `<tr onclick="prefillIP('${escapeHtml(ip.ip_address_text)}')">
                                <td class="ip-cell">${escapeHtml(ip.ip_address_text)}</td>
                                <td>${countryDisplay}</td>
                                <td>${(ip.total_events || 0).toLocaleString()}</td>
                                <td style="color:${ip.failed_events > 0 ? '#ef4444' : 'var(--text-secondary)'}">${(ip.failed_events || 0).toLocaleString()}</td>
                                <td>${isPrivate ? '<span style="color:var(--text-secondary)">N/A</span>' : `<span style="font-weight:600;color:${getScoreColor(riskScore)}">${riskScore}%</span>`}</td>
                                <td><span class="ipi-tag ipi-tag-${riskClass}">${riskClass.charAt(0).toUpperCase() + riskClass.slice(1)}</span></td>
                                <td>${ip.currently_blocked ? '<span class="ipi-tag ipi-tag-blocked">Blocked</span>' : '<span style="color:var(--text-secondary)">-</span>'}</td>
                                <td style="text-align:right;color:var(--text-secondary)">${formatLocalDateTime(ip.last_seen)}</td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
            `;

            if (p && data.pagination) {
                const pg = data.pagination;
                if (pg.pages > 1) {
                    let btns = '';
                    const start = Math.max(1, pg.page - 2);
                    const end = Math.min(pg.pages, start + 4);
                    for (let i = start; i <= end; i++) {
                        btns += `<button class="${i === pg.page ? 'active' : ''}" onclick="loadIPHistory(${i})">${i}</button>`;
                    }
                    p.innerHTML = `
                        <div class="ipi-pagination">
                            <div class="ipi-pagination-info">Showing ${(pg.page-1)*pg.limit+1}-${Math.min(pg.page*pg.limit, pg.total)} of ${pg.total}</div>
                            <div class="ipi-pagination-btns">
                                <button ${pg.page === 1 ? 'disabled' : ''} onclick="loadIPHistory(1)">«</button>
                                <button ${pg.page === 1 ? 'disabled' : ''} onclick="loadIPHistory(${pg.page-1})">‹</button>
                                ${btns}
                                <button ${pg.page === pg.pages ? 'disabled' : ''} onclick="loadIPHistory(${pg.page+1})">›</button>
                                <button ${pg.page === pg.pages ? 'disabled' : ''} onclick="loadIPHistory(${pg.pages})">»</button>
                            </div>
                        </div>
                    `;
                } else {
                    p.innerHTML = `<div class="ipi-pagination"><div class="ipi-pagination-info">Total: ${pg.total} records</div></div>`;
                }
            }
        } catch (e) {
            console.error('IP history error:', e);
            c.innerHTML = '<div class="ipi-error">Error loading IP history</div>';
        }
    }

    function prefillIP(ip) {
        const input = document.getElementById('ipi-search-input');
        if (input) {
            input.value = ip;
            analyzeIP();
        }
    }

    async function analyzeIP() {
        const input = document.getElementById('ipi-search-input');
        const r = document.getElementById('ipi-analysis-result');
        if (!input || !r) return;

        const ip = input.value.trim();
        if (!ip) {
            r.innerHTML = `<div style="color:${TC.danger};font-size:13px;padding:10px">Please enter an IP address</div>`;
            return;
        }

        // Check for private IP first
        if (isPrivateIP(ip)) {
            const privateInfo = getPrivateIPType(ip);
            r.innerHTML = `
                <div class="ipi-result ipi-result-private">
                    <div class="ipi-result-header" style="background:linear-gradient(to right, ${TC.successBg}, ${TC.successBg});">
                        <div class="ipi-result-ip-info">
                            <span class="ipi-result-flag">🏠</span>
                            <div>
                                <div class="ipi-result-ip">${escapeHtml(ip)}</div>
                                <div class="ipi-result-location">Private / Internal Network</div>
                            </div>
                        </div>
                        <div class="ipi-result-badges">
                            <span class="ipi-badge ipi-badge-private">Private IP</span>
                            <span class="ipi-badge ipi-badge-safe">Safe</span>
                        </div>
                    </div>
                    <div class="ipi-result-sections">
                        <div class="ipi-result-section">
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                                Private IP Information
                            </div>
                            <div class="ipi-data-grid">
                                <div class="ipi-data-item"><strong>IP Address</strong>${escapeHtml(ip)}</div>
                                <div class="ipi-data-item"><strong>Type</strong>${escapeHtml(privateInfo.type)}</div>
                                <div class="ipi-data-item"><strong>Range</strong><code style="background:${TC.surfaceAlt};padding:2px 6px;border-radius:4px;font-size:12px">${escapeHtml(privateInfo.range)}</code></div>
                                <div class="ipi-data-item"><strong>Typical Usage</strong>${escapeHtml(privateInfo.usage)}</div>
                            </div>
                        </div>
                        <div class="ipi-result-section">
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
                                About Private IPs
                            </div>
                            <div style="font-size:13px;color:var(--text-secondary);line-height:1.6">
                                <p style="margin:0 0 10px 0">This is a <strong>private IP address</strong> reserved for internal network use (RFC 1918). Private IPs:</p>
                                <ul style="margin:0;padding-left:20px">
                                    <li>Cannot be routed on the public internet</li>
                                    <li>Are used within local networks (home, office, data center)</li>
                                    <li>Are not tracked by external threat intelligence services</li>
                                    <li>Require NAT to communicate with the internet</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            // Still try to get local stats if this IP has events in the system
            try {
                const statsRes = await fetch(`/api/dashboard/ip-stats/${encodeURIComponent(ip)}`);
                const statsData = await statsRes.json();
                if (statsData.success && statsData.data?.statistics) {
                    const stats = statsData.data.statistics;
                    const events = statsData.data.recent_events || [];
                    // Append local activity section
                    const sectionsContainer = r.querySelector('.ipi-result-sections');
                    if (sectionsContainer && (stats.total_events > 0 || events.length > 0)) {
                        const activitySection = document.createElement('div');
                        activitySection.className = 'ipi-result-section';
                        activitySection.innerHTML = `
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20V10M18 20V4M6 20v-4"/></svg>
                                Local Activity
                            </div>
                            <div class="ipi-data-grid">
                                <div class="ipi-data-item"><strong>Total Events</strong>${(stats.total_events || 0).toLocaleString()}</div>
                                <div class="ipi-data-item"><strong>Failed Attempts</strong><span style="color:${TC.danger}">${(stats.failed_events || 0).toLocaleString()}</span></div>
                                <div class="ipi-data-item"><strong>First Seen</strong>${formatLocalDateTime(stats.first_seen)}</div>
                                <div class="ipi-data-item"><strong>Last Seen</strong>${formatLocalDateTime(stats.last_seen)}</div>
                            </div>
                            ${events.length > 0 ? `
                            <div class="ipi-event-list" style="margin-top:12px">
                                ${events.slice(0, 5).map(e => `
                                    <div class="ipi-event-item">
                                        <div>
                                            <span class="ipi-event-type ${e.event_type === 'failed' ? 'ipi-event-failed' : 'ipi-event-successful'}">${e.event_type}</span>
                                            <span style="margin-left:8px;color:var(--text-secondary)">@${escapeHtml(e.username || 'unknown')}</span>
                                        </div>
                                        <span style="color:var(--text-secondary);font-size:12px">${formatLocalDateTime(e.event_timestamp)}</span>
                                    </div>
                                `).join('')}
                            </div>
                            ` : ''}
                        `;
                        sectionsContainer.appendChild(activitySection);
                    }
                }
            } catch (e) {
                // Ignore errors for local stats lookup
            }
            return;
        }

        r.innerHTML = '<div class="ipi-loading">Analyzing IP...</div>';

        try {
            // Fetch all data in parallel
            const [statsRes, threatRes, geoRes] = await Promise.all([
                fetch(`/api/dashboard/ip-stats/${encodeURIComponent(ip)}`),
                fetch(`/api/threat-intel/lookup/${encodeURIComponent(ip)}`),
                fetch(`/api/geoip/lookup/${encodeURIComponent(ip)}`)
            ]);

            const statsData = await statsRes.json();
            const threatData = await threatRes.json();
            const geoData = await geoRes.json();

            // If none found, show not found with enrich option
            if (!statsData.success && !threatData.success && !geoData.success) {
                r.innerHTML = `
                    <div class="ipi-not-found">
                        <div class="ipi-not-found-icon">🔍</div>
                        <div class="ipi-not-found-title">IP Not Found</div>
                        <div class="ipi-not-found-text">This IP address is not in the database. Click "Enrich" to fetch data from external APIs.</div>
                        <button class="ipi-btn ipi-btn-primary" onclick="enrichIP()">Enrich IP</button>
                    </div>
                `;
                return;
            }

            // Build result from available data
            const geo = geoData.data || threatData.data || {};
            const stats = statsData.data?.statistics || {};
            const events = statsData.data?.recent_events || [];
            const blockHistory = statsData.data?.blocking_history || [];
            const hasLocalActivity = statsData.success && stats.total_events > 0;

            // Calculate ML scores - use consistent fallback to threat intel
            const abuseScore = geo.abuseipdb_score || 0;
            const vtScore = geo.virustotal_positives ? Math.min(geo.virustotal_positives * 10, 100) : 0;
            const threatIntelScore = Math.max(abuseScore, vtScore);

            // If we have local ML data, use it; otherwise fall back to threat intel
            const avgRiskScore = hasLocalActivity ? Math.round((stats.avg_risk_score || 0) * 100) : threatIntelScore;
            const maxRiskScore = hasLocalActivity ? Math.round((stats.max_risk_score || 0) * 100) : threatIntelScore;
            const riskScore = Math.max(avgRiskScore, maxRiskScore);
            const riskClass = getRiskClass(riskScore);

            // Calculate network risk score
            const networkRiskFactors = [];
            let networkRiskScore = 0;
            if (geo.is_proxy) { networkRiskScore += 25; networkRiskFactors.push('Proxy'); }
            if (geo.is_vpn) { networkRiskScore += 20; networkRiskFactors.push('VPN'); }
            if (geo.is_tor) { networkRiskScore += 35; networkRiskFactors.push('Tor Exit Node'); }
            if (geo.is_datacenter || geo.is_hosting) { networkRiskScore += 15; networkRiskFactors.push('Datacenter/Hosting'); }

            // Calculate geo risk (high-risk regions)
            const highRiskCountries = ['CN', 'RU', 'KP', 'IR', 'VN', 'PK', 'BD', 'ID', 'BR', 'IN'];
            const geoRiskScore = highRiskCountries.includes(geo.country_code) ? 20 : 0;

            // Build badges
            const badges = [];
            if (stats.currently_blocked) badges.push('<span class="ipi-badge ipi-badge-blocked">Blocked</span>');
            if (riskScore >= 70) badges.push('<span class="ipi-badge ipi-badge-high">High Risk</span>');
            else if (riskScore >= 40) badges.push('<span class="ipi-badge ipi-badge-medium">Medium Risk</span>');
            else badges.push('<span class="ipi-badge ipi-badge-low">Low Risk</span>');
            if (geo.is_proxy) badges.push('<span class="ipi-badge ipi-badge-proxy">Proxy</span>');
            if (geo.is_vpn) badges.push('<span class="ipi-badge ipi-badge-vpn">VPN</span>');
            if (geo.is_tor) badges.push('<span class="ipi-badge ipi-badge-tor">Tor</span>');

            const location = [geo.city, geo.region, geo.country_name].filter(Boolean).join(', ') || 'Unknown';

            r.innerHTML = `
                <div class="ipi-result">
                    <div class="ipi-result-header">
                        <div class="ipi-result-ip-info">
                            <span class="ipi-result-flag">${getFlag(geo.country_code)}</span>
                            <div>
                                <div class="ipi-result-ip">${escapeHtml(ip)}</div>
                                <div class="ipi-result-location">${escapeHtml(location)}</div>
                            </div>
                        </div>
                        <div class="ipi-result-badges">${badges.join('')}</div>
                    </div>
                    <div class="ipi-result-sections">
                        <!-- GeoIP Section -->
                        <div class="ipi-result-section">
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                                Geographic Data
                            </div>
                            <div class="ipi-data-grid">
                                <div class="ipi-data-item"><strong>Country</strong>${escapeHtml(geo.country_name || '-')}</div>
                                <div class="ipi-data-item"><strong>City</strong>${escapeHtml(geo.city || '-')}</div>
                                <div class="ipi-data-item"><strong>ISP</strong>${escapeHtml(geo.isp || '-')}</div>
                                <div class="ipi-data-item"><strong>ASN</strong>${geo.asn || '-'}</div>
                            </div>
                        </div>

                        <!-- Threat Intel Section -->
                        <div class="ipi-result-section">
                            <div class="ipi-section-title" style="display:flex;justify-content:space-between;align-items:center">
                                <span style="display:flex;align-items:center;gap:8px">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                                    Threat Intelligence
                                </span>
                                <button class="ipi-btn ipi-btn-secondary" style="padding:4px 10px;font-size:11px" onclick="refreshIPThreatIntel('${escapeHtml(ip)}')">🔄 Refresh</button>
                            </div>
                            <div class="ipi-data-grid" id="ipi-threat-grid">
                                <div class="ipi-data-item">
                                    <strong>AbuseIPDB Score</strong>
                                    <span style="font-weight:600;color:${getScoreColor(geo.abuseipdb_score || 0)}">${geo.abuseipdb_score || 0}%</span>
                                    <div class="ipi-score-bar"><div class="ipi-score-fill" style="width:${geo.abuseipdb_score || 0}%;background:${getScoreColor(geo.abuseipdb_score || 0)}"></div></div>
                                </div>
                                <div class="ipi-data-item"><strong>Reports</strong>${(geo.abuseipdb_reports || 0).toLocaleString()}</div>
                                <div class="ipi-data-item"><strong>VirusTotal</strong>${geo.virustotal_positives || 0}/${geo.virustotal_total || 0}</div>
                                <div class="ipi-data-item"><strong>Threat Level</strong><span class="ipi-tag ipi-tag-${riskClass}">${geo.threat_level || riskClass}</span></div>
                                ${(() => {
                                    const shodanPorts = geo.shodan_ports ? (Array.isArray(geo.shodan_ports) ? geo.shodan_ports : JSON.parse(geo.shodan_ports || '[]')) : [];
                                    const shodanVulns = geo.shodan_vulns ? (Array.isArray(geo.shodan_vulns) ? geo.shodan_vulns : JSON.parse(geo.shodan_vulns || '[]')) : [];
                                    if (shodanPorts.length > 0 || shodanVulns.length > 0) {
                                        return `
                                            <div class="ipi-data-item" style="grid-column:span 2">
                                                <strong>Shodan</strong>
                                                <div style="font-size:12px;margin-top:4px">
                                                    ${shodanPorts.length > 0 ? `<span>Ports: ${shodanPorts.slice(0, 8).join(', ')}${shodanPorts.length > 8 ? '...' : ''}</span>` : ''}
                                                    ${shodanVulns.length > 0 ? `<span style="color:${TC.danger};margin-left:12px">⚠️ ${shodanVulns.length} vulnerabilities</span>` : ''}
                                                </div>
                                            </div>
                                        `;
                                    }
                                    return '';
                                })()}
                            </div>
                        </div>

                        <!-- ML Analysis Section -->
                        <div class="ipi-result-section">
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l3 7h7l-6 5 3 7-7-5-7 5 3-7-6-5h7z"/></svg>
                                Risk Analysis
                            </div>
                            ${!hasLocalActivity ? `
                                <div style="font-size:11px;color:var(--text-hint);margin-bottom:8px;padding:6px 10px;background:rgba(var(--info-rgb),0.1);border-radius:4px">
                                    ℹ️ No local events recorded. Scores based on threat intelligence data.
                                </div>
                            ` : ''}
                            <div class="ipi-data-grid">
                                <div class="ipi-data-item">
                                    <strong>Composite Risk</strong>
                                    <span style="font-weight:600;color:${getScoreColor(riskScore)}">${riskScore}%</span>
                                    <div class="ipi-score-bar"><div class="ipi-score-fill" style="width:${riskScore}%;background:${getScoreColor(riskScore)}"></div></div>
                                </div>
                                <div class="ipi-data-item"><strong>Peak Risk</strong><span style="color:${getScoreColor(maxRiskScore)}">${maxRiskScore}%</span></div>
                                <div class="ipi-data-item"><strong>Network Risk</strong><span style="color:${getScoreColor(networkRiskScore)}">${networkRiskScore}%</span></div>
                                <div class="ipi-data-item"><strong>Geo Risk</strong><span style="color:${getScoreColor(geoRiskScore)}">${geoRiskScore > 0 ? geoRiskScore + '%' : 'Low'}</span></div>
                            </div>
                            <div class="ipi-ml-recommendation ${riskScore >= 50 ? 'threat' : 'safe'}">
                                <strong style="font-size:12px">${riskScore >= 50 ? '⚠️ Recommendation: Block' : '✓ Recommendation: Allow'}</strong>
                                <div style="font-size:12px;margin-top:4px;color:var(--text-secondary)">
                                    ${riskScore >= 70 ? 'High-risk IP with suspicious activity patterns. Consider immediate blocking.' :
                                      riskScore >= 40 ? 'Moderate risk detected. Monitor closely for further suspicious behavior.' :
                                      'Low risk IP. No immediate action required.'}
                                </div>
                            </div>
                        </div>

                        <!-- Network Analysis Section -->
                        <div class="ipi-result-section">
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="5" r="3"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="6" cy="17" r="3"/><circle cx="18" cy="17" r="3"/><line x1="12" y1="12" x2="6" y2="14"/><line x1="12" y1="12" x2="18" y2="14"/></svg>
                                Network Analysis
                            </div>
                            <div class="ipi-data-grid">
                                <div class="ipi-data-item"><strong>ASN</strong>${geo.asn ? `AS${geo.asn}` : '-'}</div>
                                <div class="ipi-data-item"><strong>Organization</strong>${escapeHtml(geo.asn_org || geo.isp || '-')}</div>
                                <div class="ipi-data-item"><strong>Connection Type</strong>${escapeHtml(geo.connection_type || 'Unknown')}</div>
                                <div class="ipi-data-item"><strong>Network Flags</strong>${networkRiskFactors.length > 0 ? networkRiskFactors.map(f => `<span class="ipi-tag ipi-tag-warning">${f}</span>`).join(' ') : '<span style="color:var(--text-hint)">None</span>'}</div>
                            </div>
                        </div>

                        <!-- Activity Summary Section -->
                        <div class="ipi-result-section">
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20V10M18 20V4M6 20v-4"/></svg>
                                Activity Summary
                            </div>
                            ${hasLocalActivity ? `
                                <div class="ipi-data-grid">
                                    <div class="ipi-data-item"><strong>Total Events</strong>${(stats.total_events || 0).toLocaleString()}</div>
                                    <div class="ipi-data-item"><strong>Failed Attempts</strong><span style="color:${TC.danger}">${(stats.failed_events || 0).toLocaleString()}</span></div>
                                    <div class="ipi-data-item"><strong>Success Rate</strong>${stats.total_events ? Math.round((stats.successful_events || 0) / stats.total_events * 100) : 0}%</div>
                                    <div class="ipi-data-item"><strong>Times Blocked</strong>${stats.times_blocked || 0}</div>
                                    <div class="ipi-data-item"><strong>First Seen</strong>${formatLocalDateTime(stats.first_seen)}</div>
                                    <div class="ipi-data-item"><strong>Last Seen</strong>${formatLocalDateTime(stats.last_seen)}</div>
                                </div>
                            ` : `
                                <div style="text-align:center;padding:20px;color:var(--text-secondary);background:rgba(var(--surface-rgb),0.5);border-radius:6px">
                                    <div style="font-size:24px;margin-bottom:8px">📭</div>
                                    <div style="font-weight:500">No Local Activity</div>
                                    <div style="font-size:12px;margin-top:4px">This IP has not been seen in any authentication events on monitored servers.</div>
                                    <div style="font-size:11px;margin-top:8px;color:var(--text-hint)">Data shown is from external threat intelligence sources only.</div>
                                </div>
                            `}
                        </div>

                        <!-- Composite Score Breakdown -->
                        <div class="ipi-result-section">
                            <div class="ipi-section-title">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                                Score Breakdown
                            </div>
                            <div class="ipi-score-breakdown">
                                <div class="ipi-score-row">
                                    <span class="ipi-score-label">AbuseIPDB</span>
                                    <div class="ipi-score-bar-container">
                                        <div class="ipi-score-bar-bg">
                                            <div class="ipi-score-bar-fill" style="width:${abuseScore}%;background:${getScoreColor(abuseScore)}"></div>
                                        </div>
                                        <span class="ipi-score-value" style="color:${getScoreColor(abuseScore)}">${abuseScore}%</span>
                                    </div>
                                </div>
                                <div class="ipi-score-row">
                                    <span class="ipi-score-label">VirusTotal</span>
                                    <div class="ipi-score-bar-container">
                                        <div class="ipi-score-bar-bg">
                                            <div class="ipi-score-bar-fill" style="width:${vtScore}%;background:${getScoreColor(vtScore)}"></div>
                                        </div>
                                        <span class="ipi-score-value" style="color:${getScoreColor(vtScore)}">${geo.virustotal_positives || 0}/${geo.virustotal_total || 95}</span>
                                    </div>
                                </div>
                                <div class="ipi-score-row">
                                    <span class="ipi-score-label">Network Risk</span>
                                    <div class="ipi-score-bar-container">
                                        <div class="ipi-score-bar-bg">
                                            <div class="ipi-score-bar-fill" style="width:${networkRiskScore}%;background:${getScoreColor(networkRiskScore)}"></div>
                                        </div>
                                        <span class="ipi-score-value" style="color:${getScoreColor(networkRiskScore)}">${networkRiskScore}%</span>
                                    </div>
                                </div>
                                <div class="ipi-score-row">
                                    <span class="ipi-score-label">Geo Risk</span>
                                    <div class="ipi-score-bar-container">
                                        <div class="ipi-score-bar-bg">
                                            <div class="ipi-score-bar-fill" style="width:${geoRiskScore}%;background:${getScoreColor(geoRiskScore)}"></div>
                                        </div>
                                        <span class="ipi-score-value" style="color:${getScoreColor(geoRiskScore)}">${geoRiskScore}%</span>
                                    </div>
                                </div>
                                ${hasLocalActivity ? `
                                    <div class="ipi-score-row">
                                        <span class="ipi-score-label">Behavioral</span>
                                        <div class="ipi-score-bar-container">
                                            <div class="ipi-score-bar-bg">
                                                <div class="ipi-score-bar-fill" style="width:${avgRiskScore}%;background:${getScoreColor(avgRiskScore)}"></div>
                                            </div>
                                            <span class="ipi-score-value" style="color:${getScoreColor(avgRiskScore)}">${avgRiskScore}%</span>
                                        </div>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>

                    ${events.length > 0 ? `
                    <div class="ipi-result-section" style="border-top:1px solid var(--border)">
                        <div class="ipi-section-title">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                            Recent Events (${events.length})
                        </div>
                        <div class="ipi-event-list">
                            ${events.slice(0, 10).map(e => `
                                <div class="ipi-event-item">
                                    <div>
                                        <span class="ipi-event-type ${e.event_type === 'failed' ? 'ipi-event-failed' : 'ipi-event-successful'}">${e.event_type}</span>
                                        <span style="margin-left:8px;color:var(--text-secondary)">@${escapeHtml(e.username || 'unknown')}</span>
                                        ${e.server_name ? `<span style="margin-left:8px;font-size:11px;color:var(--text-hint)">on ${escapeHtml(e.server_name)}</span>` : ''}
                                    </div>
                                    <span style="color:var(--text-secondary);font-size:12px">${formatLocalDateTime(e.event_timestamp)}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
            `;
        } catch (e) {
            console.error('Analysis error:', e);
            r.innerHTML = '<div class="ipi-error">Analysis failed. Please try again.</div>';
        }
    }

    async function enrichIP() {
        const input = document.getElementById('ipi-search-input');
        const r = document.getElementById('ipi-analysis-result');
        if (!input || !r) return;

        const ip = input.value.trim();
        if (!ip) return;

        // Check if it's a private IP - can't enrich from external APIs
        if (isPrivateIP(ip)) {
            r.innerHTML = `
                <div class="ipi-not-found" style="background:${TC.primaryBg};border-color:${TC.primary}">
                    <div class="ipi-not-found-icon">🏠</div>
                    <div class="ipi-not-found-title" style="color:${TC.primary}">Private IP Address</div>
                    <div class="ipi-not-found-text">Private IP addresses cannot be enriched from external APIs (AbuseIPDB, VirusTotal, etc.) as they are not routable on the public internet.</div>
                    <button class="ipi-btn ipi-btn-secondary" onclick="analyzeIP()">View Local Data</button>
                </div>
            `;
            return;
        }

        r.innerHTML = '<div class="ipi-loading">Enriching IP from external APIs...</div>';

        try {
            // Call both enrich endpoints
            const [geoRes, threatRes] = await Promise.all([
                fetch(`/api/geoip/enrich/${encodeURIComponent(ip)}`, { method: 'POST' }),
                fetch(`/api/threat-intel/enrich/${encodeURIComponent(ip)}`, { method: 'POST' })
            ]);

            const geoData = await geoRes.json();
            const threatData = await threatRes.json();

            if (geoData.success || threatData.success) {
                // Reload stats and show analysis
                loadIPIntelStats();
                loadIPHistory(1);
                analyzeIP();
            } else {
                // Show detailed error
                let errorMsg = '';
                if (geoData.error) errorMsg += `GeoIP: ${geoData.error}`;
                if (threatData.error) errorMsg += (errorMsg ? '<br>' : '') + `Threat Intel: ${threatData.error}`;

                r.innerHTML = `
                    <div class="ipi-not-found" style="background:${TC.dangerBg};border-color:${TC.danger}">
                        <div class="ipi-not-found-icon">⚠️</div>
                        <div class="ipi-not-found-title" style="color:${TC.danger}">Enrichment Failed</div>
                        <div class="ipi-not-found-text">${errorMsg || 'Could not fetch data from external APIs. This may be due to API rate limits, missing API keys, or network issues.'}</div>
                        <div style="margin-top:12px;display:flex;gap:8px;justify-content:center">
                            <button class="ipi-btn ipi-btn-primary" onclick="enrichIP()">Retry</button>
                            <button class="ipi-btn ipi-btn-secondary" onclick="analyzeIP()">View Cached Data</button>
                        </div>
                    </div>
                `;
            }
        } catch (e) {
            console.error('Enrich error:', e);
            r.innerHTML = `
                <div class="ipi-not-found" style="background:${TC.dangerBg};border-color:${TC.danger}">
                    <div class="ipi-not-found-icon">❌</div>
                    <div class="ipi-not-found-title" style="color:${TC.danger}">Network Error</div>
                    <div class="ipi-not-found-text">Could not connect to the enrichment API. Please check your network connection and try again.</div>
                    <button class="ipi-btn ipi-btn-primary" onclick="enrichIP()">Retry</button>
                </div>
            `;
        }
    }

    async function refreshIPThreatIntel(ipAddress) {
        const grid = document.getElementById('ipi-threat-grid');
        if (!grid) return;

        const originalContent = grid.innerHTML;
        grid.innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-secondary)">🔄 Refreshing threat intel...</div>';

        try {
            // Call the threat intel lookup endpoint
            const response = await fetch(`/api/threat-intel/lookup/${encodeURIComponent(ipAddress)}`);
            const data = await response.json();

            if (data.success && data.data) {
                const threat = data.data;
                const abuseScore = threat.abuseipdb_score || 0;
                const vtPositives = threat.virustotal_positives || 0;
                const vtTotal = threat.virustotal_total || 0;
                const shodanPorts = threat.shodan_ports ? (Array.isArray(threat.shodan_ports) ? threat.shodan_ports : JSON.parse(threat.shodan_ports || '[]')) : [];
                const shodanVulns = threat.shodan_vulns ? (Array.isArray(threat.shodan_vulns) ? threat.shodan_vulns : JSON.parse(threat.shodan_vulns || '[]')) : [];
                const threatLevel = threat.threat_level || threat.overall_threat_level || 'unknown';

                const shodanSection = (shodanPorts.length > 0 || shodanVulns.length > 0) ? `
                    <div class="ipi-data-item" style="grid-column:span 2">
                        <strong>Shodan</strong>
                        <div style="font-size:12px;margin-top:4px">
                            ${shodanPorts.length > 0 ? `<span>Ports: ${shodanPorts.slice(0, 8).join(', ')}${shodanPorts.length > 8 ? '...' : ''}</span>` : ''}
                            ${shodanVulns.length > 0 ? `<span style="color:${TC.danger};margin-left:12px">⚠️ ${shodanVulns.length} vulnerabilities</span>` : ''}
                        </div>
                    </div>
                ` : '';

                grid.innerHTML = `
                    <div class="ipi-data-item">
                        <strong>AbuseIPDB Score</strong>
                        <span style="font-weight:600;color:${getScoreColor(abuseScore)}">${abuseScore}%</span>
                        <div class="ipi-score-bar"><div class="ipi-score-fill" style="width:${abuseScore}%;background:${getScoreColor(abuseScore)}"></div></div>
                    </div>
                    <div class="ipi-data-item"><strong>Reports</strong>${(threat.abuseipdb_reports || 0).toLocaleString()}</div>
                    <div class="ipi-data-item"><strong>VirusTotal</strong>${vtPositives}/${vtTotal}</div>
                    <div class="ipi-data-item"><strong>Threat Level</strong><span class="ipi-tag ipi-tag-${getRiskClass(abuseScore)}">${threatLevel}</span></div>
                    ${shodanSection}
                `;

                if (typeof showNotification === 'function') {
                    showNotification('Threat intelligence refreshed', 'success');
                }
            } else {
                grid.innerHTML = originalContent;
                if (typeof showNotification === 'function') {
                    showNotification(data.error || 'Failed to refresh', 'error');
                }
            }
        } catch (error) {
            console.error('Error refreshing threat intel:', error);
            grid.innerHTML = originalContent;
            if (typeof showNotification === 'function') {
                showNotification('Failed to refresh: ' + error.message, 'error');
            }
        }
    }

    // Export functions
    window.loadIPIntelPage = loadIPIntelPage;
    window.loadIPHistory = loadIPHistory;
    window.analyzeIP = analyzeIP;
    window.enrichIP = enrichIP;
    window.prefillIP = prefillIP;
    window.refreshIPThreatIntel = refreshIPThreatIntel;
})();
