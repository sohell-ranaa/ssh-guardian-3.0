/**
 * SSH Guardian v3.0 - Event Actions Analysis Module
 * IP analysis modal with tabbed interface and ML reasoning integration
 */

(function() {
    'use strict';

    // Use shared escapeHtml from utils.js
    const escapeHtml = window.escapeHtml || (s => s);

    /**
     * Check IP status
     */
    window.checkIpStatus = async function(ipAddress) {
        if (!ipAddress) return null;
        try {
            const response = await fetch(`/api/dashboard/event-actions/ip-status/${encodeURIComponent(ipAddress)}`);
            const data = await response.json();
            return data.success ? data : null;
        } catch (error) {
            console.error('Error checking IP status:', error);
            return null;
        }
    };

    /**
     * Fetch IP geolocation info
     */
    window.fetchIpInfo = async function(ipAddress) {
        try {
            const response = await fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ipAddress)}`);
            const data = await response.json();
            return data.success ? data : null;
        } catch (error) {
            console.error('Error fetching IP info:', error);
            return null;
        }
    };

    /**
     * Show IP Details modal with tabbed interface
     */
    window.showIpDetails = async function(ipAddress) {
        if (!ipAddress) {
            showToast('No IP address provided', 'error');
            return;
        }

        const loadingOverlay = showCenteredLoader(`Analyzing ${ipAddress}...`);

        try {
            const response = await fetch(`/api/demo/ip-analysis/${encodeURIComponent(ipAddress)}`);
            const data = await response.json();

            if (loadingOverlay) loadingOverlay.remove();

            if (!data.success) {
                showToast(`Failed to analyze IP: ${data.error || 'Unknown error'}`, 'error');
                return;
            }

            showAnalysisModal(ipAddress, data);

        } catch (error) {
            if (loadingOverlay) loadingOverlay.remove();
            console.error('Error loading IP analysis:', error);
            showToast('Error loading IP analysis', 'error');
        }
    };

    /**
     * Show the analysis modal with tabs
     */
    function showAnalysisModal(ip, data) {
        document.querySelectorAll('.ip-analysis-overlay').forEach(el => el.remove());

        const composite = data.composite_risk || {};
        const behavioral = data.behavioral_analysis || {};
        const geoIntel = data.geographic_intelligence || {};
        const results = data.results || {};
        const threat = results.threat_intel || {};
        const ml = results.ml || {};
        const geo = results.geo || {};
        const history = results.history || {};
        const recommendations = results.recommendations || [];

        const threatLevel = (composite.threat_level || 'unknown').toLowerCase();
        const overallScore = Math.round(composite.overall_score || 0);

        const flagImg = geo.country_code
            ? `<img src="https://flagcdn.com/24x18/${geo.country_code.toLowerCase()}.png" alt="${geo.country_code}" onerror="this.style.display='none'">`
            : '';

        const overlay = document.createElement('div');
        overlay.className = 'ip-analysis-overlay';
        overlay.innerHTML = `
            <div class="ip-analysis-modal">
                <!-- Header -->
                <div class="ip-analysis-header">
                    <div class="ip-analysis-header-left">
                        <div class="ip-analysis-icon ${threatLevel}">
                            ${getIconForLevel(threatLevel)}
                        </div>
                        <div class="ip-analysis-title-group">
                            <h2>${escapeHtml(ip)}</h2>
                            <div class="ip-analysis-location">
                                ${flagImg}
                                <span>${escapeHtml(geo.city || 'Unknown')}, ${escapeHtml(geo.country || 'Unknown')}</span>
                                ${geo.isp ? `<span class="isp-name">• ${escapeHtml(geo.isp)}</span>` : ''}
                            </div>
                        </div>
                    </div>
                    <div class="header-actions">
                        <div class="quick-score ${threatLevel}">
                            <span class="score-value">${overallScore}</span>
                            <span class="score-label">${threatLevel}</span>
                        </div>
                        <button class="ip-analysis-close">&times;</button>
                    </div>
                </div>

                <!-- Tabs -->
                <div class="analysis-tabs">
                    <button class="analysis-tab active" data-tab="overview">
                        <span class="tab-icon">📊</span>
                        <span>Overview</span>
                    </button>
                    <button class="analysis-tab" data-tab="ml-analysis">
                        <span class="tab-icon">🧠</span>
                        <span>ML Analysis</span>
                    </button>
                    <button class="analysis-tab" data-tab="threat-intel">
                        <span class="tab-icon">🛡️</span>
                        <span>Threat Intel</span>
                    </button>
                    <button class="analysis-tab" data-tab="behavioral">
                        <span class="tab-icon">🔍</span>
                        <span>Behavioral</span>
                    </button>
                    <button class="analysis-tab" data-tab="recommendations">
                        <span class="tab-icon">💡</span>
                        <span>Actions</span>
                    </button>
                </div>

                <!-- Tab Content -->
                <div class="ip-analysis-body">
                    ${buildOverviewTab(composite, geo, history, threat)}
                    ${buildMLAnalysisTab(ml, composite, behavioral)}
                    ${buildThreatIntelTab(threat, geo)}
                    ${buildBehavioralTab(behavioral, history)}
                    ${buildRecommendationsTab(recommendations, ip)}
                </div>
            </div>
        `;

        // Event handlers
        const closeModal = () => {
            overlay.remove();
            document.removeEventListener('keydown', keyHandler);
        };

        overlay.querySelector('.ip-analysis-close').onclick = closeModal;

        const keyHandler = (e) => {
            if (e.key === 'Escape') closeModal();
        };
        document.addEventListener('keydown', keyHandler);

        overlay.onclick = (e) => {
            if (e.target === overlay) closeModal();
        };

        // Tab switching
        overlay.querySelectorAll('.analysis-tab').forEach(tab => {
            tab.onclick = () => {
                overlay.querySelectorAll('.analysis-tab').forEach(t => t.classList.remove('active'));
                overlay.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                tab.classList.add('active');
                const content = overlay.querySelector(`#tab-${tab.dataset.tab}`);
                if (content) content.classList.add('active');
            };
        });

        document.body.appendChild(overlay);
    }

    function getIconForLevel(level) {
        const icons = {
            critical: '🚨',
            high: '⚠️',
            moderate: '⚡',
            low: '✓',
            clean: '✅',
            unknown: '❓'
        };
        return icons[level] || icons.unknown;
    }

    /**
     * Overview Tab
     */
    function buildOverviewTab(composite, geo, history, threat) {
        const breakdown = composite.breakdown || {};
        const threatLevel = (composite.threat_level || 'unknown').toLowerCase();
        const overallScore = Math.round(composite.overall_score || 0);
        const confidence = Math.round(composite.confidence || 0);

        const networkFlags = [];
        if (geo.is_tor) networkFlags.push({ type: 'tor', label: 'TOR' });
        if (geo.is_vpn) networkFlags.push({ type: 'vpn', label: 'VPN' });
        if (geo.is_proxy) networkFlags.push({ type: 'proxy', label: 'PROXY' });
        if (geo.is_datacenter) networkFlags.push({ type: 'datacenter', label: 'DATACENTER' });

        return `
            <div id="tab-overview" class="tab-content active">
                <!-- Risk Score Hero -->
                <div class="overview-hero ${threatLevel}">
                    <div class="hero-left">
                        <div class="hero-title">Composite Risk Assessment</div>
                        <div class="hero-description">${getRiskDescription(threatLevel)}</div>
                        ${networkFlags.length > 0 ? `
                            <div class="network-flags">
                                ${networkFlags.map(f => `<span class="network-flag ${f.type}">${f.label}</span>`).join('')}
                            </div>
                        ` : ''}
                    </div>
                    <div class="hero-right">
                        <div class="score-circle ${threatLevel}">
                            <span class="score-number">${overallScore}</span>
                            <span class="score-level">${threatLevel.toUpperCase()}</span>
                        </div>
                        <div class="confidence-text">${confidence}% confidence</div>
                    </div>
                </div>

                <!-- Risk Breakdown -->
                <div class="section-card">
                    <div class="section-header-row">
                        <span class="section-icon blue">📊</span>
                        <h3>Risk Factor Breakdown</h3>
                    </div>
                    <div class="breakdown-grid">
                        ${buildBreakdownCard('Threat Intel', breakdown.threat_intel, 'threat-intel')}
                        ${buildBreakdownCard('ML Prediction', breakdown.ml_prediction, 'ml')}
                        ${buildBreakdownCard('Behavioral', breakdown.behavioral, 'behavioral')}
                        ${buildBreakdownCard('Geographic', breakdown.geographic, 'geographic')}
                    </div>
                </div>

                <!-- Quick Stats -->
                <div class="section-card">
                    <div class="section-header-row">
                        <span class="section-icon green">📈</span>
                        <h3>Activity Summary</h3>
                    </div>
                    <div class="stats-row">
                        <div class="stat-box">
                            <div class="stat-value info">${history.total_events || 0}</div>
                            <div class="stat-label">Total Events</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value danger">${history.failed_attempts || 0}</div>
                            <div class="stat-label">Failed</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value success">${history.successful_logins || 0}</div>
                            <div class="stat-label">Success</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-value warning">${threat.abuseipdb_score || 0}%</div>
                            <div class="stat-label">AbuseIPDB</div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function buildBreakdownCard(label, data, type) {
        const score = Math.round((data?.score || 0));
        const weight = Math.round((data?.weight || 0) * 100);
        return `
            <div class="breakdown-card ${type}">
                <div class="breakdown-score">${score}</div>
                <div class="breakdown-label">${label}</div>
                <div class="breakdown-weight">Weight: ${weight}%</div>
                <div class="breakdown-bar">
                    <div class="breakdown-bar-fill" style="width: ${Math.min(score, 100)}%"></div>
                </div>
            </div>
        `;
    }

    /**
     * ML Analysis Tab - Detailed reasoning
     */
    function buildMLAnalysisTab(ml, composite, behavioral) {
        const riskScore = Math.round(ml.risk_score || 0);
        const confidence = Math.round((ml.confidence || 0) * 100);
        const threatType = ml.threat_type || 'Unknown';
        const isAnomaly = ml.is_anomaly || false;

        // Get risk factors from behavioral analysis
        const riskFactors = behavioral.risk_factors || ml.risk_factors || [];
        const indicators = behavioral.indicators || [];

        // Build risk factors section using shared component if available
        let riskFactorsHtml = '';
        if (window.MLReasoning && riskFactors.length > 0) {
            riskFactorsHtml = window.MLReasoning.renderMLFactors(riskFactors, { compact: false });
        } else if (riskFactors.length > 0) {
            riskFactorsHtml = riskFactors.map(f => `
                <div class="ml-factor-row">
                    <div class="factor-info">
                        <span class="factor-icon">${getFactorIcon(f.type)}</span>
                        <div class="factor-details">
                            <div class="factor-title">${escapeHtml(f.title || formatFactorType(f.type))}</div>
                            <div class="factor-description">${escapeHtml(f.description || '')}</div>
                        </div>
                    </div>
                    <div class="factor-score ${getScoreClass(f.score)}">+${f.score || 0}</div>
                </div>
            `).join('');
        } else {
            riskFactorsHtml = `
                <div class="empty-state">
                    <span class="empty-icon">✓</span>
                    <span>No significant risk factors detected</span>
                </div>
            `;
        }

        return `
            <div id="tab-ml-analysis" class="tab-content">
                <!-- ML Score Overview -->
                <div class="ml-hero">
                    <div class="ml-score-display">
                        <div class="ml-circle ${getScoreClass(riskScore)}">
                            <span class="ml-score-value">${riskScore}</span>
                        </div>
                        <div class="ml-score-meta">
                            <div class="ml-score-label">ML Risk Score</div>
                            <div class="ml-confidence">${confidence}% confidence</div>
                        </div>
                    </div>
                    <div class="ml-classification">
                        <div class="classification-label">Classification</div>
                        <div class="classification-value">${escapeHtml(threatType)}</div>
                        ${isAnomaly ? '<span class="anomaly-badge">ANOMALY DETECTED</span>' : ''}
                    </div>
                </div>

                <!-- Risk Factors -->
                <div class="section-card">
                    <div class="section-header-row">
                        <span class="section-icon purple">🔍</span>
                        <h3>Risk Factors Analysis</h3>
                        <span class="factor-count">${riskFactors.length} factors</span>
                    </div>
                    <div class="ml-factors-container">
                        ${riskFactorsHtml}
                    </div>
                </div>

                <!-- Behavioral Indicators -->
                ${indicators.length > 0 ? `
                    <div class="section-card">
                        <div class="section-header-row">
                            <span class="section-icon orange">⚡</span>
                            <h3>Behavioral Indicators</h3>
                        </div>
                        <div class="indicators-grid">
                            ${indicators.map(i => `<span class="indicator-chip">${escapeHtml(i)}</span>`).join('')}
                        </div>
                    </div>
                ` : ''}

                <!-- ML Model Info -->
                <div class="section-card subtle">
                    <div class="model-info">
                        <span>Model: SSH Guardian ML v3.0</span>
                        <span>Features: 47 behavioral + network signals</span>
                        <span>Updated: Real-time</span>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Threat Intelligence Tab
     */
    function buildThreatIntelTab(threat, geo) {
        const abuseScore = threat.abuseipdb_score || 0;
        const abuseReports = threat.abuseipdb_reports || 0;
        const vtPositives = threat.virustotal_positives || 0;
        const vtTotal = threat.virustotal_total || 70;
        const shodanPorts = Array.isArray(geo.shodan_ports) ? geo.shodan_ports : [];
        const shodanVulns = Array.isArray(geo.shodan_vulns) ? geo.shodan_vulns : [];

        return `
            <div id="tab-threat-intel" class="tab-content">
                <!-- AbuseIPDB -->
                <div class="intel-card-large">
                    <div class="intel-header">
                        <div class="intel-logo abuseipdb">AIP</div>
                        <div class="intel-title">
                            <h4>AbuseIPDB</h4>
                            <span class="intel-subtitle">Community-reported abuse data</span>
                        </div>
                        <div class="intel-score-large ${getScoreClass(abuseScore)}">${abuseScore}<span>/100</span></div>
                    </div>
                    <div class="intel-body">
                        <div class="intel-stat">
                            <span class="intel-stat-value">${abuseReports}</span>
                            <span class="intel-stat-label">Total Reports</span>
                        </div>
                        <div class="intel-bar-container">
                            <div class="intel-bar">
                                <div class="intel-bar-fill ${getScoreClass(abuseScore)}" style="width: ${abuseScore}%"></div>
                            </div>
                            <div class="intel-bar-labels">
                                <span>0 - Safe</span>
                                <span>100 - Malicious</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- VirusTotal -->
                <div class="intel-card-large">
                    <div class="intel-header">
                        <div class="intel-logo virustotal">VT</div>
                        <div class="intel-title">
                            <h4>VirusTotal</h4>
                            <span class="intel-subtitle">Multi-engine security scanning</span>
                        </div>
                        <div class="intel-score-large ${vtPositives > 5 ? 'danger' : vtPositives > 0 ? 'warning' : 'safe'}">${vtPositives}<span>/${vtTotal}</span></div>
                    </div>
                    <div class="intel-body">
                        <div class="intel-stat">
                            <span class="intel-stat-value">${vtPositives > 0 ? 'FLAGGED' : 'CLEAN'}</span>
                            <span class="intel-stat-label">${vtPositives} engines detected</span>
                        </div>
                    </div>
                </div>

                <!-- Shodan -->
                ${shodanPorts.length > 0 || shodanVulns.length > 0 ? `
                    <div class="intel-card-large">
                        <div class="intel-header">
                            <div class="intel-logo shodan">SH</div>
                            <div class="intel-title">
                                <h4>Shodan</h4>
                                <span class="intel-subtitle">Open ports and vulnerabilities</span>
                            </div>
                        </div>
                        <div class="intel-body">
                            ${shodanPorts.length > 0 ? `
                                <div class="shodan-section">
                                    <div class="shodan-label">Open Ports</div>
                                    <div class="shodan-ports">
                                        ${shodanPorts.slice(0, 10).map(p => `<span class="port-chip">${p}</span>`).join('')}
                                        ${shodanPorts.length > 10 ? `<span class="port-more">+${shodanPorts.length - 10}</span>` : ''}
                                    </div>
                                </div>
                            ` : ''}
                            ${shodanVulns.length > 0 ? `
                                <div class="shodan-section vulns">
                                    <div class="shodan-label danger">Vulnerabilities (${shodanVulns.length})</div>
                                    <div class="shodan-vulns">
                                        ${shodanVulns.slice(0, 5).map(v => `<span class="vuln-chip">${escapeHtml(v)}</span>`).join('')}
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                ` : ''}

                <!-- Network Info -->
                <div class="section-card">
                    <div class="section-header-row">
                        <span class="section-icon gray">🌐</span>
                        <h3>Network Information</h3>
                    </div>
                    <div class="network-grid">
                        <div class="network-item">
                            <span class="network-label">ASN</span>
                            <span class="network-value">${geo.asn ? `AS${geo.asn}` : '-'}</span>
                        </div>
                        <div class="network-item">
                            <span class="network-label">Organization</span>
                            <span class="network-value">${escapeHtml(geo.asn_org || geo.isp || '-')}</span>
                        </div>
                        <div class="network-item">
                            <span class="network-label">Connection Type</span>
                            <span class="network-value">${escapeHtml(geo.connection_type || 'Unknown')}</span>
                        </div>
                        <div class="network-item">
                            <span class="network-label">Timezone</span>
                            <span class="network-value">${escapeHtml(geo.timezone || '-')}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Behavioral Tab
     */
    function buildBehavioralTab(behavioral, history) {
        const pattern = behavioral.pattern || 'Unknown';
        const velocity = behavioral.velocity || 0;
        const failureRate = behavioral.failure_rate || 0;
        const uniqueUsers = behavioral.unique_usernames || 0;
        const indicators = behavioral.indicators || [];

        return `
            <div id="tab-behavioral" class="tab-content">
                <!-- Pattern Analysis -->
                <div class="behavioral-hero">
                    <div class="pattern-display">
                        <div class="pattern-icon">${getPatternIcon(pattern)}</div>
                        <div class="pattern-info">
                            <div class="pattern-label">Detected Pattern</div>
                            <div class="pattern-value">${escapeHtml(pattern)}</div>
                        </div>
                    </div>
                </div>

                <!-- Behavioral Metrics -->
                <div class="section-card">
                    <div class="section-header-row">
                        <span class="section-icon orange">📊</span>
                        <h3>Behavioral Metrics</h3>
                    </div>
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value ${velocity > 5 ? 'danger' : 'safe'}">${velocity}</div>
                            <div class="metric-label">Events/min</div>
                            <div class="metric-sublabel">Attack Velocity</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value ${failureRate > 80 ? 'danger' : 'warning'}">${failureRate}%</div>
                            <div class="metric-label">Failure Rate</div>
                            <div class="metric-sublabel">Login Attempts</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value ${uniqueUsers > 5 ? 'danger' : 'safe'}">${uniqueUsers}</div>
                            <div class="metric-label">Unique Users</div>
                            <div class="metric-sublabel">Targeted Accounts</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value info">${history.anomaly_count || 0}</div>
                            <div class="metric-label">Anomalies</div>
                            <div class="metric-sublabel">Detected</div>
                        </div>
                    </div>
                </div>

                <!-- Indicators -->
                <div class="section-card">
                    <div class="section-header-row">
                        <span class="section-icon purple">🏷️</span>
                        <h3>Risk Indicators</h3>
                    </div>
                    <div class="indicators-container">
                        ${indicators.length > 0
                            ? indicators.map(i => `<span class="indicator-tag">${escapeHtml(i)}</span>`).join('')
                            : '<span class="indicator-tag clean">No anomalous indicators</span>'
                        }
                    </div>
                </div>

                <!-- Timeline -->
                ${history.first_seen ? `
                    <div class="section-card">
                        <div class="section-header-row">
                            <span class="section-icon blue">🕐</span>
                            <h3>Activity Timeline</h3>
                        </div>
                        <div class="timeline-row">
                            <div class="timeline-item">
                                <span class="timeline-label">First Seen</span>
                                <span class="timeline-value">${formatDateTime(history.first_seen)}</span>
                            </div>
                            <div class="timeline-item">
                                <span class="timeline-label">Last Seen</span>
                                <span class="timeline-value">${formatDateTime(history.last_seen)}</span>
                            </div>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }

    /**
     * Recommendations Tab
     */
    function buildRecommendationsTab(recommendations, ip) {
        if (recommendations.length === 0) {
            return `
                <div id="tab-recommendations" class="tab-content">
                    <div class="empty-recommendations">
                        <div class="empty-icon">✓</div>
                        <div class="empty-title">No Immediate Actions Required</div>
                        <div class="empty-subtitle">Continue monitoring this IP for any suspicious activity</div>
                    </div>
                </div>
            `;
        }

        return `
            <div id="tab-recommendations" class="tab-content">
                <div class="recommendations-intro">
                    <span class="recommendations-count">${recommendations.length}</span> AI-powered recommendations based on analysis
                </div>

                <div class="recommendations-list">
                    ${recommendations.slice(0, 6).map((rec, idx) => {
                        const priority = (rec.priority || 'medium').toLowerCase();
                        const confidence = Math.round((rec.confidence || rec.ai_confidence || 0) * 100);
                        const whyList = (rec.why || rec.evidence || []).filter(w => w).slice(0, 3);

                        return `
                            <div class="recommendation-card ${priority}">
                                <div class="rec-header">
                                    <span class="rec-number">${idx + 1}</span>
                                    <div class="rec-title-group">
                                        <div class="rec-action">${escapeHtml(rec.action)}</div>
                                        <div class="rec-reason">${escapeHtml(rec.reason)}</div>
                                    </div>
                                    <div class="rec-meta">
                                        <span class="rec-priority ${priority}">${priority}</span>
                                        <span class="rec-confidence">${confidence}%</span>
                                    </div>
                                </div>
                                ${whyList.length > 0 ? `
                                    <div class="rec-evidence">
                                        ${whyList.map(w => `<div class="evidence-item">• ${escapeHtml(w)}</div>`).join('')}
                                    </div>
                                ` : ''}
                                ${rec.risk_if_ignored ? `
                                    <div class="rec-risk">
                                        <strong>Risk if ignored:</strong> ${escapeHtml(rec.risk_if_ignored)}
                                    </div>
                                ` : ''}
                            </div>
                        `;
                    }).join('')}
                </div>

                <!-- Quick Actions -->
                <div class="quick-actions">
                    <button class="quick-action-btn danger" onclick="window.quickBlock && window.quickBlock('${ip}')">
                        <span>🚫</span> Block IP
                    </button>
                    <button class="quick-action-btn warning" onclick="window.quickWatch && window.quickWatch('${ip}')">
                        <span>👁️</span> Watch IP
                    </button>
                    <button class="quick-action-btn success" onclick="window.quickWhitelist && window.quickWhitelist('${ip}')">
                        <span>✓</span> Whitelist
                    </button>
                </div>
            </div>
        `;
    }

    // Helper functions
    function getRiskDescription(level) {
        const descriptions = {
            critical: 'Immediate threat detected. This IP shows strong indicators of malicious activity.',
            high: 'High risk detected. Multiple threat indicators suggest this IP is likely malicious.',
            moderate: 'Elevated risk detected. Some suspicious patterns warrant investigation.',
            low: 'Minor concerns detected. Activity appears mostly benign.',
            clean: 'No significant threats detected. This IP appears to be safe.',
            unknown: 'Insufficient data to determine threat level.'
        };
        return descriptions[level] || descriptions.unknown;
    }

    function getFactorIcon(type) {
        const icons = {
            impossible_travel: '✈️',
            new_location: '📍',
            unusual_time: '🕐',
            new_ip_for_user: '🆕',
            rapid_attempts: '⚡',
            credential_stuffing: '🔑',
            brute_force: '💥',
            success_after_failures: '🎯',
            geo_mismatch: '🌍'
        };
        return icons[type] || '🔍';
    }

    function formatFactorType(type) {
        if (!type) return 'Unknown';
        return type.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    }

    function getScoreClass(score) {
        if (score >= 80) return 'danger';
        if (score >= 60) return 'warning';
        if (score >= 40) return 'moderate';
        return 'safe';
    }

    function getPatternIcon(pattern) {
        const patterns = {
            'Brute Force': '🔨',
            'Credential Stuffing': '🔑',
            'Dictionary Attack': '📖',
            'Distributed Attack': '🌐',
            'Unknown': '❓'
        };
        return patterns[pattern] || '🔍';
    }

    // formatDateTime - use shared utility from utils.js
    const formatDateTime = window.formatLocalDateTime;

})();
