/**
 * SSH Guardian v3.0 - Simulation Analysis
 * Analysis tab rendering with threat details
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Analysis = {
        populate(data) {
            console.log('[Analysis] Populating tab with data:', data);

            document.getElementById('analysis-empty-state').style.display = 'none';
            const content = document.getElementById('analysis-content');
            content.style.display = 'block';

            const composite = data.composite_risk || {};
            const behavioral = data.behavioral_analysis || {};
            const geo = data.geographic_intelligence || {};
            const ti = data.results?.threat_intel || {};
            const ml = data.results?.ml || {};
            const history = data.results?.history || {};
            const blocking = data.blocking || {};

            try {
                const html = `
                    ${this._renderBlockingBanner(blocking)}
                    ${this._renderCompositeRisk(composite, data.ip, behavioral.pattern)}
                    ${this._renderRiskBreakdown(composite.breakdown)}
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; margin-bottom: 24px;">
                        ${this._renderThreatIntel(ti)}
                        ${this._renderMLAnalysis(ml)}
                        ${this._renderBehavioral(behavioral)}
                        ${this._renderGeographic(geo, data.results?.geo)}
                    </div>
                    ${this._renderHistorical(history)}
                `;
                content.innerHTML = html;
            } catch (err) {
                console.error('[Analysis] Error rendering HTML:', err);
                content.innerHTML = `<div class="card" style="padding: 20px; background: #fee; color: #c00;">Error rendering analysis: ${err.message}</div>`;
            }
        },

        _renderBlockingBanner(blocking) {
            if (!blocking) return '';

            if (blocking.skipped) {
                return `<div class="card" style="padding: 16px; margin-bottom: 24px; background: linear-gradient(135deg, rgba(0, 120, 212, 0.15), rgba(0, 120, 212, 0.05)); border: 2px solid var(--azure-blue); border-radius: 12px;">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div style="width: 48px; height: 48px; border-radius: 50%; background: var(--azure-blue); display: flex; align-items: center; justify-content: center; font-size: 24px; flex-shrink: 0;">ℹ️</div>
                        <div style="flex: 1;"><h3 style="margin: 0 0 4px 0; font-size: 16px; font-weight: 700; color: var(--azure-blue);">ANALYSIS ONLY MODE</h3>
                        <div style="font-size: 13px; color: var(--text-secondary);">No blocking applied. Select an agent to enable auto-blocking.</div></div>
                    </div>
                </div>`;
            }

            const isAlreadyBlocked = blocking.success === false && blocking.message?.toLowerCase().includes('already blocked');
            if (isAlreadyBlocked) {
                return `<div class="card" style="padding: 20px; margin-bottom: 24px; background: linear-gradient(135deg, rgba(230, 165, 2, 0.15), rgba(230, 165, 2, 0.05)); border: 2px solid ${TC.warning}; border-radius: 12px;">
                    <div style="display: flex; align-items: center; gap: 16px;">
                        <div style="width: 60px; height: 60px; border-radius: 50%; background: ${TC.warning}; display: flex; align-items: center; justify-content: center; font-size: 32px; flex-shrink: 0;">⚠️</div>
                        <div style="flex: 1;"><h3 style="margin: 0 0 8px 0; font-size: 20px; font-weight: 700; color: ${TC.warning};">IP ALREADY BLOCKED</h3>
                        <div style="font-size: 14px; color: var(--text-primary); margin-bottom: 8px;">This IP is already in the block list.</div>
                        <span style="padding: 4px 10px; background: rgba(230, 165, 2, 0.2); border-radius: 4px; font-weight: 600;">🆔 Block ID: #${blocking.block_id || 'N/A'}</span></div>
                    </div>
                </div>`;
            }

            if (!blocking.blocked) return '';

            const rules = blocking.triggered_rules || [];
            const duration = blocking.adjusted_duration || blocking.base_duration || 0;
            let durationText = duration >= 10080 ? `${Math.round(duration / 10080)} week(s)` :
                              duration >= 1440 ? `${Math.round(duration / 1440)} day(s)` :
                              duration >= 60 ? `${Math.round(duration / 60)} hour(s)` : `${duration} minute(s)`;

            return `<div class="card" style="padding: 20px; margin-bottom: 24px; background: linear-gradient(135deg, rgba(209, 52, 56, 0.15), rgba(209, 52, 56, 0.05)); border: 2px solid ${TC.danger}; border-radius: 12px;">
                <div style="display: flex; align-items: center; gap: 16px;">
                    <div style="width: 60px; height: 60px; border-radius: 50%; background: ${TC.danger}; display: flex; align-items: center; justify-content: center; font-size: 32px; flex-shrink: 0;">🚫</div>
                    <div style="flex: 1;">
                        <h3 style="margin: 0 0 8px 0; font-size: 20px; font-weight: 700; color: ${TC.danger};">IP AUTO-BLOCKED</h3>
                        <div style="font-size: 14px; color: var(--text-primary); margin-bottom: 8px;">This IP was automatically blocked by the threat detection rules.</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 12px; font-size: 13px;">
                            <span style="padding: 4px 10px; background: rgba(209, 52, 56, 0.2); border-radius: 4px; font-weight: 600;">⏱️ Duration: ${durationText}</span>
                            <span style="padding: 4px 10px; background: rgba(209, 52, 56, 0.2); border-radius: 4px; font-weight: 600;">🆔 Block ID: #${blocking.block_id || 'N/A'}</span>
                        </div>
                        ${rules.length > 0 ? `<div style="margin-top: 12px;"><div style="font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px;">TRIGGERED RULES:</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 8px;">${rules.map(rule => `<span style="padding: 4px 10px; background: ${TC.danger}; color: white; border-radius: 4px; font-size: 12px; font-weight: 600;">${rule}</span>`).join('')}</div></div>` : ''}
                    </div>
                </div>
            </div>`;
        },

        _renderCompositeRisk(composite, ip, pattern) {
            const score = composite.overall_score || 0;
            const level = composite.threat_level || 'UNKNOWN';
            const confidence = composite.confidence || 0;
            const colors = { CRITICAL: TC.danger, HIGH: TC.warning, MODERATE: TC.primary, LOW: TC.success, CLEAN: TC.success };

            return `<div class="card" style="padding: 24px; margin-bottom: 24px; background: linear-gradient(135deg, var(--card-bg), var(--background));">
                <h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;"><span style="font-size: 20px;">🎯</span> Overall Threat Assessment</h3>
                <div style="display: grid; grid-template-columns: auto 1fr; gap: 24px; align-items: center;">
                    <div style="width: 140px; height: 140px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; border: 8px solid ${colors[level]}; background: var(--card-bg);">
                        <div style="font-size: 42px; font-weight: 700;">${score.toFixed(1)}</div>
                        <div style="font-size: 12px; color: var(--text-secondary); font-weight: 600;">RISK SCORE</div>
                    </div>
                    <div>
                        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                            <span style="padding: 6px 16px; border-radius: 6px; font-size: 14px; font-weight: 700; text-transform: uppercase; background: ${colors[level]}; color: white;">${level}</span>
                            <span onclick="Sim.Utils.copyToClipboard('${ip}', 'IP Address')" style="font-size: 16px; font-weight: 600; font-family: monospace; color: var(--azure-blue); cursor: pointer; padding: 4px 8px; border-radius: 4px;" onmouseover="this.style.background='rgba(0,120,212,0.1)'" onmouseout="this.style.background='transparent'" title="Click to copy">${ip} 📋</span>
                        </div>
                        <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 4px;">Confidence: <strong>${confidence.toFixed(1)}%</strong></div>
                        <div style="font-size: 13px; color: var(--text-secondary);">Pattern: <strong>${pattern || 'Unknown'}</strong></div>
                    </div>
                </div>
            </div>`;
        },

        _renderRiskBreakdown(breakdown) {
            if (!breakdown) return '';
            const components = [
                { key: 'threat_intel', label: 'Threat Intelligence', color: TC.danger },
                { key: 'ml_prediction', label: 'ML Prediction', color: TC.primary },
                { key: 'behavioral', label: 'Behavioral Analysis', color: TC.warning },
                { key: 'geographic', label: 'Geographic Risk', color: TC.success }
            ];

            return `<div class="card" style="padding: 24px; margin-bottom: 24px;">
                <h3 style="margin: 0 0 20px 0; font-size: 18px; font-weight: 600;"><span style="font-size: 20px;">📈</span> Multi-Factor Risk Breakdown</h3>
                ${components.map(c => {
                    const comp = breakdown[c.key] || {};
                    const score = comp.score || 0;
                    const weighted = comp.weighted || 0;
                    const weight = comp.weight || 0;
                    return `<div style="margin-bottom: 16px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px;">
                            <span><strong>${c.label}</strong> <span style="color: var(--text-secondary);">(×${weight})</span></span>
                            <span><strong>${score.toFixed(1)}</strong>/100 = <strong style="color: ${c.color};">${weighted.toFixed(1)}</strong> pts</span>
                        </div>
                        <div style="height: 24px; background: var(--background); border-radius: 4px; overflow: hidden;">
                            <div style="height: 100%; width: ${score}%; background: linear-gradient(90deg, ${c.color}, ${c.color}aa);"></div>
                        </div>
                    </div>`;
                }).join('')}
            </div>`;
        },

        _renderThreatIntel(ti) {
            return `<div class="card" style="padding: 20px; border-left: 4px solid ${TC.danger};"><h4 style="margin: 0 0 16px 0; font-size: 16px; font-weight: 600;">🔍 Threat Intelligence</h4><div style="font-size: 13px;">AbuseIPDB: <strong>${ti.abuseipdb_score || 0}</strong>/100<br>VirusTotal: <strong>${ti.virustotal_positives || 0}</strong>/${ti.virustotal_total || 70} vendors<br>Threat Level: <strong>${(ti.threat_level || 'unknown').toUpperCase()}</strong></div></div>`;
        },

        _renderMLAnalysis(ml) {
            return `<div class="card" style="padding: 20px; border-left: 4px solid ${TC.primary};"><h4 style="margin: 0 0 16px 0; font-size: 16px; font-weight: 600;">🤖 ML Analysis</h4><div style="font-size: 13px;">Risk Score: <strong>${ml.risk_score || 0}</strong>/100<br>Confidence: <strong>${ml.confidence ? (ml.confidence*100).toFixed(1) : 0}%</strong><br>Anomaly: <strong>${ml.is_anomaly ? 'YES' : 'NO'}</strong><br>Type: <strong>${ml.threat_type || 'Unknown'}</strong></div></div>`;
        },

        _renderBehavioral(b) {
            return `<div class="card" style="padding: 20px; border-left: 4px solid ${TC.warning};"><h4 style="margin: 0 0 16px 0; font-size: 16px; font-weight: 600;">⚡ Behavioral Analysis</h4><div style="font-size: 13px;">Pattern: <strong>${b.pattern || 'Unknown'}</strong><br>Velocity: <strong>${b.velocity || 0}</strong>/min<br>Failure Rate: <strong>${b.failure_rate || 0}%</strong><br>Indicators:<ul style="margin: 8px 0 0 0; padding-left: 20px;">${(b.indicators || []).map(i => `<li>${i}</li>`).join('')}</ul></div></div>`;
        },

        _renderGeographic(gi, geo) {
            const country = geo?.country || 'Unknown';
            const city = geo?.city || 'Unknown';
            const location = city !== 'Unknown' ? `${city}, ${country}` : country;

            return `<div class="card" style="padding: 20px; border-left: 4px solid ${TC.success};">
                <h4 style="margin: 0 0 16px 0; font-size: 16px; font-weight: 600;">🌍 Geographic Intelligence</h4>
                <div style="font-size: 13px;">
                    Country: <strong onclick="Sim.Utils.copyToClipboard('${location}', 'Location')" style="cursor: pointer;" title="Click to copy">${country} 📋</strong><br>
                    ${city !== 'Unknown' ? `City: <strong>${city}</strong><br>` : ''}
                    Risk Score: <strong>${gi.score || 0}</strong>/100<br>
                    High-Risk: <strong>${gi.is_high_risk_region ? 'YES' : 'NO'}</strong><br>
                    Anonymized: <strong>${gi.is_anonymized ? 'YES' : 'NO'}</strong>
                </div>
            </div>`;
        },

        _renderHistorical(h) {
            return `<div class="card" style="padding: 24px;"><h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">📜 Historical Context</h3><div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;"><div><div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Total Events</div><div style="font-size: 24px; font-weight: 700;">${h.total_events || 0}</div></div><div><div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Failed Attempts</div><div style="font-size: 24px; font-weight: 700;">${h.failed_attempts || 0}</div></div><div><div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Unique Users</div><div style="font-size: 24px; font-weight: 700;">${h.unique_usernames || 0}</div></div><div><div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Anomalies</div><div style="font-size: 24px; font-weight: 700;">${h.anomaly_count || 0}</div></div></div></div>`;
        }
    };
})();
