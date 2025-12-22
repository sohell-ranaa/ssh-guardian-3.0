/**
 * SSH Guardian v3.0 - Simulation Results
 * Results display after simulation completion
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Results = {
        data: null,

        hide() {
            const card = document.getElementById('simulation-results-card');
            if (card) card.style.display = 'none';
        },

        async show(data) {
            const card = document.getElementById('simulation-results-card');
            if (!card) return;

            this.data = data;
            const duration = Sim.LiveStatus.startTime ? ((Date.now() - Sim.LiveStatus.startTime) / 1000).toFixed(1) + 's' : '-';

            // Update header
            const header = document.getElementById('sim-results-header');
            header.classList.remove('sim-card__header--blocked', 'sim-card__header--detected', 'sim-card__header--complete', 'sim-card__header--neutral');

            if (data.blocked) {
                header.classList.add('sim-card__header--blocked');
                this._setText('sim-result-icon', '🛡️');
                this._setText('sim-result-title', 'IP BLOCKED');
                this._setText('sim-result-subtitle', `Attack detected and blocked by ${data.blocked_by || 'SSH Guardian'}`);
            } else if (data.detected) {
                header.classList.add('sim-card__header--detected');
                this._setText('sim-result-icon', '⚠️');
                this._setText('sim-result-title', 'DETECTED - NOT BLOCKED');
                this._setText('sim-result-subtitle', 'Attack detected but below blocking threshold');
            } else {
                header.classList.add('sim-card__header--neutral');
                this._setText('sim-result-icon', 'ℹ️');
                this._setText('sim-result-title', 'SIMULATION COMPLETE');
                this._setText('sim-result-subtitle', 'No blocking action was triggered');
            }

            this._setText('sim-result-ip', data.ip || '-');
            this._setText('sim-result-scenario', data.scenario_name || data.scenario_id || '-');
            this._setText('sim-result-duration', duration);

            // Fetch threat intel
            const threatIntel = await Sim.ThreatIntel.fetchForIP(data.ip);

            const abuseScore = document.getElementById('sim-abuseipdb-score');
            abuseScore.textContent = threatIntel.abuseipdb_score ? `${threatIntel.abuseipdb_score}/100` : '-';
            this._updateScoreColor(abuseScore, threatIntel.abuseipdb_score);

            this._setText('sim-virustotal', threatIntel.virustotal_positives !== undefined
                ? `${threatIntel.virustotal_positives}/${threatIntel.virustotal_total || 70} detections` : '-');
            this._setText('sim-country', threatIntel.country || '-');
            this._setText('sim-network-type', threatIntel.network_type || threatIntel.isp || '-');

            // ML Analysis
            const mlData = await Sim.ThreatIntel.fetchMLEvaluation(data.ip, threatIntel);
            const riskScore = mlData.threat_score || mlData.risk_score || 0;

            const mlScoreEl = document.getElementById('sim-ml-risk-score');
            mlScoreEl.textContent = typeof riskScore === 'number' ? `${riskScore}/100` : riskScore;
            this._updateScoreColor(mlScoreEl, riskScore);

            this._setText('sim-ml-threat-level', mlData.risk_level || mlData.threat_level || '-');
            this._setText('sim-ml-decision', mlData.recommended_action?.replace(/_/g, ' ') || (data.blocked ? 'Block' : 'Allow'));
            this._setText('sim-ml-confidence', mlData.confidence ? `${(mlData.confidence * 100).toFixed(0)}%` : '-');

            // Blocking Decision
            const blockingDecision = document.getElementById('sim-blocking-decision');
            blockingDecision.classList.remove('sim-decision-box--blocked', 'sim-decision-box--detected', 'sim-decision-box--neutral');

            if (data.blocked) {
                blockingDecision.classList.add('sim-decision-box--blocked');
                this._setText('sim-block-icon', '🚫');
                this._setText('sim-block-action', `IP Blocked via ${data.blocked_by || 'SSH Guardian'}`);

                // Fetch detailed block reason
                const blockReason = await this._fetchBlockReason(data.ip, data.block_id);
                this._setText('sim-block-reason', blockReason);
            } else if (data.detected) {
                blockingDecision.classList.add('sim-decision-box--detected');
                this._setText('sim-block-icon', '⚠️');
                this._setText('sim-block-action', 'Attack Detected - Monitoring');
                this._setText('sim-block-reason', 'Below threshold for automatic blocking');
            } else {
                blockingDecision.classList.add('sim-decision-box--neutral');
                this._setText('sim-block-icon', '✅');
                this._setText('sim-block-action', 'No Action Taken');
                this._setText('sim-block-reason', 'Events injected but no threat detected');
            }

            // Factors
            const factors = this._collectFactors(data, threatIntel, mlData);
            const blockFactors = document.getElementById('sim-block-factors');
            blockFactors.innerHTML = factors.slice(0, 5).map(f => `<span class="sim-factor-badge">${f}</span>`).join('');

            card.style.display = 'block';
            card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        },

        _setText(id, text) {
            const el = document.getElementById(id);
            if (el) el.textContent = text;
        },

        _updateScoreColor(el, score) {
            if (!el) return;
            el.classList.remove('sim-data-item__value--danger', 'sim-data-item__value--warning', 'sim-data-item__value--success');
            if (score >= 50) el.classList.add('sim-data-item__value--danger');
            else if (score >= 25) el.classList.add('sim-data-item__value--warning');
            else el.classList.add('sim-data-item__value--success');
        },

        _collectFactors(data, threatIntel, mlData) {
            const factors = [...(mlData.factors || [])];
            if (data.blocked) factors.push(data.blocked_by === 'fail2ban' ? 'Fail2ban Jail' : 'UFW Rule');
            if (threatIntel.abuseipdb_score >= 50) factors.push('High AbuseIPDB Score');
            if (threatIntel.virustotal_positives > 0) factors.push('VirusTotal Flagged');
            if (data.events_detected > 5) factors.push(`${data.events_detected} Events`);
            return factors;
        },

        async _fetchBlockReason(ip, blockId) {
            try {
                // First try to get from events-analysis API (has ml_decision)
                const eventsUrl = `/api/dashboard/events/by-ip?ip=${encodeURIComponent(ip)}&page=1&page_size=1&time_range=30d`;
                const eventsRes = await fetch(eventsUrl);
                const eventsData = await eventsRes.json();

                if (eventsData.success && eventsData.events?.length) {
                    const eventId = eventsData.events[0].id;
                    const detailUrl = `/api/dashboard/events-analysis/${eventId}`;
                    const detailRes = await fetch(detailUrl);
                    const detailData = await detailRes.json();

                    if (detailData.success && detailData.data) {
                        const { block_info, ml_decision } = detailData.data;

                        if (block_info?.block_reason) {
                            // Build detailed explanation
                            let reason = block_info.block_reason;

                            // Add ML decision factors if available
                            if (ml_decision?.factors?.length) {
                                const factorList = ml_decision.factors.map(f => `${f.label}: ${f.value}`).join(', ');
                                reason += ` | Factors: ${factorList}`;
                            }

                            return reason;
                        }
                    }
                }

                // Fallback to basic info
                return `Block ID: #${blockId || 'N/A'} | Triggered by ML threshold`;
            } catch (e) {
                console.error('Error fetching block reason:', e);
                return `Block ID: #${blockId || 'N/A'}`;
            }
        }
    };
})();
