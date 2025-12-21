/**
 * SSH Guardian v3.0 - Simulation Threat Intelligence
 * Threat intelligence fetching and evaluation
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.ThreatIntel = {
        async fetchEvaluation(ip) {
            try {
                const response = await fetch(`/api/threat-intel/evaluate/${ip}`, { credentials: 'same-origin' });
                if (response.ok) {
                    const data = await response.json();
                    if (data.success && data.evaluation) return data.evaluation;
                }
            } catch (e) {
                console.log('[Simulation] Could not fetch threat evaluation:', e);
            }
            return null;
        },

        async fetchForIP(ip) {
            const evaluation = await this.fetchEvaluation(ip);
            if (evaluation?.details?.threat_intel) {
                const ti = evaluation.details.threat_intel;
                const net = evaluation.details.network || {};
                return {
                    abuseipdb_score: ti.abuseipdb_score || 0,
                    virustotal_positives: ti.virustotal_positives || 0,
                    virustotal_total: ti.virustotal_total || 70,
                    country: ti.country_name || 'Unknown',
                    network_type: net.is_tor ? 'TOR' : net.is_proxy ? 'Proxy' : net.is_vpn ? 'VPN' : net.is_datacenter ? 'Datacenter' : 'Regular',
                    isp: ti.isp || net.isp || 'Unknown',
                    is_tor: net.is_tor || false,
                    is_proxy: net.is_proxy || false,
                    is_vpn: net.is_vpn || false,
                    threat_level: ti.threat_level || 'unknown',
                    _fullEvaluation: evaluation
                };
            }

            try {
                const response = await fetch(`/api/threat-intel/lookup/${ip}`, { credentials: 'same-origin' });
                if (response.ok) {
                    const data = await response.json();
                    if (data.success && data.data) {
                        const d = data.data;
                        return {
                            abuseipdb_score: d.abuseipdb_score || 0,
                            virustotal_positives: d.virustotal_positives || 0,
                            virustotal_total: d.virustotal_total || 70,
                            country: d.country_name || d.country || 'Unknown',
                            network_type: d.is_datacenter ? 'Datacenter' : d.is_hosting ? 'Hosting' : d.is_vpn ? 'VPN' : d.is_proxy ? 'Proxy' : 'Regular',
                            isp: d.isp || d.asn_org || 'Unknown',
                            is_tor: d.is_tor || false,
                            is_proxy: d.is_proxy || false,
                            is_vpn: d.is_vpn || false,
                            threat_level: d.threat_level || d.overall_threat_level || 'unknown'
                        };
                    }
                }
            } catch (e) {
                console.log('[Simulation] Could not fetch threat intel:', e);
            }
            return {};
        },

        async fetchMLEvaluation(ip, threatIntel = null) {
            if (threatIntel?._fullEvaluation) {
                const eval_ = threatIntel._fullEvaluation;
                const ml = eval_.details?.ml || {};
                return {
                    threat_score: eval_.composite_score || ml.risk_score || 0,
                    risk_level: eval_.risk_level || ml.risk_level || 'unknown',
                    recommended_action: eval_.recommended_action || 'monitor',
                    confidence: eval_.confidence || 0.8,
                    factors: eval_.factors || [],
                    components: eval_.components || {},
                    is_anomaly: ml.is_anomaly || false,
                    model_used: ml.model_used || 'composite'
                };
            }

            const evaluation = await this.fetchEvaluation(ip);
            if (evaluation) {
                return {
                    threat_score: evaluation.composite_score || 0,
                    risk_level: evaluation.risk_level || 'unknown',
                    recommended_action: evaluation.recommended_action || 'monitor',
                    confidence: evaluation.confidence || 0.8,
                    factors: evaluation.factors || [],
                    components: evaluation.components || {}
                };
            }

            if (threatIntel && (threatIntel.abuseipdb_score || threatIntel.virustotal_positives)) {
                return this.computeRiskFromThreatIntel(threatIntel);
            }
            return {};
        },

        computeRiskFromThreatIntel(ti) {
            let score = 0;
            const factors = [];

            if (ti.abuseipdb_score) {
                score += Math.min(40, ti.abuseipdb_score * 0.4);
                if (ti.abuseipdb_score >= 75) factors.push('Critical AbuseIPDB');
                else if (ti.abuseipdb_score >= 50) factors.push('High AbuseIPDB');
            }

            if (ti.virustotal_positives > 0) {
                score += Math.min(30, ti.virustotal_positives * 3);
                factors.push(`${ti.virustotal_positives} AV detections`);
            }

            if (ti.is_tor) { score += 20; factors.push('TOR Exit Node'); }
            else if (ti.is_proxy) { score += 15; factors.push('Known Proxy'); }
            else if (ti.is_vpn) { score += 10; factors.push('VPN Service'); }
            else if (ti.network_type === 'Datacenter' || ti.network_type === 'Hosting') {
                score += 10; factors.push('Datacenter IP');
            }

            let risk_level = 'low';
            let action = 'monitor';
            if (score >= 75) { risk_level = 'critical'; action = 'block_immediate'; }
            else if (score >= 50) { risk_level = 'high'; action = 'block'; }
            else if (score >= 25) { risk_level = 'medium'; action = 'monitor_closely'; }

            return { threat_score: Math.round(score), risk_level, recommended_action: action, confidence: 0.85, factors, computed: true };
        }
    };
})();
