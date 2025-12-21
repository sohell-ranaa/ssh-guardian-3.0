/**
 * SSH Guardian v3.0 - Simulation Recommendations
 * Recommendations tab rendering
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Recommendations = {
        populate(data) {
            console.log('[Results] Populating tab with data:', data);

            document.getElementById('results-empty-state').style.display = 'none';
            const content = document.getElementById('results-content');
            content.style.display = 'block';

            const recs = data.results?.recommendations || [];
            const immediate = recs.filter(r => r.urgency === 'immediate');
            const shortTerm = recs.filter(r => r.urgency === 'short_term');
            const longTerm = recs.filter(r => r.urgency === 'long_term');

            try {
                const html = `
                    ${this._renderQuickActions(recs.slice(0, 3))}
                    ${immediate.length > 0 ? `<div style="margin-bottom: 24px;"><div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;"><span style="font-size: 24px;">🚨</span><h3 style="margin: 0; font-size: 18px; font-weight: 600; color: ${TC.danger};">Immediate Actions</h3></div>${immediate.map(r => this._renderRecommendation(r)).join('')}</div>` : ''}
                    ${shortTerm.length > 0 ? `<div style="margin-bottom: 24px;"><div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;"><span style="font-size: 24px;">📅</span><h3 style="margin: 0; font-size: 18px; font-weight: 600; color: ${TC.warning};">Short-Term Actions</h3></div>${shortTerm.map(r => this._renderRecommendation(r)).join('')}</div>` : ''}
                    ${longTerm.length > 0 ? `<div style="margin-bottom: 24px;"><div style="display: flex; align-items: center; gap: 8px; margin-bottom: 16px;"><span style="font-size: 24px;">🛡️</span><h3 style="margin: 0; font-size: 18px; font-weight: 600; color: ${TC.primary};">Long-Term Hardening</h3></div>${longTerm.map(r => this._renderRecommendation(r)).join('')}</div>` : ''}
                `;
                content.innerHTML = html;
            } catch (err) {
                console.error('[Results] Error rendering HTML:', err);
                content.innerHTML = `<div class="card" style="padding: 20px; background: #fee; color: #c00;">Error: ${err.message}</div>`;
            }
        },

        _renderQuickActions(topRecs) {
            if (!topRecs || topRecs.length === 0) return '';
            const priorityColors = { 'critical': TC.danger, 'high': TC.warning, 'medium': TC.primary, 'low': TC.success };

            return `<div class="card" style="padding: 24px; margin-bottom: 24px; background: linear-gradient(135deg, rgba(0, 120, 212, 0.05), rgba(230, 165, 2, 0.05)); border: 2px solid ${TC.warning};">
                <h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">⚡ Quick Actions</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 12px;">
                    ${topRecs.map(r => {
                        const color = priorityColors[r.priority] || TC.primary;
                        const confidence = r.confidence ? (r.confidence * 100).toFixed(0) : r.ai_confidence ? (r.ai_confidence * 100).toFixed(0) : 0;
                        return `<div style="padding: 16px; background: var(--card-bg); border-left: 4px solid ${color}; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                            <div style="font-size: 14px; font-weight: 600; margin-bottom: 4px; color: ${color};">${r.icon || '🔹'} ${r.action}</div>
                            <div style="font-size: 12px; color: var(--text-secondary);">${confidence}% confidence · ${r.urgency || 'N/A'}</div>
                        </div>`;
                    }).join('')}
                </div>
            </div>`;
        },

        _renderRecommendation(rec) {
            const confidence = rec.confidence ? (rec.confidence * 100).toFixed(0) : rec.ai_confidence ? (rec.ai_confidence * 100).toFixed(0) : 0;
            return `<div class="recommendation-card ${rec.priority}">
                <div style="display: flex; justify-content: space-between; margin-bottom: 12px;">
                    <h4 style="margin: 0; font-size: 16px; font-weight: 600;">${rec.icon || '🔹'} ${rec.action}</h4>
                    <span style="font-size: 13px; font-weight: 600; color: var(--text-secondary);">${confidence}% confidence</span>
                </div>
                <div style="font-size: 14px; margin-bottom: 12px; color: var(--text-secondary);">${rec.reason}</div>
                ${rec.why?.length > 0 ? `<div style="margin-bottom: 12px;"><strong style="font-size: 13px;">Why:</strong><ul style="margin: 4px 0 0 0; padding-left: 20px; font-size: 13px;">${rec.why.map(w => `<li>${w}</li>`).join('')}</ul></div>` : ''}
                ${rec.impact ? `<div style="margin-bottom: 12px; font-size: 13px;"><strong>Impact:</strong> ${rec.impact}</div>` : ''}
                ${rec.risk_if_ignored ? `<div style="padding: 8px 12px; background: rgba(209, 52, 56, 0.1); border-left: 3px solid ${TC.danger}; margin-bottom: 12px; font-size: 13px;"><strong>Risk if Ignored:</strong> ${rec.risk_if_ignored}</div>` : ''}
                <div style="display: flex; gap: 8px; margin-top: 12px;">${this._getActionButton(rec)}</div>
            </div>`;
        },

        _getActionButton(rec) {
            const type = rec.action_type;
            const data = rec.action_data;
            if (type === 'block_ip') return `<button onclick="Sim.Blocking.showModal('${data.ip}')" style="padding: 8px 16px; background: ${TC.danger}; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">🚫 Block IP</button>`;
            if (type === 'add_blocklist') return `<button onclick="Sim.Blocking.showModal('${data.ip}')" style="padding: 8px 16px; background: ${TC.warning}; color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">📋 Add to Blocklist</button>`;
            if (type === 'view_events') return `<button onclick="window.location.href='/dashboard?page=events-live'" style="padding: 8px 16px; background: ${TC.primary}; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">👁️ View Events</button>`;
            return `<button style="padding: 8px 16px; background: var(--background); color: var(--text-primary); border: 1px solid var(--border); border-radius: 4px; cursor: pointer;">ℹ️ Learn More</button>`;
        }
    };
})();
