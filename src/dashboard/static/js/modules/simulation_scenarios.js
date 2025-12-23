/**
 * SSH Guardian v3.0 - Simulation Scenarios Module
 * Demo scenarios loading, rendering, and category management
 */

// ========================
// CATEGORY CONFIGURATION
// ========================
const categoryConfig = {
    ufw_block: {
        icon: '🛡️',
        title: 'UFW Blocking Scenarios',
        description: 'Trigger SSH Guardian rules → Agent blocks IP via UFW',
        badge: null,
        steps: ['1. Select target server', '2. Click scenario card', '3. Run Attack → IP blocked via UFW']
    },
    fail2ban: {
        icon: '🔒',
        title: 'Fail2ban Scenarios',
        description: 'Generate auth.log entries → Fail2ban detects & bans automatically',
        badge: { text: 'REQUIRES TARGET', color: 'purple' },
        steps: ['1. Select target server (required)', '2. Click scenario card', '3. Run Attack → Fail2ban bans IP']
    },
    ml_behavioral: {
        icon: '🧠',
        title: 'ML Behavioral Analysis',
        description: 'Advanced pattern detection: impossible travel, time anomalies, lateral movement',
        badge: { text: 'ML', color: 'gradient' },
        steps: ['1. Select target server', '2. Click scenario card', '3. (Optional) Create Baseline first', '4. Run Attack → ML detects anomaly']
    },
    alert_only: {
        icon: '⚠️',
        title: 'Alert Only Scenarios',
        description: 'Successful logins with anomalies - generates Telegram alert but NO IP block',
        badge: { text: 'NO BLOCK', color: 'warning' },
        steps: ['1. Select target server', '2. Click scenario card', '3. Run Attack → Alert sent (no block)']
    },
    private_ip: {
        icon: '🏠',
        title: 'Private IP Scenarios',
        description: 'Internal network threats - behavioral analysis only (skip GeoIP/ThreatIntel)',
        badge: { text: 'INTERNAL', color: 'purple' },
        steps: ['1. Select target server', '2. Click scenario card', '3. Run Attack → Behavioral analysis only']
    },
    baseline: {
        icon: '✅',
        title: 'Baseline (Clean IPs)',
        description: 'Control scenario - should NOT be blocked. Use to verify no false positives.',
        badge: { text: 'CONTROL', color: 'success' },
        steps: ['1. Select target server', '2. Click scenario card', '3. Run Test → Verify NO block/alert']
    }
};

// ========================
// SCENARIO LOADING
// ========================
async function loadDemoScenarios() {
    try {
        const response = await fetch('/api/demo/scenarios', { credentials: 'same-origin' });
        const data = await response.json();
        if (data.success) {
            renderDemoScenarios(data.scenarios);
        } else {
            const grid = document.getElementById('demo-scenarios-grid');
            if (grid) grid.innerHTML = '<div style="padding: 20px; color: var(--text-secondary);">Failed to load scenarios.</div>';
        }
    } catch (error) {
        const grid = document.getElementById('demo-scenarios-grid');
        if (grid) grid.innerHTML = '<div style="padding: 20px; color: var(--text-secondary);">Error loading scenarios.</div>';
    }
}

// ========================
// CATEGORY SWITCHING
// ========================
function switchScenarioCategory(category) {
    SimulationState.currentCategory = category;

    // Update tab buttons
    document.querySelectorAll('.sim-cat-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.category === category);
    });

    // Update category description
    const config = categoryConfig[category];
    if (config) {
        document.getElementById('cat-desc-icon').textContent = config.icon;
        document.getElementById('cat-desc-title').textContent = config.title;
        document.getElementById('cat-desc-text').textContent = config.description;

        const badge = document.getElementById('cat-desc-badge');
        if (config.badge) {
            badge.textContent = config.badge.text;
            // Map color tokens to TC values
            const colorMap = {
                'purple': TC.purple,
                'gradient': `linear-gradient(135deg, ${TC.purple} 0%, ${TC.purple} 100%)`,
                'warning': TC.warning,
                'success': TC.success
            };
            badge.style.background = colorMap[config.badge.color] || config.badge.color;
            badge.style.color = 'white';
            badge.style.display = 'inline-block';
        } else {
            badge.style.display = 'none';
        }

        // Show steps guide if available
        const stepsEl = document.getElementById('cat-desc-steps');
        if (stepsEl && config.steps) {
            stepsEl.innerHTML = config.steps.map(s => `<span class="cat-step">${s}</span>`).join('');
            stepsEl.style.display = 'flex';
        } else if (stepsEl) {
            stepsEl.style.display = 'none';
        }
    }

    // Render scenarios for selected category
    renderScenariosForCategory(category);
}

// Update fail2ban category state based on target selection
function updateFail2banCategoryState() {
    const targetId = document.getElementById('scenario-target')?.value || '';
    const f2bTab = document.querySelector('.sim-cat-tab[data-category="fail2ban"]');

    if (f2bTab) {
        if (!targetId) {
            f2bTab.classList.add('disabled');
            f2bTab.title = 'Select a target server to enable Fail2ban scenarios';
        } else {
            f2bTab.classList.remove('disabled');
            f2bTab.title = '';
        }
    }
}

// ========================
// SCENARIO RENDERING
// ========================
function renderScenariosForCategory(category) {
    const colors = { critical: TC.danger, high: TC.warning, medium: TC.primary, low: TC.success };
    const icons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };

    const filteredScenarios = SimulationState.allScenarios.filter(s => s.category === category);
    const grid = document.getElementById('scenarios-grid');
    const empty = document.getElementById('scenarios-empty');

    if (!grid) return;

    if (filteredScenarios.length === 0) {
        grid.style.display = 'none';
        empty.style.display = 'block';
        return;
    }

    grid.style.display = 'grid';
    empty.style.display = 'none';

    grid.innerHTML = filteredScenarios.map(s => renderScenarioCard(s, colors, icons)).join('');
}

function renderScenarioCard(s, colors, icons) {
    // Badge based on scenario type
    let actionBadge = '';
    if (s.action_type === 'alert') {
        actionBadge = `<span style="font-size: 10px; padding: 2px 6px; background: linear-gradient(135deg, ${TC.purple} 0%, ${TC.warning} 100%); color: white; border-radius: 4px; font-weight: 600;">ALERT ONLY</span>`;
    } else if (s.category === 'ml_behavioral') {
        actionBadge = `<span style="font-size: 10px; padding: 2px 6px; background: linear-gradient(135deg, ${TC.purple} 0%, ${TC.purple} 100%); color: white; border-radius: 4px; font-weight: 600;">ML</span>`;
    } else if (s.category === 'private_ip' || s.is_private_ip) {
        actionBadge = `<span style="font-size: 10px; padding: 2px 6px; background: ${TC.purple}; color: white; border-radius: 4px; font-weight: 600;">🏠 PRIVATE IP</span>`;
    } else if (s.category === 'baseline') {
        actionBadge = `<span style="font-size: 10px; padding: 2px 6px; background: ${TC.success}; color: white; border-radius: 4px; font-weight: 600;">CONTROL</span>`;
    } else if (s.category === 'ufw_block') {
        actionBadge = `<span style="font-size: 10px; padding: 2px 6px; background: ${TC.danger}; color: white; border-radius: 4px; font-weight: 600;">UFW BLOCK</span>`;
    } else if (s.category === 'fail2ban') {
        actionBadge = `<span style="font-size: 10px; padding: 2px 6px; background: ${TC.warning}; color: black; border-radius: 4px; font-weight: 600;">FAIL2BAN</span>`;
    }

    const mlFactorsHtml = renderMLFactorsCompact(s.ml_factors);
    const tooltipHtml = renderTooltipCompact(s.tooltip);

    return `
        <div class="demo-scenario-card" data-scenario="${s.id}" data-category="${s.category}" onclick="openScenarioModal('${s.id}')"
             ${s.tooltip ? 'onmouseenter="showScenarioTooltip(this)" onmouseleave="hideScenarioTooltip(this)"' : ''}>
            <div class="scenario-loading-overlay" style="display: none;">
                <div class="scenario-spinner"></div>
                <div class="scenario-loading-text">Analyzing...</div>
            </div>
            ${tooltipHtml}
            <div class="scenario-card-content">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
                    <div style="font-size: 14px; font-weight: 600; flex: 1;">${s.name}</div>
                    ${actionBadge}
                </div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 8px; line-height: 1.4;">${s.description}</div>
                ${s.trigger ? `<div style="font-size: 11px; color: var(--azure-blue); margin-bottom: 6px;"><strong>Trigger:</strong> ${s.trigger}</div>` : ''}
                ${s.block_duration ? `<div style="font-size: 11px; color: ${s.action_type === 'alert' ? TC.warning : TC.danger}; margin-bottom: 6px;"><strong>${s.action_type === 'alert' ? 'Action:' : 'Block:'}</strong> ${s.block_duration}</div>` : ''}
                ${mlFactorsHtml}
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border);">
                    <span style="padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; background: ${colors[s.severity]}; color: white;">
                        ${icons[s.severity]} ${s.severity}
                    </span>
                    <span class="scenario-ip" style="font-family: monospace; font-size: 11px; color: var(--azure-blue); font-weight: 600;">${s.ip}</span>
                </div>
            </div>
        </div>
    `;
}

function renderMLFactorsCompact(factors) {
    if (!factors || factors.length === 0) return '';

    const totalScore = factors.reduce((sum, f) => sum + (f.score || 0), 0);
    const isAnomaly = totalScore >= 30;
    const scoreLabel = isAnomaly ? 'Anomaly Score' : 'ML Score';
    const scoreColor = isAnomaly ? TC.danger : TC.purple;

    return `
        <div class="scenario-ml-factors" style="margin-top: 6px; padding: 6px 8px; background: ${TC.purpleBg}; border-radius: 4px; font-size: 10px;">
            <div style="font-weight: 600; margin-bottom: 4px; color: ${scoreColor};">${scoreLabel}: ${totalScore}/100 ${isAnomaly ? '(ANOMALY)' : ''}</div>
            ${factors.slice(0, 2).map(f => `
                <div style="display: flex; justify-content: space-between; color: var(--text-secondary);">
                    <span>${f.type ? f.type.replace(/_/g, ' ') : 'Factor'}</span>
                    <span style="font-weight: 600; color: ${f.score >= 20 ? TC.danger : TC.warning}">+${f.score}</span>
                </div>
            `).join('')}
            ${factors.length > 2 ? `<div style="color: var(--text-hint); margin-top: 2px;">+${factors.length - 2} more</div>` : ''}
        </div>
    `;
}

function renderTooltipCompact(tooltip) {
    if (!tooltip || !tooltip.what_it_tests) return '';
    return `
        <div class="scenario-tooltip" style="display: none; position: absolute; bottom: 100%; left: 0; right: 0; margin-bottom: 8px; padding: 10px; background: ${TC.textPrimary}; color: white; border-radius: 6px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); z-index: 100; font-size: 11px; line-height: 1.4;">
            <div style="margin-bottom: 6px;"><span style="color: ${TC.textHint};">Test:</span> ${tooltip.what_it_tests}</div>
            <div style="margin-bottom: 6px;"><span style="color: ${TC.teal};">Outcome:</span> ${tooltip.expected_outcome}</div>
            ${tooltip.why_not_blocked ? `<div style="color: ${TC.warning};"><span>Why not blocked:</span> ${tooltip.why_not_blocked}</div>` : ''}
            ${tooltip.why_ml_needed ? `<div style="color: ${TC.purple};"><span>ML:</span> ${tooltip.why_ml_needed}</div>` : ''}
        </div>
    `;
}

function renderDemoScenarios(scenarios) {
    SimulationState.allScenarios = scenarios;

    // Count scenarios per category
    const counts = {
        ufw_block: scenarios.filter(s => s.category === 'ufw_block').length,
        fail2ban: scenarios.filter(s => s.category === 'fail2ban').length,
        ml_behavioral: scenarios.filter(s => s.category === 'ml_behavioral').length,
        alert_only: scenarios.filter(s => s.category === 'alert_only').length,
        private_ip: scenarios.filter(s => s.category === 'private_ip').length,
        baseline: scenarios.filter(s => s.category === 'baseline').length
    };

    // Update tab counts
    const countUfw = document.getElementById('count-ufw');
    const countF2b = document.getElementById('count-fail2ban');
    const countMl = document.getElementById('count-ml');
    const countAlert = document.getElementById('count-alert');
    const countPrivate = document.getElementById('count-private');
    const countBaseline = document.getElementById('count-baseline');

    if (countUfw) countUfw.textContent = counts.ufw_block;
    if (countF2b) countF2b.textContent = counts.fail2ban;
    if (countMl) countMl.textContent = counts.ml_behavioral;
    if (countAlert) countAlert.textContent = counts.alert_only;
    if (countPrivate) countPrivate.textContent = counts.private_ip;
    if (countBaseline) countBaseline.textContent = counts.baseline;

    // Render current category
    switchScenarioCategory(SimulationState.currentCategory);

    console.log(`[Simulation] Loaded ${scenarios.length} scenarios:`, counts);
}

// Show/hide scenario tooltip
function showScenarioTooltip(card) {
    const tooltip = card.querySelector('.scenario-tooltip');
    if (tooltip) tooltip.style.display = 'block';
}

function hideScenarioTooltip(card) {
    const tooltip = card.querySelector('.scenario-tooltip');
    if (tooltip) tooltip.style.display = 'none';
}

// ========================
// GLOBAL EXPORTS
// ========================
window.loadDemoScenarios = loadDemoScenarios;
window.switchScenarioCategory = switchScenarioCategory;
window.updateFail2banCategoryState = updateFail2banCategoryState;
window.showScenarioTooltip = showScenarioTooltip;
window.hideScenarioTooltip = hideScenarioTooltip;
