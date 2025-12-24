/**
 * SSH Guardian v3.0 - Simulation Scenarios Module
 * Demo scenarios loading and rendering (Single Page View)
 */

// ========================
// CATEGORY CONFIGURATION
// ========================
const categoryConfig = {
    baseline: {
        icon: '✅',
        title: 'Baseline (No Action)',
        color: '#2EA44F',
        bgColor: '#2EA44F20',
        order: 1
    },
    alert_only: {
        icon: '🔔',
        title: 'Alert Only (Monitor)',
        color: '#E6A502',
        bgColor: '#E6A50220',
        order: 2
    },
    fail2ban_block: {
        icon: '🔒',
        title: 'Fail2ban Block (Temporary)',
        color: '#D13438',
        bgColor: '#D1343820',
        order: 3
    },
    credential_stuffing: {
        icon: '🌙',
        title: 'Credential Stuffing Block',
        color: '#8B008B',
        bgColor: '#8B008B20',
        order: 3
    },
    ufw_block: {
        icon: '🛡️',
        title: 'UFW Block (Permanent)',
        color: '#8B0000',
        bgColor: '#8B000020',
        order: 4
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
            renderAllScenarios(data.scenarios);
        } else {
            const grid = document.getElementById('scenarios-grid');
            if (grid) grid.innerHTML = '<div style="padding: 20px; color: var(--text-secondary);">Failed to load scenarios.</div>';
        }
    } catch (error) {
        const grid = document.getElementById('scenarios-grid');
        if (grid) grid.innerHTML = '<div style="padding: 20px; color: var(--text-secondary);">Error loading scenarios.</div>';
    }
}

// ========================
// RENDER ALL SCENARIOS (NO TABS)
// ========================
function renderAllScenarios(scenarios) {
    SimulationState.allScenarios = scenarios;

    const grid = document.getElementById('scenarios-grid');
    const empty = document.getElementById('scenarios-empty');

    if (!grid) return;

    if (scenarios.length === 0) {
        grid.style.display = 'none';
        if (empty) empty.style.display = 'block';
        return;
    }

    grid.style.display = 'grid';
    if (empty) empty.style.display = 'none';

    // Render all scenarios in order (they're already sorted in demo_scenarios.py)
    grid.innerHTML = scenarios.map(s => renderEnhancedScenarioCard(s)).join('');

    console.log(`[Simulation] Loaded ${scenarios.length} scenarios`);
}

// Backward compatibility
function renderDemoScenarios(scenarios) {
    renderAllScenarios(scenarios);
}

function switchScenarioCategory(category) {
    // No-op for backward compatibility - tabs removed
    console.log('[Simulation] Tab switching disabled - showing all scenarios');
}

// Enhanced card with usage instructions
function renderEnhancedScenarioCard(s) {
    const catConfig = categoryConfig[s.category] || categoryConfig['fail2ban_block'];

    // Category badge with color
    const categoryBadge = `<span style="font-size: 10px; padding: 3px 8px; background: ${catConfig.bgColor}; color: ${catConfig.color}; border-radius: 4px; font-weight: 600; white-space: nowrap;">${catConfig.icon} ${s.category_label || s.category.replace(/_/g, ' ').toUpperCase()}</span>`;

    // Expected result styling
    let expectedColor = '#2EA44F';  // green for no action
    let expectedIcon = '✅';
    if (s.action_type === 'block') {
        expectedColor = '#D13438';
        expectedIcon = '🛡️';
    } else if (s.action_type === 'alert') {
        expectedColor = '#E6A502';
        expectedIcon = '🔔';
    }

    // Verification steps (from demo_scenarios.py)
    const verifySteps = s.verification_steps || [];
    const verifyHtml = verifySteps.length > 0
        ? `<div style="margin-top: 8px; padding-top: 8px; border-top: 1px dashed var(--border);">
            <div style="font-size: 10px; font-weight: 600; color: var(--text-secondary); margin-bottom: 4px;">🔍 VERIFY:</div>
            ${verifySteps.slice(0, 2).map(step => `<div style="font-size: 10px; color: var(--text-hint); padding-left: 12px;">• ${step}</div>`).join('')}
           </div>`
        : '';

    return `
        <div class="demo-scenario-card" data-scenario="${s.id}" data-category="${s.category}" onclick="openScenarioModal('${s.id}')"
             style="border-left: 4px solid ${catConfig.color};">
            <div class="scenario-loading-overlay" style="display: none;">
                <div class="scenario-spinner"></div>
                <div class="scenario-loading-text">Running...</div>
            </div>
            <div class="scenario-card-content" style="padding: 12px;">
                <!-- Header: Name + Badge -->
                <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 8px;">
                    <div style="font-size: 14px; font-weight: 600; color: var(--text-primary); line-height: 1.3;">${s.short_name || s.name}</div>
                    ${categoryBadge}
                </div>

                <!-- Description -->
                <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 10px; line-height: 1.4;">${s.description}</div>

                <!-- How to Use -->
                <div style="background: var(--surface-alt); border-radius: 6px; padding: 8px 10px; margin-bottom: 8px;">
                    <div style="font-size: 10px; font-weight: 600; color: var(--azure-blue); margin-bottom: 4px;">📋 HOW TO USE:</div>
                    <div style="font-size: 11px; color: var(--text-secondary); line-height: 1.5;">
                        1. Select target server above<br>
                        2. Click this card<br>
                        3. Click "Run Attack" button
                    </div>
                </div>

                <!-- Expected Result -->
                <div style="background: ${expectedColor}15; border-radius: 6px; padding: 8px 10px; border: 1px solid ${expectedColor}40;">
                    <div style="font-size: 11px; font-weight: 600; color: ${expectedColor};">
                        ${expectedIcon} EXPECTED: ${s.expected_result || (s.action_type === 'none' ? 'No alert, no block' : s.action_type === 'alert' ? 'Alert only (no block)' : 'IP blocked')}
                    </div>
                    ${s.block_duration ? `<div style="font-size: 10px; color: var(--text-secondary); margin-top: 2px;">Duration: ${s.block_duration}</div>` : ''}
                </div>

                ${verifyHtml}

                <!-- Hidden IP for scripts -->
                <span class="scenario-ip" style="display: none;">${s.ip}</span>
            </div>
        </div>
    `;
}

// Keep old function for backward compatibility
function renderScenarioCard(s, colors, icons) {
    return renderEnhancedScenarioCard(s);
}

// ========================
// GLOBAL EXPORTS
// ========================
window.loadDemoScenarios = loadDemoScenarios;
window.renderDemoScenarios = renderDemoScenarios;
window.switchScenarioCategory = switchScenarioCategory;
