/**
 * SSH Guardian v3.0 - Simulation Core Module
 * Core functions, state management, page initialization, and target selection
 */

// ========================
// GLOBAL STATE
// ========================
window.SimulationState = {
    currentAnalysisData: null,
    allScenarios: [],
    currentCategory: 'ufw_block',
    currentModalScenario: null,
    isPageInitialized: false
};

// ========================
// TAB SWITCHING
// ========================
function switchSimulationTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.sim-tab-content').forEach(tab => {
        tab.classList.remove('active');
        tab.style.display = 'none';
    });

    // Deactivate all tab buttons
    document.querySelectorAll('.sim-tab-btn').forEach(btn => btn.classList.remove('active'));

    // Show selected tab
    const selectedTab = document.getElementById('tab-' + tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
        selectedTab.style.display = 'block';
    }

    // Activate selected tab button
    const selectedBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (selectedBtn) {
        selectedBtn.classList.add('active');
    }

    console.log('[Simulation] Switched to tab:', tabName);
}

// ========================
// PAGE LOADING
// ========================
async function loadSimulationPage() {
    console.log('[Simulation] Loading page...');
    const startTime = performance.now();

    // Set loading state for cache indicator
    if (typeof CacheManager !== 'undefined') {
        CacheManager.setLoading('simulation');
    }

    try {
        // Load demo scenarios
        await loadDemoScenarios();

        // Load target server dropdown
        await loadScenarioTargets();

        // Load IP pool stats
        await loadIPPoolStats();

        // Load other data that dashboard expects (for cache status)
        await Promise.all([
            loadSimulationTemplates(),
            loadSimulationHistory()
        ]);

        const loadTime = Math.round(performance.now() - startTime);
        console.log('[Simulation] Page loaded successfully in', loadTime, 'ms');

        // Update cache status to "fresh" (not from cache)
        if (typeof CacheManager !== 'undefined') {
            CacheManager.updateStatus('simulation', false, loadTime);
        }
    } catch (error) {
        console.error('[Simulation] Error loading page:', error);

        // Set error state for cache indicator
        if (typeof CacheManager !== 'undefined') {
            CacheManager.setError('simulation', 'Failed to load simulation data');
        }
    }
}

// ========================
// TARGET SERVER SELECTION
// ========================
function onSimulationTargetChange() {
    const targetId = document.getElementById('scenario-target')?.value || '';
    const noServerDiv = document.getElementById('simulationNoServer');
    const contentDiv = document.getElementById('simulationContent');
    const refreshBtn = document.getElementById('refresh-ips-btn');
    const statusEl = document.getElementById('scenario-target-status');

    if (targetId) {
        // Server selected - show content, hide placeholder
        if (noServerDiv) noServerDiv.style.display = 'none';
        if (contentDiv) contentDiv.style.display = 'block';
        if (refreshBtn) refreshBtn.style.display = 'inline-block';

        // Update status indicator
        const targetSelect = document.getElementById('scenario-target');
        const targetOption = targetSelect.selectedOptions[0];
        if (statusEl) {
            statusEl.textContent = `Target: ${targetOption?.dataset?.ip || 'Selected'}`;
        }

        // Save selection
        localStorage.setItem('simulation_selected_target', targetId);
    } else {
        // No server selected - show placeholder, hide content
        if (noServerDiv) noServerDiv.style.display = 'block';
        if (contentDiv) contentDiv.style.display = 'none';
        if (refreshBtn) refreshBtn.style.display = 'none';
        if (statusEl) statusEl.textContent = '';

        localStorage.removeItem('simulation_selected_target');
    }

    // Update fail2ban category state
    updateFail2banCategoryState();
}

// Load target servers for scenario dropdown (agent-based)
async function loadScenarioTargets() {
    try {
        const response = await fetch('/api/live-sim/targets/from-agents', { credentials: 'same-origin' });
        const data = await response.json();

        const select = document.getElementById('scenario-target');
        if (data.success) {
            // Filter to only enabled agents
            const enabledAgents = data.agents.filter(a => a.sim_enabled);

            if (enabledAgents.length > 0) {
                select.innerHTML = '<option value="">-- Select a server --</option>' +
                    enabledAgents.map(a => {
                        const name = a.display_name || a.hostname;
                        const statusIcon = a.test_status === 'success' ? '✅' : a.test_status === 'failed' ? '❌' : '';
                        return `<option value="${a.sim_target_id}" data-ip="${a.ip_address}" data-port="${a.sim_port || 5001}">
                            🎯 ${name} (${a.ip_address}) ${statusIcon}
                        </option>`;
                    }).join('');

                // Auto-restore saved selection
                const savedTargetId = localStorage.getItem('simulation_selected_target');
                if (savedTargetId && select.querySelector(`option[value="${savedTargetId}"]`)) {
                    select.value = savedTargetId;
                    onSimulationTargetChange();
                }
            } else {
                select.innerHTML = '<option value="">-- No simulation targets configured --</option>';
            }
        } else {
            select.innerHTML = '<option value="">-- Select a server --</option>';
        }

        // Initial state update
        onSimulationTargetChange();
    } catch (error) {
        console.error('[Simulation] Error loading target servers:', error);
    }
}

// Load simulation templates (for dashboard cache)
async function loadSimulationTemplates() {
    try {
        const response = await fetch('/api/simulation/templates', { credentials: 'same-origin' });
        await response.json();
    } catch (error) {
        console.error('[Simulation] Error loading templates:', error);
    }
}

// Load simulation history (for dashboard cache)
async function loadSimulationHistory() {
    try {
        const response = await fetch('/api/simulation/history?limit=10&offset=0', { credentials: 'same-origin' });
        await response.json();
    } catch (error) {
        console.error('[Simulation] Error loading history:', error);
    }
}

// ========================
// IP POOL MANAGEMENT
// ========================
async function refreshIPPool() {
    const btn = document.getElementById('refresh-ips-btn');
    const icon = document.getElementById('refresh-ips-icon');

    if (!btn) return;

    btn.disabled = true;
    if (icon) icon.textContent = '⏳';
    btn.style.opacity = '0.7';

    try {
        showToast('Fetching fresh malicious IPs from threat sources...', 'info', 3000);

        const response = await fetch('/api/demo/refresh-ips', {
            method: 'POST',
            credentials: 'same-origin'
        });
        const data = await response.json();

        if (data.success) {
            showToast(`Updated IP pool: ${data.stats?.blocklist_count || 0} blocklist IPs`, 'success');
            await loadIPPoolStats();
            await loadDemoScenarios();
        } else {
            showToast(data.error || 'Failed to refresh IPs', 'error');
        }
    } catch (error) {
        console.error('[Simulation] Error refreshing IP pool:', error);
        showToast('Failed to refresh IP pool', 'error');
    } finally {
        btn.disabled = false;
        if (icon) icon.textContent = '🔄';
        btn.style.opacity = '1';
    }
}

async function loadIPPoolStats() {
    try {
        const response = await fetch('/api/demo/ip-pool/stats', { credentials: 'same-origin' });
        const data = await response.json();

        if (data.success && data.stats) {
            const statsEl = document.getElementById('ip-pool-stats');
            if (statsEl) {
                const s = data.stats;
                statsEl.innerHTML = `
                    <span class="ip-stat" title="Blocklist IPs">🚫 ${s.blocklist_count || 0}</span>
                    <span class="ip-stat" title="VPN IPs">🔒 ${s.vpn_count || 0}</span>
                    <span class="ip-stat" title="Datacenter IPs">🏢 ${s.datacenter_count || 0}</span>
                    <span class="ip-stat" title="Total Pool">📊 ${s.total || 0}</span>
                `;
            }
        }
    } catch (error) {
        console.error('[Simulation] Error loading IP pool stats:', error);
    }
}

// ========================
// PAGE VISIBILITY
// ========================
function initializeSimulationPageIfVisible() {
    const pageEl = document.getElementById('page-simulation');
    if (!pageEl) return;

    const isVisible = pageEl.style.display !== 'none' && pageEl.classList.contains('active');

    if (isVisible && !SimulationState.isPageInitialized) {
        console.log('[Simulation] Page became visible, loading data...');
        SimulationState.isPageInitialized = true;
        loadSimulationPage();
    }
}

function setupPageVisibilityWatcher() {
    const pageEl = document.getElementById('page-simulation');
    if (!pageEl) {
        console.log('[Simulation] Page element not found, retrying...');
        setTimeout(setupPageVisibilityWatcher, 100);
        return;
    }

    console.log('[Simulation] Setting up visibility watcher...');

    // Check immediately
    initializeSimulationPageIfVisible();

    // Watch for attribute changes (style, class)
    const observer = new MutationObserver(() => {
        initializeSimulationPageIfVisible();
    });

    observer.observe(pageEl, {
        attributes: true,
        attributeFilter: ['style', 'class']
    });
}

// Initialize based on document ready state
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupPageVisibilityWatcher);
} else {
    setupPageVisibilityWatcher();
}

// ========================
// GLOBAL EXPORTS
// ========================
window.switchSimulationTab = switchSimulationTab;
window.loadSimulationPage = loadSimulationPage;
window.onSimulationTargetChange = onSimulationTargetChange;
window.refreshIPPool = refreshIPPool;
