/**
 * SSH Guardian v3.0 - Simulation Utilities
 * Common utility functions
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Utils = {
        copyToClipboard(text, label = 'Text') {
            const onSuccess = () => showToast(`${label} copied`, 'success');
            const onError = () => showToast('Copy failed', 'error');

            if (navigator.clipboard?.writeText) {
                navigator.clipboard.writeText(text).then(onSuccess).catch(() => this._fallbackCopy(text, onSuccess, onError));
            } else {
                this._fallbackCopy(text, onSuccess, onError);
            }
        },

        _fallbackCopy(text, onSuccess, onError) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.cssText = 'position: fixed; opacity: 0;';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                onSuccess();
            } catch (err) {
                onError();
            }
            document.body.removeChild(textarea);
        }
    };
})();
/**
 * SSH Guardian v3.0 - Simulation Modal
 * Modal handling for scenario configuration
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Modal = {
        currentScenario: null,

        open(scenarioId) {
            const scenario = SimulationState.allScenarios.find(s => s.id === scenarioId);
            if (!scenario) {
                console.error('[Simulation] Scenario not found:', scenarioId);
                return;
            }

            this.currentScenario = scenario;
            const card = document.querySelector(`.demo-scenario-card[data-scenario="${scenarioId}"]`);
            const scenarioIp = card?.querySelector('.scenario-ip')?.textContent.trim() || scenario.ip;

            // Populate modal
            document.getElementById('scenario-modal-title').textContent = scenario.name;
            document.getElementById('scenario-modal-subtitle').textContent = `IP: ${scenarioIp} | User: ${scenario.username || 'root'}`;
            document.getElementById('scenario-modal-desc').textContent = scenario.description || '';

            // Check target selection
            const targetId = document.getElementById('scenario-target')?.value || '';
            const noTargetWarning = document.getElementById('scenario-no-target');
            const varsContainer = document.getElementById('scenario-modal-vars');

            if (!targetId) {
                noTargetWarning.style.display = 'block';
                varsContainer.style.opacity = '0.5';
            } else {
                noTargetWarning.style.display = 'none';
                varsContainer.style.opacity = '1';
            }

            // Populate input fields
            document.getElementById('scenario-var-ip').value = scenarioIp || '8.8.8.8';
            document.getElementById('scenario-var-user').value = scenario.username || 'testuser';
            document.getElementById('scenario-var-count').value = scenario.event_count || 1;

            // Set auth type
            const authTypeSelect = document.getElementById('scenario-var-auth');
            if (scenario.log_template?.includes('publickey')) {
                authTypeSelect.value = 'publickey';
            } else if (scenario.log_template?.includes('keyboard-interactive')) {
                authTypeSelect.value = 'keyboard-interactive';
            } else {
                authTypeSelect.value = 'password';
            }

            // Set result
            const resultSelect = document.getElementById('scenario-var-result');
            resultSelect.value = scenario.log_template?.includes('Accepted') ? 'Accepted' : 'Failed';

            // Expected result
            const expectedEl = document.getElementById('scenario-modal-expected');
            expectedEl.className = 'scenario-modal-expected';

            if (scenario.category === 'baseline') {
                expectedEl.textContent = '✅ Expected: No Block, No Alert';
                expectedEl.classList.add('no-block');
            } else if (scenario.category === 'alert_only') {
                expectedEl.textContent = '⚠️ Expected: Alert Only (No Block)';
                expectedEl.classList.add('alert');
            } else {
                expectedEl.textContent = '🛡️ Expected: IP Will Be Blocked';
                expectedEl.classList.add('block');
            }

            // Render action buttons
            this._renderActionButtons(scenario);

            // Show modal
            const modal = document.getElementById('scenario-action-modal');
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';

            modal.onclick = (e) => {
                if (e.target === modal) this.close();
            };
            document.addEventListener('keydown', this._handleEscape);
        },

        close() {
            const modal = document.getElementById('scenario-action-modal');
            modal.style.display = 'none';
            document.body.style.overflow = '';
            document.removeEventListener('keydown', this._handleEscape);
            this.currentScenario = null;
        },

        _handleEscape(e) {
            if (e.key === 'Escape') Sim.Modal.close();
        },

        _renderActionButtons(scenario) {
            const buttonsEl = document.getElementById('scenario-action-buttons');

            if (scenario.category === 'baseline') {
                buttonsEl.innerHTML = `
                    <button class="scenario-action-btn normal" onclick="Sim.Runner.run('attack')" style="border-color: ${TC.successLight};">
                        <span class="scenario-action-icon">▶️</span>
                        <div class="scenario-action-text">
                            <span class="scenario-action-title">Run Test</span>
                            <span class="scenario-action-desc">Inject ${scenario.event_count || 1} successful login - verify NO block/alert</span>
                        </div>
                    </button>`;
            } else if (scenario.category === 'alert_only') {
                buttonsEl.innerHTML = `
                    <button class="scenario-action-btn baseline" onclick="Sim.Runner.run('baseline')">
                        <span class="scenario-action-icon">📊</span>
                        <div class="scenario-action-text">
                            <span class="scenario-action-title">Make Baseline</span>
                            <span class="scenario-action-desc">Create normal login pattern for ${scenario.username || 'user'}</span>
                        </div>
                    </button>
                    <button class="scenario-action-btn attack" onclick="Sim.Runner.run('attack')">
                        <span class="scenario-action-icon">🚨</span>
                        <div class="scenario-action-text">
                            <span class="scenario-action-title">Run Anomaly</span>
                            <span class="scenario-action-desc">Inject anomalous login - should trigger alert</span>
                        </div>
                    </button>`;
            } else {
                buttonsEl.innerHTML = `
                    <button class="scenario-action-btn attack" onclick="Sim.Runner.run('attack')">
                        <span class="scenario-action-icon">🚨</span>
                        <div class="scenario-action-text">
                            <span class="scenario-action-title">Run Attack</span>
                            <span class="scenario-action-desc">Inject ${scenario.event_count || 5} events - should trigger block</span>
                        </div>
                    </button>`;
            }
        }
    };
})();
/**
 * SSH Guardian v3.0 - Simulation Live Status
 * Live status panel for attack simulation feedback
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.LiveStatus = {
        startTime: null,
        TIMELINE_STEPS: ['inject', 'detect', 'analyze', 'block', 'complete'],

        show(title, subtitle, attackIp, scenarioName, expectedResult) {
            const panel = document.getElementById('live-attack-status');
            if (!panel) return;

            panel.style.display = 'block';
            this.startTime = Date.now();

            this._setText('live-status-title', title || 'Simulation Running');
            this._setText('live-status-subtitle', subtitle || 'Initializing...');

            const spinner = document.getElementById('live-status-spinner');
            if (spinner) spinner.style.display = 'block';

            this._setText('live-attack-ip', attackIp || '-');
            this._setText('live-scenario-name', scenarioName || '-');
            this._setText('live-expected-result', expectedResult || 'IP Block Expected');

            // Reset timeline
            document.querySelectorAll('.sim-timeline__circle').forEach(circle => {
                circle.classList.remove('sim-timeline__circle--active', 'sim-timeline__circle--complete', 'sim-timeline__circle--failed');
            });

            const progressBar = document.getElementById('live-progress-bar');
            if (progressBar) progressBar.style.width = '0%';

            // Clear log
            const logSection = document.getElementById('live-log-section');
            const logEl = document.getElementById('live-log');
            if (logSection) logSection.style.display = 'none';
            if (logEl) logEl.innerHTML = '';
        },

        hide() {
            const panel = document.getElementById('live-attack-status');
            if (panel) panel.style.display = 'none';
        },

        updateStep(step, status) {
            const stepIndex = this.TIMELINE_STEPS.indexOf(step);

            // Update progress bar
            if (stepIndex >= 0) {
                const progressBar = document.getElementById('live-progress-bar');
                if (progressBar) {
                    const progress = ((stepIndex + (status === 'complete' ? 1 : 0.5)) / this.TIMELINE_STEPS.length) * 100;
                    progressBar.style.width = `${progress}%`;
                }
            }

            // Update step circle
            const stepEl = document.querySelector(`.live-step-item[data-step="${step}"]`);
            if (stepEl) {
                const circle = stepEl.querySelector('.sim-timeline__circle');
                if (circle) {
                    circle.classList.remove('sim-timeline__circle--active', 'sim-timeline__circle--complete', 'sim-timeline__circle--failed');
                    if (status === 'active') circle.classList.add('sim-timeline__circle--active');
                    else if (status === 'complete') circle.classList.add('sim-timeline__circle--complete');
                    else if (status === 'failed') circle.classList.add('sim-timeline__circle--failed');
                }
            }

            // Mark previous steps complete
            for (let i = 0; i < stepIndex; i++) {
                const prevStepEl = document.querySelector(`.live-step-item[data-step="${this.TIMELINE_STEPS[i]}"]`);
                if (prevStepEl) {
                    const circle = prevStepEl.querySelector('.sim-timeline__circle');
                    if (circle) {
                        circle.classList.remove('sim-timeline__circle--active', 'sim-timeline__circle--failed');
                        circle.classList.add('sim-timeline__circle--complete');
                    }
                }
            }
        },

        addLog(message, type = 'info') {
            const logSection = document.getElementById('live-log-section');
            const logEl = document.getElementById('live-log');

            if (logSection && logEl) {
                logSection.style.display = 'block';
                const timestamp = new Date().toLocaleTimeString();
                const entry = document.createElement('div');
                entry.className = 'sim-activity-log__entry';
                entry.innerHTML = `<span class="sim-activity-log__time">[${timestamp}]</span> <span class="sim-activity-log__msg--${type}">${message}</span>`;
                logEl.appendChild(entry);
                logEl.scrollTop = logEl.scrollHeight;
            }
        },

        _setText(id, text) {
            const el = document.getElementById(id);
            if (el) el.textContent = text;
        }
    };
})();
/**
 * SSH Guardian v3.0 - Simulation Runner
 * Scenario execution and status polling
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Runner = {
        currentSimulationData: null,

        async run(actionType) {
            const scenario = Sim.Modal.currentScenario;
            if (!scenario) {
                showToast('No scenario selected', 'error');
                return;
            }

            const targetId = document.getElementById('scenario-target')?.value || '';
            if (!targetId) {
                showToast('Please select a target server first', 'warning');
                const noTargetWarning = document.getElementById('scenario-no-target');
                if (noTargetWarning) {
                    noTargetWarning.style.display = 'block';
                    noTargetWarning.style.animation = 'shake 0.5s';
                    setTimeout(() => noTargetWarning.style.animation = '', 500);
                }
                return;
            }

            // Read input values
            const scenarioIp = document.getElementById('scenario-var-ip')?.value || scenario.ip || '8.8.8.8';
            const scenarioUser = document.getElementById('scenario-var-user')?.value || scenario.username || 'testuser';
            const authType = document.getElementById('scenario-var-auth')?.value || 'password';
            const authResult = document.getElementById('scenario-var-result')?.value || 'Failed';
            const eventCount = parseInt(document.getElementById('scenario-var-count')?.value) || scenario.event_count || 1;

            Sim.Modal.close();
            const card = document.querySelector(`.demo-scenario-card[data-scenario="${scenario.id}"]`);

            // Show loading
            const loadingOverlay = card?.querySelector('.scenario-loading-overlay');
            const loadingText = card?.querySelector('.scenario-loading-text');
            if (card) card.classList.add('running');
            if (loadingOverlay) loadingOverlay.style.display = 'flex';

            const actionLabels = { 'baseline': 'Creating Baseline', 'normal': 'Running Normal Activity', 'attack': 'Running Attack' };
            if (loadingText) loadingText.textContent = actionLabels[actionType] + '...';

            try {
                const targetSelect = document.getElementById('scenario-target');
                const targetName = targetSelect.selectedOptions[0]?.text?.replace(/[🎯✅❌]/g, '').trim() || 'Remote Server';

                const actionTitles = {
                    'baseline': `📊 Creating Baseline: ${scenario.name}`,
                    'normal': `✅ Normal Activity: ${scenario.name}`,
                    'attack': `🚨 Attack: ${scenario.name}`
                };

                Sim.LiveStatus.show(actionTitles[actionType], `Injecting to ${targetName}...`, scenarioIp, scenario.name, actionType === 'attack' ? 'Block/Alert' : 'No Block');
                Sim.LiveStatus.updateStep('inject', 'active');
                Sim.LiveStatus.addLog(`Starting ${actionType}: ${scenario.name}`, 'info');

                const response = await fetch('/api/live-sim/live/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({
                        target_id: parseInt(targetId),
                        scenario_id: scenario.id,
                        source_ip: scenarioIp,
                        username: scenarioUser,
                        auth_type: authType,
                        auth_result: authResult,
                        event_count: eventCount,
                        action_type: actionType
                    })
                });
                const result = await response.json();

                if (result.success) {
                    if (loadingText) loadingText.textContent = `✅ Injected ${result.lines_written} events`;
                    Sim.LiveStatus.updateStep('inject', 'complete');
                    Sim.LiveStatus.updateStep('detect', 'active');
                    document.getElementById('live-status-subtitle').textContent = `Injected ${result.lines_written} events - waiting for detection...`;
                    Sim.LiveStatus.addLog(`✓ Injected ${result.lines_written} events to auth.log`, 'success');

                    const toastMessages = {
                        'baseline': `📊 Baseline created with ${result.lines_written} normal events`,
                        'normal': `✅ Normal activity injected (${result.lines_written} events)`,
                        'attack': `🚨 Attack injected (${result.lines_written} events)`
                    };
                    showToast(toastMessages[actionType], 'success', 3000);

                    if (actionType === 'attack') {
                        const simulationContext = {
                            scenario_name: scenario.name,
                            scenario_type: scenario.category,
                            attack_type: scenario.category === 'fail2ban' ? 'SSH Brute Force (Fail2ban)' : 'SSH Brute Force (UFW)',
                            target_name: result.target_name || targetName,
                            lines_written: result.lines_written
                        };
                        this.pollStatus(result.run_id, scenario.id, simulationContext, scenario.category);
                    } else {
                        setTimeout(() => {
                            Sim.LiveStatus.updateStep('detect', 'complete');
                            Sim.LiveStatus.updateStep('analyze', 'complete');
                            Sim.LiveStatus.updateStep('complete', 'complete');
                            document.getElementById('live-status-title').textContent = actionType === 'baseline' ? '📊 Baseline Created' : '✅ Normal Activity Complete';
                            document.getElementById('live-status-subtitle').textContent = `${result.lines_written} events processed`;
                            document.getElementById('live-status-spinner').style.display = 'none';
                            Sim.LiveStatus.addLog('Completed successfully', 'success');
                        }, 2000);
                    }

                    setTimeout(() => {
                        if (card) card.classList.remove('running');
                        if (loadingOverlay) loadingOverlay.style.display = 'none';
                    }, 2000);
                } else {
                    if (loadingText) loadingText.textContent = 'Failed!';
                    Sim.LiveStatus.updateStep('inject', 'failed');
                    document.getElementById('live-status-title').textContent = '❌ Failed';
                    document.getElementById('live-status-subtitle').textContent = result.error;
                    document.getElementById('live-status-spinner').style.display = 'none';
                    showToast(`Failed: ${result.error}`, 'error');
                    if (card) card.classList.remove('running');
                    if (loadingOverlay) loadingOverlay.style.display = 'none';
                }
            } catch (error) {
                console.error('[Simulation] Error:', error);
                if (loadingText) loadingText.textContent = 'Error!';
                showToast(`Error: ${error.message}`, 'error');
                if (card) card.classList.remove('running');
                if (loadingOverlay) loadingOverlay.style.display = 'none';
            }
        },

        async runDemoScenario(scenarioId) {
            const targetId = document.getElementById('scenario-target')?.value || '';
            if (!targetId) {
                showToast('⚠️ Please select a target server first', 'warning', 3000);
                return;
            }

            const card = document.querySelector(`.demo-scenario-card[data-scenario="${scenarioId}"]`);
            const loadingOverlay = card?.querySelector('.scenario-loading-overlay');
            const loadingText = card?.querySelector('.scenario-loading-text');
            const scenarioIp = card?.querySelector('.scenario-ip')?.textContent.trim() || null;

            card?.classList.add('running');
            if (loadingOverlay) loadingOverlay.style.display = 'flex';
            if (loadingText) loadingText.textContent = `Injecting ${scenarioIp} to server...`;

            try {
                const nameEl = card?.querySelector('.scenario-card-content > div:first-child > div:first-child');
                const scenarioName = nameEl?.textContent?.trim() || scenarioId;
                const scenarioCategory = card?.dataset?.category || 'ufw_block';

                const expectedResultMap = {
                    'ufw_block': 'UFW Block', 'fail2ban': 'Fail2ban Ban', 'baseline': 'No Block (Clean IP)',
                    'alert_only': 'ML Behavioral Alert (No Block)', 'ml_behavioral': 'ML Analysis'
                };

                const targetSelect = document.getElementById('scenario-target');
                const targetName = targetSelect.selectedOptions[0]?.text?.replace(/[🎯✅❌]/g, '').trim() || 'Remote Server';

                Sim.LiveStatus.show(`Running: ${scenarioName}`, `Injecting to ${targetName}...`, scenarioIp, scenarioName, expectedResultMap[scenarioCategory] || 'UFW Block');
                Sim.LiveStatus.updateStep('inject', 'active');
                Sim.LiveStatus.addLog(`Starting simulation: ${scenarioName}`, 'info');
                Sim.LiveStatus.addLog(`Target IP: ${scenarioIp}`, 'info');

                const response = await fetch('/api/live-sim/live/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({
                        target_id: parseInt(targetId),
                        scenario_id: scenarioId,
                        source_ip: scenarioIp
                    })
                });
                const runResult = await response.json();

                if (runResult.success) {
                    if (loadingText) loadingText.textContent = `✅ Injected ${runResult.lines_written} events`;

                    Sim.LiveStatus.updateStep('inject', 'complete');
                    Sim.LiveStatus.updateStep('detect', 'active');
                    document.getElementById('live-status-subtitle').textContent = `Injected ${runResult.lines_written} events - waiting for detection...`;
                    Sim.LiveStatus.addLog(`✓ Injected ${runResult.lines_written} events to auth.log`, 'success');
                    Sim.LiveStatus.addLog('Waiting for agent to detect events...', 'info');

                    showToast(`🎯 Injected ${runResult.lines_written} events to ${runResult.target_name}`, 'success', 3000);

                    const simulationContext = {
                        scenario_name: scenarioName,
                        scenario_type: scenarioCategory,
                        attack_type: scenarioCategory === 'fail2ban' ? 'SSH Brute Force (Fail2ban)' : 'SSH Brute Force (UFW)',
                        target_name: runResult.target_name || targetName.replace(/[🎯✅❌]/g, '').trim(),
                        lines_written: runResult.lines_written
                    };

                    this.pollStatus(runResult.run_id, scenarioId, simulationContext, scenarioCategory);

                    setTimeout(() => {
                        card?.classList.remove('running');
                        if (loadingOverlay) loadingOverlay.style.display = 'none';
                    }, 2000);
                } else {
                    if (loadingText) loadingText.textContent = 'Failed!';
                    Sim.LiveStatus.updateStep('inject', 'failed');
                    document.getElementById('live-status-title').textContent = '❌ Injection Failed';
                    document.getElementById('live-status-subtitle').textContent = runResult.error;
                    document.getElementById('live-status-spinner').style.display = 'none';
                    showToast(`Failed: ${runResult.error}`, 'error');
                }
            } catch (error) {
                console.error('[Demo] Error:', error);
                if (loadingText) loadingText.textContent = 'Error!';
                showToast('Failed to run scenario', 'error');
            } finally {
                setTimeout(() => {
                    card?.classList.remove('running');
                    if (loadingOverlay) loadingOverlay.style.display = 'none';
                }, 500);
            }
        },

        async pollStatus(runId, scenarioId, simulationContext = {}, scenarioCategory = '') {
            let attempts = 0;
            const maxAttempts = 60;
            let detectedOnce = false;

            const poll = async () => {
                if (attempts >= maxAttempts) {
                    console.log('[LiveSim] Stopped polling after max attempts');
                    showToast('Simulation polling stopped - check Firewall page for results', 'info');
                    return;
                }
                attempts++;

                try {
                    const response = await fetch(`/api/live-sim/live/${runId}/status`, { credentials: 'same-origin' });
                    const data = await response.json();

                    if (data.success) {
                        if (data.events_detected > 0 && !detectedOnce) {
                            detectedOnce = true;
                            showToast(`👁️ Detected ${data.events_detected} events from agent`, 'info', 3000);
                            Sim.LiveStatus.updateStep('detect', 'complete');
                            Sim.LiveStatus.updateStep('analyze', 'active');
                            document.getElementById('live-status-subtitle').textContent = 'Detected! Analyzing threat...';
                            Sim.LiveStatus.addLog(`✓ Detected ${data.events_detected} events from agent`, 'success');
                            Sim.LiveStatus.addLog('Running threat analysis...', 'info');
                        }

                        if (data.is_complete) {
                            let blockedBy = null;
                            let ip = data.source_ip;

                            if (data.fail2ban_block) {
                                blockedBy = 'fail2ban';
                                showToast('🚫 Fail2ban blocked the attacking IP!', 'success', 5000);
                            }
                            if (data.ip_block) {
                                blockedBy = blockedBy ? `${blockedBy} + SSH Guardian` : 'SSH Guardian';
                                showToast(`🔒 SSH Guardian blocked IP (${data.ip_block.source})`, 'success', 5000);
                            }

                            const fullResultData = {
                                completed: true,
                                blocked: !!blockedBy,
                                blocked_by: blockedBy,
                                ip: ip,
                                fail2ban: data.fail2ban_block,
                                ufw: data.ip_block,
                                events_detected: data.events_detected || 0,
                                detected: detectedOnce || data.events_detected > 0,
                                ml_evaluated: !!data.ml_evaluation,
                                block_id: data.ip_block?.block_id,
                                block_source: data.ip_block?.source,
                                scenario_id: scenarioId,
                                scenario_name: simulationContext.scenario_name || scenarioId,
                                scenario_type: simulationContext.scenario_type,
                                attack_type: simulationContext.attack_type,
                                target_name: simulationContext.target_name,
                                lines_written: simulationContext.lines_written
                            };

                            if (blockedBy) {
                                Sim.LiveStatus.updateStep('analyze', 'complete');
                                Sim.LiveStatus.updateStep('block', 'complete');
                                Sim.LiveStatus.updateStep('complete', 'complete');
                                document.getElementById('live-status-title').textContent = '✅ Attack Blocked!';
                                document.getElementById('live-status-subtitle').textContent = `IP ${ip} blocked by ${blockedBy}`;
                                document.getElementById('live-status-spinner').style.display = 'none';
                                Sim.LiveStatus.addLog(`🛡️ IP ${ip} BLOCKED by ${blockedBy}`, 'success');
                            } else {
                                Sim.LiveStatus.updateStep('analyze', 'complete');
                                Sim.LiveStatus.updateStep('complete', 'complete');
                                document.getElementById('live-status-title').textContent = '✅ Simulation Complete';
                                document.getElementById('live-status-subtitle').textContent = 'Events injected - check results below';
                                document.getElementById('live-status-spinner').style.display = 'none';
                                Sim.LiveStatus.addLog('Simulation completed - no block triggered', 'warning');
                            }

                            Sim.Results.show(fullResultData);

                            if (!blockedBy) {
                                showToast('✅ Simulation complete - IP not blocked (may need more events)', 'info', 4000);
                            }
                            return;
                        }
                    }
                } catch (error) {
                    console.error('[LiveSim] Error polling status:', error);
                }

                setTimeout(poll, 2000);
            };

            setTimeout(poll, 3000);
        }
    };
})();
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
                this._setText('sim-block-reason', `Block ID: #${data.block_id || 'N/A'} | Source: ${data.block_source || 'auto'}`);
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
        }
    };
})();
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
/**
 * SSH Guardian v3.0 - Simulation Blocking
 * IP blocking modal and execution
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Blocking = {
        async showModal(ip) {
            console.log('[Block] Checking IP status:', ip);

            const modal = document.createElement('div');
            modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 10000;';

            const modalContent = document.createElement('div');
            modalContent.style.cssText = 'background: var(--card-bg); border-radius: 12px; padding: 24px; max-width: 600px; width: 90%; box-shadow: 0 8px 32px rgba(0,0,0,0.3);';

            modalContent.innerHTML = `<h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">🔍 Checking IP Status...</h3>
                <div style="text-align: center; padding: 40px;"><div style="font-size: 48px;">⏳</div>
                <p style="margin: 16px 0 0 0; color: var(--text-secondary);">Checking if ${ip} is already blocked...</p></div>`;

            modal.appendChild(modalContent);
            document.body.appendChild(modal);

            try {
                const globalResponse = await fetch(`/api/dashboard/blocking/blocks/check/${ip}`, { credentials: 'same-origin' });
                const globalStatus = await globalResponse.json();

                const agentsResponse = await fetch('/api/agents/list', { credentials: 'same-origin' });
                const agentsData = await agentsResponse.json();
                const agents = agentsData.agents || [];

                const agentChecks = await Promise.all(
                    agents.map(async (agent) => {
                        try {
                            const resp = await fetch(`/api/agents/${agent.id}/blocked-ips`, { credentials: 'same-origin' });
                            const data = await resp.json();
                            const isBlocked = data.blocked_ips?.some(blocked => blocked.ip_address === ip);
                            return { agent: agent.hostname, id: agent.id, blocked: isBlocked };
                        } catch (err) {
                            return { agent: agent.hostname, id: agent.id, blocked: false, error: true };
                        }
                    })
                );

                const blockedOnAgents = agentChecks.filter(a => a.blocked);
                const isAlreadyBlocked = globalStatus.is_blocked || blockedOnAgents.length > 0;

                modalContent.innerHTML = `
                    <h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">${isAlreadyBlocked ? '⚠️' : '🚫'} Block IP Address</h3>
                    <div style="background: var(--background); padding: 16px; border-radius: 8px; margin-bottom: 16px;">
                        <div style="font-family: monospace; font-size: 18px; font-weight: 600; color: var(--azure-blue);">${ip}</div>
                    </div>
                    ${isAlreadyBlocked ? `
                        <div style="background: rgba(230, 165, 2, 0.1); border-left: 4px solid ${TC.warning}; padding: 12px; margin-bottom: 16px; border-radius: 4px;">
                            <strong style="color: ${TC.warning};">⚠️ Already Blocked</strong>
                            <ul style="margin: 8px 0 0 0; padding-left: 20px; font-size: 13px;">
                                ${globalStatus.is_blocked ? `<li><strong>Global Blocklist</strong></li>` : ''}
                                ${blockedOnAgents.map(a => `<li>Agent: ${a.agent}</li>`).join('')}
                            </ul>
                        </div>` : `
                        <div style="background: rgba(209, 52, 56, 0.1); border-left: 4px solid ${TC.danger}; padding: 12px; margin-bottom: 16px; border-radius: 4px;">
                            <p style="margin: 0; font-size: 14px;"><strong>⚠️ Warning:</strong> This will block the IP on all agents.</p>
                        </div>`}
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; font-size: 14px;">Block Reason:</label>
                        <input id="block-reason" type="text" value="Threat detected via simulation" style="width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: var(--background); color: var(--text-primary);">
                    </div>
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; font-size: 14px;">Duration:</label>
                        <select id="block-duration" style="width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: var(--background); color: var(--text-primary);">
                            <option value="permanent">Permanent</option>
                            <option value="24h">24 Hours</option>
                            <option value="7d">7 Days</option>
                            <option value="30d">30 Days</option>
                        </select>
                    </div>
                    <div style="display: flex; gap: 12px; justify-content: flex-end;">
                        <button onclick="this.closest('[style*=fixed]').remove()" style="padding: 10px 20px; background: var(--background); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-weight: 600;">Cancel</button>
                        ${!isAlreadyBlocked ? `<button onclick="Sim.Blocking.execute('${ip}')" style="padding: 10px 20px; background: ${TC.danger}; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">🚫 Block IP</button>` : ''}
                    </div>`;

            } catch (error) {
                console.error('[Block] Error checking status:', error);
                modalContent.innerHTML = `<h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">❌ Error</h3>
                    <p style="margin: 0 0 16px 0;">Failed to check IP status: ${error.message}</p>
                    <button onclick="this.closest('[style*=fixed]').remove()" style="padding: 10px 20px; background: var(--background); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-weight: 600;">Close</button>`;
            }
        },

        async execute(ip) {
            const reason = document.getElementById('block-reason').value;
            const duration = document.getElementById('block-duration').value;
            const modal = document.querySelector('[style*="position: fixed"]');

            console.log('[Block] Executing block:', { ip, reason, duration });

            try {
                const response = await fetch('/api/dashboard/blocking/blocks', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ ip_address: ip, reason, duration })
                });

                const result = await response.json();

                if (result.success) {
                    showToast(`✅ IP ${ip} blocked successfully`, 'success');
                    modal.remove();
                } else {
                    showToast(`❌ Failed to block IP: ${result.error}`, 'error');
                }
            } catch (error) {
                console.error('[Block] Error:', error);
                showToast('❌ Failed to block IP', 'error');
            }
        }
    };
})();
/**
 * SSH Guardian v3.0 - Simulation Index
 * Namespace setup and global exports for backward compatibility
 */
(function() {
    'use strict';

    // Initialize namespace
    window.Sim = window.Sim || {};

    // Global exports for backward compatibility
    // These map old function names to new namespace
    window.openScenarioModal = (id) => Sim.Modal.open(id);
    window.closeScenarioModal = () => Sim.Modal.close();
    window.runScenarioAction = (type) => Sim.Runner.run(type);
    window.runDemoScenario = (id) => Sim.Runner.runDemoScenario(id);
    window.showLiveStatus = (...args) => Sim.LiveStatus.show(...args);
    window.hideLiveStatus = () => Sim.LiveStatus.hide();
    window.updateLiveStep = (step, status) => Sim.LiveStatus.updateStep(step, status);
    window.addLiveLog = (msg, type) => Sim.LiveStatus.addLog(msg, type);
    window.showSimulationResults = (data) => Sim.Results.show(data);
    window.hideSimulationResults = () => Sim.Results.hide();
    window.populateAnalysisTab = (data) => Sim.Analysis.populate(data);
    window.populateResultsTab = (data) => Sim.Recommendations.populate(data);
    window.blockIPWithModal = (ip) => Sim.Blocking.showModal(ip);
    window.blockIPInline = (ip) => Sim.Blocking.showModal(ip);
    window.executeIPBlock = (ip) => Sim.Blocking.execute(ip);
    window.copyToClipboard = (text, label) => Sim.Utils.copyToClipboard(text, label);

    console.log('[Simulation] Module initialized');
})();
