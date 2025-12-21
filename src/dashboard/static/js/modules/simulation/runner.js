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
