/**
 * SSH Guardian v3.0 - Simulation Modal
 * Modal handling for scenario configuration
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    // Global helper for night time buttons
    window.setNightTime = function(time) {
        document.getElementById('scenario-var-time').value = time;
        // Update button states
        document.querySelectorAll('.night-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.textContent.includes(formatTimeDisplay(time))) {
                btn.classList.add('active');
            }
        });
    };

    function formatTimeDisplay(time) {
        const [hours] = time.split(':');
        const h = parseInt(hours);
        if (h === 0) return '12 AM';
        return `${h} AM`;
    }

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

            // Handle credential_stuffing category specially
            const credentialControls = document.getElementById('scenario-credential-controls');
            const standardUsername = document.getElementById('standard-username-row');
            const eventCountInput = document.getElementById('scenario-var-count');

            if (scenario.category === 'credential_stuffing') {
                // Show credential stuffing controls, hide standard username
                credentialControls.style.display = 'block';
                standardUsername.style.display = 'none';

                // Lock event count to 1
                eventCountInput.value = 1;
                eventCountInput.disabled = true;

                // Populate username dropdown from scenario.usernames
                const usernameSelect = document.getElementById('scenario-var-username-select');
                const usernames = scenario.usernames || ['john.smith', 'alice.johnson', 'bob.wilson'];
                usernameSelect.innerHTML = usernames.map(u =>
                    `<option value="${u}">${u}</option>`
                ).join('');

                // Reset night time buttons
                document.querySelectorAll('.night-btn').forEach(btn => btn.classList.remove('active'));
                // Set default to 2 AM
                setNightTime('02:00');

                // Load progress from API
                this._loadCredentialProgress(scenarioIp, usernames);
            } else {
                // Standard scenario - hide credential controls
                credentialControls.style.display = 'none';
                standardUsername.style.display = 'flex';
                eventCountInput.value = scenario.event_count || 1;
                eventCountInput.disabled = false;
            }

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

        async _loadCredentialProgress(ip, allUsernames) {
            try {
                const response = await fetch(`/api/live-sim/progress/${ip}`, { credentials: 'same-origin' });
                const data = await response.json();

                const progressText = document.getElementById('credential-progress-text');
                const progressList = document.getElementById('credential-progress-list');
                const usernameSelect = document.getElementById('scenario-var-username-select');

                if (data.success) {
                    const injectedUsers = data.usernames || [];
                    const uniqueCount = data.unique_count || 0;
                    const threshold = 3;

                    progressText.textContent = `${uniqueCount}/${threshold} unique users injected`;

                    // Render progress list with checkmarks
                    progressList.innerHTML = allUsernames.map(u => {
                        const isDone = injectedUsers.includes(u);
                        return `
                            <div class="progress-item ${isDone ? 'done' : 'pending'}">
                                <span class="check-icon">${isDone ? '✓' : '○'}</span>
                                <span>${u}</span>
                            </div>
                        `;
                    }).join('');

                    // Auto-select first unused username
                    const firstUnused = allUsernames.find(u => !injectedUsers.includes(u));
                    if (firstUnused) {
                        usernameSelect.value = firstUnused;
                    }
                } else {
                    progressText.textContent = '0/3 unique users injected';
                    progressList.innerHTML = allUsernames.map(u =>
                        `<div class="progress-item pending"><span class="check-icon">○</span><span>${u}</span></div>`
                    ).join('');
                }
            } catch (error) {
                console.error('[Simulation] Failed to load credential progress:', error);
            }
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
            } else if (scenario.category === 'credential_stuffing') {
                // Special button for credential stuffing - 1 login per run
                buttonsEl.innerHTML = `
                    <button class="scenario-action-btn attack" onclick="Sim.Runner.run('attack')" style="border-color: #8B008B;">
                        <span class="scenario-action-icon">🌙</span>
                        <div class="scenario-action-text">
                            <span class="scenario-action-title">Inject Login</span>
                            <span class="scenario-action-desc">Inject 1 login at selected night time - run 3x with different users</span>
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
