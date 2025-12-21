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
