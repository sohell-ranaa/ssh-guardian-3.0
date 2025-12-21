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
