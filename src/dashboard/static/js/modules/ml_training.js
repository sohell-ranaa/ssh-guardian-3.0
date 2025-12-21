/**
 * SSH Guardian v3.0 - ML Training Page Module
 * Machine learning model training, status monitoring, and analysis
 * Extracted from ml_training.html for better maintainability
 */

(function() {
    'use strict';

    const CACHE_ENDPOINT = 'ml_training';

    /**
     * Format timestamp using TimeSettings or browser fallback
     */
    function formatMLTrainingTime(timestamp) {
        if (!timestamp) return '-';
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.formatFull(timestamp);
        }
        // Fallback - parse server timezone then display in browser TZ
        let ts = String(timestamp).replace(' ', 'T');
        if (!ts.endsWith('Z') && !ts.includes('+')) ts += '+08:00';
        return new Date(ts).toLocaleString();
    }

    let currentTrainingJobId = null;
    let trainingPollInterval = null;
    let simulationTemplates = [];

    /**
     * Initialize the training page
     */
    window.initTrainingPage = async function() {
        // Set default dates (last 30 days)
        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(startDate.getDate() - 30);

        const endDateEl = document.getElementById('training-end-date');
        const startDateEl = document.getElementById('training-start-date');

        if (endDateEl) endDateEl.value = endDate.toISOString().split('T')[0];
        if (startDateEl) startDateEl.value = startDate.toISOString().split('T')[0];

        // Set loading state
        if (typeof CacheManager !== 'undefined') {
            CacheManager.setLoading(CACHE_ENDPOINT);
        }

        const startTime = performance.now();

        try {
            // Load all data in parallel
            const [dataStatsResult, templatesResult, modelsResult, historyResult] = await Promise.all([
                loadDataStats(),
                loadSimulationTemplates(),
                loadModels(),
                loadTrainingHistory()
            ]);

            const loadTime = Math.round(performance.now() - startTime);
            const fromCache = dataStatsResult?.fromCache || modelsResult?.fromCache || historyResult?.fromCache;

            // Update cache indicator
            if (typeof CacheManager !== 'undefined') {
                CacheManager.updateStatus(CACHE_ENDPOINT, fromCache, loadTime);
                CacheManager.clearLoading(CACHE_ENDPOINT);
            }

            console.log(`ML Training page loaded in ${loadTime}ms (from_cache: ${fromCache})`);

        } catch (error) {
            console.error('Error initializing ML Training page:', error);

            if (typeof CacheManager !== 'undefined') {
                CacheManager.setError(CACHE_ENDPOINT, 'Failed to load training data');
            }
        }
    };

    /**
     * Refresh the page data
     */
    window.refreshTrainingPage = async function() {
        if (typeof CacheManager !== 'undefined') {
            CacheManager.setLoading(CACHE_ENDPOINT);
        }

        const startTime = performance.now();

        try {
            const [dataStatsResult, modelsResult, historyResult] = await Promise.all([
                loadDataStats(),
                loadModels(),
                loadTrainingHistory()
            ]);

            const loadTime = Math.round(performance.now() - startTime);
            const fromCache = dataStatsResult?.fromCache || modelsResult?.fromCache || historyResult?.fromCache;

            if (typeof CacheManager !== 'undefined') {
                CacheManager.updateStatus(CACHE_ENDPOINT, fromCache, loadTime);
                CacheManager.clearLoading(CACHE_ENDPOINT);
            }

        } catch (error) {
            console.error('Error refreshing:', error);
            if (typeof CacheManager !== 'undefined') {
                CacheManager.setError(CACHE_ENDPOINT, 'Refresh failed');
            }
        }
    };

    /**
     * Load data statistics
     */
    async function loadDataStats() {
        try {
            const [eventsRes, modelsRes] = await Promise.all([
                fetch('/api/ml/training/data-stats'),
                fetch('/api/ml/models')
            ]);

            const eventsData = await eventsRes.json();
            const modelsData = await modelsRes.json();

            if (eventsData.success) {
                const stats = eventsData.stats;
                updateElement('stats-total-events', (stats.total_events || 0).toLocaleString());
                updateElement('stats-failed-events', (stats.failed_events || 0).toLocaleString());
                updateElement('stats-success-events', (stats.success_events || 0).toLocaleString());
                updateElement('stats-unique-ips', (stats.unique_ips || 0).toLocaleString());

                // Show/hide warning based on data count
                const minDataWarning = document.getElementById('min-data-warning');
                if (minDataWarning) {
                    minDataWarning.style.display = stats.total_events < 100 ? 'block' : 'none';
                }
            }

            if (modelsData.success) {
                updateElement('stats-trained-models', modelsData.count || 0);
                const activeModel = modelsData.models?.find(m => m.is_active);
                updateElement('stats-active-model', activeModel ? formatAlgorithmName(activeModel.algorithm) : 'None');
            }

            return { success: true, fromCache: eventsData.from_cache || modelsData.from_cache };

        } catch (error) {
            console.error('Error loading data stats:', error);
            return { success: false, fromCache: false };
        }
    }

    /**
     * Load simulation templates
     */
    async function loadSimulationTemplates() {
        try {
            const response = await fetch('/api/simulation/templates');
            const data = await response.json();

            const select = document.getElementById('sim-template');
            if (!select) return { success: false, fromCache: false };

            if (data.success && data.templates && data.templates.length > 0) {
                simulationTemplates = data.templates;
                select.innerHTML = data.templates.map(t =>
                    `<option value="${t.id}">${t.name} (${t.severity})</option>`
                ).join('');

                // Show first template info
                updateTemplateInfo(data.templates[0].id);
            } else {
                select.innerHTML = '<option value="">No templates available</option>';
            }

            return { success: true, fromCache: false };

        } catch (error) {
            console.error('Error loading templates:', error);
            const select = document.getElementById('sim-template');
            if (select) {
                select.innerHTML = '<option value="">Error loading templates</option>';
            }
            return { success: false, fromCache: false };
        }
    }

    /**
     * Update template info display
     */
    function updateTemplateInfo(templateId) {
        const template = simulationTemplates.find(t => t.id === templateId);
        const infoEl = document.getElementById('sim-template-info');
        const descEl = document.getElementById('sim-template-desc');

        if (template && infoEl && descEl) {
            infoEl.style.display = 'block';
            descEl.textContent = template.description;
        }
    }

    // Template change handler
    document.addEventListener('change', function(e) {
        if (e.target.id === 'sim-template') {
            updateTemplateInfo(e.target.value);
        }
    });

    /**
     * Run simulation
     */
    window.runSimulation = async function() {
        const templateId = document.getElementById('sim-template')?.value;
        const eventCount = parseInt(document.getElementById('sim-event-count')?.value) || 50;
        const delay = parseInt(document.getElementById('sim-delay')?.value) || 50;

        if (!templateId) {
            showNotification('Please select a template', 'error');
            return;
        }

        const btn = document.getElementById('run-sim-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Generating...';
        }

        const progress = document.getElementById('sim-progress');
        if (progress) {
            progress.style.display = 'block';
            updateElement('sim-status', 'Starting simulation...');
            setProgressBar('sim-progress-bar', 10, 'warning');
        }

        try {
            const response = await fetch('/api/simulation/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    template_name: templateId,
                    parameters: {
                        event_count: eventCount,
                        delay_between_events: delay
                    }
                })
            });

            const data = await response.json();

            if (data.success) {
                updateElement('sim-status', 'Completed!');
                updateElement('sim-progress-text', `${data.summary?.events_generated || 0} events`);
                setProgressBar('sim-progress-bar', 100, 'success');

                // Refresh stats after delay
                setTimeout(() => {
                    loadDataStats();
                    if (progress) progress.style.display = 'none';
                    setProgressBar('sim-progress-bar', 0, 'warning');
                }, 2000);
            } else {
                throw new Error(data.error || 'Simulation failed');
            }
        } catch (error) {
            updateElement('sim-status', 'Error: ' + error.message);
            setProgressBar('sim-progress-bar', 100, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Generate Events';
            }
        }
    };

    /**
     * Quick generate events
     */
    window.quickGenerate = async function(templateId, buttonEl) {
        const btns = document.querySelectorAll('.quick-gen-btn');
        btns.forEach(b => {
            b.disabled = true;
            b.classList.remove('loading');
        });

        if (buttonEl) {
            buttonEl.classList.add('loading');
        }

        try {
            const response = await fetch('/api/simulation/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    template_name: templateId,
                    parameters: { event_count: 50, delay_between_events: 20 }
                })
            });

            const data = await response.json();

            if (data.success) {
                loadDataStats();
                if (typeof showNotification === 'function') {
                    showNotification(`Generated ${data.summary?.events_generated || 50} events`, 'success');
                }
            } else {
                if (typeof showNotification === 'function') {
                    showNotification('Error: ' + (data.error || 'Generation failed'), 'error');
                }
            }
        } catch (error) {
            if (typeof showNotification === 'function') {
                showNotification('Error: ' + error.message, 'error');
            }
        } finally {
            btns.forEach(b => {
                b.disabled = false;
                b.classList.remove('loading');
            });
        }
    };

    /**
     * Load trained models
     */
    async function loadModels() {
        try {
            const response = await fetch('/api/ml/models');
            const data = await response.json();

            const container = document.getElementById('models-container');
            if (!container) return { success: false, fromCache: false };

            if (data.success && data.models && data.models.length > 0) {
                container.innerHTML = `
                    <div class="models-grid">
                        ${data.models.map(model => renderModelCard(model)).join('')}
                    </div>
                `;
            } else {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">🤖</div>
                        <div class="empty-state-title">No models trained yet</div>
                        <div class="empty-state-desc">Generate training data and train your first model above</div>
                    </div>
                `;
            }

            return { success: true, fromCache: data.from_cache === true };

        } catch (error) {
            console.error('Error loading models:', error);
            return { success: false, fromCache: false };
        }
    }

    /**
     * Render a model card
     */
    function renderModelCard(model) {
        const badgeClass = model.is_active ? 'active' : model.status === 'candidate' ? 'candidate' : 'deprecated';
        const badgeText = model.is_active ? 'ACTIVE' : model.status.toUpperCase();

        return `
            <div class="model-card ${model.is_active ? 'active' : ''}">
                <div class="model-header">
                    <div>
                        <div class="model-name">${formatAlgorithmName(model.algorithm)}</div>
                        <div class="model-version">v${model.version}</div>
                    </div>
                    <span class="model-badge ${badgeClass}">${badgeText}</span>
                </div>
                <div class="model-metrics">
                    <div>
                        <div class="metric-label">Accuracy</div>
                        <div class="metric-value good">${model.metrics?.accuracy ? (model.metrics.accuracy * 100).toFixed(1) + '%' : '-'}</div>
                    </div>
                    <div>
                        <div class="metric-label">F1 Score</div>
                        <div class="metric-value good">${model.metrics?.f1_score ? (model.metrics.f1_score * 100).toFixed(1) + '%' : '-'}</div>
                    </div>
                    <div>
                        <div class="metric-label">Precision</div>
                        <div class="metric-value">${model.metrics?.precision ? (model.metrics.precision * 100).toFixed(1) + '%' : '-'}</div>
                    </div>
                    <div>
                        <div class="metric-label">Recall</div>
                        <div class="metric-value">${model.metrics?.recall ? (model.metrics.recall * 100).toFixed(1) + '%' : '-'}</div>
                    </div>
                </div>
                <div class="model-samples">
                    Samples: ${model.training_samples?.toLocaleString() || 0} train / ${model.test_samples?.toLocaleString() || 0} test
                </div>
                <div class="model-actions">
                    ${!model.is_active ? `
                        <button onclick="promoteModel(${model.id})" class="btn btn-success">Promote to Production</button>
                    ` : `
                        <button class="btn btn-disabled" disabled>Currently Active</button>
                    `}
                    <button onclick="deprecateModel(${model.id})" class="btn btn-outline-danger" style="flex: 0 0 auto; padding: 8px 12px;">Delete</button>
                </div>
            </div>
        `;
    }

    /**
     * Promote a model to production
     */
    window.promoteModel = async function(modelId) {
        if (!confirm('Promote this model to production? It will become the active model for threat detection.')) {
            return;
        }

        try {
            const response = await fetch(`/api/ml/models/${modelId}/promote`, { method: 'POST' });
            const data = await response.json();

            if (data.success) {
                loadModels();
                loadDataStats();
                if (typeof showNotification === 'function') {
                    showNotification('Model promoted to production', 'success');
                }
            } else {
                if (typeof showNotification === 'function') {
                    showNotification('Error: ' + (data.error || 'Failed to promote model'), 'error');
                }
            }
        } catch (error) {
            if (typeof showNotification === 'function') {
                showNotification('Error: ' + error.message, 'error');
            }
        }
    };

    /**
     * Deprecate (delete) a model
     */
    window.deprecateModel = async function(modelId) {
        if (!confirm('Delete this model? This action cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(`/api/ml/models/${modelId}/deprecate`, { method: 'POST' });
            const data = await response.json();

            if (data.success) {
                loadModels();
                loadDataStats();
                if (typeof showNotification === 'function') {
                    showNotification('Model deleted', 'success');
                }
            } else {
                if (typeof showNotification === 'function') {
                    showNotification('Error: ' + (data.error || 'Failed to delete model'), 'error');
                }
            }
        } catch (error) {
            if (typeof showNotification === 'function') {
                showNotification('Error: ' + error.message, 'error');
            }
        }
    };

    /**
     * Start model training
     */
    window.startTraining = async function() {
        const algorithm = document.getElementById('training-algorithm')?.value;
        const startDate = document.getElementById('training-start-date')?.value;
        const endDate = document.getElementById('training-end-date')?.value;
        const includeSim = document.getElementById('training-include-sim')?.checked;

        if (!startDate || !endDate) {
            showNotification('Please select start and end dates', 'error');
            return;
        }

        const btn = document.getElementById('start-training-btn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Starting...';
        }

        const progress = document.getElementById('training-progress');
        if (progress) {
            progress.style.display = 'block';
            updateElement('training-stage', 'Starting...');
            updateElement('training-progress-percent', '0%');
            setProgressBar('training-progress-bar', 0, 'success');
            updateElement('training-message', 'Preparing training job...');
        }

        try {
            const response = await fetch('/api/ml/training/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    algorithm: algorithm,
                    data_start: startDate,
                    data_end: endDate,
                    include_simulation: includeSim
                })
            });

            const data = await response.json();

            if (data.success) {
                currentTrainingJobId = data.job_id;
                pollTrainingStatus();
            } else {
                showNotification('Failed to start training: ' + (data.error || 'Unknown error'), 'error');
                resetTrainingUI();
            }

        } catch (error) {
            showNotification('Error starting training: ' + error.message, 'error');
            resetTrainingUI();
        }
    };

    /**
     * Poll for training status
     */
    function pollTrainingStatus() {
        if (trainingPollInterval) clearInterval(trainingPollInterval);

        trainingPollInterval = setInterval(async () => {
            if (!currentTrainingJobId) {
                clearInterval(trainingPollInterval);
                return;
            }

            try {
                const response = await fetch(`/api/ml/training/status/${currentTrainingJobId}`);
                const data = await response.json();

                if (data.success && data.job) {
                    const job = data.job;

                    updateElement('training-stage', job.stage || 'Processing...');
                    updateElement('training-progress-percent', (job.progress || 0) + '%');
                    setProgressBar('training-progress-bar', job.progress || 0, 'success');
                    updateElement('training-message', job.message || '');

                    if (job.stage === 'completed' || job.stage === 'failed') {
                        clearInterval(trainingPollInterval);
                        currentTrainingJobId = null;

                        if (job.stage === 'completed') {
                            setProgressBar('training-progress-bar', 100, 'success');
                            loadModels();
                            loadDataStats();
                            loadTrainingHistory();
                            if (typeof showNotification === 'function') {
                                showNotification('Model training completed successfully!', 'success');
                            }
                        } else {
                            setProgressBar('training-progress-bar', 100, 'error');
                            updateElement('training-message', 'Error: ' + (job.error || 'Training failed'));
                        }

                        resetTrainingUI();
                    }
                }
            } catch (error) {
                console.error('Error polling training status:', error);
            }
        }, 2000);
    }

    /**
     * Reset training UI state
     */
    function resetTrainingUI() {
        const btn = document.getElementById('start-training-btn');
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Start Training';
        }
    }

    /**
     * Load training history
     */
    async function loadTrainingHistory() {
        try {
            const response = await fetch('/api/ml/training/runs?limit=20');
            const data = await response.json();

            const tbody = document.getElementById('training-history-body');
            if (!tbody) return { success: false, fromCache: false };

            if (data.success && data.runs && data.runs.length > 0) {
                tbody.innerHTML = data.runs.map(run => renderTrainingRow(run)).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="7" class="loading-placeholder">No training runs yet</td></tr>';
            }

            return { success: true, fromCache: data.from_cache === true };

        } catch (error) {
            console.error('Error loading training history:', error);
            return { success: false, fromCache: false };
        }
    }

    /**
     * Render a training history row
     */
    function renderTrainingRow(run) {
        const statusClass = run.status === 'completed' ? 'status-completed' :
                           run.status === 'failed' ? 'status-failed' :
                           run.status === 'training' ? 'status-training' : '';

        return `
            <tr>
                <td style="font-family: monospace; font-size: 12px;">${run.uuid?.substring(0, 8) || '-'}</td>
                <td>${formatAlgorithmName(run.algorithm)}</td>
                <td class="text-center">
                    ${run.samples?.training?.toLocaleString() || '-'} / ${run.samples?.test?.toLocaleString() || '-'}
                </td>
                <td class="text-center">
                    <span class="status-badge ${statusClass}">${run.status.toUpperCase()}</span>
                </td>
                <td class="text-center" style="color: var(--text-secondary);">${run.duration_seconds ? formatDuration(run.duration_seconds) : '-'}</td>
                <td class="text-center" style="font-weight: 600; color: ${TC.success};">${run.result_model?.f1_score ? (run.result_model.f1_score * 100).toFixed(1) + '%' : '-'}</td>
                <td style="color: var(--text-secondary); font-size: 12px;">${formatMLTrainingTime(run.started_at)}</td>
            </tr>
        `;
    }

    /**
     * Helper: Update element text content
     */
    function updateElement(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    /**
     * Helper: Set progress bar width and color
     */
    function setProgressBar(id, percent, type) {
        const bar = document.getElementById(id);
        if (bar) {
            bar.style.width = percent + '%';
            bar.className = 'progress-bar progress-bar-' + type;
        }
    }

    /**
     * Helper: Format algorithm name
     */
    function formatAlgorithmName(name) {
        if (!name) return '-';
        return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    /**
     * Helper: Format duration
     */
    function formatDuration(seconds) {
        if (seconds < 60) return seconds + 's';
        if (seconds < 3600) return Math.floor(seconds / 60) + 'm ' + (seconds % 60) + 's';
        return Math.floor(seconds / 3600) + 'h ' + Math.floor((seconds % 3600) / 60) + 'm';
    }

    // showNotification - use shared utility from toast.js
    const showNotification = window.showNotification || ((msg, type) => window.showToast?.(msg, type));

})();
