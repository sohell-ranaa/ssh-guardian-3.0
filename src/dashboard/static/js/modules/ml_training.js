/**
 * SSH Guardian v3.0 - ML Training Module (Simplified)
 * Handles training results display and algorithm comparison
 */

(function() {
    'use strict';

    // Initialize when page loads
    window.initTrainingPage = async function() {
        await loadMLTraining();
    };

    window.loadMLTraining = async function() {
        try {
            const [statsRes, comparisonRes, historyRes] = await Promise.all([
                fetch('/api/ml/training/stats'),
                fetch('/api/ml/training/algorithm-comparison'),
                fetch('/api/ml/training/runs?limit=20')
            ]);

            const stats = await statsRes.json();
            const comparison = await comparisonRes.json();
            const history = await historyRes.json();

            // Render stats
            if (stats.success && stats.stats) {
                const s = stats.stats;
                setText('stats-training-samples', (s.training_samples || 0).toLocaleString());
                setText('stats-testing-samples', (s.testing_samples || 0).toLocaleString());
                setText('stats-training-runs', s.training_runs || 0);
                // best_f1 comes as string from API, convert to number
                const bestF1 = parseFloat(s.best_f1) || 0;
                setText('stats-best-f1', bestF1 ? bestF1.toFixed(2) + '%' : '-');
            }

            // Render algorithm comparison
            if (comparison.success && comparison.comparison) {
                renderAlgorithmComparison(comparison.comparison.algorithms, comparison.comparison.best_algorithm);
            }

            // Render history
            if (history.success && history.runs) {
                renderHistory(history.runs);
            }

        } catch (e) {
            console.error('Error loading ML Training:', e);
        }
    };

    function setText(id, val) {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    function formatAlgo(name) {
        if (!name) return '-';
        const map = { 'random_forest': 'Random Forest', 'xgboost': 'XGBoost', 'lightgbm': 'LightGBM' };
        return map[name] || name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }

    function renderAlgorithmComparison(algorithms, bestAlgo) {
        const container = document.getElementById('algorithm-comparison');
        if (!container) return;

        if (!algorithms || algorithms.length === 0) {
            container.innerHTML = '<div style="color: var(--text-secondary);">No training data available</div>';
            return;
        }

        container.innerHTML = algorithms.map(a => {
            const isBest = a.algorithm === bestAlgo;
            const accuracy = parseFloat(a.avg_accuracy) || 0;
            const f1 = parseFloat(a.avg_f1) || 0;
            const precision = parseFloat(a.avg_precision) || parseFloat(a.avg_auc) || 0;
            const recall = parseFloat(a.avg_recall) || 0;

            return `
                <div class="algo-card ${isBest ? 'best' : ''}">
                    <div class="algo-header">
                        <span class="algo-name">${formatAlgo(a.algorithm)}</span>
                        ${isBest ? '<span class="algo-badge">BEST</span>' : ''}
                    </div>
                    <div class="algo-metrics">
                        <div class="algo-metric">
                            <span class="algo-metric-label">Accuracy</span>
                            <span class="algo-metric-value">${accuracy.toFixed(1)}%</span>
                        </div>
                        <div class="algo-metric">
                            <span class="algo-metric-label">F1 Score</span>
                            <span class="algo-metric-value">${f1.toFixed(1)}%</span>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        // Render best model info
        const best = algorithms.find(a => a.algorithm === bestAlgo) || algorithms[0];
        if (best) {
            renderBestModelInfo(best);
            renderConfusionMatrix(best.confusion_matrix);
        }
    }

    function renderBestModelInfo(model) {
        const container = document.getElementById('best-model-info');
        if (!container) return;

        const accuracy = parseFloat(model.avg_accuracy) || parseFloat(model.best_accuracy) || 0;
        const f1 = parseFloat(model.avg_f1) || parseFloat(model.best_f1) || 0;
        const precision = parseFloat(model.avg_precision) || parseFloat(model.avg_auc) || 0;
        const recall = parseFloat(model.avg_recall) || 0;

        container.innerHTML = `
            <div style="margin-bottom: 16px;">
                <div style="color: var(--text-secondary); font-size: 12px; margin-bottom: 4px;">Best Algorithm</div>
                <div style="font-size: 18px; font-weight: 600; color: var(--text-primary);">${formatAlgo(model.algorithm)}</div>
            </div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                <div>
                    <div style="color: var(--text-secondary); font-size: 11px; margin-bottom: 2px;">Accuracy</div>
                    <div style="font-size: 16px; font-weight: 600; color: #2EA44F;">${accuracy.toFixed(2)}%</div>
                </div>
                <div>
                    <div style="color: var(--text-secondary); font-size: 11px; margin-bottom: 2px;">F1 Score</div>
                    <div style="font-size: 16px; font-weight: 600; color: #2EA44F;">${f1.toFixed(2)}%</div>
                </div>
                <div>
                    <div style="color: var(--text-secondary); font-size: 11px; margin-bottom: 2px;">AUC</div>
                    <div style="font-size: 16px; font-weight: 600; color: var(--azure-blue);">${precision.toFixed(2)}%</div>
                </div>
                <div>
                    <div style="color: var(--text-secondary); font-size: 11px; margin-bottom: 2px;">Runs</div>
                    <div style="font-size: 16px; font-weight: 600; color: var(--azure-blue);">${model.total_runs || 0}</div>
                </div>
            </div>
        `;
    }

    function renderConfusionMatrix(matrix) {
        const container = document.getElementById('best-confusion-matrix');
        if (!container) return;

        if (matrix && matrix.length === 2) {
            const tn = matrix[0][0], fp = matrix[0][1], fn = matrix[1][0], tp = matrix[1][1];
            container.innerHTML = `
                <div style="display: grid; grid-template-columns: 90px 100px 100px; gap: 3px; text-align: center;">
                    <div></div>
                    <div style="padding: 6px; background: var(--background); font-size: 10px; font-weight: 600; color: var(--text-secondary);">Pred Benign</div>
                    <div style="padding: 6px; background: var(--background); font-size: 10px; font-weight: 600; color: var(--text-secondary);">Pred Threat</div>
                    <div style="padding: 6px; background: var(--background); font-size: 10px; font-weight: 600; color: var(--text-secondary);">Act Benign</div>
                    <div style="background: rgba(46, 164, 79, 0.15); padding: 10px;"><div style="font-size: 18px; font-weight: 700; color: #2EA44F;">${tn.toLocaleString()}</div><div style="font-size: 9px; color: var(--text-secondary);">TN</div></div>
                    <div style="background: rgba(209, 52, 56, 0.15); padding: 10px;"><div style="font-size: 18px; font-weight: 700; color: #D13438;">${fp.toLocaleString()}</div><div style="font-size: 9px; color: var(--text-secondary);">FP</div></div>
                    <div style="padding: 6px; background: var(--background); font-size: 10px; font-weight: 600; color: var(--text-secondary);">Act Threat</div>
                    <div style="background: rgba(209, 52, 56, 0.15); padding: 10px;"><div style="font-size: 18px; font-weight: 700; color: #D13438;">${fn.toLocaleString()}</div><div style="font-size: 9px; color: var(--text-secondary);">FN</div></div>
                    <div style="background: rgba(46, 164, 79, 0.15); padding: 10px;"><div style="font-size: 18px; font-weight: 700; color: #2EA44F;">${tp.toLocaleString()}</div><div style="font-size: 9px; color: var(--text-secondary);">TP</div></div>
                </div>
            `;
        } else {
            container.innerHTML = '';
        }
    }

    function renderHistory(runs) {
        const tbody = document.getElementById('training-history-body');
        if (!tbody) return;

        if (!runs || runs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" style="padding: 20px; text-align: center; color: var(--text-secondary);">No training runs found</td></tr>';
            return;
        }

        tbody.innerHTML = runs.map(r => {
            const date = new Date(r.started_at || r.created_at);
            const dateStr = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
            const statusColor = r.status === 'completed' ? '#2EA44F' : r.status === 'failed' ? '#D13438' : '#f59e0b';
            const statusBg = r.status === 'completed' ? 'rgba(46, 164, 79, 0.1)' : r.status === 'failed' ? 'rgba(209, 52, 56, 0.1)' : 'rgba(245, 158, 11, 0.1)';
            const bestF1 = r.best_f1 ? (parseFloat(r.best_f1) * 100).toFixed(1) : null;

            return `<tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 12px;">${dateStr}</td>
                <td style="padding: 12px; text-align: center;">${(r.total_events || 0).toLocaleString()}</td>
                <td style="padding: 12px; text-align: center;">${r.train_count || '-'} / ${r.test_count || '-'}</td>
                <td style="padding: 12px; text-align: center;">${r.models_trained || 0}</td>
                <td style="padding: 12px; text-align: center; font-weight: 600; color: #2EA44F;">${bestF1 ? bestF1 + '%' : '-'}</td>
                <td style="padding: 12px; text-align: center;"><span style="padding: 4px 8px; border-radius: 4px; font-size: 11px; background: ${statusBg}; color: ${statusColor};">${(r.status || 'unknown').toUpperCase()}</span></td>
            </tr>`;
        }).join('');
    }

    // Legacy function stubs for compatibility
    window.loadTrainingHistory = function() { return loadMLTraining(); };
    window.loadTrainingStats = function() { return loadMLTraining(); };
    window.refreshTrainingPage = function() { return loadMLTraining(); };

})();
