/**
 * Blocking Rules Page Module
 * Handles blocking rules management and CRUD operations
 */

// Load Blocking Rules page data
async function loadBlockingRulesPage() {
    await Promise.all([
        loadOverallStats(),
        loadRules()
    ]);
}

// Load overall blocking statistics
async function loadOverallStats() {
    try {
        const response = await fetch('/api/dashboard/blocking/stats');
        const data = await response.json();

        if (data.success && data.stats) {
            const stats = data.stats;

            // Update statistics display
            document.getElementById('statTotalBlocks').textContent = stats.total_blocks || 0;
            document.getElementById('statActiveBlocks').textContent = stats.active_blocks || 0;
            document.getElementById('statManualBlocks').textContent = stats.blocks_by_source?.manual || 0;
            document.getElementById('statRuleBlocks').textContent = stats.blocks_by_source?.rule_based || 0;
            document.getElementById('statRecent24h').textContent = stats.recent_24h || 0;

            // Show the stats card
            document.getElementById('overallBlockingStats').style.display = 'block';
        }
    } catch (error) {
        console.error('Error loading overall stats:', error);
        // Don't show stats card if error
    }
}

// Load all blocking rules
async function loadRules() {
    const loadingEl = document.getElementById('rulesLoading');
    const tableEl = document.getElementById('rulesTable');
    const errorEl = document.getElementById('rulesError');

    try {
        // Show loading
        loadingEl.style.display = 'block';
        tableEl.style.display = 'none';
        errorEl.style.display = 'none';

        const response = await fetch('/api/dashboard/blocking/rules/list');
        const data = await response.json();

        if (!data.success || !data.rules || data.rules.length === 0) {
            loadingEl.style.display = 'none';
            tableEl.innerHTML = '<div class="empty-state-small">No blocking rules configured</div>';
            tableEl.style.display = 'block';
            return;
        }

        // Build table
        const tableBody = document.getElementById('rulesTableBody');
        tableBody.innerHTML = data.rules.map(rule => {
            const statusBadge = rule.is_enabled
                ? '<span style="padding: 4px 12px; background: #107C10; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Enabled</span>'
                : '<span style="padding: 4px 12px; background: #8A8886; color: white; border-radius: 3px; font-size: 12px; font-weight: 600;">Disabled</span>';

            const conditions = formatRuleConditions(rule.rule_type, rule.conditions);
            const stats = `
                <div style="font-size: 12px;">
                    <div><strong>Triggered:</strong> ${rule.times_triggered || 0} times</div>
                    <div><strong>IPs Blocked:</strong> ${rule.ips_blocked_total || 0}</div>
                    ${rule.last_triggered_at ? `<div><strong>Last:</strong> ${formatLocalDateTime(rule.last_triggered_at)}</div>` : ''}
                </div>
            `;

            // Check if this is a system rule (protected)
            const isSystemRule = rule.is_system_rule;

            // Show delete button only for non-system rules
            const deleteButton = isSystemRule
                ? `<button
                    disabled
                    style="padding: 6px 12px; border: 1px solid #8A8886; background: var(--surface); color: #8A8886; border-radius: 3px; cursor: not-allowed; font-size: 12px;"
                    title="System rules cannot be deleted"
                >
                    🔒 Protected
                </button>`
                : `<button
                    onclick="deleteRule(${rule.id}, '${escapeHtml(rule.rule_name)}')"
                    style="padding: 6px 12px; border: 1px solid #D13438; background: var(--surface); color: #D13438; border-radius: 3px; cursor: pointer; font-size: 12px;"
                    title="Delete Rule"
                >
                    Delete
                </button>`;

            return `
                <tr style="border-bottom: 1px solid var(--border-light);">
                    <td style="padding: 12px; font-size: 13px; font-weight: 600;">
                        ${escapeHtml(rule.rule_name)}
                        ${isSystemRule ? '<span style="margin-left: 8px; padding: 2px 6px; background: #0078D4; color: white; border-radius: 2px; font-size: 10px; font-weight: 600;">SYSTEM</span>' : ''}
                    </td>
                    <td style="padding: 12px; font-size: 13px;">${escapeHtml(rule.rule_type)}</td>
                    <td style="padding: 12px; font-size: 13px; text-align: center;">${rule.priority}</td>
                    <td style="padding: 12px; font-size: 12px;">${conditions}</td>
                    <td style="padding: 12px;">${stats}</td>
                    <td style="padding: 12px; text-align: center;">${statusBadge}</td>
                    <td style="padding: 12px; text-align: right;">
                        <button
                            onclick="toggleRuleStatus(${rule.id}, ${rule.is_enabled})"
                            style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 12px; margin-right: 4px;"
                            title="${rule.is_enabled ? 'Disable' : 'Enable'} Rule"
                        >
                            ${rule.is_enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                            onclick="editRule(${rule.id})"
                            style="padding: 6px 12px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 12px; margin-right: 4px;"
                            title="Edit Rule"
                        >
                            Edit
                        </button>
                        ${deleteButton}
                    </td>
                </tr>
            `;
        }).join('');

        // Show table
        loadingEl.style.display = 'none';
        tableEl.style.display = 'block';

    } catch (error) {
        console.error('Error loading rules:', error);
        loadingEl.style.display = 'none';
        errorEl.style.display = 'block';
    }
}

// Format rule conditions for display
function formatRuleConditions(ruleType, conditions) {
    if (typeof conditions === 'string') {
        try {
            conditions = JSON.parse(conditions);
        } catch (e) {
            return 'Invalid conditions';
        }
    }

    switch (ruleType) {
        case 'brute_force':
            return `
                <div style="font-size: 12px;">
                    <div><strong>Failed Attempts:</strong> ${conditions.failed_attempts || 'N/A'}</div>
                    <div><strong>Time Window:</strong> ${conditions.time_window_minutes || 'N/A'} min</div>
                </div>
            `;
        case 'threat_threshold':
            return `
                <div style="font-size: 12px;">
                    <div><strong>Threat Level:</strong> ${conditions.threat_level || 'N/A'}</div>
                    <div><strong>Min Score:</strong> ${conditions.min_abuseipdb_score || 'N/A'}</div>
                </div>
            `;
        case 'country_block':
            return `
                <div style="font-size: 12px;">
                    <div><strong>Countries:</strong> ${conditions.countries ? conditions.countries.join(', ') : 'N/A'}</div>
                </div>
            `;
        case 'rate_limit':
            return `
                <div style="font-size: 12px;">
                    <div><strong>Max Requests:</strong> ${conditions.max_requests || 'N/A'}</div>
                    <div><strong>Time Window:</strong> ${conditions.time_window_seconds || 'N/A'}s</div>
                </div>
            `;
        default:
            return '<div style="font-size: 12px;">Custom conditions</div>';
    }
}

// Toggle rule enabled/disabled status
async function toggleRuleStatus(ruleId, currentStatus) {
    try {
        const action = currentStatus ? 'disable' : 'enable';
        if (!confirm(`Are you sure you want to ${action} this rule?`)) {
            return;
        }

        const response = await fetch(`/api/dashboard/blocking/rules/${ruleId}/toggle`, {
            method: 'POST'
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`Rule ${action}d successfully`, 'success');
            loadRules();
        } else {
            showNotification(`Failed to ${action} rule: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error toggling rule:', error);
        showNotification('Error updating rule status', 'error');
    }
}

// Edit rule
async function editRule(ruleId) {
    try {
        // Fetch rule details
        const response = await fetch(`/api/dashboard/blocking/rules/list`);
        const data = await response.json();

        if (!data.success) {
            showNotification('Failed to load rule details', 'error');
            return;
        }

        const rule = data.rules.find(r => r.id === ruleId);
        if (!rule) {
            showNotification('Rule not found', 'error');
            return;
        }

        // Populate the create form with rule data
        document.getElementById('ruleName').value = rule.rule_name;
        document.getElementById('ruleType').value = rule.rule_type;
        document.getElementById('ruleBlockDuration').value = rule.block_duration_minutes;
        document.getElementById('rulePriority').value = rule.priority;
        document.getElementById('ruleDescription').value = rule.description || '';

        // Populate conditions based on rule type
        if (rule.rule_type === 'brute_force') {
            document.getElementById('bruteForceConditions').style.display = 'block';
            document.getElementById('failedAttempts').value = rule.conditions.failed_attempts || 5;
            document.getElementById('timeWindow').value = rule.conditions.time_window_minutes || 10;
        } else if (rule.rule_type === 'api_reputation' || rule.rule_type === 'threat_threshold') {
            document.getElementById('threatConditions').style.display = 'block';
            document.getElementById('minThreatLevel').value = rule.conditions.threat_level || rule.conditions.min_threat_level || 'high';
            document.getElementById('minConfidence').value = rule.conditions.min_confidence || 0.5;
        }

        // Show the form
        const formEl = document.getElementById('createRuleForm');
        formEl.style.display = 'block';

        // Update form title
        const titleEl = formEl.querySelector('.card-title');
        if (titleEl) {
            titleEl.textContent = `Edit Rule: ${rule.rule_name}`;
        }

        // Change submit button behavior for editing
        const submitBtn = document.getElementById('submitCreateRule');
        if (submitBtn) {
            submitBtn.textContent = 'Update Rule';
            submitBtn.onclick = () => updateRule(ruleId);
        }

        // Scroll to form
        formEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (error) {
        console.error('Error loading rule for editing:', error);
        showNotification('Error loading rule details', 'error');
    }
}

// Update rule
async function updateRule(ruleId) {
    try {
        const ruleName = document.getElementById('ruleName').value;
        const ruleType = document.getElementById('ruleType').value;
        const blockDuration = parseInt(document.getElementById('ruleBlockDuration').value);
        const priority = parseInt(document.getElementById('rulePriority').value);
        const description = document.getElementById('ruleDescription').value;

        if (!ruleName || !ruleType) {
            showNotification('Please fill in required fields', 'error');
            return;
        }

        let conditions = {};

        if (ruleType === 'brute_force') {
            conditions = {
                failed_attempts: parseInt(document.getElementById('failedAttempts').value),
                time_window_minutes: parseInt(document.getElementById('timeWindow').value),
                event_type: 'failed'
            };
        } else if (ruleType === 'api_reputation' || ruleType === 'threat_threshold') {
            conditions = {
                min_threat_level: document.getElementById('minThreatLevel').value,
                min_confidence: parseFloat(document.getElementById('minConfidence').value),
                sources: ['abuseipdb', 'virustotal', 'shodan']
            };
        }

        const response = await fetch(`/api/dashboard/blocking/rules/${ruleId}/update`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rule_name: ruleName,
                rule_type: ruleType,
                conditions: conditions,
                block_duration_minutes: blockDuration,
                priority: priority,
                description: description
            })
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Rule updated successfully', 'success');
            setTimeout(() => {
                resetEditForm();
                loadRules();
            }, 1500);
        } else {
            showNotification(`Failed to update rule: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error updating rule:', error);
        showNotification('Error updating rule', 'error');
    }
}

// Reset form after editing
function resetEditForm() {
    const formEl = document.getElementById('createRuleForm');
    formEl.style.display = 'none';

    // Reset title
    const titleEl = formEl.querySelector('.card-title');
    if (titleEl) {
        titleEl.textContent = 'Create Blocking Rule';
    }

    // Reset submit button
    const submitBtn = document.getElementById('submitCreateRule');
    if (submitBtn) {
        submitBtn.textContent = 'Create Rule';
        submitBtn.onclick = null; // Remove custom onclick, let main form handler take over
    }

    // Clear form fields
    document.getElementById('ruleName').value = '';
    document.getElementById('ruleType').value = '';
    document.getElementById('ruleBlockDuration').value = '1440';
    document.getElementById('rulePriority').value = '50';
    document.getElementById('ruleDescription').value = '';
    document.getElementById('failedAttempts').value = '5';
    document.getElementById('timeWindow').value = '10';
    document.getElementById('minThreatLevel').value = 'high';
    document.getElementById('minConfidence').value = '0.5';
    document.getElementById('bruteForceConditions').style.display = 'none';
    document.getElementById('threatConditions').style.display = 'none';
}

// Delete rule
async function deleteRule(ruleId, ruleName) {
    if (!confirm(`Are you sure you want to delete the rule "${ruleName}"?\n\nThis action cannot be undone.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/dashboard/blocking/rules/${ruleId}/delete`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showNotification(`Rule "${ruleName}" deleted successfully`, 'success');
            loadRules();
        } else {
            showNotification(`Failed to delete rule: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error deleting rule:', error);
        showNotification('Error deleting rule', 'error');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const colors = {
        success: '#107C10',
        error: '#D13438',
        info: '#0078D4',
        warning: '#FFB900'
    };

    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        padding: 16px 24px;
        background: ${colors[type]};
        color: white;
        border-radius: 4px;
        font-size: 14px;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add animation styles
if (!document.getElementById('notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(400px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}

// Initialize event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Refresh button
    const refreshBtn = document.getElementById('refreshRules');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadOverallStats();
            loadRules();
        });
    }

    // Show create rule form button
    const showCreateBtn = document.getElementById('showCreateRuleForm');
    if (showCreateBtn) {
        showCreateBtn.addEventListener('click', function() {
            document.getElementById('createRuleForm').style.display = 'block';
        });
    }

    // Cancel rule form button
    const cancelBtn = document.getElementById('cancelRuleForm');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', function() {
            resetEditForm();
        });
    }

    // Rule type selector
    const ruleTypeSelect = document.getElementById('ruleType');
    if (ruleTypeSelect) {
        ruleTypeSelect.addEventListener('change', function() {
            // Hide all condition sections
            document.getElementById('bruteForceConditions').style.display = 'none';
            document.getElementById('threatConditions').style.display = 'none';

            // Show relevant section
            if (this.value === 'brute_force') {
                document.getElementById('bruteForceConditions').style.display = 'block';
            } else if (this.value === 'api_reputation' || this.value === 'threat_threshold') {
                document.getElementById('threatConditions').style.display = 'block';
            }
        });
    }

    // Submit create rule button
    const submitBtn = document.getElementById('submitCreateRule');
    if (submitBtn) {
        submitBtn.addEventListener('click', async function() {
            // Only handle create, not update (update is handled by onclick)
            if (this.textContent === 'Create Rule') {
                await createRule();
            }
        });
    }
});

// Create a new rule
async function createRule() {
    try {
        const ruleName = document.getElementById('ruleName').value;
        const ruleType = document.getElementById('ruleType').value;
        const blockDuration = parseInt(document.getElementById('ruleBlockDuration').value);
        const priority = parseInt(document.getElementById('rulePriority').value);
        const description = document.getElementById('ruleDescription').value;

        if (!ruleName || !ruleType) {
            showNotification('Please fill in required fields', 'error');
            return;
        }

        let conditions = {};

        if (ruleType === 'brute_force') {
            conditions = {
                failed_attempts: parseInt(document.getElementById('failedAttempts').value),
                time_window_minutes: parseInt(document.getElementById('timeWindow').value),
                event_type: 'failed'
            };
        } else if (ruleType === 'api_reputation' || ruleType === 'threat_threshold') {
            conditions = {
                min_threat_level: document.getElementById('minThreatLevel').value,
                min_confidence: parseFloat(document.getElementById('minConfidence').value),
                sources: ['abuseipdb', 'virustotal', 'shodan']
            };
        }

        const response = await fetch('/api/dashboard/blocking/rules/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rule_name: ruleName,
                rule_type: ruleType,
                conditions: conditions,
                block_duration_minutes: blockDuration,
                priority: priority,
                description: description
            })
        });

        const data = await response.json();

        if (data.success) {
            showNotification('Rule created successfully', 'success');
            setTimeout(() => {
                resetEditForm();
                loadRules();
            }, 1500);
        } else {
            showNotification(`Failed to create rule: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error creating rule:', error);
        showNotification('Error creating rule', 'error');
    }
}
