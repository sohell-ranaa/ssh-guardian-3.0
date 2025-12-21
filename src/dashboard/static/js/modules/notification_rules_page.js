/**
 * Alert Rules Page Module
 * Manages alert/monitor rules (uses blocking_rules with action_type='alert')
 * Unified with blocking rules system
 */

(function() {
    'use strict';

    let rules = [];
    let eventTypes = [];
    let currentRuleId = null;

    // Channel definitions
    const CHANNELS = [
        { value: 'telegram', label: 'Telegram', icon: '📱' },
        { value: 'email', label: 'Email', icon: '📧' },
        { value: 'webhook', label: 'Webhook', icon: '🔗' }
    ];

    // Expose shared state for modal
    window.notificationRulesState = {
        get currentRuleId() { return currentRuleId; },
        set currentRuleId(val) { currentRuleId = val; },
        get eventTypes() { return eventTypes; },
        get rules() { return rules; }
    };

    /**
     * Load and display Alert Rules page
     */
    window.loadNotificationRulesPage = async function() {
        try {
            await loadEventTypes();
            await loadRules();
            setupEventListeners();
        } catch (error) {
            console.error('Error loading Alert Rules page:', error);
            showToast('Failed to load alert rules', 'error');
        }
    };

    /**
     * Load event types
     */
    async function loadEventTypes() {
        try {
            const response = await fetch('/api/dashboard/notification-rules/event-types');
            const data = await response.json();
            if (data.success) {
                eventTypes = data.event_types || [];
            }
        } catch (error) {
            console.error('Error loading event types:', error);
        }
    }

    /**
     * Load alert rules
     */
    async function loadRules() {
        const container = document.getElementById('notification-rules-container');
        if (container) {
            container.innerHTML = '<div class="loading-placeholder"><div class="loading-spinner"></div><span>Loading alert rules...</span></div>';
        }

        try {
            const response = await fetch('/api/dashboard/notification-rules/list');
            const data = await response.json();

            if (data.success !== false) {
                rules = data.rules || [];
                updateStats(rules);
                renderRules(rules);
            } else {
                throw new Error(data.error || 'Failed to load rules');
            }
        } catch (error) {
            console.error('Error loading rules:', error);
            if (container) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--danger);">Failed to load alert rules.</div>';
            }
        }
    }

    /**
     * Update statistics
     */
    function updateStats(rulesList) {
        const totalRules = rulesList.length;
        const activeRules = rulesList.filter(r => r.is_enabled).length;
        const totalTriggered = rulesList.reduce((sum, r) => sum + (r.times_triggered || 0), 0);

        // Count unique channels
        const channelsSet = new Set();
        rulesList.forEach(rule => {
            const channels = rule.channels || rule.notification_channels || [];
            channels.forEach(ch => channelsSet.add(ch));
        });

        document.getElementById('stat-total-rules').textContent = totalRules;
        document.getElementById('stat-active-rules').textContent = activeRules;
        document.getElementById('stat-total-triggered').textContent = totalTriggered.toLocaleString();
        document.getElementById('stat-channels-count').textContent = channelsSet.size;
    }

    /**
     * Render alert rules - compact design with inline styles
     */
    function renderRules(rulesList) {
        const container = document.getElementById('notification-rules-container');
        if (!container) return;

        if (!rulesList || rulesList.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 40px 20px; color: var(--text-secondary); background: var(--surface); border-radius: 8px; border: 1px solid var(--border);">
                    <div style="font-size: 36px; margin-bottom: 12px;">🔔</div>
                    <h3 style="font-size: 16px; font-weight: 600; margin-bottom: 6px; color: var(--text-primary);">No Alert Rules</h3>
                    <p style="font-size: 13px; margin-bottom: 16px;">Create alert rules to receive notifications about suspicious activity</p>
                    <button onclick="showCreateAlertRuleModal()" class="btn btn-sm btn-primary">+ Create Rule</button>
                </div>
            `;
            return;
        }

        let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';

        rulesList.forEach(rule => {
            const channels = rule.channels || rule.notification_channels || [];
            const typeInfo = getTypeInfo(rule.rule_type);
            const isActive = rule.is_enabled;
            const rowOpacity = isActive ? '1' : '0.6';

            html += `
                <div style="display: flex; justify-content: space-between; align-items: center; gap: 16px; padding: 12px 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 8px; opacity: ${rowOpacity};">
                    <div style="flex: 1; min-width: 0;">
                        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px; flex-wrap: wrap;">
                            <span style="display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; background: ${typeInfo.bgColor}; color: ${typeInfo.color};">${typeInfo.icon} ${typeInfo.label}</span>
                            <span style="font-size: 14px; font-weight: 600; color: var(--text-primary);">${escapeHtml(rule.rule_name)}</span>
                            <span style="font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 10px; background: ${isActive ? 'rgba(16, 185, 129, 0.1)' : 'var(--surface-alt)'}; color: ${isActive ? '#10b981' : 'var(--text-tertiary)'};">${isActive ? 'Active' : 'Off'}</span>
                            ${rule.is_system_rule ? `<span style="font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 10px; background: ${TC.primaryBg}; color: ${TC.primary};">System</span>` : ''}
                        </div>
                        <div style="display: flex; align-items: center; gap: 12px; font-size: 12px; color: var(--text-secondary); flex-wrap: wrap;">
                            <span style="font-size: 14px;">${channels.map(ch => getChannelIcon(ch)).join(' ') || '-'}</span>
                            <span>Priority: ${rule.priority || 50}</span>
                            <span>Triggered: ${(rule.times_triggered || 0).toLocaleString()}</span>
                            ${rule.last_triggered_at ? `<span>Last: ${formatDateTime(rule.last_triggered_at)}</span>` : ''}
                        </div>
                    </div>
                    <div style="display: flex; gap: 4px; flex-shrink: 0;">
                        <button onclick="testAlertRule(${rule.id})" class="btn btn-sm btn-secondary" style="padding: 4px 8px; font-size: 11px;">Test</button>
                        <button onclick="toggleAlertRule(${rule.id})" class="btn btn-sm ${isActive ? 'btn-warning' : 'btn-success'}" style="padding: 4px 8px; font-size: 11px;">${isActive ? 'Off' : 'On'}</button>
                        <button onclick="showEditAlertRuleModal(${rule.id})" class="btn btn-sm btn-secondary" style="padding: 4px 8px; font-size: 11px;">Edit</button>
                        ${!rule.is_system_rule ? `<button onclick="deleteAlertRule(${rule.id})" class="btn btn-sm btn-danger" style="padding: 4px 8px; font-size: 11px;">Del</button>` : ''}
                    </div>
                </div>
            `;
        });

        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * Get rule type display info
     */
    function getTypeInfo(ruleType) {
        const typeMap = {
            'brute_force': { icon: '🔨', label: 'Brute Force', color: TC.danger, bgColor: TC.dangerBg },
            'distributed_brute_force': { icon: '🤖', label: 'Distributed BF', color: TC.danger, bgColor: TC.dangerBg },
            'account_takeover': { icon: '🎭', label: 'Account Takeover', color: TC.purple, bgColor: TC.purpleBg },
            'credential_stuffing': { icon: '🔑', label: 'Credential Stuffing', color: TC.warningDark, bgColor: TC.warningBg },
            'velocity': { icon: '⚡', label: 'Velocity/DDoS', color: TC.orange, bgColor: TC.warningBg },
            'ml_threshold': { icon: '🧠', label: 'ML Risk', color: TC.purple, bgColor: TC.purpleBg },
            'behavioral_analysis': { icon: '📊', label: 'Behavioral', color: TC.teal, bgColor: TC.primaryBg },
            'api_reputation': { icon: '🌐', label: 'API Reputation', color: TC.success, bgColor: TC.successBg },
            'geo_restriction': { icon: '🌍', label: 'Geo Restriction', color: TC.primary, bgColor: TC.primaryBg },
            'off_hours_anomaly': { icon: '🌙', label: 'Off-Hours', color: TC.purple, bgColor: TC.purpleBg },
            'repeat_offender': { icon: '🔄', label: 'Repeat Offender', color: TC.primary, bgColor: TC.primaryBg },
            'custom': { icon: '⚙️', label: 'Custom', color: TC.textSecondary, bgColor: TC.surfaceAlt }
        };
        return typeMap[ruleType] || { icon: '📝', label: ruleType || 'Unknown', color: TC.textSecondary, bgColor: TC.surfaceAlt };
    }

    /**
     * Get channel icon
     */
    function getChannelIcon(channel) {
        const icons = { telegram: '📱', email: '📧', webhook: '🔗' };
        return icons[channel] || '📌';
    }

    // formatDateTime - use shared utility from utils.js
    const formatDateTime = window.formatLocalDateTime;

    /**
     * Toggle alert rule
     */
    window.toggleAlertRule = async function(ruleId) {
        try {
            const response = await fetch(`/api/dashboard/notification-rules/toggle/${ruleId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();

            if (data.success) {
                showToast('Rule toggled successfully', 'success');
                loadRules();
            } else {
                showToast(data.error || 'Failed to toggle rule', 'error');
            }
        } catch (error) {
            console.error('Error toggling rule:', error);
            showToast('Failed to toggle rule', 'error');
        }
    };

    /**
     * Test alert rule
     */
    window.testAlertRule = async function(ruleId) {
        try {
            showToast('Sending test notification...', 'info');
            const response = await fetch(`/api/dashboard/notification-rules/test/${ruleId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();

            if (data.success) {
                const results = data.results || [];
                const successCount = results.filter(r => r.success).length;
                showToast(`Test complete: ${successCount}/${results.length} channels succeeded`, successCount > 0 ? 'success' : 'warning');
            } else {
                showToast(data.error || 'Test failed', 'error');
            }
        } catch (error) {
            console.error('Error testing rule:', error);
            showToast('Failed to test rule', 'error');
        }
    };

    /**
     * Delete alert rule
     */
    window.deleteAlertRule = async function(ruleId) {
        if (!confirm('Are you sure you want to delete this alert rule?')) return;

        try {
            const response = await fetch(`/api/dashboard/notification-rules/delete/${ruleId}`, {
                method: 'DELETE'
            });
            const data = await response.json();

            if (data.success) {
                showToast('Rule deleted successfully', 'success');
                loadRules();
            } else {
                showToast(data.error || 'Failed to delete rule', 'error');
            }
        } catch (error) {
            console.error('Error deleting rule:', error);
            showToast('Failed to delete rule', 'error');
        }
    };

    /**
     * Show create alert rule modal
     */
    window.showCreateAlertRuleModal = function() {
        currentRuleId = null;
        showAlertRuleModal(null);
    };

    /**
     * Show edit alert rule modal
     */
    window.showEditAlertRuleModal = async function(ruleId) {
        try {
            const response = await fetch(`/api/dashboard/notification-rules/details/${ruleId}`);
            const data = await response.json();

            if (data.success) {
                currentRuleId = ruleId;
                showAlertRuleModal(data.rule);
            } else {
                showToast('Failed to load rule details', 'error');
            }
        } catch (error) {
            console.error('Error loading rule:', error);
            showToast('Failed to load rule', 'error');
        }
    };

    /**
     * Show alert rule modal (create/edit)
     */
    function showAlertRuleModal(rule) {
        const existingModal = document.getElementById('alert-rule-modal');
        if (existingModal) existingModal.remove();

        const isEdit = !!rule;
        const title = isEdit ? 'Edit Alert Rule' : 'Create Alert Rule';
        // Default telegram and email to checked for new rules
        const channels = rule?.channels || rule?.notification_channels || (isEdit ? [] : ['telegram', 'email']);

        // Build event type options
        let eventTypeOptions = '';
        eventTypes.forEach(et => {
            const selected = rule?.rule_type === et.value ? 'selected' : '';
            eventTypeOptions += `<option value="${et.value}" ${selected}>${et.icon} ${et.label}</option>`;
        });

        const modal = document.createElement('div');
        modal.id = 'alert-rule-modal';
        modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        modal.innerHTML = `
            <div style="background: var(--surface); border-radius: 8px; width: 550px; max-width: 90vw; max-height: 90vh; overflow-y: auto;">
                <div style="padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                    <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: var(--text-primary);">${title}</h2>
                    <button onclick="this.closest('#alert-rule-modal').remove()" style="background: none; border: none; cursor: pointer; font-size: 24px; color: var(--text-secondary);">&times;</button>
                </div>
                <div style="padding: 20px;">
                    <form id="alert-rule-form" onsubmit="saveAlertRule(event)">
                        <div style="margin-bottom: 16px;">
                            <label style="display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px;">Rule Name *</label>
                            <input type="text" id="rule-name" value="${escapeHtml(rule?.rule_name || '')}" class="form-control" required style="width: 100%;">
                        </div>

                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                            <div>
                                <label style="display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px;">Rule Type *</label>
                                <select id="rule-type" class="form-control" required style="width: 100%;">
                                    ${eventTypeOptions}
                                </select>
                            </div>
                            <div>
                                <label style="display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px;">Action Type</label>
                                <select id="action-type" class="form-control" style="width: 100%;">
                                    <option value="alert" ${rule?.action_type === 'alert' || !rule ? 'selected' : ''}>Alert (Notify)</option>
                                    <option value="monitor" ${rule?.action_type === 'monitor' ? 'selected' : ''}>Monitor (Log Only)</option>
                                </select>
                            </div>
                        </div>

                        <div style="margin-bottom: 16px;">
                            <label style="display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px;">Notification Channels *</label>
                            <div style="display: flex; gap: 16px;">
                                ${CHANNELS.map(ch => `
                                    <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                                        <input type="checkbox" name="channels" value="${ch.value}" ${channels.includes(ch.value) ? 'checked' : ''}>
                                        <span>${ch.icon} ${ch.label}</span>
                                    </label>
                                `).join('')}
                            </div>
                        </div>

                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
                            <div>
                                <label style="display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px;">Priority</label>
                                <input type="number" id="rule-priority" value="${rule?.priority || 50}" min="1" max="100" class="form-control" style="width: 100%;">
                            </div>
                            <div style="display: flex; align-items: center; padding-top: 24px;">
                                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                    <input type="checkbox" id="rule-enabled" ${rule?.is_enabled !== false ? 'checked' : ''}>
                                    <span>Enabled</span>
                                </label>
                            </div>
                        </div>

                        <div style="margin-bottom: 16px;">
                            <label style="display: block; font-size: 13px; font-weight: 500; margin-bottom: 6px;">Description</label>
                            <textarea id="rule-description" class="form-control" rows="2" style="width: 100%;">${escapeHtml(rule?.description || '')}</textarea>
                        </div>

                        <div style="display: flex; justify-content: flex-end; gap: 8px; padding-top: 16px; border-top: 1px solid var(--border);">
                            <button type="button" class="btn btn-secondary" onclick="this.closest('#alert-rule-modal').remove()">Cancel</button>
                            <button type="submit" class="btn btn-primary">${isEdit ? 'Save Changes' : 'Create Rule'}</button>
                        </div>
                    </form>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    /**
     * Save alert rule
     */
    window.saveAlertRule = async function(event) {
        event.preventDefault();

        const ruleName = document.getElementById('rule-name').value.trim();
        const ruleType = document.getElementById('rule-type').value;
        const actionType = document.getElementById('action-type').value;
        const priority = parseInt(document.getElementById('rule-priority').value) || 50;
        const isEnabled = document.getElementById('rule-enabled').checked;
        const description = document.getElementById('rule-description').value.trim();

        const channelCheckboxes = document.querySelectorAll('input[name="channels"]:checked');
        const channels = Array.from(channelCheckboxes).map(cb => cb.value);

        if (!ruleName) {
            showToast('Rule name is required', 'error');
            return;
        }

        if (actionType === 'alert' && channels.length === 0) {
            showToast('At least one notification channel is required for alerts', 'error');
            return;
        }

        const payload = {
            rule_name: ruleName,
            rule_type: ruleType,
            action_type: actionType,
            channels: channels,
            priority: priority,
            is_enabled: isEnabled,
            description: description
        };

        try {
            const url = currentRuleId
                ? `/api/dashboard/notification-rules/update/${currentRuleId}`
                : '/api/dashboard/notification-rules/create';
            const method = currentRuleId ? 'PUT' : 'POST';

            const response = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (data.success) {
                document.getElementById('alert-rule-modal').remove();
                showToast(currentRuleId ? 'Rule updated' : 'Rule created', 'success');
                loadRules();
            } else {
                showToast(data.error || 'Failed to save rule', 'error');
            }
        } catch (error) {
            console.error('Error saving rule:', error);
            showToast('Failed to save rule', 'error');
        }
    };

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        const createBtn = document.getElementById('notif-rules-create-btn');
        if (createBtn) {
            createBtn.onclick = showCreateAlertRuleModal;
        }

        const refreshBtn = document.getElementById('notif-rules-refresh-btn');
        if (refreshBtn) {
            refreshBtn.onclick = loadRules;
        }
    }

    // Export for external use
    window.loadRules = loadRules;

    /**
     * Show toast notification
     */
    function showToast(message, type) {
        if (typeof window.showNotification === 'function') {
            window.showNotification(message, type);
        } else {
            alert(message);
        }
    }

    // escapeHtml - use shared utility from utils.js
    const escapeHtml = window.escapeHtml;

})();
