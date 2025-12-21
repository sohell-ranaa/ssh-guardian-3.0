/**
 * Email Routing Page Module
 * Manages email notification routing rules
 * Routes notifications from specific agents and rule types to designated email addresses
 */

(function() {
    'use strict';

    let rules = [];
    let agents = [];
    let ruleTypes = [];
    let currentRuleId = null;

    /**
     * Load and display Email Routing page
     */
    window.loadEmailRoutingPage = async function() {
        try {
            await loadRoutingData();
            renderRules();
            setupEventListeners();
        } catch (error) {
            console.error('Error loading Email Routing page:', error);
            showToast('Failed to load email routing', 'error');
        }
    };

    /**
     * Load routing data from API
     */
    async function loadRoutingData() {
        const container = document.getElementById('email-routing-container');
        if (container) {
            container.innerHTML = '<div class="loading-placeholder"><div class="loading-spinner"></div><span>Loading routing rules...</span></div>';
        }

        try {
            const response = await fetch('/api/dashboard/email-routing/list');
            const data = await response.json();

            if (data.success) {
                rules = data.data.rules || [];
                agents = data.data.agents || [];
                ruleTypes = data.data.rule_types || [];
                updateStats();
            } else {
                throw new Error(data.error || 'Failed to load data');
            }
        } catch (error) {
            console.error('Error loading routing data:', error);
            if (container) {
                container.innerHTML = '<div class="loading-placeholder"><span style="color: var(--danger);">Failed to load routing rules</span></div>';
            }
        }
    }

    /**
     * Update statistics
     */
    function updateStats() {
        const totalRules = rules.length;
        const activeRules = rules.filter(r => r.is_enabled).length;
        const totalEmails = new Set(rules.flatMap(r => r.email_addresses || [])).size;
        const agentsCovered = new Set(rules.flatMap(r => r.agents || []));
        const allAgents = agentsCovered.has('all');

        document.getElementById('stat-routing-rules').textContent = totalRules;
        document.getElementById('stat-active-routing').textContent = activeRules;
        document.getElementById('stat-unique-emails').textContent = totalEmails;
        document.getElementById('stat-agents-covered').textContent = allAgents ? 'All' : agentsCovered.size;
    }

    /**
     * Render routing rules list
     */
    function renderRules() {
        const container = document.getElementById('email-routing-container');
        if (!container) return;

        if (!rules || rules.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px 20px; color: var(--text-secondary);">
                    <div style="font-size: 48px; margin-bottom: 16px;">📧</div>
                    <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 8px; color: var(--text-primary);">No Email Routing Rules</h3>
                    <p style="font-size: 14px; margin-bottom: 24px;">Create routing rules to send notifications to specific email addresses based on agents and rule types</p>
                    <button onclick="showCreateRoutingModal()" class="btn btn-primary">
                        + Create Routing Rule
                    </button>
                </div>
            `;
            return;
        }

        let html = '<div style="display: grid; gap: 14px;">';

        rules.forEach(rule => {
            const agentLabels = getAgentLabels(rule.agents || []);
            const typeLabels = getRuleTypeLabels(rule.rule_types || []);
            const statusColor = rule.is_enabled ? TC.success : TC.muted;
            const statusBg = rule.is_enabled ? TC.successBg : 'var(--surface-alt)';
            const statusText = rule.is_enabled ? 'Active' : 'Disabled';

            html += `
                <div class="card routing-rule-card ${rule.is_enabled ? '' : 'disabled'}">
                    <div class="routing-rule-header">
                        <div class="routing-rule-info">
                            <div class="routing-rule-title-row">
                                <h3 class="routing-rule-name">${escapeHtml(rule.name)}</h3>
                                <span class="routing-rule-status ${rule.is_enabled ? 'active' : 'inactive'}">
                                    <span class="status-dot"></span>
                                    ${statusText}
                                </span>
                            </div>
                            ${rule.description ? `<p class="routing-rule-desc">${escapeHtml(rule.description)}</p>` : ''}
                        </div>
                        <div class="routing-rule-actions">
                            <label class="routing-toggle" title="${rule.is_enabled ? 'Click to disable' : 'Click to enable'}">
                                <input type="checkbox" ${rule.is_enabled ? 'checked' : ''} onchange="toggleRoutingRule('${rule.id}')">
                                <span class="routing-toggle-slider"></span>
                            </label>
                            <button onclick="showEditRoutingModal('${rule.id}')" title="Edit" class="btn-icon-action">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                                    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                                </svg>
                            </button>
                            <button onclick="deleteRoutingRule('${rule.id}')" title="Delete" class="btn-icon-action btn-icon-danger">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div class="routing-rule-details">
                        <div class="routing-detail-col">
                            <div class="routing-detail-label">Agents</div>
                            <div class="routing-detail-tags">
                                ${agentLabels.map(a => `<span class="tag tag-blue">${escapeHtml(a)}</span>`).join('')}
                            </div>
                        </div>
                        <div class="routing-detail-col">
                            <div class="routing-detail-label">Rule Types</div>
                            <div class="routing-detail-tags">
                                ${typeLabels.slice(0, 3).map(t => `<span class="tag tag-orange">${escapeHtml(t)}</span>`).join('')}
                                ${typeLabels.length > 3 ? `<span class="tag tag-muted">+${typeLabels.length - 3} more</span>` : ''}
                            </div>
                        </div>
                        <div class="routing-detail-col">
                            <div class="routing-detail-label">Email Recipients</div>
                            <div class="routing-detail-tags">
                                ${(rule.email_addresses || []).slice(0, 2).map(e => `<span class="tag tag-green">${escapeHtml(e)}</span>`).join('')}
                                ${(rule.email_addresses || []).length > 2 ? `<span class="tag tag-muted">+${rule.email_addresses.length - 2} more</span>` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            `;
        });

        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * Get agent display labels
     */
    function getAgentLabels(agentIds) {
        if (!agentIds || agentIds.length === 0 || agentIds.includes('all')) {
            return ['All Agents'];
        }
        return agentIds.map(id => {
            const agent = agents.find(a => a.agent_id === id || a.id === id);
            return agent ? (agent.hostname || agent.agent_id) : id;
        });
    }

    /**
     * Get rule type display labels
     */
    function getRuleTypeLabels(types) {
        if (!types || types.length === 0 || types.includes('all')) {
            return ['All Types'];
        }
        return types.map(t => {
            const type = ruleTypes.find(rt => rt.value === t);
            return type ? type.label : t;
        });
    }

    /**
     * Show create routing modal
     */
    window.showCreateRoutingModal = function() {
        currentRuleId = null;
        showRoutingModal(null);
    };

    /**
     * Show edit routing modal
     */
    window.showEditRoutingModal = function(ruleId) {
        const rule = rules.find(r => r.id === ruleId);
        if (rule) {
            currentRuleId = ruleId;
            showRoutingModal(rule);
        }
    };

    /**
     * Show routing modal (create/edit)
     */
    function showRoutingModal(rule) {
        const existingModal = document.getElementById('email-routing-modal');
        if (existingModal) existingModal.remove();

        const isEdit = !!rule;
        const title = isEdit ? 'Edit Routing Rule' : 'Create Routing Rule';

        // Build agents checkboxes
        const selectedAgents = rule?.agents || ['all'];
        let agentsHtml = `
            <label class="routing-checkbox-item routing-checkbox-all">
                <input type="checkbox" name="agents" value="all" ${selectedAgents.includes('all') ? 'checked' : ''} onchange="toggleAllAgents(this)">
                <span>All Agents</span>
            </label>
            <div id="agents-list" class="routing-checkbox-list" style="display: ${selectedAgents.includes('all') ? 'none' : 'block'};">
        `;
        if (agents.length === 0) {
            agentsHtml += '<div class="routing-empty-msg">No agents found</div>';
        } else {
            agents.forEach(agent => {
                const agentId = agent.agent_id || agent.id;
                const checked = selectedAgents.includes(agentId) ? 'checked' : '';
                const status = agent.is_active ? 'online' : 'offline';
                agentsHtml += `
                    <label class="routing-checkbox-item">
                        <input type="checkbox" name="agents" value="${agentId}" ${checked}>
                        <span class="routing-agent-status ${status}"></span>
                        <span>${escapeHtml(agent.hostname || agentId)}</span>
                    </label>
                `;
            });
        }
        agentsHtml += '</div>';

        // Build rule types checkboxes
        const selectedTypes = rule?.rule_types || ['all'];
        let typesHtml = `
            <label class="routing-checkbox-item routing-checkbox-all">
                <input type="checkbox" name="rule_types" value="all" ${selectedTypes.includes('all') ? 'checked' : ''} onchange="toggleAllTypes(this)">
                <span>All Rule Types</span>
            </label>
            <div id="types-list" class="routing-checkbox-list" style="display: ${selectedTypes.includes('all') ? 'none' : 'block'};">
        `;
        ruleTypes.forEach(type => {
            const checked = selectedTypes.includes(type.value) ? 'checked' : '';
            typesHtml += `
                <label class="routing-checkbox-item">
                    <input type="checkbox" name="rule_types" value="${type.value}" ${checked}>
                    <span class="routing-type-icon">${type.icon}</span>
                    <span>${escapeHtml(type.label)}</span>
                </label>
            `;
        });
        typesHtml += '</div>';

        // Build email tags
        const existingEmails = rule?.email_addresses || [];

        const modal = document.createElement('div');
        modal.id = 'email-routing-modal';
        modal.className = 'modal-overlay active';
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        modal.innerHTML = `
            <div class="modal routing-modal">
                <div class="modal-header">
                    <h3 class="modal-title">${title}</h3>
                    <button type="button" class="modal-close" onclick="this.closest('#email-routing-modal').remove()">&times;</button>
                </div>
                <form id="email-routing-form" onsubmit="saveRoutingRule(event)">
                    <div class="modal-body">
                        <!-- Rule Name -->
                        <div class="form-group">
                            <label class="form-label">Rule Name <span class="required">*</span></label>
                            <input type="text" id="routing-name" value="${escapeHtml(rule?.name || '')}" class="form-control" required placeholder="e.g., Security Team Alerts">
                        </div>

                        <!-- Description -->
                        <div class="form-group">
                            <label class="form-label">Description</label>
                            <input type="text" id="routing-description" value="${escapeHtml(rule?.description || '')}" class="form-control" placeholder="Brief description of this routing rule">
                        </div>

                        <!-- Agents & Rule Types -->
                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Agents</label>
                                <div class="routing-select-box">
                                    ${agentsHtml}
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Rule Types</label>
                                <div class="routing-select-box">
                                    ${typesHtml}
                                </div>
                            </div>
                        </div>

                        <!-- Email Recipients -->
                        <div class="form-group">
                            <label class="form-label">Email Recipients <span class="required">*</span></label>
                            <div class="email-input-container">
                                <div id="email-tags-container" class="email-tags">
                                    ${existingEmails.map(email => `
                                        <span class="email-tag" data-email="${escapeHtml(email)}">
                                            ${escapeHtml(email)}
                                            <button type="button" class="email-tag-remove" onclick="removeEmailTag(this)">&times;</button>
                                        </span>
                                    `).join('')}
                                </div>
                                <div class="email-input-row">
                                    <input type="email" id="email-input" class="form-control" placeholder="Enter email address">
                                    <button type="button" class="btn btn-secondary" onclick="addEmailFromInput()">Add</button>
                                </div>
                                <div id="email-error" class="form-error" style="display: none;"></div>
                            </div>
                        </div>

                        <!-- Priority & Enabled -->
                        <div class="form-row">
                            <div class="form-group">
                                <label class="form-label">Priority</label>
                                <input type="number" id="routing-priority" value="${rule?.priority || 50}" min="1" max="100" class="form-control">
                                <div class="form-hint">Lower = higher priority (1-100)</div>
                            </div>
                            <div class="form-group">
                                <label class="form-label">Status</label>
                                <div class="toggle-field">
                                    <label class="toggle-switch-inline">
                                        <input type="checkbox" id="routing-enabled" ${rule?.is_enabled !== false ? 'checked' : ''}>
                                        <span class="toggle-track"></span>
                                        <span class="toggle-status">${rule?.is_enabled !== false ? 'Enabled' : 'Disabled'}</span>
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" onclick="this.closest('#email-routing-modal').remove()">Cancel</button>
                        <button type="submit" class="btn btn-primary" id="routing-submit-btn">${isEdit ? 'Save Changes' : 'Create Rule'}</button>
                    </div>
                </form>
            </div>
        `;

        document.body.appendChild(modal);

        // Add enter key handler for email input
        const emailInput = document.getElementById('email-input');
        if (emailInput) {
            emailInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    addEmailFromInput();
                }
            });
        }

        // Update toggle status text on change
        const enabledCheckbox = document.getElementById('routing-enabled');
        if (enabledCheckbox) {
            enabledCheckbox.addEventListener('change', (e) => {
                const statusEl = e.target.closest('.toggle-switch-inline').querySelector('.toggle-status');
                if (statusEl) {
                    statusEl.textContent = e.target.checked ? 'Enabled' : 'Disabled';
                }
            });
        }
    }

    /**
     * Add email from input field
     */
    window.addEmailFromInput = function() {
        const input = document.getElementById('email-input');
        const errorEl = document.getElementById('email-error');
        const container = document.getElementById('email-tags-container');

        if (!input || !container) return;

        const email = input.value.trim().toLowerCase();
        errorEl.style.display = 'none';

        if (!email) return;

        // Validate email
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!emailPattern.test(email)) {
            errorEl.textContent = 'Please enter a valid email address';
            errorEl.style.display = 'block';
            input.focus();
            return;
        }

        // Check for duplicates
        const existingTags = container.querySelectorAll('.email-tag');
        for (const tag of existingTags) {
            if (tag.dataset.email === email) {
                errorEl.textContent = 'This email is already added';
                errorEl.style.display = 'block';
                input.focus();
                return;
            }
        }

        // Add tag
        const tag = document.createElement('span');
        tag.className = 'email-tag';
        tag.dataset.email = email;
        tag.innerHTML = `
            ${escapeHtml(email)}
            <button type="button" class="email-tag-remove" onclick="removeEmailTag(this)">&times;</button>
        `;
        container.appendChild(tag);

        // Clear input
        input.value = '';
        input.focus();
    };

    /**
     * Remove email tag
     */
    window.removeEmailTag = function(btn) {
        const tag = btn.closest('.email-tag');
        if (tag) tag.remove();
    };

    /**
     * Toggle all agents checkbox
     */
    window.toggleAllAgents = function(checkbox) {
        const list = document.getElementById('agents-list');
        if (list) {
            list.style.display = checkbox.checked ? 'none' : 'grid';
            // Uncheck individual agents when "all" is selected
            if (checkbox.checked) {
                list.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            }
        }
    };

    /**
     * Toggle all rule types checkbox
     */
    window.toggleAllTypes = function(checkbox) {
        const list = document.getElementById('types-list');
        if (list) {
            list.style.display = checkbox.checked ? 'none' : 'grid';
            if (checkbox.checked) {
                list.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            }
        }
    };

    /**
     * Save routing rule
     */
    window.saveRoutingRule = async function(event) {
        event.preventDefault();

        const name = document.getElementById('routing-name').value.trim();
        const description = document.getElementById('routing-description').value.trim();
        const priority = parseInt(document.getElementById('routing-priority').value) || 50;
        const isEnabled = document.getElementById('routing-enabled').checked;
        const errorEl = document.getElementById('email-error');

        // Get selected agents
        const agentCheckboxes = document.querySelectorAll('input[name="agents"]:checked');
        let selectedAgents = Array.from(agentCheckboxes).map(cb => cb.value);
        if (selectedAgents.includes('all')) {
            selectedAgents = ['all'];
        } else if (selectedAgents.length === 0) {
            selectedAgents = ['all'];
        }

        // Get selected rule types
        const typeCheckboxes = document.querySelectorAll('input[name="rule_types"]:checked');
        let selectedTypes = Array.from(typeCheckboxes).map(cb => cb.value);
        if (selectedTypes.includes('all')) {
            selectedTypes = ['all'];
        } else if (selectedTypes.length === 0) {
            selectedTypes = ['all'];
        }

        // Get email addresses from tags
        const emailTags = document.querySelectorAll('#email-tags-container .email-tag');
        const emailAddresses = Array.from(emailTags).map(tag => tag.dataset.email);

        if (emailAddresses.length === 0) {
            if (errorEl) {
                errorEl.textContent = 'Add at least one email address';
                errorEl.style.display = 'block';
            }
            showToast('At least one email address is required', 'error');
            return;
        }

        // Disable submit button
        const submitBtn = document.getElementById('routing-submit-btn');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'Saving...';
        }

        const payload = {
            name: name,
            description: description,
            agents: selectedAgents,
            rule_types: selectedTypes,
            email_addresses: emailAddresses,
            priority: priority,
            is_enabled: isEnabled
        };

        try {
            const url = currentRuleId
                ? `/api/dashboard/email-routing/update/${currentRuleId}`
                : '/api/dashboard/email-routing/create';
            const method = currentRuleId ? 'PUT' : 'POST';

            const response = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (data.success) {
                document.getElementById('email-routing-modal').remove();
                showToast(currentRuleId ? 'Routing rule updated' : 'Routing rule created', 'success');
                loadRoutingData().then(renderRules);
            } else {
                showToast(data.error || 'Failed to save rule', 'error');
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.textContent = currentRuleId ? 'Save Changes' : 'Create Rule';
                }
            }
        } catch (error) {
            console.error('Error saving rule:', error);
            showToast('Failed to save rule', 'error');
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = currentRuleId ? 'Save Changes' : 'Create Rule';
            }
        }
    };

    /**
     * Toggle routing rule
     */
    window.toggleRoutingRule = async function(ruleId) {
        try {
            const response = await fetch(`/api/dashboard/email-routing/toggle/${ruleId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            const data = await response.json();

            if (data.success) {
                showToast(data.message, 'success');
                loadRoutingData().then(renderRules);
            } else {
                showToast(data.error || 'Failed to toggle rule', 'error');
            }
        } catch (error) {
            console.error('Error toggling rule:', error);
            showToast('Failed to toggle rule', 'error');
        }
    };

    /**
     * Delete routing rule
     */
    window.deleteRoutingRule = async function(ruleId) {
        if (!confirm('Are you sure you want to delete this routing rule?')) return;

        try {
            const response = await fetch(`/api/dashboard/email-routing/delete/${ruleId}`, {
                method: 'DELETE'
            });
            const data = await response.json();

            if (data.success) {
                showToast('Routing rule deleted', 'success');
                loadRoutingData().then(renderRules);
            } else {
                showToast(data.error || 'Failed to delete rule', 'error');
            }
        } catch (error) {
            console.error('Error deleting rule:', error);
            showToast('Failed to delete rule', 'error');
        }
    };

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        const createBtn = document.getElementById('email-routing-create-btn');
        if (createBtn) {
            createBtn.onclick = showCreateRoutingModal;
        }

        const refreshBtn = document.getElementById('email-routing-refresh-btn');
        if (refreshBtn) {
            refreshBtn.onclick = () => loadRoutingData().then(renderRules);
        }
    }

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

    /**
     * Escape HTML - use shared utility from utils.js
     */
    const escapeHtml = window.escapeHtml;

})();
