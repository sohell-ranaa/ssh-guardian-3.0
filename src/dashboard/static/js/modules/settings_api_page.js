/**
 * Settings API Keys Page Module
 * Handles API key management for agent authentication
 */

(function() {
    'use strict';

    let apiKeys = [];

    /**
     * Load and display Settings API Keys page
     */
    window.loadSettingsApiPage = async function() {
        console.log('Loading Settings API Keys page...');

        try {
            // Load API keys data
            await loadApiKeys();

            // Setup event listeners
            setupApiKeysEventListeners();

        } catch (error) {
            console.error('Error loading Settings API Keys page:', error);
            showNotification('Failed to load API keys', 'error');
        }
    };

    /**
     * Load API keys from agents table
     */
    async function loadApiKeys() {
        const container = document.getElementById('api-keys-container');
        if (container) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #605E5C;">Loading API keys...</div>';
        }

        try {
            const response = await fetch('/api/agents/list');
            const data = await response.json();

            if (data.success) {
                apiKeys = data.agents || [];
                renderApiKeys(apiKeys);
            } else {
                throw new Error(data.error || 'Failed to load API keys');
            }

        } catch (error) {
            console.error('Error loading API keys:', error);
            showNotification('Failed to load API keys', 'error');
            if (container) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #D13438;">Failed to load API keys. Please try again.</div>';
            }
        }
    }

    /**
     * Render API keys list
     */
    function renderApiKeys(agents) {
        const container = document.getElementById('api-keys-container');

        if (!container) return;

        if (!agents || agents.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px 20px; color: #605E5C;">
                    <div style="font-size: 48px; margin-bottom: 16px;">🔑</div>
                    <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 8px; color: #323130;">No API Keys</h3>
                    <p style="font-size: 14px; margin-bottom: 24px;">Create an API key to allow agents to submit events</p>
                    <button onclick="showCreateApiKeyModal()" class="btn btn-primary" style="padding: 10px 20px;">
                        + Create API Key
                    </button>
                </div>
            `;
            return;
        }

        let html = `
            <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; overflow: hidden;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #F3F2F1;">
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Agent Name</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Hostname</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">API Key</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Status</th>
                            <th style="text-align: left; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Last Seen</th>
                            <th style="text-align: center; padding: 14px 16px; font-size: 13px; font-weight: 600; color: #605E5C; border-bottom: 1px solid #EDEBE9;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        agents.forEach((agent, index) => {
            const isLast = index === agents.length - 1;
            const borderStyle = isLast ? '' : 'border-bottom: 1px solid #EDEBE9;';
            const statusColor = agent.status === 'online' ? '#107C10' : (agent.status === 'offline' ? '#D13438' : '#605E5C');
            const maskedKey = agent.api_key ? maskApiKey(agent.api_key) : 'N/A';

            html += `
                <tr style="${borderStyle}">
                    <td style="padding: 14px 16px; font-size: 14px; color: #323130;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 20px;">🖥️</span>
                            <div>
                                <div style="font-weight: 500;">${agent.display_name || agent.hostname || 'Unknown'}</div>
                                <div style="font-size: 12px; color: #605E5C;">${agent.environment || 'production'}</div>
                            </div>
                        </div>
                    </td>
                    <td style="padding: 14px 16px; font-size: 14px; color: #605E5C;">
                        ${agent.hostname || 'N/A'}
                    </td>
                    <td style="padding: 14px 16px; font-size: 13px; font-family: 'Consolas', 'Monaco', monospace; color: #605E5C;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="api-key-display" data-agent-id="${agent.id}" data-masked="${maskedKey}" data-full="${agent.api_key || ''}">${maskedKey}</span>
                            ${agent.api_key ? `
                                <button class="btn-toggle-key" data-agent-id="${agent.id}"
                                        style="padding: 4px 8px; font-size: 11px; background: transparent; border: 1px solid #EDEBE9; border-radius: 4px; cursor: pointer; color: #605E5C;">
                                    Show
                                </button>
                                <button class="btn-copy-key" data-key="${agent.api_key}"
                                        style="padding: 4px 8px; font-size: 11px; background: transparent; border: 1px solid #EDEBE9; border-radius: 4px; cursor: pointer; color: #605E5C;">
                                    📋
                                </button>
                            ` : '<span style="color: #A19F9D;">Not set</span>'}
                        </div>
                    </td>
                    <td style="padding: 14px 16px;">
                        <span style="display: inline-flex; align-items: center; gap: 6px;">
                            <span style="width: 8px; height: 8px; border-radius: 50%; background: ${statusColor};"></span>
                            <span style="font-size: 14px; color: #605E5C; text-transform: capitalize;">${agent.status || 'unknown'}</span>
                        </span>
                    </td>
                    <td style="padding: 14px 16px; font-size: 14px; color: #605E5C;">
                        ${formatTimestamp(agent.last_heartbeat)}
                    </td>
                    <td style="padding: 14px 16px; text-align: center;">
                        <div style="display: flex; gap: 8px; justify-content: center;">
                            <button class="btn-regenerate-key btn btn-sm" data-agent-id="${agent.id}"
                                    style="padding: 6px 12px; font-size: 12px; background: #0078D4; color: white; border: none; border-radius: 4px; cursor: pointer;">
                                🔄 Regenerate
                            </button>
                            <button class="btn-revoke-key btn btn-sm" data-agent-id="${agent.id}"
                                    style="padding: 6px 12px; font-size: 12px; background: #D13438; color: white; border: none; border-radius: 4px; cursor: pointer;">
                                🚫 Revoke
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;

        // Add modals
        html += renderCreateApiKeyModal();

        container.innerHTML = html;

        // Setup inline event listeners
        setupInlineEventListeners();
    }

    /**
     * Render Create API Key Modal
     */
    function renderCreateApiKeyModal() {
        return `
            <div id="create-api-key-modal" class="modal-overlay" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                <div class="modal-content" style="background: #FFFFFF; border-radius: 8px; width: 100%; max-width: 500px; max-height: 90vh; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
                    <div class="modal-header" style="padding: 20px 24px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Create New API Key</h3>
                        <button id="create-modal-close-btn" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #605E5C; padding: 0; line-height: 1;">&times;</button>
                    </div>
                    <div class="modal-body" style="padding: 24px;">
                        <div style="display: flex; flex-direction: column; gap: 20px;">
                            <div class="form-group">
                                <label for="agent-display-name" style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Agent Display Name <span style="color: #D13438;">*</span>
                                </label>
                                <input type="text" id="agent-display-name" placeholder="e.g., Production Server 01"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label for="agent-hostname" style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Hostname <span style="color: #D13438;">*</span>
                                </label>
                                <input type="text" id="agent-hostname" placeholder="e.g., server-01.example.com"
                                       style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div class="form-group">
                                <label for="agent-environment" style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Environment
                                </label>
                                <select id="agent-environment" style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                                    <option value="production">Production</option>
                                    <option value="staging">Staging</option>
                                    <option value="development">Development</option>
                                    <option value="testing">Testing</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="agent-type" style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                                    Agent Type
                                </label>
                                <select id="agent-type" style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                                    <option value="primary">Primary</option>
                                    <option value="secondary" selected>Secondary</option>
                                    <option value="monitor_only">Monitor Only</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer" style="padding: 16px 24px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end; gap: 12px;">
                        <button id="create-modal-cancel-btn" class="btn btn-secondary" style="padding: 10px 20px;">Cancel</button>
                        <button id="create-modal-save-btn" class="btn btn-primary" style="padding: 10px 20px;">Create Agent</button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Mask API key for display
     */
    function maskApiKey(key) {
        if (!key || key.length < 8) return key;
        return key.substring(0, 8) + '...' + key.substring(key.length - 4);
    }

    /**
     * Format timestamp for display
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'Never';
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return 'Never';

        // Use TimeSettings relative time if available
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.relative(timestamp);
        }

        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    }

    /**
     * Setup inline event listeners after rendering
     */
    function setupInlineEventListeners() {
        // Toggle key visibility
        document.querySelectorAll('.btn-toggle-key').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const agentId = e.target.getAttribute('data-agent-id');
                const display = document.querySelector(`.api-key-display[data-agent-id="${agentId}"]`);
                if (display) {
                    const isShowing = btn.textContent === 'Hide';
                    if (isShowing) {
                        display.textContent = display.getAttribute('data-masked');
                        btn.textContent = 'Show';
                    } else {
                        display.textContent = display.getAttribute('data-full');
                        btn.textContent = 'Hide';
                    }
                }
            });
        });

        // Copy key to clipboard
        document.querySelectorAll('.btn-copy-key').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const key = e.target.getAttribute('data-key');
                if (key) {
                    navigator.clipboard.writeText(key).then(() => {
                        showNotification('API key copied to clipboard', 'success');
                    }).catch(() => {
                        showNotification('Failed to copy API key', 'error');
                    });
                }
            });
        });

        // Regenerate key
        document.querySelectorAll('.btn-regenerate-key').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const agentId = e.target.getAttribute('data-agent-id');
                if (confirm('Are you sure you want to regenerate this API key? The old key will stop working immediately.')) {
                    await regenerateApiKey(agentId);
                }
            });
        });

        // Revoke key
        document.querySelectorAll('.btn-revoke-key').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const agentId = e.target.getAttribute('data-agent-id');
                if (confirm('Are you sure you want to revoke this API key? The agent will no longer be able to submit events.')) {
                    await revokeApiKey(agentId);
                }
            });
        });

        // Setup modal listeners
        setupCreateModalListeners();
    }

    /**
     * Setup Create Modal Event Listeners
     */
    function setupCreateModalListeners() {
        const modal = document.getElementById('create-api-key-modal');
        const closeBtn = document.getElementById('create-modal-close-btn');
        const cancelBtn = document.getElementById('create-modal-cancel-btn');
        const saveBtn = document.getElementById('create-modal-save-btn');

        if (!modal) return;

        const closeModal = () => {
            modal.style.display = 'none';
            // Clear form
            document.getElementById('agent-display-name').value = '';
            document.getElementById('agent-hostname').value = '';
            document.getElementById('agent-environment').value = 'production';
            document.getElementById('agent-type').value = 'secondary';
        };

        if (closeBtn) closeBtn.onclick = closeModal;
        if (cancelBtn) cancelBtn.onclick = closeModal;
        modal.onclick = (e) => {
            if (e.target === modal) closeModal();
        };

        if (saveBtn) {
            saveBtn.onclick = async () => {
                await createNewAgent();
            };
        }
    }

    /**
     * Create new agent with API key
     */
    async function createNewAgent() {
        const displayName = document.getElementById('agent-display-name').value.trim();
        const hostname = document.getElementById('agent-hostname').value.trim();
        const environment = document.getElementById('agent-environment').value;
        const agentType = document.getElementById('agent-type').value;

        if (!displayName || !hostname) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }

        const saveBtn = document.getElementById('create-modal-save-btn');
        saveBtn.textContent = 'Creating...';
        saveBtn.disabled = true;

        try {
            const response = await fetch('/api/dashboard/api-keys/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    display_name: displayName,
                    hostname: hostname,
                    environment: environment,
                    agent_type: agentType
                })
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Agent created successfully!', 'success');

                // Show the new API key in an alert (important for user to copy)
                if (data.api_key) {
                    showNewApiKeyAlert(data.api_key, displayName);
                }

                // Close modal and refresh list
                document.getElementById('create-api-key-modal').style.display = 'none';
                await loadApiKeys();
            } else {
                throw new Error(data.error || 'Failed to create agent');
            }

        } catch (error) {
            console.error('Error creating agent:', error);
            showNotification(error.message || 'Failed to create agent', 'error');
        } finally {
            saveBtn.textContent = 'Create Agent';
            saveBtn.disabled = false;
        }
    }

    /**
     * Show new API key alert
     */
    function showNewApiKeyAlert(apiKey, agentName) {
        const alertHtml = `
            <div id="new-api-key-alert" style="position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1001; display: flex; justify-content: center; align-items: center;">
                <div style="background: #FFFFFF; border-radius: 8px; padding: 24px; max-width: 500px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
                    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
                        <span style="font-size: 32px;">✅</span>
                        <h3 style="margin: 0; color: #107C10;">Agent Created Successfully!</h3>
                    </div>
                    <p style="color: #323130; margin-bottom: 16px;">Your new API key for <strong>${agentName}</strong>:</p>
                    <div style="background: #F3F2F1; padding: 16px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 14px; word-break: break-all; margin-bottom: 16px;">
                        ${apiKey}
                    </div>
                    <div style="background: #FFF4CE; border: 1px solid #FFB900; padding: 12px; border-radius: 4px; margin-bottom: 20px;">
                        <strong style="color: #B47B00;">⚠️ Important:</strong>
                        <span style="color: #323130;">Copy this API key now. You won't be able to see it again!</span>
                    </div>
                    <div style="display: flex; gap: 12px; justify-content: flex-end;">
                        <button onclick="navigator.clipboard.writeText('${apiKey}').then(() => showNotification('API key copied!', 'success'))"
                                class="btn btn-secondary" style="padding: 10px 20px;">
                            📋 Copy Key
                        </button>
                        <button onclick="document.getElementById('new-api-key-alert').remove()"
                                class="btn btn-primary" style="padding: 10px 20px;">
                            Done
                        </button>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', alertHtml);
    }

    /**
     * Regenerate API key for an agent
     */
    async function regenerateApiKey(agentId) {
        try {
            const response = await fetch(`/api/agents/${agentId}/regenerate-key`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                showNotification('API key regenerated successfully', 'success');

                // Show new key if returned
                if (data.api_key) {
                    const agent = apiKeys.find(a => a.id == agentId);
                    showNewApiKeyAlert(data.api_key, agent?.display_name || 'Agent');
                }

                await loadApiKeys();
            } else {
                throw new Error(data.error || 'Failed to regenerate API key');
            }

        } catch (error) {
            console.error('Error regenerating API key:', error);
            showNotification('Failed to regenerate API key', 'error');
        }
    }

    /**
     * Revoke API key for an agent
     */
    async function revokeApiKey(agentId) {
        try {
            const response = await fetch(`/api/agents/${agentId}/revoke-key`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                showNotification('API key revoked successfully', 'success');
                await loadApiKeys();
            } else {
                throw new Error(data.error || 'Failed to revoke API key');
            }

        } catch (error) {
            console.error('Error revoking API key:', error);
            showNotification('Failed to revoke API key', 'error');
        }
    }

    /**
     * Show create API key modal
     */
    window.showCreateApiKeyModal = function() {
        const modal = document.getElementById('create-api-key-modal');
        if (modal) {
            modal.style.display = 'flex';
        } else {
            // If modal doesn't exist yet (empty state), render it first
            loadApiKeys();
        }
    };

    /**
     * Setup event listeners
     */
    function setupApiKeysEventListeners() {
        // Create button
        const createBtn = document.getElementById('api-keys-create-btn');
        if (createBtn) {
            createBtn.addEventListener('click', () => {
                showCreateApiKeyModal();
            });
        }

        // Refresh button
        const refreshBtn = document.getElementById('api-keys-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                loadApiKeys();
                showNotification('API keys refreshed', 'success');
            });
        }
    }

})();
