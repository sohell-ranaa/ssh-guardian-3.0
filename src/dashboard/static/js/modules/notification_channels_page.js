/**
 * Notification Channels Page Module
 * Manages Telegram, Email, and Webhook notification channels
 * Updated to match v3.1 API structure
 */

(function() {
    'use strict';

    let channels = [];

    /**
     * Load and display Notification Channels page
     */
    window.loadNotificationChannelsPage = async function() {
        try {
            await loadChannels();
            setupEventListeners();
        } catch (error) {
            console.error('Error loading Notification Channels page:', error);
        }
    };

    /**
     * Load channels from API
     */
    /**
     * Update channel statistics
     */
    function updateChannelStats() {
        const total = channels.length;
        const active = channels.filter(c => c.is_enabled && c.status === 'active').length;
        const configured = channels.filter(c => c.status !== 'not_configured').length;
        const errors = channels.filter(c => c.status === 'error' || c.last_error).length;

        const totalEl = document.getElementById('stat-channels-total');
        const activeEl = document.getElementById('stat-channels-active');
        const configuredEl = document.getElementById('stat-channels-configured');
        const errorsEl = document.getElementById('stat-channels-errors');

        if (totalEl) totalEl.textContent = total;
        if (activeEl) activeEl.textContent = active;
        if (configuredEl) configuredEl.textContent = configured;
        if (errorsEl) {
            errorsEl.textContent = errors;
            errorsEl.style.color = errors > 0 ? 'var(--danger)' : 'var(--success)';
        }
    }

    async function loadChannels() {
        const container = document.getElementById('notif-channels-container');
        if (container) {
            container.innerHTML = '<div class="loading-placeholder" style="padding: 60px;"><div class="loading-spinner"></div><span>Loading channels...</span></div>';
        }

        try {
            const response = await fetch('/api/dashboard/notification-channels/list');
            const data = await response.json();

            if (data.success) {
                channels = data.data.channels || [];
                updateChannelStats();
                renderChannels();
            } else {
                throw new Error(data.error || 'Failed to load channels');
            }
        } catch (error) {
            console.error('Error loading channels:', error);
            if (container) {
                container.innerHTML = '<div class="loading-placeholder" style="padding: 60px;"><span style="color: var(--danger);">Failed to load channels</span></div>';
            }
        }
    }

    /**
     * Render channels cards
     */
    function renderChannels() {
        const container = document.getElementById('notif-channels-container');
        if (!container) return;

        if (!channels || channels.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px; color: var(--text-secondary);">
                    <div style="font-size: 48px; margin-bottom: 16px;">📡</div>
                    <div style="font-size: 16px; font-weight: 600; color: var(--text-primary);">No Notification Channels</div>
                    <div style="font-size: 14px; margin-top: 8px;">Configure notification channels to start receiving alerts</div>
                </div>
            `;
            return;
        }

        let html = '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 24px;">';

        channels.forEach(channel => {
            const channelType = channel.integration_type;
            const statusColor = getStatusColor(channel.status);
            const statusIcon = getStatusIcon(channel.status);
            const statusText = getStatusText(channel.status);

            html += `
                <div class="card" style="padding: 0; overflow: hidden;">
                    <div style="padding: 20px; border-bottom: 1px solid var(--border);">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div style="display: flex; align-items: center; gap: 12px;">
                                <div style="width: 48px; height: 48px; border-radius: 8px; background: ${getChannelBg(channelType)}; display: flex; align-items: center; justify-content: center; font-size: 24px;">
                                    ${channel.icon || getChannelIcon(channelType)}
                                </div>
                                <div>
                                    <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: var(--text-primary);">${escapeHtml(channel.name)}</h3>
                                    <p style="margin: 4px 0 0; font-size: 13px; color: var(--text-secondary);">${channel.description || ''}</p>
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 12px; background: ${statusColor}15; color: ${statusColor}; font-size: 11px; font-weight: 600;">
                                    ${statusIcon} ${statusText}
                                </span>
                                ${channel.id ? `
                                <label class="toggle-switch">
                                    <input type="checkbox" ${channel.is_enabled ? 'checked' : ''} onchange="toggleChannel('${channelType}', this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                                ` : ''}
                            </div>
                        </div>
                    </div>

                    <div style="padding: 20px;">
                        ${renderChannelConfig(channel)}

                        ${channel.last_error ? `
                            <div style="margin-top: 16px; padding: 12px; background: var(--danger)10; border-radius: 4px; border: 1px solid var(--danger)30;">
                                <div style="font-size: 11px; color: var(--danger); font-weight: 600; margin-bottom: 4px;">Last Error</div>
                                <div style="font-size: 12px; color: var(--text-secondary);">${escapeHtml(channel.last_error)}</div>
                            </div>
                        ` : ''}

                        ${channel.last_used_at ? `
                            <div style="margin-top: 12px; font-size: 11px; color: var(--text-secondary);">
                                Last used: ${formatDateTime(channel.last_used_at)}
                            </div>
                        ` : ''}
                    </div>

                    <div style="padding: 16px 20px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 8px;">
                        <button class="btn btn-secondary btn-sm" onclick="editChannel('${channelType}')">
                            Configure
                        </button>
                        ${channel.id ? `
                        <button class="btn btn-primary btn-sm" onclick="testChannel('${channelType}', this)">
                            Test
                        </button>
                        ` : ''}
                    </div>
                </div>
            `;
        });

        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * Render channel configuration summary
     */
    function renderChannelConfig(channel) {
        const config = channel.config || {};
        const channelType = channel.integration_type;
        let html = '<div style="display: grid; gap: 8px;">';

        if (channelType === 'telegram') {
            const botToken = config.bot_token || '';
            const chatId = config.chat_id || '';
            html += `
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: var(--text-secondary);">Bot Token</span>
                    <span style="color: var(--text-primary); font-family: monospace;">${botToken && botToken !== '' ? '********' : '<span style="color: var(--text-tertiary);">Not configured</span>'}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: var(--text-secondary);">Chat ID</span>
                    <span style="color: var(--text-primary); font-family: monospace;">${chatId || '<span style="color: var(--text-tertiary);">Not configured</span>'}</span>
                </div>
            `;
        } else if (channelType === 'smtp') {
            const host = config.host || '';
            const port = config.port || '';
            const fromEmail = config.from_email || '';
            html += `
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: var(--text-secondary);">SMTP Server</span>
                    <span style="color: var(--text-primary); font-family: monospace;">${host ? `${host}:${port}` : '<span style="color: var(--text-tertiary);">Not configured</span>'}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: var(--text-secondary);">From Email</span>
                    <span style="color: var(--text-primary);">${fromEmail || '<span style="color: var(--text-tertiary);">Not configured</span>'}</span>
                </div>
            `;
        } else if (channelType === 'webhook') {
            const url = config.url || '';
            html += `
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: var(--text-secondary);">Webhook URL</span>
                    <span style="color: var(--text-primary); font-family: monospace; max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${url || '<span style="color: var(--text-tertiary);">Not configured</span>'}</span>
                </div>
            `;
        }

        html += '</div>';
        return html;
    }

    /**
     * Get status color
     */
    function getStatusColor(status) {
        const colors = {
            active: TC.successDark,
            configured: TC.primary,
            inactive: TC.textSecondary,
            error: TC.danger,
            not_configured: TC.muted
        };
        return colors[status] || TC.textSecondary;
    }

    /**
     * Get status icon
     */
    function getStatusIcon(status) {
        const icons = {
            active: '●',
            configured: '○',
            inactive: '○',
            error: '⚠',
            not_configured: '○'
        };
        return icons[status] || '○';
    }

    /**
     * Get status display text
     */
    function getStatusText(status) {
        const texts = {
            active: 'Active',
            configured: 'Configured',
            inactive: 'Disabled',
            error: 'Error',
            not_configured: 'Not Configured'
        };
        return texts[status] || status;
    }

    /**
     * Get channel icon
     */
    function getChannelIcon(channelType) {
        const icons = {
            telegram: '📱',
            smtp: '📧',
            webhook: '🔗'
        };
        return icons[channelType] || '📡';
    }

    /**
     * Get channel background color
     */
    function getChannelBg(channelType) {
        const colors = {
            telegram: TC.primaryBg,
            smtp: TC.dangerBg,
            webhook: TC.purpleBg
        };
        return colors[channelType] || 'var(--surface-alt)';
    }

    // formatDateTime - use shared utility from utils.js
    const formatDateTime = window.formatLocalDateTime;

    /**
     * Toggle channel enabled state
     */
    window.toggleChannel = async function(channelType, enabled) {
        try {
            const endpoint = enabled ? 'enable' : 'disable';
            const response = await fetch(`/api/dashboard/notification-channels/${channelType}/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message || `Channel ${enabled ? 'enabled' : 'disabled'}`, 'success');
                loadChannels();
            } else {
                showNotification(data.error || 'Failed to update channel', 'error');
                loadChannels();
            }
        } catch (error) {
            console.error('Error toggling channel:', error);
            showNotification('Failed to update channel', 'error');
            loadChannels();
        }
    };

    /**
     * Edit channel configuration
     */
    window.editChannel = async function(channelType) {
        try {
            const response = await fetch(`/api/dashboard/notification-channels/${channelType}`);
            const data = await response.json();

            if (data.success) {
                showConfigModal(data.data);
            } else {
                showNotification(data.error || 'Failed to load channel', 'error');
            }
        } catch (error) {
            console.error('Error loading channel:', error);
            showNotification('Failed to load channel', 'error');
        }
    };

    /**
     * Show configuration modal
     */
    function showConfigModal(channel) {
        const existingModal = document.getElementById('channel-config-modal');
        if (existingModal) existingModal.remove();

        const config = channel.config || {};
        const configFields = channel.config_fields || [];
        let formHtml = '';

        // Build form fields from config_fields definitions
        configFields.forEach(field => {
            const key = field.key;
            const value = config[key] || '';
            const isPassword = field.type === 'password';
            const isBoolean = field.type === 'boolean';
            const required = field.required ? 'required' : '';

            if (isBoolean) {
                formHtml += `
                    <div style="margin-bottom: 16px;">
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" id="config-${key}" ${value === 'true' || value === true ? 'checked' : ''} style="width: 18px; height: 18px;">
                            <span style="font-size: 14px; color: var(--text-primary);">${field.label}</span>
                        </label>
                        ${field.description ? `<div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; margin-left: 26px;">${field.description}</div>` : ''}
                    </div>
                `;
            } else {
                const inputType = isPassword ? 'password' : (field.type === 'number' ? 'number' : 'text');
                formHtml += `
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; font-size: 13px; font-weight: 500; color: var(--text-primary); margin-bottom: 6px;">
                            ${field.label}
                            ${field.required ? '<span style="color: var(--danger);">*</span>' : ''}
                        </label>
                        <input type="${inputType}" id="config-${key}" value="${escapeHtml(String(value))}"
                               class="form-control" style="width: 100%;" ${required}
                               placeholder="${field.description || ''}">
                        ${field.description ? `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">${field.description}</div>` : ''}
                    </div>
                `;
            }
        });

        const modal = document.createElement('div');
        modal.id = 'channel-config-modal';
        modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        modal.innerHTML = `
            <div style="background: var(--surface); border-radius: 8px; width: 500px; max-width: 90vw; max-height: 90vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div style="padding: 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                    <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: var(--text-primary);">Configure ${channel.name}</h2>
                    <button onclick="this.closest('#channel-config-modal').remove()" style="background: none; border: none; cursor: pointer; font-size: 24px; color: var(--text-secondary); line-height: 1;">&times;</button>
                </div>
                <div style="padding: 20px;">
                    <form id="channel-config-form" onsubmit="saveChannelConfig(event, '${channel.integration_type}')">
                        ${formHtml}
                        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 24px; padding-top: 16px; border-top: 1px solid var(--border);">
                            <button type="button" class="btn btn-secondary" onclick="this.closest('#channel-config-modal').remove()">Cancel</button>
                            <button type="submit" class="btn btn-primary">Save Configuration</button>
                        </div>
                    </form>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    /**
     * Save channel configuration
     */
    window.saveChannelConfig = async function(event, channelType) {
        event.preventDefault();

        const form = document.getElementById('channel-config-form');
        const inputs = form.querySelectorAll('input');
        const configData = {};

        inputs.forEach(input => {
            const key = input.id.replace('config-', '');
            if (input.type === 'checkbox') {
                configData[key] = input.checked ? 'true' : 'false';
            } else {
                configData[key] = input.value;
            }
        });

        try {
            const response = await fetch(`/api/dashboard/notification-channels/${channelType}/configure`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(configData)
            });

            const data = await response.json();

            if (data.success) {
                document.getElementById('channel-config-modal').remove();
                showNotification('Configuration saved successfully', 'success');
                loadChannels();
            } else {
                showNotification(data.error || 'Failed to save configuration', 'error');
            }
        } catch (error) {
            console.error('Error saving configuration:', error);
            showNotification('Failed to save configuration', 'error');
        }
    };

    /**
     * Test channel
     */
    window.testChannel = async function(channelType, btn) {
        let testParams = {};

        // For SMTP, ask for test email
        if (channelType === 'smtp') {
            const email = prompt('Enter email address for test:', '');
            if (email === null) return;
            testParams.test_email = email;
        }

        try {
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Testing...';
            }

            const response = await fetch(`/api/dashboard/notification-channels/${channelType}/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(testParams)
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message || 'Test successful', 'success');
            } else {
                showNotification(data.error || 'Test failed', 'error');
            }

            loadChannels();
        } catch (error) {
            console.error('Error testing channel:', error);
            showNotification('Test failed: ' + error.message, 'error');
        }
    };

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        const refreshBtn = document.getElementById('notif-channels-refresh-btn');
        if (refreshBtn) {
            refreshBtn.onclick = loadChannels;
        }
    }

    // showNotification - use shared utility from toast.js
    const showNotification = window.showNotification || ((msg, type) => window.showToast?.(msg, type));

    // escapeHtml - use shared utility from utils.js
    const escapeHtml = window.escapeHtml;

})();
