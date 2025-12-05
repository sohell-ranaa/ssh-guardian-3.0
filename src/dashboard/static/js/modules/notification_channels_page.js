/**
 * Notification Channels Page Module
 * Manages Telegram, Email, and Webhook notification channels
 */

(function() {
    'use strict';

    let channels = [];

    /**
     * Load and display Notification Channels page
     */
    window.loadNotificationChannelsPage = async function() {
        console.log('Loading Notification Channels page...');

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
    async function loadChannels() {
        const container = document.getElementById('notif-channels-container');
        if (container) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #605E5C;">Loading channels...</div>';
        }

        try {
            const response = await fetch('/api/dashboard/notification-channels/list');
            const data = await response.json();

            if (data.success) {
                channels = data.data.channels || [];
                renderChannels();
            } else {
                throw new Error(data.error || 'Failed to load channels');
            }
        } catch (error) {
            console.error('Error loading channels:', error);
            if (container) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #D13438;">Failed to load channels</div>';
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
                <div style="text-align: center; padding: 60px; color: #605E5C;">
                    <div style="font-size: 48px; margin-bottom: 16px;">📡</div>
                    <div style="font-size: 16px; font-weight: 600;">No Notification Channels</div>
                    <div style="font-size: 14px; margin-top: 8px;">Configure notification channels to start receiving alerts</div>
                </div>
            `;
            return;
        }

        let html = '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 24px;">';

        channels.forEach(channel => {
            const statusColor = getStatusColor(channel.status);
            const statusIcon = getStatusIcon(channel.status);
            const channelIcon = getChannelIcon(channel.integration_id);

            html += `
                <div class="card" style="padding: 0; overflow: hidden;">
                    <div style="padding: 20px; border-bottom: 1px solid #EDEBE9;">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div style="display: flex; align-items: center; gap: 12px;">
                                <div style="width: 48px; height: 48px; border-radius: 8px; background: ${getChannelBg(channel.integration_id)}; display: flex; align-items: center; justify-content: center; font-size: 24px;">
                                    ${channelIcon}
                                </div>
                                <div>
                                    <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: #323130;">${channel.name}</h3>
                                    <p style="margin: 4px 0 0; font-size: 13px; color: #605E5C;">${channel.description || ''}</p>
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <span style="display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; border-radius: 4px; background: ${statusColor}15; color: ${statusColor}; font-size: 12px;">
                                    ${statusIcon} ${channel.status}
                                </span>
                                <label class="toggle-switch">
                                    <input type="checkbox" ${channel.is_enabled ? 'checked' : ''} onchange="toggleChannel('${channel.integration_id}', this.checked)">
                                    <span class="toggle-slider"></span>
                                </label>
                            </div>
                        </div>
                    </div>

                    <div style="padding: 20px;">
                        ${renderChannelConfig(channel)}

                        ${channel.last_test_at ? `
                            <div style="margin-top: 16px; padding: 12px; background: #FAF9F8; border-radius: 4px;">
                                <div style="font-size: 11px; color: #605E5C; margin-bottom: 4px;">Last Test</div>
                                <div style="font-size: 13px; color: ${channel.status === 'error' ? '#D13438' : '#107C10'};">
                                    ${channel.last_test_result || 'No result'}
                                </div>
                                <div style="font-size: 11px; color: #A19F9D; margin-top: 4px;">
                                    ${formatDateTime(channel.last_test_at)}
                                </div>
                            </div>
                        ` : ''}
                    </div>

                    <div style="padding: 16px 20px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end; gap: 8px;">
                        <button class="btn btn-secondary btn-sm" onclick="editChannel('${channel.integration_id}')">
                            Configure
                        </button>
                        <button class="btn btn-primary btn-sm" onclick="testChannel('${channel.integration_id}')">
                            Test
                        </button>
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
        let html = '<div style="display: grid; gap: 8px;">';

        if (channel.integration_id === 'telegram') {
            const botToken = config.bot_token?.value || '';
            const chatId = config.chat_id?.value || '';
            html += `
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: #605E5C;">Bot Token</span>
                    <span style="color: #323130; font-family: monospace;">${botToken ? '********' : 'Not configured'}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: #605E5C;">Chat ID</span>
                    <span style="color: #323130; font-family: monospace;">${chatId || 'Not configured'}</span>
                </div>
            `;
        } else if (channel.integration_id === 'smtp') {
            const host = config.host?.value || '';
            const port = config.port?.value || '';
            const from = config.from_email?.value || '';
            html += `
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: #605E5C;">SMTP Server</span>
                    <span style="color: #323130; font-family: monospace;">${host ? `${host}:${port}` : 'Not configured'}</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 13px;">
                    <span style="color: #605E5C;">From Email</span>
                    <span style="color: #323130;">${from || 'Not configured'}</span>
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
            active: '#107C10',
            configured: '#0078D4',
            inactive: '#605E5C',
            error: '#D13438'
        };
        return colors[status] || '#605E5C';
    }

    /**
     * Get status icon
     */
    function getStatusIcon(status) {
        const icons = {
            active: '●',
            configured: '○',
            inactive: '○',
            error: '!'
        };
        return icons[status] || '○';
    }

    /**
     * Get channel icon
     */
    function getChannelIcon(channelId) {
        const icons = {
            telegram: '<svg width="24" height="24" viewBox="0 0 24 24" fill="#0088cc"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 0 0-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.95-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.36.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .38z"/></svg>',
            smtp: '<svg width="24" height="24" viewBox="0 0 24 24" fill="#D13438"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>'
        };
        return icons[channelId] || '📡';
    }

    /**
     * Get channel background color
     */
    function getChannelBg(channelId) {
        const colors = {
            telegram: '#0088cc15',
            smtp: '#D1343815'
        };
        return colors[channelId] || '#FAF9F8';
    }

    /**
     * Format date time
     */
    function formatDateTime(dateStr) {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        return date.toLocaleString();
    }

    /**
     * Toggle channel enabled state
     */
    window.toggleChannel = async function(channelId, enabled) {
        try {
            const endpoint = enabled ? 'enable' : 'disable';
            const response = await fetch(`/api/dashboard/notification-channels/${channelId}/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                loadChannels();
            } else {
                alert(data.error || 'Failed to update channel');
                loadChannels(); // Reload to reset state
            }
        } catch (error) {
            console.error('Error toggling channel:', error);
            alert('Failed to update channel');
            loadChannels();
        }
    };

    /**
     * Edit channel configuration
     */
    window.editChannel = async function(channelId) {
        try {
            const response = await fetch(`/api/dashboard/notification-channels/${channelId}`);
            const data = await response.json();

            if (data.success) {
                showConfigModal(data.data);
            } else {
                alert(data.error || 'Failed to load channel');
            }
        } catch (error) {
            console.error('Error loading channel:', error);
            alert('Failed to load channel');
        }
    };

    /**
     * Show configuration modal
     */
    function showConfigModal(channel) {
        const existingModal = document.getElementById('channel-config-modal');
        if (existingModal) existingModal.remove();

        const config = channel.config || {};
        let formHtml = '';

        // Build form fields based on config
        for (const [key, cfg] of Object.entries(config)) {
            if (key === 'enabled') continue; // Skip enabled field

            const inputType = cfg.is_sensitive ? 'password' : (cfg.type === 'boolean' ? 'checkbox' : 'text');
            const value = cfg.value || '';
            const required = cfg.is_required ? 'required' : '';

            if (cfg.type === 'boolean') {
                formHtml += `
                    <div style="margin-bottom: 16px;">
                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                            <input type="checkbox" id="config-${key}" ${value === 'true' ? 'checked' : ''} style="width: 18px; height: 18px;">
                            <span style="font-size: 14px; color: #323130;">${cfg.display_name || key}</span>
                        </label>
                        ${cfg.description ? `<div style="font-size: 12px; color: #605E5C; margin-top: 4px; margin-left: 26px;">${cfg.description}</div>` : ''}
                    </div>
                `;
            } else {
                formHtml += `
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; font-size: 13px; font-weight: 500; color: #323130; margin-bottom: 6px;">
                            ${cfg.display_name || key}
                            ${cfg.is_required ? '<span style="color: #D13438;">*</span>' : ''}
                        </label>
                        <input type="${inputType}" id="config-${key}" value="${escapeHtml(value)}"
                               class="form-control" style="width: 100%;" ${required}
                               placeholder="${cfg.description || ''}">
                        ${cfg.description ? `<div style="font-size: 11px; color: #605E5C; margin-top: 4px;">${cfg.description}</div>` : ''}
                    </div>
                `;
            }
        }

        const modal = document.createElement('div');
        modal.id = 'channel-config-modal';
        modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        modal.innerHTML = `
            <div style="background: #FFFFFF; border-radius: 8px; width: 500px; max-width: 90vw; max-height: 90vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div style="padding: 20px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                    <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Configure ${channel.name}</h2>
                    <button onclick="this.closest('#channel-config-modal').remove()" style="background: none; border: none; cursor: pointer; font-size: 24px; color: #605E5C;">&times;</button>
                </div>
                <div style="padding: 20px;">
                    <form id="channel-config-form" onsubmit="saveChannelConfig(event, '${channel.integration_id}')">
                        ${formHtml}
                        <div style="display: flex; justify-content: flex-end; gap: 8px; margin-top: 24px; padding-top: 16px; border-top: 1px solid #EDEBE9;">
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
    window.saveChannelConfig = async function(event, channelId) {
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
            const response = await fetch(`/api/dashboard/notification-channels/${channelId}/configure`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(configData)
            });

            const data = await response.json();

            if (data.success) {
                document.getElementById('channel-config-modal').remove();
                loadChannels();
            } else {
                alert(data.error || 'Failed to save configuration');
            }
        } catch (error) {
            console.error('Error saving configuration:', error);
            alert('Failed to save configuration');
        }
    };

    /**
     * Test channel
     */
    window.testChannel = async function(channelId) {
        let testParams = {};

        // For SMTP, ask for test email
        if (channelId === 'smtp') {
            const email = prompt('Enter email address for test:', '');
            if (email === null) return;
            testParams.test_email = email;
        }

        try {
            const btn = event.target;
            btn.disabled = true;
            btn.textContent = 'Testing...';

            const response = await fetch(`/api/dashboard/notification-channels/${channelId}/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(testParams)
            });

            const data = await response.json();

            if (data.success) {
                alert('Test successful: ' + (data.message || 'Channel working'));
            } else {
                alert('Test failed: ' + (data.error || 'Unknown error'));
            }

            loadChannels();
        } catch (error) {
            console.error('Error testing channel:', error);
            alert('Test failed: ' + error.message);
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

    /**
     * Escape HTML
     */
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

})();
