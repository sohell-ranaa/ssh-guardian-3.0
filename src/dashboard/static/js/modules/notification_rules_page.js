/**
 * Notification Rules Page Module
 * Handles notification rule CRUD operations
 */

(function() {
    'use strict';

    let rules = [];
    let triggers = [];
    let currentRuleId = null;

    const CHANNELS = [
        { value: 'telegram', label: 'Telegram', icon: '📱' },
        { value: 'email', label: 'Email', icon: '📧' },
        { value: 'webhook', label: 'Webhook', icon: '🔗' }
    ];

    const MESSAGE_FORMATS = [
        { value: 'text', label: 'Plain Text' },
        { value: 'markdown', label: 'Markdown' },
        { value: 'html', label: 'HTML' }
    ];

    /**
     * Load and display Notification Rules page
     */
    window.loadNotificationRulesPage = async function() {
        console.log('Loading Notification Rules page...');

        try {
            await loadTriggers();
            await loadRules();
            await loadRecentNotifications();
            setupNotificationRulesEventListeners();
        } catch (error) {
            console.error('Error loading Notification Rules page:', error);
            showNotification('Failed to load notification rules', 'error');
        }
    };

    /**
     * Load trigger types
     */
    async function loadTriggers() {
        try {
            const response = await fetch('/api/dashboard/notification-rules/triggers');
            const data = await response.json();

            if (data.success) {
                triggers = data.data.triggers || [];
            }
        } catch (error) {
            console.error('Error loading triggers:', error);
        }
    }

    /**
     * Load notification rules
     */
    async function loadRules() {
        const container = document.getElementById('notification-rules-container');
        if (container) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #605E5C;">Loading notification rules...</div>';
        }

        try {
            const response = await fetch('/api/dashboard/notification-rules/list');
            const data = await response.json();

            if (data.success) {
                rules = data.data.rules || [];
                updateStats(rules);
                renderRules(rules);
            } else {
                throw new Error(data.error || 'Failed to load rules');
            }
        } catch (error) {
            console.error('Error loading rules:', error);
            if (container) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #D13438;">Failed to load notification rules.</div>';
            }
        }
    }

    /**
     * Load recent notifications
     */
    async function loadRecentNotifications() {
        const container = document.getElementById('recent-notifications-container');
        if (!container) return;

        try {
            const response = await fetch('/api/dashboard/notification-history/list?limit=10');
            const data = await response.json();

            if (data.success && data.data.notifications && data.data.notifications.length > 0) {
                renderRecentNotifications(data.data.notifications);
            } else {
                container.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-secondary);">No recent notifications</div>';
            }
        } catch (error) {
            console.error('Error loading recent notifications:', error);
            container.innerHTML = '<div style="text-align: center; padding: 30px; color: var(--text-secondary);">Failed to load notifications</div>';
        }
    }

    /**
     * Render recent notifications
     */
    function renderRecentNotifications(notifications) {
        const container = document.getElementById('recent-notifications-container');
        if (!container) return;

        let html = `
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                    <tr style="background: var(--background); text-align: left;">
                        <th style="padding: 10px 12px; font-weight: 600; color: var(--text-secondary); font-size: 11px; text-transform: uppercase;">Time</th>
                        <th style="padding: 10px 12px; font-weight: 600; color: var(--text-secondary); font-size: 11px; text-transform: uppercase;">Trigger</th>
                        <th style="padding: 10px 12px; font-weight: 600; color: var(--text-secondary); font-size: 11px; text-transform: uppercase;">Rule</th>
                        <th style="padding: 10px 12px; font-weight: 600; color: var(--text-secondary); font-size: 11px; text-transform: uppercase;">Channels</th>
                        <th style="padding: 10px 12px; font-weight: 600; color: var(--text-secondary); font-size: 11px; text-transform: uppercase;">Status</th>
                    </tr>
                </thead>
                <tbody>
        `;

        notifications.forEach(notif => {
            const triggerInfo = getTriggerInfo(notif.trigger_type);
            const channels = parseJSON(notif.channels, []);
            const deliveryStatus = parseJSON(notif.delivery_status, {});
            const statusColor = notif.status === 'sent' ? '#107C10' : notif.status === 'failed' ? '#D13438' : '#F59E0B';
            const statusBg = notif.status === 'sent' ? '#DFF6DD' : notif.status === 'failed' ? '#FDE7E9' : '#FFF4CE';

            // Build channel delivery badges
            let channelBadges = '';
            channels.forEach(ch => {
                const chStatus = deliveryStatus[ch];
                const chColor = chStatus === 'sent' ? '#107C10' : chStatus === 'failed' ? '#D13438' : '#605E5C';
                const chBg = chStatus === 'sent' ? '#DFF6DD' : chStatus === 'failed' ? '#FDE7E9' : '#F3F2F1';
                const chIcon = ch === 'telegram' ? '📱' : ch === 'email' ? '📧' : '🔗';
                channelBadges += `<span style="display: inline-flex; align-items: center; gap: 3px; padding: 3px 8px; border-radius: 10px; font-size: 11px; background: ${chBg}; color: ${chColor}; margin-right: 4px;">${chIcon} ${chStatus || 'pending'}</span>`;
            });

            html += `
                <tr style="border-bottom: 1px solid var(--border-light);">
                    <td style="padding: 12px; color: var(--text-secondary); white-space: nowrap;">${formatDateTime(notif.created_at)}</td>
                    <td style="padding: 12px;">
                        <span style="display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 500; background: ${triggerInfo.bgColor}; color: ${triggerInfo.color};">
                            ${triggerInfo.icon} ${triggerInfo.label}
                        </span>
                    </td>
                    <td style="padding: 12px; color: var(--text-primary);">${escapeHtml(notif.rule_name || 'Unknown')}</td>
                    <td style="padding: 12px;">${channelBadges}</td>
                    <td style="padding: 12px;">
                        <span style="padding: 4px 10px; border-radius: 10px; font-size: 11px; font-weight: 600; background: ${statusBg}; color: ${statusColor}; text-transform: uppercase;">
                            ${notif.status}
                        </span>
                    </td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    /**
     * Update statistics cards
     */
    function updateStats(rulesList) {
        const totalRules = rulesList.length;
        const activeRules = rulesList.filter(r => r.is_enabled).length;
        const totalTriggered = rulesList.reduce((sum, r) => sum + (r.times_triggered || 0), 0);

        // Count unique channels
        const channelsSet = new Set();
        rulesList.forEach(rule => {
            const channels = parseJSON(rule.channels, []);
            channels.forEach(ch => channelsSet.add(ch));
        });

        document.getElementById('stat-total-rules').textContent = totalRules;
        document.getElementById('stat-active-rules').textContent = activeRules;
        document.getElementById('stat-total-triggered').textContent = totalTriggered.toLocaleString();
        document.getElementById('stat-channels-count').textContent = channelsSet.size;
    }

    /**
     * Render notification rules
     */
    function renderRules(rulesList) {
        const container = document.getElementById('notification-rules-container');
        if (!container) return;

        if (!rulesList || rulesList.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px 20px; color: var(--text-secondary);">
                    <div style="font-size: 48px; margin-bottom: 16px;">🔔</div>
                    <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 8px; color: var(--text-primary);">No Notification Rules</h3>
                    <p style="font-size: 14px; margin-bottom: 24px;">Create your first notification rule to receive automated alerts</p>
                    <button onclick="showCreateRuleModal()" style="padding: 10px 24px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 500;">
                        + Create Rule
                    </button>
                </div>
            `;
            return;
        }

        let html = '<div style="display: grid; gap: 14px;">';

        rulesList.forEach(rule => {
            const channels = parseJSON(rule.channels, []);
            const triggerInfo = getTriggerInfo(rule.trigger_on);
            const statusColor = rule.is_enabled ? '#107C10' : '#A19F9D';
            const statusBg = rule.is_enabled ? '#DFF6DD' : '#F3F2F1';
            const statusText = rule.is_enabled ? 'Enabled' : 'Disabled';

            html += `
                <div style="background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 18px; transition: box-shadow 0.2s ease;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px;">
                        <div style="flex: 1;">
                            <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                                <h3 style="margin: 0; font-size: 15px; font-weight: 600; color: var(--text-primary);">${escapeHtml(rule.rule_name)}</h3>
                                <span style="padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; background: ${statusBg}; color: ${statusColor};">
                                    ${statusText}
                                </span>
                            </div>
                            <div style="display: flex; flex-wrap: wrap; gap: 6px; align-items: center;">
                                <span style="display: inline-flex; align-items: center; gap: 5px; padding: 5px 11px; border-radius: 4px; font-size: 12px; font-weight: 500; background: ${triggerInfo.bgColor}; color: ${triggerInfo.color};">
                                    ${triggerInfo.icon} ${triggerInfo.label}
                                </span>
                                ${channels.map(ch => {
                                    const channelInfo = CHANNELS.find(c => c.value === ch) || { icon: '📌', label: ch };
                                    return `<span style="display: inline-flex; align-items: center; gap: 5px; padding: 5px 10px; border-radius: 4px; font-size: 12px; background: var(--background); color: var(--text-secondary); border: 1px solid var(--border-light);">${channelInfo.icon} ${channelInfo.label}</span>`;
                                }).join('')}
                            </div>
                        </div>
                        <div style="display: flex; gap: 6px; flex-shrink: 0;">
                            <button onclick="testRule(${rule.id})" title="Test Rule" style="background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px; color: var(--azure-blue); font-weight: 500; transition: all 0.2s;">
                                ▶ Test
                            </button>
                            <button onclick="toggleRule(${rule.id})" title="${rule.is_enabled ? 'Disable' : 'Enable'}" style="background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px; color: ${rule.is_enabled ? '#D13438' : '#107C10'}; font-weight: 500; transition: all 0.2s;">
                                ${rule.is_enabled ? '⏸ Disable' : '▶ Enable'}
                            </button>
                            <button onclick="showEditRuleModal(${rule.id})" title="Edit" style="background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px; color: var(--text-primary); transition: all 0.2s;">
                                ✏️ Edit
                            </button>
                            <button onclick="deleteRule(${rule.id})" title="Delete" style="background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 6px 12px; cursor: pointer; font-size: 12px; color: #D13438; transition: all 0.2s;">
                                🗑️
                            </button>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 14px; padding-top: 14px; border-top: 1px solid var(--border-light);">
                        <div>
                            <div style="font-size: 10px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; font-weight: 600;">Rate Limit</div>
                            <div style="font-size: 14px; color: var(--text-primary); font-weight: 600;">${rule.rate_limit_minutes} min</div>
                        </div>
                        <div>
                            <div style="font-size: 10px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; font-weight: 600;">Triggered</div>
                            <div style="font-size: 14px; color: var(--text-primary); font-weight: 600;">${(rule.times_triggered || 0).toLocaleString()}</div>
                        </div>
                        <div>
                            <div style="font-size: 10px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; font-weight: 600;">Last Triggered</div>
                            <div style="font-size: 13px; color: var(--text-primary);">${rule.last_triggered_at ? formatDateTime(rule.last_triggered_at) : 'Never'}</div>
                        </div>
                        <div>
                            <div style="font-size: 10px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; font-weight: 600;">Format</div>
                            <div style="font-size: 13px; color: var(--text-primary); text-transform: capitalize;">${rule.message_format || 'markdown'}</div>
                        </div>
                    </div>
                </div>
            `;
        });

        html += '</div>';
        container.innerHTML = html;
    }

    /**
     * Get trigger display info - aligned with blocking rules
     */
    function getTriggerInfo(trigger) {
        const triggerMap = {
            // Core triggers
            'ip_blocked': { icon: '🛡️', label: 'IP Blocked', color: '#0078D4', bgColor: '#deecf9' },
            'agent_offline': { icon: '📴', label: 'Agent Offline', color: '#605E5C', bgColor: '#F3F2F1' },
            'system_error': { icon: '❌', label: 'System Error', color: '#D13438', bgColor: '#FDE7E9' },
            'successful_login': { icon: '✅', label: 'Login Success', color: '#107C10', bgColor: '#DFF6DD' },

            // Attack triggers
            'brute_force_detected': { icon: '🔨', label: 'Brute Force', color: '#D13438', bgColor: '#FDE7E9' },
            'distributed_brute_force_detected': { icon: '🤖', label: 'Distributed BF', color: '#8B0000', bgColor: '#FFE4E1' },
            'account_takeover_detected': { icon: '🎭', label: 'Account Takeover', color: '#8B008B', bgColor: '#F5E6F5' },
            'credential_stuffing_detected': { icon: '🔑', label: 'Credential Stuffing', color: '#B8860B', bgColor: '#FFF8DC' },
            'off_hours_anomaly_detected': { icon: '🌙', label: 'Off-Hours', color: '#4B0082', bgColor: '#E6E6FA' },
            'velocity_attack_detected': { icon: '⚡', label: 'Velocity/DDoS', color: '#FF4500', bgColor: '#FFE4E1' },

            // ML/API triggers
            'ml_threat_detected': { icon: '🧠', label: 'ML Threat', color: '#6366f1', bgColor: '#EEF2FF' },
            'high_risk_detected': { icon: '⚠️', label: 'High Risk (API)', color: '#FF8C00', bgColor: '#FFF4CE' },
            'anomaly_detected': { icon: '🔍', label: 'Anomaly', color: '#5C2D91', bgColor: '#EDE5F4' },

            // Geo/Network triggers
            'geo_anomaly_detected': { icon: '🌍', label: 'Impossible Travel', color: '#0077B6', bgColor: '#E0F7FA' },
            'tor_detected': { icon: '🧅', label: 'Tor Exit Node', color: '#7B68EE', bgColor: '#F0E6FF' },
            'proxy_detected': { icon: '🔒', label: 'Proxy/VPN', color: '#2F4F4F', bgColor: '#E0FFFF' },
            'geo_blocked': { icon: '🚫', label: 'Geo-Blocked', color: '#CD5C5C', bgColor: '#FFE4E1' }
        };

        return triggerMap[trigger] || { icon: '📝', label: trigger, color: '#605E5C', bgColor: '#F3F2F1' };
    }

    /**
     * Format triggers for select dropdown with optgroups
     */
    function formatTriggersForSelect(triggerList, selectedValue) {
        const categories = {
            'core': { label: '📋 Core System', triggers: [] },
            'attack': { label: '⚔️ Attack Detection', triggers: [] },
            'ml': { label: '🧠 ML & API Intelligence', triggers: [] },
            'geo': { label: '🌍 Geo & Network', triggers: [] }
        };

        // Group triggers by category
        triggerList.forEach(t => {
            const cat = t.category || 'core';
            if (categories[cat]) {
                categories[cat].triggers.push(t);
            }
        });

        let html = '';
        for (const [key, cat] of Object.entries(categories)) {
            if (cat.triggers.length > 0) {
                html += `<optgroup label="${cat.label}">`;
                cat.triggers.forEach(t => {
                    const icon = t.icon || '📝';
                    const selected = t.value === selectedValue ? 'selected' : '';
                    html += `<option value="${t.value}" ${selected}>${icon} ${t.label}</option>`;
                });
                html += '</optgroup>';
            }
        }
        return html;
    }

    /**
     * Get trigger description
     */
    function getTriggerDescription(triggerList, value) {
        const trigger = triggerList.find(t => t.value === value);
        if (trigger) {
            return `<strong>${trigger.icon || '📝'} ${trigger.label}:</strong> ${trigger.description}`;
        }
        return '';
    }

    /**
     * Show create rule modal
     */
    window.showCreateRuleModal = function() {
        currentRuleId = null;
        showRuleModal('➕ Create Notification Rule', {});
    };

    /**
     * Show edit rule modal
     */
    window.showEditRuleModal = async function(ruleId) {
        try {
            const response = await fetch(`/api/dashboard/notification-rules/${ruleId}`);
            const data = await response.json();

            if (data.success) {
                currentRuleId = ruleId;
                showRuleModal('✏️ Edit Notification Rule', data.data);
            } else {
                showNotification(data.error || 'Failed to load rule', 'error');
            }
        } catch (error) {
            console.error('Error loading rule:', error);
            showNotification('Failed to load rule', 'error');
        }
    };

    /**
     * Show rule modal
     */
    function showRuleModal(title, rule) {
        const channels = parseJSON(rule.channels, []);
        const conditions = parseJSON(rule.conditions, {});
        const emailRecipients = parseJSON(rule.email_recipients, []);

        const modal = document.createElement('div');
        modal.id = 'rule-modal';
        modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';

        modal.innerHTML = `
            <div style="background: #FFFFFF; border-radius: 8px; width: 90%; max-width: 700px; max-height: 90vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);">
                <div style="padding: 20px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">${title}</h3>
                    <button onclick="closeRuleModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #605E5C;">&times;</button>
                </div>
                <form id="rule-form" style="padding: 20px;">
                    <div style="display: grid; gap: 20px;">
                        <!-- Rule Name -->
                        <div>
                            <label style="display: block; font-size: 13px; font-weight: 600; color: #323130; margin-bottom: 6px;">Rule Name *</label>
                            <input type="text" id="rule-name" value="${escapeHtml(rule.rule_name || '')}" required
                                style="width: 100%; padding: 10px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                        </div>

                        <!-- Trigger -->
                        <div>
                            <label style="display: block; font-size: 13px; font-weight: 600; color: #323130; margin-bottom: 6px;">Trigger On *</label>
                            <select id="rule-trigger" required style="width: 100%; padding: 10px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px;">
                                <option value="">Select trigger...</option>
                                ${formatTriggersForSelect(triggers, rule.trigger_on)}
                            </select>
                            <div id="trigger-description" style="margin-top: 6px; padding: 8px 10px; background: #FAF9F8; border-radius: 4px; font-size: 12px; color: #605E5C; display: ${rule.trigger_on ? 'block' : 'none'};">
                                ${rule.trigger_on ? getTriggerDescription(triggers, rule.trigger_on) : ''}
                            </div>
                        </div>

                        <!-- Channels -->
                        <div>
                            <label style="display: block; font-size: 13px; font-weight: 600; color: #323130; margin-bottom: 6px;">Notification Channels *</label>
                            <div style="display: flex; gap: 16px; flex-wrap: wrap;">
                                ${CHANNELS.map(ch => `
                                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                        <input type="checkbox" name="channels" value="${ch.value}" ${channels.includes(ch.value) ? 'checked' : ''}>
                                        <span>${ch.icon} ${ch.label}</span>
                                    </label>
                                `).join('')}
                            </div>
                        </div>

                        <!-- Telegram Settings -->
                        <div id="telegram-settings" style="display: ${channels.includes('telegram') ? 'block' : 'none'}; padding: 16px; background: #FAF9F8; border-radius: 4px;">
                            <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #323130;">📱 Telegram Settings</h4>
                            <div style="display: grid; gap: 12px;">
                                <div>
                                    <label style="display: block; font-size: 12px; color: #605E5C; margin-bottom: 4px;">Chat ID (leave empty to use global)</label>
                                    <input type="text" id="rule-telegram-chat-id" value="${escapeHtml(rule.telegram_chat_id || '')}"
                                        style="width: 100%; padding: 8px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 13px; box-sizing: border-box;">
                                </div>
                            </div>
                        </div>

                        <!-- Email Settings -->
                        <div id="email-settings" style="display: ${channels.includes('email') ? 'block' : 'none'}; padding: 16px; background: #FAF9F8; border-radius: 4px;">
                            <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #323130;">📧 Email Settings</h4>
                            <div>
                                <label style="display: block; font-size: 12px; color: #605E5C; margin-bottom: 4px;">Recipients (comma-separated)</label>
                                <input type="text" id="rule-email-recipients" value="${emailRecipients.join(', ')}"
                                    style="width: 100%; padding: 8px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 13px; box-sizing: border-box;">
                            </div>
                        </div>

                        <!-- Webhook Settings -->
                        <div id="webhook-settings" style="display: ${channels.includes('webhook') ? 'block' : 'none'}; padding: 16px; background: #FAF9F8; border-radius: 4px;">
                            <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #323130;">🔗 Webhook Settings</h4>
                            <div>
                                <label style="display: block; font-size: 12px; color: #605E5C; margin-bottom: 4px;">Webhook URL</label>
                                <input type="url" id="rule-webhook-url" value="${escapeHtml(rule.webhook_url || '')}"
                                    style="width: 100%; padding: 8px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 13px; box-sizing: border-box;">
                            </div>
                        </div>

                        <!-- Message Template -->
                        <div>
                            <label style="display: block; font-size: 13px; font-weight: 600; color: #323130; margin-bottom: 6px;">Message Template *</label>
                            <textarea id="rule-message" required rows="5"
                                style="width: 100%; padding: 10px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; font-family: monospace; box-sizing: border-box; resize: vertical;">${escapeHtml(rule.message_template || getDefaultTemplate())}</textarea>
                            <p style="margin: 4px 0 0 0; font-size: 11px; color: #605E5C;">Variables: {ip_address}, {risk_score}, {reason}, {timestamp}, {agent_name}</p>
                        </div>

                        <!-- Options Row -->
                        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px;">
                            <div>
                                <label style="display: block; font-size: 13px; font-weight: 600; color: #323130; margin-bottom: 6px;">Format</label>
                                <select id="rule-format" style="width: 100%; padding: 10px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px;">
                                    ${MESSAGE_FORMATS.map(f => `<option value="${f.value}" ${rule.message_format === f.value ? 'selected' : ''}>${f.label}</option>`).join('')}
                                </select>
                            </div>
                            <div>
                                <label style="display: block; font-size: 13px; font-weight: 600; color: #323130; margin-bottom: 6px;">Rate Limit (min)</label>
                                <input type="number" id="rule-rate-limit" value="${rule.rate_limit_minutes || 5}" min="1" max="1440"
                                    style="width: 100%; padding: 10px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                            </div>
                            <div>
                                <label style="display: block; font-size: 13px; font-weight: 600; color: #323130; margin-bottom: 6px;">Status</label>
                                <select id="rule-enabled" style="width: 100%; padding: 10px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px;">
                                    <option value="true" ${rule.is_enabled !== false ? 'selected' : ''}>Enabled</option>
                                    <option value="false" ${rule.is_enabled === false ? 'selected' : ''}>Disabled</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </form>
                <div style="padding: 16px 20px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end; gap: 12px;">
                    <button onclick="closeRuleModal()" style="padding: 10px 20px; background: #F3F2F1; border: 1px solid #EDEBE9; border-radius: 4px; cursor: pointer; font-size: 14px; color: #323130;">
                        ✕ Cancel
                    </button>
                    <button onclick="saveRule()" style="padding: 10px 20px; background: #0078D4; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; color: #FFFFFF;">
                        ${currentRuleId ? '💾 Update Rule' : '➕ Create Rule'}
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Setup channel checkbox listeners
        document.querySelectorAll('input[name="channels"]').forEach(checkbox => {
            checkbox.addEventListener('change', updateChannelSettings);
        });

        // Setup trigger select listener to show description
        const triggerSelect = document.getElementById('rule-trigger');
        if (triggerSelect) {
            triggerSelect.addEventListener('change', function() {
                const descDiv = document.getElementById('trigger-description');
                if (this.value) {
                    descDiv.innerHTML = getTriggerDescription(triggers, this.value);
                    descDiv.style.display = 'block';
                } else {
                    descDiv.style.display = 'none';
                }
            });
        }

        // Close on backdrop click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeRuleModal();
        });
    }

    /**
     * Update channel settings visibility
     */
    function updateChannelSettings() {
        const checkboxes = document.querySelectorAll('input[name="channels"]');
        checkboxes.forEach(cb => {
            const settingsDiv = document.getElementById(`${cb.value}-settings`);
            if (settingsDiv) {
                settingsDiv.style.display = cb.checked ? 'block' : 'none';
            }
        });
    }

    /**
     * Get default message template
     */
    function getDefaultTemplate() {
        return `🔔 **SSH Guardian Alert**

**Event:** {trigger_type}
**IP:** {ip_address}
**Risk Score:** {risk_score}
**Reason:** {reason}

**Time:** {timestamp}`;
    }

    /**
     * Close rule modal
     */
    window.closeRuleModal = function() {
        const modal = document.getElementById('rule-modal');
        if (modal) modal.remove();
        currentRuleId = null;
    };

    /**
     * Save rule
     */
    window.saveRule = async function() {
        const ruleName = document.getElementById('rule-name').value.trim();
        const trigger = document.getElementById('rule-trigger').value;
        const message = document.getElementById('rule-message').value.trim();

        // Get selected channels
        const channels = [];
        document.querySelectorAll('input[name="channels"]:checked').forEach(cb => {
            channels.push(cb.value);
        });

        if (!ruleName || !trigger || channels.length === 0 || !message) {
            showNotification('Please fill in all required fields', 'error');
            return;
        }

        // Get email recipients
        const emailRecipientsStr = document.getElementById('rule-email-recipients')?.value || '';
        const emailRecipients = emailRecipientsStr.split(',').map(e => e.trim()).filter(e => e);

        const payload = {
            rule_name: ruleName,
            trigger_on: trigger,
            channels: channels,
            message_template: message,
            message_format: document.getElementById('rule-format').value,
            rate_limit_minutes: parseInt(document.getElementById('rule-rate-limit').value) || 5,
            is_enabled: document.getElementById('rule-enabled').value === 'true',
            telegram_chat_id: document.getElementById('rule-telegram-chat-id')?.value || '',
            email_recipients: emailRecipients,
            webhook_url: document.getElementById('rule-webhook-url')?.value || ''
        };

        try {
            const url = currentRuleId
                ? `/api/dashboard/notification-rules/${currentRuleId}`
                : '/api/dashboard/notification-rules/create';

            const response = await fetch(url, {
                method: currentRuleId ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message || 'Rule saved successfully', 'success');
                closeRuleModal();
                loadRules();
            } else {
                showNotification(data.error || 'Failed to save rule', 'error');
            }
        } catch (error) {
            console.error('Error saving rule:', error);
            showNotification('Failed to save rule', 'error');
        }
    };

    /**
     * Toggle rule enabled status
     */
    window.toggleRule = async function(ruleId) {
        try {
            const response = await fetch(`/api/dashboard/notification-rules/${ruleId}/toggle`, {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message, 'success');
                loadRules();
            } else {
                showNotification(data.error || 'Failed to toggle rule', 'error');
            }
        } catch (error) {
            console.error('Error toggling rule:', error);
            showNotification('Failed to toggle rule', 'error');
        }
    };

    /**
     * Delete rule
     */
    window.deleteRule = async function(ruleId) {
        if (!confirm('Are you sure you want to delete this notification rule?')) {
            return;
        }

        try {
            const response = await fetch(`/api/dashboard/notification-rules/${ruleId}`, {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Rule deleted successfully', 'success');
                loadRules();
            } else {
                showNotification(data.error || 'Failed to delete rule', 'error');
            }
        } catch (error) {
            console.error('Error deleting rule:', error);
            showNotification('Failed to delete rule', 'error');
        }
    };

    /**
     * Test rule
     */
    window.testRule = async function(ruleId) {
        try {
            showNotification('Sending test notification...', 'info');

            const response = await fetch(`/api/dashboard/notification-rules/${ruleId}/test`, {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                const results = data.data.results || [];
                const successCount = results.filter(r => r.success).length;

                // Build detailed message
                let detailMessages = results.map(r => {
                    const icon = r.channel === 'telegram' ? '📱' : r.channel === 'email' ? '📧' : '🔗';
                    const status = r.success ? '✅' : '❌';
                    return `${icon} ${r.channel}: ${status} ${r.success ? r.message : r.error}`;
                }).join('\n');

                if (successCount === results.length) {
                    showNotification(`All test notifications sent!\n${detailMessages}`, 'success');
                } else if (successCount > 0) {
                    showNotification(`Partial success:\n${detailMessages}`, 'warning');
                } else {
                    showNotification(`Test failed:\n${detailMessages}`, 'error');
                }

                // Reload recent notifications to show test result
                setTimeout(() => loadRecentNotifications(), 1000);
            } else {
                showNotification(data.error || 'Failed to test rule', 'error');
            }
        } catch (error) {
            console.error('Error testing rule:', error);
            showNotification('Failed to test rule', 'error');
        }
    };

    /**
     * Setup event listeners
     */
    function setupNotificationRulesEventListeners() {
        const createBtn = document.getElementById('notif-rules-create-btn');
        if (createBtn) {
            createBtn.onclick = showCreateRuleModal;
        }

        const refreshBtn = document.getElementById('notif-rules-refresh-btn');
        if (refreshBtn) {
            refreshBtn.onclick = loadRules;
        }
    }

    /**
     * Parse JSON safely
     */
    function parseJSON(value, defaultValue) {
        if (!value) return defaultValue;
        if (typeof value === 'object') return value;
        try {
            return JSON.parse(value);
        } catch (e) {
            return defaultValue;
        }
    }

    /**
     * Format date/time
     */
    function formatDateTime(dateStr) {
        if (!dateStr) return '-';
        // Use TimeSettings if available
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.formatShort(dateStr);
        }
        const date = new Date(dateStr);
        return date.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    /**
     * Escape HTML
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Show notification
     */
    function showNotification(message, type) {
        if (typeof window.showNotification === 'function') {
            window.showNotification(message, type);
        } else {
            alert(message);
        }
    }

})();
