/**
 * Settings General Page Module
 * Handles display and editing of system settings
 */

(function() {
    'use strict';

    let allSettings = [];
    let currentCategory = 'all';

    /**
     * Load and display Settings General page
     */
    window.loadSettingsGeneralPage = async function() {
        console.log('Loading Settings General page...');

        try {
            // Load settings data
            await loadSettings();

            // Setup event listeners
            setupSettingsEventListeners();

        } catch (error) {
            console.error('Error loading Settings General page:', error);
            showNotification('Failed to load settings', 'error');
        }
    };

    /**
     * Load settings from API
     */
    async function loadSettings(category = '') {
        try {
            const url = category ? `/api/dashboard/settings/list?category=${category}` : '/api/dashboard/settings/list';
            const response = await fetch(url);
            const data = await response.json();

            if (data.success) {
                allSettings = data.data.settings;
                renderSettingsByCategory(data.data.grouped);
            } else {
                throw new Error(data.error || 'Failed to load settings');
            }

        } catch (error) {
            console.error('Error loading settings:', error);
            showNotification('Failed to load settings', 'error');
        }
    }

    /**
     * Render settings grouped by category
     */
    function renderSettingsByCategory(grouped) {
        const container = document.getElementById('settings-categories-container');

        if (!container) return;

        if (Object.keys(grouped).length === 0) {
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 40px;">No settings found</p>';
            return;
        }

        let html = '';

        // Render each category
        for (const [category, settings] of Object.entries(grouped)) {
            html += `
                <div class="settings-category-section" style="margin-bottom: 32px;">
                    <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 16px; text-transform: capitalize; color: var(--text-primary);">
                        ${category}
                    </h3>
                    <div style="background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden;">
                        ${settings.map((setting, index) => renderSettingRow(setting, index === settings.length - 1)).join('')}
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;

        // Setup inline event listeners
        setupInlineEventListeners();
    }

    /**
     * Render a single setting row
     */
    function renderSettingRow(setting, isLast) {
        const borderStyle = isLast ? '' : 'border-bottom: 1px solid var(--border);';
        const isBoolean = setting.setting_type === 'boolean';
        const isNumber = setting.setting_type === 'number';
        const isSensitive = setting.is_sensitive;

        let inputHtml = '';

        if (isBoolean) {
            const isChecked = setting.setting_value === 'true' || setting.setting_value === '1';
            inputHtml = `
                <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                    <input type="checkbox"
                           id="setting-${setting.id}"
                           data-setting-id="${setting.id}"
                           ${isChecked ? 'checked' : ''}
                           style="width: 18px; height: 18px; cursor: pointer;">
                    <span style="font-size: 13px; color: var(--text-secondary);">Enabled</span>
                </label>
            `;
        } else if (isNumber) {
            inputHtml = `
                <input type="number"
                       id="setting-${setting.id}"
                       data-setting-id="${setting.id}"
                       value="${setting.setting_value || ''}"
                       style="width: 100%; max-width: 300px; padding: 8px 12px; border: 1px solid var(--border); border-radius: 4px; background: var(--background); color: var(--text-primary); font-size: 14px;">
            `;
        } else {
            inputHtml = `
                <input type="${isSensitive ? 'password' : 'text'}"
                       id="setting-${setting.id}"
                       data-setting-id="${setting.id}"
                       value="${setting.setting_value || ''}"
                       placeholder="${setting.description || ''}"
                       style="width: 100%; max-width: 500px; padding: 8px 12px; border: 1px solid var(--border); border-radius: 4px; background: var(--background); color: var(--text-primary); font-size: 14px;">
            `;
        }

        return `
            <div style="padding: 20px; ${borderStyle}">
                <div style="display: flex; justify-content: space-between; align-items: start; gap: 24px;">
                    <div style="flex: 1;">
                        <div style="font-weight: 500; font-size: 14px; margin-bottom: 4px; color: var(--text-primary);">
                            ${formatSettingKey(setting.setting_key)}
                        </div>
                        ${setting.description ? `
                            <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
                                ${setting.description}
                            </div>
                        ` : ''}
                        ${inputHtml}
                    </div>
                    <button class="btn-save-setting"
                            data-setting-id="${setting.id}"
                            style="padding: 8px 16px; background: var(--primary); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 500; white-space: nowrap;">
                        Save
                    </button>
                </div>
            </div>
        `;
    }

    /**
     * Setup inline event listeners after rendering
     */
    function setupInlineEventListeners() {
        // Save buttons
        document.querySelectorAll('.btn-save-setting').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const settingId = e.target.getAttribute('data-setting-id');
                const input = document.getElementById(`setting-${settingId}`);

                if (!input) return;

                let value;
                if (input.type === 'checkbox') {
                    value = input.checked ? 'true' : 'false';
                } else {
                    value = input.value;
                }

                await saveSetting(settingId, value);
            });
        });
    }

    /**
     * Save a single setting
     */
    async function saveSetting(settingId, value) {
        try {
            const response = await fetch(`/api/dashboard/settings/${settingId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    setting_value: value
                })
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Setting saved successfully', 'success');
            } else {
                throw new Error(data.error || 'Failed to save setting');
            }

        } catch (error) {
            console.error('Error saving setting:', error);
            showNotification('Failed to save setting', 'error');
        }
    }

    /**
     * Setup event listeners
     */
    function setupSettingsEventListeners() {
        // Category filter
        const categorySelect = document.getElementById('settings-category-filter');
        if (categorySelect) {
            categorySelect.addEventListener('change', (e) => {
                currentCategory = e.target.value;
                const category = currentCategory === 'all' ? '' : currentCategory;
                loadSettings(category);
            });
        }

        // Refresh button
        const refreshBtn = document.getElementById('settings-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                const category = currentCategory === 'all' ? '' : currentCategory;
                loadSettings(category);
                showNotification('Settings refreshed', 'success');
            });
        }

        // Save all button
        const saveAllBtn = document.getElementById('settings-save-all-btn');
        if (saveAllBtn) {
            saveAllBtn.addEventListener('click', async () => {
                await saveAllSettings();
            });
        }
    }

    /**
     * Save all modified settings
     */
    async function saveAllSettings() {
        try {
            const settingsToUpdate = [];

            // Collect all settings from inputs
            allSettings.forEach(setting => {
                const input = document.getElementById(`setting-${setting.id}`);
                if (input) {
                    let value;
                    if (input.type === 'checkbox') {
                        value = input.checked ? 'true' : 'false';
                    } else {
                        value = input.value;
                    }

                    // Only include if changed
                    if (value !== setting.setting_value) {
                        settingsToUpdate.push({
                            id: setting.id,
                            setting_value: value
                        });
                    }
                }
            });

            if (settingsToUpdate.length === 0) {
                showNotification('No changes to save', 'info');
                return;
            }

            const response = await fetch('/api/dashboard/settings/bulk-update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    settings: settingsToUpdate
                })
            });

            const data = await response.json();

            if (data.success) {
                showNotification(data.message || 'All settings saved successfully', 'success');
                // Reload settings to get updated values
                const category = currentCategory === 'all' ? '' : currentCategory;
                await loadSettings(category);
            } else {
                throw new Error(data.error || 'Failed to save settings');
            }

        } catch (error) {
            console.error('Error saving settings:', error);
            showNotification('Failed to save settings', 'error');
        }
    }

    /**
     * Helper: Format setting key for display
     */
    function formatSettingKey(key) {
        return key
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }

})();
