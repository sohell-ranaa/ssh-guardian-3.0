/**
 * Settings General Page Module
 * Handles display and editing of system settings
 */

(function() {
    'use strict';

    let allSettings = [];
    let currentCategory = 'all';
    let timeSettingsData = null;

    /**
     * Load and display Settings General page
     */
    window.loadSettingsGeneralPage = async function() {
        try {
            // Load settings data
            await loadSettings();

            // Load and render time settings section
            await loadAndRenderTimeSettings();

            // Load and render navigation settings section
            await loadNavigationSettings();

            // Setup event listeners
            setupSettingsEventListeners();

        } catch (error) {
            console.error('Error loading Settings General page:', error);
            showNotification('Failed to load settings', 'error');
        }
    };

    /**
     * Load and populate navigation settings
     */
    async function loadNavigationSettings() {
        try {
            const response = await fetch('/api/dashboard/settings/navigation');
            const data = await response.json();

            if (data.success && data.data) {
                const select = document.getElementById('default-landing-page');
                if (select) {
                    select.value = data.data.default_landing_page || 'overview';
                }
            }
        } catch (error) {
            console.error('Error loading navigation settings:', error);
        }

        // Setup save button listener
        const saveBtn = document.getElementById('save-navigation-settings');
        if (saveBtn) {
            saveBtn.addEventListener('click', saveNavigationSettings);
        }
    }

    /**
     * Save navigation settings
     */
    async function saveNavigationSettings() {
        const select = document.getElementById('default-landing-page');
        const statusSpan = document.getElementById('navigation-save-status');

        if (!select) return;

        try {
            const response = await fetch('/api/dashboard/settings/navigation', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    default_landing_page: select.value
                })
            });

            const data = await response.json();

            if (data.success) {
                if (statusSpan) {
                    statusSpan.textContent = 'Saved!';
                    statusSpan.style.color = 'var(--success, #107C10)';
                    setTimeout(() => { statusSpan.textContent = ''; }, 3000);
                }
                showNotification('Navigation settings saved successfully', 'success');
            } else {
                if (statusSpan) {
                    statusSpan.textContent = 'Failed to save';
                    statusSpan.style.color = 'var(--error, #D13438)';
                }
                showNotification('Failed to save navigation settings: ' + (data.error || 'Unknown error'), 'error');
            }
        } catch (error) {
            console.error('Error saving navigation settings:', error);
            if (statusSpan) {
                statusSpan.textContent = 'Error';
                statusSpan.style.color = 'var(--error, #D13438)';
            }
            showNotification('Error saving navigation settings', 'error');
        }
    }

    /**
     * Load and render time settings section
     */
    async function loadAndRenderTimeSettings() {
        try {
            const response = await fetch('/api/dashboard/settings/time');
            const data = await response.json();

            if (data.success) {
                timeSettingsData = data.data;
                renderTimeSettingsSection();
            }
        } catch (error) {
            console.error('Error loading time settings:', error);
        }
    }

    /**
     * Render Time Settings section
     */
    function renderTimeSettingsSection() {
        const container = document.getElementById('time-settings-container');
        if (!container || !timeSettingsData) return;

        const html = `
            <div class="card" style="padding: 16px;">
                <h3 style="font-size: 14px; font-weight: 600; color: var(--text-primary); margin: 0 0 12px 0;">🕐 Time & Date</h3>
                <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 12px;">
                    <select id="time-setting-timezone" style="padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--background); color: var(--text-primary); font-size: 12px;">
                        ${(timeSettingsData.available_timezones || []).map(tz => {
                            const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
                            const displayText = tz === 'Local' ? 'Local' : tz;
                            const isSelected = timeSettingsData.timezone === tz ? 'selected' : '';
                            return '<option value="' + tz + '" ' + isSelected + '>' + displayText + '</option>';
                        }).join('')}
                    </select>
                    <select id="time-setting-time-format" style="padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--background); color: var(--text-primary); font-size: 12px;">
                        <option value="24h" ${timeSettingsData.time_format === '24h' ? 'selected' : ''}>24h</option>
                        <option value="12h" ${timeSettingsData.time_format === '12h' ? 'selected' : ''}>12h</option>
                    </select>
                    <select id="time-setting-date-format" style="padding: 8px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--background); color: var(--text-primary); font-size: 12px;">
                        ${(timeSettingsData.available_date_formats || []).map(fmt => {
                            return `<option value="${fmt}" ${timeSettingsData.date_format === fmt ? 'selected' : ''}>${fmt}</option>`;
                        }).join('')}
                    </select>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span id="time-preview" style="font-size: 12px; font-family: monospace; color: var(--text-secondary);">${getCurrentTimePreview()}</span>
                    <button id="save-time-settings-btn" style="padding: 8px 14px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; font-size: 12px; font-weight: 500; cursor: pointer;">
                        Save
                    </button>
                </div>
            </div>
        `;

        container.innerHTML = html;

        // Setup time settings event listeners
        setupTimeSettingsListeners();

        // Start preview update interval
        startPreviewUpdate();
    }

    /**
     * Get example date for format preview
     */
    function getDateFormatExample(format) {
        const d = new Date();
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');

        switch (format) {
            case 'DD/MM/YYYY': return `${day}/${month}/${year}`;
            case 'MM/DD/YYYY': return `${month}/${day}/${year}`;
            case 'DD-MM-YYYY': return `${day}-${month}-${year}`;
            case 'YYYY-MM-DD':
            default: return `${year}-${month}-${day}`;
        }
    }

    /**
     * Get current time preview based on selected settings
     */
    function getCurrentTimePreview() {
        if (!timeSettingsData) return '';

        let timezone = document.getElementById('time-setting-timezone')?.value || timeSettingsData.timezone;
        const timeFormat = document.getElementById('time-setting-time-format')?.value || timeSettingsData.time_format;
        const dateFormat = document.getElementById('time-setting-date-format')?.value || timeSettingsData.date_format;

        // Resolve 'Local' to browser's actual timezone
        if (timezone === 'Local') {
            timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        }

        try {
            const now = new Date();
            const options = { timeZone: timezone };
            const formatter = new Intl.DateTimeFormat('en-US', {
                ...options,
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: timeFormat === '12h'
            });

            const parts = formatter.formatToParts(now);
            const partMap = {};
            parts.forEach(p => partMap[p.type] = p.value);

            let datePart;
            switch (dateFormat) {
                case 'DD/MM/YYYY': datePart = `${partMap.day}/${partMap.month}/${partMap.year}`; break;
                case 'MM/DD/YYYY': datePart = `${partMap.month}/${partMap.day}/${partMap.year}`; break;
                case 'DD-MM-YYYY': datePart = `${partMap.day}-${partMap.month}-${partMap.year}`; break;
                default: datePart = `${partMap.year}-${partMap.month}-${partMap.day}`;
            }

            const timePart = timeFormat === '12h'
                ? `${partMap.hour}:${partMap.minute}:${partMap.second} ${partMap.dayPeriod || ''}`
                : `${partMap.hour}:${partMap.minute}:${partMap.second}`;

            return `${datePart} ${timePart}`;
        } catch (error) {
            return 'Invalid timezone';
        }
    }

    /**
     * Setup time settings event listeners
     */
    function setupTimeSettingsListeners() {
        // Update preview on any change
        const updatePreview = () => {
            const preview = document.getElementById('time-preview');
            if (preview) {
                preview.textContent = getCurrentTimePreview();
            }
        };

        // Update timezone hint when selection changes
        const updateTimezoneHint = () => {
            const hint = document.getElementById('timezone-hint');
            const tzSelect = document.getElementById('time-setting-timezone');
            if (hint && tzSelect) {
                if (tzSelect.value === 'Local') {
                    hint.textContent = "Using your browser's timezone automatically";
                } else {
                    hint.textContent = 'All timestamps will be displayed in this timezone';
                }
            }
        };

        document.getElementById('time-setting-timezone')?.addEventListener('change', () => {
            updatePreview();
            updateTimezoneHint();
        });
        document.getElementById('time-setting-date-format')?.addEventListener('change', updatePreview);
        document.getElementById('time-setting-time-format')?.addEventListener('change', updatePreview);

        // Save button
        document.getElementById('save-time-settings-btn')?.addEventListener('click', saveTimeSettings);
    }

    let previewInterval = null;

    /**
     * Start updating preview every second
     */
    function startPreviewUpdate() {
        if (previewInterval) clearInterval(previewInterval);
        previewInterval = setInterval(() => {
            const preview = document.getElementById('time-preview');
            if (preview) {
                preview.textContent = getCurrentTimePreview();
            }
        }, 1000);
    }

    /**
     * Save time settings to database
     */
    async function saveTimeSettings() {
        const timezone = document.getElementById('time-setting-timezone')?.value;
        const timeFormat = document.getElementById('time-setting-time-format')?.value;
        const dateFormat = document.getElementById('time-setting-date-format')?.value;

        try {
            const response = await fetch('/api/dashboard/settings/time', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    timezone: timezone,
                    time_format: timeFormat,
                    date_format: dateFormat
                })
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Time settings saved successfully', 'success');

                // Update local timeSettingsData
                if (timeSettingsData) {
                    timeSettingsData.timezone = timezone;
                    timeSettingsData.time_format = timeFormat;
                    timeSettingsData.date_format = dateFormat;
                }

                // Force reload TimeSettings module so all pages use new settings
                if (window.TimeSettings && typeof window.TimeSettings.reload === 'function') {
                    await window.TimeSettings.reload();
                }
            } else {
                showNotification('Failed to save time settings: ' + (data.error || 'Unknown error'), 'error');
            }
        } catch (error) {
            console.error('Error saving time settings:', error);
            showNotification('Error saving time settings', 'error');
        }
    }

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

        // Filter out 'display' category (already shown in Time & Date section) and 'navigation' (shown above)
        const filteredGrouped = {};
        for (const [category, settings] of Object.entries(grouped)) {
            if (category !== 'display' && category !== 'navigation') {
                filteredGrouped[category] = settings;
            }
        }

        if (Object.keys(filteredGrouped).length === 0) {
            container.innerHTML = '<p style="text-align: center; color: var(--text-secondary); padding: 20px;">No additional settings</p>';
            return;
        }

        let html = '';

        // Render each category
        for (const [category, settings] of Object.entries(filteredGrouped)) {
            html += `
                <div class="settings-category-section" style="margin-bottom: 16px;">
                    <h3 style="font-size: 15px; font-weight: 600; margin-bottom: 10px; text-transform: capitalize; color: var(--text-primary);">
                        ${getCategoryIcon(category)} ${category}
                    </h3>
                    <div style="background: var(--surface); border: 1px solid var(--border); border-radius: 6px; overflow: hidden;">
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
     * Get icon for category
     */
    function getCategoryIcon(category) {
        const icons = {
            'general': '⚙️',
            'security': '🔒',
            'notifications': '🔔',
            'display': '🎨',
            'navigation': '🧭'
        };
        return icons[category] || '📋';
    }

    /**
     * Render a single setting row
     */
    function renderSettingRow(setting, isLast) {
        const borderStyle = isLast ? '' : 'border-bottom: 1px solid var(--border-light);';
        const isBoolean = setting.setting_type === 'boolean';
        const isNumber = setting.setting_type === 'number';
        const isSensitive = setting.is_sensitive;

        let inputHtml = '';

        if (isBoolean) {
            const isChecked = setting.setting_value === 'true' || setting.setting_value === '1';
            inputHtml = `
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                    <input type="checkbox"
                           id="setting-${setting.id}"
                           data-setting-id="${setting.id}"
                           ${isChecked ? 'checked' : ''}
                           style="width: 16px; height: 16px; cursor: pointer;">
                    <span style="font-size: 12px; color: var(--text-secondary);">Enabled</span>
                </label>
            `;
        } else if (isNumber) {
            inputHtml = `
                <input type="number"
                       id="setting-${setting.id}"
                       data-setting-id="${setting.id}"
                       value="${setting.setting_value || ''}"
                       style="width: 120px; padding: 6px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--background); color: var(--text-primary); font-size: 13px;">
            `;
        } else {
            inputHtml = `
                <input type="${isSensitive ? 'password' : 'text'}"
                       id="setting-${setting.id}"
                       data-setting-id="${setting.id}"
                       value="${setting.setting_value || ''}"
                       placeholder="${setting.description || ''}"
                       style="width: 100%; max-width: 280px; padding: 6px 10px; border: 1px solid var(--border); border-radius: 4px; background: var(--background); color: var(--text-primary); font-size: 13px;">
            `;
        }

        return `
            <div style="padding: 12px 16px; ${borderStyle} display: flex; justify-content: space-between; align-items: center; gap: 16px;">
                <div style="flex: 1; min-width: 0;">
                    <div style="font-weight: 500; font-size: 13px; color: var(--text-primary);">
                        ${formatSettingKey(setting.setting_key)}
                    </div>
                    ${setting.description ? `<div style="font-size: 11px; color: var(--text-secondary); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${setting.description}</div>` : ''}
                </div>
                <div style="display: flex; align-items: center; gap: 10px; flex-shrink: 0;">
                    ${inputHtml}
                    <button class="btn-save-setting"
                            data-setting-id="${setting.id}"
                            style="padding: 6px 12px; background: var(--azure-blue); color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500;">
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
