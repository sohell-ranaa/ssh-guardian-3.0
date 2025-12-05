/**
 * System Status Page Module
 * Handles cache management, time settings, and system health monitoring
 */

(function() {
    'use strict';

    // Time settings stored in localStorage
    const TIME_SETTINGS_KEY = 'ssh_guardian_time_settings';
    let timeUpdateInterval = null;

    /**
     * Load and display System Status page
     */
    window.loadSystemStatusPage = async function() {
        try {
            // Load time settings from localStorage
            loadTimeSettings();

            // Load cache stats
            await loadCacheStats();

            // Load system health
            await loadSystemHealth();

            // Setup event listeners
            setupSystemStatusEventListeners();

            // Start time display update
            startTimeUpdate();

            // Update time preview
            updateTimePreview();

        } catch (error) {
            console.error('Error loading System Status page:', error);
            showNotification('Failed to load system status', 'error');
        }
    };

    /**
     * Load time settings from localStorage
     */
    function loadTimeSettings() {
        const settings = getTimeSettings();

        // Set select values
        const timezoneSelect = document.getElementById('timezone-select');
        const timeFormatSelect = document.getElementById('time-format-select');
        const dateFormatSelect = document.getElementById('date-format-select');

        if (timezoneSelect) timezoneSelect.value = settings.timezone;
        if (timeFormatSelect) timeFormatSelect.value = settings.timeFormat;
        if (dateFormatSelect) dateFormatSelect.value = settings.dateFormat;

        // Update preview
        updateTimePreview();
    }

    /**
     * Get time settings from localStorage
     */
    function getTimeSettings() {
        try {
            const stored = localStorage.getItem(TIME_SETTINGS_KEY);
            if (stored) {
                return JSON.parse(stored);
            }
        } catch (e) {
            console.error('Error reading time settings:', e);
        }

        // Default settings - use browser's local timezone
        return {
            timezone: 'local',
            timeFormat: '24h',
            dateFormat: 'YYYY-MM-DD'
        };
    }

    /**
     * Save time settings to localStorage
     */
    function saveTimeSettings(settings) {
        try {
            localStorage.setItem(TIME_SETTINGS_KEY, JSON.stringify(settings));
            return true;
        } catch (e) {
            console.error('Error saving time settings:', e);
            return false;
        }
    }

    /**
     * Format a date according to current settings
     */
    window.formatDateTime = function(dateString, showTime = true) {
        if (!dateString) return '-';

        const settings = getTimeSettings();
        const date = new Date(dateString);

        // Handle timezone
        let options = {};
        if (settings.timezone !== 'local' && settings.timezone !== 'UTC') {
            options.timeZone = settings.timezone;
        } else if (settings.timezone === 'UTC') {
            options.timeZone = 'UTC';
        }

        // Format date part
        let dateStr = '';
        const year = date.toLocaleDateString('en-CA', { ...options, year: 'numeric' });
        const month = date.toLocaleDateString('en-CA', { ...options, month: '2-digit' });
        const day = date.toLocaleDateString('en-CA', { ...options, day: '2-digit' });
        const monthShort = date.toLocaleDateString('en-US', { ...options, month: 'short' });

        switch (settings.dateFormat) {
            case 'YYYY-MM-DD':
                dateStr = `${year}-${month}-${day}`;
                break;
            case 'DD/MM/YYYY':
                dateStr = `${day}/${month}/${year}`;
                break;
            case 'MM/DD/YYYY':
                dateStr = `${month}/${day}/${year}`;
                break;
            case 'DD MMM YYYY':
                dateStr = `${day} ${monthShort} ${year}`;
                break;
            default:
                dateStr = `${year}-${month}-${day}`;
        }

        if (!showTime) {
            return dateStr;
        }

        // Format time part
        let timeStr = '';
        if (settings.timeFormat === '12h') {
            timeStr = date.toLocaleTimeString('en-US', {
                ...options,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: true
            });
        } else {
            timeStr = date.toLocaleTimeString('en-GB', {
                ...options,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });
        }

        return `${dateStr} ${timeStr}`;
    };

    /**
     * Update time preview display
     */
    function updateTimePreview() {
        const previewEl = document.getElementById('time-preview');
        if (previewEl) {
            previewEl.textContent = formatDateTime(new Date().toISOString());
        }
    }

    /**
     * Start updating current time display
     */
    function startTimeUpdate() {
        // Clear any existing interval
        if (timeUpdateInterval) {
            clearInterval(timeUpdateInterval);
        }

        // Update immediately
        updateCurrentTimeDisplay();

        // Update every second
        timeUpdateInterval = setInterval(() => {
            updateCurrentTimeDisplay();
            updateTimePreview();
        }, 1000);
    }

    /**
     * Update current time display in header
     */
    function updateCurrentTimeDisplay() {
        const timeEl = document.getElementById('current-time-display');
        if (timeEl) {
            const settings = getTimeSettings();
            const tzLabel = settings.timezone === 'local' ? Intl.DateTimeFormat().resolvedOptions().timeZone : settings.timezone;
            timeEl.textContent = `${formatDateTime(new Date().toISOString())} (${tzLabel})`;
        }
    }

    /**
     * Load cache statistics
     */
    async function loadCacheStats() {
        try {
            const response = await fetch('/api/dashboard/events/cache/stats');
            const data = await response.json();

            if (data.success && data.cache) {
                const cache = data.cache;

                // Update stats display
                document.getElementById('cache-total-keys').textContent = cache.total_keys || '0';
                document.getElementById('cache-memory-used').textContent = cache.memory_used || 'N/A';
                document.getElementById('cache-memory-peak').textContent = cache.memory_peak || 'N/A';

                // Update status
                const statusBadge = document.getElementById('cache-status-badge');
                const statusText = document.getElementById('cache-hit-rate');

                if (cache.connected) {
                    statusBadge.textContent = 'Connected';
                    statusBadge.className = 'badge badge-success';
                    statusText.textContent = 'Active';
                } else if (cache.enabled) {
                    statusBadge.textContent = 'Disconnected';
                    statusBadge.className = 'badge badge-danger';
                    statusText.textContent = 'Error';
                } else {
                    statusBadge.textContent = 'Disabled';
                    statusBadge.className = 'badge badge-secondary';
                    statusText.textContent = 'Disabled';
                }
            }
        } catch (error) {
            console.error('Error loading cache stats:', error);
            document.getElementById('cache-status-badge').textContent = 'Error';
            document.getElementById('cache-status-badge').className = 'badge badge-danger';
        }
    }

    /**
     * Load system health status
     */
    async function loadSystemHealth() {
        try {
            const response = await fetch('/health');
            const data = await response.json();

            // Update database status
            const dbIcon = document.getElementById('db-status-icon');
            const dbText = document.getElementById('db-status-text');
            if (data.database === 'connected') {
                dbIcon.textContent = 'OK';
                dbText.textContent = 'Connected';
                dbIcon.parentElement.style.background = 'var(--success-bg)';
            } else {
                dbIcon.textContent = 'X';
                dbText.textContent = 'Disconnected';
                dbIcon.parentElement.style.background = 'var(--danger-bg)';
            }

            // Update server status
            const serverIcon = document.getElementById('server-status-icon');
            const serverText = document.getElementById('server-status-text');
            if (data.status === 'healthy') {
                serverIcon.textContent = 'OK';
                serverText.textContent = 'Healthy';
                serverIcon.parentElement.style.background = 'var(--success-bg)';
            } else {
                serverIcon.textContent = '!';
                serverText.textContent = data.status || 'Unknown';
                serverIcon.parentElement.style.background = 'var(--warning-bg)';
            }

            // Update version
            document.getElementById('version-text').textContent = `Version ${data.version || '3.0.0'}`;

            // Update Redis status based on cache stats
            const cacheResponse = await fetch('/api/dashboard/events/cache/stats');
            const cacheData = await cacheResponse.json();

            const redisIcon = document.getElementById('redis-status-icon');
            const redisText = document.getElementById('redis-status-text');
            if (cacheData.success && cacheData.cache && cacheData.cache.connected) {
                redisIcon.textContent = 'OK';
                redisText.textContent = 'Connected';
                redisIcon.parentElement.style.background = 'var(--success-bg)';
            } else if (cacheData.cache && cacheData.cache.enabled === false) {
                redisIcon.textContent = '-';
                redisText.textContent = 'Not Configured';
                redisIcon.parentElement.style.background = 'var(--secondary-bg)';
            } else {
                redisIcon.textContent = 'X';
                redisText.textContent = 'Disconnected';
                redisIcon.parentElement.style.background = 'var(--danger-bg)';
            }

        } catch (error) {
            console.error('Error loading system health:', error);
        }
    }

    /**
     * Setup event listeners
     */
    function setupSystemStatusEventListeners() {
        // Time setting changes - update preview
        ['timezone-select', 'time-format-select', 'date-format-select'].forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.addEventListener('change', updateTimePreview);
            }
        });

        // Save time settings
        const saveTimeBtn = document.getElementById('save-time-settings-btn');
        if (saveTimeBtn) {
            saveTimeBtn.addEventListener('click', () => {
                const settings = {
                    timezone: document.getElementById('timezone-select').value,
                    timeFormat: document.getElementById('time-format-select').value,
                    dateFormat: document.getElementById('date-format-select').value
                };

                if (saveTimeSettings(settings)) {
                    showNotification('Time settings saved successfully', 'success');
                    // Update all times in the page
                    updateCurrentTimeDisplay();
                } else {
                    showNotification('Failed to save time settings', 'error');
                }
            });
        }

        // Refresh button
        const refreshBtn = document.getElementById('system-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', async () => {
                await loadCacheStats();
                await loadSystemHealth();
                showNotification('System status refreshed', 'success');
            });
        }

        // Clear events cache
        const clearEventsBtn = document.getElementById('clear-events-cache-btn');
        if (clearEventsBtn) {
            clearEventsBtn.addEventListener('click', async () => {
                try {
                    const response = await fetch('/api/dashboard/events/cache/clear', { method: 'POST' });
                    const data = await response.json();
                    if (data.success) {
                        showNotification('Events cache cleared', 'success');
                        await loadCacheStats();
                    } else {
                        throw new Error(data.error);
                    }
                } catch (error) {
                    showNotification('Failed to clear events cache', 'error');
                }
            });
        }

        // Clear stats cache
        const clearStatsBtn = document.getElementById('clear-stats-cache-btn');
        if (clearStatsBtn) {
            clearStatsBtn.addEventListener('click', async () => {
                try {
                    const response = await fetch('/api/dashboard/system/cache/clear-stats', { method: 'POST' });
                    const data = await response.json();
                    if (data.success) {
                        showNotification('Stats cache cleared', 'success');
                        await loadCacheStats();
                    } else {
                        throw new Error(data.error);
                    }
                } catch (error) {
                    showNotification('Failed to clear stats cache', 'error');
                }
            });
        }

        // Clear all cache
        const clearAllBtn = document.getElementById('clear-all-cache-btn');
        if (clearAllBtn) {
            clearAllBtn.addEventListener('click', async () => {
                if (!confirm('Are you sure you want to clear all cache? This may cause slower page loads temporarily.')) {
                    return;
                }

                try {
                    const response = await fetch('/api/dashboard/system/cache/clear-all', { method: 'POST' });
                    const data = await response.json();
                    if (data.success) {
                        showNotification('All cache cleared', 'success');
                        await loadCacheStats();
                    } else {
                        throw new Error(data.error);
                    }
                } catch (error) {
                    showNotification('Failed to clear all cache', 'error');
                }
            });
        }
    }

    /**
     * Cleanup when leaving page
     */
    window.unloadSystemStatusPage = function() {
        if (timeUpdateInterval) {
            clearInterval(timeUpdateInterval);
            timeUpdateInterval = null;
        }
    };

})();
