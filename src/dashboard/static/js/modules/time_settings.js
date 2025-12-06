/**
 * Time Settings Module
 * Handles persistent time/date formatting settings from the database
 */

(function() {
    'use strict';

    // Default settings (used until loaded from server)
    let timeSettings = {
        time_format: '24h',
        date_format: 'YYYY-MM-DD',
        timezone: 'UTC',
        datetime_format: 'YYYY-MM-DD HH:mm:ss'
    };

    let settingsLoaded = false;
    let loadPromise = null;

    /**
     * Load time settings from server
     * @param {boolean} forceReload - Force reload from server even if already loaded
     */
    async function loadTimeSettings(forceReload = false) {
        // Return cached promise if already loading/loaded and not forcing reload
        if (loadPromise && !forceReload) return loadPromise;

        // Reset promise for fresh load
        loadPromise = (async () => {
            try {
                // Add nocache param to bypass server cache when forcing reload
                const url = forceReload
                    ? '/api/dashboard/settings/time?nocache=1'
                    : '/api/dashboard/settings/time';
                const response = await fetch(url);
                const data = await response.json();

                if (data.success) {
                    timeSettings = {
                        time_format: data.data.time_format || '24h',
                        date_format: data.data.date_format || 'YYYY-MM-DD',
                        timezone: data.data.timezone || 'UTC',
                        datetime_format: data.data.datetime_format || 'YYYY-MM-DD HH:mm:ss',
                        available_timezones: data.data.available_timezones || [],
                        available_time_formats: data.data.available_time_formats || ['12h', '24h'],
                        available_date_formats: data.data.available_date_formats || []
                    };
                    settingsLoaded = true;
                    console.log('Time settings loaded:', timeSettings);
                }
            } catch (error) {
                console.error('Failed to load time settings:', error);
            }
        })();

        return loadPromise;
    }

    /**
     * Save time settings to server
     */
    async function saveTimeSettings(settings) {
        try {
            const response = await fetch('/api/dashboard/settings/time', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });

            const data = await response.json();

            if (data.success) {
                // Update local settings
                Object.assign(timeSettings, settings);
                if (typeof showToast === 'function') {
                    showToast('Time settings saved', 'success');
                }
                return true;
            } else {
                if (typeof showToast === 'function') {
                    showToast('Failed to save time settings: ' + (data.error || 'Unknown error'), 'error');
                }
                return false;
            }
        } catch (error) {
            console.error('Error saving time settings:', error);
            if (typeof showToast === 'function') {
                showToast('Error saving time settings', 'error');
            }
            return false;
        }
    }

    /**
     * Get current time settings
     */
    function getTimeSettings() {
        return { ...timeSettings };
    }

    /**
     * Get the effective timezone (resolves 'Local' to browser's timezone)
     * @returns {string} The timezone identifier to use
     */
    function getEffectiveTimezone() {
        if (timeSettings.timezone === 'Local') {
            // Get the browser's local timezone
            return Intl.DateTimeFormat().resolvedOptions().timeZone;
        }
        return timeSettings.timezone;
    }

    /**
     * Get user's local timezone name (for display purposes)
     * @returns {string} The browser's local timezone identifier
     */
    function getBrowserTimezone() {
        return Intl.DateTimeFormat().resolvedOptions().timeZone;
    }

    /**
     * Format a date/time according to user's settings
     * @param {string|Date} dateInput - Date string or Date object (assumed UTC if no timezone)
     * @param {string} format - 'time', 'date', 'datetime', or custom format
     * @returns {string} Formatted date/time string
     */
    function formatDateTime(dateInput, format = 'datetime') {
        if (!dateInput) return 'N/A';

        let date;
        if (dateInput instanceof Date) {
            date = dateInput;
        } else {
            // If the string doesn't have timezone info, treat it as UTC
            let dateStr = String(dateInput);
            if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.includes('-', 10)) {
                dateStr += 'Z';  // Append Z to indicate UTC
            }
            date = new Date(dateStr);
        }

        if (isNaN(date.getTime())) return 'Invalid Date';

        // Convert to user's timezone (resolve 'Local' to actual browser timezone)
        const effectiveTz = getEffectiveTimezone();
        const options = { timeZone: effectiveTz };

        try {
            // Get parts in the target timezone
            const formatter = new Intl.DateTimeFormat('en-US', {
                ...options,
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: timeSettings.time_format === '12h'
            });

            const parts = formatter.formatToParts(date);
            const partMap = {};
            parts.forEach(p => {
                partMap[p.type] = p.value;
            });

            const year = partMap.year;
            const month = partMap.month;
            const day = partMap.day;
            const hour = partMap.hour;
            const minute = partMap.minute;
            const second = partMap.second;
            const dayPeriod = partMap.dayPeriod || '';

            // Format based on requested format type
            if (format === 'time') {
                if (timeSettings.time_format === '12h') {
                    return `${hour}:${minute} ${dayPeriod}`;
                } else {
                    return `${hour}:${minute}`;
                }
            } else if (format === 'date') {
                return formatDatePart(year, month, day);
            } else if (format === 'datetime' || format === 'full') {
                const datePart = formatDatePart(year, month, day);
                if (timeSettings.time_format === '12h') {
                    return `${datePart} ${hour}:${minute}:${second} ${dayPeriod}`;
                } else {
                    return `${datePart} ${hour}:${minute}:${second}`;
                }
            } else if (format === 'short') {
                const datePart = formatDatePart(year, month, day);
                if (timeSettings.time_format === '12h') {
                    return `${datePart} ${hour}:${minute} ${dayPeriod}`;
                } else {
                    return `${datePart} ${hour}:${minute}`;
                }
            } else {
                // Custom format - use datetime_format setting
                return formatCustom(date, timeSettings.datetime_format);
            }
        } catch (error) {
            console.error('Error formatting date:', error);
            return date.toLocaleString();
        }
    }

    /**
     * Format date part based on user's date_format setting
     */
    function formatDatePart(year, month, day) {
        switch (timeSettings.date_format) {
            case 'DD/MM/YYYY':
                return `${day}/${month}/${year}`;
            case 'MM/DD/YYYY':
                return `${month}/${day}/${year}`;
            case 'DD-MM-YYYY':
                return `${day}-${month}-${year}`;
            case 'YYYY-MM-DD':
            default:
                return `${year}-${month}-${day}`;
        }
    }

    /**
     * Format using custom format string
     */
    function formatCustom(date, formatStr) {
        const effectiveTz = getEffectiveTimezone();
        const options = { timeZone: effectiveTz };
        const formatter = new Intl.DateTimeFormat('en-US', {
            ...options,
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });

        const parts = formatter.formatToParts(date);
        const partMap = {};
        parts.forEach(p => {
            partMap[p.type] = p.value;
        });

        return formatStr
            .replace('YYYY', partMap.year)
            .replace('MM', partMap.month)
            .replace('DD', partMap.day)
            .replace('HH', partMap.hour)
            .replace('mm', partMap.minute)
            .replace('ss', partMap.second);
    }

    /**
     * Get relative time (e.g., "5 minutes ago")
     */
    function getRelativeTime(dateInput) {
        if (!dateInput) return 'N/A';

        let date;
        if (dateInput instanceof Date) {
            date = dateInput;
        } else {
            // If the string doesn't have timezone info, treat it as UTC
            let dateStr = String(dateInput);
            if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.includes('-', 10)) {
                dateStr += 'Z';  // Append Z to indicate UTC
            }
            date = new Date(dateStr);
        }
        if (isNaN(date.getTime())) return 'Invalid Date';

        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);

        if (diffSec < 60) return 'Just now';
        if (diffMin < 60) return `${diffMin} minute${diffMin !== 1 ? 's' : ''} ago`;
        if (diffHour < 24) return `${diffHour} hour${diffHour !== 1 ? 's' : ''} ago`;
        if (diffDay < 7) return `${diffDay} day${diffDay !== 1 ? 's' : ''} ago`;

        return formatDateTime(date, 'date');
    }

    // Export functions globally
    window.TimeSettings = {
        load: loadTimeSettings,
        reload: () => loadTimeSettings(true),  // Force reload from server
        save: saveTimeSettings,
        get: getTimeSettings,
        format: formatDateTime,
        formatDate: (d) => formatDateTime(d, 'date'),
        formatTime: (d) => formatDateTime(d, 'time'),
        formatShort: (d) => formatDateTime(d, 'short'),
        formatFull: (d) => formatDateTime(d, 'datetime'),
        relative: getRelativeTime,
        isLoaded: () => settingsLoaded,
        getEffectiveTimezone: getEffectiveTimezone,  // Resolves 'Local' to actual TZ
        getBrowserTimezone: getBrowserTimezone       // Gets browser's local timezone
    };

    // Auto-load settings when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadTimeSettings);
    } else {
        loadTimeSettings();
    }

})();
