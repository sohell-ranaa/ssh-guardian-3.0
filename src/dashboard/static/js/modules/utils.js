/**
 * SSH Guardian v3.0 - Global Utilities
 * Common functions used across the dashboard
 * - Date/time formatting with timezone support (uses TimeSettings)
 * - Theme colors access
 * - HTML escaping for XSS prevention
 */

/**
 * Parse timestamp - server timestamps are in +08:00 if no timezone info
 */
function parseTimestamp(dateString) {
    if (!dateString) return null;
    let ts = String(dateString).replace(' ', 'T');
    // Add server timezone if no timezone info
    if (!ts.endsWith('Z') && !ts.includes('+') && !ts.match(/-\d{2}:\d{2}$/)) {
        ts += '+08:00';
    }
    return new Date(ts);
}

/**
 * Format date to user's timezone with full datetime
 * Uses TimeSettings if available, otherwise browser's native timezone
 */
function formatLocalDateTime(dateString) {
    if (!dateString) return 'N/A';

    // Use TimeSettings if available
    if (window.TimeSettings?.isLoaded()) {
        return window.TimeSettings.formatFull(dateString);
    }

    // Fallback: browser's native timezone
    const date = parseTimestamp(dateString);
    if (!date || isNaN(date.getTime())) return 'Invalid Date';

    return date.toLocaleString();
}

/**
 * Format date to user's timezone (date only)
 */
function formatLocalDate(dateString) {
    if (!dateString) return 'N/A';

    if (window.TimeSettings?.isLoaded()) {
        return window.TimeSettings.formatDate(dateString);
    }

    // Fallback: browser's native timezone
    const date = parseTimestamp(dateString);
    if (!date || isNaN(date.getTime())) return 'Invalid Date';

    return date.toLocaleDateString();
}

/**
 * Format time only
 */
function formatLocalTime(dateString) {
    if (!dateString) return 'N/A';

    if (window.TimeSettings?.isLoaded()) {
        return window.TimeSettings.formatTime(dateString);
    }

    // Fallback: browser's native timezone
    const date = parseTimestamp(dateString);
    if (!date || isNaN(date.getTime())) return 'Invalid Date';

    return date.toLocaleTimeString();
}

/**
 * Get current timezone info
 */
function getLocalTimezoneInfo() {
    if (window.TimeSettings?.isLoaded()) {
        const tz = window.TimeSettings.getEffectiveTimezone();
        return { timezone: tz, formatted: tz };
    }
    // Fallback: browser's timezone
    const browserTz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    return { timezone: browserTz, formatted: browserTz };
}

/**
 * Theme Colors Utility
 * Use CSS variables for consistent theming in JS
 */
const ThemeColors = {
    // Helper to get CSS variable value
    _get(name, fallback) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
    },

    // Brand colors
    get primary() { return this._get('--azure-blue', '#0078D4'); },
    get primaryDark() { return this._get('--azure-dark', '#004C87'); },
    get primaryHover() { return this._get('--azure-hover', '#106EBE'); },

    // Semantic colors
    get success() { return this._get('--color-success', '#2EA44F'); },
    get successDark() { return this._get('--color-success-dark', '#107C10'); },
    get successLight() { return this._get('--color-success-light', '#10b981'); },
    get danger() { return this._get('--color-danger', '#D13438'); },
    get dangerDark() { return this._get('--color-danger-dark', '#A80000'); },
    get warning() { return this._get('--color-warning', '#E6A502'); },
    get warningDark() { return this._get('--color-warning-dark', '#CC9400'); },
    get info() { return this._get('--color-info', '#0078D4'); },
    get muted() { return this._get('--color-muted', '#605E5C'); },

    // Extended palette
    get orange() { return this._get('--color-orange', '#FF8C00'); },
    get orangeDark() { return this._get('--color-orange-dark', '#D83B01'); },
    get purple() { return this._get('--color-purple', '#8764B8'); },
    get purpleDark() { return this._get('--color-purple-dark', '#5C2D91'); },
    get gold() { return this._get('--color-gold', '#FFB900'); },
    get pink() { return this._get('--color-pink', '#C239B3'); },

    // Text colors
    get textPrimary() { return this._get('--text-primary', '#323130'); },
    get textSecondary() { return this._get('--text-secondary', '#605E5C'); },
    get textTertiary() { return this._get('--text-tertiary', '#8A8886'); },
    get textHint() { return this._get('--text-hint', '#A19F9D'); },

    // Surface colors
    get surface() { return this._get('--surface', '#FFFFFF'); },
    get surfaceAlt() { return this._get('--surface-alt', '#F9F9F8'); },
    get background() { return this._get('--background', '#F3F2F1'); },
    get border() { return this._get('--border', '#EDEBE9'); },
    get borderLight() { return this._get('--border-light', '#E8E6E3'); }
};

// Shorthand alias
window.TC = ThemeColors;
window.ThemeColors = ThemeColors;

/**
 * HTML Escape Utility
 * Prevents XSS by escaping HTML special characters
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const str = String(text);
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return str.replace(/[&<>"']/g, m => map[m]);
}

window.escapeHtml = escapeHtml;
window.parseTimestamp = parseTimestamp;
window.formatLocalDateTime = formatLocalDateTime;
window.formatLocalDate = formatLocalDate;
window.formatLocalTime = formatLocalTime;
window.getLocalTimezoneInfo = getLocalTimezoneInfo;

/**
 * Format Time Ago Utility
 * Converts a date string to a human-readable "time ago" format
 */
function formatTimeAgo(dateStr) {
    if (!dateStr) return 'Unknown';
    // Use TimeSettings for proper timezone handling if available
    if (window.TimeSettings?.isLoaded()) {
        return window.TimeSettings.relative(dateStr);
    }
    // Fallback: Server timestamps are in server timezone (+08:00)
    let str = String(dateStr).replace(' ', 'T');
    if (!str.endsWith('Z') && !str.includes('+') && !str.match(/T\d{2}:\d{2}:\d{2}-/)) {
        str += '+08:00';
    }
    const date = new Date(str);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);

    if (diff < 0) return 'Just now';
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return date.toLocaleDateString();
}

window.formatTimeAgo = formatTimeAgo;

/**
 * Format Future Time Utility
 * Converts a future date string to human-readable format
 */
function formatFutureTime(dateStr) {
    if (!dateStr) return 'Unknown';
    // Server timestamps are in server timezone (+08:00)
    let str = String(dateStr).replace(' ', 'T');
    if (!str.endsWith('Z') && !str.includes('+') && !str.match(/T\d{2}:\d{2}:\d{2}-/)) {
        str += '+08:00';
    }
    const date = new Date(str);
    const now = new Date();
    const diff = Math.floor((date - now) / 1000);

    if (diff < 0) return 'Expired';
    if (diff < 60) return 'in less than a minute';
    if (diff < 3600) return `in ${Math.floor(diff / 60)}m`;
    if (diff < 86400) return `in ${Math.floor(diff / 3600)}h`;
    if (diff < 604800) return `in ${Math.floor(diff / 86400)} days`;
    return date.toLocaleDateString();
}

window.formatFutureTime = formatFutureTime;

// Toast functions are provided by toast.js
// Fallback if toast.js not loaded
if (typeof window.showToast !== 'function') {
    window.showToast = function(message, type = 'info') {
        console.log(`[${type.toUpperCase()}] ${message}`);
    };
    window.showNotification = window.showToast;
}

/**
 * IP Validation Utilities
 */
function isPrivateIP(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    const first = parseInt(parts[0]);
    const second = parseInt(parts[1]);
    return first === 10 || first === 127 ||
           (first === 172 && second >= 16 && second <= 31) ||
           (first === 192 && second === 168);
}

function isValidIPv4(ip) {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
        const num = parseInt(part, 10);
        return !isNaN(num) && num >= 0 && num <= 255 && part === num.toString();
    });
}

window.isPrivateIP = isPrivateIP;
window.isValidIPv4 = isValidIPv4;

/**
 * Fetch with Timeout Utility
 * Wrapper for fetch with configurable timeout
 */
async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return response;
    } catch (e) {
        clearTimeout(timeoutId);
        throw e;
    }
}

window.fetchWithTimeout = fetchWithTimeout;

/**
 * Get Score Class Utility
 * Returns CSS class based on risk score
 */
function getScoreClass(score) {
    const numScore = parseInt(score) || 0;
    if (numScore >= 80) return 'critical';
    if (numScore >= 60) return 'high';
    if (numScore >= 40) return 'moderate';
    return 'low';
}

window.getScoreClass = getScoreClass;

/**
 * Format large numbers with K/M suffixes
 * @param {number|string} num - The number to format
 * @returns {string} - Formatted number string
 */
function formatNumber(num) {
    if (num === '--' || num === undefined || num === null) return '--';
    const n = parseInt(num);
    if (isNaN(n)) return String(num);
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n.toLocaleString();
}

window.formatNumber = formatNumber;

/**
 * Password Toggle Utility
 * Creates a show/hide toggle for password fields
 * Shows password while holding the button, hides on release
 *
 * Usage:
 *   // Single input
 *   PasswordToggle.wrap(document.getElementById('my-password'));
 *
 *   // All password inputs in a container
 *   PasswordToggle.wrapAll(document.getElementById('my-form'));
 *
 *   // Create input with toggle (returns wrapper element)
 *   const wrapper = PasswordToggle.createInput({ id: 'password', placeholder: 'Enter password' });
 *
 * CSS classes added:
 *   .password-wrapper - Container for input + toggle button
 *   .password-toggle-btn - The toggle button
 *   .password-toggle-icon - Icon inside the button
 */
const PasswordToggle = {
    // Eye icons (SVG)
    icons: {
        hidden: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
            <line x1="1" y1="1" x2="23" y2="23"/>
        </svg>`,
        visible: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
            <circle cx="12" cy="12" r="3"/>
        </svg>`
    },

    /**
     * Inject CSS styles if not already present
     */
    injectStyles() {
        if (document.getElementById('password-toggle-styles')) return;

        const style = document.createElement('style');
        style.id = 'password-toggle-styles';
        style.textContent = `
            .password-wrapper {
                position: relative;
                display: flex;
                align-items: center;
                width: 100%;
            }
            .password-wrapper input {
                padding-right: 40px !important;
                width: 100%;
            }
            .password-toggle-btn {
                position: absolute;
                right: 8px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                cursor: pointer;
                padding: 4px;
                display: flex;
                align-items: center;
                justify-content: center;
                color: var(--text-secondary, #605E5C);
                border-radius: 4px;
                transition: color 0.15s, background 0.15s;
                user-select: none;
                -webkit-user-select: none;
            }
            .password-toggle-btn:hover {
                color: var(--text-primary, #323130);
                background: var(--background, #F3F2F1);
            }
            .password-toggle-btn:active {
                color: var(--azure-blue, #0078D4);
                background: var(--azure-bg, #E6F4FF);
            }
            .password-toggle-btn:focus {
                outline: none;
            }
            .password-toggle-icon {
                display: flex;
                align-items: center;
                justify-content: center;
            }
            /* For inputs with left icons (like login page) */
            .input-wrapper.password-wrapper input {
                padding-right: 40px !important;
            }
        `;
        document.head.appendChild(style);
    },

    /**
     * Create toggle button element
     */
    createToggleButton() {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'password-toggle-btn';
        btn.title = 'Hold to show password';
        btn.innerHTML = `<span class="password-toggle-icon">${this.icons.hidden}</span>`;
        return btn;
    },

    /**
     * Wrap an existing password input with toggle functionality
     * @param {HTMLInputElement} input - The password input element
     * @returns {HTMLElement} - The wrapper element
     */
    wrap(input) {
        if (!input || input.type !== 'password') return null;
        if (input.parentElement?.classList.contains('password-wrapper')) return input.parentElement;

        this.injectStyles();

        // Create wrapper
        const wrapper = document.createElement('div');
        wrapper.className = 'password-wrapper';

        // Check if input is inside an input-wrapper (like login page)
        const parentWrapper = input.parentElement;
        if (parentWrapper?.classList.contains('input-wrapper')) {
            parentWrapper.classList.add('password-wrapper');
            const btn = this.createToggleButton();
            this.attachToggleEvents(btn, input);
            parentWrapper.appendChild(btn);
            return parentWrapper;
        }

        // Standard wrapping
        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        const btn = this.createToggleButton();
        this.attachToggleEvents(btn, input);
        wrapper.appendChild(btn);

        return wrapper;
    },

    /**
     * Attach mouse/touch events to toggle button
     */
    attachToggleEvents(btn, input) {
        const icon = btn.querySelector('.password-toggle-icon');

        const showPassword = () => {
            input.type = 'text';
            icon.innerHTML = this.icons.visible;
        };

        const hidePassword = () => {
            input.type = 'password';
            icon.innerHTML = this.icons.hidden;
        };

        // Mouse events
        btn.addEventListener('mousedown', (e) => {
            e.preventDefault();
            showPassword();
        });
        btn.addEventListener('mouseup', hidePassword);
        btn.addEventListener('mouseleave', hidePassword);

        // Touch events for mobile
        btn.addEventListener('touchstart', (e) => {
            e.preventDefault();
            showPassword();
        });
        btn.addEventListener('touchend', hidePassword);
        btn.addEventListener('touchcancel', hidePassword);

        // Prevent form submission on Enter while focused on button
        btn.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
            }
        });
    },

    /**
     * Wrap all password inputs in a container
     * @param {HTMLElement} container - Container element (form, div, etc.)
     */
    wrapAll(container) {
        if (!container) return;
        const inputs = container.querySelectorAll('input[type="password"]');
        inputs.forEach(input => this.wrap(input));
    },

    /**
     * Create a new password input with toggle built-in
     * @param {Object} options - Input attributes (id, name, placeholder, value, required, style, className)
     * @returns {HTMLElement} - The wrapper element containing input and toggle
     */
    createInput(options = {}) {
        this.injectStyles();

        const wrapper = document.createElement('div');
        wrapper.className = 'password-wrapper';

        const input = document.createElement('input');
        input.type = 'password';
        if (options.id) input.id = options.id;
        if (options.name) input.name = options.name;
        if (options.placeholder) input.placeholder = options.placeholder;
        if (options.value) input.value = options.value;
        if (options.required) input.required = true;
        if (options.style) input.style.cssText = options.style;
        if (options.className) input.className = options.className;

        wrapper.appendChild(input);

        const btn = this.createToggleButton();
        this.attachToggleEvents(btn, input);
        wrapper.appendChild(btn);

        return wrapper;
    },

    /**
     * Initialize all password inputs on page load
     * Call this after DOM content is loaded
     */
    initAll() {
        this.wrapAll(document.body);
    }
};

window.PasswordToggle = PasswordToggle;

/**
 * Hard Reload Utility
 * Provides a button component for performing hard page reloads (clearing cache)
 *
 * Usage:
 *   // Create and append button to a container
 *   const btn = HardReload.createButton();
 *   document.getElementById('my-container').appendChild(btn);
 *
 *   // Or initialize in a specific container (auto-finds element with data-hard-reload)
 *   HardReload.init();
 *
 *   // Programmatic hard reload
 *   HardReload.reload();
 */
const HardReload = {
    // Reload icon (SVG - circular arrow)
    icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M23 4v6h-6"/>
        <path d="M1 20v-6h6"/>
        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
    </svg>`,

    // Spinning animation icon
    spinIcon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="hard-reload-spin">
        <path d="M23 4v6h-6"/>
        <path d="M1 20v-6h6"/>
        <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
    </svg>`,

    /**
     * Inject CSS styles if not already present
     */
    injectStyles() {
        if (document.getElementById('hard-reload-styles')) return;

        const style = document.createElement('style');
        style.id = 'hard-reload-styles';
        style.textContent = `
            .hard-reload-btn {
                width: 36px;
                height: 36px;
                border: none;
                background: transparent;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 4px;
                color: var(--text-secondary, #605E5C);
                transition: background 0.15s, color 0.15s, transform 0.15s;
            }
            .hard-reload-btn:hover {
                background: var(--background, #F3F2F1);
                color: var(--text-primary, #323130);
            }
            .hard-reload-btn:active {
                transform: scale(0.95);
            }
            .hard-reload-btn:focus {
                outline: none;
                box-shadow: 0 0 0 2px var(--azure-blue, #0078D4);
            }
            .hard-reload-btn.reloading {
                pointer-events: none;
                color: var(--azure-blue, #0078D4);
            }
            .hard-reload-btn svg {
                display: block;
            }
            @keyframes hard-reload-spin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            .hard-reload-spin {
                animation: hard-reload-spin 0.8s linear infinite;
            }
        `;
        document.head.appendChild(style);
    },

    /**
     * Perform a hard reload (bypass cache) - clears both browser and server cache
     */
    reload() {
        // 1. Clear localStorage cache (Overview module cache)
        const cacheKeys = [
            'overview_thesis_content', 'overview_thesis_cached_at',
            'overview_guide_content', 'overview_guide_cached_at'
        ];
        cacheKeys.forEach(key => localStorage.removeItem(key));

        // 2. Clear sessionStorage
        sessionStorage.clear();

        // 3. Clear service worker caches if available
        if ('caches' in window) {
            caches.keys().then(names => {
                names.forEach(name => caches.delete(name));
            });
        }

        // 4. Clear server-side Redis cache
        fetch('/api/dashboard/system/cache/clear', { method: 'POST' })
            .catch(() => {}) // Ignore errors, continue with reload
            .finally(() => {
                // Hard reload - bypass cache
                window.location.reload(true);
            });
    },

    /**
     * Create the reload button element
     * @param {Object} options - Optional configuration
     * @param {string} options.title - Button tooltip (default: "Hard Reload (Clear Cache)")
     * @param {string} options.className - Additional CSS classes
     * @returns {HTMLButtonElement} - The button element
     */
    createButton(options = {}) {
        this.injectStyles();

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'hard-reload-btn' + (options.className ? ' ' + options.className : '');
        btn.title = options.title || 'Hard Reload (Clear Cache)';
        btn.innerHTML = this.icon;

        btn.addEventListener('click', () => {
            // Show spinning animation
            btn.classList.add('reloading');
            btn.innerHTML = this.spinIcon;

            // Short delay to show animation, then reload
            setTimeout(() => {
                this.reload();
            }, 300);
        });

        return btn;
    },

    /**
     * Initialize hard reload button in container with data-hard-reload attribute
     * or in a specified container
     * @param {HTMLElement|string} container - Container element or selector (optional)
     */
    init(container) {
        let target;

        if (container) {
            target = typeof container === 'string' ? document.querySelector(container) : container;
        } else {
            target = document.querySelector('[data-hard-reload]');
        }

        if (target && !target.querySelector('.hard-reload-btn')) {
            const btn = this.createButton();
            target.appendChild(btn);
        }
    }
};

window.HardReload = HardReload;
