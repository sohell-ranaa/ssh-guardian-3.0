/**
 * SSH Guardian v3.0 - Firewall UFW Sync Indicator
 * UFW sync indicator utilities
 */
(function() {
    'use strict';

    function showUFWSyncIndicator(text = 'Syncing...') {
        const indicator = document.getElementById('ufwSyncIndicator');
        const textEl = indicator?.querySelector('.ufw-sync-text');
        if (indicator) {
            indicator.style.display = 'inline-flex';
            if (textEl) textEl.textContent = text;
        }
    }

    function hideUFWSyncIndicator() {
        const indicator = document.getElementById('ufwSyncIndicator');
        if (indicator) {
            indicator.style.display = 'none';
        }
    }

    function updateUFWSyncText(text) {
        const indicator = document.getElementById('ufwSyncIndicator');
        const textEl = indicator?.querySelector('.ufw-sync-text');
        if (textEl) textEl.textContent = text;
    }

    function updateUFWRuleCount(count) {
        const countEl = document.getElementById('ufwRuleCount');
        if (countEl) {
            countEl.textContent = `${count} rule${count !== 1 ? 's' : ''}`;
        }
    }

    // Global exports
    window.showUFWSyncIndicator = showUFWSyncIndicator;
    window.hideUFWSyncIndicator = hideUFWSyncIndicator;
    window.updateUFWSyncText = updateUFWSyncText;
    window.updateUFWRuleCount = updateUFWRuleCount;
})();
