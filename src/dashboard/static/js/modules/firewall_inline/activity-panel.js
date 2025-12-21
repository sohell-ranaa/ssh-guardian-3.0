/**
 * SSH Guardian v3.0 - Firewall Inline Activity Panel
 * Recent Activity Slide Panel functionality
 */
(function() {
    'use strict';

    function toggleRecentActivityPanel(event) {
        if (event) {
            event.stopPropagation();
        }
        const panel = document.getElementById('recentActivityPanel');
        const backdrop = document.getElementById('recentActivityBackdrop');

        if (panel.classList.contains('open')) {
            closeRecentActivityPanel();
        } else {
            panel.classList.add('open');
            backdrop.classList.add('open');
            // Use window.currentAgentId from the module's global variable
            if (window.currentAgentId) {
                loadRecentLogs(window.currentAgentId);
            }
        }
    }

    function closeRecentActivityPanel() {
        const panel = document.getElementById('recentActivityPanel');
        const backdrop = document.getElementById('recentActivityBackdrop');
        if (panel) panel.classList.remove('open');
        if (backdrop) backdrop.classList.remove('open');
    }

    // filterRecentLogs - reload logs when filter changes
    function filterRecentLogs() {
        if (window.currentAgentId) {
            loadRecentLogs(window.currentAgentId);
        }
    }

    // Global exports
    window.toggleRecentActivityPanel = toggleRecentActivityPanel;
    window.closeRecentActivityPanel = closeRecentActivityPanel;
    window.filterRecentLogs = filterRecentLogs;
})();
