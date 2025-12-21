/**
 * SSH Guardian v3.0 - Firewall Inline Index
 * Module initialization and global exports
 */
(function() {
    'use strict';

    // Module version
    window._fwInlineVersion = '3.0.58';

    // Log initialization
    console.log('[Firewall Inline] Modular version loaded');

    // Note: All functions are exported by their respective modules
    // - tabs.js: switchFirewallTab
    // - activity-panel.js: toggleRecentActivityPanel, closeRecentActivityPanel, filterRecentLogs
    // - blocked-ips.js: loadBlockedIPs, filterBlockedIPs, searchBlockedIPs, unblockIP, reconcileBlockedIPs
    // - block-detail.js: showRealBlockDetail
    // - block-modal.js: showBlockIPModal, closeBlockIPModal, quickBlockIP
    // - logins.js: loadSuccessfulLoginsFirewall, showLoginDetailModalFW

    // Additional exports for backward compatibility
    window.showBlockedIPDetailModal = window.showRealBlockDetail;
})();
