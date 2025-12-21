/**
 * Blocked IPs Module - Entry Point
 * Modular structure for IP blocking management
 *
 * Sub-modules:
 * - core.js: Data loading and table rendering
 * - actions.js: Block/unblock operations
 * - filters.js: Search and filter functionality
 * - forms.js: Manual block/unblock forms
 * - modal.js: IP details modal
 * - ui.js: UI helpers and notifications
 */

(function() {
    'use strict';

    // Create namespace
    window.BlockedIPs = window.BlockedIPs || {};

    // Module state
    BlockedIPs.state = {
        currentAgentFilter: '',
        blocks: [],
        agents: []
    };

    // Main page loader - called from HTML
    window.loadBlockedIPsPage = async function() {
        try {
            await BlockedIPs.Filters.loadAgentsForDropdown();
            await BlockedIPs.Core.loadIPBlocks();
            BlockedIPs.Filters.setupAll();
            BlockedIPs.Forms.setupAll();
        } catch (error) {
            console.error('Error loading Blocked IPs page:', error);
        }
    };

    // Re-export commonly used functions to window for backward compatibility
    window.showBlockIpDetails = (ip) => BlockedIPs.Modal.showDetails(ip);
    window.unblockIPFromTable = (ip, id) => BlockedIPs.Actions.unblock(ip, id);
    window.reblockIPFromTable = (ip) => BlockedIPs.Actions.reblock(ip);
    window.disableBlockFromTable = (ip, id) => BlockedIPs.Actions.disable(ip, id);
    window.confirmDeleteBlock = (ip, id) => BlockedIPs.Actions.confirmDelete(ip, id);

})();
