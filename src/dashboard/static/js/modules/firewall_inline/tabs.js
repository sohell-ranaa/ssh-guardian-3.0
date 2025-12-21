/**
 * SSH Guardian v3.0 - Firewall Inline Tabs
 * Tab switching functionality
 */
(function() {
    'use strict';

    function switchFirewallTab(tabName) {
        // Hide all tab contents and remove active class
        document.querySelectorAll('.fw-tab-content').forEach(tab => tab.style.display = 'none');
        document.querySelectorAll('.fw-tab').forEach(tab => tab.classList.remove('active'));

        // Show selected tab content
        const tabContent = document.getElementById('tab-' + tabName);
        if (tabContent) tabContent.style.display = 'block';

        // Add active class to selected tab
        const tabButton = document.querySelector(`.fw-tab[data-tab="${tabName}"]`);
        if (tabButton) tabButton.classList.add('active');

        // Load data for specific tabs
        if (tabName === 'fail2ban') {
            (window.loadFail2banBans || loadFail2banBans)?.();
        } else if (tabName === 'blocked') {
            loadBlockedIPs?.();
        } else if (tabName === 'rules') {
            loadBlockingRules?.();
        } else if (tabName === 'logins') {
            (window.loadSuccessfulLoginsFirewall || loadSuccessfulLoginsFirewall)?.();
        } else if (tabName === 'ufw' && window.currentAgentId) {
            (window.loadUFWData || loadUFWData)?.(window.currentAgentId);
        }
    }

    // Global export
    window.switchFirewallTab = switchFirewallTab;
})();
