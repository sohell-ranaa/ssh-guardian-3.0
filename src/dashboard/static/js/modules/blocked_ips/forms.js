/**
 * Blocked IPs - Forms Module
 * Manual block/unblock forms and form toggles
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};

    BlockedIPs.Forms = {
        /**
         * Setup all forms
         */
        setupAll() {
            this.setupFormToggles();
            this.setupManualBlockForm();
            this.setupManualUnblockForm();
            this.setupRefreshButton();
        },

        /**
         * Setup form section toggles
         */
        setupFormToggles() {
            const toggles = document.querySelectorAll('[data-toggle-form]');
            toggles.forEach(toggle => {
                toggle.addEventListener('click', () => {
                    const formId = toggle.dataset.toggleForm;
                    const formSection = document.getElementById(formId);
                    if (formSection) {
                        const isVisible = formSection.style.display !== 'none';
                        formSection.style.display = isVisible ? 'none' : 'block';
                        toggle.classList.toggle('active', !isVisible);
                    }
                });
            });
        },

        /**
         * Setup manual block form
         */
        setupManualBlockForm() {
            const form = document.getElementById('manualBlockForm');
            if (!form) return;

            form.addEventListener('submit', async (e) => {
                e.preventDefault();

                const ipInput = document.getElementById('blockIpAddress');
                const reasonInput = document.getElementById('blockReason');
                const durationSelect = document.getElementById('blockDuration');
                const agentSelect = document.getElementById('blockAgentFilter');
                const submitBtn = form.querySelector('button[type="submit"]');

                const ip = ipInput?.value?.trim();
                const reason = reasonInput?.value?.trim() || 'Manual block from dashboard';
                const duration = parseInt(durationSelect?.value) || 0;
                const agentId = agentSelect?.value || null;

                if (!ip) {
                    BlockedIPs.UI.notify('Please enter an IP address', 'error');
                    return;
                }

                // Validate IP format
                if (!window.isValidIPv4 || !window.isValidIPv4(ip)) {
                    BlockedIPs.UI.notify('Invalid IP address format', 'error');
                    return;
                }

                try {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Blocking...';

                    const payload = {
                        ip_address: ip,
                        reason: reason,
                        duration_hours: duration || null
                    };

                    if (agentId) {
                        payload.agent_id = agentId;
                    }

                    const response = await fetch('/api/dashboard/blocking/blocks/manual', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });

                    const data = await response.json();

                    if (data.success) {
                        BlockedIPs.UI.notify(`IP ${ip} has been blocked`, 'success');
                        form.reset();
                        BlockedIPs.Core.loadIPBlocks();
                    } else {
                        BlockedIPs.UI.notify(`Failed to block IP: ${data.error || 'Unknown error'}`, 'error');
                    }
                } catch (error) {
                    console.error('Error blocking IP:', error);
                    BlockedIPs.UI.notify(`Error blocking IP: ${error.message}`, 'error');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Block IP';
                }
            });
        },

        /**
         * Setup manual unblock form
         */
        setupManualUnblockForm() {
            const form = document.getElementById('manualUnblockForm');
            if (!form) return;

            form.addEventListener('submit', async (e) => {
                e.preventDefault();

                const ipInput = document.getElementById('unblockIpAddress');
                const reasonInput = document.getElementById('unblockReason');
                const submitBtn = form.querySelector('button[type="submit"]');

                const ip = ipInput?.value?.trim();
                const reason = reasonInput?.value?.trim() || 'Manual unblock from dashboard';

                if (!ip) {
                    BlockedIPs.UI.notify('Please enter an IP address', 'error');
                    return;
                }

                try {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Unblocking...';

                    const response = await fetch('/api/dashboard/blocking/blocks/unblock', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            ip_address: ip,
                            reason: reason
                        })
                    });

                    const data = await response.json();

                    if (data.success) {
                        BlockedIPs.UI.notify(`IP ${ip} has been unblocked`, 'success');
                        form.reset();
                        BlockedIPs.Core.loadIPBlocks();
                    } else {
                        BlockedIPs.UI.notify(`Failed to unblock IP: ${data.error || 'Unknown error'}`, 'error');
                    }
                } catch (error) {
                    console.error('Error unblocking IP:', error);
                    BlockedIPs.UI.notify(`Error unblocking IP: ${error.message}`, 'error');
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Unblock IP';
                }
            });
        },

        /**
         * Setup refresh button
         */
        setupRefreshButton() {
            const refreshBtn = document.getElementById('refreshBlocksBtn');
            if (!refreshBtn) return;

            refreshBtn.addEventListener('click', () => {
                BlockedIPs.Core.loadIPBlocks();
            });
        }
    };
})();
