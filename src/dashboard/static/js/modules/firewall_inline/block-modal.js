/**
 * SSH Guardian v3.0 - Firewall Inline Block Modal
 * Block IP modal functionality
 */
(function() {
    'use strict';

    function showBlockIPModal(prefillIp = '', prefillAgentId = '', prefillAgentName = '') {
        const modal = document.getElementById('blockIPModal');
        if (modal) modal.style.display = 'flex';

        // Reset and setup octet inputs
        setIPToOctets(prefillIp);
        setupIPOctetInputs();

        // Reset container border
        const container = document.getElementById('ipInputContainer');
        if (container) container.style.borderColor = 'var(--border)';

        // Update hidden field and validate if prefilled
        const ipInput = document.getElementById('quickBlockIP');
        if (prefillIp) {
            if (ipInput) ipInput.value = prefillIp;
            updateIPContainerState();
        } else {
            if (ipInput) ipInput.value = '';
        }

        const reasonInput = document.getElementById('quickBlockReason');
        const messageEl = document.getElementById('quickBlockMessage');
        if (reasonInput) reasonInput.value = '';
        if (messageEl) messageEl.style.display = 'none';

        // Focus first octet
        setTimeout(() => document.getElementById('ipOctet1')?.focus(), 100);

        // Set agent from context
        const agentIdInput = document.getElementById('quickBlockAgentId');
        const agentDisplay = document.getElementById('quickBlockAgentDisplay');

        // Priority: 1) Passed parameters, 2) Page selector, 3) window.currentAgentId
        if (prefillAgentId && prefillAgentName) {
            agentIdInput.value = prefillAgentId;
            agentDisplay.textContent = prefillAgentName;
        } else {
            // Try page's agent selector
            const pageAgentSelector = document.getElementById('firewallAgentSelector');
            if (pageAgentSelector && pageAgentSelector.value) {
                agentIdInput.value = pageAgentSelector.value;
                const selectedOption = pageAgentSelector.options[pageAgentSelector.selectedIndex];
                agentDisplay.textContent = selectedOption ? selectedOption.text : pageAgentSelector.value;
            } else if (window.currentAgentId) {
                // Use global currentAgentId
                agentIdInput.value = window.currentAgentId;
                // Try to get agent name from cached agents or fetch
                if (window.cachedAgents && window.cachedAgents.length > 0) {
                    const agent = window.cachedAgents.find(a => a.agent_id === window.currentAgentId || a.id == window.currentAgentId);
                    agentDisplay.textContent = agent ? (agent.display_name || agent.hostname || agent.agent_id) : window.currentAgentId;
                } else {
                    // Fetch agent info
                    fetch('/api/agents/list')
                        .then(r => r.json())
                        .then(data => {
                            if (data.success && data.agents) {
                                window.cachedAgents = data.agents;
                                const agent = data.agents.find(a => a.agent_id === window.currentAgentId || a.id == window.currentAgentId);
                                agentDisplay.textContent = agent ? (agent.display_name || agent.hostname || agent.agent_id) : window.currentAgentId;
                            }
                        })
                        .catch(() => {
                            agentDisplay.textContent = window.currentAgentId;
                        });
                    agentDisplay.textContent = 'Loading...';
                }
            } else {
                // No agent selected - try to get first available
                agentIdInput.value = '';
                agentDisplay.textContent = 'Loading...';
                fetch('/api/agents/list')
                    .then(r => r.json())
                    .then(data => {
                        if (data.success && data.agents && data.agents.length > 0) {
                            window.cachedAgents = data.agents;
                            const onlineAgent = data.agents.find(a => a.status === 'online') || data.agents[0];
                            if (onlineAgent) {
                                agentIdInput.value = onlineAgent.agent_id || onlineAgent.id;
                                agentDisplay.textContent = onlineAgent.display_name || onlineAgent.hostname || onlineAgent.agent_id;
                                window.currentAgentId = onlineAgent.agent_id || onlineAgent.id;
                            } else {
                                agentDisplay.textContent = 'No agents available';
                            }
                        } else {
                            agentDisplay.textContent = 'No agents available';
                        }
                    })
                    .catch(() => {
                        agentDisplay.textContent = 'Failed to load agents';
                    });
            }
        }
    }

    function closeBlockIPModal() {
        const modal = document.getElementById('blockIPModal');
        if (modal) modal.style.display = 'none';
    }

    function quickBlockIP() {
        console.log('=== quickBlockIP called ===');

        // Get IP from octet inputs
        const ip = getIPFromOctets();
        console.log('IP from octets:', ip);
        const container = document.getElementById('ipInputContainer');
        const agentId = document.getElementById('quickBlockAgentId').value;
        const agentName = document.getElementById('quickBlockAgentDisplay').textContent;
        const method = document.getElementById('quickBlockMethod').value;
        const duration = parseInt(document.getElementById('quickBlockDuration').value);
        const reason = document.getElementById('quickBlockReason').value.trim() || 'Manual block from dashboard';
        const msgEl = document.getElementById('quickBlockMessage');

        // Check all octets are filled
        if (!ip) {
            msgEl.textContent = 'Please enter a complete IP address';
            msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
            msgEl.style.color = TC.danger;
            msgEl.style.display = 'block';
            if (container) container.style.borderColor = TC.danger;
            document.getElementById('ipOctet1')?.focus();
            return;
        }

        // Require agent - no global blocks allowed
        if (!agentId) {
            msgEl.textContent = 'No agent selected. Please select an agent first.';
            msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
            msgEl.style.color = TC.danger;
            msgEl.style.display = 'block';
            return;
        }

        // Mark as valid
        if (container) container.style.borderColor = TC.successDark;

        msgEl.textContent = `Blocking ${ip} on ${agentName}...`;
        msgEl.style.background = 'rgba(0, 120, 212, 0.1)';
        msgEl.style.color = 'var(--azure-blue)';
        msgEl.style.display = 'block';

        // Convert seconds to minutes for the API
        const durationMinutes = Math.floor(duration / 60);
        const endpoint = method === 'fail2ban' ? '/api/dashboard/fail2ban/ban' : '/api/dashboard/blocking/blocks/manual';
        const payload = method === 'fail2ban'
            ? { ip_address: ip, bantime: duration, reason: reason, agent_id: agentId }
            : { ip_address: ip, reason: reason, duration_minutes: durationMinutes || 1440, agent_id: agentId };

        fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(r => r.json())
        .then(data => {
            console.log('Block IP response:', data);
            if (data.success) {
                msgEl.textContent = `Successfully blocked ${ip}`;
                msgEl.style.background = 'rgba(16, 124, 16, 0.1)';
                msgEl.style.color = TC.successDark;

                // Set the agent filter
                if (agentId) {
                    window.currentAgentId = agentId;
                    const pageAgentSelector = document.getElementById('firewallAgentSelector');
                    if (pageAgentSelector) pageAgentSelector.value = agentId;
                }

                // Close modal after brief delay to show success message
                setTimeout(function() {
                    try {
                        // Close the modal
                        const modal = document.getElementById('blockIPModal');
                        if (modal) modal.style.display = 'none';

                        // Try to switch tab and reload
                        const blockedTab = document.querySelector('[data-tab="blocked"]');
                        if (blockedTab) blockedTab.click();
                        if (typeof loadBlockedIPs === 'function') loadBlockedIPs();
                    } catch (e) {
                        console.error('Error after blocking:', e);
                    }
                }, 800);
            } else {
                msgEl.textContent = data.error || 'Failed to block IP';
                msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
                msgEl.style.color = TC.danger;
            }
        })
        .catch(err => {
            console.error('Block IP error:', err);
            msgEl.textContent = 'Error blocking IP: ' + err.message;
            msgEl.style.background = 'rgba(209, 52, 56, 0.1)';
            msgEl.style.color = TC.danger;
        });
    }

    // Global exports
    window.showBlockIPModal = showBlockIPModal;
    window.closeBlockIPModal = closeBlockIPModal;
    window.quickBlockIP = quickBlockIP;
})();
