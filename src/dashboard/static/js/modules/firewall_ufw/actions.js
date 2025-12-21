/**
 * SSH Guardian v3.0 - Firewall UFW Actions
 * UFW command execution, quick actions, rule management
 */
(function() {
    'use strict';

    async function quickAction(action) {
        if (!window.currentAgentId) {
            showNotification('Please select a server first', 'error');
            return;
        }

        let actionType = '';
        let params = {};
        let confirmMsg = '';

        switch (action) {
            case 'allow-ssh':
                actionType = 'allow_port';
                params = { port: 22, protocol: 'tcp' };
                confirmMsg = 'Allow SSH (port 22) from anywhere?';
                break;
            case 'allow-http':
                if (confirm('Allow HTTP (80) and HTTPS (443) from anywhere?')) {
                    await executeUFWQuickAction('allow_port', { port: 80, protocol: 'tcp' });
                    await executeUFWQuickAction('allow_port', { port: 443, protocol: 'tcp' });
                    return;
                }
                return;
            case 'allow-mysql':
                actionType = 'allow_port';
                params = { port: 3306, protocol: 'tcp' };
                confirmMsg = 'Allow MySQL (port 3306) from anywhere? Consider restricting to specific IPs for security.';
                break;
            case 'limit-ssh':
                actionType = 'limit_port';
                params = { port: 22, protocol: 'tcp' };
                confirmMsg = 'Enable SSH rate limiting (brute force protection)?';
                break;
            case 'enable':
                actionType = 'enable';
                confirmMsg = 'Enable UFW firewall?';
                break;
            case 'disable':
                actionType = 'disable';
                confirmMsg = 'WARNING: This will disable the firewall completely. Are you sure?';
                break;
        }

        if (confirmMsg && confirm(confirmMsg)) {
            await executeUFWQuickAction(actionType, params);
        }
    }

    function updateUFWToggleButton(isActive) {
        const toggleBtn = document.getElementById('ufwToggleBtn');
        if (!toggleBtn) return;

        const icon = toggleBtn.querySelector('.toggle-icon');
        const text = toggleBtn.querySelector('.toggle-text');

        if (isActive) {
            toggleBtn.setAttribute('data-status', 'active');
            if (icon) icon.textContent = '🛡️';
            if (text) text.textContent = 'UFW Active';
        } else {
            toggleBtn.setAttribute('data-status', 'inactive');
            if (icon) icon.textContent = '⚠️';
            if (text) text.textContent = 'UFW Disabled';
        }
    }

    async function toggleUFW() {
        if (!window.currentAgentId) {
            showNotification('Please select a server first', 'error');
            return;
        }

        const toggleBtn = document.getElementById('ufwToggleBtn');
        const currentStatus = toggleBtn?.getAttribute('data-status');

        if (currentStatus === 'unknown') {
            showNotification('UFW status is loading, please wait...', 'warning');
            return;
        }

        const isCurrentlyActive = currentStatus === 'active';
        const action = isCurrentlyActive ? 'disable' : 'enable';
        const confirmMsg = isCurrentlyActive
            ? 'WARNING: This will disable the firewall completely. Are you sure?'
            : 'Enable UFW firewall?';

        if (confirm(confirmMsg)) {
            const text = toggleBtn?.querySelector('.toggle-text');
            const icon = toggleBtn?.querySelector('.toggle-icon');
            if (text) text.textContent = 'Processing...';
            if (icon) icon.textContent = '⏳';
            toggleBtn?.setAttribute('data-status', 'unknown');

            await executeUFWQuickAction(action, {});
        }
    }

    async function addSimpleRule() {
        if (!window.currentAgentId) {
            showUFWMessage('Please select a server first', 'error');
            return;
        }

        const action = document.getElementById('simpleRuleAction')?.value;
        const protocol = document.getElementById('simpleRuleProtocol')?.value || 'tcp';
        let port = document.getElementById('simpleRulePort')?.value;
        let source = document.getElementById('simpleRuleCustomSource')?.value?.trim();

        if (port === 'custom') {
            port = document.getElementById('simpleRuleCustomPort')?.value?.trim();
            if (!port) {
                showUFWMessage('Please enter a custom port', 'error');
                return;
            }
        }

        let actionType;
        const params = { protocol: protocol === 'all' ? 'tcp' : protocol };

        if (source) {
            actionType = action === 'ACCEPT' ? 'allow_ip' : 'block_ip';
            params.ip = source;
            if (port && port !== 'any') params.port = port;
        } else if (port && port !== 'any') {
            actionType = action === 'ACCEPT' ? 'allow_port' : 'deny_port';
            params.port = port;
        } else {
            showUFWMessage('Please specify a port or source IP', 'error');
            return;
        }

        await executeUFWQuickAction(actionType, params);
    }

    async function deleteUFWRule(ruleIndex) {
        if (!window.currentAgentId) return;
        if (!confirm(`Remove UFW rule #${ruleIndex}?`)) return;
        await executeUFWQuickAction('delete_rule', { rule_number: ruleIndex });
    }

    async function deleteSimpleRule(table, chain, ruleNum) {
        await deleteUFWRule(ruleNum);
    }

    async function executeUFWQuickAction(actionType, params = {}) {
        if (typeof window.showGlobalSync === 'function') {
            window.showGlobalSync('ufw', `Executing ${actionType.replace('_', ' ')}...`);
        } else {
            showUFWSyncIndicator('Executing...');
        }

        try {
            const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/quick-action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action_type: actionType, ...params })
            });

            const data = await response.json();

            if (data.executed) {
                if (data.success) {
                    if (typeof window.completeSyncOperation === 'function') {
                        window.completeSyncOperation(true, data.message || 'Done');
                    } else {
                        hideUFWSyncIndicator();
                        showUFWMessage(data.message || 'Command executed', 'success');
                        if (typeof window.loadUFWData === 'function' && window.currentAgentId) {
                            setTimeout(() => window.loadUFWData(window.currentAgentId, true), 500);
                        }
                    }
                } else {
                    if (typeof window.completeSyncOperation === 'function') {
                        window.completeSyncOperation(false, data.message || 'Command failed');
                    } else {
                        hideUFWSyncIndicator();
                        showUFWMessage(`Error: ${data.message || 'Command failed'}`, 'error');
                    }
                }
            } else if (data.success) {
                addToCommandQueue(data.command_id, data.ufw_command, 'pending');
                if (typeof window.updateSyncProgress === 'function') {
                    window.updateSyncProgress('Waiting for agent...', 'info');
                } else {
                    updateUFWSyncText('Waiting for agent...');
                    showUFWMessage('Command queued', 'success');
                }
                await fetch(`/api/agents/${window.currentAgentId}/ufw/request-sync`, { method: 'POST' });
                pollCommandCompletion(data.command_id);
            } else {
                if (typeof window.completeSyncOperation === 'function') {
                    window.completeSyncOperation(false, data.error || 'Unknown error');
                } else {
                    hideUFWSyncIndicator();
                    showUFWMessage(`Error: ${data.error}`, 'error');
                }
            }
        } catch (error) {
            if (typeof window.completeSyncOperation === 'function') {
                window.completeSyncOperation(false, error.message);
            } else {
                hideUFWSyncIndicator();
                showUFWMessage(`Error: ${error.message}`, 'error');
            }
        }
    }

    async function pollCommandCompletion(commandId, attempts = 0) {
        if (attempts > 30) return;

        const cmd = window.ufwCommandQueue.find(c => c.id === commandId);
        if (!cmd || cmd.status !== 'pending') return;

        setTimeout(async () => {
            try {
                const resp = await fetch(`/api/agents/${window.currentAgentId}/ufw?force=true`);
                const data = await resp.json();

                if (data.recent_commands) {
                    const serverCmd = data.recent_commands.find(c => c.command_uuid === commandId);
                    if (serverCmd) {
                        if (serverCmd.status === 'completed') {
                            updateCommandStatus(commandId, 'completed', serverCmd.result_message);
                            return;
                        } else if (serverCmd.status === 'failed') {
                            updateCommandStatus(commandId, 'failed', serverCmd.result_message);
                            return;
                        }
                    }
                }
                pollCommandCompletion(commandId, attempts + 1);
            } catch (e) {
                pollCommandCompletion(commandId, attempts + 1);
            }
        }, 1000);
    }

    function pollForUpdate(agentId, attempts = 0) {
        if (attempts > 10) {
            if (typeof window.loadUFWData === 'function') {
                window.loadUFWData(agentId, true);
            }
            return;
        }
        setTimeout(async () => {
            try {
                const resp = await fetch(`/api/agents/${agentId}/ufw`);
                const data = await resp.json();
                if (data.success && data.has_data) {
                    if (typeof window.loadUFWData === 'function') {
                        window.loadUFWData(agentId, true);
                    }
                } else {
                    pollForUpdate(agentId, attempts + 1);
                }
            } catch (e) {
                pollForUpdate(agentId, attempts + 1);
            }
        }, 1000);
    }

    async function executeUFWCommand(commandType, params) {
        showUFWSyncIndicator('Adding rule...');

        try {
            const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command_type: commandType, params })
            });

            const data = await response.json();

            if (data.success) {
                const cmdText = data.ufw_command || `ufw ${commandType}`;
                addToCommandQueue(data.command_id, cmdText, 'pending');
                showUFWMessage('Command queued', 'success');
                updateUFWSyncText('Waiting for agent...');
                await fetch(`/api/agents/${window.currentAgentId}/ufw/request-sync`, { method: 'POST' });
                pollCommandCompletion(data.command_id);
            } else {
                hideUFWSyncIndicator();
                showUFWMessage(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            hideUFWSyncIndicator();
            showUFWMessage(`Error: ${error.message}`, 'error');
        }
    }

    async function executeFirewallCommand(action, params) {
        let commandType = action;
        if (action === 'add_rule') {
            commandType = params.target === 'ACCEPT' ? 'allow' : 'deny';
        } else if (action === 'delete_rule') {
            return deleteUFWRule(params.rule_num);
        }
        return executeUFWCommand(commandType, params);
    }

    function showUFWMessage(message, type) {
        if (window.syncState?.isActive) return;

        if (typeof window.showToast === 'function') {
            window.showToast(message, type === 'error' ? 'error' : (type === 'info' ? 'info' : 'success'));
            return;
        }
        const el = document.getElementById('addRuleMessage');
        if (!el) return;
        el.style.display = 'block';
        el.textContent = message;
        el.style.background = type === 'error' ? TC.dangerBg :
                              type === 'success' ? TC.successBg : TC.primaryBg;
        el.style.color = type === 'error' ? TC.danger : type === 'success' ? TC.successDark : TC.primary;
        if (type !== 'error') setTimeout(() => { if (el) el.style.display = 'none'; }, 3000);
    }

    function showNotification(message, type) {
        if (typeof window.showToast === 'function') window.showToast(message, type);
    }

    // Global exports
    window.quickAction = quickAction;
    window.toggleUFW = toggleUFW;
    window.updateUFWToggleButton = updateUFWToggleButton;
    window.addSimpleRule = addSimpleRule;
    window.deleteUFWRule = deleteUFWRule;
    window.deleteSimpleRule = deleteSimpleRule;
    window.executeUFWQuickAction = executeUFWQuickAction;
    window.showUFWMessage = showUFWMessage;
})();
