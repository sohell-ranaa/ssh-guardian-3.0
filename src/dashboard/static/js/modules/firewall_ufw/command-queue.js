/**
 * SSH Guardian v3.0 - Firewall UFW Command Queue
 * Manages pending UFW commands and polling
 */
(function() {
    'use strict';

    // Track pending commands
    window.ufwCommandQueue = [];
    window.ufwQueuePolling = null;

    function addToCommandQueue(commandId, commandText, status = 'pending') {
        const queue = window.ufwCommandQueue;

        // Don't add duplicates
        if (queue.some(c => c.id === commandId)) return;

        queue.unshift({
            id: commandId,
            command: commandText,
            status: status,
            timestamp: new Date()
        });

        // Keep max 10 items
        if (queue.length > 10) queue.pop();

        renderCommandQueue();
        showCommandQueuePanel(true);
        startQueuePolling();
    }

    function updateCommandStatus(commandId, status, message = '') {
        const queue = window.ufwCommandQueue;
        const cmd = queue.find(c => c.id === commandId);
        if (cmd) {
            cmd.status = status;
            cmd.message = message;
            renderCommandQueue();

            // If completed or failed, refresh the rules list
            if (status === 'completed' || status === 'failed') {
                if (typeof updateUFWSyncText === 'function') {
                    updateUFWSyncText('Refreshing...');
                }

                if (window.currentAgentId) {
                    setTimeout(() => {
                        const refreshPromise = typeof loadUFWData === 'function'
                            ? loadUFWData(window.currentAgentId, true)
                            : (typeof window.loadUFWData === 'function'
                                ? window.loadUFWData(window.currentAgentId, true)
                                : (typeof loadFirewallPage === 'function'
                                    ? loadFirewallPage(true)
                                    : Promise.resolve()));

                        Promise.resolve(refreshPromise).finally(() => {
                            if (typeof hideUFWSyncIndicator === 'function') {
                                hideUFWSyncIndicator();
                            }
                        });
                    }, 500);
                } else {
                    if (typeof hideUFWSyncIndicator === 'function') {
                        hideUFWSyncIndicator();
                    }
                }
            }
        }

        // Hide panel if all completed
        const pending = queue.filter(c => c.status === 'pending');
        if (pending.length === 0) {
            stopQueuePolling();
            setTimeout(() => {
                const stillPending = window.ufwCommandQueue.filter(c => c.status === 'pending');
                if (stillPending.length === 0) {
                    showCommandQueuePanel(false);
                }
            }, 3000);
        }
    }

    function renderCommandQueue() {
        const panel = document.getElementById('ufwCommandQueue');
        const list = document.getElementById('ufwQueueList');
        const countBadge = document.getElementById('ufwQueueCount');

        if (!panel || !list) return;

        const queue = window.ufwCommandQueue;
        const pendingCount = queue.filter(c => c.status === 'pending').length;

        if (countBadge) countBadge.textContent = pendingCount;

        list.innerHTML = queue.map(cmd => {
            const statusIcon = cmd.status === 'pending' ? '⏳' :
                              cmd.status === 'completed' ? '✅' : '❌';
            const statusText = cmd.status === 'pending' ? 'Pending...' :
                              cmd.status === 'completed' ? 'Done' : 'Failed';
            const timeAgo = getTimeAgo(cmd.timestamp);

            return `
                <div class="queue-item ${cmd.status}">
                    <span class="status-icon">${statusIcon}</span>
                    <span class="command-text">${_escapeHtml(cmd.command)}</span>
                    <span class="status-text">${statusText}</span>
                    <span style="font-size: 10px; color: var(--text-hint);">${timeAgo}</span>
                </div>
            `;
        }).join('');
    }

    function showCommandQueuePanel(show) {
        const panel = document.getElementById('ufwCommandQueue');
        if (panel) {
            panel.style.display = show ? 'block' : 'none';
        }
    }

    function clearCompletedCommands() {
        window.ufwCommandQueue = window.ufwCommandQueue.filter(c => c.status === 'pending');
        renderCommandQueue();
        if (window.ufwCommandQueue.length === 0) {
            showCommandQueuePanel(false);
        }
    }

    function startQueuePolling() {
        if (window.ufwQueuePolling) return;

        window.ufwQueuePolling = setInterval(async () => {
            const pending = window.ufwCommandQueue.filter(c => c.status === 'pending');
            if (pending.length === 0) {
                stopQueuePolling();
                return;
            }
            await checkPendingCommands();
        }, 2000);
    }

    function stopQueuePolling() {
        if (window.ufwQueuePolling) {
            clearInterval(window.ufwQueuePolling);
            window.ufwQueuePolling = null;
        }
    }

    async function checkPendingCommands() {
        if (!window.currentAgentId) return;

        try {
            const resp = await fetch(`/api/agents/${window.currentAgentId}/ufw?force=true`);
            const data = await resp.json();

            if (data.recent_commands) {
                const recentMap = new Map(data.recent_commands.map(c => [c.command_uuid, c]));

                window.ufwCommandQueue.forEach(cmd => {
                    if (cmd.status === 'pending') {
                        const serverCmd = recentMap.get(cmd.id);
                        if (serverCmd) {
                            if (serverCmd.status === 'completed') {
                                updateCommandStatus(cmd.id, 'completed', serverCmd.result_message);
                            } else if (serverCmd.status === 'failed') {
                                updateCommandStatus(cmd.id, 'failed', serverCmd.result_message);
                            }
                        }
                    }
                });
            }
        } catch (e) {
            console.error('Error checking command status:', e);
        }
    }

    function getTimeAgo(date) {
        const seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 5) return 'just now';
        if (seconds < 60) return `${seconds}s ago`;
        const minutes = Math.floor(seconds / 60);
        if (minutes < 60) return `${minutes}m ago`;
        return `${Math.floor(minutes / 60)}h ago`;
    }

    function _escapeHtml(text) {
        if (window.escapeHtml) return window.escapeHtml(text);
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    }

    // Global exports
    window.addToCommandQueue = addToCommandQueue;
    window.updateCommandStatus = updateCommandStatus;
    window.checkPendingCommands = checkPendingCommands;
    window.clearCompletedCommands = clearCompletedCommands;
    window.showCommandQueuePanel = showCommandQueuePanel;
})();
