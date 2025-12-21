/**
 * SSH Guardian v3.0 - Global Sync Indicator
 * Unified sync status indicator for UFW, Fail2ban, and Agent operations
 */

// Track sync state
const syncState = {
    isActive: false,
    currentOperation: null,
    queue: [],
    lastSync: {
        ufw: null,
        fail2ban: null,
        agent: null
    }
};

/**
 * Show the global sync indicator with activity log
 */
function showGlobalSync(operation, message) {
    syncState.isActive = true;
    syncState.currentOperation = operation;

    // Get or create the sync overlay
    let overlay = document.getElementById('globalSyncOverlay');
    if (!overlay) {
        overlay = createSyncOverlay();
        document.body.appendChild(overlay);
    }

    // Update the operation type and message
    const typeEl = overlay.querySelector('.sync-operation-type');
    const msgEl = overlay.querySelector('.sync-operation-message');
    const logEl = overlay.querySelector('.sync-activity-log');
    const spinnerEl = overlay.querySelector('.sync-spinner');
    const statusEl = overlay.querySelector('.sync-status-icon');

    // Reset state for new operation
    if (logEl) logEl.innerHTML = '';
    if (spinnerEl) spinnerEl.style.display = 'block';
    if (statusEl) statusEl.style.display = 'none';

    if (typeEl) {
        const icons = { ufw: '🛡️', fail2ban: '🔒', agent: '🖥️', general: '🔄' };
        typeEl.innerHTML = `${icons[operation] || '🔄'} ${capitalizeFirst(operation)}`;
    }
    if (msgEl) msgEl.textContent = message;

    // Add initial log entry
    addSyncLog(logEl, message, 'info');

    overlay.style.display = 'flex';
    overlay.classList.add('active');
}

/**
 * Update sync progress
 */
function updateSyncProgress(message, type = 'info') {
    const overlay = document.getElementById('globalSyncOverlay');
    if (!overlay) return;

    const msgEl = overlay.querySelector('.sync-operation-message');
    const logEl = overlay.querySelector('.sync-activity-log');

    if (msgEl) msgEl.textContent = message;
    addSyncLog(logEl, message, type);
}

/**
 * Complete sync operation
 */
function completeSyncOperation(success = true, message = null) {
    const overlay = document.getElementById('globalSyncOverlay');
    if (!overlay) return;

    const msgEl = overlay.querySelector('.sync-operation-message');
    const logEl = overlay.querySelector('.sync-activity-log');
    const spinnerEl = overlay.querySelector('.sync-spinner');
    const statusEl = overlay.querySelector('.sync-status-icon');

    // Update last sync time
    if (syncState.currentOperation) {
        syncState.lastSync[syncState.currentOperation] = new Date();
        updateLastSyncDisplay();
    }

    // Show completion status
    if (spinnerEl) spinnerEl.style.display = 'none';
    if (statusEl) {
        statusEl.style.display = 'block';
        statusEl.innerHTML = success ? '✅' : '❌';
    }

    const finalMsg = message || (success ? 'Operation completed successfully' : 'Operation failed');
    if (msgEl) msgEl.textContent = finalMsg;
    addSyncLog(logEl, finalMsg, success ? 'success' : 'error');

    // Auto-hide after delay and refresh data
    const operationType = syncState.currentOperation; // Save before hideGlobalSync clears it
    setTimeout(() => {
        hideGlobalSync();
        // Trigger refresh callbacks
        if (success && operationType) {
            triggerRefreshCallbacks(operationType);
        }
    }, 1500);
}

/**
 * Hide the sync overlay
 */
function hideGlobalSync() {
    const overlay = document.getElementById('globalSyncOverlay');
    if (overlay) {
        overlay.classList.remove('active');
        setTimeout(() => {
            overlay.style.display = 'none';
            // Reset spinner visibility
            const spinnerEl = overlay.querySelector('.sync-spinner');
            const statusEl = overlay.querySelector('.sync-status-icon');
            if (spinnerEl) spinnerEl.style.display = 'block';
            if (statusEl) statusEl.style.display = 'none';
        }, 300);
    }
    syncState.isActive = false;
    syncState.currentOperation = null;
}

/**
 * Create the sync overlay HTML
 */
function createSyncOverlay() {
    const overlay = document.createElement('div');
    overlay.id = 'globalSyncOverlay';
    overlay.className = 'global-sync-overlay';
    overlay.innerHTML = `
        <div class="global-sync-modal">
            <div class="sync-header">
                <div class="sync-spinner"></div>
                <div class="sync-status-icon" style="display: none; font-size: 24px;"></div>
                <div class="sync-header-text">
                    <div class="sync-operation-type">Syncing...</div>
                    <div class="sync-operation-message">Please wait...</div>
                </div>
            </div>
            <div class="sync-activity-log"></div>
            <div class="sync-footer">
                <button class="sync-cancel-btn" onclick="cancelSyncOperation()">Cancel</button>
            </div>
        </div>
    `;
    return overlay;
}

/**
 * Add entry to activity log
 */
function addSyncLog(logEl, message, type = 'info') {
    if (!logEl) return;

    const icons = {
        info: '📋',
        success: '✅',
        error: '❌',
        warning: '⚠️'
    };

    const entry = document.createElement('div');
    entry.className = `sync-log-entry ${type}`;
    entry.innerHTML = `
        <span class="sync-log-icon">${icons[type] || '📋'}</span>
        <span class="sync-log-message">${message}</span>
        <span class="sync-log-time">${formatTime(new Date())}</span>
    `;

    logEl.appendChild(entry);
    logEl.scrollTop = logEl.scrollHeight;
}

/**
 * Cancel current sync operation
 */
function cancelSyncOperation() {
    hideGlobalSync();
    if (typeof window.showToast === 'function') {
        window.showToast('Operation cancelled', 'warning');
    }
}

/**
 * Update the last sync display for all sync types
 */
function updateLastSyncDisplay() {
    const lastSyncDisplay = document.getElementById('lastSyncDisplay');

    // Update individual sync type displays
    const ufwEl = document.getElementById('lastSyncUFW');
    const f2bEl = document.getElementById('lastSyncF2B');

    if (syncState.lastSync.ufw && ufwEl) {
        ufwEl.textContent = formatTimeAgo(syncState.lastSync.ufw);
    }
    if (syncState.lastSync.fail2ban && f2bEl) {
        f2bEl.textContent = formatTimeAgo(syncState.lastSync.fail2ban);
    }

    // Show the container if any sync has occurred
    if (lastSyncDisplay && (syncState.lastSync.ufw || syncState.lastSync.fail2ban)) {
        lastSyncDisplay.style.display = 'block';
    }
}

/**
 * Set last sync time for a specific type
 */
function setLastSync(type, time = new Date()) {
    syncState.lastSync[type] = time;
    updateLastSyncDisplay();
}

/**
 * Trigger refresh callbacks after successful sync
 */
function triggerRefreshCallbacks(operation) {
    try {
        switch (operation) {
            case 'ufw':
                if (typeof window.loadUFWData === 'function' && window.currentAgentId) {
                    window.loadUFWData(window.currentAgentId, true);
                }
                break;
            case 'fail2ban':
                if (typeof window.loadFail2banBans === 'function') {
                    window.loadFail2banBans();
                }
                if (typeof window.loadF2bStats === 'function') {
                    window.loadF2bStats();
                }
                break;
            case 'agent':
                if (typeof window.loadAgentDetails === 'function' && window.currentAgentId) {
                    window.loadAgentDetails(window.currentAgentId);
                }
                break;
        }
    } catch (e) {
        console.error('[SyncIndicator] Error in refresh callback:', e);
    }
}

/**
 * Helper: Capitalize first letter
 */
function capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Helper: Format time as HH:MM:SS
 */
function formatTime(date) {
    return date.toLocaleTimeString('en-US', { hour12: false });
}

/**
 * Helper: Format relative time (fallback if not available from utils)
 */
function formatTimeAgo(dateInput) {
    if (typeof window.formatTimeAgo === 'function') {
        return window.formatTimeAgo(dateInput);
    }
    // Simple fallback
    const date = dateInput instanceof Date ? dateInput : new Date(dateInput);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
}

// ============================================================================
// WRAPPED OPERATIONS (use these instead of direct API calls)
// ============================================================================

/**
 * Execute fail2ban unban with sync indicator
 */
async function executeF2bUnban(agentId, ipAddress, jailName = 'sshd') {
    showGlobalSync('fail2ban', `Unbanning ${ipAddress}...`);

    try {
        updateSyncProgress(`Executing fail2ban-client unbanip...`);

        const response = await fetch(`/api/agents/${agentId}/fail2ban/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                command_type: 'unban',
                ip_address: ipAddress,
                jail_name: jailName
            })
        });

        const data = await response.json();

        if (data.success || data.executed) {
            updateSyncProgress(data.message || `${ipAddress} unbanned`, 'success');
            completeSyncOperation(true, data.message || 'Unban completed');
            return true;
        } else {
            const errorMsg = data.error || data.message || 'Unknown error';
            updateSyncProgress(`Failed: ${errorMsg}`, 'error');
            completeSyncOperation(false, errorMsg);
            return false;
        }
    } catch (error) {
        updateSyncProgress(`Error: ${error.message}`, 'error');
        completeSyncOperation(false, error.message);
        return false;
    }
}

/**
 * Execute fail2ban ban with sync indicator
 */
async function executeF2bBan(agentId, ipAddress, jailName = 'sshd', bantime = 600) {
    showGlobalSync('fail2ban', `Banning ${ipAddress}...`);

    try {
        updateSyncProgress(`Sending ban command to agent...`);

        const response = await fetch(`/api/agents/${agentId}/fail2ban/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                command_type: 'ban',
                ip_address: ipAddress,
                jail_name: jailName,
                bantime_seconds: bantime
            })
        });

        const data = await response.json();

        if (data.success && data.executed) {
            updateSyncProgress(`${ipAddress} banned successfully`, 'success');
            completeSyncOperation(true, data.message);
            return true;
        } else if (data.success) {
            updateSyncProgress(`Command queued, waiting for agent...`, 'warning');
            completeSyncOperation(true, 'Command queued for agent');
            return true;
        } else {
            updateSyncProgress(`Failed: ${data.error}`, 'error');
            completeSyncOperation(false, data.error);
            return false;
        }
    } catch (error) {
        updateSyncProgress(`Error: ${error.message}`, 'error');
        completeSyncOperation(false, error.message);
        return false;
    }
}

/**
 * Execute UFW sync with indicator
 */
async function executeUfwSync(agentId) {
    showGlobalSync('ufw', 'Syncing UFW rules...');

    try {
        updateSyncProgress('Requesting sync from agent...');

        const response = await fetch(`/api/agents/${agentId}/ufw/request-sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            updateSyncProgress('Waiting for agent response...');

            // Wait and then refresh
            await new Promise(resolve => setTimeout(resolve, 2000));
            updateSyncProgress('Refreshing UFW data...', 'success');

            completeSyncOperation(true, 'UFW sync completed');
            return true;
        } else {
            updateSyncProgress(`Sync failed: ${data.error}`, 'error');
            completeSyncOperation(false, data.error);
            return false;
        }
    } catch (error) {
        updateSyncProgress(`Error: ${error.message}`, 'error');
        completeSyncOperation(false, error.message);
        return false;
    }
}

/**
 * Execute UFW command with indicator
 */
async function executeUfwCommand(agentId, commandType, params) {
    const actionNames = {
        'deny': 'Blocking',
        'allow': 'Allowing',
        'delete': 'Deleting rule',
        'enable': 'Enabling UFW',
        'disable': 'Disabling UFW'
    };

    showGlobalSync('ufw', `${actionNames[commandType] || 'Executing'}...`);

    try {
        updateSyncProgress(`Sending ${commandType} command...`);

        const response = await fetch(`/api/agents/${agentId}/ufw/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                command_type: commandType,
                params: params
            })
        });

        const data = await response.json();

        if (data.success) {
            updateSyncProgress('Command sent, waiting for agent...', 'success');

            // Wait and refresh
            await new Promise(resolve => setTimeout(resolve, 2000));
            completeSyncOperation(true, 'Command executed successfully');
            return true;
        } else {
            updateSyncProgress(`Failed: ${data.error}`, 'error');
            completeSyncOperation(false, data.error);
            return false;
        }
    } catch (error) {
        updateSyncProgress(`Error: ${error.message}`, 'error');
        completeSyncOperation(false, error.message);
        return false;
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

window.showGlobalSync = showGlobalSync;
window.updateSyncProgress = updateSyncProgress;
window.completeSyncOperation = completeSyncOperation;
window.hideGlobalSync = hideGlobalSync;
window.cancelSyncOperation = cancelSyncOperation;
window.executeF2bUnban = executeF2bUnban;
window.executeF2bBan = executeF2bBan;
window.executeUfwSync = executeUfwSync;
window.executeUfwCommand = executeUfwCommand;
window.syncState = syncState;
window.setLastSync = setLastSync;
window.updateLastSyncDisplay = updateLastSyncDisplay;
window.triggerRefreshCallbacks = triggerRefreshCallbacks;

console.log('[SyncIndicator] Global sync indicator loaded');
