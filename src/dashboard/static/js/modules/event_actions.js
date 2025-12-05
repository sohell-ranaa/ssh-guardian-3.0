/**
 * Event Actions Module
 * Handles actionable functions for the Events Live page in SSH Guardian
 */

(function() {
    'use strict';

    // Inject CSS styles
    const styles = `
        /* Action Dropdown Menu */
        .action-dropdown {
            position: absolute;
            background: var(--card-bg, #ffffff);
            border: 1px solid var(--border, #e0e0e0);
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            z-index: 1000;
            min-width: 200px;
            padding: 8px 0;
        }

        .action-dropdown-item {
            padding: 10px 16px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            transition: background 0.2s;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
        }

        .action-dropdown-item:hover {
            background: var(--hover-bg, #f5f5f5);
        }

        .action-dropdown-item.red { color: #D83B01; }
        .action-dropdown-item.green { color: #107C10; }
        .action-dropdown-item.yellow { color: #CA5010; }
        .action-dropdown-item.blue { color: #0078D4; }
        .action-dropdown-item.orange { color: #F7630C; }
        .action-dropdown-item.gray { color: #605E5C; }

        .action-dropdown-divider {
            height: 1px;
            background: var(--border, #e0e0e0);
            margin: 4px 0;
        }

        /* Modal Dialog */
        .action-modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 2000;
            animation: fadeIn 0.2s;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .action-modal {
            background: var(--card-bg, #ffffff);
            border-radius: 4px;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow: auto;
            animation: slideUp 0.3s;
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .action-modal-header {
            padding: 20px;
            border-bottom: 1px solid var(--border, #e0e0e0);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .action-modal-title {
            font-size: 16px;
            font-weight: 600;
            margin: 0;
        }

        .action-modal-close {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: var(--text-secondary, #605E5C);
            padding: 0;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 2px;
            transition: background 0.2s;
        }

        .action-modal-close:hover {
            background: var(--hover-bg, #f5f5f5);
        }

        .action-modal-body {
            padding: 20px;
        }

        .action-modal-footer {
            padding: 20px;
            border-top: 1px solid var(--border, #e0e0e0);
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }

        .action-form-group {
            margin-bottom: 16px;
        }

        .action-form-label {
            display: block;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 6px;
            color: var(--text-primary, #323130);
        }

        .action-form-input,
        .action-form-select,
        .action-form-textarea {
            width: 100%;
            padding: 8px 12px;
            border: 1px solid var(--border, #e0e0e0);
            border-radius: 2px;
            font-size: 13px;
            font-family: inherit;
            box-sizing: border-box;
        }

        .action-form-textarea {
            resize: vertical;
            min-height: 80px;
        }

        .action-form-input:focus,
        .action-form-select:focus,
        .action-form-textarea:focus {
            outline: none;
            border-color: #0078D4;
        }

        .action-btn {
            padding: 8px 16px;
            border: 1px solid var(--border, #e0e0e0);
            border-radius: 2px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.2s;
        }

        .action-btn-primary {
            background: #0078D4;
            color: white;
            border-color: #0078D4;
        }

        .action-btn-primary:hover {
            background: #106EBE;
        }

        .action-btn-secondary {
            background: var(--card-bg, #ffffff);
            color: var(--text-primary, #323130);
        }

        .action-btn-secondary:hover {
            background: var(--hover-bg, #f5f5f5);
        }

        .action-btn-danger {
            background: #D83B01;
            color: white;
            border-color: #D83B01;
        }

        .action-btn-danger:hover {
            background: #C33400;
        }

        .action-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        /* Toast Notifications */
        .toast-container {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 3000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .toast {
            background: var(--card-bg, #ffffff);
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            padding: 16px;
            min-width: 300px;
            max-width: 400px;
            display: flex;
            align-items: flex-start;
            gap: 12px;
            animation: slideInRight 0.3s;
            border-left: 4px solid #0078D4;
        }

        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(100%);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        .toast.success {
            border-left-color: #107C10;
        }

        .toast.error {
            border-left-color: #D83B01;
        }

        .toast.warning {
            border-left-color: #CA5010;
        }

        .toast.info {
            border-left-color: #0078D4;
        }

        .toast-icon {
            font-size: 20px;
            flex-shrink: 0;
        }

        .toast.success .toast-icon { color: #107C10; }
        .toast.error .toast-icon { color: #D83B01; }
        .toast.warning .toast-icon { color: #CA5010; }
        .toast.info .toast-icon { color: #0078D4; }

        .toast-content {
            flex: 1;
        }

        .toast-message {
            font-size: 13px;
            color: var(--text-primary, #323130);
            margin: 0;
        }

        .toast-close {
            background: none;
            border: none;
            font-size: 18px;
            cursor: pointer;
            color: var(--text-secondary, #605E5C);
            padding: 0;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
        }

        .loading-spinner {
            border: 2px solid var(--border, #e0e0e0);
            border-top-color: #0078D4;
            border-radius: 50%;
            width: 16px;
            height: 16px;
            animation: spin 0.8s linear infinite;
            display: inline-block;
            vertical-align: middle;
            margin-right: 8px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    `;

    // Inject styles into document
    const styleSheet = document.createElement('style');
    styleSheet.textContent = styles;
    document.head.appendChild(styleSheet);

    // Create toast container
    let toastContainer = null;
    function getToastContainer() {
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.className = 'toast-container';
            document.body.appendChild(toastContainer);
        }
        return toastContainer;
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Show toast notification
     * @param {string} message - Message to display
     * @param {string} type - Type: success, error, warning, info
     * @param {number} duration - Auto-dismiss duration in ms (default: 3000)
     */
    window.showToast = function(message, type = 'success', duration = 3000) {
        const container = getToastContainer();

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;

        const icons = {
            success: '&#x2713;',
            error: '&#x2717;',
            warning: '&#x26A0;',
            info: '&#x2139;'
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-content">
                <p class="toast-message">${escapeHtml(message)}</p>
            </div>
            <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
        `;

        container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => {
                toast.style.animation = 'slideInRight 0.3s reverse';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        return toast;
    };

    /**
     * Show modal dialog
     * @param {string} title - Modal title
     * @param {string|HTMLElement} content - Modal content (HTML string or element)
     * @param {Function} onConfirm - Callback when confirmed
     * @param {Object} options - Additional options
     */
    window.showActionModal = function(title, content, onConfirm, options = {}) {
        // Remove existing modals
        document.querySelectorAll('.action-modal-overlay').forEach(el => el.remove());

        const overlay = document.createElement('div');
        overlay.className = 'action-modal-overlay';

        const modal = document.createElement('div');
        modal.className = 'action-modal';

        const header = document.createElement('div');
        header.className = 'action-modal-header';
        header.innerHTML = `
            <h3 class="action-modal-title">${escapeHtml(title)}</h3>
            <button class="action-modal-close">&times;</button>
        `;

        const body = document.createElement('div');
        body.className = 'action-modal-body';
        if (typeof content === 'string') {
            body.innerHTML = content;
        } else {
            body.appendChild(content);
        }

        const footer = document.createElement('div');
        footer.className = 'action-modal-footer';

        // If onConfirm is null, show only a Close button (info modal)
        if (onConfirm === null) {
            const closeBtn = document.createElement('button');
            closeBtn.className = 'action-btn action-btn-primary';
            closeBtn.textContent = options.confirmText || 'Close';
            closeBtn.onclick = () => overlay.remove();
            footer.appendChild(closeBtn);
        } else {
            // Show Cancel and Confirm buttons for action modals
            if (options.showCancel !== false) {
                const cancelBtn = document.createElement('button');
                cancelBtn.className = 'action-btn action-btn-secondary';
                cancelBtn.textContent = options.cancelText || 'Cancel';
                cancelBtn.onclick = () => overlay.remove();
                footer.appendChild(cancelBtn);
            }

            const confirmBtn = document.createElement('button');
            confirmBtn.className = `action-btn ${options.dangerMode ? 'action-btn-danger' : 'action-btn-primary'}`;
            confirmBtn.textContent = options.confirmText || 'Confirm';
            confirmBtn.onclick = async () => {
                confirmBtn.disabled = true;
                confirmBtn.innerHTML = '<span class="loading-spinner"></span>Processing...';
                try {
                    await onConfirm(modal);
                    overlay.remove();
                } catch (error) {
                    console.error('Modal confirm error:', error);
                    confirmBtn.disabled = false;
                    confirmBtn.textContent = options.confirmText || 'Confirm';
                }
            };
            footer.appendChild(confirmBtn);
        }

        modal.appendChild(header);
        modal.appendChild(body);
        modal.appendChild(footer);
        overlay.appendChild(modal);

        // Close button handler
        header.querySelector('.action-modal-close').onclick = () => overlay.remove();

        // Keyboard shortcuts
        const keyHandler = (e) => {
            if (e.key === 'Escape') {
                overlay.remove();
                document.removeEventListener('keydown', keyHandler);
            }
        };
        document.addEventListener('keydown', keyHandler);

        // Close on overlay click
        overlay.onclick = (e) => {
            if (e.target === overlay) {
                overlay.remove();
            }
        };

        document.body.appendChild(overlay);

        // Focus first input if exists
        const firstInput = body.querySelector('input, textarea, select');
        if (firstInput) {
            setTimeout(() => firstInput.focus(), 100);
        }

        return modal;
    };

    /**
     * Quick whitelist an IP address
     * @param {string} ipAddress - IP address to whitelist
     * @param {string} reason - Reason for whitelisting
     */
    window.quickWhitelist = async function(ipAddress, reason = '') {
        if (!ipAddress) {
            showToast('No IP address provided', 'error');
            return;
        }

        const content = `
            <div class="action-form-group">
                <label class="action-form-label">IP Address</label>
                <input type="text" class="action-form-input" value="${escapeHtml(ipAddress)}" readonly style="background: #f5f5f5;">
            </div>
            <div class="action-form-group">
                <label class="action-form-label">Reason for Whitelisting</label>
                <textarea class="action-form-textarea" id="whitelistReason" placeholder="Enter reason for whitelisting this IP...">${escapeHtml(reason)}</textarea>
            </div>
            <p style="font-size: 12px; color: var(--text-secondary); margin-top: 0;">This IP will be permanently whitelisted and will not be blocked by any automated rules.</p>
        `;

        showActionModal('Whitelist IP Address', content, async (modal) => {
            const reasonInput = modal.querySelector('#whitelistReason');
            const finalReason = reasonInput.value.trim() || 'Whitelisted from events view';

            try {
                const response = await fetch('/api/dashboard/event-actions/whitelist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        reason: finalReason
                    })
                });

                const data = await response.json();

                if (data.success) {
                    showToast(`IP ${ipAddress} whitelisted successfully!`, 'success');

                    // Refresh events list if function exists
                    if (typeof window.loadLiveEvents === 'function') {
                        setTimeout(() => window.loadLiveEvents(), 500);
                    }
                } else {
                    showToast(`Failed to whitelist IP: ${data.message || data.error || 'Unknown error'}`, 'error', 5000);
                }
            } catch (error) {
                console.error('Error whitelisting IP:', error);
                showToast('Error whitelisting IP. Please try again.', 'error');
                throw error;
            }
        }, {
            confirmText: 'Whitelist',
            dangerMode: false
        });
    };

    /**
     * Quick watch an IP address
     * @param {string} ipAddress - IP address to watch
     * @param {string} reason - Reason for watching
     * @param {string} watchLevel - Watch level: low, medium, high, critical
     */
    window.quickWatch = async function(ipAddress, reason = '', watchLevel = 'medium') {
        if (!ipAddress) {
            showToast('No IP address provided', 'error');
            return;
        }

        const content = `
            <div class="action-form-group">
                <label class="action-form-label">IP Address</label>
                <input type="text" class="action-form-input" value="${escapeHtml(ipAddress)}" readonly style="background: #f5f5f5;">
            </div>
            <div class="action-form-group">
                <label class="action-form-label">Watch Level</label>
                <select class="action-form-select" id="watchLevel">
                    <option value="low" ${watchLevel === 'low' ? 'selected' : ''}>Low - Passive monitoring</option>
                    <option value="medium" ${watchLevel === 'medium' ? 'selected' : ''}>Medium - Active monitoring</option>
                    <option value="high" ${watchLevel === 'high' ? 'selected' : ''}>High - Close monitoring with alerts</option>
                    <option value="critical" ${watchLevel === 'critical' ? 'selected' : ''}>Critical - Immediate attention required</option>
                </select>
            </div>
            <div class="action-form-group">
                <label class="action-form-label">Reason for Watching</label>
                <textarea class="action-form-textarea" id="watchReason" placeholder="Enter reason for watching this IP...">${escapeHtml(reason)}</textarea>
            </div>
            <p style="font-size: 12px; color: var(--text-secondary); margin-top: 0;">This IP will be added to the watchlist for enhanced monitoring.</p>
        `;

        showActionModal('Add IP to Watchlist', content, async (modal) => {
            const levelInput = modal.querySelector('#watchLevel');
            const reasonInput = modal.querySelector('#watchReason');
            const finalReason = reasonInput.value.trim() || 'Added from events view';

            try {
                const response = await fetch('/api/dashboard/event-actions/watchlist', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        watch_level: levelInput.value,
                        reason: finalReason
                    })
                });

                const data = await response.json();

                if (data.success) {
                    showToast(`IP ${ipAddress} added to watchlist (${levelInput.value})`, 'success');
                } else {
                    showToast(`Failed to add to watchlist: ${data.message || data.error || 'Unknown error'}`, 'error', 5000);
                }
            } catch (error) {
                console.error('Error adding to watchlist:', error);
                showToast('Error adding to watchlist. Please try again.', 'error');
                throw error;
            }
        }, {
            confirmText: 'Add to Watchlist',
            dangerMode: false
        });
    };

    /**
     * Quick note for an IP address or event
     * @param {string} ipAddress - IP address
     * @param {string|null} eventId - Optional event ID
     */
    window.quickNote = async function(ipAddress, eventId = null) {
        if (!ipAddress) {
            showToast('No IP address provided', 'error');
            return;
        }

        const content = `
            <div class="action-form-group">
                <label class="action-form-label">IP Address</label>
                <input type="text" class="action-form-input" value="${escapeHtml(ipAddress)}" readonly style="background: #f5f5f5;">
            </div>
            ${eventId ? `
            <div class="action-form-group">
                <label class="action-form-label">Event ID</label>
                <input type="text" class="action-form-input" value="${escapeHtml(eventId)}" readonly style="background: #f5f5f5;">
            </div>
            ` : ''}
            <div class="action-form-group">
                <label class="action-form-label">Note Content</label>
                <textarea class="action-form-textarea" id="noteContent" placeholder="Enter your note..." style="min-height: 120px;"></textarea>
            </div>
            <p style="font-size: 12px; color: var(--text-secondary); margin-top: 0;">
                ${eventId ? 'This note will be attached to the specific event.' : 'This note will be associated with the IP address.'}
            </p>
        `;

        showActionModal('Add Note', content, async (modal) => {
            const noteInput = modal.querySelector('#noteContent');
            const noteText = noteInput.value.trim();

            if (!noteText) {
                showToast('Please enter a note', 'warning');
                throw new Error('Empty note');
            }

            try {
                const response = await fetch('/api/dashboard/event-actions/notes', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        event_id: eventId,
                        note: noteText
                    })
                });

                const data = await response.json();

                if (data.success) {
                    showToast('Note added successfully', 'success');
                } else {
                    showToast(`Failed to add note: ${data.message || data.error || 'Unknown error'}`, 'error', 5000);
                }
            } catch (error) {
                console.error('Error adding note:', error);
                showToast('Error adding note. Please try again.', 'error');
                throw error;
            }
        }, {
            confirmText: 'Add Note',
            dangerMode: false
        });
    };

    /**
     * Quick report an IP address or event
     * @param {string} ipAddress - IP address
     * @param {string|null} eventId - Optional event ID
     */
    window.quickReport = async function(ipAddress, eventId = null) {
        if (!ipAddress) {
            showToast('No IP address provided', 'error');
            return;
        }

        const content = `
            <div class="action-form-group">
                <label class="action-form-label">IP Address</label>
                <input type="text" class="action-form-input" value="${escapeHtml(ipAddress)}" readonly style="background: #f5f5f5;">
            </div>
            ${eventId ? `
            <div class="action-form-group">
                <label class="action-form-label">Event ID</label>
                <input type="text" class="action-form-input" value="${escapeHtml(eventId)}" readonly style="background: #f5f5f5;">
            </div>
            ` : ''}
            <div class="action-form-group">
                <label class="action-form-label">Report Category</label>
                <select class="action-form-select" id="reportCategory">
                    <option value="ssh_brute_force">SSH Brute Force Attack</option>
                    <option value="port_scanning">Port Scanning Activity</option>
                    <option value="malicious_payload">Malicious Payload Detected</option>
                    <option value="credential_stuffing">Credential Stuffing</option>
                    <option value="dos_attempt">DoS Attempt</option>
                    <option value="suspicious_pattern">Suspicious Pattern</option>
                    <option value="known_malicious">Known Malicious Actor</option>
                    <option value="other">Other</option>
                </select>
            </div>
            <div class="action-form-group">
                <label class="action-form-label">Report Details</label>
                <textarea class="action-form-textarea" id="reportDetails" placeholder="Provide additional details about this report..." style="min-height: 100px;"></textarea>
            </div>
            <p style="font-size: 12px; color: var(--text-secondary); margin-top: 0;">This report will be logged for security analysis and may be shared with threat intelligence platforms.</p>
        `;

        showActionModal('Report IP Address', content, async (modal) => {
            const categoryInput = modal.querySelector('#reportCategory');
            const detailsInput = modal.querySelector('#reportDetails');
            const details = detailsInput.value.trim();

            try {
                const response = await fetch('/api/dashboard/event-actions/report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        event_id: eventId,
                        category: categoryInput.value,
                        details: details
                    })
                });

                const data = await response.json();

                if (data.success) {
                    showToast('Report submitted successfully', 'success');
                } else {
                    showToast(`Failed to submit report: ${data.message || data.error || 'Unknown error'}`, 'error', 5000);
                }
            } catch (error) {
                console.error('Error submitting report:', error);
                showToast('Error submitting report. Please try again.', 'error');
                throw error;
            }
        }, {
            confirmText: 'Submit Report',
            dangerMode: true
        });
    };

    /**
     * Show IP actions dropdown menu
     * @param {string} ipAddress - IP address
     * @param {string|null} eventId - Optional event ID
     * @param {HTMLElement} element - Element to position dropdown near
     */
    window.showIpActions = function(ipAddress, eventId = null, element = null) {
        if (!ipAddress) {
            console.error('No IP address provided');
            return;
        }

        // Remove existing dropdowns
        document.querySelectorAll('.action-dropdown').forEach(el => el.remove());

        const dropdown = document.createElement('div');
        dropdown.className = 'action-dropdown';

        dropdown.innerHTML = `
            <button class="action-dropdown-item green" data-action="whitelist">
                <span>&#x2713;</span>
                <span>Whitelist IP</span>
            </button>
            <button class="action-dropdown-item yellow" data-action="watch">
                <span>&#x1F441;</span>
                <span>Watch IP</span>
            </button>
            <div class="action-dropdown-divider"></div>
            <button class="action-dropdown-item blue" data-action="note">
                <span>&#x1F4DD;</span>
                <span>Add Note</span>
            </button>
            <button class="action-dropdown-item orange" data-action="report">
                <span>&#x26A0;</span>
                <span>Report IP</span>
            </button>
            <div class="action-dropdown-divider"></div>
            <button class="action-dropdown-item gray" data-action="details">
                <span>&#x2139;</span>
                <span>View Details</span>
            </button>
        `;

        // Position dropdown with viewport boundary checks
        document.body.appendChild(dropdown);

        if (element) {
            const rect = element.getBoundingClientRect();
            const dropdownRect = dropdown.getBoundingClientRect();

            // Calculate position
            let top = rect.bottom + 5;
            let left = rect.left;

            // Check if dropdown goes below viewport
            if (top + dropdownRect.height > window.innerHeight) {
                top = rect.top - dropdownRect.height - 5;
            }

            // Check if dropdown goes past right edge
            if (left + dropdownRect.width > window.innerWidth) {
                left = window.innerWidth - dropdownRect.width - 10;
            }

            // Ensure left is not negative
            if (left < 0) left = 10;

            dropdown.style.position = 'fixed';
            dropdown.style.top = `${top}px`;
            dropdown.style.left = `${left}px`;
        } else {
            dropdown.style.position = 'fixed';
            dropdown.style.top = '50%';
            dropdown.style.left = '50%';
            dropdown.style.transform = 'translate(-50%, -50%)';
        }

        // Add click handlers
        dropdown.querySelectorAll('.action-dropdown-item').forEach(item => {
            item.addEventListener('click', () => {
                const action = item.dataset.action;
                dropdown.remove();

                switch (action) {
                    case 'whitelist':
                        window.quickWhitelist(ipAddress);
                        break;
                    case 'watch':
                        window.quickWatch(ipAddress);
                        break;
                    case 'note':
                        window.quickNote(ipAddress, eventId);
                        break;
                    case 'report':
                        window.quickReport(ipAddress, eventId);
                        break;
                    case 'details':
                        window.showIpDetails(ipAddress);
                        break;
                }
            });
        });

        // Close on outside click
        const closeHandler = (e) => {
            if (!dropdown.contains(e.target) && e.target !== element) {
                dropdown.remove();
                document.removeEventListener('click', closeHandler);
            }
        };
        setTimeout(() => document.addEventListener('click', closeHandler), 0);

        // Close on escape
        const keyHandler = (e) => {
            if (e.key === 'Escape') {
                dropdown.remove();
                document.removeEventListener('keydown', keyHandler);
            }
        };
        document.addEventListener('keydown', keyHandler);
    };

    /**
     * Check IP status
     * @param {string} ipAddress - IP address to check
     * @returns {Promise<Object>} IP status object
     */
    window.checkIpStatus = async function(ipAddress) {
        if (!ipAddress) {
            console.error('No IP address provided');
            return null;
        }

        try {
            const response = await fetch(`/api/dashboard/event-actions/ip-status/${encodeURIComponent(ipAddress)}`);
            const data = await response.json();

            if (data.success) {
                return data;
            } else {
                console.error('Failed to check IP status:', data.error);
                return null;
            }
        } catch (error) {
            console.error('Error checking IP status:', error);
            return null;
        }
    };

    /**
     * Fetch IP geolocation info from FreeIPAPI
     * @param {string} ipAddress - IP address to lookup
     * @returns {Promise<Object>} IP info object
     */
    window.fetchIpInfo = async function(ipAddress) {
        try {
            const response = await fetch(`/api/dashboard/ip-info/lookup/${encodeURIComponent(ipAddress)}`);
            const data = await response.json();
            return data.success ? data : null;
        } catch (error) {
            console.error('Error fetching IP info:', error);
            return null;
        }
    };

    /**
     * Show IP Details modal with full geolocation info
     * @param {string} ipAddress - IP address to show details for
     */
    window.showIpDetails = async function(ipAddress) {
        if (!ipAddress) {
            showToast('No IP address provided', 'error');
            return;
        }

        // Show loading toast
        const loadingToast = showToast(`Loading details for ${ipAddress}...`, 'info', 0);

        try {
            // Fetch IP status and geolocation info in parallel
            const [status, geoInfo] = await Promise.all([
                window.checkIpStatus(ipAddress),
                window.fetchIpInfo(ipAddress)
            ]);

            // Remove loading toast
            if (loadingToast) loadingToast.remove();

            // Build status badges
            const statusBadges = [];
            if (status && status.is_blocked) {
                statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #D83B01; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Blocked</span>');
            }
            if (status && status.is_whitelisted) {
                statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #107C10; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Whitelisted</span>');
            }
            if (status && status.is_watched) {
                statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #FFB900; color: #323130; border-radius: 3px; font-size: 11px; margin-right: 5px;">Watched</span>');
            }
            if (geoInfo && geoInfo.is_proxy) {
                statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #8764B8; color: white; border-radius: 3px; font-size: 11px; margin-right: 5px;">Proxy/VPN</span>');
            }
            if (statusBadges.length === 0) {
                statusBadges.push('<span style="display: inline-block; padding: 4px 8px; background: #605E5C; color: white; border-radius: 3px; font-size: 11px;">No Special Status</span>');
            }

            // Build geolocation section
            let geoSection = '';
            if (geoInfo && geoInfo.success) {
                const flagEmoji = geoInfo.country_code && geoInfo.country_code !== 'N/A'
                    ? `<img src="https://flagcdn.com/24x18/${geoInfo.country_code.toLowerCase()}.png" alt="${geoInfo.country_code}" style="vertical-align: middle; margin-right: 6px;">`
                    : '';

                geoSection = `
                    <div style="border-top: 1px solid var(--border, #e0e0e0); padding-top: 16px; margin-top: 8px;">
                        <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px; font-weight: 600;">GEOLOCATION</div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">Country</div>
                                <div style="font-size: 13px; font-weight: 500;">${flagEmoji}${escapeHtml(geoInfo.country || 'Unknown')} (${escapeHtml(geoInfo.country_code || 'N/A')})</div>
                            </div>
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">City</div>
                                <div style="font-size: 13px; font-weight: 500;">${escapeHtml(geoInfo.city || 'Unknown')}</div>
                            </div>
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">Region</div>
                                <div style="font-size: 13px; font-weight: 500;">${escapeHtml(geoInfo.region || 'Unknown')}</div>
                            </div>
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">Timezone</div>
                                <div style="font-size: 13px; font-weight: 500;">${escapeHtml(geoInfo.timezone || 'N/A')}</div>
                            </div>
                        </div>
                    </div>
                    <div style="border-top: 1px solid var(--border, #e0e0e0); padding-top: 16px; margin-top: 16px;">
                        <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px; font-weight: 600;">NETWORK</div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">ISP / Organization</div>
                                <div style="font-size: 13px; font-weight: 500;">${escapeHtml(geoInfo.isp || 'Unknown')}</div>
                            </div>
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">ASN</div>
                                <div style="font-size: 13px; font-weight: 500;">AS${escapeHtml(geoInfo.asn || 'N/A')}</div>
                            </div>
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">Coordinates</div>
                                <div style="font-size: 13px; font-weight: 500;">${geoInfo.latitude || 0}, ${geoInfo.longitude || 0}</div>
                            </div>
                            <div>
                                <div style="font-size: 11px; color: var(--text-secondary);">Continent</div>
                                <div style="font-size: 13px; font-weight: 500;">${escapeHtml(geoInfo.continent || 'Unknown')}</div>
                            </div>
                        </div>
                    </div>
                `;
            } else {
                geoSection = `
                    <div style="border-top: 1px solid var(--border, #e0e0e0); padding-top: 16px; margin-top: 8px;">
                        <div style="font-size: 12px; color: var(--text-secondary); text-align: center;">
                            Geolocation info unavailable
                        </div>
                    </div>
                `;
            }

            const content = `
                <div style="padding: 0;">
                    <div style="display: grid; gap: 16px;">
                        <div>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">IP Address</div>
                            <div style="font-family: monospace; font-size: 18px; font-weight: 600;">${escapeHtml(ipAddress)}</div>
                        </div>
                        <div>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 8px;">Status</div>
                            <div>${statusBadges.join('')}</div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
                            <div style="background: var(--hover-bg, #f5f5f5); padding: 12px; border-radius: 4px;">
                                <div style="font-size: 24px; font-weight: 600; color: #0078D4;">${status?.notes_count || 0}</div>
                                <div style="font-size: 12px; color: var(--text-secondary);">Notes</div>
                            </div>
                            <div style="background: var(--hover-bg, #f5f5f5); padding: 12px; border-radius: 4px;">
                                <div style="font-size: 24px; font-weight: 600; color: #F7630C;">${status?.reports_count || 0}</div>
                                <div style="font-size: 12px; color: var(--text-secondary);">Reports</div>
                            </div>
                        </div>
                        ${geoSection}
                    </div>
                </div>
            `;

            showActionModal(`IP Details: ${ipAddress}`, content, null, {
                showCancel: false,
                confirmText: 'Close'
            });

        } catch (error) {
            if (loadingToast) loadingToast.remove();
            console.error('Error loading IP details:', error);
            showToast('Error loading IP details', 'error');
        }
    };

})();
