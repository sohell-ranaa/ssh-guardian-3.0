/**
 * SSH Guardian v3.0 - Notification Pane Module
 * Facebook-style notification dropdown with real-time updates
 */

window.NotificationPane = {
    isOpen: false,
    pollInterval: null,
    pollIntervalMs: 30000, // 30 seconds
    notifications: [],
    unreadCount: 0,

    /**
     * Initialize the notification pane
     */
    init() {
        console.log('[NotificationPane] Initializing...');

        // Load initial unread count
        this.loadUnreadCount();

        // Start polling for new notifications
        this.startPolling();

        // Setup click outside to close
        this.setupClickOutside();

        // Setup keyboard escape to close
        this.setupKeyboardClose();

        // Setup event delegation for notification clicks
        this.setupEventDelegation();

        console.log('[NotificationPane] Initialized successfully');
    },

    /**
     * Load unread notification count for badge
     */
    async loadUnreadCount() {
        try {
            const response = await fetch('/api/notifications/unread-count');
            const data = await response.json();

            if (data.success) {
                this.unreadCount = data.data?.count || 0;
                this.updateBadge(this.unreadCount);
            }
        } catch (error) {
            console.error('[NotificationPane] Error loading unread count:', error);
        }
    },

    /**
     * Update the notification badge
     */
    updateBadge(count) {
        const badge = document.getElementById('notificationBadge');
        if (!badge) return;

        if (count > 0) {
            badge.textContent = count > 99 ? '99+' : count;
            badge.classList.remove('hidden');
            badge.style.display = 'flex';
        } else {
            badge.classList.add('hidden');
            badge.style.display = 'none';
        }
    },

    /**
     * Toggle the notification pane
     */
    toggle() {
        if (this.isOpen) {
            this.close();
        } else {
            this.open();
        }
    },

    /**
     * Open the notification pane
     */
    async open() {
        const pane = document.getElementById('notificationPane');
        const overlay = document.getElementById('notificationOverlay');

        if (!pane) return;

        // Show loading state
        this.showLoading();

        pane.classList.add('open');
        pane.style.display = 'block';
        if (overlay) overlay.classList.add('active');

        this.isOpen = true;

        // Load notifications
        await this.loadNotifications();
    },

    /**
     * Close the notification pane
     */
    close() {
        const pane = document.getElementById('notificationPane');
        const overlay = document.getElementById('notificationOverlay');

        if (!pane) return;

        pane.classList.remove('open');
        pane.style.display = 'none';
        if (overlay) overlay.classList.remove('active');

        this.isOpen = false;
    },

    /**
     * Show loading spinner in pane
     */
    showLoading() {
        const container = document.getElementById('notificationList');
        if (!container) return;

        container.innerHTML = `
            <div class="pane-loading">
                <div class="pane-loading-spinner"></div>
                <p>Loading notifications...</p>
            </div>
        `;
    },

    /**
     * Load notifications for the pane
     */
    async loadNotifications() {
        try {
            const response = await fetch('/api/notifications/recent?limit=20');
            const data = await response.json();

            if (data.success) {
                this.notifications = data.data?.notifications || [];
                this.renderNotifications(this.notifications);
            } else {
                this.showError('Failed to load notifications');
            }
        } catch (error) {
            console.error('[NotificationPane] Error loading notifications:', error);
            this.showError('Failed to load notifications');
        }
    },

    /**
     * Render notifications in the pane
     */
    renderNotifications(notifications) {
        const container = document.getElementById('notificationList');
        if (!container) return;

        if (!notifications || notifications.length === 0) {
            container.innerHTML = `
                <div class="pane-empty">
                    <div class="pane-empty-icon">&#128276;</div>
                    <p class="pane-empty-text">No notifications yet</p>
                </div>
            `;
            return;
        }

        container.innerHTML = notifications.map(n => this.renderNotificationItem(n)).join('');
    },

    /**
     * Render a single notification item
     */
    renderNotificationItem(notification) {
        const isUnread = !notification.is_read;
        const priority = notification.priority || 'normal';
        const timeAgo = this.formatTimeAgo(notification.created_at);

        // Strip HTML and truncate body
        let title = this.stripHtml(notification.message_title || '');
        let body = this.stripHtml(notification.message_body || '');
        if (body.length > 120) {
            body = body.substring(0, 120) + '...';
        }

        // Store IP and event ID as data attributes for click handling
        const ipAddress = notification.ip_address || '';
        const eventId = notification.trigger_event_id || '';
        const triggerType = notification.trigger_type || '';

        return `
            <div class="notification-item ${isUnread ? 'unread' : ''} ${priority}"
                 data-id="${notification.id}"
                 data-ip="${this.escapeHtml(ipAddress)}"
                 data-event-id="${eventId}"
                 data-trigger-type="${this.escapeHtml(triggerType)}">
                <div class="notification-content">
                    <h4 class="notification-title">${this.escapeHtml(title)}</h4>
                    <p class="notification-body">${this.escapeHtml(body)}</p>
                </div>
                <div class="notification-meta">
                    <span class="notification-time">${timeAgo}</span>
                    <span class="notification-priority ${priority}">${priority}</span>
                </div>
                <div class="notification-actions">
                    ${!notification.is_read ? `<button class="notification-action-btn" data-action="mark-read">Mark Read</button>` : ''}
                    ${eventId ? `<button class="notification-action-btn" data-action="view-event">View Event</button>` : ''}
                    ${this.shouldShowBlockIP(triggerType, ipAddress) ? `<button class="notification-action-btn danger" data-action="block-ip">Block IP</button>` : ''}
                    <button class="notification-action-btn" data-action="delete">Delete</button>
                </div>
            </div>
        `;
    },

    /**
     * Check if Block IP button should be shown
     */
    shouldShowBlockIP(triggerType, ipAddress) {
        if (!ipAddress) return false;
        const threatTypes = ['high_risk_detected', 'brute_force_detected', 'failed_auth', 'suspicious_activity'];
        return threatTypes.includes(triggerType);
    },

    /**
     * Setup event delegation for notification actions
     */
    setupEventDelegation() {
        const container = document.getElementById('notificationList');
        if (!container) return;

        container.addEventListener('click', (event) => {
            const target = event.target;
            const notificationItem = target.closest('.notification-item');

            if (!notificationItem) return;

            const notificationId = parseInt(notificationItem.dataset.id);
            const ipAddress = notificationItem.dataset.ip;
            const eventId = notificationItem.dataset.eventId;

            // Handle action button clicks
            if (target.classList.contains('notification-action-btn')) {
                event.stopPropagation();
                const action = target.dataset.action;

                switch (action) {
                    case 'mark-read':
                        this.markRead(notificationId, target);
                        break;
                    case 'view-event':
                        this.viewEvent(eventId);
                        break;
                    case 'block-ip':
                        this.blockIP(ipAddress, notificationId, target);
                        break;
                    case 'delete':
                        this.deleteNotification(notificationId);
                        break;
                }
                return;
            }

            // Handle click on notification item itself
            this.handleItemClick(notificationId, eventId);
        });
    },

    /**
     * Handle click on notification item (not on buttons)
     */
    handleItemClick(notificationId, eventId) {
        // Mark as read
        this.markRead(notificationId);

        // Navigate to event if available
        if (eventId) {
            this.close();
            window.location.hash = `events-live?event=${eventId}`;
        }
    },

    /**
     * Mark a notification as read
     */
    async markRead(notificationId, buttonElement) {
        try {
            const response = await fetch(`/api/notifications/${notificationId}/read`, {
                method: 'POST'
            });
            const data = await response.json();

            if (data.success) {
                // Update UI
                const item = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
                if (item) {
                    item.classList.remove('unread');
                    // Remove the Mark Read button
                    const markReadBtn = item.querySelector('[data-action="mark-read"]');
                    if (markReadBtn) {
                        markReadBtn.remove();
                    }
                }

                // Update badge
                this.unreadCount = Math.max(0, this.unreadCount - 1);
                this.updateBadge(this.unreadCount);
            }
        } catch (error) {
            console.error('[NotificationPane] Error marking as read:', error);
        }
    },

    /**
     * Mark all notifications as read
     */
    async markAllRead() {
        try {
            const response = await fetch('/api/notifications/mark-all-read', {
                method: 'POST'
            });
            const data = await response.json();

            if (data.success) {
                // Update UI - remove unread class from all items
                document.querySelectorAll('.notification-item.unread').forEach(item => {
                    item.classList.remove('unread');
                });

                // Remove all "Mark Read" buttons
                document.querySelectorAll('[data-action="mark-read"]').forEach(btn => {
                    btn.remove();
                });

                // Update badge
                this.unreadCount = 0;
                this.updateBadge(0);

                // Show success message (optional)
                console.log(`[NotificationPane] Marked ${data.data?.marked_read_count || 0} notifications as read`);
            }
        } catch (error) {
            console.error('[NotificationPane] Error marking all as read:', error);
        }
    },

    /**
     * Delete a notification
     */
    async deleteNotification(notificationId) {
        try {
            const response = await fetch(`/api/notifications/${notificationId}`, {
                method: 'DELETE'
            });
            const data = await response.json();

            if (data.success) {
                // Remove from UI with animation
                const item = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
                if (item) {
                    item.style.opacity = '0';
                    item.style.transform = 'translateX(20px)';
                    setTimeout(() => {
                        item.remove();

                        // Check if list is empty
                        const container = document.getElementById('notificationList');
                        if (container && container.querySelectorAll('.notification-item').length === 0) {
                            this.renderNotifications([]);
                        }
                    }, 200);
                }

                // Update notifications array
                this.notifications = this.notifications.filter(n => n.id !== notificationId);
            }
        } catch (error) {
            console.error('[NotificationPane] Error deleting notification:', error);
        }
    },

    /**
     * View event associated with notification
     */
    viewEvent(eventId) {
        this.close();
        window.location.hash = `events-live?event=${eventId}`;
    },

    /**
     * Block an IP address from notification
     */
    async blockIP(ipAddress, notificationId, buttonElement) {
        if (!confirm(`Block IP address ${ipAddress}?`)) {
            return;
        }

        try {
            const response = await fetch(`/api/notifications/${notificationId}/action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    action: 'block_ip',
                    ip_address: ipAddress
                })
            });

            const data = await response.json();

            if (data.success) {
                if (data.data?.already_blocked) {
                    alert(`IP ${ipAddress} is already blocked.`);
                } else if (data.data?.blocked) {
                    alert(`IP ${ipAddress} has been blocked successfully.`);

                    // Update button
                    if (buttonElement) {
                        buttonElement.textContent = 'Blocked';
                        buttonElement.disabled = true;
                        buttonElement.classList.remove('danger');
                    }
                }
            } else {
                alert(`Failed to block IP: ${data.error}`);
            }
        } catch (error) {
            console.error('[NotificationPane] Error blocking IP:', error);
            alert('Failed to block IP. Please try again.');
        }
    },

    /**
     * Setup click outside to close pane
     */
    setupClickOutside() {
        document.addEventListener('click', (event) => {
            if (!this.isOpen) return;

            const pane = document.getElementById('notificationPane');
            const bell = document.getElementById('notificationBell');

            if (!pane || !bell) return;

            // Check if click is outside pane and bell
            if (!pane.contains(event.target) && !bell.contains(event.target)) {
                this.close();
            }
        });
    },

    /**
     * Setup keyboard escape to close
     */
    setupKeyboardClose() {
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && this.isOpen) {
                this.close();
            }
        });
    },

    /**
     * Start polling for new notifications
     */
    startPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
        }

        this.pollInterval = setInterval(() => {
            this.loadUnreadCount();

            // If pane is open, also refresh the list
            if (this.isOpen) {
                this.loadNotifications();
            }
        }, this.pollIntervalMs);
    },

    /**
     * Stop polling
     */
    stopPolling() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
    },

    /**
     * Show error message in pane
     */
    showError(message) {
        const container = document.getElementById('notificationList');
        if (!container) return;

        container.innerHTML = `
            <div class="pane-empty">
                <div class="pane-empty-icon">&#9888;</div>
                <p class="pane-empty-text">${message}</p>
            </div>
        `;
    },

    /**
     * Format timestamp to relative time
     */
    formatTimeAgo(timestamp) {
        if (!timestamp) return '';

        // Ensure UTC parsing - append Z if no timezone info
        let dateStr = String(timestamp);
        if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.includes('-', 10)) {
            dateStr += 'Z';
        }
        const date = new Date(dateStr);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        if (seconds < 60) return 'Just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;

        // For older dates, show the date
        return date.toLocaleDateString();
    },

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Strip HTML tags and emojis, clean text for display
     */
    stripHtml(text) {
        if (!text) return '';
        // Remove HTML tags
        let cleaned = text.replace(/<[^>]*>/g, '');
        // Remove common emojis
        cleaned = cleaned.replace(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]|[\u{1F600}-\u{1F64F}]|[\u{1F680}-\u{1F6FF}]|[\u{1F1E0}-\u{1F1FF}]/gu, '');
        // Clean up extra whitespace
        cleaned = cleaned.replace(/\n{3,}/g, '\n\n').trim();
        // Decode HTML entities
        const textarea = document.createElement('textarea');
        textarea.innerHTML = cleaned;
        return textarea.value;
    }
};

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    // Small delay to ensure all elements are rendered
    setTimeout(() => {
        NotificationPane.init();
    }, 500);
});
