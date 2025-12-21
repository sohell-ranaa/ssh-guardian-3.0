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
     * Update the notification badge and pane count
     */
    updateBadge(count) {
        const badge = document.getElementById('notificationBadge');
        const paneCount = document.getElementById('paneUnreadCount');

        if (badge) {
            if (count > 0) {
                badge.textContent = count > 99 ? '99+' : count;
                badge.classList.remove('hidden');
                badge.style.display = 'flex';
            } else {
                badge.classList.add('hidden');
                badge.style.display = 'none';
            }
        }

        if (paneCount) {
            paneCount.textContent = count > 0 ? `${count} unread` : '';
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

        // Mark all as read silently (just update backend, keep showing notifications)
        this.markAllReadSilent();
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
     * Load notifications for the pane (unread only)
     */
    async loadNotifications() {
        try {
            const response = await fetch('/api/notifications/recent?limit=20&unread_only=true');
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
     * Category definitions for grouping notifications
     */
    categories: {
        security: {
            label: 'Security Alerts',
            icon: '🛡️',
            types: ['high_risk_detected', 'brute_force_detected', 'suspicious_activity', 'failed_auth', 'brute_force', 'distributed_brute_force', 'account_takeover', 'credential_stuffing']
        },
        blocking: {
            label: 'IP Blocking',
            icon: '🚫',
            types: ['ip_blocked', 'ip_unblocked', 'auto_blocked', 'manual_block']
        },
        system: {
            label: 'System',
            icon: '⚙️',
            types: ['system', 'agent_status', 'config_change', 'service_status']
        },
        other: {
            label: 'Other',
            icon: '📋',
            types: []
        }
    },

    /**
     * Get category for a notification based on trigger_type
     */
    getCategory(triggerType) {
        for (const [key, cat] of Object.entries(this.categories)) {
            if (cat.types.includes(triggerType)) {
                return key;
            }
        }
        return 'other';
    },

    /**
     * Group notifications by category
     */
    groupByCategory(notifications) {
        const groups = {};

        notifications.forEach(n => {
            const category = this.getCategory(n.trigger_type || '');
            if (!groups[category]) {
                groups[category] = [];
            }
            groups[category].push(n);
        });

        return groups;
    },

    /**
     * Current active tab
     */
    activeTab: 'all',

    /**
     * Render notifications in the pane with tabs
     */
    renderNotifications(notifications) {
        const container = document.getElementById('notificationList');
        if (!container) return;

        if (!notifications || notifications.length === 0) {
            container.innerHTML = `
                <div class="pane-empty">
                    <div class="pane-empty-icon">✓</div>
                    <p class="pane-empty-text">All caught up!</p>
                    <p style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">No unread notifications</p>
                </div>
            `;
            return;
        }

        // Group notifications by category
        const grouped = this.groupByCategory(notifications);

        // Build tabs
        const categoryOrder = ['security', 'blocking', 'system', 'other'];
        let tabsHtml = `
            <div class="notif-tabs">
                <button class="notif-tab ${this.activeTab === 'all' ? 'active' : ''}" data-tab="all">
                    All <span class="tab-count">${notifications.length}</span>
                </button>
        `;

        categoryOrder.forEach(catKey => {
            const count = grouped[catKey]?.length || 0;
            if (count > 0) {
                const cat = this.categories[catKey];
                tabsHtml += `
                    <button class="notif-tab ${this.activeTab === catKey ? 'active' : ''}" data-tab="${catKey}">
                        ${cat.icon} <span class="tab-count">${count}</span>
                    </button>
                `;
            }
        });
        tabsHtml += '</div>';

        // Build notification list based on active tab
        let itemsHtml = '<div class="notif-items">';
        const itemsToShow = this.activeTab === 'all'
            ? notifications
            : (grouped[this.activeTab] || []);

        itemsHtml += itemsToShow.map(n => this.renderNotificationItem(n)).join('');
        itemsHtml += '</div>';

        container.innerHTML = tabsHtml + itemsHtml;

        // Add tab click handlers
        container.querySelectorAll('.notif-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.activeTab = e.currentTarget.dataset.tab;
                this.renderNotifications(this.notifications);
            });
        });
    },

    /**
     * Render a single notification item (all shown are unread)
     */
    renderNotificationItem(notification) {
        const priority = notification.priority || 'normal';
        const timeAgo = this.formatTimeAgo(notification.created_at);

        // Strip HTML and truncate body
        let title = this.stripHtml(notification.message_title || '');
        let body = this.stripHtml(notification.message_body || '');
        if (body.length > 80) {
            body = body.substring(0, 80) + '...';
        }

        // Store IP and event ID as data attributes for click handling
        const ipAddress = notification.ip_address || '';
        const eventId = notification.trigger_event_id || '';
        const triggerType = notification.trigger_type || '';

        return `
            <div class="notification-item ${priority}"
                 data-id="${notification.id}"
                 data-ip="${this.escapeHtml(ipAddress)}"
                 data-event-id="${eventId}"
                 data-trigger-type="${this.escapeHtml(triggerType)}">
                <div class="notification-main">
                    <div class="notification-content">
                        <h4 class="notification-title">${this.escapeHtml(title)}</h4>
                        ${body ? `<p class="notification-body">${this.escapeHtml(body)}</p>` : ''}
                    </div>
                    <div class="notification-actions-mini">
                        <button class="notification-btn-mini" data-action="mark-read" title="Mark as read">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                        </button>
                        <button class="notification-btn-mini danger" data-action="delete" title="Delete">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M18 6L6 18M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                </div>
                <div class="notification-meta">
                    <span class="notification-time">${timeAgo}</span>
                    ${ipAddress ? `<span class="notification-ip">${this.escapeHtml(ipAddress)}</span>` : ''}
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
            const actionBtn = target.closest('.notification-btn-mini') || target.closest('.notification-action-btn');
            const notificationItem = target.closest('.notification-item');

            if (!notificationItem) return;

            const notificationId = parseInt(notificationItem.dataset.id);
            const ipAddress = notificationItem.dataset.ip;
            const eventId = notificationItem.dataset.eventId;

            // Handle action button clicks
            if (actionBtn) {
                event.stopPropagation();
                const action = actionBtn.dataset.action;

                switch (action) {
                    case 'mark-read':
                        this.markRead(notificationId, actionBtn);
                        break;
                    case 'view-event':
                        this.viewEvent(eventId);
                        break;
                    case 'block-ip':
                        this.blockIP(ipAddress, notificationId, actionBtn);
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
        // Find the notification data
        const notification = this.notifications.find(n => n.id === notificationId);
        if (notification) {
            this.showNotificationDetail(notification);
        }
    },

    /**
     * Show notification detail modal - enhanced with more info like event detail modal
     */
    showNotificationDetail(notification) {
        // Remove existing detail modal if any
        const existing = document.getElementById('notificationDetailModal');
        if (existing) existing.remove();

        const priority = notification.priority || 'normal';
        const timeAgo = this.formatTimeAgo(notification.created_at);
        const title = this.stripHtml(notification.message_title || 'Notification');
        const body = this.stripHtml(notification.message_body || '');
        const ipAddress = notification.ip_address || '';
        const username = notification.username || '';
        const agentName = notification.agent_name || '';
        const triggerType = notification.trigger_type || '';
        const category = this.getCategory(triggerType);
        const categoryInfo = this.categories[category];
        const mlScore = notification.ml_score || 0;
        const mlFactors = notification.ml_factors || [];
        const geoData = notification.geo_data || {};
        const channel = notification.channel || '';
        const ruleName = notification.rule_name || '';

        // Priority badge styling
        const priorityBadge = {
            critical: { bg: TC.dangerBg, color: TC.danger, label: 'CRITICAL' },
            high: { bg: TC.warningBg, color: TC.orange, label: 'HIGH' },
            normal: { bg: TC.primaryBg, color: TC.primary, label: 'NORMAL' },
            low: { bg: TC.successBg, color: TC.teal, label: 'LOW' }
        }[priority] || { bg: 'var(--surface-alt)', color: TC.textSecondary, label: 'INFO' };

        // Build sections
        let sectionsHtml = '';

        // Event Info Section
        sectionsHtml += `
            <div class="detail-section">
                <div class="detail-section-title">Event Information</div>
                <div class="detail-grid">
                    ${ipAddress ? `<div><span class="detail-label">IP Address:</span> <span style="font-family: monospace;">${this.escapeHtml(ipAddress)}</span></div>` : ''}
                    ${username ? `<div><span class="detail-label">Username:</span> ${this.escapeHtml(username)}</div>` : ''}
                    ${agentName ? `<div><span class="detail-label">Agent:</span> ${this.escapeHtml(agentName)}</div>` : ''}
                    ${channel ? `<div><span class="detail-label">Channel:</span> ${this.escapeHtml(channel)}</div>` : ''}
                    ${ruleName ? `<div><span class="detail-label">Rule:</span> ${this.escapeHtml(ruleName)}</div>` : ''}
                    <div><span class="detail-label">Time:</span> ${timeAgo}</div>
                </div>
            </div>
        `;

        // Location Section (if geo_data exists)
        if (geoData && (geoData.country || geoData.city)) {
            sectionsHtml += `
                <div class="detail-section">
                    <div class="detail-section-title">Location</div>
                    <div class="detail-grid">
                        ${geoData.country ? `<div><span class="detail-label">Country:</span> ${this.escapeHtml(geoData.country)} ${geoData.country_code ? `(${geoData.country_code})` : ''}</div>` : ''}
                        ${geoData.city ? `<div><span class="detail-label">City:</span> ${this.escapeHtml(geoData.city)}</div>` : ''}
                        ${geoData.isp ? `<div><span class="detail-label">ISP:</span> ${this.escapeHtml(geoData.isp)}</div>` : ''}
                    </div>
                </div>
            `;
        }

        // ML Score Section (if ml_score exists)
        if (mlScore > 0) {
            const scoreClass = mlScore >= 80 ? 'critical' : mlScore >= 60 ? 'high' : mlScore >= 40 ? 'moderate' : 'low';
            const scoreColor = mlScore >= 80 ? TC.danger : mlScore >= 60 ? TC.orange : mlScore >= 40 ? TC.primary : TC.teal;

            sectionsHtml += `
                <div class="detail-section">
                    <div class="detail-section-title">ML Risk Assessment</div>
                    <div style="display: flex; align-items: center; gap: 16px; margin-bottom: 12px;">
                        <div style="width: 60px; height: 60px; border-radius: 50%; background: ${scoreColor}15; display: flex; align-items: center; justify-content: center; flex-direction: column;">
                            <span style="font-size: 20px; font-weight: 700; color: ${scoreColor};">${mlScore}</span>
                        </div>
                        <div>
                            <div style="font-weight: 600; color: var(--text-primary);">Risk Score</div>
                            <div style="font-size: 12px; color: var(--text-secondary);">${scoreClass.charAt(0).toUpperCase() + scoreClass.slice(1)} Risk</div>
                        </div>
                    </div>
                    ${mlFactors && mlFactors.length > 0 ? `
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                            ${mlFactors.map(f => `<span style="padding: 4px 8px; background: var(--surface-alt); border: 1px solid var(--border); border-radius: 4px; font-size: 11px; color: var(--text-secondary);">${this.escapeHtml(f)}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        }

        // Message Section
        sectionsHtml += `
            <div class="detail-section">
                <div class="detail-section-title">Message</div>
                <div style="background: var(--surface-alt); padding: 12px; border-radius: 6px; border: 1px solid var(--border); font-size: 13px; line-height: 1.6; white-space: pre-wrap; max-height: 150px; overflow-y: auto;">
                    ${this.escapeHtml(body || 'No message content')}
                </div>
            </div>
        `;

        const modal = document.createElement('div');
        modal.id = 'notificationDetailModal';
        modal.className = 'notif-detail-overlay';
        modal.innerHTML = `
            <div class="notif-detail-modal" style="max-width: 560px;">
                <div class="notif-detail-header" style="display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid var(--border);">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span style="font-size: 20px;">${categoryInfo.icon}</span>
                        <div>
                            <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: var(--text-primary);">${this.escapeHtml(title)}</h3>
                            <div style="display: flex; gap: 8px; margin-top: 4px;">
                                <span style="padding: 2px 8px; font-size: 10px; font-weight: 600; border-radius: 4px; background: ${priorityBadge.bg}; color: ${priorityBadge.color};">${priorityBadge.label}</span>
                                <span style="font-size: 12px; color: var(--text-secondary);">${categoryInfo.label}</span>
                            </div>
                        </div>
                    </div>
                    <button class="notif-detail-close" onclick="NotificationPane.closeDetail()" style="background: none; border: none; font-size: 24px; color: var(--text-secondary); cursor: pointer; padding: 4px;">&times;</button>
                </div>
                <div class="notif-detail-body" style="padding: 20px; max-height: 60vh; overflow-y: auto;">
                    ${sectionsHtml}
                </div>
                <div class="notif-detail-footer" style="display: flex; justify-content: flex-end; gap: 8px; padding: 16px 20px; border-top: 1px solid var(--border);">
                    <button class="btn btn-secondary" onclick="NotificationPane.closeDetail()">Close</button>
                    <button class="btn btn-primary" onclick="NotificationPane.markReadAndClose(${notification.id})">
                        Mark as Read
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Close on overlay click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeDetail();
            }
        });

        // Close on escape
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                this.closeDetail();
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    },

    /**
     * Close notification detail modal
     */
    closeDetail() {
        const modal = document.getElementById('notificationDetailModal');
        if (modal) {
            modal.remove();
        }
    },

    /**
     * Mark notification as read and close detail modal
     */
    markReadAndClose(notificationId) {
        this.markRead(notificationId);
        this.closeDetail();
    },

    /**
     * Mark a notification as read and remove from pane
     */
    async markRead(notificationId, buttonElement) {
        try {
            const response = await fetch(`/api/notifications/${notificationId}/read`, {
                method: 'POST'
            });
            const data = await response.json();

            if (data.success) {
                this.removeNotificationFromUI(notificationId);

                // Update notifications array
                this.notifications = this.notifications.filter(n => n.id !== notificationId);

                // Update badge
                this.unreadCount = Math.max(0, this.unreadCount - 1);
                this.updateBadge(this.unreadCount);

                // Sync with history page if it's visible
                this.syncHistoryPage();
            }
        } catch (error) {
            console.error('[NotificationPane] Error marking as read:', error);
        }
    },

    /**
     * Sync with history page stats
     */
    syncHistoryPage() {
        // Update history page unread stat if visible
        const unreadEl = document.getElementById('stat-notif-unread');
        if (unreadEl) {
            unreadEl.textContent = this.unreadCount.toLocaleString();
        }
    },

    /**
     * Remove notification from UI with animation
     */
    removeNotificationFromUI(notificationId) {
        const item = document.querySelector(`.notification-item[data-id="${notificationId}"]`);
        if (!item) return;

        item.style.opacity = '0';
        item.style.transform = 'translateX(-20px)';
        item.style.transition = 'all 0.2s ease';

        setTimeout(() => {
            item.remove();

            // Re-render to update tab counts
            this.renderNotifications(this.notifications);
        }, 200);
    },

    /**
     * Mark all as read silently (update backend + badge, keep list visible)
     */
    async markAllReadSilent() {
        try {
            const response = await fetch('/api/notifications/mark-all-read', {
                method: 'POST'
            });
            const data = await response.json();
            if (data.success) {
                this.unreadCount = 0;
                this.updateBadge(0);
            }
        } catch (error) {
            console.error('[NotificationPane] Error marking as read:', error);
        }
    },

    /**
     * Mark all notifications as read and clear list
     */
    async markAllRead() {
        try {
            const response = await fetch('/api/notifications/mark-all-read', {
                method: 'POST'
            });
            const data = await response.json();

            if (data.success) {
                // Clear the notifications array
                this.notifications = [];

                // Update badge
                this.unreadCount = 0;
                this.updateBadge(0);

                // Show empty state
                this.renderNotifications([]);

                // Sync with history page
                this.syncHistoryPage();

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
                this.removeNotificationFromUI(notificationId);

                // Update notifications array and badge
                const wasUnread = this.notifications.find(n => n.id === notificationId);
                this.notifications = this.notifications.filter(n => n.id !== notificationId);

                if (wasUnread) {
                    this.unreadCount = Math.max(0, this.unreadCount - 1);
                    this.updateBadge(this.unreadCount);
                    this.syncHistoryPage();
                }
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
        // Use TimeSettings for proper timezone handling
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.relative(timestamp);
        }
        // Server timestamps are in +08:00 (Asia/Kuala_Lumpur)
        let dateStr = String(timestamp).replace(' ', 'T');
        if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.match(/T\d{2}:\d{2}:\d{2}-/)) {
            dateStr += '+08:00';
        }
        const date = new Date(dateStr);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        if (seconds < 0) return 'Just now';
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
        // Convert literal \n to actual newlines
        let cleaned = text.replace(/\\n/g, '\n');
        // Remove HTML tags
        cleaned = cleaned.replace(/<[^>]*>/g, '');
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
