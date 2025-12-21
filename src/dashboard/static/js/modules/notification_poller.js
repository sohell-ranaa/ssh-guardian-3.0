/**
 * SSH Guardian v3.0 - Real-time Notification Poller
 * Polls for auto-block notifications and displays toast alerts
 */

const NotificationPoller = {
    pollInterval: null,
    pollDelay: 10000, // 10 seconds
    seenNotifications: new Set(),
    isPolling: false,

    start() {
        if (this.isPolling) return;
        this.isPolling = true;

        // Initial poll
        this.poll();

        // Start interval
        this.pollInterval = setInterval(() => this.poll(), this.pollDelay);
        console.log('[NotificationPoller] Started polling for notifications');
    },

    stop() {
        if (this.pollInterval) {
            clearInterval(this.pollInterval);
            this.pollInterval = null;
        }
        this.isPolling = false;
        console.log('[NotificationPoller] Stopped polling');
    },

    async poll() {
        try {
            const response = await fetch('/api/dashboard/block-events/notifications/unread?limit=10');
            const data = await response.json();

            if (data.success && data.notifications && data.notifications.length > 0) {
                this.processNotifications(data.notifications);
            }
        } catch (error) {
            console.error('[NotificationPoller] Poll error:', error);
        }
    },

    processNotifications(notifications) {
        notifications.forEach(notification => {
            // Skip if already seen
            if (this.seenNotifications.has(notification.uuid)) return;

            // Skip if already read
            if (notification.is_read) return;

            // Skip if no message content
            if (!notification.message || notification.message === 'Notification') return;

            // Mark as seen
            this.seenNotifications.add(notification.uuid);

            // Show toast based on notification type
            this.showNotificationToast(notification);

            // Mark as read on server
            this.markAsRead(notification.uuid);
        });

        // Keep seen set from growing too large
        if (this.seenNotifications.size > 100) {
            const arr = Array.from(this.seenNotifications);
            this.seenNotifications = new Set(arr.slice(-50));
        }
    },

    showNotificationToast(notification) {
        const type = notification.severity === 'critical' ? 'error' :
                     notification.severity === 'warning' ? 'warning' : 'info';

        // Build message with details
        let message = notification.message;
        const data = notification.data || {};

        if (data.threat_score) {
            message += ` | Score: ${data.threat_score}`;
        }

        if (data.factors && data.factors.length > 0) {
            message += ` | ${data.factors.slice(0, 2).join(', ')}`;
        }

        // Show toast with longer duration for auto-blocks
        const duration = notification.notification_type === 'auto_block' ? 8000 : 5000;

        if (typeof showToast === 'function') {
            showToast(message, type, duration);
        }

        // Also update notification badge if exists
        this.updateBadge();
    },

    updateBadge() {
        const badge = document.getElementById('notification-badge');
        if (badge) {
            const current = parseInt(badge.textContent) || 0;
            badge.textContent = current + 1;
            badge.style.display = 'flex';
        }
    },

    async markAsRead(uuid) {
        try {
            await fetch(`/api/dashboard/block-events/notifications/${uuid}/read`, {
                method: 'POST'
            });
        } catch (error) {
            console.error('[NotificationPoller] Mark read error:', error);
        }
    },

    async markAllRead() {
        try {
            const response = await fetch('/api/dashboard/block-events/notifications/mark-all-read', {
                method: 'POST'
            });
            const data = await response.json();

            if (data.success) {
                const badge = document.getElementById('notification-badge');
                if (badge) {
                    badge.textContent = '0';
                    badge.style.display = 'none';
                }
            }

            return data;
        } catch (error) {
            console.error('[NotificationPoller] Mark all read error:', error);
            return { success: false, error: error.message };
        }
    }
};

// Auto-start when page loads - DISABLED to prevent toast spam
// The NotificationPane handles the top-bar notification icon now
// document.addEventListener('DOMContentLoaded', () => {
//     setTimeout(() => NotificationPoller.start(), 2000);
// });

// Stop when page unloads
window.addEventListener('beforeunload', () => {
    NotificationPoller.stop();
});

// Global exports
window.NotificationPoller = NotificationPoller;
