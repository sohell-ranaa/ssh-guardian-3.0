/**
 * Notification History Page Module
 * Handles notification history display and filtering
 */

(function() {
    'use strict';

    let notifications = [];
    let triggerTypes = [];
    let currentPage = 1;
    let perPage = 50;
    let totalPages = 1;
    let currentFilters = {};

    /**
     * Load and display Notification History page
     */
    window.loadNotificationHistoryPage = async function() {
        try {
            // Load trigger types for filter dropdown
            await loadTriggerTypes();

            // Load stats
            await loadNotificationStats();

            // Load notifications
            await loadNotifications();

            // Setup event listeners
            setupEventListeners();

        } catch (error) {
            console.error('Error loading Notification History page:', error);
        }
    };

    /**
     * Load trigger types for filtering
     */
    async function loadTriggerTypes() {
        try {
            const response = await fetch('/api/dashboard/notification-history/trigger-types');
            const data = await response.json();

            if (data.success) {
                triggerTypes = data.data.trigger_types || [];
                renderTriggerTypeFilter();
            }
        } catch (error) {
            console.error('Error loading trigger types:', error);
        }
    }

    /**
     * Render trigger type filter dropdown
     */
    function renderTriggerTypeFilter() {
        const select = document.getElementById('notif-filter-trigger');
        if (!select) return;

        let html = '<option value="">All Triggers</option>';
        triggerTypes.forEach(trigger => {
            const label = formatTriggerLabel(trigger.trigger_type);
            html += `<option value="${trigger.trigger_type}">${label} (${trigger.count})</option>`;
        });

        select.innerHTML = html;
    }

    /**
     * Format trigger label for display
     */
    function formatTriggerLabel(trigger) {
        if (!trigger) return 'Unknown';
        return trigger
            .replace(/_/g, ' ')
            .replace(/\b\w/g, c => c.toUpperCase());
    }

    /**
     * Load notification statistics
     */
    async function loadNotificationStats() {
        try {
            const response = await fetch('/api/dashboard/notification-history/stats');
            const data = await response.json();

            if (data.success) {
                renderNotificationStats(data.data);
            }
        } catch (error) {
            console.error('Error loading notification stats:', error);
        }
    }

    /**
     * Render notification statistics
     */
    function renderNotificationStats(stats) {
        const container = document.getElementById('notif-history-stats');
        if (!container) return;

        const sentCount = stats.by_status?.sent || 0;
        const failedCount = stats.by_status?.failed || 0;
        const pendingCount = stats.by_status?.pending || 0;

        container.innerHTML = `
            <div class="stat-card">
                <div class="stat-value" style="color: #0078D4;">${stats.total.toLocaleString()}</div>
                <div class="stat-label">Total Notifications</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #107C10;">${stats.today.toLocaleString()}</div>
                <div class="stat-label">Today</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #107C10;">${sentCount.toLocaleString()}</div>
                <div class="stat-label">Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: ${failedCount > 0 ? '#D13438' : '#107C10'};">${failedCount.toLocaleString()}</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: #FF8C00;">${pendingCount.toLocaleString()}</div>
                <div class="stat-label">Pending</div>
            </div>
        `;
    }

    /**
     * Load notifications from API
     */
    async function loadNotifications() {
        const tbody = document.getElementById('notif-history-tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 40px; color: #605E5C;">Loading notifications...</td></tr>';
        }

        try {
            const params = new URLSearchParams({
                page: currentPage,
                per_page: perPage
            });

            // Add filters
            if (currentFilters.status) params.append('status', currentFilters.status);
            if (currentFilters.trigger_type) params.append('trigger_type', currentFilters.trigger_type);
            if (currentFilters.priority) params.append('priority', currentFilters.priority);
            if (currentFilters.channel) params.append('channel', currentFilters.channel);
            if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
            if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);
            if (currentFilters.search) params.append('search', currentFilters.search);

            // Use fetchWithCache if available to track cache status
            let data;
            if (typeof fetchWithCache === 'function') {
                data = await fetchWithCache(`/api/dashboard/notification-history/list?${params}`, 'notifications');
            } else {
                const response = await fetch(`/api/dashboard/notification-history/list?${params}`);
                data = await response.json();
            }

            if (data.success) {
                notifications = data.data.notifications || [];
                totalPages = data.data.total_pages || 1;
                renderNotifications();
                renderPagination(data.data);
            } else {
                throw new Error(data.error || 'Failed to load notifications');
            }

        } catch (error) {
            console.error('Error loading notifications:', error);
            if (tbody) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; padding: 40px; color: #D13438;">Failed to load notifications. Please try again.</td></tr>';
            }
        }
    }

    /**
     * Render notifications table
     */
    function renderNotifications() {
        const tbody = document.getElementById('notif-history-tbody');
        if (!tbody) return;

        if (!notifications || notifications.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="text-align: center; padding: 60px 20px; color: #605E5C;">
                        <div style="font-size: 48px; margin-bottom: 16px;">📭</div>
                        <div style="font-size: 16px; font-weight: 600; color: #323130;">No Notifications Found</div>
                        <div style="font-size: 14px; margin-top: 8px;">No notifications match your current filters</div>
                    </td>
                </tr>
            `;
            return;
        }

        let html = '';
        notifications.forEach(notif => {
            const statusClass = getStatusClass(notif.status);
            const priorityClass = getPriorityClass(notif.priority);
            const channels = parseChannels(notif.channels);
            const timeAgo = formatTimeAgo(notif.created_at);

            html += `
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9; font-family: monospace; font-size: 12px; color: #605E5C;">#${notif.id}</td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9; white-space: nowrap;">
                        <div style="font-size: 13px; color: #323130;">${timeAgo}</div>
                        <div style="font-size: 11px; color: #A19F9D;">${formatDateTime(notif.created_at)}</div>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9;">
                        <span style="font-size: 13px; color: #0078D4;">${notif.rule_name || 'N/A'}</span>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9;">
                        <span class="badge badge-outline">${formatTriggerLabel(notif.trigger_type)}</span>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9; max-width: 250px;">
                        <div style="font-size: 13px; font-weight: 500; color: #323130; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(notif.message_title || '')}</div>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9;">
                        ${renderChannelBadges(channels)}
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9;">
                        <span class="badge ${priorityClass}">${notif.priority || 'normal'}</span>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9;">
                        <span class="badge ${statusClass}">${notif.status || 'unknown'}</span>
                    </td>
                    <td style="padding: 12px; border-bottom: 1px solid #EDEBE9;">
                        <div style="display: flex; gap: 4px;">
                            <button onclick="viewNotificationDetails(${notif.id})" class="btn btn-sm btn-secondary" title="View Details">
                                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 3.5a4.5 4.5 0 0 0-4.5 4.5A4.5 4.5 0 0 0 8 12.5a4.5 4.5 0 0 0 4.5-4.5A4.5 4.5 0 0 0 8 3.5zm0 7a2.5 2.5 0 0 1-2.5-2.5A2.5 2.5 0 0 1 8 5.5a2.5 2.5 0 0 1 2.5 2.5A2.5 2.5 0 0 1 8 10.5z"/></svg>
                            </button>
                            ${notif.status === 'failed' ? `
                                <button onclick="retryNotification(${notif.id})" class="btn btn-sm btn-primary" title="Retry">
                                    <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M8 3V0L4 4l4 4V5c2.76 0 5 2.24 5 5s-2.24 5-5 5-5-2.24-5-5H1c0 3.87 3.13 7 7 7s7-3.13 7-7-3.13-7-7-7z"/></svg>
                                </button>
                            ` : ''}
                        </div>
                    </td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }

    /**
     * Parse channels JSON
     */
    function parseChannels(channelsJson) {
        try {
            if (typeof channelsJson === 'string') {
                return JSON.parse(channelsJson);
            }
            return channelsJson || [];
        } catch (e) {
            return [];
        }
    }

    /**
     * Render channel badges
     */
    function renderChannelBadges(channels) {
        if (!channels || channels.length === 0) return '<span style="color: #A19F9D;">-</span>';

        const icons = {
            telegram: '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm4.64 6.8c-.15 1.58-.8 5.42-1.13 7.19-.14.75-.42 1-.68 1.03-.58.05-1.02-.38-1.58-.75-.88-.58-1.38-.94-2.23-1.5-.99-.65-.35-1.01.22-1.59.15-.15 2.71-2.48 2.76-2.69a.2.2 0 0 0-.05-.18c-.06-.05-.14-.03-.21-.02-.09.02-1.49.95-4.22 2.79-.4.27-.76.41-1.08.4-.36-.01-1.04-.2-1.55-.37-.63-.2-1.12-.31-1.08-.66.02-.18.27-.36.74-.55 2.92-1.27 4.86-2.11 5.83-2.51 2.78-1.16 3.35-1.36 3.73-1.36.08 0 .27.02.39.12.1.08.13.19.14.27-.01.06.01.24 0 .38z"/></svg>',
            email: '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>',
            webhook: '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M10 15l5.88-4L10 7v8zm9.5-6.5l-7.5-4.5-7.5 4.5v9l7.5 4.5 7.5-4.5v-9z"/></svg>'
        };

        return channels.map(ch => {
            const icon = icons[ch] || '';
            const color = ch === 'telegram' ? '#0088cc' : ch === 'email' ? '#D13438' : '#107C10';
            return `<span style="display: inline-flex; align-items: center; gap: 4px; padding: 2px 8px; background: ${color}15; color: ${color}; border-radius: 4px; font-size: 11px; margin-right: 4px;">${icon} ${ch}</span>`;
        }).join('');
    }

    /**
     * Get status badge class
     */
    function getStatusClass(status) {
        const classes = {
            sent: 'badge-success',
            failed: 'badge-danger',
            pending: 'badge-warning',
            cancelled: 'badge-secondary'
        };
        return classes[status] || 'badge-secondary';
    }

    /**
     * Get priority badge class
     */
    function getPriorityClass(priority) {
        const classes = {
            critical: 'badge-danger',
            high: 'badge-warning',
            normal: 'badge-info',
            low: 'badge-secondary'
        };
        return classes[priority] || 'badge-secondary';
    }

    /**
     * Format time ago
     */
    function formatTimeAgo(dateStr) {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        return date.toLocaleDateString();
    }

    /**
     * Format date time
     */
    function formatDateTime(dateStr) {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        return date.toLocaleString();
    }

    /**
     * Escape HTML
     */
    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Render pagination
     */
    function renderPagination(data) {
        const container = document.getElementById('notif-history-pagination');
        if (!container) return;

        const { page, total_pages, total } = data;
        if (total_pages <= 1) {
            container.innerHTML = `<span style="color: #605E5C; font-size: 13px;">${total} notification${total !== 1 ? 's' : ''}</span>`;
            return;
        }

        let html = `<span style="color: #605E5C; font-size: 13px; margin-right: 16px;">${total} notification${total !== 1 ? 's' : ''}</span>`;

        // Previous button
        html += `<button class="btn btn-sm btn-secondary" ${page <= 1 ? 'disabled' : ''} onclick="goToNotifPage(${page - 1})">Prev</button>`;

        // Page numbers
        const startPage = Math.max(1, page - 2);
        const endPage = Math.min(total_pages, page + 2);

        if (startPage > 1) {
            html += `<button class="btn btn-sm btn-secondary" onclick="goToNotifPage(1)">1</button>`;
            if (startPage > 2) html += `<span style="padding: 0 8px; color: #605E5C;">...</span>`;
        }

        for (let i = startPage; i <= endPage; i++) {
            html += `<button class="btn btn-sm ${i === page ? 'btn-primary' : 'btn-secondary'}" onclick="goToNotifPage(${i})">${i}</button>`;
        }

        if (endPage < total_pages) {
            if (endPage < total_pages - 1) html += `<span style="padding: 0 8px; color: #605E5C;">...</span>`;
            html += `<button class="btn btn-sm btn-secondary" onclick="goToNotifPage(${total_pages})">${total_pages}</button>`;
        }

        // Next button
        html += `<button class="btn btn-sm btn-secondary" ${page >= total_pages ? 'disabled' : ''} onclick="goToNotifPage(${page + 1})">Next</button>`;

        container.innerHTML = html;
    }

    /**
     * Go to page
     */
    window.goToNotifPage = function(page) {
        currentPage = page;
        loadNotifications();
    };

    /**
     * View notification details
     */
    window.viewNotificationDetails = async function(id) {
        try {
            const response = await fetch(`/api/dashboard/notification-history/${id}`);
            const data = await response.json();

            if (data.success) {
                showNotificationModal(data.data);
            } else {
                alert('Failed to load notification details');
            }
        } catch (error) {
            console.error('Error loading notification details:', error);
            alert('Failed to load notification details');
        }
    };

    /**
     * Show notification modal
     */
    function showNotificationModal(notif) {
        // Remove existing modal
        const existingModal = document.getElementById('notif-detail-modal');
        if (existingModal) existingModal.remove();

        const channels = parseChannels(notif.channels);
        const deliveryStatus = parseDeliveryStatus(notif.delivery_status);

        const modal = document.createElement('div');
        modal.id = 'notif-detail-modal';
        modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        modal.innerHTML = `
            <div style="background: #FFFFFF; border-radius: 8px; width: 600px; max-width: 90vw; max-height: 90vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);">
                <div style="padding: 20px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                    <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Notification Details</h2>
                    <button onclick="this.closest('#notif-detail-modal').remove()" style="background: none; border: none; cursor: pointer; font-size: 24px; color: #605E5C; line-height: 1;">&times;</button>
                </div>
                <div style="padding: 20px;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">ID</label>
                            <div style="font-family: monospace; color: #323130;">#${notif.id}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">UUID</label>
                            <div style="font-family: monospace; font-size: 11px; color: #323130; word-break: break-all;">${notif.notification_uuid || 'N/A'}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Status</label>
                            <span class="badge ${getStatusClass(notif.status)}">${notif.status}</span>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Priority</label>
                            <span class="badge ${getPriorityClass(notif.priority)}">${notif.priority}</span>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Created</label>
                            <div style="color: #323130;">${formatDateTime(notif.created_at)}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Sent</label>
                            <div style="color: #323130;">${notif.sent_at ? formatDateTime(notif.sent_at) : 'Not sent'}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Rule</label>
                            <div style="color: #0078D4;">${notif.rule_name || 'N/A'}</div>
                        </div>
                        <div>
                            <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Trigger Type</label>
                            <span class="badge badge-outline">${formatTriggerLabel(notif.trigger_type)}</span>
                        </div>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Channels</label>
                        <div>${renderChannelBadges(channels)}</div>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Title</label>
                        <div style="color: #323130; font-weight: 500;">${escapeHtml(notif.message_title)}</div>
                    </div>

                    <div style="margin-bottom: 20px;">
                        <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Message</label>
                        <div style="background: #FAF9F8; padding: 12px; border-radius: 4px; color: #323130; white-space: pre-wrap; font-size: 13px;">${escapeHtml(notif.message_body)}</div>
                    </div>

                    ${notif.failed_reason ? `
                        <div style="margin-bottom: 20px;">
                            <label style="font-size: 12px; color: #D13438; display: block; margin-bottom: 4px;">Failed Reason</label>
                            <div style="background: #FDE7E9; padding: 12px; border-radius: 4px; color: #A80000; font-size: 13px;">${escapeHtml(notif.failed_reason)}</div>
                        </div>
                    ` : ''}

                    <div style="margin-bottom: 20px;">
                        <label style="font-size: 12px; color: #605E5C; display: block; margin-bottom: 4px;">Delivery Status</label>
                        <div style="background: #FAF9F8; padding: 12px; border-radius: 4px; font-size: 12px; font-family: monospace;">
                            ${deliveryStatus}
                        </div>
                    </div>

                    ${notif.status === 'failed' ? `
                        <div style="text-align: right; padding-top: 16px; border-top: 1px solid #EDEBE9;">
                            <button onclick="retryNotification(${notif.id}); this.closest('#notif-detail-modal').remove();" class="btn btn-primary">
                                Retry Notification
                            </button>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;

        document.body.appendChild(modal);
    }

    /**
     * Parse delivery status JSON
     */
    function parseDeliveryStatus(statusJson) {
        try {
            if (!statusJson) return '<span style="color: #A19F9D;">No delivery data</span>';
            const status = typeof statusJson === 'string' ? JSON.parse(statusJson) : statusJson;

            let html = '';
            for (const [channel, data] of Object.entries(status)) {
                const success = data.success;
                const icon = success ? '✓' : '✗';
                const color = success ? '#107C10' : '#D13438';
                html += `<div style="margin-bottom: 8px;"><strong style="color: ${color};">${icon} ${channel}:</strong> `;
                if (success) {
                    html += `<span style="color: #107C10;">Delivered</span>`;
                    if (data.message_id) html += ` (ID: ${data.message_id})`;
                } else {
                    html += `<span style="color: #D13438;">Failed</span>`;
                    if (data.error) html += ` - ${escapeHtml(data.error)}`;
                }
                html += '</div>';
            }
            return html || '<span style="color: #A19F9D;">No delivery data</span>';
        } catch (e) {
            return '<span style="color: #A19F9D;">Unable to parse delivery status</span>';
        }
    }

    /**
     * Retry failed notification
     */
    window.retryNotification = async function(id) {
        if (!confirm('Are you sure you want to retry this notification?')) return;

        try {
            const response = await fetch(`/api/dashboard/notification-history/retry/${id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            const data = await response.json();

            if (data.success) {
                alert('Notification queued for retry');
                loadNotifications();
                loadNotificationStats();
            } else {
                alert(data.error || 'Failed to retry notification');
            }
        } catch (error) {
            console.error('Error retrying notification:', error);
            alert('Failed to retry notification');
        }
    };

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        // Refresh button
        const refreshBtn = document.getElementById('notif-history-refresh-btn');
        if (refreshBtn) {
            refreshBtn.onclick = () => {
                loadNotificationStats();
                loadNotifications();
            };
        }

        // Export button
        const exportBtn = document.getElementById('notif-history-export-btn');
        if (exportBtn) {
            exportBtn.onclick = exportNotifications;
        }

        // Apply filters button
        const applyBtn = document.getElementById('notif-filter-apply-btn');
        if (applyBtn) {
            applyBtn.onclick = applyFilters;
        }

        // Clear filters button
        const clearBtn = document.getElementById('notif-filter-clear-btn');
        if (clearBtn) {
            clearBtn.onclick = clearFilters;
        }

        // Enter key on search
        const searchInput = document.getElementById('notif-filter-search');
        if (searchInput) {
            searchInput.onkeypress = (e) => {
                if (e.key === 'Enter') applyFilters();
            };
        }
    }

    /**
     * Apply filters
     */
    function applyFilters() {
        currentFilters = {
            status: document.getElementById('notif-filter-status')?.value || '',
            priority: document.getElementById('notif-filter-priority')?.value || '',
            channel: document.getElementById('notif-filter-channel')?.value || '',
            trigger_type: document.getElementById('notif-filter-trigger')?.value || '',
            start_date: document.getElementById('notif-filter-start')?.value || '',
            end_date: document.getElementById('notif-filter-end')?.value || '',
            search: document.getElementById('notif-filter-search')?.value || ''
        };

        currentPage = 1;
        loadNotifications();
    }

    /**
     * Clear filters
     */
    function clearFilters() {
        document.getElementById('notif-filter-status').value = '';
        document.getElementById('notif-filter-priority').value = '';
        document.getElementById('notif-filter-channel').value = '';
        document.getElementById('notif-filter-trigger').value = '';
        document.getElementById('notif-filter-start').value = '';
        document.getElementById('notif-filter-end').value = '';
        document.getElementById('notif-filter-search').value = '';

        currentFilters = {};
        currentPage = 1;
        loadNotifications();
    }

    /**
     * Export notifications
     */
    async function exportNotifications() {
        try {
            const params = new URLSearchParams({ limit: 10000 });

            // Add current filters
            if (currentFilters.status) params.append('status', currentFilters.status);
            if (currentFilters.trigger_type) params.append('trigger_type', currentFilters.trigger_type);
            if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
            if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);

            const response = await fetch(`/api/dashboard/notification-history/export?${params}`);
            const data = await response.json();

            if (data.success) {
                const blob = new Blob([JSON.stringify(data.data.notifications, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `notifications_export_${new Date().toISOString().slice(0, 10)}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            } else {
                alert('Failed to export notifications');
            }
        } catch (error) {
            console.error('Error exporting notifications:', error);
            alert('Failed to export notifications');
        }
    }

})();
