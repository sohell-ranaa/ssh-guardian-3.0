/**
 * Notification History Page Module
 * Handles notification history display and filtering
 * Updated for v3.1 database schema with category tabs
 */

(function() {
    'use strict';

    let notifications = [];
    let currentPage = 1;
    let perPage = 50;
    let totalPages = 1;
    let currentFilters = {};
    let currentCategory = 'all';
    let categoryCounts = { all: 0, security: 0, blocking: 0, system: 0 };

    /**
     * Load and display Notification History page
     */
    window.loadNotificationHistoryPage = async function() {
        try {
            // Reset to first page when loading page
            currentPage = 1;
            currentCategory = 'all';

            // Load stats
            await loadNotificationStats();

            // Load channels for filter dropdown
            await loadChannelsFilter();

            // Load notifications
            await loadNotifications();

            // Setup event listeners
            setupEventListeners();

            // Setup category tabs
            setupCategoryTabs();

        } catch (error) {
            console.error('Error loading Notification History page:', error);
        }
    };

    /**
     * Load channels for filtering
     */
    async function loadChannelsFilter() {
        try {
            const response = await fetch('/api/dashboard/notification-history/channels');
            const data = await response.json();

            if (data.success) {
                const channels = data.data.channels || [];
                renderChannelsFilter(channels);
            }
        } catch (error) {
            console.error('Error loading channels:', error);
        }
    }

    /**
     * Render channels filter dropdown
     */
    function renderChannelsFilter(channels) {
        const select = document.getElementById('notif-filter-channel');
        if (!select) return;

        let html = '<option value="">All Channels</option>';
        channels.forEach(ch => {
            if (ch.channel) {
                const icon = getChannelIcon(ch.channel);
                html += `<option value="${ch.channel}">${icon} ${ch.channel} (${ch.count})</option>`;
            }
        });

        select.innerHTML = html;
    }

    /**
     * Get channel icon
     */
    function getChannelIcon(channel) {
        const icons = { telegram: '📱', email: '📧', smtp: '📧', webhook: '🔗' };
        return icons[channel] || '📌';
    }

    /**
     * Load notification statistics
     */
    async function loadNotificationStats() {
        try {
            // Load history stats and unread count in parallel
            const [statsResponse, unreadResponse] = await Promise.all([
                fetch('/api/dashboard/notification-history/stats'),
                fetch('/api/notifications/unread-count')
            ]);

            const statsData = await statsResponse.json();
            const unreadData = await unreadResponse.json();

            if (statsData.success) {
                const unreadCount = unreadData.success ? (unreadData.data?.count || 0) : 0;
                renderNotificationStats(statsData.data, unreadCount);
            }
        } catch (error) {
            console.error('Error loading notification stats:', error);
        }
    }

    /**
     * Render notification statistics
     */
    function renderNotificationStats(stats, unreadCount) {
        const sentCount = stats.by_status?.sent || 0;
        const failedCount = stats.by_status?.failed || 0;

        // Update individual stat elements
        const totalEl = document.getElementById('stat-notif-total');
        const deliveredEl = document.getElementById('stat-notif-delivered');
        const failedEl = document.getElementById('stat-notif-failed');
        const unreadEl = document.getElementById('stat-notif-unread');

        if (totalEl) totalEl.textContent = (stats.total || 0).toLocaleString();
        if (deliveredEl) deliveredEl.textContent = sentCount.toLocaleString();
        if (failedEl) failedEl.textContent = failedCount.toLocaleString();
        if (unreadEl) unreadEl.textContent = unreadCount.toLocaleString();
    }

    /**
     * Sync unread count with notification pane badge
     */
    function syncUnreadCount() {
        // Update the notification pane badge if available
        if (window.NotificationPane) {
            window.NotificationPane.loadUnreadCount();
        }
    }

    /**
     * Load notifications from API
     */
    async function loadNotifications() {
        const tbody = document.getElementById('notif-history-tbody');
        if (tbody) {
            tbody.innerHTML = '<tr><td colspan="6"><div class="loading-placeholder"><div class="loading-spinner"></div><span>Loading notifications...</span></div></td></tr>';
        }

        try {
            const params = new URLSearchParams({
                page: currentPage,
                per_page: perPage
            });

            // Add filters
            if (currentFilters.status) params.append('status', currentFilters.status);
            if (currentFilters.channel) params.append('channel', currentFilters.channel);
            if (currentFilters.is_security_alert) params.append('is_security_alert', currentFilters.is_security_alert);
            if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
            if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);
            if (currentFilters.search) params.append('search', currentFilters.search);
            if (currentFilters.ip) params.append('ip', currentFilters.ip);

            const response = await fetch(`/api/dashboard/notification-history/list?${params}`);
            const data = await response.json();

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
                tbody.innerHTML = '<tr><td colspan="6"><div class="loading-placeholder"><span style="color: var(--danger);">Failed to load notifications. Please try again.</span></div></td></tr>';
            }
        }
    }

    /**
     * Determine notification category based on content
     */
    function getNotificationCategory(notif) {
        const subject = (notif.subject || '').toLowerCase();
        const message = (notif.message || '').toLowerCase();

        // Security category
        if (notif.is_security_alert ||
            subject.includes('brute force') ||
            subject.includes('threat') ||
            subject.includes('attack') ||
            subject.includes('intrusion') ||
            subject.includes('suspicious')) {
            return 'security';
        }

        // Blocking category
        if (subject.includes('blocked') ||
            subject.includes('block') ||
            subject.includes('banned') ||
            subject.includes('unblock') ||
            message.includes('blocked') ||
            message.includes('firewall')) {
            return 'blocking';
        }

        // System category
        if (subject.includes('system') ||
            subject.includes('status') ||
            subject.includes('agent') ||
            subject.includes('service') ||
            subject.includes('config')) {
            return 'system';
        }

        return 'other';
    }

    /**
     * Filter notifications by current category
     */
    function filterByCategory(notifs) {
        if (currentCategory === 'all') return notifs;

        return notifs.filter(n => getNotificationCategory(n) === currentCategory);
    }

    /**
     * Update category counts
     */
    function updateCategoryCounts(allNotifs) {
        categoryCounts = { all: allNotifs.length, security: 0, blocking: 0, system: 0 };

        allNotifs.forEach(n => {
            const cat = getNotificationCategory(n);
            if (categoryCounts[cat] !== undefined) {
                categoryCounts[cat]++;
            }
        });

        // Update tab badges
        document.querySelectorAll('.history-tab').forEach(tab => {
            const category = tab.dataset.category;
            const countSpan = tab.querySelector('.tab-count');
            if (countSpan && categoryCounts[category] !== undefined) {
                countSpan.textContent = categoryCounts[category];
            }
        });
    }

    /**
     * Setup category tabs
     */
    function setupCategoryTabs() {
        const tabsContainer = document.getElementById('notif-history-tabs');
        if (!tabsContainer) return;

        tabsContainer.querySelectorAll('.history-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();

                // Update active tab
                tabsContainer.querySelectorAll('.history-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                // Set current category and reload
                currentCategory = tab.dataset.category;
                currentPage = 1;
                loadNotifications();
            });
        });
    }

    /**
     * Render notifications table
     */
    function renderNotifications() {
        const tbody = document.getElementById('notif-history-tbody');
        if (!tbody) return;

        // Update category counts from all loaded notifications
        updateCategoryCounts(notifications);

        // Filter by current category
        const filteredNotifs = filterByCategory(notifications);

        if (!filteredNotifs || filteredNotifs.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" class="history-empty">
                        <div class="history-empty-icon">📭</div>
                        <div class="history-empty-title">No Notifications Found</div>
                        <div class="history-empty-text">No notifications match your current filters</div>
                    </td>
                </tr>
            `;
            return;
        }

        let html = '';
        filteredNotifs.forEach(notif => {
            const timeAgo = formatTimeAgo(notif.created_at);
            const timeAbsolute = formatDateTime(notif.created_at);
            const category = getNotificationCategory(notif);
            const channelClass = `channel-${notif.channel || 'unknown'}`;
            const statusClass = `status-${notif.status || 'unknown'}`;

            html += `
                <tr class="has-category category-${category}">
                    <td class="time-cell">
                        <span class="time-relative">${timeAgo}</span>
                        <span class="time-absolute">${timeAbsolute}</span>
                    </td>
                    <td>
                        <span class="channel-badge ${channelClass}">
                            ${getChannelIcon(notif.channel)} ${notif.channel || 'unknown'}
                        </span>
                    </td>
                    <td class="subject-cell" title="${stripHtmlTags(notif.subject || 'No subject')}">
                        ${stripHtmlTags(notif.subject || 'No subject')}
                    </td>
                    <td class="ip-cell">
                        ${notif.ip_address || '-'}
                    </td>
                    <td>
                        <span class="status-badge ${statusClass}">${notif.status || 'unknown'}</span>
                    </td>
                    <td>
                        <div class="actions-cell">
                            <button onclick="viewNotificationDetails(${notif.id})" class="btn btn-sm btn-secondary" title="View">
                                👁
                            </button>
                            ${notif.status === 'failed' ? `
                                <button onclick="retryNotification(${notif.id})" class="btn btn-sm btn-primary" title="Retry">↻</button>
                            ` : ''}
                        </div>
                    </td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }

    /**
     * Get channel background color
     */
    function getChannelBg(channel) {
        const colors = { telegram: TC.primaryBg, email: TC.dangerBg, smtp: TC.dangerBg, webhook: TC.successBg };
        return colors[channel] || 'var(--surface-alt)';
    }

    /**
     * Get channel text color
     */
    function getChannelColor(channel) {
        const colors = { telegram: TC.primary, email: TC.danger, smtp: TC.danger, webhook: TC.successDark };
        return colors[channel] || 'var(--text-secondary)';
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
     * Format time ago
     */
    function formatTimeAgo(dateStr) {
        if (!dateStr) return 'N/A';
        if (window.TimeSettings?.isLoaded()) {
            return window.TimeSettings.relative(dateStr);
        }
        // Fallback - server timestamps are in +08:00
        let parseDateStr = String(dateStr).replace(' ', 'T');
        if (!parseDateStr.endsWith('Z') && !parseDateStr.includes('+')) {
            parseDateStr += '+08:00';
        }
        const date = new Date(parseDateStr);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);

        if (diffMs < 0) return 'Just now';
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        return date.toLocaleDateString();
    }

    // formatDateTime - use shared utility from utils.js
    const formatDateTime = window.formatLocalDateTime;

    /**
     * Render pagination
     */
    function renderPagination(data) {
        const container = document.getElementById('notif-history-pagination');
        if (!container) return;

        const { page, total_pages, total } = data;
        if (total_pages <= 1) {
            container.innerHTML = `<span style="color: var(--text-secondary); font-size: 13px;">${total} notification${total !== 1 ? 's' : ''}</span>`;
            return;
        }

        let html = `<span style="color: var(--text-secondary); font-size: 13px; margin-right: 16px;">${total} notification${total !== 1 ? 's' : ''}</span>`;

        html += `<button class="btn btn-sm btn-secondary" ${page <= 1 ? 'disabled' : ''} onclick="goToNotifPage(${page - 1})">Prev</button>`;

        const startPage = Math.max(1, page - 2);
        const endPage = Math.min(total_pages, page + 2);

        if (startPage > 1) {
            html += `<button class="btn btn-sm btn-secondary" onclick="goToNotifPage(1)">1</button>`;
            if (startPage > 2) html += `<span style="padding: 0 8px; color: var(--text-secondary);">...</span>`;
        }

        for (let i = startPage; i <= endPage; i++) {
            html += `<button class="btn btn-sm ${i === page ? 'btn-primary' : 'btn-secondary'}" onclick="goToNotifPage(${i})">${i}</button>`;
        }

        if (endPage < total_pages) {
            if (endPage < total_pages - 1) html += `<span style="padding: 0 8px; color: var(--text-secondary);">...</span>`;
            html += `<button class="btn btn-sm btn-secondary" onclick="goToNotifPage(${total_pages})">${total_pages}</button>`;
        }

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
                showNotification('Failed to load notification details', 'error');
            }
        } catch (error) {
            console.error('Error loading notification details:', error);
            showNotification('Failed to load notification details', 'error');
        }
    };

    /**
     * Show notification modal with improved design
     */
    function showNotificationModal(notif) {
        const existingModal = document.getElementById('notif-detail-modal');
        if (existingModal) existingModal.remove();

        const modal = document.createElement('div');
        modal.id = 'notif-detail-modal';
        modal.className = 'notif-detail-modal-overlay';
        modal.onclick = (e) => { if (e.target === modal) modal.remove(); };

        const geoData = notif.geo_data || {};
        const mlFactors = notif.ml_factors || [];
        const category = getNotificationCategory(notif);
        const categoryLabel = { security: '🛡️ Security', blocking: '🚫 Blocking', system: '⚙️ System' }[category] || '📬 General';
        const channelClass = `channel-${notif.channel || 'unknown'}`;

        modal.innerHTML = `
            <div class="notif-detail-modal">
                <div class="notif-detail-header">
                    <h3>
                        ${categoryLabel} Notification
                        <span class="status-badge status-${notif.status}">${notif.status}</span>
                    </h3>
                    <button class="close-btn" onclick="this.closest('#notif-detail-modal').remove()">&times;</button>
                </div>
                <div class="notif-detail-body">
                    <!-- Basic Info -->
                    <div class="notif-detail-section">
                        <div class="notif-detail-grid">
                            <div class="notif-detail-field">
                                <label>Notification ID</label>
                                <div class="value mono">#${notif.id}</div>
                            </div>
                            <div class="notif-detail-field">
                                <label>Channel</label>
                                <span class="channel-badge ${channelClass}">
                                    ${getChannelIcon(notif.channel)} ${notif.channel || 'unknown'}
                                </span>
                            </div>
                            <div class="notif-detail-field">
                                <label>Created</label>
                                <div class="value">${formatTimeAgo(notif.created_at)}</div>
                            </div>
                            <div class="notif-detail-field">
                                <label>Timestamp</label>
                                <div class="value mono" style="font-size: 12px;">${formatDateTime(notif.created_at)}</div>
                            </div>
                        </div>
                    </div>

                    <!-- Subject & Message -->
                    <div class="notif-detail-section">
                        <div class="notif-detail-section-title">Content</div>
                        <div class="notif-detail-field">
                            <label>Subject</label>
                            <div class="value" style="font-weight: 600;">${formatMessageForDisplay(notif.subject || 'No subject')}</div>
                        </div>
                        <div class="notif-detail-field">
                            <label>Message</label>
                            <div class="notif-detail-message">${formatMessageForDisplay(notif.message || 'No message content')}</div>
                        </div>
                    </div>

                    <!-- Source Info -->
                    ${notif.ip_address || notif.rule_name ? `
                    <div class="notif-detail-section">
                        <div class="notif-detail-section-title">Source</div>
                        <div class="notif-detail-grid">
                            ${notif.ip_address ? `
                            <div class="notif-detail-field">
                                <label>IP Address</label>
                                <div class="value mono">${notif.ip_address}${notif.username ? ` <span style="color: var(--text-secondary);">(${escapeHtml(notif.username)})</span>` : ''}</div>
                            </div>
                            ` : ''}
                            ${notif.rule_name ? `
                            <div class="notif-detail-field">
                                <label>Triggered by Rule</label>
                                <div class="value" style="color: var(--azure-blue);">${escapeHtml(notif.rule_name)}</div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}

                    <!-- ML Score -->
                    ${notif.ml_score ? `
                    <div class="notif-detail-section">
                        <div class="notif-detail-section-title">ML Analysis</div>
                        <div class="notif-detail-field">
                            <label>Risk Score</label>
                            <div style="display: flex; align-items: center; gap: 12px; margin-top: 4px;">
                                <div style="flex: 1; max-width: 150px; height: 8px; background: var(--border); border-radius: 4px; overflow: hidden;">
                                    <div style="width: ${notif.ml_score}%; height: 100%; background: ${notif.ml_score >= 80 ? 'var(--danger)' : notif.ml_score >= 60 ? 'var(--warning)' : 'var(--success)'};"></div>
                                </div>
                                <span style="font-weight: 700; font-size: 18px; color: ${notif.ml_score >= 80 ? 'var(--danger)' : notif.ml_score >= 60 ? 'var(--warning)' : 'var(--success)'};">${notif.ml_score}%</span>
                            </div>
                        </div>
                        ${mlFactors.length > 0 ? `
                        <div class="notif-detail-field">
                            <label>Risk Factors</label>
                            <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-top: 4px;">
                                ${mlFactors.map(f => `<span style="padding: 4px 10px; background: var(--surface-alt); border-radius: 12px; font-size: 12px; color: var(--text-secondary); border: 1px solid var(--border);">${escapeHtml(f)}</span>`).join('')}
                            </div>
                        </div>
                        ` : ''}
                    </div>
                    ` : ''}

                    <!-- Geo Data -->
                    ${Object.keys(geoData).length > 0 ? `
                    <div class="notif-detail-section">
                        <div class="notif-detail-section-title">Geographic Information</div>
                        <div class="notif-detail-grid">
                            ${geoData.country ? `
                            <div class="notif-detail-field">
                                <label>Country</label>
                                <div class="value">${geoData.country}${geoData.countryCode ? ` (${geoData.countryCode})` : ''}</div>
                            </div>
                            ` : ''}
                            ${geoData.city ? `
                            <div class="notif-detail-field">
                                <label>City</label>
                                <div class="value">${geoData.city}</div>
                            </div>
                            ` : ''}
                            ${geoData.isp ? `
                            <div class="notif-detail-field">
                                <label>ISP</label>
                                <div class="value">${escapeHtml(geoData.isp)}</div>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}

                    <!-- Error -->
                    ${notif.error_message ? `
                    <div class="notif-detail-section">
                        <div class="notif-detail-section-title" style="color: var(--danger);">Error Details</div>
                        <div style="background: var(--color-danger-bg); padding: 12px; border-radius: 6px; color: var(--danger); font-size: 13px; border: 1px solid rgba(209, 52, 56, 0.2);">
                            ${escapeHtml(notif.error_message)}
                        </div>
                    </div>
                    ` : ''}
                </div>
                <div class="notif-detail-footer">
                    ${notif.status === 'failed' ? `
                        <button onclick="retryNotification(${notif.id}); this.closest('#notif-detail-modal').remove();" class="btn btn-primary">
                            ↻ Retry
                        </button>
                    ` : ''}
                    ${notif.is_security_alert && !notif.is_acknowledged ? `
                        <button onclick="acknowledgeAlert(${notif.id}); this.closest('#notif-detail-modal').remove();" class="btn btn-success">
                            ✓ Acknowledge
                        </button>
                    ` : ''}
                    <button onclick="this.closest('#notif-detail-modal').remove();" class="btn btn-secondary">Close</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
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
                showNotification('Notification queued for retry', 'success');
                loadNotifications();
                loadNotificationStats();
                syncUnreadCount();
            } else {
                showNotification(data.error || 'Failed to retry notification', 'error');
            }
        } catch (error) {
            console.error('Error retrying notification:', error);
            showNotification('Failed to retry notification', 'error');
        }
    };

    /**
     * Acknowledge security alert
     */
    window.acknowledgeAlert = async function(id) {
        try {
            const response = await fetch(`/api/dashboard/notification-history/acknowledge/${id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action_taken: 'acknowledged' })
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Alert acknowledged', 'success');
                loadNotifications();
                loadNotificationStats();
                syncUnreadCount();
            } else {
                showNotification(data.error || 'Failed to acknowledge alert', 'error');
            }
        } catch (error) {
            console.error('Error acknowledging alert:', error);
            showNotification('Failed to acknowledge alert', 'error');
        }
    };

    /**
     * Setup event listeners
     */
    function setupEventListeners() {
        const refreshBtn = document.getElementById('notif-history-refresh-btn');
        if (refreshBtn) {
            refreshBtn.onclick = () => {
                loadNotificationStats();
                loadNotifications();
            };
        }

        const exportBtn = document.getElementById('notif-history-export-btn');
        if (exportBtn) {
            exportBtn.onclick = exportNotifications;
        }

        const applyBtn = document.getElementById('notif-filter-apply-btn');
        if (applyBtn) {
            applyBtn.onclick = applyFilters;
        }

        const clearBtn = document.getElementById('notif-filter-clear-btn');
        if (clearBtn) {
            clearBtn.onclick = clearFilters;
        }

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
            channel: document.getElementById('notif-filter-channel')?.value || '',
            is_security_alert: document.getElementById('notif-filter-alert')?.value || '',
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
        const fields = ['notif-filter-status', 'notif-filter-channel', 'notif-filter-alert', 'notif-filter-start', 'notif-filter-end', 'notif-filter-search'];
        fields.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });

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

            if (currentFilters.status) params.append('status', currentFilters.status);
            if (currentFilters.channel) params.append('channel', currentFilters.channel);
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
                showNotification('Failed to export notifications', 'error');
            }
        } catch (error) {
            console.error('Error exporting notifications:', error);
            showNotification('Failed to export notifications', 'error');
        }
    }

    // showNotification - use shared utility from toast.js
    const showNotification = window.showNotification || ((msg, type) => window.showToast?.(msg, type));

    // escapeHtml - use shared utility from utils.js
    const escapeHtml = window.escapeHtml;

    /**
     * Strip all HTML tags from string (for table display)
     */
    function stripHtmlTags(str) {
        if (!str) return '';
        return String(str)
            .replace(/\\n/g, ' ')
            .replace(/<[^>]*>/g, '')
            .trim();
    }

    /**
     * Format notification message for display
     * Converts Telegram-style HTML to readable formatted text
     */
    function formatMessageForDisplay(str) {
        if (!str) return '';
        return String(str)
            // Convert literal \n to line breaks
            .replace(/\\n/g, '<br>')
            // Convert <b> tags to styled spans
            .replace(/<b>/gi, '<strong>')
            .replace(/<\/b>/gi, '</strong>')
            // Convert <i> tags
            .replace(/<i>/gi, '<em style="color: var(--text-secondary);">')
            .replace(/<\/i>/gi, '</em>')
            // Remove any other HTML tags for security
            .replace(/<(?!\/?(strong|em|br)\b)[^>]*>/gi, '');
    }

})();
