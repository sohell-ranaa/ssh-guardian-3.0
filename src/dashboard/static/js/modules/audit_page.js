/**
 * Audit Logs Page Module
 * Handles audit log display and filtering
 */

(function() {
    'use strict';

    let auditLogs = [];
    let actionTypes = [];
    let currentPage = 1;
    let perPage = 50;
    let totalPages = 1;
    let currentFilters = {};

    /**
     * Load and display Audit page
     */
    window.loadAuditPage = async function() {
        console.log('Loading Audit page...');

        try {
            // Load action types for filter dropdown
            await loadActionTypes();

            // Load stats
            await loadAuditStats();

            // Load audit logs
            await loadAuditLogs();

            // Setup event listeners
            setupAuditEventListeners();

        } catch (error) {
            console.error('Error loading Audit page:', error);
            showNotification('Failed to load audit logs', 'error');
        }
    };

    /**
     * Load action types for filtering
     */
    async function loadActionTypes() {
        try {
            const response = await fetch('/api/dashboard/audit/actions');
            const data = await response.json();

            if (data.success) {
                actionTypes = data.data.actions || [];
                renderActionFilter();
            }
        } catch (error) {
            console.error('Error loading action types:', error);
        }
    }

    /**
     * Render action filter dropdown
     */
    function renderActionFilter() {
        const select = document.getElementById('audit-action-filter');
        if (!select) return;

        let html = '<option value="">All Actions</option>';
        actionTypes.forEach(action => {
            const label = formatActionLabel(action.action);
            html += `<option value="${action.action}">${label} (${action.count})</option>`;
        });

        select.innerHTML = html;
    }

    /**
     * Format action label for display
     */
    function formatActionLabel(action) {
        if (!action) return 'Unknown';
        return action
            .replace(/_/g, ' ')
            .replace(/\b\w/g, c => c.toUpperCase());
    }

    /**
     * Load audit statistics
     */
    async function loadAuditStats() {
        try {
            const response = await fetch('/api/dashboard/audit/stats');
            const data = await response.json();

            if (data.success) {
                renderAuditStats(data.data);
            }
        } catch (error) {
            console.error('Error loading audit stats:', error);
        }
    }

    /**
     * Render audit statistics
     */
    function renderAuditStats(stats) {
        const container = document.getElementById('audit-stats-container');
        if (!container) return;

        container.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 24px;">
                <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; padding: 16px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 600; color: #0078D4;">${stats.total.toLocaleString()}</div>
                    <div style="font-size: 12px; color: #605E5C; margin-top: 4px;">Total Logs</div>
                </div>
                <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; padding: 16px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 600; color: #107C10;">${stats.today.toLocaleString()}</div>
                    <div style="font-size: 12px; color: #605E5C; margin-top: 4px;">Today</div>
                </div>
                <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; padding: 16px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 600; color: #5C2D91;">${stats.this_week.toLocaleString()}</div>
                    <div style="font-size: 12px; color: #605E5C; margin-top: 4px;">This Week</div>
                </div>
                <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; padding: 16px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 600; color: #008272;">${stats.active_users}</div>
                    <div style="font-size: 12px; color: #605E5C; margin-top: 4px;">Active Users (7d)</div>
                </div>
                <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; padding: 16px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 600; color: ${stats.failed_logins_today > 0 ? '#D13438' : '#107C10'};">${stats.failed_logins_today}</div>
                    <div style="font-size: 12px; color: #605E5C; margin-top: 4px;">Failed Logins Today</div>
                </div>
            </div>
        `;
    }

    /**
     * Load audit logs from API
     */
    async function loadAuditLogs() {
        const container = document.getElementById('audit-logs-container');
        if (container) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #605E5C;">Loading audit logs...</div>';
        }

        try {
            const params = new URLSearchParams({
                page: currentPage,
                per_page: perPage
            });

            // Add filters
            if (currentFilters.action) params.append('action', currentFilters.action);
            if (currentFilters.user_id) params.append('user_id', currentFilters.user_id);
            if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
            if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);
            if (currentFilters.search) params.append('search', currentFilters.search);

            // Use fetchWithCache if available to track cache status
            let data;
            if (typeof fetchWithCache === 'function') {
                data = await fetchWithCache(`/api/dashboard/audit/list?${params}`, 'audit');
            } else {
                const response = await fetch(`/api/dashboard/audit/list?${params}`);
                data = await response.json();
            }

            if (data.success) {
                auditLogs = data.data.logs || [];
                totalPages = data.data.total_pages || 1;
                renderAuditLogs(auditLogs);
                renderPagination(data.data);
            } else {
                throw new Error(data.error || 'Failed to load audit logs');
            }

        } catch (error) {
            console.error('Error loading audit logs:', error);
            if (container) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #D13438;">Failed to load audit logs. Please try again.</div>';
            }
        }
    }

    /**
     * Render audit logs table
     */
    function renderAuditLogs(logs) {
        const container = document.getElementById('audit-logs-container');
        if (!container) return;

        if (!logs || logs.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 60px 20px; color: #605E5C;">
                    <div style="font-size: 48px; margin-bottom: 16px;">📋</div>
                    <h3 style="font-size: 18px; font-weight: 600; margin-bottom: 8px; color: #323130;">No Audit Logs</h3>
                    <p style="font-size: 14px;">No audit logs match your current filters</p>
                </div>
            `;
            return;
        }

        let html = `
            <div style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; overflow: hidden;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #FAF9F8; border-bottom: 1px solid #EDEBE9;">
                            <th style="padding: 12px 16px; text-align: left; font-weight: 600; font-size: 12px; color: #605E5C; text-transform: uppercase;">Time</th>
                            <th style="padding: 12px 16px; text-align: left; font-weight: 600; font-size: 12px; color: #605E5C; text-transform: uppercase;">User</th>
                            <th style="padding: 12px 16px; text-align: left; font-weight: 600; font-size: 12px; color: #605E5C; text-transform: uppercase;">Action</th>
                            <th style="padding: 12px 16px; text-align: left; font-weight: 600; font-size: 12px; color: #605E5C; text-transform: uppercase;">Details</th>
                            <th style="padding: 12px 16px; text-align: left; font-weight: 600; font-size: 12px; color: #605E5C; text-transform: uppercase;">IP Address</th>
                            <th style="padding: 12px 16px; text-align: center; font-weight: 600; font-size: 12px; color: #605E5C; text-transform: uppercase;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        logs.forEach(log => {
            const actionInfo = getActionInfo(log.action);
            const time = formatDateTime(log.created_at);
            const userName = log.user_name || log.user_email || 'System';
            const details = formatDetails(log.details);

            html += `
                <tr style="border-bottom: 1px solid #EDEBE9;" onmouseover="this.style.background='#FAF9F8'" onmouseout="this.style.background='#FFFFFF'">
                    <td style="padding: 12px 16px; font-size: 13px; color: #605E5C; white-space: nowrap;">
                        ${time}
                    </td>
                    <td style="padding: 12px 16px;">
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 28px; height: 28px; border-radius: 50%; background: #0078D4; color: white; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 600;">
                                ${getInitials(userName)}
                            </div>
                            <span style="font-size: 13px; color: #323130;">${escapeHtml(userName)}</span>
                        </div>
                    </td>
                    <td style="padding: 12px 16px;">
                        <span style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 500; background: ${actionInfo.bgColor}; color: ${actionInfo.color};">
                            ${actionInfo.icon} ${actionInfo.label}
                        </span>
                    </td>
                    <td style="padding: 12px 16px; font-size: 13px; color: #605E5C; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                        ${details}
                    </td>
                    <td style="padding: 12px 16px; font-size: 13px; color: #605E5C; font-family: monospace;">
                        ${escapeHtml(log.ip_address || '-')}
                    </td>
                    <td style="padding: 12px 16px; text-align: center;">
                        <button onclick="showAuditDetails(${log.id})" style="background: none; border: 1px solid #EDEBE9; border-radius: 4px; padding: 4px 8px; cursor: pointer; font-size: 12px; color: #0078D4;" title="View Details">
                            View
                        </button>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;

        container.innerHTML = html;
    }

    /**
     * Get action display info
     */
    function getActionInfo(action) {
        const actionMap = {
            'login_success': { icon: '✅', label: 'Login Success', color: '#107C10', bgColor: '#DFF6DD' },
            'login_otp_sent': { icon: '📧', label: 'OTP Sent', color: '#0078D4', bgColor: '#DEECF9' },
            'login_otp_failed': { icon: '❌', label: 'OTP Failed', color: '#D13438', bgColor: '#FDE7E9' },
            'login_trusted_device': { icon: '🔐', label: 'Trusted Login', color: '#107C10', bgColor: '#DFF6DD' },
            'logout': { icon: '🚪', label: 'Logout', color: '#605E5C', bgColor: '#F3F2F1' },
            'user_created': { icon: '👤', label: 'User Created', color: '#0078D4', bgColor: '#DEECF9' },
            'user_updated': { icon: '✏️', label: 'User Updated', color: '#5C2D91', bgColor: '#EDE5F4' },
            'user_deleted': { icon: '🗑️', label: 'User Deleted', color: '#D13438', bgColor: '#FDE7E9' },
            'settings_changed': { icon: '⚙️', label: 'Settings Changed', color: '#5C2D91', bgColor: '#EDE5F4' },
            'password_reset': { icon: '🔑', label: 'Password Reset', color: '#FF8C00', bgColor: '#FFF4CE' }
        };

        return actionMap[action] || {
            icon: '📝',
            label: formatActionLabel(action),
            color: '#605E5C',
            bgColor: '#F3F2F1'
        };
    }

    /**
     * Format details object for display
     */
    function formatDetails(details) {
        if (!details) return '-';

        try {
            const obj = typeof details === 'string' ? JSON.parse(details) : details;

            if (obj.role) return `Role: ${obj.role}`;
            if (obj.email) return `Email: ${obj.email}`;
            if (obj.message) return obj.message;

            // Show first key-value pair
            const keys = Object.keys(obj);
            if (keys.length > 0) {
                return `${keys[0]}: ${obj[keys[0]]}`;
            }

            return JSON.stringify(obj);
        } catch (e) {
            return String(details);
        }
    }

    /**
     * Render pagination controls
     */
    function renderPagination(data) {
        const container = document.getElementById('audit-pagination');
        if (!container) return;

        const { page, total_pages, total, per_page } = data;
        const start = (page - 1) * per_page + 1;
        const end = Math.min(page * per_page, total);

        let html = `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 16px 0;">
                <div style="font-size: 13px; color: #605E5C;">
                    Showing ${start} - ${end} of ${total.toLocaleString()} logs
                </div>
                <div style="display: flex; gap: 8px; align-items: center;">
        `;

        // Previous button
        html += `
            <button onclick="goToAuditPage(${page - 1})" ${page <= 1 ? 'disabled' : ''}
                style="padding: 6px 12px; border: 1px solid #EDEBE9; border-radius: 4px; background: ${page <= 1 ? '#F3F2F1' : '#FFFFFF'}; cursor: ${page <= 1 ? 'not-allowed' : 'pointer'}; font-size: 13px; color: ${page <= 1 ? '#A19F9D' : '#323130'};">
                Previous
            </button>
        `;

        // Page numbers
        const maxPages = 5;
        let startPage = Math.max(1, page - Math.floor(maxPages / 2));
        let endPage = Math.min(total_pages, startPage + maxPages - 1);

        if (endPage - startPage < maxPages - 1) {
            startPage = Math.max(1, endPage - maxPages + 1);
        }

        if (startPage > 1) {
            html += `<button onclick="goToAuditPage(1)" style="padding: 6px 10px; border: 1px solid #EDEBE9; border-radius: 4px; background: #FFFFFF; cursor: pointer; font-size: 13px;">1</button>`;
            if (startPage > 2) {
                html += `<span style="color: #605E5C;">...</span>`;
            }
        }

        for (let i = startPage; i <= endPage; i++) {
            const isActive = i === page;
            html += `
                <button onclick="goToAuditPage(${i})"
                    style="padding: 6px 10px; border: 1px solid ${isActive ? '#0078D4' : '#EDEBE9'}; border-radius: 4px; background: ${isActive ? '#0078D4' : '#FFFFFF'}; color: ${isActive ? '#FFFFFF' : '#323130'}; cursor: pointer; font-size: 13px; font-weight: ${isActive ? '600' : '400'};">
                    ${i}
                </button>
            `;
        }

        if (endPage < total_pages) {
            if (endPage < total_pages - 1) {
                html += `<span style="color: #605E5C;">...</span>`;
            }
            html += `<button onclick="goToAuditPage(${total_pages})" style="padding: 6px 10px; border: 1px solid #EDEBE9; border-radius: 4px; background: #FFFFFF; cursor: pointer; font-size: 13px;">${total_pages}</button>`;
        }

        // Next button
        html += `
            <button onclick="goToAuditPage(${page + 1})" ${page >= total_pages ? 'disabled' : ''}
                style="padding: 6px 12px; border: 1px solid #EDEBE9; border-radius: 4px; background: ${page >= total_pages ? '#F3F2F1' : '#FFFFFF'}; cursor: ${page >= total_pages ? 'not-allowed' : 'pointer'}; font-size: 13px; color: ${page >= total_pages ? '#A19F9D' : '#323130'};">
                Next
            </button>
        `;

        html += `
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    /**
     * Go to specific page
     */
    window.goToAuditPage = function(page) {
        if (page < 1 || page > totalPages) return;
        currentPage = page;
        loadAuditLogs();
    };

    /**
     * Show audit log details modal
     */
    window.showAuditDetails = async function(logId) {
        try {
            const response = await fetch(`/api/dashboard/audit/${logId}`);
            const data = await response.json();

            if (!data.success) {
                showNotification(data.error || 'Failed to load details', 'error');
                return;
            }

            const log = data.data;
            const actionInfo = getActionInfo(log.action);

            // Create modal
            const modal = document.createElement('div');
            modal.id = 'audit-detail-modal';
            modal.style.cssText = 'position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 10000;';

            modal.innerHTML = `
                <div style="background: #FFFFFF; border-radius: 8px; width: 90%; max-width: 600px; max-height: 80vh; overflow-y: auto; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);">
                    <div style="padding: 20px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Audit Log Details</h3>
                        <button onclick="closeAuditDetailModal()" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #605E5C;">&times;</button>
                    </div>
                    <div style="padding: 20px;">
                        <div style="display: grid; gap: 16px;">
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">ID:</span>
                                <span style="color: #323130; font-size: 13px;">#${log.id}</span>
                            </div>
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">Time:</span>
                                <span style="color: #323130; font-size: 13px;">${formatDateTime(log.created_at)}</span>
                            </div>
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">User:</span>
                                <span style="color: #323130; font-size: 13px;">${escapeHtml(log.user_name || log.user_email || 'System')}</span>
                            </div>
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">Action:</span>
                                <span style="display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: 500; background: ${actionInfo.bgColor}; color: ${actionInfo.color}; width: fit-content;">
                                    ${actionInfo.icon} ${actionInfo.label}
                                </span>
                            </div>
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">IP Address:</span>
                                <span style="color: #323130; font-size: 13px; font-family: monospace;">${escapeHtml(log.ip_address || '-')}</span>
                            </div>
                            ${log.resource_type ? `
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">Resource:</span>
                                <span style="color: #323130; font-size: 13px;">${escapeHtml(log.resource_type)} ${log.resource_id ? `#${log.resource_id}` : ''}</span>
                            </div>
                            ` : ''}
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">Details:</span>
                                <pre style="margin: 0; background: #FAF9F8; padding: 12px; border-radius: 4px; font-size: 12px; overflow-x: auto; color: #323130;">${log.details ? JSON.stringify(log.details, null, 2) : '-'}</pre>
                            </div>
                            <div style="display: grid; grid-template-columns: 120px 1fr; gap: 8px; align-items: start;">
                                <span style="font-weight: 600; color: #605E5C; font-size: 13px;">User Agent:</span>
                                <span style="color: #605E5C; font-size: 12px; word-break: break-all;">${escapeHtml(log.user_agent || '-')}</span>
                            </div>
                        </div>
                    </div>
                    <div style="padding: 16px 20px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end;">
                        <button onclick="closeAuditDetailModal()" style="padding: 8px 16px; background: #F3F2F1; border: 1px solid #EDEBE9; border-radius: 4px; cursor: pointer; font-size: 14px; color: #323130;">
                            Close
                        </button>
                    </div>
                </div>
            `;

            document.body.appendChild(modal);

            // Close on backdrop click
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeAuditDetailModal();
            });

        } catch (error) {
            console.error('Error loading audit details:', error);
            showNotification('Failed to load audit log details', 'error');
        }
    };

    /**
     * Close audit detail modal
     */
    window.closeAuditDetailModal = function() {
        const modal = document.getElementById('audit-detail-modal');
        if (modal) modal.remove();
    };

    /**
     * Apply filters
     */
    window.applyAuditFilters = function() {
        currentFilters = {
            action: document.getElementById('audit-action-filter')?.value || '',
            start_date: document.getElementById('audit-start-date')?.value || '',
            end_date: document.getElementById('audit-end-date')?.value || ''
        };
        currentPage = 1;
        loadAuditLogs();
    };

    /**
     * Clear filters
     */
    window.clearAuditFilters = function() {
        document.getElementById('audit-action-filter').value = '';
        document.getElementById('audit-start-date').value = '';
        document.getElementById('audit-end-date').value = '';
        currentFilters = {};
        currentPage = 1;
        loadAuditLogs();
    };

    /**
     * Export audit logs
     */
    window.exportAuditLogs = async function() {
        try {
            const params = new URLSearchParams({ limit: 10000 });
            if (currentFilters.action) params.append('action', currentFilters.action);
            if (currentFilters.start_date) params.append('start_date', currentFilters.start_date);
            if (currentFilters.end_date) params.append('end_date', currentFilters.end_date);

            const response = await fetch(`/api/dashboard/audit/export?${params}`);
            const data = await response.json();

            if (data.success) {
                // Create and download JSON file
                const blob = new Blob([JSON.stringify(data.data.logs, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `audit_logs_${new Date().toISOString().split('T')[0]}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                showNotification(`Exported ${data.data.count} audit logs`, 'success');
            } else {
                throw new Error(data.error);
            }
        } catch (error) {
            console.error('Error exporting audit logs:', error);
            showNotification('Failed to export audit logs', 'error');
        }
    };

    /**
     * Setup event listeners
     */
    function setupAuditEventListeners() {
        const refreshBtn = document.getElementById('audit-refresh-btn');
        if (refreshBtn) {
            refreshBtn.onclick = () => {
                loadAuditStats();
                loadAuditLogs();
            };
        }

        const exportBtn = document.getElementById('audit-export-btn');
        if (exportBtn) {
            exportBtn.onclick = exportAuditLogs;
        }

        const applyBtn = document.getElementById('audit-apply-filters-btn');
        if (applyBtn) {
            applyBtn.onclick = applyAuditFilters;
        }

        const clearBtn = document.getElementById('audit-clear-filters-btn');
        if (clearBtn) {
            clearBtn.onclick = clearAuditFilters;
        }

        // Per page select
        const perPageSelect = document.getElementById('audit-per-page');
        if (perPageSelect) {
            perPageSelect.onchange = (e) => {
                perPage = parseInt(e.target.value);
                currentPage = 1;
                loadAuditLogs();
            };
        }
    }

    /**
     * Format date/time
     */
    function formatDateTime(dateStr) {
        if (!dateStr) return '-';
        const date = new Date(dateStr);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    /**
     * Get initials from name
     */
    function getInitials(name) {
        if (!name) return '?';
        return name.split(' ').map(n => n[0]).join('').toUpperCase().substring(0, 2);
    }

    /**
     * Escape HTML
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Show notification
     */
    function showNotification(message, type) {
        if (typeof window.showNotification === 'function') {
            window.showNotification(message, type);
        } else {
            alert(message);
        }
    }

})();
