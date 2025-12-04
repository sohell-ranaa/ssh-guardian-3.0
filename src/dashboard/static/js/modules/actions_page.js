/**
 * Blocking Actions Page Module
 * Displays audit log of blocking/unblocking actions
 */

// Load Actions page
async function loadActionsPage() {
    await loadActionsList();
    loadActionsStats();
    setupActionsFilters();
}

// Load actions list
async function loadActionsList() {
    const loadingEl = document.getElementById('actionsLoading');
    const tableEl = document.getElementById('actionsTable');
    const errorEl = document.getElementById('actionsError');

    try {
        // Show loading
        if (loadingEl) loadingEl.style.display = 'block';
        if (tableEl) tableEl.style.display = 'none';
        if (errorEl) errorEl.style.display = 'none';

        // Get filter values
        const actionType = document.getElementById('actionTypeFilter')?.value || '';
        const actionSource = document.getElementById('actionSourceFilter')?.value || '';

        const params = new URLSearchParams({ limit: 100, offset: 0 });
        if (actionType) params.append('action_type', actionType);
        if (actionSource) params.append('action_source', actionSource);

        const response = await fetch(`/api/dashboard/blocking/actions/list?${params}`);
        const data = await response.json();

        if (!data.success || !data.actions || data.actions.length === 0) {
            if (loadingEl) loadingEl.style.display = 'none';
            if (tableEl) {
                tableEl.innerHTML = '<div class="empty-state-small">No blocking actions found</div>';
                tableEl.style.display = 'block';
            }
            return;
        }

        // Build table
        const tableBody = document.getElementById('actionsTableBody');
        if (!tableBody) return;

        tableBody.innerHTML = data.actions.map(action => {
            // Action type badge
            const typeBadge = {
                'blocked': '<span style="padding: 4px 10px; background: #D13438; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">BLOCKED</span>',
                'unblocked': '<span style="padding: 4px 10px; background: #107C10; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">UNBLOCKED</span>',
                'modified': '<span style="padding: 4px 10px; background: #FFB900; color: #323130; border-radius: 3px; font-size: 11px; font-weight: 600;">MODIFIED</span>'
            }[action.action_type] || action.action_type;

            // Action source badge
            const sourceBadge = {
                'system': '<span style="padding: 4px 8px; background: #8A8886; color: white; border-radius: 3px; font-size: 11px;">System</span>',
                'manual': '<span style="padding: 4px 8px; background: #0078D4; color: white; border-radius: 3px; font-size: 11px;">Manual</span>',
                'rule': '<span style="padding: 4px 8px; background: #8764B8; color: white; border-radius: 3px; font-size: 11px;">Rule</span>',
                'api': '<span style="padding: 4px 8px; background: #CA5010; color: white; border-radius: 3px; font-size: 11px;">API</span>'
            }[action.action_source] || action.action_source;

            // Location
            const location = action.location ?
                `${action.location.city || 'Unknown'}, ${action.location.country || ''}` :
                'N/A';

            // Performed by
            const performedBy = action.performed_by ?
                `${action.performed_by.name} (${action.performed_by.username})` :
                (action.triggered_by_rule || 'System');

            return `
                <tr style="border-bottom: 1px solid var(--border-light);">
                    <td style="padding: 12px; font-size: 12px;">
                        ${formatLocalDateTime(action.created_at)}
                    </td>
                    <td style="padding: 12px;">${typeBadge}</td>
                    <td style="padding: 12px; font-family: monospace; font-size: 13px; font-weight: 600;">
                        ${escapeHtml(action.ip_address)}
                    </td>
                    <td style="padding: 12px; font-size: 12px;">${location}</td>
                    <td style="padding: 12px;">${sourceBadge}</td>
                    <td style="padding: 12px; font-size: 12px;">
                        ${performedBy}
                    </td>
                    <td style="padding: 12px; font-size: 12px;">
                        ${escapeHtml(action.reason || 'No reason specified')}
                    </td>
                </tr>
            `;
        }).join('');

        // Show table
        if (loadingEl) loadingEl.style.display = 'none';
        if (tableEl) tableEl.style.display = 'block';

    } catch (error) {
        console.error('Error loading actions:', error);
        if (loadingEl) loadingEl.style.display = 'none';
        if (errorEl) errorEl.style.display = 'block';
    }
}

// Load statistics
async function loadActionsStats() {
    const statsContainer = document.getElementById('actionsStatsContainer');
    if (!statsContainer) return;

    try {
        const response = await fetch('/api/dashboard/blocking/actions/stats');
        const data = await response.json();

        if (!data.success) return;

        statsContainer.innerHTML = `
            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                <div style="padding: 12px 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Total Actions</div>
                    <div style="font-size: 24px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">${data.totals.total_actions}</div>
                </div>
                <div style="padding: 12px 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Total Blocks</div>
                    <div style="font-size: 24px; font-weight: 700; color: #D13438; margin-top: 4px;">${data.totals.total_blocks}</div>
                </div>
                <div style="padding: 12px 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Total Unblocks</div>
                    <div style="font-size: 24px; font-weight: 700; color: #107C10; margin-top: 4px;">${data.totals.total_unblocks}</div>
                </div>
                <div style="padding: 12px 20px; background: var(--card-bg); border: 1px solid var(--border); border-radius: 4px;">
                    <div style="font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px;">Unique IPs</div>
                    <div style="font-size: 24px; font-weight: 700; color: var(--text-primary); margin-top: 4px;">${data.totals.unique_ips}</div>
                </div>
            </div>
        `;
    } catch (error) {
        console.error('Error loading actions stats:', error);
    }
}

// Setup filters
function setupActionsFilters() {
    const actionTypeFilter = document.getElementById('actionTypeFilter');
    const actionSourceFilter = document.getElementById('actionSourceFilter');
    const refreshBtn = document.getElementById('refreshActionsBtn');

    if (actionTypeFilter) {
        actionTypeFilter.onchange = loadActionsList;
    }

    if (actionSourceFilter) {
        actionSourceFilter.onchange = loadActionsList;
    }

    if (refreshBtn) {
        refreshBtn.onclick = () => {
            loadActionsList();
            loadActionsStats();
        };
    }
}
