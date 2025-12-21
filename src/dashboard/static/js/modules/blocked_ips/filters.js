/**
 * Blocked IPs - Filters Module
 * Search, filter, and agent dropdown functionality
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml;

    BlockedIPs.Filters = {
        /**
         * Load agents for filter dropdown
         */
        async loadAgentsForDropdown() {
            try {
                const response = await fetch('/api/agents/list');
                const data = await response.json();

                if (!data.agents) return;

                const agentFilter = document.getElementById('blockAgentFilter');
                if (!agentFilter) return;

                agentFilter.innerHTML = '<option value="">All Agents (Global)</option>';

                (data.agents || []).forEach(agent => {
                    const option = document.createElement('option');
                    option.value = agent.id;
                    option.textContent = agent.display_name || agent.hostname || `Agent ${agent.id}`;
                    agentFilter.appendChild(option);
                });

                BlockedIPs.state.agents = data.agents;
            } catch (error) {
                console.error('Error loading agents for filter:', error);
            }
        },

        /**
         * Populate agent filter from blocks data
         */
        populateAgentDropdown(uniqueAgents) {
            const filterSelect = document.getElementById('blockSourceAgentFilter');
            if (!filterSelect) return;

            const currentValue = filterSelect.value;
            filterSelect.innerHTML = '<option value="">All Sources</option>';

            uniqueAgents.sort().forEach(agent => {
                const option = document.createElement('option');
                option.value = agent;
                option.textContent = agent;
                filterSelect.appendChild(option);
            });

            filterSelect.value = currentValue;
        },

        /**
         * Setup all filters
         */
        setupAll() {
            this.setupSearchFilter();
            this.setupAgentFilter();
            this.setupSourceFilter();
            this.setupStatusFilter();
        },

        /**
         * Setup search filter
         */
        setupSearchFilter() {
            const searchInput = document.getElementById('blockSearchFilter');
            if (!searchInput) return;

            let debounceTimer;
            searchInput.addEventListener('input', () => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => this.applyFilters(), 300);
            });
        },

        /**
         * Setup agent filter
         */
        setupAgentFilter() {
            const agentFilter = document.getElementById('blockAgentFilter');
            if (!agentFilter) return;

            agentFilter.addEventListener('change', () => {
                BlockedIPs.state.currentAgentFilter = agentFilter.value;
                BlockedIPs.Core.loadIPBlocks();
            });
        },

        /**
         * Setup source filter
         */
        setupSourceFilter() {
            const sourceFilter = document.getElementById('blockSourceAgentFilter');
            if (!sourceFilter) return;

            sourceFilter.addEventListener('change', () => this.applyFilters());
        },

        /**
         * Setup status filter
         */
        setupStatusFilter() {
            const statusFilter = document.getElementById('blockStatusFilter');
            if (!statusFilter) return;

            statusFilter.addEventListener('change', () => this.applyFilters());
        },

        /**
         * Apply all filters to table
         */
        applyFilters() {
            const searchValue = (document.getElementById('blockSearchFilter')?.value || '').toLowerCase();
            const sourceValue = document.getElementById('blockSourceAgentFilter')?.value || '';
            const statusValue = document.getElementById('blockStatusFilter')?.value || '';

            const rows = document.querySelectorAll('#blocksTableBody tr');

            rows.forEach(row => {
                const ip = row.dataset.ip?.toLowerCase() || '';
                const agent = row.dataset.agent || '';
                const source = row.dataset.source?.toLowerCase() || '';
                const isActive = row.querySelector('[style*="background: var(--color-danger)"]') ||
                                 row.querySelector('[style*="background: rgb(209, 52, 56)"]');

                let show = true;

                // Search filter
                if (searchValue && !ip.includes(searchValue)) {
                    show = false;
                }

                // Source/Agent filter
                if (sourceValue && agent !== sourceValue) {
                    show = false;
                }

                // Status filter
                if (statusValue === 'active' && !isActive) {
                    show = false;
                } else if (statusValue === 'expired' && isActive) {
                    show = false;
                }

                row.style.display = show ? '' : 'none';
            });
        }
    };
})();
