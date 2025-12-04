/**
 * Agent Search Module
 * Handles filtering and searching of agents
 */

let allAgents = []; // Store all agents for filtering

// Initialize search functionality
function initAgentSearch() {
    const searchInput = document.getElementById('agent-search-input');
    const statusFilter = document.getElementById('agent-status-filter');
    const environmentFilter = document.getElementById('agent-environment-filter');

    if (searchInput) {
        searchInput.addEventListener('input', filterAgents);
    }
    if (statusFilter) {
        statusFilter.addEventListener('change', filterAgents);
    }
    if (environmentFilter) {
        environmentFilter.addEventListener('change', filterAgents);
    }
}

// Store agents for filtering
function storeAgentsForSearch(agents) {
    allAgents = agents;
}

// Filter agents based on search and filters
function filterAgents() {
    const searchTerm = document.getElementById('agent-search-input')?.value.toLowerCase() || '';
    const statusFilter = document.getElementById('agent-status-filter')?.value || 'all';
    const environmentFilter = document.getElementById('agent-environment-filter')?.value || 'all';

    const filtered = allAgents.filter(agent => {
        // Search filter
        const matchesSearch = !searchTerm ||
            agent.hostname?.toLowerCase().includes(searchTerm) ||
            agent.agent_id?.toLowerCase().includes(searchTerm) ||
            agent.ip_address_primary?.toLowerCase().includes(searchTerm) ||
            agent.display_name?.toLowerCase().includes(searchTerm);

        // Status filter
        const matchesStatus = statusFilter === 'all' ||
            (statusFilter === 'online' && agent.status === 'online' && agent.last_heartbeat) ||
            (statusFilter === 'offline' && (agent.status !== 'online' || !agent.last_heartbeat)) ||
            (statusFilter === 'approved' && agent.is_approved) ||
            (statusFilter === 'pending' && !agent.is_approved);

        // Environment filter
        const matchesEnvironment = environmentFilter === 'all' ||
            agent.environment === environmentFilter;

        return matchesSearch && matchesStatus && matchesEnvironment;
    });

    // Display filtered agents
    displayFilteredAgents(filtered);
    updateSearchStats(filtered.length, allAgents.length);
}

// Display filtered agents
function displayFilteredAgents(agents) {
    const container = document.getElementById('agents-container');

    if (agents.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🔍</div>
                <div class="empty-state-title">No Agents Found</div>
                <div class="empty-state-description">Try adjusting your search or filters</div>
            </div>
        `;
        return;
    }

    container.innerHTML = agents.map(agent => createAgentCard(agent)).join('');
}

// Update search stats
function updateSearchStats(filtered, total) {
    const statsEl = document.getElementById('search-stats');
    if (statsEl) {
        if (filtered === total) {
            statsEl.textContent = `Showing all ${total} agents`;
        } else {
            statsEl.textContent = `Showing ${filtered} of ${total} agents`;
        }
    }
}

// Clear all filters
function clearAgentFilters() {
    const searchInput = document.getElementById('agent-search-input');
    const statusFilter = document.getElementById('agent-status-filter');
    const environmentFilter = document.getElementById('agent-environment-filter');

    if (searchInput) searchInput.value = '';
    if (statusFilter) statusFilter.value = 'all';
    if (environmentFilter) environmentFilter.value = 'all';

    filterAgents();
}
