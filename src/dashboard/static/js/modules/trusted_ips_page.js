/**
 * SSH Guardian v3.0 - Trusted IPs Page Module
 */

const TrustedIPs = {
    data: [],
    filteredData: [],
    currentType: 'ip',

    // IPv4 validation regex
    ipv4Regex: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,

    // CIDR validation regex (IPv4/prefix)
    cidrRegex: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/,

    async init() {
        await this.loadData();
    },

    async loadData() {
        try {
            const response = await fetch('/api/trusted/sources', {
                headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
            });
            const result = await response.json();

            if (result.success) {
                this.data = result.sources || [];
                this.updateStats();
                this.applyFilters();
            } else {
                this.showError('Failed to load trusted sources');
            }
        } catch (error) {
            console.error('Error loading trusted IPs:', error);
            this.showError('Error loading data');
        }
    },

    updateStats() {
        const total = this.data.length;
        const auto = this.data.filter(d => d.is_auto_trusted && !d.is_manually_trusted).length;
        const manual = this.data.filter(d => d.is_manually_trusted).length;
        const networks = this.data.filter(d => d.source_type === 'network').length;

        document.getElementById('tip-stat-total').textContent = total;
        document.getElementById('tip-stat-auto').textContent = auto;
        document.getElementById('tip-stat-manual').textContent = manual;
        document.getElementById('tip-stat-networks').textContent = networks;
    },

    applyFilters() {
        const typeFilter = document.getElementById('tip-filter-type').value;
        const sourceFilter = document.getElementById('tip-filter-source').value;
        const searchTerm = document.getElementById('tip-search').value.toLowerCase();

        this.filteredData = this.data.filter(item => {
            if (typeFilter && item.source_type !== typeFilter) return false;
            if (sourceFilter === 'auto' && !item.is_auto_trusted) return false;
            if (sourceFilter === 'manual' && !item.is_manually_trusted) return false;

            if (searchTerm) {
                const searchFields = [
                    item.ip_address,
                    item.network_cidr,
                    item.trust_reason
                ].filter(Boolean).join(' ').toLowerCase();
                if (!searchFields.includes(searchTerm)) return false;
            }

            return true;
        });

        this.renderTable();
    },

    renderTable() {
        const tbody = document.getElementById('tip-table-body');
        const emptyState = document.getElementById('tip-empty');
        const tableContainer = document.getElementById('tip-table-container');

        if (this.filteredData.length === 0) {
            tbody.innerHTML = '';
            tableContainer.style.display = 'none';
            emptyState.style.display = 'block';
            return;
        }

        tableContainer.style.display = 'block';
        emptyState.style.display = 'none';

        tbody.innerHTML = this.filteredData.map(item => {
            const ipDisplay = item.ip_address || item.network_cidr || '-';
            const typeBadge = item.source_type === 'network'
                ? '<span class="tip-tag tip-tag-network">Network</span>'
                : '<span class="tip-tag tip-tag-ip">IP</span>';

            const sourceBadge = item.is_manually_trusted
                ? '<span class="tip-tag tip-tag-manual">Manual</span>'
                : '<span class="tip-tag tip-tag-auto">Auto</span>';

            const score = parseFloat(item.trust_score) || 0;
            const scoreClass = score >= 80 ? 'tip-score-high' : score >= 50 ? 'tip-score-medium' : 'tip-score-low';

            const successLogins = item.successful_logins || 0;
            const failedLogins = item.failed_logins || 0;

            const trustedAt = item.trusted_at ? this.formatDate(item.trusted_at) : '-';
            const lastSeen = item.last_seen_at ? this.formatDate(item.last_seen_at) : '-';

            return `
                <tr>
                    <td class="ip-cell">${this.escapeHtml(ipDisplay)}</td>
                    <td>${typeBadge}</td>
                    <td>
                        <div class="tip-score">
                            <span class="tip-score-value">${score.toFixed(0)}</span>
                            <div class="tip-score-bar">
                                <div class="tip-score-fill ${scoreClass}" style="width: ${score}%"></div>
                            </div>
                        </div>
                    </td>
                    <td>
                        <div class="tip-logins">
                            <span class="tip-logins-success">${successLogins}</span>
                            <span>/</span>
                            <span class="tip-logins-failed">${failedLogins}</span>
                        </div>
                    </td>
                    <td>${sourceBadge}</td>
                    <td>${this.escapeHtml(item.trust_reason || '-')}</td>
                    <td>${trustedAt}</td>
                    <td>${lastSeen}</td>
                    <td>
                        <button class="tip-btn tip-btn-danger" onclick="TrustedIPs.removeEntry(${item.id})" title="Remove from trusted">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    },

    // Validation functions
    isValidIPv4(ip) {
        return this.ipv4Regex.test(ip);
    },

    isValidCIDR(cidr) {
        return this.cidrRegex.test(cidr);
    },

    validateIPInput(input) {
        const value = input.value.trim();
        const errorEl = document.getElementById('tip-ip-error');
        const hintEl = document.getElementById('tip-ip-hint');

        if (!value) {
            input.classList.remove('valid', 'invalid');
            errorEl.style.display = 'none';
            hintEl.style.display = 'block';
            return false;
        }

        if (this.isValidIPv4(value)) {
            input.classList.remove('invalid');
            input.classList.add('valid');
            errorEl.style.display = 'none';
            hintEl.style.display = 'block';
            return true;
        } else {
            input.classList.remove('valid');
            input.classList.add('invalid');
            errorEl.textContent = 'Invalid IPv4 format. Use format: 192.168.1.100';
            errorEl.style.display = 'block';
            hintEl.style.display = 'none';
            return false;
        }
    },

    validateCIDRInput(input) {
        const value = input.value.trim();
        const errorEl = document.getElementById('tip-network-error');
        const hintEl = document.getElementById('tip-network-hint');

        if (!value) {
            input.classList.remove('valid', 'invalid');
            errorEl.style.display = 'none';
            hintEl.style.display = 'block';
            return false;
        }

        if (this.isValidCIDR(value)) {
            input.classList.remove('invalid');
            input.classList.add('valid');
            errorEl.style.display = 'none';
            hintEl.style.display = 'block';
            return true;
        } else {
            input.classList.remove('valid');
            input.classList.add('invalid');

            // More specific error messages
            if (value.includes('/')) {
                const [ip, prefix] = value.split('/');
                if (!this.ipv4Regex.test(ip)) {
                    errorEl.textContent = 'Invalid IP address portion';
                } else {
                    const prefixNum = parseInt(prefix);
                    if (isNaN(prefixNum) || prefixNum < 0 || prefixNum > 32) {
                        errorEl.textContent = 'Prefix must be between 0 and 32';
                    } else {
                        errorEl.textContent = 'Invalid CIDR format';
                    }
                }
            } else {
                errorEl.textContent = 'Missing prefix (e.g., /24)';
            }

            errorEl.style.display = 'block';
            hintEl.style.display = 'none';
            return false;
        }
    },

    // Type toggle
    setType(type) {
        this.currentType = type;
        document.getElementById('tip-form-type').value = type;

        // Update toggle buttons
        document.querySelectorAll('.tip-type-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.type === type);
        });

        // Show/hide appropriate input
        document.getElementById('tip-form-ip-group').style.display = type === 'ip' ? 'block' : 'none';
        document.getElementById('tip-form-network-group').style.display = type === 'network' ? 'block' : 'none';

        // Clear validation states
        const ipInput = document.getElementById('tip-form-ip');
        const networkInput = document.getElementById('tip-form-network');
        ipInput.classList.remove('valid', 'invalid');
        networkInput.classList.remove('valid', 'invalid');
        document.getElementById('tip-ip-error').style.display = 'none';
        document.getElementById('tip-network-error').style.display = 'none';
        document.getElementById('tip-ip-hint').style.display = 'block';
        document.getElementById('tip-network-hint').style.display = 'block';
    },

    showAddModal() {
        document.getElementById('tip-modal-title').textContent = 'Add Trusted IP';
        document.getElementById('tip-form-ip').value = '';
        document.getElementById('tip-form-network').value = '';
        document.getElementById('tip-form-reason').value = '';

        // Reset to IP type
        this.setType('ip');

        document.getElementById('tip-modal').style.display = 'flex';
    },

    closeModal() {
        document.getElementById('tip-modal').style.display = 'none';
    },

    toggleFormType() {
        const type = document.getElementById('tip-form-type').value;
        this.setType(type);
    },

    async saveEntry() {
        const type = document.getElementById('tip-form-type').value;
        const ip = document.getElementById('tip-form-ip').value.trim();
        const network = document.getElementById('tip-form-network').value.trim();
        const reason = document.getElementById('tip-form-reason').value.trim();

        // Validate based on type
        if (type === 'ip') {
            if (!ip) {
                this.showToast('Please enter an IP address', 'error');
                document.getElementById('tip-form-ip').focus();
                return;
            }
            if (!this.isValidIPv4(ip)) {
                this.showToast('Invalid IPv4 address format', 'error');
                document.getElementById('tip-form-ip').focus();
                return;
            }
        } else {
            if (!network) {
                this.showToast('Please enter a network CIDR', 'error');
                document.getElementById('tip-form-network').focus();
                return;
            }
            if (!this.isValidCIDR(network)) {
                this.showToast('Invalid CIDR format. Use format: 192.168.1.0/24', 'error');
                document.getElementById('tip-form-network').focus();
                return;
            }
        }

        const payload = {
            reason: reason || 'Manually added'
        };

        if (type === 'ip') {
            payload.ip_address = ip;
        } else {
            payload.network_cidr = network;
        }

        // Disable save button
        const saveBtn = document.getElementById('tip-save-btn');
        const originalText = saveBtn.innerHTML;
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Saving...';

        try {
            const response = await fetch('/api/trusted/add', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (result.success) {
                this.closeModal();
                await this.loadData();
                this.showToast('Trusted IP added successfully', 'success');
            } else {
                this.showToast(result.error || 'Failed to add trusted IP', 'error');
            }
        } catch (error) {
            console.error('Error saving:', error);
            this.showToast('Error saving trusted IP', 'error');
        } finally {
            saveBtn.disabled = false;
            saveBtn.innerHTML = originalText;
        }
    },

    async removeEntry(id) {
        if (!confirm('Are you sure you want to remove this trusted source?')) {
            return;
        }

        try {
            const response = await fetch(`/api/trusted/remove/${id}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${localStorage.getItem('token')}`
                }
            });

            const result = await response.json();

            if (result.success) {
                await this.loadData();
                this.showToast('Trusted source removed', 'success');
            } else {
                this.showToast(result.error || 'Failed to remove', 'error');
            }
        } catch (error) {
            console.error('Error removing:', error);
            this.showToast('Error removing trusted source', 'error');
        }
    },

    async refresh() {
        document.getElementById('tip-table-body').innerHTML = '<tr><td colspan="9" class="tip-loading">Loading...</td></tr>';
        await this.loadData();
        this.showToast('Data refreshed', 'success');
    },

    formatDate(dateStr) {
        if (!dateStr) return '-';
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        });
    },

    escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    showError(message) {
        document.getElementById('tip-table-body').innerHTML = `
            <tr><td colspan="9" class="tip-loading" style="color: var(--tip-red);">${message}</td></tr>
        `;
    },

    showToast(message, type = 'info') {
        if (window.showToast) {
            window.showToast(message, type);
        } else if (window.Toast && window.Toast.show) {
            window.Toast.show(message, type);
        } else {
            console.log(`[${type}] ${message}`);
        }
    }
};

// Page loader function
async function loadTrustedIPsPage() {
    await TrustedIPs.init();
}

// Export for module system
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { TrustedIPs, loadTrustedIPsPage };
}
