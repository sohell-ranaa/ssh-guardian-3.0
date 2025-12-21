/**
 * Blocked IPs - Actions Module
 * Block/Unblock/Delete operations
 */

(function() {
    'use strict';

    const BlockedIPs = window.BlockedIPs = window.BlockedIPs || {};
    const escapeHtml = window.escapeHtml || ((t) => t == null ? '' : String(t).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'})[m]));
    const TC = window.TC || { primary:'#0078D4', danger:'#D13438', success:'#107C10', warning:'#FFB900', purple:'#8764B8', textSecondary:'#605E5C' };

    BlockedIPs.Actions = {
        /**
         * Unblock IP from table
         */
        async unblock(ipAddress, blockId) {
            if (!confirm(`Unblock IP: ${ipAddress}?`)) return;
            await this.unblockIP(ipAddress, 'Unblocked from IP Blocks page');
        },

        /**
         * Re-block a previously unblocked IP
         */
        async reblock(ipAddress) {
            if (!confirm(`Re-block IP: ${ipAddress}?`)) return;

            try {
                const response = await fetch('/api/dashboard/blocking/blocks/manual', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        reason: 'Re-blocked from IP Blocks page',
                        duration_hours: 24
                    })
                });

                const data = await response.json();

                if (data.success) {
                    BlockedIPs.UI.notify(`IP ${ipAddress} has been re-blocked`, 'success');
                    BlockedIPs.Core.loadIPBlocks();
                } else {
                    BlockedIPs.UI.notify(`Failed to re-block IP: ${data.error || 'Unknown error'}`, 'error');
                }
            } catch (error) {
                console.error('Error re-blocking IP:', error);
                BlockedIPs.UI.notify(`Error re-blocking IP: ${error.message}`, 'error');
            }
        },

        /**
         * Disable block (unblock but keep record)
         */
        async disable(ipAddress, blockId) {
            if (!confirm(`Disable block for IP: ${ipAddress}?\n\nThis will unblock the IP but keep the record for reference.`)) {
                return;
            }
            await this.unblockIP(ipAddress, 'Disabled from IP Blocks page');
        },

        /**
         * Unblock IP address
         */
        async unblockIP(ipAddress, reason) {
            try {
                const response = await fetch('/api/dashboard/blocking/blocks/unblock', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ip_address: ipAddress,
                        reason: reason || 'Unblocked from dashboard'
                    })
                });

                const data = await response.json();

                if (data.success) {
                    BlockedIPs.UI.notify(`IP ${ipAddress} has been unblocked`, 'success');
                    BlockedIPs.Core.loadIPBlocks();
                } else {
                    BlockedIPs.UI.notify(`Failed to unblock IP: ${data.error || 'Unknown error'}`, 'error');
                }
            } catch (error) {
                console.error('Error unblocking IP:', error);
                BlockedIPs.UI.notify(`Error unblocking IP: ${error.message}`, 'error');
            }
        },

        /**
         * Show delete confirmation modal
         */
        confirmDelete(ipAddress, blockId) {
            BlockedIPs.Modal.injectStyles();

            document.querySelectorAll('.block-modal-overlay').forEach(el => el.remove());

            const overlay = document.createElement('div');
            overlay.className = 'block-modal-overlay';

            const modal = document.createElement('div');
            modal.className = 'block-modal';

            modal.innerHTML = `
                <div class="block-modal-header" style="background: linear-gradient(135deg, ${TC.danger} 0%, ${TC.danger} 100%);">
                    <h3 class="block-modal-title" style="color: white;">
                        <span style="font-size: 20px;">⚠️</span>
                        Delete Block Record
                    </h3>
                    <button class="block-modal-close" style="color: rgba(255,255,255,0.8);" title="Close">&times;</button>
                </div>
                <div class="block-modal-body" style="padding: 24px;">
                    <p style="margin-bottom: 16px;">This will <strong>permanently delete</strong> the block record for:</p>
                    <div style="background: var(--background); padding: 12px 16px; border-radius: 6px; font-family: monospace; font-size: 16px; margin-bottom: 16px;">
                        ${escapeHtml(ipAddress)}
                    </div>
                    <p style="color: ${TC.danger}; margin-bottom: 16px;">⚠️ This action cannot be undone.</p>
                    <p style="margin-bottom: 8px;">Type the IP address to confirm:</p>
                    <input type="text" id="deleteConfirmInput" class="form-control" placeholder="Enter IP address" style="margin-bottom: 16px;">
                </div>
                <div class="block-modal-footer" style="justify-content: flex-end; gap: 10px;">
                    <button class="block-modal-btn block-modal-btn-secondary modal-cancel">Cancel</button>
                    <button class="block-modal-btn" id="confirmDeleteBtn" style="background: ${TC.danger}; color: white; opacity: 0.5; pointer-events: none;">Delete Record</button>
                </div>
            `;

            overlay.appendChild(modal);
            document.body.appendChild(overlay);
            document.body.style.overflow = 'hidden';

            const input = modal.querySelector('#deleteConfirmInput');
            const deleteBtn = modal.querySelector('#confirmDeleteBtn');

            input.addEventListener('input', () => {
                if (input.value === ipAddress) {
                    deleteBtn.style.opacity = '1';
                    deleteBtn.style.pointerEvents = 'auto';
                } else {
                    deleteBtn.style.opacity = '0.5';
                    deleteBtn.style.pointerEvents = 'none';
                }
            });

            const closeModal = () => {
                overlay.remove();
                document.body.style.overflow = '';
            };

            modal.querySelector('.block-modal-close').onclick = closeModal;
            modal.querySelector('.modal-cancel').onclick = closeModal;
            overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };

            deleteBtn.onclick = async () => {
                if (input.value === ipAddress) {
                    closeModal();
                    await this.deleteFromDB(ipAddress, blockId);
                }
            };

            input.focus();
        },

        /**
         * Delete block record from database
         */
        async deleteFromDB(ipAddress, blockId) {
            try {
                const response = await fetch(`/api/dashboard/blocking/blocks/${blockId}`, {
                    method: 'DELETE',
                    headers: { 'Content-Type': 'application/json' }
                });

                const data = await response.json();

                if (data.success) {
                    BlockedIPs.UI.notify(`Block record for ${ipAddress} has been deleted`, 'success');
                    BlockedIPs.Core.loadIPBlocks();
                } else {
                    BlockedIPs.UI.notify(`Failed to delete record: ${data.error || 'Unknown error'}`, 'error');
                }
            } catch (error) {
                console.error('Error deleting block record:', error);
                BlockedIPs.UI.notify(`Error deleting record: ${error.message}`, 'error');
            }
        }
    };
})();
