/**
 * SSH Guardian v3.0 - Firewall UFW Drag and Drop
 * Rule reordering via drag and drop
 */
(function() {
    'use strict';

    let draggedElement = null;
    let draggedIndex = null;

    function initDragAndDrop() {
        const container = document.getElementById('simpleRulesList');
        if (!container) return;

        const cards = container.querySelectorAll('.simple-rule-card');
        cards.forEach(card => {
            card.addEventListener('dragstart', handleDragStart);
            card.addEventListener('dragover', handleDragOver);
            card.addEventListener('drop', handleDrop);
            card.addEventListener('dragend', handleDragEnd);
            card.addEventListener('dragenter', handleDragEnter);
            card.addEventListener('dragleave', handleDragLeave);
        });
    }

    function handleDragStart(e) {
        draggedElement = this;
        draggedIndex = parseInt(this.dataset.ruleIndex);
        this.classList.add('dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', this.dataset.ruleIndex);
    }

    function handleDragOver(e) {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
    }

    function handleDragEnter(e) {
        e.preventDefault();
        if (this !== draggedElement) {
            this.classList.add('drag-over');
        }
    }

    function handleDragLeave(e) {
        this.classList.remove('drag-over');
    }

    function handleDrop(e) {
        e.preventDefault();
        e.stopPropagation();

        this.classList.remove('drag-over');

        if (draggedElement !== this) {
            const targetIndex = parseInt(this.dataset.ruleIndex);
            const sourceIndex = draggedIndex;

            if (sourceIndex !== targetIndex) {
                if (confirm(`Move rule #${sourceIndex} to position #${targetIndex}?`)) {
                    reorderUFWRules(sourceIndex, targetIndex);
                }
            }
        }

        return false;
    }

    function handleDragEnd(e) {
        this.classList.remove('dragging');
        document.querySelectorAll('.simple-rule-card').forEach(card => {
            card.classList.remove('drag-over');
        });
        draggedElement = null;
        draggedIndex = null;
    }

    async function reorderUFWRules(fromIndex, toIndex) {
        if (!window.currentAgentId) return;

        showUFWMessage('Reordering rules... This may take a moment.', 'info');

        try {
            const response = await fetch(`/api/agents/${window.currentAgentId}/ufw/reorder`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    from_index: fromIndex,
                    to_index: toIndex
                })
            });

            const data = await response.json();

            if (data.success) {
                showUFWMessage('Reorder command queued! Syncing...', 'success');
                if (typeof showNotification === 'function') {
                    showNotification('UFW rules reorder queued', 'success');
                }
                await fetch(`/api/agents/${window.currentAgentId}/ufw/request-sync`, { method: 'POST' });
                if (typeof pollForUpdate === 'function') {
                    pollForUpdate(window.currentAgentId);
                }
            } else {
                showUFWMessage(`Error: ${data.error}`, 'error');
            }
        } catch (error) {
            showUFWMessage(`Error: ${error.message}`, 'error');
        }
    }

    // Global exports
    window.initDragAndDrop = initDragAndDrop;
})();
