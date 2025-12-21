/**
 * SSH Guardian v3.0 - Toast Notification Component
 * Shared toast system with stacking, progress bar, and controls
 */

const ToastManager = {
    container: null,
    maxToasts: 5,
    toasts: [],
    stylesAdded: false,

    init() {
        if (this.container) return;

        this.container = document.createElement('div');
        this.container.id = 'toast-container';
        this.container.style.cssText = `
            position: fixed;
            top: 16px;
            right: 16px;
            z-index: 10001;
            display: flex;
            flex-direction: column;
            gap: 8px;
            max-width: 360px;
            pointer-events: none;
        `;
        document.body.appendChild(this.container);
        this.addStyles();
    },

    addStyles() {
        if (this.stylesAdded) return;
        const style = document.createElement('style');
        style.id = 'toast-styles';
        style.textContent = `
            .toast-item {
                display: flex;
                align-items: flex-start;
                gap: 10px;
                padding: 12px 14px;
                border-radius: 8px;
                color: white;
                font-size: 13px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                pointer-events: auto;
                position: relative;
                overflow: hidden;
                animation: toastSlideIn 0.25s ease-out;
                cursor: pointer;
            }
            .toast-item:hover { filter: brightness(1.05); }
            .toast-item.removing { animation: toastSlideOut 0.2s ease-in forwards; }
            .toast-icon { font-size: 15px; flex-shrink: 0; margin-top: 1px; }
            .toast-content { flex: 1; line-height: 1.4; word-break: break-word; }
            .toast-close {
                background: none;
                border: none;
                color: rgba(255,255,255,0.7);
                cursor: pointer;
                font-size: 16px;
                padding: 0;
                line-height: 1;
                flex-shrink: 0;
                transition: color 0.15s;
            }
            .toast-close:hover { color: white; }
            .toast-progress {
                position: absolute;
                bottom: 0;
                left: 0;
                height: 3px;
                background: rgba(255,255,255,0.4);
                border-radius: 0 0 8px 8px;
            }
            .toast-success { background: linear-gradient(135deg, var(--color-success, #10b981) 0%, var(--color-success-dark, #059669) 100%); }
            .toast-error { background: linear-gradient(135deg, var(--color-danger, #ef4444) 0%, var(--color-danger-dark, #dc2626) 100%); }
            .toast-warning { background: linear-gradient(135deg, var(--color-warning, #f59e0b) 0%, var(--color-warning-dark, #d97706) 100%); }
            .toast-info { background: linear-gradient(135deg, var(--azure-blue, #3b82f6) 0%, var(--azure-dark, #2563eb) 100%); }
            @keyframes toastSlideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes toastSlideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
            @keyframes toastProgress {
                from { width: 100%; }
                to { width: 0%; }
            }
        `;
        document.head.appendChild(style);
        this.stylesAdded = true;
    },

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text || '';
        return div.innerHTML;
    },

    show(message, type = 'info', duration = 4000) {
        this.init();

        // Prevent duplicates
        if (this.toasts.some(t => t.message === message)) return;

        // Remove oldest if at max
        while (this.toasts.length >= this.maxToasts) {
            this.remove(this.toasts[0].id);
        }

        const id = Date.now() + Math.random();
        const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };

        const toast = document.createElement('div');
        toast.className = `toast-item toast-${type}`;
        toast.dataset.id = id;
        toast.innerHTML = `
            <span class="toast-icon">${icons[type] || icons.info}</span>
            <span class="toast-content">${this.escapeHtml(message)}</span>
            <button class="toast-close" aria-label="Close">&times;</button>
            <div class="toast-progress" style="animation: toastProgress ${duration}ms linear forwards;"></div>
        `;

        toast.addEventListener('click', () => this.remove(id));

        // Pause on hover
        let timeoutId;
        const startTimer = () => {
            timeoutId = setTimeout(() => this.remove(id), duration);
            const progress = toast.querySelector('.toast-progress');
            if (progress) progress.style.animationPlayState = 'running';
        };
        const pauseTimer = () => {
            clearTimeout(timeoutId);
            const progress = toast.querySelector('.toast-progress');
            if (progress) progress.style.animationPlayState = 'paused';
        };

        toast.addEventListener('mouseenter', pauseTimer);
        toast.addEventListener('mouseleave', startTimer);

        this.container.appendChild(toast);
        this.toasts.push({ id, message, element: toast });
        startTimer();

        return id;
    },

    remove(id) {
        const index = this.toasts.findIndex(t => t.id === id);
        if (index === -1) return;

        const toast = this.toasts[index].element;
        toast.classList.add('removing');
        setTimeout(() => {
            toast.remove();
            this.toasts.splice(index, 1);
        }, 200);
    },

    clear() {
        this.toasts.forEach(t => t.element.remove());
        this.toasts = [];
    }
};

// Public API
function showToast(message, type = 'info', duration = 4000) {
    return ToastManager.show(message, type, duration);
}

function showNotification(type, message, duration = 4000) {
    return ToastManager.show(message, type, duration);
}

function clearToasts() {
    ToastManager.clear();
}

// Global exports
window.ToastManager = ToastManager;
window.showToast = showToast;
window.showNotification = showNotification;
window.clearToasts = clearToasts;
