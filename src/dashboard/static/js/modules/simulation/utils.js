/**
 * SSH Guardian v3.0 - Simulation Utilities
 * Common utility functions
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Utils = {
        copyToClipboard(text, label = 'Text') {
            const onSuccess = () => showToast(`${label} copied`, 'success');
            const onError = () => showToast('Copy failed', 'error');

            if (navigator.clipboard?.writeText) {
                navigator.clipboard.writeText(text).then(onSuccess).catch(() => this._fallbackCopy(text, onSuccess, onError));
            } else {
                this._fallbackCopy(text, onSuccess, onError);
            }
        },

        _fallbackCopy(text, onSuccess, onError) {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.cssText = 'position: fixed; opacity: 0;';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                onSuccess();
            } catch (err) {
                onError();
            }
            document.body.removeChild(textarea);
        }
    };
})();
