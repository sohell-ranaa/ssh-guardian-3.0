/**
 * SSH Guardian v3.0 - Firewall Utilities
 * Firewall-specific utility functions
 * Note: Common utilities (escapeHtml, formatTimeAgo, showNotification, etc.)
 *       are now in utils.js which is loaded first
 */

// ===============================================
// IPv4 Octet Input Handling
// ===============================================

let ipOctetInputsInitialized = false;

function validateOctet(value) {
    if (value === '') return { valid: true, empty: true };
    if (!/^\d+$/.test(value)) return { valid: false, error: 'Numbers only' };
    const num = parseInt(value, 10);
    if (num < 0 || num > 255) return { valid: false, error: 'Must be 0-255' };
    return { valid: true, empty: false };
}

function getIPFromOctets() {
    const o1 = document.getElementById('ipOctet1')?.value.trim() || '';
    const o2 = document.getElementById('ipOctet2')?.value.trim() || '';
    const o3 = document.getElementById('ipOctet3')?.value.trim() || '';
    const o4 = document.getElementById('ipOctet4')?.value.trim() || '';

    if (!o1 || !o2 || !o3 || !o4) return '';
    return `${o1}.${o2}.${o3}.${o4}`;
}

function setIPToOctets(ip) {
    const parts = ip ? ip.split('.') : ['', '', '', ''];
    document.getElementById('ipOctet1').value = parts[0] || '';
    document.getElementById('ipOctet2').value = parts[1] || '';
    document.getElementById('ipOctet3').value = parts[2] || '';
    document.getElementById('ipOctet4').value = parts[3] || '';
}

function updateIPContainerState() {
    const container = document.getElementById('ipInputContainer');
    const msgEl = document.getElementById('quickBlockMessage');
    if (!container) return;

    const octets = [
        document.getElementById('ipOctet1'),
        document.getElementById('ipOctet2'),
        document.getElementById('ipOctet3'),
        document.getElementById('ipOctet4')
    ];

    let allValid = true;
    let allFilled = true;
    let hasError = false;

    octets.forEach((octet, i) => {
        const val = octet.value.trim();
        if (!val) {
            allFilled = false;
        } else {
            const result = validateOctet(val);
            if (!result.valid) {
                allValid = false;
                hasError = true;
                octet.style.color = TC.danger;
            } else {
                octet.style.color = 'var(--text-primary)';
            }
        }
    });

    if (hasError) {
        container.style.borderColor = TC.danger;
    } else if (allFilled && allValid) {
        container.style.borderColor = TC.successDark;
        if (msgEl) msgEl.style.display = 'none';
    } else {
        container.style.borderColor = 'var(--border)';
    }

    // Update hidden field
    const hiddenInput = document.getElementById('quickBlockIP');
    if (hiddenInput) {
        hiddenInput.value = allFilled ? getIPFromOctets() : '';
    }
}

function setupIPOctetInputs() {
    if (ipOctetInputsInitialized) return;
    ipOctetInputsInitialized = true;

    const octets = [
        document.getElementById('ipOctet1'),
        document.getElementById('ipOctet2'),
        document.getElementById('ipOctet3'),
        document.getElementById('ipOctet4')
    ];

    const msgEl = document.getElementById('quickBlockMessage');
    const container = document.getElementById('ipInputContainer');

    octets.forEach((octet, index) => {
        if (!octet) return;

        octet.setAttribute('type', 'text');
        octet.setAttribute('inputmode', 'numeric');
        octet.setAttribute('pattern', '[0-9]*');

        // Prevent non-numeric input
        octet.addEventListener('keypress', function(e) {
            if (e.key === 'Tab' || e.key === 'Enter') return;

            if (e.key === '.') {
                e.preventDefault();
                if (index < 3 && this.value) {
                    octets[index + 1].focus();
                }
                return;
            }

            if (!/^[0-9]$/.test(e.key)) {
                e.preventDefault();
                showOctetError('Only numbers 0-9 allowed');
                return;
            }

            const newValue = this.value + e.key;
            const num = parseInt(newValue, 10);
            if (num > 255) {
                e.preventDefault();
                showOctetError('Value must be 0-255');
                if (this.value && index < 3) {
                    octets[index + 1].value = e.key;
                    octets[index + 1].focus();
                    updateIPContainerState();
                }
                return;
            }
        });

        // Validate on input
        octet.addEventListener('input', function(e) {
            let val = this.value.replace(/[^0-9]/g, '');

            if (val.length > 1 && val[0] === '0') {
                val = parseInt(val, 10).toString();
            }

            if (val !== '' && parseInt(val, 10) > 255) {
                val = '255';
                showOctetError('Maximum value is 255');
            }

            this.value = val;

            if (val.length === 3 || (val.length > 0 && parseInt(val, 10) > 25)) {
                if (index < 3) {
                    octets[index + 1].focus();
                    octets[index + 1].select();
                }
            }

            updateIPContainerState();
        });

        // Navigation
        octet.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' && this.value === '' && index > 0) {
                octets[index - 1].focus();
            }
            if (e.key === 'ArrowLeft' && this.selectionStart === 0 && index > 0) {
                e.preventDefault();
                octets[index - 1].focus();
            }
            if (e.key === 'ArrowRight' && this.selectionStart === this.value.length && index < 3) {
                e.preventDefault();
                octets[index + 1].focus();
            }
        });

        // Paste handling
        octet.addEventListener('paste', function(e) {
            e.preventDefault();
            const pastedText = (e.clipboardData || window.clipboardData).getData('text').trim();

            if (pastedText.includes('.')) {
                const parts = pastedText.split('.');
                if (parts.length === 4) {
                    let valid = true;
                    parts.forEach((part, i) => {
                        const num = parseInt(part, 10);
                        if (!isNaN(num) && num >= 0 && num <= 255) {
                            octets[i].value = num.toString();
                        } else {
                            valid = false;
                        }
                    });
                    if (!valid) showOctetError('Invalid IP address format');
                    updateIPContainerState();
                    octets[3].focus();
                    return;
                }
            }

            const num = parseInt(pastedText, 10);
            if (!isNaN(num) && num >= 0 && num <= 255) {
                this.value = num.toString();
                updateIPContainerState();
                if (index < 3) octets[index + 1].focus();
            } else {
                showOctetError('Invalid value (must be 0-255)');
            }
        });

        octet.addEventListener('focus', function() {
            setTimeout(() => this.select(), 10);
            if (msgEl) msgEl.style.display = 'none';
        });
    });

    function showOctetError(message) {
        if (msgEl) {
            msgEl.textContent = message;
            msgEl.style.background = TC.dangerBg;
            msgEl.style.color = TC.danger;
            msgEl.style.display = 'block';
        }
        if (container) {
            container.style.borderColor = TC.danger;
        }
        setTimeout(() => {
            if (msgEl) msgEl.style.display = 'none';
            updateIPContainerState();
        }, 2000);
    }
}

function resetIPOctetInputs() {
    ipOctetInputsInitialized = false;
}

// ===============================================
// Global Exports (firewall-specific functions only)
// Common utilities (escapeHtml, formatTimeAgo, showNotification,
// isPrivateIP, isValidIPv4, fetchWithTimeout) are exported by utils.js
// ===============================================

window.validateOctet = validateOctet;
window.getIPFromOctets = getIPFromOctets;
window.setIPToOctets = setIPToOctets;
window.updateIPContainerState = updateIPContainerState;
window.setupIPOctetInputs = setupIPOctetInputs;
window.resetIPOctetInputs = resetIPOctetInputs;
