/**
 * SSH Guardian v3.0 - Firewall UFW Listening Ports
 * Renders listening ports view
 */
(function() {
    'use strict';

    function renderListeningPorts(ports) {
        const container = document.getElementById('interfacesGrid');
        if (!container) return;

        if (!ports || ports.length === 0) {
            container.innerHTML = '<p style="color: var(--text-secondary);">No listening ports detected</p>';
            return;
        }

        container.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px;">
                ${ports.slice(0, 12).map(port => {
                    const isProtected = port.is_protected;
                    return `
                        <div style="background: var(--background); padding: 10px 14px; border-radius: 4px; border: 1px solid var(--border); ${isProtected ? `border-left: 3px solid ${TC.successDark};` : ''}">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-weight: 600; font-size: 16px;">${port.port}</span>
                                <span style="font-size: 11px; color: var(--text-secondary);">${port.protocol.toUpperCase()}</span>
                            </div>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
                                ${port.process_name || 'unknown'}
                            </div>
                            ${isProtected ? `<span style="font-size: 10px; color: ${TC.successDark};">Protected</span>` : ''}
                        </div>
                    `;
                }).join('')}
            </div>
            ${ports.length > 12 ? `<p style="color: var(--text-secondary); margin-top: 10px; font-size: 12px;">+ ${ports.length - 12} more ports</p>` : ''}
        `;
    }

    // Global exports
    window.renderListeningPorts = renderListeningPorts;
})();
