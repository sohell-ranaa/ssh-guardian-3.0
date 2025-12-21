/**
 * SSH Guardian v3.0 - Simulation Blocking
 * IP blocking modal and execution
 */
(function() {
    'use strict';

    window.Sim = window.Sim || {};

    Sim.Blocking = {
        async showModal(ip) {
            console.log('[Block] Checking IP status:', ip);

            const modal = document.createElement('div');
            modal.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 10000;';

            const modalContent = document.createElement('div');
            modalContent.style.cssText = 'background: var(--card-bg); border-radius: 12px; padding: 24px; max-width: 600px; width: 90%; box-shadow: 0 8px 32px rgba(0,0,0,0.3);';

            modalContent.innerHTML = `<h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">🔍 Checking IP Status...</h3>
                <div style="text-align: center; padding: 40px;"><div style="font-size: 48px;">⏳</div>
                <p style="margin: 16px 0 0 0; color: var(--text-secondary);">Checking if ${ip} is already blocked...</p></div>`;

            modal.appendChild(modalContent);
            document.body.appendChild(modal);

            try {
                const globalResponse = await fetch(`/api/dashboard/blocking/blocks/check/${ip}`, { credentials: 'same-origin' });
                const globalStatus = await globalResponse.json();

                const agentsResponse = await fetch('/api/agents/list', { credentials: 'same-origin' });
                const agentsData = await agentsResponse.json();
                const agents = agentsData.agents || [];

                const agentChecks = await Promise.all(
                    agents.map(async (agent) => {
                        try {
                            const resp = await fetch(`/api/agents/${agent.id}/blocked-ips`, { credentials: 'same-origin' });
                            const data = await resp.json();
                            const isBlocked = data.blocked_ips?.some(blocked => blocked.ip_address === ip);
                            return { agent: agent.hostname, id: agent.id, blocked: isBlocked };
                        } catch (err) {
                            return { agent: agent.hostname, id: agent.id, blocked: false, error: true };
                        }
                    })
                );

                const blockedOnAgents = agentChecks.filter(a => a.blocked);
                const isAlreadyBlocked = globalStatus.is_blocked || blockedOnAgents.length > 0;

                modalContent.innerHTML = `
                    <h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">${isAlreadyBlocked ? '⚠️' : '🚫'} Block IP Address</h3>
                    <div style="background: var(--background); padding: 16px; border-radius: 8px; margin-bottom: 16px;">
                        <div style="font-family: monospace; font-size: 18px; font-weight: 600; color: var(--azure-blue);">${ip}</div>
                    </div>
                    ${isAlreadyBlocked ? `
                        <div style="background: rgba(230, 165, 2, 0.1); border-left: 4px solid ${TC.warning}; padding: 12px; margin-bottom: 16px; border-radius: 4px;">
                            <strong style="color: ${TC.warning};">⚠️ Already Blocked</strong>
                            <ul style="margin: 8px 0 0 0; padding-left: 20px; font-size: 13px;">
                                ${globalStatus.is_blocked ? `<li><strong>Global Blocklist</strong></li>` : ''}
                                ${blockedOnAgents.map(a => `<li>Agent: ${a.agent}</li>`).join('')}
                            </ul>
                        </div>` : `
                        <div style="background: rgba(209, 52, 56, 0.1); border-left: 4px solid ${TC.danger}; padding: 12px; margin-bottom: 16px; border-radius: 4px;">
                            <p style="margin: 0; font-size: 14px;"><strong>⚠️ Warning:</strong> This will block the IP on all agents.</p>
                        </div>`}
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; font-size: 14px;">Block Reason:</label>
                        <input id="block-reason" type="text" value="Threat detected via simulation" style="width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: var(--background); color: var(--text-primary);">
                    </div>
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; margin-bottom: 8px; font-weight: 600; font-size: 14px;">Duration:</label>
                        <select id="block-duration" style="width: 100%; padding: 10px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; background: var(--background); color: var(--text-primary);">
                            <option value="permanent">Permanent</option>
                            <option value="24h">24 Hours</option>
                            <option value="7d">7 Days</option>
                            <option value="30d">30 Days</option>
                        </select>
                    </div>
                    <div style="display: flex; gap: 12px; justify-content: flex-end;">
                        <button onclick="this.closest('[style*=fixed]').remove()" style="padding: 10px 20px; background: var(--background); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-weight: 600;">Cancel</button>
                        ${!isAlreadyBlocked ? `<button onclick="Sim.Blocking.execute('${ip}')" style="padding: 10px 20px; background: ${TC.danger}; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;">🚫 Block IP</button>` : ''}
                    </div>`;

            } catch (error) {
                console.error('[Block] Error checking status:', error);
                modalContent.innerHTML = `<h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600;">❌ Error</h3>
                    <p style="margin: 0 0 16px 0;">Failed to check IP status: ${error.message}</p>
                    <button onclick="this.closest('[style*=fixed]').remove()" style="padding: 10px 20px; background: var(--background); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-weight: 600;">Close</button>`;
            }
        },

        async execute(ip) {
            const reason = document.getElementById('block-reason').value;
            const duration = document.getElementById('block-duration').value;
            const modal = document.querySelector('[style*="position: fixed"]');

            console.log('[Block] Executing block:', { ip, reason, duration });

            try {
                const response = await fetch('/api/dashboard/blocking/blocks', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'same-origin',
                    body: JSON.stringify({ ip_address: ip, reason, duration })
                });

                const result = await response.json();

                if (result.success) {
                    showToast(`✅ IP ${ip} blocked successfully`, 'success');
                    modal.remove();
                } else {
                    showToast(`❌ Failed to block IP: ${result.error}`, 'error');
                }
            } catch (error) {
                console.error('[Block] Error:', error);
                showToast('❌ Failed to block IP', 'error');
            }
        }
    };
})();
