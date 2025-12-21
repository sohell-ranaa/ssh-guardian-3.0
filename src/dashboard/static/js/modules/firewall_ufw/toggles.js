/**
 * SSH Guardian v3.0 - Firewall UFW Toggles
 * Toggle functions and advanced view
 */
(function() {
    'use strict';

    let showAdvanced = false;

    function toggleCustomPort(select) {
        const customInput = document.getElementById('simpleRuleCustomPort');
        if (customInput) {
            customInput.style.display = select.value === 'custom' ? 'inline-block' : 'none';
        }
    }

    function toggleAdvancedView() {
        showAdvanced = !showAdvanced;
        const section = document.getElementById('advancedViewSection');
        if (!section) return;

        if (showAdvanced) {
            section.style.display = 'block';
            if (typeof ufwData !== 'undefined' && ufwData) {
                renderAdvancedRules(ufwData.rules || []);
            }
        } else {
            section.style.display = 'none';
        }
    }

    function renderAdvancedRules(rules) {
        const container = document.getElementById('advancedRulesGrid');
        if (!container) return;

        if (!rules || rules.length === 0) {
            container.innerHTML = '<p style="text-align: center; padding: 20px; color: var(--text-secondary);">No rules found</p>';
            return;
        }

        container.innerHTML = `
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                    <tr style="background: var(--background); border-bottom: 2px solid var(--border);">
                        <th style="padding: 10px; text-align: left;">#</th>
                        <th style="padding: 10px; text-align: left;">Action</th>
                        <th style="padding: 10px; text-align: left;">Dir</th>
                        <th style="padding: 10px; text-align: left;">To Port</th>
                        <th style="padding: 10px; text-align: left;">Protocol</th>
                        <th style="padding: 10px; text-align: left;">From</th>
                        <th style="padding: 10px; text-align: left;">IPv6</th>
                    </tr>
                </thead>
                <tbody>
                    ${rules.map(rule => `
                        <tr style="border-bottom: 1px solid var(--border);">
                            <td style="padding: 8px 10px;">${rule.rule_index}</td>
                            <td style="padding: 8px 10px;">
                                <span style="padding: 2px 8px; border-radius: 2px; font-size: 11px; ${getActionStyle(rule.action)}">${rule.action}</span>
                            </td>
                            <td style="padding: 8px 10px;">${rule.direction}</td>
                            <td style="padding: 8px 10px; font-family: monospace;">${rule.to_port || 'Any'}</td>
                            <td style="padding: 8px 10px;">${rule.protocol || 'all'}</td>
                            <td style="padding: 8px 10px; font-family: monospace; font-size: 11px;">${rule.from_ip || 'Anywhere'}</td>
                            <td style="padding: 8px 10px;">${rule.is_v6 ? 'Yes' : 'No'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }

    function getActionStyle(action) {
        switch (action?.toUpperCase()) {
            case 'ALLOW': return `background: ${TC.successBg}; color: ${TC.successDark};`;
            case 'DENY': return `background: ${TC.dangerBg}; color: ${TC.danger};`;
            case 'REJECT': return `background: ${TC.warningBg}; color: ${TC.warningDark};`;
            case 'LIMIT': return `background: ${TC.primaryBg}; color: ${TC.primary};`;
            default: return 'background: var(--surface); color: var(--text-secondary);';
        }
    }

    function getTargetStyle(target) {
        return getActionStyle(target);
    }

    // Global exports
    window.toggleCustomPort = toggleCustomPort;
    window.toggleAdvancedView = toggleAdvancedView;
    window.renderAdvancedRules = renderAdvancedRules;
})();
