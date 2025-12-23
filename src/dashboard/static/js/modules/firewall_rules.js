/**
 * SSH Guardian v3.0 - Firewall Blocking Rules
 * Rule creation, editing, deletion, and display
 * Extracted from firewall_inline.js for better maintainability
 *
 * Dependencies: firewall_utils.js
 */

// ===============================================
// Blocking Rules Tab
// ===============================================
let fwEditingRuleId = null;

function loadBlockingRules() {
    loadFwRulesStats();
    loadFwRulesList();
    setupFwRulesEventListeners();
}

async function loadFwRulesStats() {
    try {
        const response = await fetch('/api/dashboard/blocking/stats');
        const data = await response.json();
        if (data.success && data.stats) {
            const stats = data.stats;
            document.getElementById('fwStatTotalBlocks').textContent = stats.total_blocks || 0;
            document.getElementById('fwStatActiveBlocks').textContent = stats.active_blocks || 0;
            document.getElementById('fwStatManualBlocks').textContent = stats.blocks_by_source?.manual || 0;
            document.getElementById('fwStatRuleBlocks').textContent = stats.blocks_by_source?.rule_based || 0;
            document.getElementById('fwStatRecent24h').textContent = stats.recent_24h || 0;
            document.getElementById('fwOverallBlockingStats').style.display = 'block';

            // ML Detection Stats
            if (stats.ml_stats) {
                const mlTotal = document.getElementById('fwStatMLTotal');
                const mlToday = document.getElementById('fwStatMLToday');
                const mlWeek = document.getElementById('fwStatMLWeek');
                const mlCard = document.getElementById('fwMLDetectionStats');

                if (mlTotal) mlTotal.textContent = stats.ml_stats.total || 0;
                if (mlToday) mlToday.textContent = stats.ml_stats.today || 0;
                if (mlWeek) mlWeek.textContent = stats.ml_stats.this_week || 0;
                if (mlCard) mlCard.style.display = 'block';
            }
        }
    } catch (error) {
        console.error('Error loading rules stats:', error);
    }
}

async function loadFwRulesList() {
    const loadingEl = document.getElementById('fwRulesLoading');
    const tableEl = document.getElementById('fwRulesTable');
    const emptyEl = document.getElementById('fwRulesEmpty');
    const errorEl = document.getElementById('fwRulesError');

    loadingEl.style.display = 'block';
    tableEl.style.display = 'none';
    emptyEl.style.display = 'none';
    errorEl.style.display = 'none';

    try {
        const response = await fetch('/api/dashboard/blocking/rules/list');
        const data = await response.json();

        loadingEl.style.display = 'none';

        if (!data.success || !data.rules || data.rules.length === 0) {
            emptyEl.style.display = 'block';
            return;
        }

        const tableBody = document.getElementById('fwRulesTableBody');
        tableBody.innerHTML = data.rules.map(rule => {
            const statusBadge = rule.is_enabled
                ? `<span style="padding: 3px 10px; background: ${TC.successDark}; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">Enabled</span>`
                : `<span style="padding: 3px 10px; background: ${TC.muted}; color: white; border-radius: 3px; font-size: 11px; font-weight: 600;">Disabled</span>`;

            const conditions = formatFwRuleConditions(rule.rule_type, rule.conditions);
            const stats = `<div style="font-size: 11px;"><div>Triggered: ${rule.times_triggered || 0}x</div><div>Blocked: ${rule.ips_blocked_total || 0} IPs</div></div>`;
            const isSystemRule = rule.is_system_rule;

            const deleteBtn = isSystemRule
                ? '<button disabled style="padding: 4px 8px; border: 1px solid #8A8886; background: var(--surface); color: #8A8886; border-radius: 3px; cursor: not-allowed; font-size: 11px;" title="System rule">🔒</button>'
                : `<button onclick="fwDeleteRule(${rule.id}, '${escapeHtml(rule.rule_name)}')" style="padding: 4px 8px; border: 1px solid #D13438; background: var(--surface); color: #D13438; border-radius: 3px; cursor: pointer; font-size: 11px;">Del</button>`;

            const tooltip = getRuleTypeTooltip(rule.rule_type);
            return `
                <tr style="border-bottom: 1px solid var(--border-light);">
                    <td style="padding: 10px; font-size: 12px; font-weight: 600; position: relative;">
                        <span class="rule-name-tooltip" data-tooltip="${escapeHtml(tooltip)}" style="cursor: help; border-bottom: 1px dotted var(--text-secondary);">
                            ${escapeHtml(rule.rule_name)}
                        </span>
                        ${isSystemRule ? `<span style="margin-left: 6px; padding: 2px 5px; background: ${TC.primary}; color: white; border-radius: 2px; font-size: 9px;">SYS</span>` : ''}
                    </td>
                    <td style="padding: 10px; font-size: 12px;">${escapeHtml(rule.rule_type)}</td>
                    <td style="padding: 10px; font-size: 12px; text-align: center;">${rule.priority}</td>
                    <td style="padding: 10px;">${conditions}</td>
                    <td style="padding: 10px;">${stats}</td>
                    <td style="padding: 10px; text-align: center;">${statusBadge}</td>
                    <td style="padding: 10px; text-align: right; white-space: nowrap;">
                        <button onclick="fwToggleRule(${rule.id}, ${rule.is_enabled})" style="padding: 4px 8px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 11px; margin-right: 4px;">${rule.is_enabled ? 'Disable' : 'Enable'}</button>
                        <button onclick="fwEditRule(${rule.id})" style="padding: 4px 8px; border: 1px solid var(--border); background: var(--surface); border-radius: 3px; cursor: pointer; font-size: 11px; margin-right: 4px;">Edit</button>
                        ${deleteBtn}
                    </td>
                </tr>
            `;
        }).join('');

        tableEl.style.display = 'block';

        // Initialize tooltips after table is rendered
        initRuleTooltips();
    } catch (error) {
        console.error('Error loading rules:', error);
        loadingEl.style.display = 'none';
        errorEl.style.display = 'block';
    }
}

function formatFwRuleConditions(ruleType, conditions) {
    if (typeof conditions === 'string') {
        try { conditions = JSON.parse(conditions); } catch (e) { return '<span style="font-size:11px;">Invalid</span>'; }
    }
    if (!conditions) return '<span style="font-size:11px;">-</span>';

    switch (ruleType) {
        case 'brute_force':
            return `<div style="font-size:11px;"><div>${conditions.failed_attempts || 'N/A'} fails</div><div>${conditions.time_window_minutes || 'N/A'} min window</div></div>`;
        case 'ml_threshold':
            return `<div style="font-size:11px;"><div>Risk ≥ ${conditions.min_risk_score || 'N/A'}</div><div>Conf ≥ ${conditions.min_confidence || 'N/A'}</div><div>${conditions.min_failed_attempts || 1} fails in ${conditions.time_window_hours || 24}h</div></div>`;
        case 'api_reputation':
            return `<div style="font-size:11px;"><div>AbuseIPDB ≥ ${conditions.min_abuseipdb_score || 'N/A'}</div></div>`;
        case 'velocity':
            return `<div style="font-size:11px;"><div>${conditions.max_events || 'N/A'} events</div><div>${conditions.time_window_seconds || 'N/A'}s window</div></div>`;
        case 'repeat_offender':
            return `<div style="font-size:11px;"><div>Escalating blocks</div></div>`;
        case 'distributed_brute_force':
            return `<div style="font-size:11px;"><div>${conditions.unique_ips_threshold || 'N/A'} IPs, ${conditions.unique_usernames_threshold || 'N/A'} users</div><div>${conditions.time_window_minutes || 'N/A'} min, ≤${conditions.max_attempts_per_ip || 'N/A'}/IP</div></div>`;
        case 'account_takeover':
            return `<div style="font-size:11px;"><div>${conditions.unique_ips_threshold || 'N/A'} IPs/user</div><div>${conditions.unique_countries_threshold || 'N/A'} countries, ${conditions.time_window_minutes || 'N/A'} min</div></div>`;
        case 'off_hours_anomaly':
            return `<div style="font-size:11px;"><div>Work: ${conditions.work_start_hour || 8}:00-${conditions.work_end_hour || 18}:00</div><div>Min ${conditions.min_off_hours_attempts || 3} off-hours attempts</div></div>`;
        default:
            return '<div style="font-size:11px;">Custom</div>';
    }
}

// Rule type tooltip descriptions
function getRuleTypeTooltip(ruleType) {
    const tooltips = {
        'brute_force': `BRUTE FORCE DETECTION
━━━━━━━━━━━━━━━━━━━━━
Blocks IP after X failed login attempts within Y minutes from the same IP.

Example: IP 192.168.1.100 tries 5 passwords for "admin" in 10 min → Blocked`,

        'ml_threshold': `ML THRESHOLD (Machine Learning)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Uses ML to analyze behavior patterns and assign risk score (0-100).

ML analyzes: Login timing, username patterns, geographic anomalies

Example: Bot-like behavior detected (perfect timing, sequential usernames) → Risk: 92 → Blocked`,

        'api_reputation': `API REPUTATION (AbuseIPDB + VirusTotal)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Queries threat intelligence APIs to check if IP is reported malicious.

APIs check: Spam reports, hacking attempts, malware, botnet membership

Example: IP has AbuseIPDB score 95 (reported 500+ times) → Blocked immediately`,

        'velocity': `VELOCITY / DDoS DETECTION
━━━━━━━━━━━━━━━━━━━━━━━━━
Detects rapid-fire attacks by counting events per second.

Example: IP sends 25 login requests in 60 seconds → Blocked for DDoS behavior`,

        'repeat_offender': `REPEAT OFFENDER ESCALATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Increases block duration for IPs that keep coming back.

Escalation: 1st = base, 2nd = 2 days, 3rd = 7 days, 4th+ = 30 days`,

        'distributed_brute_force': `DISTRIBUTED BRUTE FORCE (ML + API Enhanced)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects botnet-style attacks: many IPs try many usernames with LOW frequency per IP (evades rate limits).

ML Enhancement: Pattern score from IP distribution + username diversity + timing
API Enhancement: Checks if IPs are known threats via AbuseIPDB

Example: 8 IPs each try 2-3 attempts on 15 usernames in 1 hour → Botnet detected → All blocked`,

        'account_takeover': `ACCOUNT TAKEOVER (GeoIP + API Enhanced)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects credential stuffing: SAME username tried from MULTIPLE IPs/countries quickly.

GeoIP Enhancement: Detects geographic diversity (impossible travel)
API Enhancement: Weights score higher if IPs have bad reputation

Example: "john.doe" login attempts from USA, Russia, China in 30 min → Leaked credentials → Block all`,

        'off_hours_anomaly': `OFF-HOURS ANOMALY (Baseline + API Enhanced)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Detects login attempts outside business hours or weekends.

Baseline Learning: Learns user's typical login hours from 30-day history
API Enhancement: 1.5x-2x threat multiplier for bad reputation IPs

Example: "admin" normally logs in 9am-5pm, attempt at 3am from suspicious IP → Flagged`
    };
    return tooltips[ruleType] || 'Custom blocking rule';
}

// Initialize rule name tooltips
function initRuleTooltips() {
    // Create tooltip container if not exists
    let tooltipEl = document.getElementById('ruleTooltipContainer');
    if (!tooltipEl) {
        tooltipEl = document.createElement('div');
        tooltipEl.id = 'ruleTooltipContainer';
        tooltipEl.className = 'rule-tooltip-container';
        document.body.appendChild(tooltipEl);
    }

    // Add event listeners to all rule name tooltips
    document.querySelectorAll('.rule-name-tooltip').forEach(el => {
        el.addEventListener('mouseenter', function(e) {
            const tooltip = this.getAttribute('data-tooltip');
            if (!tooltip) return;

            tooltipEl.textContent = tooltip;
            tooltipEl.classList.add('visible');

            // Position tooltip below the element
            const rect = this.getBoundingClientRect();
            const tooltipRect = tooltipEl.getBoundingClientRect();

            let left = rect.left;
            let top = rect.bottom + 10;

            // Adjust if tooltip goes off screen right
            if (left + tooltipRect.width > window.innerWidth - 20) {
                left = window.innerWidth - tooltipRect.width - 20;
            }

            // Adjust if tooltip goes off screen bottom
            if (top + tooltipRect.height > window.innerHeight - 20) {
                top = rect.top - tooltipRect.height - 10;
                // Move arrow to bottom
                tooltipEl.style.setProperty('--arrow-position', 'bottom');
            }

            tooltipEl.style.left = left + 'px';
            tooltipEl.style.top = top + 'px';
        });

        el.addEventListener('mouseleave', function() {
            tooltipEl.classList.remove('visible');
        });
    });
}

function setupFwRulesEventListeners() {
    // Refresh button
    document.getElementById('fwRefreshRules')?.addEventListener('click', loadBlockingRules);

    // Show create form button
    document.getElementById('fwShowCreateRuleForm')?.addEventListener('click', () => {
        fwResetRuleForm();
        document.getElementById('fwCreateRuleForm').style.display = 'block';
    });

    // Cancel form button
    document.getElementById('fwCancelRuleForm')?.addEventListener('click', () => {
        document.getElementById('fwCreateRuleForm').style.display = 'none';
        fwResetRuleForm();
    });

    // Rule type selector
    document.getElementById('fwRuleType')?.addEventListener('change', function() {
        // Hide all condition panels
        document.getElementById('fwBruteForceConditions').style.display = 'none';
        document.getElementById('fwMlConditions').style.display = 'none';
        document.getElementById('fwApiConditions').style.display = 'none';
        document.getElementById('fwVelocityConditions').style.display = 'none';
        document.getElementById('fwRepeatConditions').style.display = 'none';
        document.getElementById('fwDistributedBFConditions').style.display = 'none';
        document.getElementById('fwAccountTakeoverConditions').style.display = 'none';
        document.getElementById('fwOffHoursConditions').style.display = 'none';
        // Show relevant panel
        if (this.value === 'brute_force') {
            document.getElementById('fwBruteForceConditions').style.display = 'block';
        } else if (this.value === 'ml_threshold') {
            document.getElementById('fwMlConditions').style.display = 'block';
        } else if (this.value === 'api_reputation') {
            document.getElementById('fwApiConditions').style.display = 'block';
        } else if (this.value === 'velocity') {
            document.getElementById('fwVelocityConditions').style.display = 'block';
        } else if (this.value === 'repeat_offender') {
            document.getElementById('fwRepeatConditions').style.display = 'block';
        } else if (this.value === 'distributed_brute_force') {
            document.getElementById('fwDistributedBFConditions').style.display = 'block';
        } else if (this.value === 'account_takeover') {
            document.getElementById('fwAccountTakeoverConditions').style.display = 'block';
        } else if (this.value === 'off_hours_anomaly') {
            document.getElementById('fwOffHoursConditions').style.display = 'block';
        }
    });

    // Submit button
    document.getElementById('fwSubmitCreateRule')?.addEventListener('click', async () => {
        if (fwEditingRuleId) {
            await fwUpdateRule(fwEditingRuleId);
        } else {
            await fwCreateRule();
        }
    });
}

async function fwCreateRule() {
    const ruleName = document.getElementById('fwRuleName').value;
    const ruleType = document.getElementById('fwRuleType').value;
    const blockDuration = parseInt(document.getElementById('fwRuleBlockDuration').value);
    const priority = parseInt(document.getElementById('fwRulePriority').value);
    const description = document.getElementById('fwRuleDescription').value;

    if (!ruleName || !ruleType) {
        alert('Please fill in required fields');
        return;
    }

    let conditions = {};
    if (ruleType === 'brute_force') {
        conditions = {
            failed_attempts: parseInt(document.getElementById('fwFailedAttempts').value),
            time_window_minutes: parseInt(document.getElementById('fwTimeWindow').value),
            event_type: 'failed'
        };
    } else if (ruleType === 'ml_threshold') {
        conditions = {
            min_risk_score: parseInt(document.getElementById('fwMinRiskScore').value),
            min_confidence: parseFloat(document.getElementById('fwMlMinConfidence').value),
            min_failed_attempts: parseInt(document.getElementById('fwMlMinFailedAttempts')?.value || 5),
            time_window_hours: parseInt(document.getElementById('fwMlTimeWindowHours')?.value || 24)
        };
    } else if (ruleType === 'api_reputation') {
        conditions = {
            min_abuseipdb_score: parseInt(document.getElementById('fwMinAbuseScore').value),
            block_on_success: document.getElementById('fwBlockOnSuccess').value === 'true'
        };
    } else if (ruleType === 'velocity') {
        conditions = {
            max_events: parseInt(document.getElementById('fwMaxEvents').value),
            time_window_seconds: parseInt(document.getElementById('fwTimeWindowSeconds').value)
        };
    } else if (ruleType === 'repeat_offender') {
        conditions = {
            escalation: { "2": 2880, "3": 10080, "4": 43200 }
        };
    } else if (ruleType === 'distributed_brute_force') {
        conditions = {
            unique_ips_threshold: parseInt(document.getElementById('fwDistBFUniqueIPs').value),
            unique_usernames_threshold: parseInt(document.getElementById('fwDistBFUniqueUsernames').value),
            time_window_minutes: parseInt(document.getElementById('fwDistBFTimeWindow').value),
            max_attempts_per_ip: parseInt(document.getElementById('fwDistBFMaxPerIP').value),
            requires_approval: false
        };
    } else if (ruleType === 'account_takeover') {
        conditions = {
            unique_ips_threshold: parseInt(document.getElementById('fwATOUniqueIPs').value),
            time_window_minutes: parseInt(document.getElementById('fwATOTimeWindow').value),
            unique_countries_threshold: parseInt(document.getElementById('fwATOUniqueCountries').value),
            check_threat_intel: document.getElementById('fwATOCheckThreatIntel').checked,
            requires_approval: false
        };
    } else if (ruleType === 'off_hours_anomaly') {
        conditions = {
            work_start_hour: parseInt(document.getElementById('fwOffHoursStart').value),
            work_end_hour: parseInt(document.getElementById('fwOffHoursEnd').value),
            work_days: [0, 1, 2, 3, 4], // Monday to Friday (0=Mon in Python weekday)
            min_off_hours_attempts: parseInt(document.getElementById('fwOffHoursMinAttempts').value),
            check_user_baseline: document.getElementById('fwOffHoursCheckBaseline').checked,
            requires_approval: document.getElementById('fwOffHoursRequireApproval').checked
        };
    }

    try {
        const response = await fetch('/api/dashboard/blocking/rules/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_name: ruleName, rule_type: ruleType, conditions, block_duration_minutes: blockDuration, priority, description })
        });
        const data = await response.json();
        if (data.success) {
            alert('Rule created successfully');
            document.getElementById('fwCreateRuleForm').style.display = 'none';
            fwResetRuleForm();
            loadFwRulesList();
        } else {
            alert('Failed to create rule: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error creating rule:', error);
        alert('Error creating rule');
    }
}

async function fwEditRule(ruleId) {
    try {
        const response = await fetch('/api/dashboard/blocking/rules/list');
        const data = await response.json();
        if (!data.success) return alert('Failed to load rule');

        const rule = data.rules.find(r => r.id === ruleId);
        if (!rule) return alert('Rule not found');

        fwEditingRuleId = ruleId;
        document.getElementById('fwRuleName').value = rule.rule_name;
        document.getElementById('fwRuleType').value = rule.rule_type;
        document.getElementById('fwRuleBlockDuration').value = rule.block_duration_minutes;
        document.getElementById('fwRulePriority').value = rule.priority;
        document.getElementById('fwRuleDescription').value = rule.description || '';

        // Hide all condition panels
        document.getElementById('fwBruteForceConditions').style.display = 'none';
        document.getElementById('fwMlConditions').style.display = 'none';
        document.getElementById('fwApiConditions').style.display = 'none';
        document.getElementById('fwVelocityConditions').style.display = 'none';
        document.getElementById('fwRepeatConditions').style.display = 'none';
        document.getElementById('fwDistributedBFConditions').style.display = 'none';
        document.getElementById('fwAccountTakeoverConditions').style.display = 'none';
        document.getElementById('fwOffHoursConditions').style.display = 'none';

        // Show and populate relevant panel
        if (rule.rule_type === 'brute_force') {
            document.getElementById('fwBruteForceConditions').style.display = 'block';
            document.getElementById('fwFailedAttempts').value = rule.conditions?.failed_attempts || 5;
            document.getElementById('fwTimeWindow').value = rule.conditions?.time_window_minutes || 10;
        } else if (rule.rule_type === 'ml_threshold') {
            document.getElementById('fwMlConditions').style.display = 'block';
            document.getElementById('fwMinRiskScore').value = rule.conditions?.min_risk_score || 85;
            document.getElementById('fwMlMinConfidence').value = rule.conditions?.min_confidence || 0.8;
            const mlMinFailedAttempts = document.getElementById('fwMlMinFailedAttempts');
            const mlTimeWindowHours = document.getElementById('fwMlTimeWindowHours');
            if (mlMinFailedAttempts) mlMinFailedAttempts.value = rule.conditions?.min_failed_attempts || 5;
            if (mlTimeWindowHours) mlTimeWindowHours.value = rule.conditions?.time_window_hours || 24;
        } else if (rule.rule_type === 'api_reputation') {
            document.getElementById('fwApiConditions').style.display = 'block';
            document.getElementById('fwMinAbuseScore').value = rule.conditions?.min_abuseipdb_score || 90;
            document.getElementById('fwBlockOnSuccess').value = rule.conditions?.block_on_success !== false ? 'true' : 'false';
        } else if (rule.rule_type === 'velocity') {
            document.getElementById('fwVelocityConditions').style.display = 'block';
            document.getElementById('fwMaxEvents').value = rule.conditions?.max_events || 20;
            document.getElementById('fwTimeWindowSeconds').value = rule.conditions?.time_window_seconds || 60;
        } else if (rule.rule_type === 'repeat_offender') {
            document.getElementById('fwRepeatConditions').style.display = 'block';
        } else if (rule.rule_type === 'distributed_brute_force') {
            document.getElementById('fwDistributedBFConditions').style.display = 'block';
            document.getElementById('fwDistBFUniqueIPs').value = rule.conditions?.unique_ips_threshold || 5;
            document.getElementById('fwDistBFUniqueUsernames').value = rule.conditions?.unique_usernames_threshold || 10;
            document.getElementById('fwDistBFTimeWindow').value = rule.conditions?.time_window_minutes || 60;
            document.getElementById('fwDistBFMaxPerIP').value = rule.conditions?.max_attempts_per_ip || 3;
        } else if (rule.rule_type === 'account_takeover') {
            document.getElementById('fwAccountTakeoverConditions').style.display = 'block';
            document.getElementById('fwATOUniqueIPs').value = rule.conditions?.unique_ips_threshold || 3;
            document.getElementById('fwATOTimeWindow').value = rule.conditions?.time_window_minutes || 30;
            document.getElementById('fwATOUniqueCountries').value = rule.conditions?.unique_countries_threshold || 2;
            document.getElementById('fwATOCheckThreatIntel').checked = rule.conditions?.check_threat_intel !== false;
        } else if (rule.rule_type === 'off_hours_anomaly') {
            document.getElementById('fwOffHoursConditions').style.display = 'block';
            document.getElementById('fwOffHoursStart').value = rule.conditions?.work_start_hour || 8;
            document.getElementById('fwOffHoursEnd').value = rule.conditions?.work_end_hour || 18;
            document.getElementById('fwOffHoursMinAttempts').value = rule.conditions?.min_off_hours_attempts || 3;
            document.getElementById('fwOffHoursCheckBaseline').checked = rule.conditions?.check_user_baseline !== false;
            document.getElementById('fwOffHoursRequireApproval').checked = rule.conditions?.requires_approval === true;
        }

        document.getElementById('fwSubmitCreateRule').textContent = 'Update Rule';
        document.getElementById('fwCreateRuleForm').style.display = 'block';
        document.getElementById('fwCreateRuleForm').scrollIntoView({ behavior: 'smooth' });
    } catch (error) {
        console.error('Error loading rule:', error);
        alert('Error loading rule');
    }
}

async function fwUpdateRule(ruleId) {
    const ruleName = document.getElementById('fwRuleName').value;
    const ruleType = document.getElementById('fwRuleType').value;
    const blockDuration = parseInt(document.getElementById('fwRuleBlockDuration').value);
    const priority = parseInt(document.getElementById('fwRulePriority').value);
    const description = document.getElementById('fwRuleDescription').value;

    if (!ruleName || !ruleType) {
        alert('Please fill in required fields');
        return;
    }

    let conditions = {};
    if (ruleType === 'brute_force') {
        conditions = {
            failed_attempts: parseInt(document.getElementById('fwFailedAttempts').value),
            time_window_minutes: parseInt(document.getElementById('fwTimeWindow').value),
            event_type: 'failed'
        };
    } else if (ruleType === 'ml_threshold') {
        conditions = {
            min_risk_score: parseInt(document.getElementById('fwMinRiskScore').value),
            min_confidence: parseFloat(document.getElementById('fwMlMinConfidence').value),
            min_failed_attempts: parseInt(document.getElementById('fwMlMinFailedAttempts')?.value || 5),
            time_window_hours: parseInt(document.getElementById('fwMlTimeWindowHours')?.value || 24)
        };
    } else if (ruleType === 'api_reputation') {
        conditions = {
            min_abuseipdb_score: parseInt(document.getElementById('fwMinAbuseScore').value),
            block_on_success: document.getElementById('fwBlockOnSuccess').value === 'true'
        };
    } else if (ruleType === 'velocity') {
        conditions = {
            max_events: parseInt(document.getElementById('fwMaxEvents').value),
            time_window_seconds: parseInt(document.getElementById('fwTimeWindowSeconds').value)
        };
    } else if (ruleType === 'repeat_offender') {
        conditions = {
            escalation: { "2": 2880, "3": 10080, "4": 43200 }
        };
    } else if (ruleType === 'distributed_brute_force') {
        conditions = {
            unique_ips_threshold: parseInt(document.getElementById('fwDistBFUniqueIPs').value),
            unique_usernames_threshold: parseInt(document.getElementById('fwDistBFUniqueUsernames').value),
            time_window_minutes: parseInt(document.getElementById('fwDistBFTimeWindow').value),
            max_attempts_per_ip: parseInt(document.getElementById('fwDistBFMaxPerIP').value),
            requires_approval: false
        };
    } else if (ruleType === 'account_takeover') {
        conditions = {
            unique_ips_threshold: parseInt(document.getElementById('fwATOUniqueIPs').value),
            time_window_minutes: parseInt(document.getElementById('fwATOTimeWindow').value),
            unique_countries_threshold: parseInt(document.getElementById('fwATOUniqueCountries').value),
            check_threat_intel: document.getElementById('fwATOCheckThreatIntel').checked,
            requires_approval: false
        };
    } else if (ruleType === 'off_hours_anomaly') {
        conditions = {
            work_start_hour: parseInt(document.getElementById('fwOffHoursStart').value),
            work_end_hour: parseInt(document.getElementById('fwOffHoursEnd').value),
            work_days: [0, 1, 2, 3, 4], // Monday to Friday (0=Mon in Python weekday)
            min_off_hours_attempts: parseInt(document.getElementById('fwOffHoursMinAttempts').value),
            check_user_baseline: document.getElementById('fwOffHoursCheckBaseline').checked,
            requires_approval: document.getElementById('fwOffHoursRequireApproval').checked
        };
    }

    try {
        const response = await fetch(`/api/dashboard/blocking/rules/${ruleId}/update`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_name: ruleName, rule_type: ruleType, conditions, block_duration_minutes: blockDuration, priority, description })
        });
        const data = await response.json();
        if (data.success) {
            alert('Rule updated successfully');
            document.getElementById('fwCreateRuleForm').style.display = 'none';
            fwResetRuleForm();
            loadFwRulesList();
        } else {
            alert('Failed to update rule: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error updating rule:', error);
        alert('Error updating rule');
    }
}

async function fwToggleRule(ruleId, currentStatus) {
    if (!confirm(`${currentStatus ? 'Disable' : 'Enable'} this rule?`)) return;

    try {
        const response = await fetch(`/api/dashboard/blocking/rules/${ruleId}/toggle`, { method: 'POST' });
        const data = await response.json();
        if (data.success) {
            loadFwRulesList();
        } else {
            alert('Failed to toggle rule: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error toggling rule:', error);
        alert('Error toggling rule');
    }
}

async function fwDeleteRule(ruleId, ruleName) {
    if (!confirm(`Delete rule "${ruleName}"? This cannot be undone.`)) return;

    try {
        const response = await fetch(`/api/dashboard/blocking/rules/${ruleId}/delete`, { method: 'DELETE' });
        const data = await response.json();
        if (data.success) {
            alert('Rule deleted');
            loadFwRulesList();
        } else {
            alert('Failed to delete rule: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Error deleting rule:', error);
        alert('Error deleting rule');
    }
}

function fwResetRuleForm() {
    fwEditingRuleId = null;
    document.getElementById('fwRuleName').value = '';
    document.getElementById('fwRuleType').value = '';
    document.getElementById('fwRuleBlockDuration').value = '1440';
    document.getElementById('fwRulePriority').value = '50';
    document.getElementById('fwRuleDescription').value = '';
    // Brute force
    document.getElementById('fwFailedAttempts').value = '5';
    document.getElementById('fwTimeWindow').value = '10';
    // ML threshold
    document.getElementById('fwMinRiskScore').value = '85';
    document.getElementById('fwMlMinConfidence').value = '0.8';
    const mlMinFailedAttempts = document.getElementById('fwMlMinFailedAttempts');
    const mlTimeWindowHours = document.getElementById('fwMlTimeWindowHours');
    if (mlMinFailedAttempts) mlMinFailedAttempts.value = '5';
    if (mlTimeWindowHours) mlTimeWindowHours.value = '24';
    // API reputation
    document.getElementById('fwMinAbuseScore').value = '90';
    document.getElementById('fwBlockOnSuccess').value = 'true';
    // Velocity
    document.getElementById('fwMaxEvents').value = '20';
    document.getElementById('fwTimeWindowSeconds').value = '60';
    // Hide all condition panels
    document.getElementById('fwBruteForceConditions').style.display = 'none';
    document.getElementById('fwMlConditions').style.display = 'none';
    document.getElementById('fwApiConditions').style.display = 'none';
    document.getElementById('fwVelocityConditions').style.display = 'none';
    document.getElementById('fwRepeatConditions').style.display = 'none';
    document.getElementById('fwSubmitCreateRule').textContent = 'Create Rule';
}

// escapeHtml is now available globally from utils.js

// Utility functions (formatTimeAgo, formatFutureTime, showNotification)
// are now in firewall_utils.js

// Close modal on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        closeBlockIPModal();
        closeRecentActivityPanel();
    }
});

// Close modal on backdrop click
document.getElementById('blockIPModal')?.addEventListener('click', function(e) {
    if (e.target === this) {
        closeBlockIPModal();
    }
});


// Export functions globally
window.loadBlockingRules = loadBlockingRules;
window.loadFwRulesStats = loadFwRulesStats;
window.loadFwRulesList = loadFwRulesList;
window.fwCreateRule = fwCreateRule;
window.fwEditRule = fwEditRule;
window.fwUpdateRule = fwUpdateRule;
window.fwToggleRule = fwToggleRule;
window.fwDeleteRule = fwDeleteRule;
window.fwResetRuleForm = fwResetRuleForm;
window.initRuleTooltips = initRuleTooltips;
