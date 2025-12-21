/**
 * SSH Guardian v3.0 - ML Reasoning Component
 * Shared module for displaying ML behavioral analysis results
 *
 * Usage:
 *   // Use via window.MLReasoning
 *   const html = window.MLReasoning.renderMLAnalysis(mlData);
 *   const factorsHtml = window.MLReasoning.renderMLFactors(riskFactors);
 *   const tooltipHtml = window.MLReasoning.renderMLTooltip(tooltipData);
 */

(function() {
'use strict';

/**
 * Risk level colors and icons
 */
const RISK_LEVELS = {
    critical: { color: TC.danger, bgColor: TC.dangerBg, icon: '🚨', label: 'Critical' },
    high: { color: TC.orange, bgColor: TC.warningBg, icon: '⚠️', label: 'High' },
    medium: { color: TC.warningDark, bgColor: TC.warningBg, icon: '⚡', label: 'Medium' },
    low: { color: TC.success, bgColor: TC.successBg, icon: '✓', label: 'Low' },
    clean: { color: TC.textSecondary, bgColor: TC.surfaceAlt, icon: '✓', label: 'Clean' }
};

/**
 * Factor type icons
 */
const FACTOR_ICONS = {
    impossible_travel: '✈️',
    new_location: '📍',
    unusual_time: '🕐',
    new_ip_for_user: '🆕',
    rapid_attempts: '⚡',
    credential_stuffing: '🔑',
    brute_force: '💥',
    account_enumeration: '📋',
    success_after_failures: '🎯',
    geo_mismatch: '🌍',
    default: '🔍'
};

/**
 * Render full ML analysis panel
 * @param {Object} mlData - ML analysis data
 * @param {Object} options - Rendering options
 * @returns {string} HTML string
 */
function renderMLAnalysis(mlData, options = {}) {
    if (!mlData) {
        return `<div class="ml-analysis-empty">No ML analysis data available</div>`;
    }

    const {
        risk_score = 0,
        risk_factors = [],
        recommendations = [],
        confidence = 0,
        user_baseline = {}
    } = mlData;

    const riskLevel = getRiskLevel(risk_score);
    const levelConfig = RISK_LEVELS[riskLevel] || RISK_LEVELS.low;
    const showBaseline = options.showBaseline !== false && Object.keys(user_baseline).length > 0;
    const compact = options.compact === true;

    return `
        <div class="ml-analysis-panel" style="
            background: ${levelConfig.bgColor};
            border: 1px solid ${levelConfig.color}20;
            border-radius: 8px;
            padding: ${compact ? '12px' : '16px'};
            margin: ${compact ? '8px 0' : '12px 0'};
        ">
            <!-- Header with score -->
            <div class="ml-analysis-header" style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: ${compact ? '8px' : '12px'};
                padding-bottom: ${compact ? '8px' : '12px'};
                border-bottom: 1px solid ${levelConfig.color}30;
            ">
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 20px;">${levelConfig.icon}</span>
                    <div>
                        <div style="font-weight: 600; color: ${levelConfig.color};">
                            ML Behavioral Analysis
                        </div>
                        <div style="font-size: 12px; color: ${TC.textSecondary};">
                            Confidence: ${(confidence * 100).toFixed(0)}%
                        </div>
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="
                        font-size: ${compact ? '24px' : '28px'};
                        font-weight: 700;
                        color: ${levelConfig.color};
                    ">${risk_score}</div>
                    <div style="
                        font-size: 11px;
                        text-transform: uppercase;
                        color: ${levelConfig.color};
                        font-weight: 500;
                    ">${levelConfig.label} Risk</div>
                </div>
            </div>

            <!-- Risk Factors -->
            ${risk_factors.length > 0 ? `
                <div class="ml-risk-factors" style="margin-bottom: ${compact ? '8px' : '12px'};">
                    <div style="
                        font-size: 11px;
                        text-transform: uppercase;
                        color: ${TC.textSecondary};
                        margin-bottom: 8px;
                        font-weight: 500;
                    ">Risk Factors Detected</div>
                    ${renderMLFactors(risk_factors, { compact })}
                </div>
            ` : ''}

            <!-- Recommendations -->
            ${recommendations.length > 0 && !compact ? `
                <div class="ml-recommendations" style="
                    background: white;
                    border-radius: 6px;
                    padding: 12px;
                    margin-bottom: 12px;
                ">
                    <div style="
                        font-size: 11px;
                        text-transform: uppercase;
                        color: ${TC.textSecondary};
                        margin-bottom: 8px;
                        font-weight: 500;
                    ">Recommendations</div>
                    ${recommendations.map(rec => `
                        <div style="
                            font-size: 13px;
                            color: ${TC.textPrimary};
                            padding: 4px 0;
                            padding-left: 20px;
                            position: relative;
                        ">
                            <span style="
                                position: absolute;
                                left: 0;
                                color: ${levelConfig.color};
                            ">→</span>
                            ${rec}
                        </div>
                    `).join('')}
                </div>
            ` : ''}

            <!-- User Baseline -->
            ${showBaseline ? `
                <div class="ml-baseline" style="
                    background: ${TC.surfaceAlt};
                    border-radius: 6px;
                    padding: 12px;
                    font-size: 12px;
                ">
                    <div style="
                        font-size: 11px;
                        text-transform: uppercase;
                        color: ${TC.textSecondary};
                        margin-bottom: 8px;
                        font-weight: 500;
                    ">User Baseline</div>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px;">
                        ${user_baseline.total_logins ? `
                            <div>
                                <span style="color: ${TC.textSecondary};">Total Logins:</span>
                                <span style="font-weight: 500;"> ${user_baseline.total_logins}</span>
                            </div>
                        ` : ''}
                        ${user_baseline.known_locations?.length ? `
                            <div>
                                <span style="color: ${TC.textSecondary};">Known Locations:</span>
                                <span style="font-weight: 500;"> ${user_baseline.known_locations.length}</span>
                            </div>
                        ` : ''}
                        ${user_baseline.known_ips?.length ? `
                            <div>
                                <span style="color: ${TC.textSecondary};">Known IPs:</span>
                                <span style="font-weight: 500;"> ${user_baseline.known_ips.length}</span>
                            </div>
                        ` : ''}
                        ${user_baseline.typical_hours?.length ? `
                            <div>
                                <span style="color: ${TC.textSecondary};">Typical Hours:</span>
                                <span style="font-weight: 500;"> ${formatHours(user_baseline.typical_hours)}</span>
                            </div>
                        ` : ''}
                    </div>
                </div>
            ` : ''}
        </div>
    `;
}

/**
 * Render ML risk factors list
 * @param {Array} factors - Array of risk factor objects
 * @param {Object} options - Rendering options
 * @returns {string} HTML string
 */
function renderMLFactors(factors, options = {}) {
    if (!factors || factors.length === 0) {
        return '<div style="color: ${TC.textSecondary}; font-size: 13px;">No risk factors detected</div>';
    }

    const compact = options.compact === true;
    const maxFactors = options.maxFactors || (compact ? 3 : 10);
    const displayFactors = factors.slice(0, maxFactors);
    const remaining = factors.length - maxFactors;

    return `
        <div class="ml-factors-list">
            ${displayFactors.map(factor => {
                const icon = FACTOR_ICONS[factor.type] || FACTOR_ICONS.default;
                const scoreColor = factor.score >= 30 ? TC.danger :
                                   factor.score >= 15 ? TC.orange : TC.warningDark;

                return `
                    <div class="ml-factor-item" style="
                        display: flex;
                        justify-content: space-between;
                        align-items: flex-start;
                        padding: ${compact ? '6px 0' : '8px 0'};
                        border-bottom: 1px solid ${TC.border};
                    " ${factor.details ? `title="${escapeHtml(JSON.stringify(factor.details))}"` : ''}>
                        <div style="display: flex; gap: 8px; flex: 1;">
                            <span style="font-size: ${compact ? '14px' : '16px'};">${icon}</span>
                            <div style="flex: 1;">
                                <div style="
                                    font-weight: 500;
                                    font-size: ${compact ? '12px' : '13px'};
                                    color: ${TC.textPrimary};
                                ">${factor.title || formatFactorType(factor.type)}</div>
                                ${!compact && factor.description ? `
                                    <div style="
                                        font-size: 12px;
                                        color: ${TC.textSecondary};
                                        margin-top: 2px;
                                        line-height: 1.4;
                                    ">${truncate(factor.description, 150)}</div>
                                ` : ''}
                            </div>
                        </div>
                        <div style="
                            background: ${scoreColor}15;
                            color: ${scoreColor};
                            padding: 2px 8px;
                            border-radius: 12px;
                            font-size: 12px;
                            font-weight: 600;
                            white-space: nowrap;
                        ">+${factor.score || 0}</div>
                    </div>
                `;
            }).join('')}
            ${remaining > 0 ? `
                <div style="
                    font-size: 12px;
                    color: ${TC.textSecondary};
                    padding-top: 8px;
                    text-align: center;
                ">+${remaining} more factor${remaining > 1 ? 's' : ''}</div>
            ` : ''}
        </div>
    `;
}

/**
 * Render ML scenario tooltip content
 * @param {Object} tooltip - Tooltip data object
 * @returns {string} HTML string
 */
function renderMLTooltip(tooltip) {
    if (!tooltip) return '';

    const {
        what_it_tests = '',
        expected_outcome = '',
        why_ml_needed = '',
        real_world = ''
    } = tooltip;

    return `
        <div class="ml-tooltip-content" style="
            background: ${TC.textPrimary};
            color: white;
            padding: 12px;
            border-radius: 8px;
            font-size: 12px;
            max-width: 320px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        ">
            ${what_it_tests ? `
                <div style="margin-bottom: 8px;">
                    <div style="color: ${TC.textHint}; font-size: 10px; text-transform: uppercase; margin-bottom: 2px;">
                        What it tests
                    </div>
                    <div style="color: ${TC.surface};">${what_it_tests}</div>
                </div>
            ` : ''}
            ${expected_outcome ? `
                <div style="margin-bottom: 8px;">
                    <div style="color: ${TC.textHint}; font-size: 10px; text-transform: uppercase; margin-bottom: 2px;">
                        Expected outcome
                    </div>
                    <div style="color: ${TC.teal};">${expected_outcome}</div>
                </div>
            ` : ''}
            ${why_ml_needed ? `
                <div style="margin-bottom: 8px;">
                    <div style="color: ${TC.textHint}; font-size: 10px; text-transform: uppercase; margin-bottom: 2px;">
                        Why ML is needed
                    </div>
                    <div style="color: ${TC.purple};">${why_ml_needed}</div>
                </div>
            ` : ''}
            ${real_world ? `
                <div>
                    <div style="color: ${TC.textHint}; font-size: 10px; text-transform: uppercase; margin-bottom: 2px;">
                        Real-world scenario
                    </div>
                    <div style="color: ${TC.warning};">${real_world}</div>
                </div>
            ` : ''}
        </div>
    `;
}

/**
 * Render inline ML score badge
 * @param {number} score - Risk score (0-100)
 * @param {Object} options - Badge options
 * @returns {string} HTML string
 */
function renderMLScoreBadge(score, options = {}) {
    const riskLevel = getRiskLevel(score);
    const levelConfig = RISK_LEVELS[riskLevel];
    const size = options.size || 'medium';

    const sizes = {
        small: { fontSize: '11px', padding: '2px 6px' },
        medium: { fontSize: '12px', padding: '3px 8px' },
        large: { fontSize: '14px', padding: '4px 12px' }
    };

    const sizeConfig = sizes[size] || sizes.medium;

    return `
        <span class="ml-score-badge" style="
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: ${levelConfig.bgColor};
            color: ${levelConfig.color};
            font-size: ${sizeConfig.fontSize};
            font-weight: 600;
            padding: ${sizeConfig.padding};
            border-radius: 12px;
            border: 1px solid ${levelConfig.color}40;
        ">
            <span>${levelConfig.icon}</span>
            <span>${score}</span>
        </span>
    `;
}

/**
 * Render ML analysis summary for table rows
 * @param {Object} mlData - ML data
 * @returns {string} HTML string
 */
function renderMLSummary(mlData) {
    if (!mlData) {
        return `<span style="color: ${TC.textHint};">-</span>`;
    }

    const { risk_score = 0, risk_factors = [] } = mlData;
    const factorCount = risk_factors.length;
    const topFactor = risk_factors[0];

    return `
        <div class="ml-summary" style="display: flex; align-items: center; gap: 8px;">
            ${renderMLScoreBadge(risk_score, { size: 'small' })}
            ${factorCount > 0 ? `
                <span style="
                    font-size: 11px;
                    color: ${TC.textSecondary};
                    max-width: 150px;
                    overflow: hidden;
                    text-overflow: ellipsis;
                    white-space: nowrap;
                " title="${topFactor?.title || topFactor?.type}">
                    ${topFactor?.title || formatFactorType(topFactor?.type)}
                    ${factorCount > 1 ? ` +${factorCount - 1}` : ''}
                </span>
            ` : ''}
        </div>
    `;
}

// ============== Helper Functions ==============

/**
 * Get risk level from score
 */
function getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'clean';
}

/**
 * Format factor type to readable string
 */
function formatFactorType(type) {
    if (!type) return 'Unknown';
    return type
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

/**
 * Format hours array to readable string
 */
function formatHours(hours) {
    if (!hours || hours.length === 0) return '-';
    const sorted = [...hours].sort((a, b) => a - b);
    if (sorted.length <= 3) {
        return sorted.map(h => `${h}:00`).join(', ');
    }
    return `${sorted[0]}:00 - ${sorted[sorted.length - 1]}:00`;
}

/**
 * Truncate string with ellipsis
 */
function truncate(str, maxLen) {
    if (!str || str.length <= maxLen) return str;
    return str.slice(0, maxLen - 3) + '...';
}

// escapeHtml - use shared utility from utils.js
const escapeHtml = window.escapeHtml;

// Export to global scope
window.MLReasoning = {
    renderMLAnalysis,
    renderMLFactors,
    renderMLTooltip,
    renderMLScoreBadge,
    renderMLSummary,
    RISK_LEVELS,
    FACTOR_ICONS
};

})(); // End IIFE
