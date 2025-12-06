/**
 * Settings Integrations Page Module
 * Handles third-party service integration configuration
 */

(function() {
    'use strict';

    let integrations = [];
    let currentIntegration = null;

    /**
     * Load and display Settings Integrations page
     */
    window.loadSettingsIntegrationsPage = async function() {
        try {
            // Load integrations data
            await loadIntegrations();

            // Setup event listeners
            setupIntegrationsEventListeners();

        } catch (error) {
            console.error('Error loading Settings Integrations page:', error);
            showNotification('Failed to load integrations', 'error');
        }
    };

    /**
     * Load integrations from API
     */
    async function loadIntegrations() {
        const container = document.getElementById('integrations-container');
        if (container) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #605E5C;">Loading integrations...</div>';
        }

        try {
            const response = await fetch('/api/dashboard/integrations/list');
            const data = await response.json();

            if (data.success) {
                integrations = data.data.integrations;
                renderIntegrations(integrations);
            } else {
                throw new Error(data.error || 'Failed to load integrations');
            }

        } catch (error) {
            console.error('Error loading integrations:', error);
            showNotification('Failed to load integrations', 'error');
            if (container) {
                container.innerHTML = '<div style="text-align: center; padding: 40px; color: #D13438;">Failed to load integrations. Please try again.</div>';
            }
        }
    }

    /**
     * Render integrations list
     */
    function renderIntegrations(integrations) {
        const container = document.getElementById('integrations-container');

        if (!container) return;

        if (!integrations || integrations.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 40px; color: #605E5C;">No integrations configured</div>';
            return;
        }

        let html = '<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 24px;">';

        integrations.forEach(integration => {
            html += renderIntegrationCard(integration);
        });

        html += '</div>';

        // Add modal HTML
        html += renderConfigModal();

        container.innerHTML = html;

        // Setup inline event listeners
        setupInlineEventListeners();
    }

    /**
     * Render a single integration card
     */
    function renderIntegrationCard(integration) {
        const statusColors = {
            'active': '#107C10',
            'configured': '#0078D4',
            'inactive': '#A19F9D',
            'error': '#D13438'
        };

        const statusLabels = {
            'active': 'Active',
            'configured': 'Configured (Disabled)',
            'inactive': 'Not Configured',
            'error': 'Error'
        };

        const statusColor = statusColors[integration.status] || statusColors.inactive;
        const statusText = statusLabels[integration.status] || integration.status;

        // Build config summary
        let configSummary = '';
        if (integration.config_fields && integration.config_fields.length > 0) {
            configSummary = '<div style="margin-top: 12px; padding: 12px; background: #F3F2F1; border-radius: 4px; font-size: 12px;">';
            integration.config_fields.slice(0, 4).forEach(field => {
                if (field.key !== 'enabled') {
                    const valueDisplay = field.is_sensitive
                        ? (field.has_value ? '<span style="color: #107C10;">Configured</span>' : '<span style="color: #A19F9D;">Not set</span>')
                        : (field.value || '<span style="color: #A19F9D;">Not set</span>');
                    configSummary += `<div style="margin-bottom: 4px;"><strong>${field.display_name}:</strong> ${valueDisplay}</div>`;
                }
            });
            configSummary += '</div>';
        }

        // Last test info
        let lastTestInfo = '';
        if (integration.last_test_at) {
            const formattedDate = window.TimeSettings?.isLoaded()
                ? window.TimeSettings.formatFull(integration.last_test_at)
                : new Date(integration.last_test_at).toLocaleString();
            lastTestInfo = `<div style="font-size: 11px; color: #605E5C; margin-top: 8px;">Last tested: ${formattedDate}</div>`;
        }
        if (integration.error_message) {
            lastTestInfo += `<div style="font-size: 11px; color: #D13438; margin-top: 4px;">Error: ${integration.error_message}</div>`;
        }

        return `
            <div class="integration-card" data-integration-id="${integration.integration_id}"
                 style="background: #FFFFFF; border: 1px solid #EDEBE9; border-radius: 8px; padding: 24px; position: relative;">

                <div style="display: flex; align-items: start; gap: 16px; margin-bottom: 12px;">
                    <div style="font-size: 36px; line-height: 1;">${integration.icon || '🔌'}</div>
                    <div style="flex: 1;">
                        <div style="font-weight: 600; font-size: 16px; color: #323130; margin-bottom: 4px;">
                            ${integration.name}
                        </div>
                        <div style="font-size: 13px; color: #605E5C; line-height: 1.4;">
                            ${integration.description}
                        </div>
                    </div>
                </div>

                ${configSummary}
                ${lastTestInfo}

                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 16px; padding-top: 16px; border-top: 1px solid #EDEBE9;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="width: 10px; height: 10px; border-radius: 50%; background: ${statusColor};"></span>
                        <span style="font-size: 13px; color: #605E5C;">${statusText}</span>
                    </div>
                    <div style="display: flex; gap: 8px;">
                        <button class="btn-configure-integration btn btn-primary btn-sm"
                                data-integration-id="${integration.integration_id}">
                            Configure
                        </button>
                        <button class="btn-test-integration btn btn-secondary btn-sm"
                                data-integration-id="${integration.integration_id}"
                                ${integration.status === 'inactive' ? 'disabled' : ''}>
                            Test
                        </button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Render configuration modal HTML
     */
    function renderConfigModal() {
        return `
            <div id="integration-config-modal" class="modal-overlay" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                <div class="modal-content" style="background: #FFFFFF; border-radius: 8px; width: 100%; max-width: 500px; max-height: 90vh; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
                    <div class="modal-header" style="padding: 20px 24px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                        <h3 id="modal-title" style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Configure Integration</h3>
                        <button id="modal-close-btn" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #605E5C; padding: 0; line-height: 1;">&times;</button>
                    </div>
                    <div class="modal-body" style="padding: 24px; overflow-y: auto; max-height: calc(90vh - 140px);">
                        <div id="modal-form-container">
                            <!-- Form fields will be rendered here -->
                        </div>
                    </div>
                    <div class="modal-footer" style="padding: 16px 24px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end; gap: 12px;">
                        <button id="modal-cancel-btn" class="btn btn-secondary">Cancel</button>
                        <button id="modal-save-btn" class="btn btn-primary">Save Configuration</button>
                    </div>
                </div>
            </div>

            <div id="integration-test-modal" class="modal-overlay" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center;">
                <div class="modal-content" style="background: #FFFFFF; border-radius: 8px; width: 100%; max-width: 450px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.2);">
                    <div class="modal-header" style="padding: 20px 24px; border-bottom: 1px solid #EDEBE9; display: flex; justify-content: space-between; align-items: center;">
                        <h3 id="test-modal-title" style="margin: 0; font-size: 18px; font-weight: 600; color: #323130;">Test Integration</h3>
                        <button id="test-modal-close-btn" style="background: none; border: none; font-size: 24px; cursor: pointer; color: #605E5C; padding: 0; line-height: 1;">&times;</button>
                    </div>
                    <div class="modal-body" style="padding: 24px;">
                        <div id="test-modal-form-container">
                            <!-- Test form will be rendered here -->
                        </div>
                        <div id="test-result-container" style="margin-top: 16px; display: none;">
                            <!-- Test results will appear here -->
                        </div>
                    </div>
                    <div class="modal-footer" style="padding: 16px 24px; border-top: 1px solid #EDEBE9; display: flex; justify-content: flex-end; gap: 12px;">
                        <button id="test-modal-cancel-btn" class="btn btn-secondary">Close</button>
                        <button id="test-modal-run-btn" class="btn btn-primary">Run Test</button>
                    </div>
                </div>
            </div>
        `;
    }

    /**
     * Get test form fields for each integration type
     */
    function getTestFormFields(integrationId) {
        const testForms = {
            'telegram': {
                title: 'Test Telegram',
                description: 'This will verify your bot token and send a test message to the configured chat.',
                fields: []
            },
            'smtp': {
                title: 'Test SMTP',
                description: 'Verify SMTP connection and optionally send a test email.',
                fields: [
                    { key: 'test_email', label: 'Send test email to (optional)', type: 'email', placeholder: 'recipient@example.com' }
                ]
            },
            'abuseipdb': {
                title: 'Test AbuseIPDB',
                description: 'Check IP reputation using AbuseIPDB API.',
                fields: [
                    { key: 'test_ip', label: 'Test IP Address', type: 'text', placeholder: '8.8.8.8', default: '8.8.8.8' }
                ]
            },
            'virustotal': {
                title: 'Test VirusTotal',
                description: 'Scan an IP address using VirusTotal API.',
                fields: [
                    { key: 'test_ip', label: 'Test IP Address', type: 'text', placeholder: '8.8.8.8', default: '8.8.8.8' }
                ]
            },
            'shodan': {
                title: 'Test Shodan',
                description: 'Verify Shodan API key and check available credits.',
                fields: []
            },
            'ipapi': {
                title: 'Test IP-API',
                description: 'Test GeoIP lookup service.',
                fields: [
                    { key: 'test_ip', label: 'Test IP Address', type: 'text', placeholder: '8.8.8.8', default: '8.8.8.8' }
                ]
            }
        };
        return testForms[integrationId] || { title: 'Test Integration', description: '', fields: [] };
    }

    /**
     * Open test modal for an integration
     */
    function openTestModal(integrationId, integrationName) {
        const formConfig = getTestFormFields(integrationId);

        // Update modal title
        document.getElementById('test-modal-title').textContent = formConfig.title;

        // Render form
        const formContainer = document.getElementById('test-modal-form-container');
        let html = `<p style="color: #605E5C; margin-bottom: 16px;">${formConfig.description}</p>`;

        formConfig.fields.forEach(field => {
            html += `
                <div class="form-group" style="margin-bottom: 16px;">
                    <label for="test-${field.key}" style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                        ${field.label}
                    </label>
                    <input type="${field.type}" id="test-${field.key}" data-test-key="${field.key}"
                           value="${field.default || ''}"
                           placeholder="${field.placeholder || ''}"
                           style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px; box-sizing: border-box;">
                </div>
            `;
        });

        formContainer.innerHTML = html;

        // Reset result container
        document.getElementById('test-result-container').style.display = 'none';
        document.getElementById('test-result-container').innerHTML = '';

        // Show modal
        const modal = document.getElementById('integration-test-modal');
        modal.style.display = 'flex';

        // Setup test modal event listeners
        setupTestModalEventListeners(integrationId);
    }

    /**
     * Setup test modal event listeners
     */
    function setupTestModalEventListeners(integrationId) {
        const modal = document.getElementById('integration-test-modal');
        const closeBtn = document.getElementById('test-modal-close-btn');
        const cancelBtn = document.getElementById('test-modal-cancel-btn');
        const runBtn = document.getElementById('test-modal-run-btn');

        const closeModal = () => {
            modal.style.display = 'none';
        };

        closeBtn.onclick = closeModal;
        cancelBtn.onclick = closeModal;
        modal.onclick = (e) => {
            if (e.target === modal) closeModal();
        };

        runBtn.onclick = async () => {
            await runIntegrationTest(integrationId);
        };
    }

    /**
     * Run integration test
     */
    async function runIntegrationTest(integrationId) {
        const runBtn = document.getElementById('test-modal-run-btn');
        const resultContainer = document.getElementById('test-result-container');

        runBtn.textContent = 'Testing...';
        runBtn.disabled = true;
        resultContainer.style.display = 'block';
        resultContainer.innerHTML = '<div style="text-align: center; padding: 20px; color: #605E5C;"><span style="display: inline-block; animation: spin 1s linear infinite;">⏳</span> Running test...</div>';

        // Collect test parameters
        const testParams = {};
        document.querySelectorAll('[data-test-key]').forEach(input => {
            const key = input.getAttribute('data-test-key');
            if (input.value.trim()) {
                testParams[key] = input.value.trim();
            }
        });

        try {
            const response = await fetch(`/api/dashboard/integrations/${integrationId}/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(testParams)
            });

            const data = await response.json();

            if (data.success) {
                let resultHtml = `
                    <div style="background: #DFF6DD; border: 1px solid #107C10; border-radius: 4px; padding: 16px;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                            <span style="font-size: 20px;">✅</span>
                            <strong style="color: #107C10;">Test Successful</strong>
                        </div>
                        <div style="color: #323130;">${data.message}</div>
                `;

                if (data.data && Object.keys(data.data).length > 0) {
                    resultHtml += '<div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid #107C10;">';
                    for (const [key, value] of Object.entries(data.data)) {
                        const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                        resultHtml += `<div style="font-size: 13px; margin-bottom: 4px;"><strong>${displayKey}:</strong> ${value}</div>`;
                    }
                    resultHtml += '</div>';
                }

                resultHtml += '</div>';
                resultContainer.innerHTML = resultHtml;
                showNotification(data.message, 'success');
            } else {
                resultContainer.innerHTML = `
                    <div style="background: #FDE7E9; border: 1px solid #D13438; border-radius: 4px; padding: 16px;">
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                            <span style="font-size: 20px;">❌</span>
                            <strong style="color: #D13438;">Test Failed</strong>
                        </div>
                        <div style="color: #323130;">${data.error}</div>
                    </div>
                `;
                showNotification(data.error, 'error');
            }

            // Refresh integrations list to show updated test status
            await loadIntegrations();

        } catch (error) {
            console.error('Error running test:', error);
            resultContainer.innerHTML = `
                <div style="background: #FDE7E9; border: 1px solid #D13438; border-radius: 4px; padding: 16px;">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 20px;">❌</span>
                        <strong style="color: #D13438;">Error: ${error.message}</strong>
                    </div>
                </div>
            `;
        } finally {
            runBtn.textContent = 'Run Test';
            runBtn.disabled = false;
        }
    }

    /**
     * Open configuration modal for an integration
     */
    async function openConfigureModal(integrationId) {
        try {
            // Fetch latest integration data
            const response = await fetch(`/api/dashboard/integrations/${integrationId}`);
            const data = await response.json();

            if (!data.success) {
                throw new Error(data.error || 'Failed to load integration');
            }

            currentIntegration = data.data;

            // Update modal title
            document.getElementById('modal-title').textContent = `Configure ${currentIntegration.name}`;

            // Render form fields
            const formContainer = document.getElementById('modal-form-container');
            formContainer.innerHTML = renderConfigForm(currentIntegration);

            // Show modal
            const modal = document.getElementById('integration-config-modal');
            modal.style.display = 'flex';

            // Setup modal event listeners
            setupModalEventListeners();

        } catch (error) {
            console.error('Error opening config modal:', error);
            showNotification('Failed to load integration configuration', 'error');
        }
    }

    /**
     * Render configuration form fields
     */
    function renderConfigForm(integration) {
        if (!integration.config_fields || integration.config_fields.length === 0) {
            return '<p style="color: #605E5C;">No configuration options available for this integration.</p>';
        }

        let html = '<div style="display: flex; flex-direction: column; gap: 20px;">';

        integration.config_fields.forEach(field => {
            const inputId = `config-${field.key}`;
            const required = field.is_required ? '<span style="color: #D13438;">*</span>' : '';

            html += `
                <div class="form-group">
                    <label for="${inputId}" style="display: block; margin-bottom: 6px; font-weight: 500; font-size: 14px; color: #323130;">
                        ${field.display_name} ${required}
                    </label>
            `;

            if (field.type === 'boolean') {
                const isChecked = field.value === 'true' || field.value === true;
                html += `
                    <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                        <input type="checkbox" id="${inputId}" data-config-key="${field.key}"
                               ${isChecked ? 'checked' : ''}
                               style="width: 18px; height: 18px; cursor: pointer;">
                        <span style="font-size: 14px; color: #605E5C;">Enable</span>
                    </label>
                `;
            } else if (field.is_sensitive) {
                html += `
                    <input type="password" id="${inputId}" data-config-key="${field.key}"
                           placeholder="${field.has_value ? '••••••••••••••••' : 'Enter ' + field.display_name}"
                           style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px;">
                    ${field.has_value ? '<div style="font-size: 11px; color: #107C10; margin-top: 4px;">Currently configured. Leave blank to keep existing value.</div>' : ''}
                `;
            } else if (field.type === 'number') {
                html += `
                    <input type="number" id="${inputId}" data-config-key="${field.key}"
                           value="${field.value || ''}"
                           placeholder="Enter ${field.display_name}"
                           style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px;">
                `;
            } else {
                html += `
                    <input type="text" id="${inputId}" data-config-key="${field.key}"
                           value="${field.value || ''}"
                           placeholder="Enter ${field.display_name}"
                           style="width: 100%; padding: 10px 12px; border: 1px solid #EDEBE9; border-radius: 4px; font-size: 14px;">
                `;
            }

            if (field.description) {
                html += `<div style="font-size: 12px; color: #605E5C; margin-top: 4px;">${field.description}</div>`;
            }

            html += '</div>';
        });

        html += '</div>';
        return html;
    }

    /**
     * Setup modal event listeners
     */
    function setupModalEventListeners() {
        const modal = document.getElementById('integration-config-modal');
        const closeBtn = document.getElementById('modal-close-btn');
        const cancelBtn = document.getElementById('modal-cancel-btn');
        const saveBtn = document.getElementById('modal-save-btn');

        // Close modal handlers
        const closeModal = () => {
            modal.style.display = 'none';
            currentIntegration = null;
        };

        closeBtn.onclick = closeModal;
        cancelBtn.onclick = closeModal;

        // Click outside to close
        modal.onclick = (e) => {
            if (e.target === modal) closeModal();
        };

        // Save configuration
        saveBtn.onclick = async () => {
            await saveConfiguration();
        };
    }

    /**
     * Save integration configuration
     */
    async function saveConfiguration() {
        if (!currentIntegration) return;

        const saveBtn = document.getElementById('modal-save-btn');
        const originalText = saveBtn.textContent;
        saveBtn.textContent = 'Saving...';
        saveBtn.disabled = true;

        try {
            // Collect form values
            const configData = {};
            currentIntegration.config_fields.forEach(field => {
                const input = document.getElementById(`config-${field.key}`);
                if (input) {
                    if (field.type === 'boolean') {
                        configData[field.key] = input.checked ? 'true' : 'false';
                    } else {
                        // Only include non-empty values for sensitive fields
                        if (field.is_sensitive && !input.value) {
                            // Skip - keep existing value
                        } else {
                            configData[field.key] = input.value;
                        }
                    }
                }
            });

            // Save to API
            const response = await fetch(`/api/dashboard/integrations/${currentIntegration.integration_id}/configure`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(configData)
            });

            const data = await response.json();

            if (data.success) {
                showNotification('Configuration saved successfully', 'success');

                // Close modal and refresh list
                document.getElementById('integration-config-modal').style.display = 'none';
                currentIntegration = null;
                await loadIntegrations();
            } else {
                throw new Error(data.error || 'Failed to save configuration');
            }

        } catch (error) {
            console.error('Error saving configuration:', error);
            showNotification(error.message || 'Failed to save configuration', 'error');
        } finally {
            saveBtn.textContent = originalText;
            saveBtn.disabled = false;
        }
    }

    /**
     * Setup inline event listeners after rendering
     */
    function setupInlineEventListeners() {
        // Configure buttons
        document.querySelectorAll('.btn-configure-integration').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const integrationId = e.target.getAttribute('data-integration-id');
                openConfigureModal(integrationId);
            });
        });

        // Test buttons
        document.querySelectorAll('.btn-test-integration').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const integrationId = e.target.getAttribute('data-integration-id');
                const integrationName = e.target.closest('.integration-card').querySelector('[style*="font-weight: 600"]').textContent.trim();
                openTestModal(integrationId, integrationName);
            });
        });
    }

    /**
     * Setup event listeners
     */
    function setupIntegrationsEventListeners() {
        // Refresh button
        const refreshBtn = document.getElementById('integrations-refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                loadIntegrations();
            });
        }
    }

})();
