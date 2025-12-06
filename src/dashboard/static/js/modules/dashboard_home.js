/**
 * SSH Guardian v3.0 - Dashboard Home Module
 * Action-focused design with User Guide Wizard and Research Thesis
 */

const DashboardHome = {
    // State
    currentTab: 'guide',
    currentStep: 1,
    totalSteps: 6,
    guideData: null,
    thesisData: null,
    isLoading: false,
    statsLoaded: false,

    // API Endpoints
    API: {
        guide: '/api/dashboard/content/guide/full',
        thesis: '/api/dashboard/content/thesis/full',
        stats: '/api/events/stats',
        agents: '/api/agents/list',
        blocks: '/api/blocking/list'
    },

    /**
     * Initialize the dashboard home module
     */
    init() {
        console.log('DashboardHome: Initializing...');
        this.loadHeroStats();
        this.loadGuide();
        this.renderWizardDots();
    },

    /**
     * Load hero section live statistics
     */
    async loadHeroStats() {
        if (this.statsLoaded) return;

        try {
            // Fetch stats in parallel
            const [eventsRes, agentsRes, blocksRes, threatsRes] = await Promise.all([
                fetch('/api/events/list?limit=1').catch(() => null),
                fetch('/api/agents/list').catch(() => null),
                fetch('/api/blocking/list?is_active=true').catch(() => null),
                fetch('/api/events/list?event_type=Failed&limit=1').catch(() => null)
            ]);

            // Total events
            let totalEvents = '--';
            if (eventsRes?.ok) {
                const eventsData = await eventsRes.json();
                totalEvents = eventsData.data?.pagination?.total || eventsData.data?.total || '0';
            }

            // Active agents
            let activeAgents = '--';
            if (agentsRes?.ok) {
                const agentsData = await agentsRes.json();
                const agents = agentsData.data?.agents || agentsData.data || [];
                activeAgents = agents.filter(a => a.status === 'online' || a.is_approved).length || agents.length;
            }

            // Blocked IPs
            let blockedIPs = '--';
            if (blocksRes?.ok) {
                const blocksData = await blocksRes.json();
                blockedIPs = blocksData.data?.length || blocksData.data?.total || '0';
            }

            // Threats detected (failed login attempts)
            let threatsDetected = '--';
            if (threatsRes?.ok) {
                const threatsData = await threatsRes.json();
                threatsDetected = threatsData.data?.pagination?.total || threatsData.data?.total || '0';
            }

            // Update UI
            const eventsEl = document.getElementById('stat-events');
            const agentsEl = document.getElementById('stat-agents');
            const blockedEl = document.getElementById('stat-blocked');
            const threatsEl = document.getElementById('stat-threats');

            if (eventsEl) eventsEl.textContent = this.formatNumber(totalEvents);
            if (agentsEl) agentsEl.textContent = activeAgents;
            if (blockedEl) blockedEl.textContent = this.formatNumber(blockedIPs);
            if (threatsEl) threatsEl.textContent = this.formatNumber(threatsDetected);

            this.statsLoaded = true;
        } catch (error) {
            console.error('Error loading hero stats:', error);
        }
    },

    /**
     * Format large numbers
     */
    formatNumber(num) {
        if (num === '--' || num === undefined || num === null) return '--';
        const n = parseInt(num);
        if (isNaN(n)) return num;
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return n.toString();
    },

    /**
     * Switch between tabs
     */
    switchTab(tab) {
        if (this.currentTab === tab) return;

        // Update tab buttons
        document.querySelectorAll('.dashboard-home-tab').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tab);
        });

        // Update tab content
        document.querySelectorAll('.dashboard-home-tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `tab-${tab}`);
        });

        this.currentTab = tab;

        // Load content if needed
        if (tab === 'guide' && !this.guideData) {
            this.loadGuide();
        } else if (tab === 'thesis' && !this.thesisData) {
            this.loadThesis();
        }
    },

    // =========================================
    // GUIDE WIZARD FUNCTIONS
    // =========================================

    /**
     * Load guide content from API
     */
    async loadGuide() {
        if (this.isLoading) return;
        this.isLoading = true;

        try {
            const response = await fetch(this.API.guide);
            const result = await response.json();

            if (result.success && result.data) {
                this.guideData = result.data;
                this.totalSteps = result.data.total_steps || result.data.steps?.length || 6;
                document.getElementById('total-steps').textContent = this.totalSteps;
                this.renderGuideStep(this.currentStep);
            } else {
                // Use default content
                this.renderGuideStep(this.currentStep);
            }
        } catch (error) {
            console.error('Error loading guide:', error);
            this.renderGuideStep(this.currentStep);
        } finally {
            this.isLoading = false;
        }
    },

    /**
     * Render wizard step dots
     */
    renderWizardDots() {
        const container = document.getElementById('wizard-dots');
        if (!container) return;

        let html = '';
        for (let i = 1; i <= this.totalSteps; i++) {
            const classes = ['wizard-dot'];
            if (i === this.currentStep) classes.push('active');
            if (i < this.currentStep) classes.push('completed');
            html += `<div class="${classes.join(' ')}" onclick="DashboardHome.goToStep(${i})"></div>`;
        }
        container.innerHTML = html;
    },

    /**
     * Render current guide step content
     */
    renderGuideStep(stepNum) {
        // Get step data from API or use default
        let step;
        if (this.guideData?.steps?.length) {
            step = this.guideData.steps.find(s => s.step_number === stepNum);
        }

        if (!step) {
            step = this.getDefaultStep(stepNum);
        }

        // Update header
        const iconEl = document.getElementById('wizard-icon');
        const titleEl = document.getElementById('wizard-title');
        const subtitleEl = document.getElementById('wizard-subtitle');

        if (iconEl) iconEl.innerHTML = step.icon || '&#128214;';
        if (titleEl) titleEl.textContent = step.title;
        if (subtitleEl) subtitleEl.textContent = step.subtitle || '';

        // Update content body
        const bodyEl = document.getElementById('wizard-content-body');
        if (bodyEl) {
            bodyEl.innerHTML = `
                <div class="wizard-step-content">
                    ${step.content_html}
                    ${step.tips_html ? `
                        <div class="wizard-tips-box">
                            <div class="wizard-tips-title">&#128161; Pro Tip</div>
                            <p>${step.tips_html}</p>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        this.updateWizardUI();
    },

    /**
     * Get default step content
     */
    getDefaultStep(stepNum) {
        const steps = {
            1: {
                icon: '&#128737;',
                title: 'Welcome to SSH Guardian',
                subtitle: 'A Research Project for SME Cybersecurity',
                content_html: `
                    <p>SSH Guardian is a <strong>lightweight SSH anomaly detection agent</strong> designed specifically for Small and Medium Enterprises (SMEs) operating on limited cloud infrastructure.</p>
                    <p>This project is part of a Masters-level research thesis at <strong>Asia Pacific University of Technology & Innovation</strong>.</p>
                    <h3>Key Features</h3>
                    <ul>
                        <li><strong>Real-time Monitoring</strong> - Track SSH authentication events as they happen</li>
                        <li><strong>ML-Based Detection</strong> - Isolation Forest algorithm for anomaly detection</li>
                        <li><strong>Threat Intelligence</strong> - Integration with AbuseIPDB and VirusTotal</li>
                        <li><strong>Automated Response</strong> - Rule-based IP blocking via UFW</li>
                        <li><strong>Resource Efficient</strong> - Minimal CPU/RAM footprint for SME servers</li>
                    </ul>
                `,
                tips_html: 'Use the Quick Actions cards above to jump directly to key features, or continue through this guide to learn about each component.'
            },
            2: {
                icon: '&#127959;',
                title: 'System Architecture',
                subtitle: '5-Layer Security Pipeline',
                content_html: `
                    <p>SSH Guardian uses a <strong>multi-layered architecture</strong> to process and analyze authentication events efficiently:</p>
                    <h3>Architecture Layers</h3>
                    <ol>
                        <li><strong>Data Collection Layer</strong> - Agent monitors SSH auth logs using inotify for real-time detection</li>
                        <li><strong>Processing Layer</strong> - Events parsed, normalized, and enriched with GeoIP data</li>
                        <li><strong>Analysis Layer</strong> - ML model + threat intelligence APIs evaluate risk score</li>
                        <li><strong>Alert Layer</strong> - Notifications via Telegram, email, or webhooks</li>
                        <li><strong>Storage Layer</strong> - MySQL database for events, statistics, and audit trail</li>
                    </ol>
                    <h3>Composite Risk Scoring</h3>
                    <ul>
                        <li><strong>35%</strong> - Threat Intelligence (AbuseIPDB, VirusTotal)</li>
                        <li><strong>30%</strong> - ML Anomaly Score (Isolation Forest)</li>
                        <li><strong>25%</strong> - Behavioral Patterns (velocity, uniqueness)</li>
                        <li><strong>10%</strong> - Geographic Risk (high-risk regions)</li>
                    </ul>
                `,
                tips_html: 'The architecture is designed for horizontal scalability - deploy multiple agents while centralizing monitoring in this dashboard.'
            },
            3: {
                icon: '&#128640;',
                title: 'Agent Deployment',
                subtitle: 'Install Monitoring Agents on Your Servers',
                content_html: `
                    <p>Deploy SSH Guardian agents on your cloud servers to start monitoring SSH authentication events.</p>
                    <h3>Quick Installation</h3>
                    <div style="background: #1e1e2e; padding: 16px; border-radius: 8px; margin: 16px 0; overflow-x: auto;">
                        <code style="color: #89b4fa; font-family: monospace;">curl -sSL https://ssh-guardian.rpu.solutions/install.sh | sudo bash</code>
                    </div>
                    <h3>Registration Process</h3>
                    <ol>
                        <li>Run the installer on your target server</li>
                        <li>Agent generates a unique UUID and registers with this dashboard</li>
                        <li>Navigate to <strong>Agents</strong> page and approve the new agent</li>
                        <li>Agent begins sending real-time authentication events</li>
                    </ol>
                    <h3>System Requirements</h3>
                    <ul>
                        <li>Linux server (Ubuntu 20.04+, Debian 11+, CentOS 8+)</li>
                        <li>Python 3.8 or higher</li>
                        <li>Read access to /var/log/auth.log</li>
                        <li>HTTPS access to dashboard API</li>
                    </ul>
                `,
                tips_html: 'After installation, the agent appears in "Pending Approval" on the Agents page. Approve it to start receiving events.'
            },
            4: {
                icon: '&#128200;',
                title: 'Live Events Monitoring',
                subtitle: 'Real-time Authentication Event Stream',
                content_html: `
                    <p>The <strong>Live Events</strong> page shows all SSH authentication attempts across your monitored servers in real-time.</p>
                    <h3>Event Types</h3>
                    <ul>
                        <li><span style="color: #ef4444; font-weight: bold;">Failed</span> - Invalid password or public key rejected</li>
                        <li><span style="color: #10b981; font-weight: bold;">Successful</span> - Authenticated login session</li>
                        <li><span style="color: #f59e0b; font-weight: bold;">Invalid User</span> - Username does not exist</li>
                    </ul>
                    <h3>Threat Analysis</h3>
                    <p>Click <strong>"View Details"</strong> on any event to see:</p>
                    <ul>
                        <li>GeoIP location with map visualization</li>
                        <li>AbuseIPDB reputation score and reports</li>
                        <li>VirusTotal detection results</li>
                        <li>ML anomaly assessment and confidence</li>
                        <li>Historical patterns for this IP</li>
                    </ul>
                    <h3>Quick Actions</h3>
                    <ul>
                        <li><strong>Block IP</strong> - Add to UFW deny list immediately</li>
                        <li><strong>Watchlist</strong> - Monitor future activity closely</li>
                        <li><strong>Whitelist</strong> - Mark as trusted (excludes from blocking)</li>
                        <li><strong>Report</strong> - Generate detailed threat analysis PDF</li>
                    </ul>
                `,
                tips_html: 'Use filters to narrow events by date, type, agent, or risk level. High-risk events (score > 80) are highlighted.'
            },
            5: {
                icon: '&#128274;',
                title: 'Firewall Management',
                subtitle: 'UFW Integration and IP Blocking',
                content_html: `
                    <p>SSH Guardian integrates directly with <strong>UFW (Uncomplicated Firewall)</strong> for automated threat response.</p>
                    <h3>Automatic Blocking Rules</h3>
                    <p>Configure rules in <strong>Settings > Blocking Rules</strong> to automatically block IPs:</p>
                    <ul>
                        <li><strong>Failed Attempts</strong> - e.g., 5 failures in 10 minutes</li>
                        <li><strong>ML Risk Score</strong> - Block when score exceeds threshold</li>
                        <li><strong>AbuseIPDB Score</strong> - Block IPs with high abuse confidence</li>
                        <li><strong>Geographic Restrictions</strong> - Block entire countries</li>
                    </ul>
                    <h3>Firewall Page Features</h3>
                    <ul>
                        <li>View all active blocks with expiration countdown</li>
                        <li>Manually block/unblock individual IPs or CIDR ranges</li>
                        <li>Configure UFW port rules (allow/deny services)</li>
                        <li>Set block durations (15 min to permanent)</li>
                    </ul>
                    <h3>Audit Trail</h3>
                    <p>Every action is logged with timestamp, IP, reason, and trigger source (rule/manual/system).</p>
                `,
                tips_html: 'Enable Auto-Unblock with shorter durations (1-24 hours) to prevent permanent lockouts from legitimate users.'
            },
            6: {
                icon: '&#129302;',
                title: 'Threat Intelligence & ML',
                subtitle: 'Advanced Detection Capabilities',
                content_html: `
                    <p>SSH Guardian combines multiple detection methods for comprehensive threat assessment.</p>
                    <h3>Threat Intelligence APIs</h3>
                    <ul>
                        <li><strong>AbuseIPDB</strong> - Crowdsourced IP reputation with abuse confidence scores</li>
                        <li><strong>VirusTotal</strong> - Multi-engine malware and malicious URL detection</li>
                        <li><strong>FreeIPAPI</strong> - Geolocation, VPN detection, and proxy identification</li>
                    </ul>
                    <h3>Machine Learning Detection</h3>
                    <p>The <strong>Isolation Forest</strong> algorithm detects anomalies based on:</p>
                    <ul>
                        <li><strong>Time Patterns</strong> - Unusual hours of activity</li>
                        <li><strong>Geographic Anomalies</strong> - Login from new countries</li>
                        <li><strong>Volume Patterns</strong> - Sudden spikes in attempts</li>
                        <li><strong>Target Diversity</strong> - Multiple usernames from same IP</li>
                    </ul>
                    <h3>Model Management</h3>
                    <p>Navigate to <strong>Settings > ML Settings</strong> to:</p>
                    <ul>
                        <li>View current model performance metrics</li>
                        <li>Trigger retraining with recent data</li>
                        <li>Adjust anomaly sensitivity threshold</li>
                    </ul>
                `,
                tips_html: 'The ML model learns your environment\'s baseline over time. Allow 1-2 weeks of data before relying heavily on ML scores.'
            }
        };

        return steps[stepNum] || steps[1];
    },

    /**
     * Update wizard UI state
     */
    updateWizardUI() {
        // Update step counter
        const currentStepEl = document.getElementById('current-step');
        if (currentStepEl) currentStepEl.textContent = this.currentStep;

        // Update progress bar
        const progressFill = document.getElementById('wizard-progress-fill');
        if (progressFill) {
            const progress = (this.currentStep / this.totalSteps) * 100;
            progressFill.style.width = `${progress}%`;
        }

        // Update navigation buttons
        const prevBtn = document.getElementById('wizard-prev');
        const nextBtn = document.getElementById('wizard-next');

        if (prevBtn) prevBtn.disabled = this.currentStep <= 1;
        if (nextBtn) {
            nextBtn.disabled = this.currentStep >= this.totalSteps;
            nextBtn.innerHTML = this.currentStep >= this.totalSteps
                ? 'Complete &#10003;'
                : 'Next &#8594;';
        }

        // Update step cards
        document.querySelectorAll('.wizard-step-card').forEach(card => {
            const step = parseInt(card.dataset.step);
            card.classList.toggle('active', step === this.currentStep);
            card.classList.toggle('completed', step < this.currentStep);

            const numberEl = card.querySelector('.wizard-step-number');
            if (numberEl) {
                numberEl.innerHTML = step < this.currentStep ? '&#10003;' : step;
            }
        });

        // Update dots
        this.renderWizardDots();
    },

    /**
     * Navigate to next step
     */
    nextStep() {
        if (this.currentStep < this.totalSteps) {
            this.currentStep++;
            this.renderGuideStep(this.currentStep);
        }
    },

    /**
     * Navigate to previous step
     */
    prevStep() {
        if (this.currentStep > 1) {
            this.currentStep--;
            this.renderGuideStep(this.currentStep);
        }
    },

    /**
     * Go to specific step
     */
    goToStep(stepNum) {
        if (stepNum >= 1 && stepNum <= this.totalSteps) {
            this.currentStep = stepNum;
            this.renderGuideStep(this.currentStep);
        }
    },

    // =========================================
    // THESIS FUNCTIONS
    // =========================================

    /**
     * Load thesis content from API
     */
    async loadThesis() {
        if (this.isLoading) return;
        this.isLoading = true;

        try {
            const response = await fetch(this.API.thesis);
            const result = await response.json();

            if (result.success && result.data) {
                this.thesisData = result.data;
                this.renderThesisHeader();
                this.renderThesisTOC();
                this.renderThesisSections();
                this.initScrollSpy();
            } else {
                this.renderDefaultThesis();
            }
        } catch (error) {
            console.error('Error loading thesis:', error);
            this.renderDefaultThesis();
        } finally {
            this.isLoading = false;
        }
    },

    /**
     * Render thesis header
     */
    renderThesisHeader() {
        const meta = this.thesisData?.metadata || {};

        const titleEl = document.getElementById('thesis-title-text');
        if (titleEl) {
            titleEl.textContent = meta.title || 'Research Thesis';
        }

        const metaGrid = document.getElementById('thesis-meta-grid');
        if (metaGrid) {
            metaGrid.innerHTML = `
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Student</div>
                    <div class="thesis-meta-value">${meta.student_name || 'N/A'} (${meta.student_id || 'N/A'})</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Institution</div>
                    <div class="thesis-meta-value">${meta.institution || 'N/A'}</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Supervisor</div>
                    <div class="thesis-meta-value">${meta.supervisor || 'N/A'}</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Module</div>
                    <div class="thesis-meta-value">${meta.module_code || ''} ${meta.module_name || ''}</div>
                </div>
            `;
        }
    },

    /**
     * Render table of contents
     */
    renderThesisTOC() {
        const container = document.getElementById('toc-list');
        if (!container) return;

        const toc = this.thesisData?.toc || [];

        if (toc.length === 0) {
            container.innerHTML = '<li class="toc-item"><span class="toc-link">No content available</span></li>';
            return;
        }

        container.innerHTML = toc.map(item => `
            <li class="toc-item level-${item.toc_level || 1}">
                <a class="toc-link" href="#section-${item.section_key}" onclick="DashboardHome.scrollToSection('${item.section_key}'); return false;">
                    ${item.chapter_number ? `<span class="toc-chapter-num">${item.chapter_number}</span>` : ''}
                    ${item.title}
                </a>
            </li>
        `).join('');
    },

    /**
     * Render thesis sections
     */
    renderThesisSections() {
        const container = document.getElementById('thesis-sections');
        if (!container) return;

        const sections = this.thesisData?.sections || [];

        if (sections.length === 0) {
            this.renderDefaultThesis();
            return;
        }

        container.innerHTML = sections.map(section => `
            <section class="thesis-section" id="section-${section.section_key}">
                <div class="thesis-section-header">
                    ${section.chapter_number ? `<span class="thesis-section-number">${section.chapter_number}</span>` : ''}
                    <h2 class="thesis-section-title">${section.title}</h2>
                </div>
                <div class="thesis-section-content">
                    ${section.content_html}
                </div>
            </section>
        `).join('');
    },

    /**
     * Render default thesis content
     */
    renderDefaultThesis() {
        const titleEl = document.getElementById('thesis-title-text');
        if (titleEl) {
            titleEl.textContent = 'Design and Evaluation of a Lightweight SSH Access Behavior Profiling and Anomaly Alerting Agent';
        }

        const metaGrid = document.getElementById('thesis-meta-grid');
        if (metaGrid) {
            metaGrid.innerHTML = `
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Student</div>
                    <div class="thesis-meta-value">Md Sohel Rana (TP086217)</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Institution</div>
                    <div class="thesis-meta-value">Asia Pacific University</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Module</div>
                    <div class="thesis-meta-value">Research Methodology</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Year</div>
                    <div class="thesis-meta-value">2025</div>
                </div>
            `;
        }

        const tocContainer = document.getElementById('toc-list');
        if (tocContainer) {
            tocContainer.innerHTML = `
                <li class="toc-item"><a class="toc-link active" href="#section-abstract" onclick="DashboardHome.scrollToSection('abstract'); return false;"><span class="toc-chapter-num">-</span> Abstract</a></li>
                <li class="toc-item"><a class="toc-link" href="#section-intro" onclick="DashboardHome.scrollToSection('intro'); return false;"><span class="toc-chapter-num">1</span> Introduction</a></li>
                <li class="toc-item"><a class="toc-link" href="#section-methodology" onclick="DashboardHome.scrollToSection('methodology'); return false;"><span class="toc-chapter-num">3</span> Methodology</a></li>
            `;
        }

        const sectionsContainer = document.getElementById('thesis-sections');
        if (sectionsContainer) {
            sectionsContainer.innerHTML = `
                <section class="thesis-section" id="section-abstract">
                    <div class="thesis-section-header">
                        <span class="thesis-section-number">Abstract</span>
                        <h2 class="thesis-section-title">Abstract</h2>
                    </div>
                    <div class="thesis-section-content">
                        <p>This research presents the design, implementation, and evaluation of SSH Guardian, a lightweight SSH access behavior profiling and anomaly alerting agent for Small and Medium Enterprises (SMEs).</p>
                        <p>The system employs Isolation Forest machine learning for unsupervised anomaly detection, integrated with threat intelligence services to provide comprehensive risk assessment.</p>
                        <p><strong>Keywords:</strong> SSH Security, Anomaly Detection, Machine Learning, SME Cybersecurity</p>
                    </div>
                </section>
                <section class="thesis-section" id="section-intro">
                    <div class="thesis-section-header">
                        <span class="thesis-section-number">Chapter 1</span>
                        <h2 class="thesis-section-title">Introduction</h2>
                    </div>
                    <div class="thesis-section-content">
                        <h3>1.1 Background</h3>
                        <p>The Secure Shell (SSH) protocol remains the primary method for remote server administration. However, SSH services face constant attack attempts including brute force attacks, credential stuffing, and targeted intrusions.</p>
                        <h3>1.2 Problem Statement</h3>
                        <p>Current SSH security solutions present challenges for SMEs: enterprise solutions are cost-prohibitive, manual analysis is error-prone, and traditional detection misses sophisticated patterns.</p>
                    </div>
                </section>
                <section class="thesis-section" id="section-methodology">
                    <div class="thesis-section-header">
                        <span class="thesis-section-number">Chapter 3</span>
                        <h2 class="thesis-section-title">Methodology</h2>
                    </div>
                    <div class="thesis-section-content">
                        <h3>3.1 System Architecture</h3>
                        <p>SSH Guardian employs a five-layer architecture: Data Collection, Processing, Analysis, Alert, and Storage layers designed to balance accuracy with resource efficiency.</p>
                        <p>Content is loaded from the database. Use the API to add full thesis content.</p>
                    </div>
                </section>
            `;
        }
    },

    /**
     * Scroll to thesis section
     */
    scrollToSection(sectionKey) {
        const element = document.getElementById(`section-${sectionKey}`);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'start' });

            // Update active TOC link
            document.querySelectorAll('.toc-link').forEach(link => {
                link.classList.toggle('active', link.href?.includes(sectionKey) || link.getAttribute('href')?.includes(sectionKey));
            });
        }
    },

    /**
     * Initialize scroll spy for TOC
     */
    initScrollSpy() {
        const sections = document.querySelectorAll('.thesis-section');
        const tocLinks = document.querySelectorAll('.toc-link');

        if (sections.length === 0) return;

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const sectionKey = entry.target.id.replace('section-', '');
                    tocLinks.forEach(link => {
                        const href = link.href || link.getAttribute('href') || '';
                        link.classList.toggle('active', href.includes(sectionKey));
                    });
                }
            });
        }, { threshold: 0.2, rootMargin: '-100px 0px -50% 0px' });

        sections.forEach(section => observer.observe(section));
    }
};

// Navigation helper function for action cards
function navigateTo(page) {
    // Check if there's a navigation function available
    if (typeof window.navigateToPage === 'function') {
        window.navigateToPage(page);
    } else if (typeof window.showPage === 'function') {
        window.showPage(page);
    } else {
        // Fallback: update URL hash and trigger hashchange
        window.location.hash = page;
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('page-dashboard')) {
        DashboardHome.init();
    }
});

// Also initialize on hash change for SPA navigation
window.addEventListener('hashchange', () => {
    if (window.location.hash === '#dashboard' && document.getElementById('page-dashboard')) {
        DashboardHome.init();
    }
});
