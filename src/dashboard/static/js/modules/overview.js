/**
 * SSH Guardian v3.0 - Overview Module
 * User Guide Wizard and Research Thesis with Caching
 */

const Overview = {
    // State
    currentTab: 'guide',
    currentStep: 1,
    totalSteps: 8,
    guideData: null,
    thesisData: null,
    isLoading: false,
    initialized: false,

    // API Endpoints
    API: {
        guide: '/api/dashboard/content/guide/full',
        thesis: '/api/dashboard/content/thesis/full',
        events: '/api/dashboard/events/list',
        eventsSummary: '/api/dashboard/events-analysis/summary',
        agents: '/api/agents/list',
        blocks: '/api/dashboard/blocking/blocks/list'
    },

    // Cache configuration
    CACHE: {
        THESIS_KEY: 'overview_thesis_content',
        THESIS_TIME_KEY: 'overview_thesis_cached_at',
        GUIDE_KEY: 'overview_guide_content',
        GUIDE_TIME_KEY: 'overview_guide_cached_at',
        TTL: 86400000 // 24 hours
    },

    // DOM element references (cached for performance)
    els: {},

    /**
     * Initialize the overview module
     */
    init() {
        if (this.initialized) {
            this.loadHeroStats();
            return;
        }

        this.cacheElements();
        this.loadHeroStats();
        this.loadGuide();
        this.renderWizardDots();
        this.initQuickNav();
        this.initialized = true;
    },

    /**
     * Cache DOM element references for better performance
     */
    cacheElements() {
        this.els = {
            // Wizard elements
            wizardIcon: document.getElementById('overview-wizard-icon'),
            wizardTitle: document.getElementById('overview-wizard-title'),
            wizardSubtitle: document.getElementById('overview-wizard-subtitle'),
            wizardBody: document.getElementById('overview-wizard-content-body'),
            wizardDots: document.getElementById('overview-wizard-dots'),
            wizardStepsGrid: document.getElementById('overview-wizard-steps-grid'),
            wizardPrevBtn: document.getElementById('overview-wizard-prev'),
            wizardNextBtn: document.getElementById('overview-wizard-next'),
            wizardProgress: document.getElementById('overview-wizard-progress-fill'),
            currentStepEl: document.getElementById('overview-current-step'),
            totalStepsEl: document.getElementById('overview-total-steps'),
            wizardSection: document.getElementById('wizard-section'),
            wizardContentPanel: document.querySelector('.wizard-content-panel'),
            // Stats elements
            statEvents: document.getElementById('overview-stat-events'),
            statAgents: document.getElementById('overview-stat-agents'),
            statBlocked: document.getElementById('overview-stat-blocked'),
            statThreats: document.getElementById('overview-stat-threats'),
            // TOC elements
            thesisToc: document.getElementById('overview-thesis-toc'),
            tocOverlay: document.querySelector('.thesis-toc-overlay')
        };
    },

    /**
     * Initialize quick navigation bar with scroll spy
     */
    initQuickNav() {
        const navBar = document.getElementById('quickNavBar');
        if (!navBar) {
            console.log('Overview: quickNavBar not found');
            return;
        }

        const navItems = navBar.querySelectorAll('.quick-nav-item');
        const sectionIds = ['quick-actions-section', 'tech-stack-section', 'wizard-section'];
        const self = this;

        console.log('Overview: Initializing quick nav with', navItems.length, 'items');

        // Smooth scroll on click
        navItems.forEach(item => {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                const targetId = this.getAttribute('href')?.substring(1);
                console.log('Overview: Quick nav clicked, target:', targetId);
                const targetEl = document.getElementById(targetId);
                if (targetEl) {
                    // Update active state immediately
                    navItems.forEach(nav => nav.classList.remove('active'));
                    this.classList.add('active');
                    // Scroll to element
                    self.scrollToElement(targetEl);
                } else {
                    console.log('Overview: Target element not found:', targetId);
                }
            });
        });

        // Scroll spy using IntersectionObserver
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const sectionId = entry.target.id;
                    navItems.forEach(item => {
                        const targetId = item.getAttribute('href')?.substring(1);
                        item.classList.toggle('active', targetId === sectionId);
                    });
                }
            });
        }, { rootMargin: '-100px 0px -50% 0px', threshold: 0 });

        sectionIds.forEach(id => {
            const el = document.getElementById(id);
            if (el) observer.observe(el);
        });
    },

    /**
     * Scroll to element with offset for sticky headers
     */
    scrollToElement(element, offset = 100) {
        if (!element) {
            console.log('Overview: scrollToElement - element is null');
            return;
        }

        // Find the scrollable container (.main-content)
        const scrollContainer = document.querySelector('.main-content');
        if (scrollContainer) {
            // Calculate position relative to scroll container
            const containerRect = scrollContainer.getBoundingClientRect();
            const elementRect = element.getBoundingClientRect();
            const scrollTop = scrollContainer.scrollTop + (elementRect.top - containerRect.top) - offset;

            console.log('Overview: scrolling .main-content to', scrollTop);
            scrollContainer.scrollTo({ top: Math.max(0, scrollTop), behavior: 'smooth' });
        } else {
            // Fallback to scrollIntoView
            console.log('Overview: using scrollIntoView fallback');
            element.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    },

    // =========================================
    // CACHE HELPERS
    // =========================================

    isCacheValid(timeKey) {
        const cachedAt = localStorage.getItem(timeKey);
        return cachedAt && (Date.now() - parseInt(cachedAt)) < this.CACHE.TTL;
    },

    getFromCache(key, timeKey) {
        if (!this.isCacheValid(timeKey)) return null;
        try {
            return JSON.parse(localStorage.getItem(key));
        } catch {
            return null;
        }
    },

    saveToCache(key, timeKey, data) {
        try {
            localStorage.setItem(key, JSON.stringify(data));
            localStorage.setItem(timeKey, Date.now().toString());
        } catch (e) {
            console.warn('Cache save failed:', e);
        }
    },

    clearCache() {
        ['THESIS_KEY', 'THESIS_TIME_KEY', 'GUIDE_KEY', 'GUIDE_TIME_KEY'].forEach(k => {
            localStorage.removeItem(this.CACHE[k]);
        });
        this.guideData = null;
        this.thesisData = null;
        console.log('Overview: Cache cleared');
    },

    // =========================================
    // HERO STATS
    // =========================================

    async loadHeroStats() {
        try {
            const [eventsRes, agentsRes, blocksRes, summaryRes] = await Promise.all([
                fetch(`${this.API.events}?limit=1`).catch(() => null),
                fetch(this.API.agents).catch(() => null),
                fetch(`${this.API.blocks}?is_active=true`).catch(() => null),
                fetch(this.API.eventsSummary).catch(() => null)
            ]);

            const fmt = window.formatNumber || (n => n);

            // Total events
            if (eventsRes?.ok) {
                const data = await eventsRes.json();
                this.updateStat('statEvents', fmt(data.pagination?.total || 0));
            }

            // Active agents
            if (agentsRes?.ok) {
                const data = await agentsRes.json();
                const agents = data.agents || [];
                this.updateStat('statAgents', agents.filter(a => a.is_approved).length || agents.length);
            }

            // Blocked IPs
            if (blocksRes?.ok) {
                const data = await blocksRes.json();
                this.updateStat('statBlocked', fmt((data.blocks || []).filter(b => b.is_active).length));
            }

            // Threats detected
            if (summaryRes?.ok) {
                const data = await summaryRes.json();
                const threats = data.data?.summary?.failed_count || data.data?.events_by_type?.failed || 0;
                this.updateStat('statThreats', fmt(threats));
            }
        } catch (error) {
            console.error('Error loading stats:', error);
        }
    },

    updateStat(key, value) {
        if (this.els[key]) this.els[key].textContent = value;
    },

    // =========================================
    // TAB SWITCHING
    // =========================================

    switchTab(tab) {
        if (this.currentTab === tab) return;

        document.querySelectorAll('.overview-tab').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tab);
        });

        document.querySelectorAll('.overview-tab-content').forEach(content => {
            content.classList.toggle('active', content.id === `overview-tab-${tab}`);
        });

        this.currentTab = tab;

        if (tab === 'guide' && !this.guideData) this.loadGuide();
        else if (tab === 'thesis' && !this.thesisData) this.loadThesis();
    },

    // =========================================
    // GUIDE WIZARD
    // =========================================

    async loadGuide() {
        if (this.isLoading) return;

        // Always use 8 steps (our built-in guide)
        this.totalSteps = 8;
        if (this.els.totalStepsEl) this.els.totalStepsEl.textContent = this.totalSteps;

        const cached = this.getFromCache(this.CACHE.GUIDE_KEY, this.CACHE.GUIDE_TIME_KEY);
        if (cached) {
            this.guideData = cached;
            this.renderGuideStep(this.currentStep);
            return;
        }

        this.isLoading = true;

        try {
            const response = await fetch(this.API.guide);
            const result = await response.json();

            if (result.success && result.data) {
                this.guideData = result.data;
                this.saveToCache(this.CACHE.GUIDE_KEY, this.CACHE.GUIDE_TIME_KEY, result.data);
            }
            this.renderGuideStep(this.currentStep);
        } catch (error) {
            console.error('Error loading guide:', error);
            this.renderGuideStep(this.currentStep);
        } finally {
            this.isLoading = false;
        }
    },

    renderWizardDots() {
        if (!this.els.wizardDots) return;

        this.els.wizardDots.innerHTML = Array.from({ length: this.totalSteps }, (_, i) => {
            const step = i + 1;
            const classes = ['wizard-dot'];
            if (step === this.currentStep) classes.push('active');
            if (step < this.currentStep) classes.push('completed');
            return `<div class="${classes.join(' ')}" onclick="Overview.goToStep(${step})"></div>`;
        }).join('');
    },

    renderGuideStep(stepNum) {
        let step = this.guideData?.steps?.find(s => s.step_number === stepNum);
        if (!step) step = this.getDefaultStep(stepNum);

        if (this.els.wizardIcon) this.els.wizardIcon.innerHTML = step.icon || '&#128214;';
        if (this.els.wizardTitle) this.els.wizardTitle.textContent = step.title;
        if (this.els.wizardSubtitle) this.els.wizardSubtitle.textContent = step.subtitle || '';

        if (this.els.wizardBody) {
            this.els.wizardBody.innerHTML = `
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

    updateWizardUI() {
        if (this.els.currentStepEl) this.els.currentStepEl.textContent = this.currentStep;

        if (this.els.wizardProgress) {
            this.els.wizardProgress.style.width = `${(this.currentStep / this.totalSteps) * 100}%`;
        }

        if (this.els.wizardPrevBtn) this.els.wizardPrevBtn.disabled = this.currentStep <= 1;
        if (this.els.wizardNextBtn) {
            this.els.wizardNextBtn.disabled = this.currentStep >= this.totalSteps;
            this.els.wizardNextBtn.innerHTML = this.currentStep >= this.totalSteps ? 'Complete &#10003;' : 'Next &#8594;';
        }

        if (this.els.wizardStepsGrid) {
            this.els.wizardStepsGrid.querySelectorAll('.wizard-step-card').forEach(card => {
                const step = parseInt(card.dataset.step);
                card.classList.toggle('active', step === this.currentStep);
                card.classList.toggle('completed', step < this.currentStep);
                const numEl = card.querySelector('.wizard-step-number');
                if (numEl) numEl.innerHTML = step < this.currentStep ? '&#10003;' : step;
            });
        }

        this.renderWizardDots();
    },

    // Navigation methods
    nextStep() {
        if (this.currentStep < this.totalSteps) {
            this.currentStep++;
            this.renderGuideStep(this.currentStep);
            this.scrollToWizardContent();
        }
    },

    prevStep() {
        if (this.currentStep > 1) {
            this.currentStep--;
            this.renderGuideStep(this.currentStep);
            this.scrollToWizardContent();
        }
    },

    goToStep(stepNum) {
        if (stepNum >= 1 && stepNum <= this.totalSteps && stepNum !== this.currentStep) {
            this.currentStep = stepNum;
            this.renderGuideStep(this.currentStep);
            this.scrollToWizardContent();
        }
    },

    /**
     * Scroll to wizard content panel header
     */
    scrollToWizardContent() {
        // Use requestAnimationFrame to ensure DOM is updated before scrolling
        requestAnimationFrame(() => {
            const target = this.els.wizardContentPanel || document.querySelector('.wizard-content-panel');
            if (target) {
                this.scrollToElement(target, 70);
            }
        });
    },

    // =========================================
    // DEFAULT STEP CONTENT
    // =========================================

    getDefaultStep(stepNum) {
        const steps = {
            1: {
                icon: '&#128737;',
                title: 'What is SSH Guardian?',
                subtitle: 'An Open-Source Enhancement for Fail2ban',
                content_html: `
                    <p>SSH Guardian is an <strong>open-source security tool</strong> that enhances fail2ban with Machine Learning capabilities and third-party threat intelligence integrations.</p>

                    <h3>Why SSH Guardian?</h3>
                    <p>While fail2ban is excellent at reactive blocking, SSH Guardian adds:</p>
                    <ul>
                        <li><strong>Proactive Threat Detection</strong> - Block known bad IPs on first attempt using AbuseIPDB & VirusTotal</li>
                        <li><strong>ML-Based Anomaly Detection</strong> - Identify sophisticated attacks that bypass simple rules</li>
                        <li><strong>Centralized Dashboard</strong> - Monitor single or multiple servers from one interface</li>
                        <li><strong>Smart Escalation</strong> - Automatically escalate repeat offenders from fail2ban to permanent UFW blocks</li>
                    </ul>

                    <h3>Deployment Modes</h3>
                    <div class="deployment-modes">
                        <div class="mode-card">
                            <strong>&#128421; Single Server</strong>
                            <p>Dashboard + Agent on same machine. Perfect for standalone VPS or cloud instances.</p>
                        </div>
                        <div class="mode-card">
                            <strong>&#127760; Distributed</strong>
                            <p>Central dashboard coordinating multiple agents across your infrastructure.</p>
                        </div>
                    </div>

                    <h3>Supported Platforms</h3>
                    <ul>
                        <li><strong>Ubuntu 22.04+</strong> (Tested & Recommended)</li>
                        <li>Debian 11+ (Compatible)</li>
                        <li>Any systemd-based Linux with Python 3.8+</li>
                    </ul>
                `,
                tips_html: 'SSH Guardian works alongside fail2ban, not as a replacement. It adds intelligence to your existing security stack.'
            },
            2: {
                icon: '&#127959;',
                title: 'System Architecture',
                subtitle: 'How Components Work Together',
                content_html: `
                    <p>SSH Guardian uses a <strong>distributed agent-server architecture</strong> with a 10-stage event processing pipeline.</p>

                    <h3>Core Components</h3>
                    <table class="arch-table">
                        <tr><td><strong>Dashboard Server</strong></td><td>Central Flask API + Web UI (Port 8081)</td></tr>
                        <tr><td><strong>Remote Agents</strong></td><td>Python service on each monitored server</td></tr>
                        <tr><td><strong>Database</strong></td><td>MySQL 8.0+ or SQLite3 for storage</td></tr>
                        <tr><td><strong>Cache</strong></td><td>Redis for high-speed caching (optional)</td></tr>
                    </table>

                    <h3>Event Processing Pipeline</h3>
                    <ol>
                        <li><strong>Log Collection</strong> - Agent monitors /var/log/auth.log in real-time</li>
                        <li><strong>Event Parsing</strong> - Extract IP, username, timestamp, auth method</li>
                        <li><strong>GeoIP Enrichment</strong> - Add country, city, coordinates, ISP</li>
                        <li><strong>Threat Intel Lookup</strong> - Query AbuseIPDB, VirusTotal, Shodan</li>
                        <li><strong>ML Prediction</strong> - Generate risk score using trained model</li>
                        <li><strong>Rule Evaluation</strong> - Check against 10+ blocking rule types</li>
                        <li><strong>Block Decision</strong> - Determine if block is needed</li>
                        <li><strong>Command Dispatch</strong> - Queue UFW/fail2ban commands to agent</li>
                        <li><strong>Notification</strong> - Alert via Telegram/Email if configured</li>
                        <li><strong>Audit Logging</strong> - Record all actions for compliance</li>
                    </ol>

                    <h3>Agent-Server Communication</h3>
                    <ul>
                        <li><strong>Heartbeat</strong> - Every 60 seconds (CPU, memory, disk usage)</li>
                        <li><strong>Log Submission</strong> - Batch of 100 events per request</li>
                        <li><strong>Firewall Sync</strong> - Every 5 minutes (UFW rules sync)</li>
                        <li><strong>Command Polling</strong> - Every 30 seconds (pending blocks/unblocks)</li>
                    </ul>
                `,
                tips_html: 'The architecture supports horizontal scaling - add as many agents as needed without dashboard changes.'
            },
            3: {
                icon: '&#128640;',
                title: 'Dashboard Installation',
                subtitle: 'Set Up the Central Server',
                content_html: `
                    <p>The dashboard is your central control panel. Install it on a server that all agents can reach.</p>

                    <h3>Prerequisites</h3>
                    <ul>
                        <li>Ubuntu 22.04+ server</li>
                        <li>Python 3.10 or higher</li>
                        <li>2GB RAM minimum (4GB recommended)</li>
                        <li>Open port 8081 for dashboard access</li>
                    </ul>

                    <h3>Database Options</h3>
                    <p>During installation, you'll choose between:</p>
                    <table class="arch-table">
                        <tr>
                            <td><strong>SQLite3</strong></td>
                            <td>Zero configuration, perfect for single-server setups or testing</td>
                        </tr>
                        <tr>
                            <td><strong>MySQL 8.0+</strong></td>
                            <td>Recommended for production and multi-agent deployments</td>
                        </tr>
                    </table>

                    <h3>Installation Steps</h3>
                    <div class="code-block">
                        <code># Clone the repository</code><br>
                        <code>git clone https://github.com/yourusername/ssh-guardian.git</code><br>
                        <code>cd ssh-guardian</code><br><br>
                        <code># Run the installer</code><br>
                        <code>sudo ./install.sh</code>
                    </div>

                    <h3>Installer Prompts</h3>
                    <ol>
                        <li><strong>Database Type</strong> - Choose SQLite3 or MySQL</li>
                        <li><strong>MySQL Credentials</strong> - If MySQL selected, provide host/user/password</li>
                        <li><strong>Admin Account</strong> - Create your dashboard login</li>
                        <li><strong>API Keys</strong> - Optionally configure AbuseIPDB/VirusTotal keys</li>
                        <li><strong>Port</strong> - Default 8081 (can customize)</li>
                    </ol>

                    <p>After installation, access the dashboard at: <code>http://your-server-ip:8081</code></p>
                `,
                tips_html: 'For production, use MySQL with Redis caching. SQLite3 is great for testing or single-server deployments under 1000 events/day.'
            },
            4: {
                icon: '&#128421;',
                title: 'Agent Deployment',
                subtitle: 'Install Agents on Monitored Servers',
                content_html: `
                    <p>Deploy agents on each server you want to monitor. Agents are lightweight and run as a systemd service.</p>

                    <h3>Quick Installation</h3>
                    <div class="code-block">
                        <code># Download and run the agent installer</code><br>
                        <code>curl -sSL https://your-dashboard:8081/install-agent.sh | sudo bash</code>
                    </div>

                    <h3>Interactive Configuration</h3>
                    <p>The installer will prompt for:</p>
                    <table class="arch-table">
                        <tr><td><strong>Dashboard URL</strong></td><td>e.g., http://192.168.1.100:8081</td></tr>
                        <tr><td><strong>Agent ID</strong></td><td>Auto-generated: hostname-mac (customizable)</td></tr>
                        <tr><td><strong>Fail2ban Integration</strong></td><td>Yes/No - sync with existing fail2ban</td></tr>
                    </table>

                    <h3>What Gets Installed</h3>
                    <ul>
                        <li><code>/opt/ssh-guardian-agent/</code> - Agent scripts</li>
                        <li><code>/etc/ssh-guardian/agent.json</code> - Configuration file</li>
                        <li><code>/var/lib/ssh-guardian/</code> - State persistence</li>
                        <li><code>ssh-guardian-agent.service</code> - Systemd service</li>
                    </ul>

                    <h3>Agent Approval Workflow</h3>
                    <ol>
                        <li>Agent starts and sends registration request</li>
                        <li>Dashboard shows agent in <strong>"Pending Approval"</strong> state</li>
                        <li>Admin reviews and clicks <strong>"Approve"</strong></li>
                        <li>Agent receives API key and begins sending events</li>
                    </ol>

                    <h3>Verify Agent Status</h3>
                    <div class="code-block">
                        <code>sudo systemctl status ssh-guardian-agent</code><br>
                        <code>sudo journalctl -u ssh-guardian-agent -f</code>
                    </div>
                `,
                tips_html: 'Enable fail2ban integration if you have existing fail2ban rules. SSH Guardian will coordinate with fail2ban rather than conflict.'
            },
            5: {
                icon: '&#128200;',
                title: 'Real-Time Monitoring',
                subtitle: 'Track Authentication Events Live',
                content_html: `
                    <p>Once agents are deployed, the <strong>Live Events</strong> page shows all SSH activity across your infrastructure.</p>

                    <h3>Event Types</h3>
                    <ul>
                        <li><span class="event-badge failed">Failed</span> Invalid password or rejected public key</li>
                        <li><span class="event-badge success">Successful</span> Authenticated login session</li>
                        <li><span class="event-badge invalid">Invalid User</span> Username does not exist on system</li>
                        <li><span class="event-badge disconnect">Disconnect</span> Session ended (normal or forced)</li>
                    </ul>

                    <h3>Event Details Include</h3>
                    <table class="arch-table">
                        <tr><td><strong>Source IP</strong></td><td>Attacker's IP address</td></tr>
                        <tr><td><strong>GeoIP Data</strong></td><td>Country, city, ISP, VPN/Tor detection</td></tr>
                        <tr><td><strong>Risk Score</strong></td><td>0-100 ML-generated threat score</td></tr>
                        <tr><td><strong>AbuseIPDB</strong></td><td>Reputation score and abuse reports</td></tr>
                        <tr><td><strong>VirusTotal</strong></td><td>Malware detection results</td></tr>
                        <tr><td><strong>Agent</strong></td><td>Which server received the attempt</td></tr>
                    </table>

                    <h3>Filtering & Search</h3>
                    <ul>
                        <li>Filter by date range, event type, agent, country</li>
                        <li>Search by IP address or username</li>
                        <li>Sort by timestamp, risk score, or event count</li>
                        <li>Export filtered results to CSV</li>
                    </ul>

                    <h3>Quick Actions</h3>
                    <p>From any event, you can:</p>
                    <ul>
                        <li><strong>Block IP</strong> - Immediately add to UFW deny list</li>
                        <li><strong>Whitelist</strong> - Mark as trusted (never block)</li>
                        <li><strong>View History</strong> - See all events from this IP</li>
                        <li><strong>Generate Report</strong> - Export detailed threat analysis</li>
                    </ul>
                `,
                tips_html: 'The dashboard auto-refreshes every 30 seconds. High-risk events (score > 70) are highlighted in red.'
            },
            6: {
                icon: '&#128274;',
                title: 'Fail2ban & UFW Integration',
                subtitle: 'Hybrid Blocking Strategy',
                content_html: `
                    <p>SSH Guardian works <strong>alongside fail2ban</strong>, adding intelligence without replacing your existing setup.</p>

                    <h3>How They Work Together</h3>
                    <table class="arch-table">
                        <tr>
                            <td><strong>Fail2ban</strong></td>
                            <td>Reactive - blocks after X failed attempts in Y minutes</td>
                        </tr>
                        <tr>
                            <td><strong>SSH Guardian</strong></td>
                            <td>Proactive - blocks known bad IPs on first attempt</td>
                        </tr>
                        <tr>
                            <td><strong>UFW</strong></td>
                            <td>Permanent blocks for high-threat IPs and repeat offenders</td>
                        </tr>
                    </table>

                    <h3>Smart Escalation</h3>
                    <p>Based on threat score, SSH Guardian escalates blocking:</p>
                    <ol>
                        <li><strong>Score 0-30:</strong> Standard fail2ban (1 hour ban)</li>
                        <li><strong>Score 30-60:</strong> Extended fail2ban (6 hours)</li>
                        <li><strong>Score 60-80:</strong> Extended fail2ban (24 hours)</li>
                        <li><strong>Score 80+:</strong> Permanent UFW block</li>
                        <li><strong>3rd offense:</strong> Auto-escalate to UFW regardless of score</li>
                    </ol>

                    <h3>UFW Management Features</h3>
                    <ul>
                        <li>View all UFW rules synced from agents</li>
                        <li>Add/remove rules from dashboard (pushed to agents)</li>
                        <li>Protected ports: 22, 80, 443, 8081 (never auto-blocked)</li>
                        <li>Rule templates for common configurations</li>
                    </ul>

                    <h3>Fail2ban Sync</h3>
                    <p>When fail2ban bans an IP:</p>
                    <ol>
                        <li>Agent detects ban via fail2ban database</li>
                        <li>Reports to dashboard with jail name and ban time</li>
                        <li>Dashboard runs threat analysis on the IP</li>
                        <li>If high-risk, escalates to UFW permanent block</li>
                    </ol>
                `,
                tips_html: 'The Firewall page shows both fail2ban temporary bans and UFW permanent blocks. You can unblock from either directly.'
            },
            7: {
                icon: '&#129302;',
                title: 'ML & Threat Intelligence',
                subtitle: 'Advanced Detection Capabilities',
                content_html: `
                    <p>SSH Guardian uses <strong>Machine Learning</strong> combined with <strong>3rd-party threat intelligence</strong> for comprehensive threat assessment.</p>

                    <h3>Machine Learning Models</h3>
                    <p>Supports 4 algorithms (configurable):</p>
                    <table class="arch-table">
                        <tr><td><strong>Random Forest</strong></td><td>Default - balanced performance (300 trees)</td></tr>
                        <tr><td><strong>Isolation Forest</strong></td><td>Unsupervised anomaly detection</td></tr>
                        <tr><td><strong>XGBoost</strong></td><td>High-performance gradient boosting</td></tr>
                        <tr><td><strong>Gradient Boosting</strong></td><td>Sequential error correction</td></tr>
                    </table>

                    <h3>42 Features Analyzed</h3>
                    <ul>
                        <li><strong>Temporal:</strong> Hour, day of week, business hours, night time</li>
                        <li><strong>Behavioral:</strong> Failed attempts (24h), success rate, attack velocity</li>
                        <li><strong>Geographic:</strong> Country, coordinates, VPN/Tor/datacenter flags</li>
                        <li><strong>Username:</strong> Is root, is system account, entropy, frequency</li>
                        <li><strong>Network:</strong> Private IP, bogon, reserved ranges</li>
                        <li><strong>Reputation:</strong> AbuseIPDB score, VirusTotal detections</li>
                    </ul>

                    <h3>Threat Intelligence APIs</h3>
                    <table class="arch-table">
                        <tr><td><strong>AbuseIPDB</strong></td><td>IP reputation (0-100), abuse reports, categories</td></tr>
                        <tr><td><strong>VirusTotal</strong></td><td>Multi-vendor malware detection</td></tr>
                        <tr><td><strong>Shodan</strong></td><td>Open ports, vulnerabilities (optional)</td></tr>
                        <tr><td><strong>GeoIP</strong></td><td>Location, ISP, VPN/proxy detection</td></tr>
                    </table>

                    <h3>Model Training</h3>
                    <p>From the ML page, you can:</p>
                    <ul>
                        <li>Trigger model retraining with recent data</li>
                        <li>View training metrics (accuracy, F1, precision, recall)</li>
                        <li>Compare algorithm performance</li>
                        <li>Adjust anomaly sensitivity threshold</li>
                    </ul>
                `,
                tips_html: 'API results are cached for 7 days to reduce costs. Configure your API keys in Settings > Integrations.'
            },
            8: {
                icon: '&#9889;',
                title: 'Auto-Blocking Rules',
                subtitle: 'Configure Automated Threat Response',
                content_html: `
                    <p>SSH Guardian supports <strong>10+ rule types</strong> for automated blocking. Configure them in <strong>Settings > Blocking Rules</strong>.</p>

                    <h3>Available Rule Types</h3>
                    <table class="arch-table">
                        <tr><td><strong>Brute Force</strong></td><td>X failed attempts in Y minutes</td></tr>
                        <tr><td><strong>ML Threshold</strong></td><td>Block when risk_score exceeds value</td></tr>
                        <tr><td><strong>AbuseIPDB Score</strong></td><td>Block IPs with high abuse confidence</td></tr>
                        <tr><td><strong>Credential Stuffing</strong></td><td>Multiple usernames from same IP</td></tr>
                        <tr><td><strong>Velocity</strong></td><td>High-frequency attacks (>10/minute)</td></tr>
                        <tr><td><strong>Impossible Travel</strong></td><td>Same user from distant locations</td></tr>
                        <tr><td><strong>Tor/VPN Detection</strong></td><td>Block anonymous access sources</td></tr>
                        <tr><td><strong>Geographic</strong></td><td>Block specific countries</td></tr>
                        <tr><td><strong>Off-Hours</strong></td><td>Block logins outside business hours</td></tr>
                        <tr><td><strong>Threat Combo</strong></td><td>Multiple indicators combined</td></tr>
                    </table>

                    <h3>Rule Configuration</h3>
                    <p>Each rule has:</p>
                    <ul>
                        <li><strong>Enabled/Disabled</strong> - Toggle without deleting</li>
                        <li><strong>Priority</strong> - Order of evaluation (1-100)</li>
                        <li><strong>Block Duration</strong> - 15min, 1hr, 24hr, permanent</li>
                        <li><strong>Conditions</strong> - Thresholds and parameters</li>
                        <li><strong>Scope</strong> - All agents or specific agents</li>
                    </ul>

                    <h3>Example Configurations</h3>
                    <div class="code-block" style="font-size: 12px;">
                        <code><strong># Brute Force Rule</strong></code><br>
                        <code>Type: brute_force</code><br>
                        <code>Threshold: 5 failures in 10 minutes</code><br>
                        <code>Block Duration: 1 hour</code><br><br>
                        <code><strong># High-Risk IP Rule</strong></code><br>
                        <code>Type: ml_threshold</code><br>
                        <code>Threshold: risk_score > 80</code><br>
                        <code>Block Duration: Permanent</code>
                    </div>

                    <h3>Notifications</h3>
                    <p>Get alerted when rules trigger:</p>
                    <ul>
                        <li><strong>Telegram</strong> - Instant bot notifications</li>
                        <li><strong>Email</strong> - Detailed threat reports</li>
                        <li><strong>Webhook</strong> - Custom integrations (Slack, Discord, etc.)</li>
                    </ul>
                `,
                tips_html: 'Start with conservative thresholds and tighten over time. Monitor the Audit Log to see which rules trigger most often.'
            }
        };
        return steps[stepNum] || steps[1];
    },

    // =========================================
    // THESIS FUNCTIONS
    // =========================================

    async loadThesis() {
        if (this.isLoading) return;

        const cached = this.getFromCache(this.CACHE.THESIS_KEY, this.CACHE.THESIS_TIME_KEY);
        if (cached?.sections?.length >= 10) {
            this.thesisData = cached;
            this.renderThesis();
            return;
        }

        if (cached) {
            localStorage.removeItem(this.CACHE.THESIS_KEY);
            localStorage.removeItem(this.CACHE.THESIS_TIME_KEY);
        }

        this.isLoading = true;

        try {
            const response = await fetch(this.API.thesis);
            const result = await response.json();

            if (result.success && result.data) {
                this.thesisData = result.data;
                this.saveToCache(this.CACHE.THESIS_KEY, this.CACHE.THESIS_TIME_KEY, result.data);
                this.renderThesis();
            } else {
                OverviewThesis.renderDefaultThesis();
            }
        } catch (error) {
            console.error('Error loading thesis:', error);
            OverviewThesis.renderDefaultThesis();
        } finally {
            this.isLoading = false;
        }
    },

    renderThesis() {
        OverviewThesis.renderThesisHeader();
        OverviewThesis.renderThesisTOC();
        OverviewThesis.renderThesisSections();
        OverviewThesis.initScrollSpy();
    },

    scrollToSection(sectionKey) {
        OverviewThesis.scrollToSection(sectionKey);
        this.closeMobileTOC();
    },

    // =========================================
    // MOBILE TOC
    // =========================================

    toggleMobileTOC() {
        const toc = this.els.thesisToc || document.getElementById('overview-thesis-toc');
        const overlay = this.els.tocOverlay || document.querySelector('.thesis-toc-overlay');
        if (!toc) return;

        if (toc.classList.contains('mobile-open')) {
            this.closeMobileTOC();
        } else {
            toc.classList.add('mobile-open');
            overlay?.classList.add('visible');
            document.body.style.overflow = 'hidden';
        }
    },

    closeMobileTOC() {
        const toc = this.els.thesisToc || document.getElementById('overview-thesis-toc');
        const overlay = this.els.tocOverlay || document.querySelector('.thesis-toc-overlay');
        toc?.classList.remove('mobile-open');
        overlay?.classList.remove('visible');
        document.body.style.overflow = '';
    },

    // =========================================
    // DOCX EXPORT
    // =========================================

    exportThesisDocx() {
        const btn = document.querySelector('.btn-export-docx');
        if (!btn) return;

        const originalHTML = btn.innerHTML;
        btn.classList.add('loading');
        btn.innerHTML = '<span class="export-icon">&#8987;</span><span class="export-text">Exporting...</span>';

        fetch('/api/dashboard/content/thesis/export/docx')
            .then(response => {
                if (!response.ok) throw new Error('Export failed');
                return response.blob();
            })
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'SSH_Guardian_Thesis.docx';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();

                btn.innerHTML = '<span class="export-icon">&#10004;</span><span class="export-text">Downloaded!</span>';
                setTimeout(() => {
                    btn.innerHTML = originalHTML;
                    btn.classList.remove('loading');
                }, 2000);
            })
            .catch(error => {
                console.error('Export error:', error);
                btn.innerHTML = '<span class="export-icon">&#10060;</span><span class="export-text">Error</span>';
                setTimeout(() => {
                    btn.innerHTML = originalHTML;
                    btn.classList.remove('loading');
                }, 3000);
            });
    }
};

// Navigation helper for action cards
function navigateTo(page) {
    window.location.hash = page;
}

// Initialize Overview when page loads
function loadOverviewPage() {
    if (document.getElementById('page-overview')) {
        Overview.init();
    }
}

// Listen for hash changes
window.addEventListener('hashchange', () => {
    if (window.location.hash === '#overview' && document.getElementById('page-overview')) {
        Overview.init();
    }
});

// Export for global access
window.Overview = Overview;
window.loadOverviewPage = loadOverviewPage;
