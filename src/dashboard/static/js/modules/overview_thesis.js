/**
 * SSH Guardian v3.0 - Overview Thesis Module
 * Thesis rendering, scroll spy, section navigation
 * Extracted from overview.js for better maintainability
 */

const OverviewThesis = {
    // Reference to main Overview module
    getOverview() {
        return window.Overview;
    },

    /**
     * Render thesis header
     */
    renderThesisHeader() {
        const meta = this.getOverview().thesisData?.metadata || {};

        const titleEl = document.getElementById('overview-thesis-title-text');
        if (titleEl) {
            titleEl.textContent = meta.title || 'Research Thesis';
        }

        const metaGrid = document.getElementById('overview-thesis-meta-grid');
        if (metaGrid) {
            metaGrid.innerHTML = `
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Student</div>
                    <div class="thesis-meta-value">${meta.student_name || 'Md Sohel Rana'} (${meta.student_id || 'TP086217'})</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Institution</div>
                    <div class="thesis-meta-value">${meta.institution || 'Asia Pacific University of Technology & Innovation'}</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Supervisor</div>
                    <div class="thesis-meta-value">${meta.supervisor || 'N/A'}</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Module</div>
                    <div class="thesis-meta-value">${meta.module_code || 'CT095-6-M RMCE'} ${meta.module_name || ''}</div>
                </div>
            `;
        }
    },

    /**
     * Render table of contents
     */
    renderThesisTOC() {
        const container = document.getElementById('overview-toc-list');
        if (!container) return;

        const toc = this.getOverview().thesisData?.toc || [];

        if (toc.length === 0) {
            container.innerHTML = '<li class="toc-item"><span class="toc-link">No content available</span></li>';
            return;
        }

        container.innerHTML = toc.map(item => `
            <li class="toc-item level-${item.toc_level || 1}">
                <a class="toc-link" href="#overview-section-${item.section_key}" onclick="Overview.scrollToSection('${item.section_key}'); return false;">
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
        const container = document.getElementById('overview-thesis-sections');
        if (!container) return;

        const sections = this.getOverview().thesisData?.sections || [];

        if (sections.length === 0) {
            this.renderDefaultThesis();
            return;
        }

        container.innerHTML = sections.map(section => `
            <section class="thesis-section" id="overview-section-${section.section_key}">
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
        const titleEl = document.getElementById('overview-thesis-title-text');
        if (titleEl) {
            titleEl.textContent = 'Design and Evaluation of a Lightweight SSH Access Behavior Profiling and Anomaly Alerting Agent';
        }

        const metaGrid = document.getElementById('overview-thesis-meta-grid');
        if (metaGrid) {
            metaGrid.innerHTML = `
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Student</div>
                    <div class="thesis-meta-value">Md Sohel Rana (TP086217)</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Institution</div>
                    <div class="thesis-meta-value">Asia Pacific University of Technology & Innovation</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Module</div>
                    <div class="thesis-meta-value">CT095-6-M RMCE</div>
                </div>
                <div class="thesis-meta-item">
                    <div class="thesis-meta-label">Year</div>
                    <div class="thesis-meta-value">2025</div>
                </div>
            `;
        }

        const tocContainer = document.getElementById('overview-toc-list');
        if (tocContainer) {
            tocContainer.innerHTML = `
                <li class="toc-item"><a class="toc-link active" href="#overview-section-abstract" onclick="Overview.scrollToSection('abstract'); return false;"><span class="toc-chapter-num">-</span> Abstract</a></li>
                <li class="toc-item"><a class="toc-link" href="#overview-section-intro" onclick="Overview.scrollToSection('intro'); return false;"><span class="toc-chapter-num">1</span> Introduction</a></li>
                <li class="toc-item"><a class="toc-link" href="#overview-section-methodology" onclick="Overview.scrollToSection('methodology'); return false;"><span class="toc-chapter-num">3</span> Methodology</a></li>
            `;
        }

        const sectionsContainer = document.getElementById('overview-thesis-sections');
        if (sectionsContainer) {
            sectionsContainer.innerHTML = `
                <section class="thesis-section" id="overview-section-abstract">
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
                <section class="thesis-section" id="overview-section-intro">
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
                <section class="thesis-section" id="overview-section-methodology">
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
        const element = document.getElementById(`overview-section-${sectionKey}`);
        if (element) {
            element.scrollIntoView({ behavior: 'smooth', block: 'start' });

            // Update active TOC link
            document.querySelectorAll('#overview-toc-list .toc-link').forEach(link => {
                link.classList.toggle('active', link.href?.includes(sectionKey) || link.getAttribute('href')?.includes(sectionKey));
            });
        }
    },

    /**
     * Initialize scroll spy for TOC
     */
    initScrollSpy() {
        const sections = document.querySelectorAll('#overview-thesis-sections .thesis-section');
        const tocLinks = document.querySelectorAll('#overview-toc-list .toc-link');

        if (sections.length === 0) return;

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const sectionKey = entry.target.id.replace('overview-section-', '');
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

// Export for global access
window.OverviewThesis = OverviewThesis;
