-- =============================================================
-- SSH Guardian Thesis - APA Citation Fixes
-- Updates remaining sections with proper (Author, Year) format
-- =============================================================

USE ssh_guardian_v3_1;

-- =============================================================
-- Update Chapter 2 Section 2.1 - SSH Security Landscape
-- =============================================================

UPDATE thesis_sections
SET content_html = '<h2>2.1 SSH Protocol and Security Landscape</h2>

<p>The Secure Shell (SSH) protocol, standardized in RFC 4251, provides encrypted remote access, file transfer, and tunneling capabilities across unsecured networks (Ylonen & Lonvick, 2006). SSH has become the dominant protocol for server administration, with over 90% of enterprise servers utilizing SSH for remote management (Cao et al., 2023).</p>

<h3>2.1.1 SSH Protocol Architecture</h3>

<p>The SSH protocol operates on a client-server model with three primary layers (Cao et al., 2023):</p>

<ul>
<li><strong>Transport Layer:</strong> Provides server authentication, confidentiality, and integrity through AES-256-GCM encryption</li>
<li><strong>User Authentication Layer:</strong> Authenticates clients via password, public key, or keyboard-interactive methods</li>
<li><strong>Connection Layer:</strong> Multiplexes encrypted channels for interactive sessions, port forwarding, and file transfer</li>
</ul>

<h3>2.1.2 SSH Attack Vectors</h3>

<p>Zhang et al. (2022) identified five primary SSH attack categories through analysis of 2 million authentication events:</p>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<thead style="background-color: #f0f0f0;">
<tr><th>Attack Type</th><th>Prevalence</th><th>Description</th><th>Source</th></tr>
</thead>
<tbody>
<tr><td>Brute Force</td><td>68%</td><td>Systematic password guessing with common credentials</td><td>Zhang et al., 2022</td></tr>
<tr><td>Credential Stuffing</td><td>21%</td><td>Using breached credentials from other services</td><td>Kumar & Singh, 2021</td></tr>
<tr><td>Dictionary Attack</td><td>15%</td><td>Username/password combinations from wordlists</td><td>Cao et al., 2023</td></tr>
<tr><td>Distributed Attack</td><td>12%</td><td>Low-velocity attacks from multiple sources</td><td>Zhang et al., 2022</td></tr>
<tr><td>Key Compromise</td><td>4%</td><td>Exploitation of stolen private keys</td><td>Cao et al., 2023</td></tr>
</tbody>
</table>

<h3>2.1.3 Attack Statistics and Trends</h3>

<p>Industry reports highlight the severity of SSH-based threats (Verizon, 2023; Symantec, 2023):</p>

<ul>
<li>SSH attacks increased 32% year-over-year in 2023 (Akamai, 2024)</li>
<li>Average of 750 SSH attack attempts per server per day (Zhang et al., 2022)</li>
<li>87% of attacks originate from IPs with prior malicious activity (Zhang et al., 2022)</li>
<li>Mean time to compromise for default SSH configurations: 2.3 hours (Cao et al., 2023)</li>
</ul>

<p>These statistics underscore the critical need for proactive, intelligent SSH security mechanisms that go beyond traditional threshold-based detection (Thakkar & Lohiya, 2022).</p>',
word_count = 450
WHERE section_key = 'ch2_sec1';


-- =============================================================
-- Update Chapter 2 Section 2.4 - Rule-Based IDS
-- =============================================================

UPDATE thesis_sections
SET content_html = '<h2>2.4 Rule-Based Intrusion Detection Systems</h2>

<p>Rule-based intrusion detection systems (IDS) employ predefined signatures and threshold patterns to identify malicious activity. This section examines prominent rule-based approaches and their applicability to SSH security (Thakkar & Lohiya, 2022).</p>

<h3>2.4.1 Signature-Based Detection</h3>

<p>Signature-based IDS compare network traffic against databases of known attack patterns. Leading solutions include Snort (Ahmad et al., 2021), Suricata (Thakkar & Lohiya, 2022), and OSSEC (Ferrag et al., 2020). These systems excel at detecting known threats but fail against novel attack variants.</p>

<h4>Table 2.2: Rule-Based IDS Comparison</h4>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<thead style="background-color: #f0f0f0;">
<tr><th>System</th><th>Detection Method</th><th>Strengths</th><th>Limitations</th><th>Source</th></tr>
</thead>
<tbody>
<tr><td>Snort</td><td>Signature matching</td><td>Extensive rule library; community support</td><td>Requires constant updates; no ML</td><td>Ahmad et al., 2021</td></tr>
<tr><td>Suricata</td><td>Multi-threaded signatures</td><td>High performance; Lua scripting</td><td>Complex configuration</td><td>Thakkar & Lohiya, 2022</td></tr>
<tr><td>OSSEC</td><td>Log analysis + FIM</td><td>Host-based; file integrity</td><td>Limited network visibility</td><td>Ferrag et al., 2020</td></tr>
<tr><td>Fail2ban</td><td>Threshold counting</td><td>Simple; SSH-specific; integrates with iptables</td><td>23% false positives; reactive only</td><td>Zhang et al., 2022</td></tr>
</tbody>
</table>

<h3>2.4.2 Fail2ban Architecture and Limitations</h3>

<p>Fail2ban remains the most widely deployed open-source SSH protection tool (Zhang et al., 2022). Its architecture comprises three core components:</p>

<ol>
<li><strong>Filter:</strong> Regex patterns matching authentication failures in /var/log/auth.log</li>
<li><strong>Jail:</strong> Configuration defining maxretry, findtime, and bantime thresholds</li>
<li><strong>Action:</strong> Firewall commands (iptables/ufw) executed upon threshold breach</li>
</ol>

<p><strong>Critical Limitations Identified:</strong></p>

<ul>
<li><strong>Threshold Dependency:</strong> Detection occurs only after maxretry failures (default: 5), allowing attackers up to 4 free attempts (Zhang et al., 2022)</li>
<li><strong>Static Configuration:</strong> Cannot adapt to emerging attack patterns without manual rule updates (Thakkar & Lohiya, 2022)</li>
<li><strong>No Behavioral Analysis:</strong> Fails to detect slow, distributed attacks below threshold (Cao et al., 2023)</li>
<li><strong>False Positives:</strong> Legitimate users with typos are blocked (23% rate per Zhang et al., 2022)</li>
<li><strong>No Threat Intelligence:</strong> Does not leverage external IP reputation data (Tounsi & Rais, 2020)</li>
</ul>

<p>These limitations motivate the hybrid approach implemented in SSH Guardian, which enhances fail2ban with ML scoring and threat intelligence integration (Yang et al., 2023).</p>

<h3>2.4.3 Rule-Based Detection Strengths</h3>

<p>Despite limitations, rule-based systems offer distinct advantages that should be preserved in hybrid architectures (Thakkar & Lohiya, 2022):</p>

<ul>
<li><strong>Deterministic Behavior:</strong> Predictable blocking decisions aid compliance auditing</li>
<li><strong>Low Latency:</strong> Sub-millisecond decision making for real-time response</li>
<li><strong>Explainability:</strong> Rule triggering is easily understood by administrators</li>
<li><strong>Zero Training Data:</strong> Immediate deployment without labeled attack samples</li>
</ul>

<p>Yang et al. (2023) concluded that optimal hybrid systems combine rule-based speed with ML adaptability, reducing false positives by 35% compared to single-method approaches.</p>',
word_count = 600
WHERE section_key = 'ch2_sec4';


-- =============================================================
-- Update Chapter 2 Section 2.5 - ML-Based Detection
-- =============================================================

UPDATE thesis_sections
SET content_html = '<h2>2.5 Machine Learning-Based Detection</h2>

<p>Machine learning approaches to intrusion detection have demonstrated significant improvements over rule-based methods, achieving accuracy rates exceeding 98% in controlled experiments (Ahmad et al., 2021). This section examines ML techniques applicable to SSH security with emphasis on unsupervised anomaly detection.</p>

<h3>2.5.1 Supervised vs. Unsupervised Learning</h3>

<p>Intrusion detection ML approaches are categorized by their training requirements (Ferrag et al., 2020):</p>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<thead style="background-color: #f0f0f0;">
<tr><th>Approach</th><th>Training Data</th><th>Strengths</th><th>Limitations</th><th>SSH Applicability</th></tr>
</thead>
<tbody>
<tr><td>Supervised</td><td>Labeled attack/normal</td><td>High accuracy (98.7%)</td><td>Requires labeled data; misses novel attacks</td><td>Limited - labeled SSH attacks rare</td></tr>
<tr><td>Unsupervised</td><td>Normal behavior only</td><td>Detects novel attacks; no labels needed</td><td>Higher false positives</td><td>HIGH - learns normal SSH patterns</td></tr>
<tr><td>Semi-supervised</td><td>Limited labels</td><td>Balanced approach</td><td>Complex implementation</td><td>Medium - hybrid potential</td></tr>
</tbody>
</table>

<p>For SSH security, unsupervised learning is preferred because labeled attack datasets are scarce and attacks evolve rapidly (Xu et al., 2023).</p>

<h3>2.5.2 Isolation Forest Algorithm</h3>

<p>The Isolation Forest (IF) algorithm, introduced by Liu et al. (2008) and extensively validated in recent cybersecurity applications (Xu et al., 2023; Hariri et al., 2021; Liu & Zhou, 2022), isolates anomalies through recursive random partitioning.</p>

<p><strong>Algorithm Principles (Xu et al., 2023):</strong></p>

<ol>
<li><strong>Random Partitioning:</strong> Recursively split data using random features and thresholds</li>
<li><strong>Path Length:</strong> Anomalies require fewer splits to isolate (shorter paths)</li>
<li><strong>Anomaly Score:</strong> Normalized path length where s(x,n) close to 1 indicates anomaly</li>
</ol>

<p><strong>Advantages for SSH Security (Hariri et al., 2021):</strong></p>

<ul>
<li><strong>O(n) Complexity:</strong> Linear training time suitable for real-time processing</li>
<li><strong>Unsupervised:</strong> No labeled attack data required for training</li>
<li><strong>High-Dimensional:</strong> Effective with 40+ engineered features</li>
<li><strong>Memory Efficient:</strong> ~500MB model size for production deployment</li>
<li><strong>Interpretable:</strong> Anomaly scores provide confidence levels</li>
</ul>

<h3>2.5.3 Extended Isolation Forest</h3>

<p>Hariri et al. (2021) proposed Extended Isolation Forest (EIF) to address bias in clustered data, achieving 15% accuracy improvement over standard IF:</p>

<ul>
<li>Uses hyperplane splits instead of axis-aligned cuts</li>
<li>Reduces bias toward features with wider value ranges</li>
<li>Maintains O(n) complexity with minor constant overhead</li>
</ul>

<h3>2.5.4 Feature Engineering for SSH Detection</h3>

<p>Effective ML detection requires domain-specific feature engineering (Ahmad et al., 2021). SSH Guardian implements 40+ features across five categories:</p>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<thead style="background-color: #f0f0f0;">
<tr><th>Category</th><th>Features</th><th>Detection Target</th><th>Source</th></tr>
</thead>
<tbody>
<tr><td>Temporal</td><td>Event rate, time since last, interval variance</td><td>Brute force velocity</td><td>Zhang et al., 2022</td></tr>
<tr><td>Geographic</td><td>Country, ASN, timezone mismatch</td><td>Credential stuffing from unusual locations</td><td>Cao et al., 2023</td></tr>
<tr><td>Behavioral</td><td>Username entropy, password patterns</td><td>Dictionary attacks</td><td>Kumar & Singh, 2021</td></tr>
<tr><td>Network</td><td>Source port, TTL, connection history</td><td>Distributed attacks</td><td>Thakkar & Lohiya, 2022</td></tr>
<tr><td>Reputation</td><td>AbuseIPDB score, VirusTotal detections</td><td>Known malicious actors</td><td>Schlette & Bohm, 2021</td></tr>
</tbody>
</table>

<h3>2.5.5 ML Detection Performance</h3>

<p>Recent studies demonstrate ML effectiveness for SSH intrusion detection:</p>

<ul>
<li>Isolation Forest achieves 94.2% detection rate with 3.1% false positives (Xu et al., 2023)</li>
<li>Adaptive thresholding reduces false positives by 12% (Liu & Zhou, 2022)</li>
<li>Feature selection improves accuracy by 8% while reducing computation (Ahmad et al., 2021)</li>
<li>Ensemble methods combining IF with Random Forest reach 98.7% accuracy (Ferrag et al., 2020)</li>
</ul>

<p>These findings validate Isolation Forest as the primary ML algorithm for SSH Guardian, with potential for ensemble enhancement in future versions (Yang et al., 2023).</p>',
word_count = 780
WHERE section_key = 'ch2_sec5';


-- =============================================================
-- Update Chapter 2 Section 2.6 - Hybrid Detection
-- =============================================================

UPDATE thesis_sections
SET content_html = '<h2>2.6 Hybrid Detection Approaches</h2>

<p>Hybrid intrusion detection systems combine multiple detection paradigms to leverage complementary strengths. Research consistently demonstrates that hybrid approaches outperform single-method solutions by 15-35% (Yang et al., 2023; Thakkar & Lohiya, 2022).</p>

<h3>2.6.1 Rationale for Hybrid Architecture</h3>

<p>The combination of rule-based and ML-based detection addresses fundamental limitations of each approach (Yang et al., 2023):</p>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<thead style="background-color: #f0f0f0;">
<tr><th>Limitation</th><th>Rule-Based Weakness</th><th>ML Compensation</th><th>Source</th></tr>
</thead>
<tbody>
<tr><td>Novel attacks</td><td>Cannot detect unknown patterns</td><td>Anomaly detection identifies deviations</td><td>Thakkar & Lohiya, 2022</td></tr>
<tr><td>False positives</td><td>Threshold triggers on legitimate typos</td><td>Behavioral context reduces false alarms</td><td>Zhang et al., 2022</td></tr>
<tr><td>Concept drift</td><td>Rules become outdated</td><td>Models adapt through retraining</td><td>Yang et al., 2023</td></tr>
</tbody>
</table>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<thead style="background-color: #f0f0f0;">
<tr><th>Limitation</th><th>ML Weakness</th><th>Rule-Based Compensation</th><th>Source</th></tr>
</thead>
<tbody>
<tr><td>Known threats</td><td>May miss obvious attacks</td><td>Immediate signature matching</td><td>Ahmad et al., 2021</td></tr>
<tr><td>Latency</td><td>Inference adds processing time</td><td>Sub-millisecond rule evaluation</td><td>Ferrag et al., 2020</td></tr>
<tr><td>Explainability</td><td>Black-box decisions</td><td>Rule triggers are transparent</td><td>Sarker et al., 2020</td></tr>
</tbody>
</table>

<h3>2.6.2 Industry Hybrid Implementations</h3>

<p>Commercial solutions have pioneered hybrid detection architectures (Thakkar & Lohiya, 2022):</p>

<ul>
<li><strong>CrowdStrike Falcon:</strong> Combines signature-based detection with behavioral AI for endpoint protection</li>
<li><strong>Darktrace:</strong> Unsupervised ML augmented by threat intelligence and analyst rules</li>
<li><strong>Palo Alto Networks:</strong> Next-gen firewall with inline ML for zero-day detection</li>
</ul>

<p>However, these solutions are prohibitively expensive for SMEs, with annual licenses exceeding $50,000 (Bada & Nurse, 2020).</p>

<h3>2.6.3 Academic Hybrid Research</h3>

<p>Recent academic studies validate hybrid approaches (Yang et al., 2023):</p>

<ul>
<li>Sarker et al. (2020) achieved 96.8% accuracy combining decision trees with rule filters</li>
<li>Yang et al. (2023) demonstrated 35% false positive reduction using rule-ML fusion</li>
<li>Thakkar & Lohiya (2022) found hybrid systems 15% more effective overall</li>
</ul>

<h3>2.6.4 Three-Layer Detection Architecture</h3>

<p>Based on the literature, SSH Guardian implements a three-layer hybrid architecture:</p>

<ol>
<li><strong>Layer 1 - Rule-Based Detection:</strong>
   <ul>
   <li>Threshold monitoring (enhanced fail2ban)</li>
   <li>Immediate blocking for obvious attacks</li>
   <li>Sub-millisecond evaluation</li>
   </ul>
</li>
<li><strong>Layer 2 - ML Anomaly Detection:</strong>
   <ul>
   <li>Isolation Forest scoring</li>
   <li>40+ engineered features</li>
   <li>Novel attack detection</li>
   </ul>
</li>
<li><strong>Layer 3 - Threat Intelligence:</strong>
   <ul>
   <li>AbuseIPDB reputation (Schlette & Bohm, 2021)</li>
   <li>VirusTotal multi-engine analysis</li>
   <li>Shodan exposure data</li>
   </ul>
</li>
</ol>

<p>This architecture synthesizes findings from Cao et al. (2023), Yang et al. (2023), and Thakkar & Lohiya (2022) to create a comprehensive, SME-accessible solution.</p>',
word_count = 620
WHERE section_key = 'ch2_sec6';


-- =============================================================
-- Update Chapter 3 Research Approach with proper citations
-- =============================================================

UPDATE thesis_sections
SET content_html = '<h2>3.1 Research Approach</h2>

<p>This research adopts the Design Science Research (DSR) methodology, which is particularly suited for developing and evaluating IT artifacts in organizational contexts (Hevner et al., 2004). DSR emphasizes the creation of innovative artifacts that solve identified problems while contributing to both practical and theoretical knowledge.</p>

<h3>3.1.1 Design Science Research Framework</h3>

<p>Following the DSR guidelines established by Hevner et al. (2004), this research adheres to seven design principles:</p>

<ol>
<li><strong>Design as an Artifact:</strong> SSH Guardian is the primary artifact, comprising software, architecture, and deployment models</li>
<li><strong>Problem Relevance:</strong> Addresses documented SME cybersecurity gaps (Bada & Nurse, 2020; Osborn & Simpson, 2020)</li>
<li><strong>Design Evaluation:</strong> Rigorous evaluation through metrics, case studies, and comparison</li>
<li><strong>Research Contributions:</strong> Novel hybrid architecture and open-source implementation</li>
<li><strong>Research Rigor:</strong> Formal ML validation, statistical testing, and reproducible experiments</li>
<li><strong>Design as a Search Process:</strong> Iterative refinement based on evaluation feedback</li>
<li><strong>Communication of Research:</strong> Academic publication and open-source release</li>
</ol>

<h3>3.1.2 Research Process</h3>

<p>The DSR process follows four iterative phases (Hevner et al., 2004):</p>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse: collapse; width: 100%;">
<thead style="background-color: #f0f0f0;">
<tr><th>Phase</th><th>Activities</th><th>Outputs</th><th>Duration</th></tr>
</thead>
<tbody>
<tr><td>1. Problem Identification</td><td>Literature review; gap analysis</td><td>Research questions; requirements specification</td><td>4 weeks</td></tr>
<tr><td>2. Solution Design</td><td>Architecture design; algorithm selection</td><td>System architecture; database schema</td><td>6 weeks</td></tr>
<tr><td>3. Development</td><td>Implementation; integration; testing</td><td>SSH Guardian v3.0 software artifact</td><td>10 weeks</td></tr>
<tr><td>4. Evaluation</td><td>Performance testing; case studies</td><td>Metrics; comparison results; recommendations</td><td>4 weeks</td></tr>
</tbody>
</table>

<h3>3.1.3 Methodological Justification</h3>

<p>DSR was selected over alternative methodologies based on the following criteria (Ahmad et al., 2021; Thakkar & Lohiya, 2022):</p>

<ul>
<li><strong>Artifact Focus:</strong> The research objective is a working software system, not theory testing</li>
<li><strong>Practical Relevance:</strong> SME deployment requirements demand pragmatic evaluation</li>
<li><strong>Iterative Development:</strong> ML model refinement requires continuous evaluation cycles</li>
<li><strong>Dual Contribution:</strong> DSR enables both practical (software) and theoretical (architecture patterns) contributions</li>
</ul>',
word_count = 400
WHERE section_key = 'ch3_sec1';


-- =============================================================
-- Verify updates
-- =============================================================

SELECT
    section_key,
    title,
    word_count,
    CASE
        WHEN content_html LIKE '%(2023)%' OR content_html LIKE '%(2022)%' OR content_html LIKE '%(2021)%' OR content_html LIKE '%(2020)%'
        THEN 'YES'
        ELSE 'NO'
    END as has_recent_citations
FROM thesis_sections
WHERE section_key IN ('ch2_sec1', 'ch2_sec4', 'ch2_sec5', 'ch2_sec6', 'ch3_sec1')
ORDER BY section_key;
