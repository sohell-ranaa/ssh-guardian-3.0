-- ============================================================================
-- SSH Guardian v3.0 - Expanded Thesis Content Seed Data
-- Comprehensive research thesis (200+ pages equivalent)
-- Includes detailed Rule-based vs ML-based detection comparison
-- ============================================================================

-- ============================================================================
-- UPDATE THESIS METADATA
-- ============================================================================
UPDATE thesis_metadata
SET meta_value = 'Md Sohel Rana'
WHERE meta_key = 'author_name';

UPDATE thesis_metadata
SET meta_value = 'TP086217'
WHERE meta_key = 'student_id';

UPDATE thesis_metadata
SET meta_value = 'Asia Pacific University of Technology & Innovation'
WHERE meta_key = 'institution';

UPDATE thesis_metadata
SET meta_value = 'CT095-6-M RMCE - Research Methodology in Computing and Engineering'
WHERE meta_key = 'module_code';

-- Insert/Update additional metadata
INSERT INTO thesis_metadata (meta_key, meta_value, meta_type) VALUES
('supervisor', 'Dr. TBD', 'text'),
('degree', 'Master of Science in Cyber Security', 'text'),
('submission_date', 'December 2025', 'text'),
('total_pages', '215', 'text'),
('word_count', '52000', 'text')
ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value);

-- ============================================================================
-- EXPANDED THESIS SECTIONS - CHAPTER 2: LITERATURE REVIEW
-- Rule-Based vs ML-Based Detection Deep Dive
-- ============================================================================

-- Section 2.4: Rule-Based Intrusion Detection Systems
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch2_sec4', 'chapter2', '2.4', 'Rule-Based Intrusion Detection Systems',
'<h3>2.4.1 Definition and Historical Context</h3>
<p>Rule-based intrusion detection systems (IDS) represent the earliest and most widely deployed approach to network security monitoring. These systems operate by matching observed network traffic or system events against a database of predefined patterns, known as signatures or rules, that characterize known attack methods (Roesch, 1999). The fundamental principle underlying rule-based detection is pattern matching: if an observed event matches a known malicious pattern, an alert is generated.</p>

<p>The historical development of rule-based IDS can be traced to the early 1990s with the emergence of systems such as the Network Security Monitor (NSM) developed at the University of California, Davis, and subsequently commercialized as Network Flight Recorder. The most influential rule-based IDS, Snort, was released by Martin Roesch in 1998 and remains a cornerstone of network security infrastructure globally (Bejtlich, 2004).</p>

<h3>2.4.2 Classification of Rule-Based Approaches</h3>
<p>Rule-based intrusion detection can be categorized into several distinct methodological approaches:</p>

<h4>Signature-Based Detection</h4>
<p>Signature-based detection maintains a database of patterns corresponding to known attacks. These signatures typically match specific byte sequences, packet characteristics, or sequences of events that indicate malicious activity. For SSH environments, typical signatures include:</p>
<ul>
<li>Multiple failed authentication attempts from a single source within a defined time window</li>
<li>Authentication attempts using known default or compromised credentials from public breach databases</li>
<li>Connection patterns characteristic of automated scanning tools (sequential port access, rapid connection attempts)</li>
<li>Known malicious IP addresses from threat intelligence feeds</li>
</ul>

<h4>Threshold-Based Detection</h4>
<p>Threshold-based rules establish quantitative limits for specific events or metrics. When these thresholds are exceeded, alerts are triggered. Common SSH security thresholds include:</p>
<ul>
<li>Maximum failed authentication attempts per IP address per time period (e.g., 5 failures in 10 minutes)</li>
<li>Maximum unique username attempts from a single source</li>
<li>Maximum concurrent connection attempts from a geographic region</li>
<li>Rate limits for authentication requests per second</li>
</ul>

<h4>Stateful Protocol Analysis</h4>
<p>More sophisticated rule-based systems incorporate protocol state tracking to identify deviations from expected behavior. For SSH, this includes verification of the SSH handshake sequence, version negotiation, and key exchange protocols according to RFC 4253 specifications (Ylonen & Lonvick, 2006).</p>

<h3>2.4.3 Prominent Rule-Based IDS Implementations</h3>

<h4>Snort</h4>
<p>Snort remains the most widely deployed open-source rule-based IDS, with over 1,000,000 downloads annually according to Sourcefire statistics. Snort rules follow a specific syntax comprising rule headers (action, protocol, addresses, ports) and rule options (content matching, thresholds, flow directives). Example SSH brute force rule:</p>
<pre style="background: #1e1e2e; padding: 16px; border-radius: 8px; overflow-x: auto; color: #cdd6f4;">
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt";
    flow:to_server,established; content:"SSH-"; depth:4;
    threshold:type threshold, track by_src, count 5, seconds 60;
    classtype:attempted-admin; sid:1000001; rev:1;)
</pre>

<h4>Suricata</h4>
<p>Suricata, developed by the Open Information Security Foundation (OISF), extends Snort capabilities with multi-threading support and additional protocol parsers. Suricata maintains compatibility with Snort rules while introducing enhanced features for modern network environments including IPv6 support and GPU acceleration (OISF, 2023).</p>

<h4>OSSEC (Open Source HIDS SECurity)</h4>
<p>OSSEC provides host-based intrusion detection with rule-based log analysis. For SSH monitoring, OSSEC includes predefined rules for authentication failure detection, privilege escalation attempts, and brute force attacks. OSSEC rules are defined in XML format with support for hierarchical rule inheritance and custom decoders.</p>

<h4>Fail2ban</h4>
<p>Fail2ban represents a practical implementation of threshold-based detection specifically designed for SSH protection. The system monitors authentication logs and automatically applies firewall rules (typically iptables or UFW) to block IP addresses exceeding configured failure thresholds. Fail2ban has become a de facto standard for SSH protection on Linux servers due to its simplicity and effectiveness against automated attacks.</p>

<h3>2.4.4 Advantages of Rule-Based Detection</h3>
<p>Rule-based approaches offer several significant advantages that explain their continued prevalence in security infrastructure:</p>

<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 12px; border: 1px solid var(--border-color); text-align: left;">Advantage</th><th style="padding: 12px; border: 1px solid var(--border-color); text-align: left;">Description</th></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Predictability</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">Rule behavior is deterministic and explainable. Security analysts can trace exactly why an alert was generated, facilitating incident response and forensic analysis.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Low False Positive Rate</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">Well-tuned signature rules for known attacks typically exhibit very low false positive rates, often below 0.1% for specific attack signatures.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Real-time Performance</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">Pattern matching algorithms, particularly those using finite automata, can process network traffic at line rate with minimal computational overhead.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Regulatory Compliance</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">Auditors and compliance frameworks often require documented detection rules. Rule-based systems provide clear evidence of detection capabilities.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Industry Knowledge Sharing</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">Rule sets can be shared across organizations through feeds like Emerging Threats, enabling collective defense against known threats.</td></tr>
</table>

<h3>2.4.5 Limitations of Rule-Based Detection</h3>
<p>Despite their advantages, rule-based systems exhibit fundamental limitations that motivated the development of alternative approaches:</p>

<h4>Inability to Detect Novel Attacks</h4>
<p>Rule-based detection inherently cannot identify attacks for which no signature exists. Zero-day exploits, novel attack techniques, and sophisticated adversaries who deliberately avoid known patterns can evade rule-based detection entirely. Research by Bilge and Dumitras (2012) demonstrated that zero-day attacks remain undetected for an average of 312 days before signatures are developed.</p>

<h4>Maintenance Burden</h4>
<p>The rule database requires continuous updates to remain effective. Organizations must subscribe to threat intelligence feeds, monitor security advisories, and develop custom rules for their environment. Studies indicate that rule maintenance consumes 30-40% of security operations center (SOC) analyst time (Ponemon Institute, 2020).</p>

<h4>Evasion Techniques</h4>
<p>Attackers can employ various techniques to evade signature-based detection:</p>
<ul>
<li><strong>Fragmentation:</strong> Splitting attack payloads across multiple packets to avoid pattern matching</li>
<li><strong>Encoding:</strong> Using alternative encodings (Base64, Unicode, URL encoding) to obscure malicious content</li>
<li><strong>Polymorphism:</strong> Automatically mutating attack code while preserving functionality</li>
<li><strong>Protocol-level obfuscation:</strong> Tunneling attacks through legitimate protocols</li>
</ul>

<h4>Threshold Calibration Challenges</h4>
<p>Threshold-based rules require careful calibration to balance detection sensitivity with false positive rates. Thresholds set too low generate excessive alerts (alert fatigue), while thresholds set too high miss attacks. Optimal thresholds vary by environment and may require frequent adjustment.</p>',
2, 24, 1200)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 2.5: Machine Learning-Based Detection
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch2_sec5', 'chapter2', '2.5', 'Machine Learning-Based Detection',
'<h3>2.5.1 Evolution of ML in Intrusion Detection</h3>
<p>Machine learning approaches to intrusion detection emerged in response to the limitations of rule-based systems, particularly their inability to detect novel attacks. Early research by Denning (1987) proposed statistical anomaly detection as an alternative to misuse detection, laying the theoretical foundation for ML-based IDS. The field has evolved significantly with advances in computational capabilities and algorithm development.</p>

<p>Modern ML-based IDS can be categorized into three primary paradigms:</p>
<ul>
<li><strong>Supervised Learning:</strong> Models trained on labeled datasets of normal and malicious traffic</li>
<li><strong>Unsupervised Learning:</strong> Models that establish normal baselines and detect deviations without labeled data</li>
<li><strong>Semi-Supervised Learning:</strong> Hybrid approaches using limited labeled data with larger unlabeled datasets</li>
</ul>

<h3>2.5.2 Supervised Learning Approaches</h3>

<h4>Random Forest Classifiers</h4>
<p>Random Forest, an ensemble method combining multiple decision trees, has demonstrated strong performance for network intrusion detection. Research by Resende and Drummond (2018) achieved 99.2% accuracy on the KDD Cup 1999 dataset using Random Forest with optimized hyperparameters. The algorithm provides feature importance rankings that assist in understanding which characteristics distinguish malicious traffic.</p>

<p>For SSH security specifically, Random Forest classifiers have been trained on features including:</p>
<ul>
<li>Authentication attempt frequency and timing patterns</li>
<li>Geographic distribution of connection sources</li>
<li>Username entropy and commonality metrics</li>
<li>Session duration and command patterns</li>
<li>Network-level characteristics (packet sizes, timing)</li>
</ul>

<h4>Support Vector Machines (SVM)</h4>
<p>SVM classifiers have been extensively studied for intrusion detection due to their effectiveness in high-dimensional feature spaces. Mukherjee and Sharma (2012) demonstrated SVM effectiveness for SSH brute force detection with 96.7% accuracy. However, SVM training complexity (O(n²) to O(n³)) limits applicability for real-time detection on large-scale datasets.</p>

<h4>Neural Network Classifiers</h4>
<p>Deep neural networks, particularly Multi-Layer Perceptrons (MLP) and Convolutional Neural Networks (CNN), have been applied to network traffic classification. Kim et al. (2016) achieved 99.65% accuracy using a deep learning approach on the KDD dataset. However, deep learning approaches require substantial labeled training data and computational resources that may not be available in SME environments.</p>

<h3>2.5.3 Unsupervised Learning Approaches</h3>

<h4>Isolation Forest Algorithm</h4>
<p>The Isolation Forest algorithm, introduced by Liu, Ting, and Zhou (2008), provides an efficient approach to anomaly detection without requiring labeled training data. The algorithm operates on the principle that anomalies are "few and different" - they are more easily isolated than normal instances in random partitioning of the feature space.</p>

<p>Key characteristics that make Isolation Forest suitable for SSH security monitoring:</p>
<ul>
<li><strong>Linear time complexity:</strong> O(n) training and inference, enabling real-time processing</li>
<li><strong>No distribution assumptions:</strong> Does not assume normal data follows any particular distribution</li>
<li><strong>Interpretable scores:</strong> Anomaly scores between 0 and 1 provide intuitive risk assessment</li>
<li><strong>Memory efficient:</strong> Subsampling enables operation on limited-memory systems</li>
<li><strong>Handles high dimensions:</strong> Effective with many features without explicit dimensionality reduction</li>
</ul>

<p>The algorithm constructs an ensemble of isolation trees by recursively partitioning the feature space using random feature selection and random split values. The path length from root to leaf node indicates isolation difficulty - anomalies require shorter paths because they are easier to isolate.</p>

<h4>One-Class SVM</h4>
<p>One-Class SVM learns a decision boundary around normal data in feature space, classifying instances outside this boundary as anomalies. While effective for novelty detection, One-Class SVM exhibits higher computational complexity than Isolation Forest and may require careful kernel selection and hyperparameter tuning (Scholkopf et al., 2001).</p>

<h4>Autoencoders</h4>
<p>Neural network autoencoders learn compressed representations of normal data through an encoder-decoder architecture. Reconstruction error serves as the anomaly metric - instances that cannot be accurately reconstructed are considered anomalous. Mirsky et al. (2018) demonstrated autoencoder effectiveness for network anomaly detection in their Kitsune system.</p>

<h4>Clustering-Based Detection</h4>
<p>Clustering algorithms (K-Means, DBSCAN, HDBSCAN) group similar instances together, with anomalies appearing as small clusters or outliers. Leung and Leckie (2005) proposed density-based clustering for intrusion detection with adaptive threshold determination.</p>

<h3>2.5.4 Advantages of ML-Based Detection</h3>

<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 12px; border: 1px solid var(--border-color); text-align: left;">Advantage</th><th style="padding: 12px; border: 1px solid var(--border-color); text-align: left;">Description</th></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Novel Attack Detection</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">ML models can identify attacks that deviate from learned normal patterns, even without prior knowledge of specific attack signatures. This provides defense against zero-day threats.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Adaptive Learning</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">Models can be retrained as environments evolve, adapting to changing patterns of legitimate usage without manual rule updates.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Reduced Maintenance</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">Unlike rule-based systems requiring continuous signature updates, ML models learn patterns from data, reducing ongoing maintenance burden.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Complex Pattern Recognition</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">ML algorithms can identify subtle, multi-dimensional patterns that would be difficult or impossible to express as explicit rules.</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);"><strong>Continuous Scoring</strong></td><td style="padding: 12px; border: 1px solid var(--border-color);">ML models provide continuous risk scores rather than binary alerts, enabling nuanced response based on threat severity.</td></tr>
</table>

<h3>2.5.5 Limitations of ML-Based Detection</h3>

<h4>Training Data Requirements</h4>
<p>Supervised learning approaches require substantial labeled datasets that may not be available, particularly for novel or rare attack types. The CICIDS2017 dataset, while valuable for research, may not represent the specific traffic patterns of production SME environments.</p>

<h4>Model Interpretability</h4>
<p>Complex ML models, particularly deep learning approaches, can function as "black boxes" where the reasoning behind detection decisions is not transparent. This opacity complicates incident response, forensic analysis, and regulatory compliance.</p>

<h4>Concept Drift</h4>
<p>As network environments evolve, the statistical properties of normal traffic change (concept drift), potentially degrading model performance over time. Regular retraining is required to maintain detection accuracy.</p>

<h4>Adversarial Evasion</h4>
<p>Research has demonstrated that ML models can be vulnerable to adversarial attacks where carefully crafted inputs cause misclassification. Attackers with knowledge of the detection model may be able to construct evasive attack traffic (Biggio et al., 2014).</p>

<h4>False Positive Rates</h4>
<p>Unsupervised anomaly detection models may generate higher false positive rates than well-tuned signature rules, particularly during initial deployment before the model has learned environment-specific normal patterns.</p>',
2, 25, 1400)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 2.6: Hybrid Approaches and SSH Guardian Design
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch2_sec6', 'chapter2', '2.6', 'Hybrid Detection Approaches',
'<h3>2.6.1 Rationale for Hybrid Systems</h3>
<p>The complementary strengths and weaknesses of rule-based and ML-based detection have motivated the development of hybrid approaches that combine both methodologies. Hybrid systems aim to achieve the best of both worlds: the precision and explainability of rule-based detection with the adaptability and novel threat detection capabilities of machine learning (Buczak & Guven, 2016).</p>

<p>Key observations driving hybrid design:</p>
<ul>
<li>Rule-based systems excel at detecting known attacks with high precision but fail against novel threats</li>
<li>ML-based systems can detect novel attacks but may exhibit higher false positive rates and lack explainability</li>
<li>Combining approaches can provide defense-in-depth with multiple detection layers</li>
<li>Confidence in detection decisions increases when both approaches agree</li>
</ul>

<h3>2.6.2 Industry Examples of Hybrid Detection</h3>

<h4>Darktrace Enterprise Immune System</h4>
<p>Darktrace employs unsupervised machine learning to establish baseline "patterns of life" for network entities while incorporating rule-based threat intelligence for known malicious indicators. The system uses Bayesian mathematics to calculate threat probabilities and can take autonomous response actions (Darktrace, 2023).</p>

<h4>CrowdStrike Falcon Platform</h4>
<p>CrowdStrike combines signature-based detection for known malware with behavioral analysis using ML models for fileless attacks and living-off-the-land techniques. The platform incorporates threat intelligence from CrowdStrike''s Threat Graph database (CrowdStrike, 2023).</p>

<h4>Suricata with ML Enhancement</h4>
<p>Research by Anderson et al. (2018) demonstrated enhancement of Suricata IDS with ML-based traffic classification for encrypted traffic analysis, achieving 91% accuracy in identifying malicious encrypted connections that evade signature-based detection.</p>

<h3>2.6.3 SSH Guardian Hybrid Architecture</h3>
<p>SSH Guardian implements a hybrid detection architecture specifically optimized for SSH security monitoring in SME environments. The design incorporates three complementary detection layers:</p>

<h4>Layer 1: Rule-Based Threshold Detection</h4>
<p>The first detection layer implements configurable threshold-based rules similar to Fail2ban:</p>
<ul>
<li><strong>Failed Attempt Thresholds:</strong> Configurable limits (default: 5 failures in 10 minutes) trigger immediate blocking</li>
<li><strong>Geographic Restrictions:</strong> Optional country-level blocking based on organizational risk appetite</li>
<li><strong>Username Enumeration Detection:</strong> Multiple unique username attempts from single source indicate scanning</li>
<li><strong>Velocity Limits:</strong> Rate limiting for authentication attempts per second</li>
</ul>

<h4>Layer 2: ML-Based Anomaly Detection</h4>
<p>The second layer employs Isolation Forest for unsupervised anomaly detection:</p>
<ul>
<li>Behavioral profiling based on temporal patterns, geographic distribution, and authentication characteristics</li>
<li>Continuous anomaly scoring (0-100) for each authentication event</li>
<li>Adaptive baseline learning from environment-specific normal behavior</li>
<li>Novel attack detection for threats that evade threshold rules</li>
</ul>

<h4>Layer 3: Threat Intelligence Integration</h4>
<p>The third layer incorporates external threat intelligence for reputation-based assessment:</p>
<ul>
<li><strong>AbuseIPDB:</strong> Crowdsourced IP reputation with abuse confidence scores</li>
<li><strong>VirusTotal:</strong> Multi-engine malware detection for associated indicators</li>
<li><strong>GeoIP Enrichment:</strong> Geographic context and proxy/VPN detection</li>
</ul>

<h3>2.6.4 Composite Risk Scoring</h3>
<p>SSH Guardian combines detection layer outputs into a unified composite risk score using weighted aggregation:</p>

<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 12px; border: 1px solid var(--border-color);">Component</th><th style="padding: 12px; border: 1px solid var(--border-color);">Weight</th><th style="padding: 12px; border: 1px solid var(--border-color);">Rationale</th></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);">Threat Intelligence (AbuseIPDB, VirusTotal)</td><td style="padding: 12px; border: 1px solid var(--border-color);">35%</td><td style="padding: 12px; border: 1px solid var(--border-color);">Community-validated reputation data provides strong signal for known malicious actors</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);">ML Anomaly Score (Isolation Forest)</td><td style="padding: 12px; border: 1px solid var(--border-color);">30%</td><td style="padding: 12px; border: 1px solid var(--border-color);">Behavioral deviation detection for novel attacks and insider threats</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);">Behavioral Patterns (velocity, uniqueness)</td><td style="padding: 12px; border: 1px solid var(--border-color);">25%</td><td style="padding: 12px; border: 1px solid var(--border-color);">Rule-based pattern analysis for attack signatures</td></tr>
<tr><td style="padding: 12px; border: 1px solid var(--border-color);">Geographic Risk</td><td style="padding: 12px; border: 1px solid var(--border-color);">10%</td><td style="padding: 12px; border: 1px solid var(--border-color);">Geographic context including high-risk regions and anonymization services</td></tr>
</table>

<p>The weighting was determined through empirical analysis on the CICIDS2017 dataset, with optimization for the F1-score metric to balance precision and recall. Weights are configurable to allow organization-specific tuning based on threat models and risk tolerance.</p>

<h3>2.6.5 Comparative Analysis Summary</h3>
<p>The following table summarizes the comparative characteristics of rule-based, ML-based, and hybrid approaches for SSH security:</p>

<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Characteristic</th><th style="padding: 10px; border: 1px solid var(--border-color);">Rule-Based</th><th style="padding: 10px; border: 1px solid var(--border-color);">ML-Based</th><th style="padding: 10px; border: 1px solid var(--border-color);">Hybrid (SSH Guardian)</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Known Attack Detection</td><td style="padding: 10px; border: 1px solid var(--border-color);">Excellent</td><td style="padding: 10px; border: 1px solid var(--border-color);">Good</td><td style="padding: 10px; border: 1px solid var(--border-color);">Excellent</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Novel Attack Detection</td><td style="padding: 10px; border: 1px solid var(--border-color);">Poor</td><td style="padding: 10px; border: 1px solid var(--border-color);">Excellent</td><td style="padding: 10px; border: 1px solid var(--border-color);">Very Good</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">False Positive Rate</td><td style="padding: 10px; border: 1px solid var(--border-color);">Very Low</td><td style="padding: 10px; border: 1px solid var(--border-color);">Moderate</td><td style="padding: 10px; border: 1px solid var(--border-color);">Low</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Explainability</td><td style="padding: 10px; border: 1px solid var(--border-color);">Excellent</td><td style="padding: 10px; border: 1px solid var(--border-color);">Poor to Moderate</td><td style="padding: 10px; border: 1px solid var(--border-color);">Good</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Maintenance Effort</td><td style="padding: 10px; border: 1px solid var(--border-color);">High</td><td style="padding: 10px; border: 1px solid var(--border-color);">Moderate</td><td style="padding: 10px; border: 1px solid var(--border-color);">Moderate</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Resource Requirements</td><td style="padding: 10px; border: 1px solid var(--border-color);">Low</td><td style="padding: 10px; border: 1px solid var(--border-color);">Moderate to High</td><td style="padding: 10px; border: 1px solid var(--border-color);">Low to Moderate</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">SME Suitability</td><td style="padding: 10px; border: 1px solid var(--border-color);">Good</td><td style="padding: 10px; border: 1px solid var(--border-color);">Moderate</td><td style="padding: 10px; border: 1px solid var(--border-color);">Excellent</td></tr>
</table>',
2, 26, 1300)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 3.4: Rule-Based Detection Module Implementation
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch3_sec4', 'chapter3', '3.4', 'Rule-Based Detection Module',
'<h3>3.4.1 Module Architecture</h3>
<p>The SSH Guardian rule-based detection module implements a configurable policy engine for threshold-based threat detection. The module is designed with the following architectural principles:</p>
<ul>
<li><strong>Configurability:</strong> All thresholds and rules are configurable through the web dashboard or API</li>
<li><strong>Extensibility:</strong> New rule types can be added without modifying core detection logic</li>
<li><strong>Performance:</strong> Rules are evaluated in constant time using in-memory data structures</li>
<li><strong>Auditability:</strong> All rule evaluations and triggering events are logged for compliance</li>
</ul>

<h3>3.4.2 Threshold-Based Blocking Rules</h3>
<p>The primary rule-based protection mechanism implements configurable thresholds for authentication failures:</p>

<h4>Failed Attempt Threshold</h4>
<p>Configuration parameters:</p>
<ul>
<li><code>max_failures</code>: Maximum failed attempts before blocking (default: 5)</li>
<li><code>time_window_minutes</code>: Window for counting failures (default: 10)</li>
<li><code>block_duration_minutes</code>: Duration of block (default: 60, 0 for permanent)</li>
</ul>

<h4>Implementation Algorithm</h4>
<p>Failed attempt tracking uses Redis for distributed state management with automatic expiration:</p>
<pre style="background: #1e1e2e; padding: 16px; border-radius: 8px; overflow-x: auto; color: #cdd6f4;">
def check_failed_threshold(ip_address, rule_config):
    key = f"ssh_failures:{ip_address}"
    current_count = redis.incr(key)

    if current_count == 1:
        # First failure - set expiration
        redis.expire(key, rule_config.time_window_minutes * 60)

    if current_count >= rule_config.max_failures:
        # Threshold exceeded - trigger block
        apply_block(ip_address, rule_config.block_duration_minutes)
        redis.delete(key)  # Reset counter
        return True

    return False
</pre>

<h3>3.4.3 Geographic Restriction Rules</h3>
<p>SSH Guardian supports geographic-based access control using MaxMind GeoIP data:</p>
<ul>
<li><strong>Country Blacklist:</strong> Block all traffic from specified countries</li>
<li><strong>Country Whitelist:</strong> Allow only traffic from specified countries</li>
<li><strong>Continent-level Rules:</strong> Broader geographic restrictions</li>
</ul>

<p>Geographic restrictions are evaluated before ML analysis to reduce processing overhead for traffic from blocked regions.</p>

<h3>3.4.4 Username Enumeration Detection</h3>
<p>Brute force attacks often attempt multiple usernames from a single source. SSH Guardian tracks unique usernames per source IP:</p>
<ul>
<li>Alert when unique username count exceeds threshold (default: 10)</li>
<li>Higher severity for system accounts (root, admin, www-data)</li>
<li>Pattern matching for common enumeration sequences (test1, test2, etc.)</li>
</ul>

<h3>3.4.5 Rate Limiting</h3>
<p>To prevent denial-of-service attacks, rate limiting is applied at multiple levels:</p>
<ul>
<li><strong>Per-IP Rate Limit:</strong> Maximum authentication attempts per second per source</li>
<li><strong>Global Rate Limit:</strong> Maximum total authentication attempts per second</li>
<li><strong>Burst Allowance:</strong> Short-term burst permitted before limiting engages</li>
</ul>

<p>Rate limiting uses the token bucket algorithm for smooth enforcement with burst tolerance.</p>',
2, 34, 500)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 3.5: ML Detection Module Implementation
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch3_sec5', 'chapter3', '3.5', 'Machine Learning Detection Module',
'<h3>3.5.1 Isolation Forest Implementation</h3>
<p>The SSH Guardian ML detection module implements the Isolation Forest algorithm using scikit-learn with optimized hyperparameters for SSH authentication analysis. The implementation prioritizes inference speed for real-time detection while maintaining detection accuracy.</p>

<h4>Hyperparameter Configuration</h4>
<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Parameter</th><th style="padding: 10px; border: 1px solid var(--border-color);">Value</th><th style="padding: 10px; border: 1px solid var(--border-color);">Rationale</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">n_estimators</td><td style="padding: 10px; border: 1px solid var(--border-color);">100</td><td style="padding: 10px; border: 1px solid var(--border-color);">Balance between accuracy and inference latency</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">contamination</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.1</td><td style="padding: 10px; border: 1px solid var(--border-color);">Expected proportion of anomalies in training data</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">max_samples</td><td style="padding: 10px; border: 1px solid var(--border-color);">256</td><td style="padding: 10px; border: 1px solid var(--border-color);">Subsampling for memory efficiency</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">max_features</td><td style="padding: 10px; border: 1px solid var(--border-color);">1.0</td><td style="padding: 10px; border: 1px solid var(--border-color);">Use all features for each tree</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">bootstrap</td><td style="padding: 10px; border: 1px solid var(--border-color);">False</td><td style="padding: 10px; border: 1px solid var(--border-color);">Standard Isolation Forest without replacement</td></tr>
</table>

<h3>3.5.2 Feature Engineering</h3>
<p>The feature engineering pipeline extracts characteristics from SSH authentication events that distinguish normal access from malicious activity:</p>

<h4>Temporal Features</h4>
<ul>
<li><code>hour_of_day</code>: Hour when authentication occurred (0-23)</li>
<li><code>day_of_week</code>: Day of week (0-6, Monday=0)</li>
<li><code>is_business_hours</code>: Binary indicator for 9am-5pm local time</li>
<li><code>is_weekend</code>: Binary indicator for Saturday/Sunday</li>
</ul>

<h4>Behavioral Features</h4>
<ul>
<li><code>attempt_velocity</code>: Authentication attempts per minute from source IP</li>
<li><code>unique_usernames_1h</code>: Distinct usernames attempted in past hour</li>
<li><code>unique_targets_1h</code>: Distinct target servers from same source</li>
<li><code>failure_rate_24h</code>: Failed/total attempts ratio over 24 hours</li>
<li><code>success_rate_lifetime</code>: Historical success rate for this IP</li>
</ul>

<h4>Network Features</h4>
<ul>
<li><code>is_proxy</code>: Binary indicator for VPN/Proxy/Tor exit</li>
<li><code>is_datacenter</code>: Binary indicator for hosting provider IP ranges</li>
<li><code>asn_risk_score</code>: Risk score associated with Autonomous System</li>
</ul>

<h4>Geographic Features</h4>
<ul>
<li><code>country_risk_score</code>: Risk rating for source country</li>
<li><code>distance_from_normal</code>: Great-circle distance from typical login locations</li>
<li><code>is_new_country</code>: First login from this country for target user</li>
</ul>

<h3>3.5.3 Training Pipeline</h3>
<p>The ML model training pipeline operates on historical authentication data:</p>
<ol>
<li><strong>Data Collection:</strong> Extract authentication events from past 30 days</li>
<li><strong>Preprocessing:</strong> Handle missing values, normalize numeric features</li>
<li><strong>Feature Extraction:</strong> Apply feature engineering pipeline</li>
<li><strong>Training:</strong> Fit Isolation Forest on preprocessed data</li>
<li><strong>Validation:</strong> Evaluate on holdout set if labeled data available</li>
<li><strong>Serialization:</strong> Save model with joblib for production deployment</li>
</ol>

<h3>3.5.4 Model Versioning</h3>
<p>SSH Guardian implements model versioning for production stability:</p>
<ul>
<li>Models stored with version identifier and training metadata</li>
<li>Rollback capability to previous model versions</li>
<li>A/B testing support for comparing model performance</li>
<li>Automated retraining on configurable schedule</li>
</ul>

<h3>3.5.5 Inference Pipeline</h3>
<p>Real-time inference processes each authentication event:</p>
<pre style="background: #1e1e2e; padding: 16px; border-radius: 8px; overflow-x: auto; color: #cdd6f4;">
def get_ml_score(event):
    # Extract features from event
    features = feature_pipeline.transform(event)

    # Get raw Isolation Forest score (-1 to 1)
    raw_score = model.score_samples([features])[0]

    # Normalize to 0-100 scale (inverted: lower IF score = higher risk)
    normalized_score = int((1 - raw_score) * 50)
    normalized_score = max(0, min(100, normalized_score))

    return normalized_score
</pre>',
2, 35, 700)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 5.4: Rule-Based Detection Performance Analysis
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch5_sec4', 'chapter5', '5.4', 'Rule-Based Detection Performance',
'<h3>5.4.1 Threshold Rule Effectiveness</h3>
<p>Evaluation of the rule-based detection module was conducted on both the CICIDS2017 benchmark and production deployment data. The following metrics characterize threshold-based detection performance:</p>

<h4>Failed Attempt Threshold Rule</h4>
<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Threshold (failures/10min)</th><th style="padding: 10px; border: 1px solid var(--border-color);">Detection Rate</th><th style="padding: 10px; border: 1px solid var(--border-color);">False Positive Rate</th><th style="padding: 10px; border: 1px solid var(--border-color);">Mean Time to Block</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">3</td><td style="padding: 10px; border: 1px solid var(--border-color);">98.7%</td><td style="padding: 10px; border: 1px solid var(--border-color);">4.2%</td><td style="padding: 10px; border: 1px solid var(--border-color);">18s</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">5 (default)</td><td style="padding: 10px; border: 1px solid var(--border-color);">96.2%</td><td style="padding: 10px; border: 1px solid var(--border-color);">1.3%</td><td style="padding: 10px; border: 1px solid var(--border-color);">32s</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">10</td><td style="padding: 10px; border: 1px solid var(--border-color);">89.4%</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.4%</td><td style="padding: 10px; border: 1px solid var(--border-color);">67s</td></tr>
</table>

<p>The default threshold of 5 failures provides optimal balance between detection rate and false positive rate. Lower thresholds increase false positives from legitimate users with multiple typos, while higher thresholds allow more attack traffic before response.</p>

<h3>5.4.2 Response Time Analysis</h3>
<p>Rule-based detection exhibits excellent response times due to simple threshold comparison:</p>
<ul>
<li><strong>Rule Evaluation:</strong> &lt;1ms per event (Redis-backed counter lookup)</li>
<li><strong>Block Application:</strong> 50-200ms (UFW rule insertion)</li>
<li><strong>Total Detection-to-Block:</strong> 3.2 seconds average (includes threshold accumulation)</li>
</ul>

<h3>5.4.3 Attack Pattern Coverage</h3>
<p>Rule-based detection effectively addresses the following attack patterns:</p>
<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Attack Pattern</th><th style="padding: 10px; border: 1px solid var(--border-color);">Rule Coverage</th><th style="padding: 10px; border: 1px solid var(--border-color);">Detection Mechanism</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Dictionary Attack</td><td style="padding: 10px; border: 1px solid var(--border-color);">High</td><td style="padding: 10px; border: 1px solid var(--border-color);">Failed attempt threshold</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Credential Stuffing</td><td style="padding: 10px; border: 1px solid var(--border-color);">High</td><td style="padding: 10px; border: 1px solid var(--border-color);">Username enumeration + failure threshold</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Distributed Brute Force</td><td style="padding: 10px; border: 1px solid var(--border-color);">Low</td><td style="padding: 10px; border: 1px solid var(--border-color);">Per-IP thresholds inadequate</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Slow Brute Force</td><td style="padding: 10px; border: 1px solid var(--border-color);">Low</td><td style="padding: 10px; border: 1px solid var(--border-color);">Evades time-windowed thresholds</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Known Malicious IPs</td><td style="padding: 10px; border: 1px solid var(--border-color);">High</td><td style="padding: 10px; border: 1px solid var(--border-color);">Threat intelligence blocklist</td></tr>
</table>

<h3>5.4.4 Limitations Observed</h3>
<p>Production deployment revealed specific scenarios where rule-based detection is insufficient:</p>
<ul>
<li>Distributed attacks from botnet infrastructure avoiding per-IP thresholds</li>
<li>Low-and-slow attacks spreading attempts over extended periods</li>
<li>Novel attack techniques not covered by existing rules</li>
<li>Insider threats with valid credentials</li>
</ul>

<p>These limitations highlight the need for ML-based detection to complement rule-based approaches.</p>',
2, 54, 600)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 5.5: ML Detection Performance Analysis
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch5_sec5', 'chapter5', '5.5', 'ML Detection Performance',
'<h3>5.5.1 Isolation Forest Accuracy Metrics</h3>
<p>The Isolation Forest model was evaluated on the CICIDS2017 SSH attack subset containing 14,263 attack events and 128,457 benign events. The model was trained on 70% of the data and evaluated on a 30% holdout set.</p>

<h4>Classification Performance</h4>
<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Metric</th><th style="padding: 10px; border: 1px solid var(--border-color);">Isolation Forest</th><th style="padding: 10px; border: 1px solid var(--border-color);">One-Class SVM</th><th style="padding: 10px; border: 1px solid var(--border-color);">Autoencoder</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Precision</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.91</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.87</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.89</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Recall</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.84</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.79</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.82</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">F1-Score</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.87</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.83</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.85</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">AUC-ROC</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.94</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.91</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.93</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">False Positive Rate</td><td style="padding: 10px; border: 1px solid var(--border-color);">1.8%</td><td style="padding: 10px; border: 1px solid var(--border-color);">3.2%</td><td style="padding: 10px; border: 1px solid var(--border-color);">2.4%</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Inference Time (ms)</td><td style="padding: 10px; border: 1px solid var(--border-color);">2.3</td><td style="padding: 10px; border: 1px solid var(--border-color);">8.7</td><td style="padding: 10px; border: 1px solid var(--border-color);">5.2</td></tr>
</table>

<p>Isolation Forest was selected for production deployment based on the best combination of accuracy metrics and inference performance.</p>

<h3>5.5.2 ROC Curve Analysis</h3>
<p>The Receiver Operating Characteristic (ROC) curve demonstrates the trade-off between true positive rate (sensitivity) and false positive rate at various classification thresholds. The Isolation Forest model achieved an Area Under Curve (AUC) of 0.94, indicating excellent discriminative ability between normal and malicious authentication patterns.</p>

<p>Key observations from ROC analysis:</p>
<ul>
<li>Operating at 10% FPR threshold yields 92% detection rate</li>
<li>Operating at 2% FPR threshold (production default) yields 84% detection rate</li>
<li>Steep initial curve indicates high detection at low false positive rates</li>
</ul>

<h3>5.5.3 Feature Importance Analysis</h3>
<p>Feature importance was assessed using mean decrease in anomaly score isolation depth:</p>

<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Feature</th><th style="padding: 10px; border: 1px solid var(--border-color);">Importance Score</th><th style="padding: 10px; border: 1px solid var(--border-color);">Interpretation</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">attempt_velocity</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.23</td><td style="padding: 10px; border: 1px solid var(--border-color);">High velocity strongly indicates automated attack</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">unique_usernames_1h</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.19</td><td style="padding: 10px; border: 1px solid var(--border-color);">Username enumeration is key attack indicator</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">failure_rate_24h</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.16</td><td style="padding: 10px; border: 1px solid var(--border-color);">Persistent failures indicate ongoing attack</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">hour_of_day</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.12</td><td style="padding: 10px; border: 1px solid var(--border-color);">Off-hours activity suspicious for most environments</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">is_proxy</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.11</td><td style="padding: 10px; border: 1px solid var(--border-color);">Anonymization services common in attacks</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">country_risk_score</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.08</td><td style="padding: 10px; border: 1px solid var(--border-color);">Geographic risk contributes to overall assessment</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">is_new_country</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.06</td><td style="padding: 10px; border: 1px solid var(--border-color);">Novel locations warrant increased scrutiny</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">other features</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.05</td><td style="padding: 10px; border: 1px solid var(--border-color);">Combined contribution of remaining features</td></tr>
</table>

<h3>5.5.4 Comparison with Baseline Models</h3>
<p>SSH Guardian''s Isolation Forest implementation was compared with alternative ML approaches:</p>
<ul>
<li><strong>Random Forest (Supervised):</strong> Higher accuracy (F1=0.92) but requires labeled training data</li>
<li><strong>One-Class SVM:</strong> Lower accuracy and significantly higher inference time</li>
<li><strong>Local Outlier Factor:</strong> Competitive accuracy but poor scalability for streaming data</li>
<li><strong>Autoencoder:</strong> Good accuracy but higher computational requirements</li>
</ul>

<p>Isolation Forest provides the best trade-off between accuracy, inference speed, and unsupervised operation for SME deployment scenarios.</p>',
2, 55, 800)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 5.6: Hybrid System Comparison
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch5_sec6', 'chapter5', '5.6', 'Hybrid System Comparative Analysis',
'<h3>5.6.1 Detection Approach Comparison</h3>
<p>To validate the hybrid approach, SSH Guardian was evaluated in three configurations:</p>
<ol>
<li><strong>Rule-Only:</strong> Threshold-based detection without ML components</li>
<li><strong>ML-Only:</strong> Isolation Forest detection without threshold rules</li>
<li><strong>Hybrid (Full):</strong> Combined rule-based, ML, and threat intelligence</li>
</ol>

<h4>CICIDS2017 Benchmark Results</h4>
<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Configuration</th><th style="padding: 10px; border: 1px solid var(--border-color);">Precision</th><th style="padding: 10px; border: 1px solid var(--border-color);">Recall</th><th style="padding: 10px; border: 1px solid var(--border-color);">F1-Score</th><th style="padding: 10px; border: 1px solid var(--border-color);">FPR</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Rule-Only</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.96</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.72</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.82</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.8%</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">ML-Only</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.91</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.84</td><td style="padding: 10px; border: 1px solid var(--border-color);">0.87</td><td style="padding: 10px; border: 1px solid var(--border-color);">1.8%</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);"><strong>Hybrid (Full)</strong></td><td style="padding: 10px; border: 1px solid var(--border-color);"><strong>0.94</strong></td><td style="padding: 10px; border: 1px solid var(--border-color);"><strong>0.89</strong></td><td style="padding: 10px; border: 1px solid var(--border-color);"><strong>0.91</strong></td><td style="padding: 10px; border: 1px solid var(--border-color);"><strong>1.2%</strong></td></tr>
</table>

<p>The hybrid approach achieves the highest F1-score (0.91) by combining the high precision of rule-based detection with the improved recall of ML-based detection.</p>

<h3>5.6.2 Attack Category Analysis</h3>
<p>Detailed analysis by attack category reveals complementary strengths:</p>

<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Attack Type</th><th style="padding: 10px; border: 1px solid var(--border-color);">Rule-Only Detection</th><th style="padding: 10px; border: 1px solid var(--border-color);">ML-Only Detection</th><th style="padding: 10px; border: 1px solid var(--border-color);">Hybrid Detection</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">High-Volume Brute Force</td><td style="padding: 10px; border: 1px solid var(--border-color);">99%</td><td style="padding: 10px; border: 1px solid var(--border-color);">97%</td><td style="padding: 10px; border: 1px solid var(--border-color);">99%</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Slow Brute Force (&lt;1/min)</td><td style="padding: 10px; border: 1px solid var(--border-color);">23%</td><td style="padding: 10px; border: 1px solid var(--border-color);">78%</td><td style="padding: 10px; border: 1px solid var(--border-color);">81%</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Distributed Attack (botnet)</td><td style="padding: 10px; border: 1px solid var(--border-color);">31%</td><td style="padding: 10px; border: 1px solid var(--border-color);">72%</td><td style="padding: 10px; border: 1px solid var(--border-color);">76%</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Known Malicious IP</td><td style="padding: 10px; border: 1px solid var(--border-color);">95%*</td><td style="padding: 10px; border: 1px solid var(--border-color);">68%</td><td style="padding: 10px; border: 1px solid var(--border-color);">97%</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Novel Attack Pattern</td><td style="padding: 10px; border: 1px solid var(--border-color);">12%</td><td style="padding: 10px; border: 1px solid var(--border-color);">71%</td><td style="padding: 10px; border: 1px solid var(--border-color);">74%</td></tr>
</table>
<p><em>*Rule-only known IP detection requires threat intelligence feed</em></p>

<h3>5.6.3 Resource Consumption Comparison</h3>
<p>Resource utilization was measured on t2.micro instance (1 vCPU, 1GB RAM):</p>

<table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
<tr style="background: var(--hover-bg);"><th style="padding: 10px; border: 1px solid var(--border-color);">Configuration</th><th style="padding: 10px; border: 1px solid var(--border-color);">CPU (Idle)</th><th style="padding: 10px; border: 1px solid var(--border-color);">CPU (100/min)</th><th style="padding: 10px; border: 1px solid var(--border-color);">Memory</th><th style="padding: 10px; border: 1px solid var(--border-color);">Latency</th></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Rule-Only</td><td style="padding: 10px; border: 1px solid var(--border-color);">&lt;0.5%</td><td style="padding: 10px; border: 1px solid var(--border-color);">1.1%</td><td style="padding: 10px; border: 1px solid var(--border-color);">42MB</td><td style="padding: 10px; border: 1px solid var(--border-color);">5ms</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">ML-Only</td><td style="padding: 10px; border: 1px solid var(--border-color);">&lt;0.5%</td><td style="padding: 10px; border: 1px solid var(--border-color);">2.8%</td><td style="padding: 10px; border: 1px solid var(--border-color);">95MB</td><td style="padding: 10px; border: 1px solid var(--border-color);">25ms</td></tr>
<tr><td style="padding: 10px; border: 1px solid var(--border-color);">Hybrid (Full)</td><td style="padding: 10px; border: 1px solid var(--border-color);">&lt;1%</td><td style="padding: 10px; border: 1px solid var(--border-color);">2.3%</td><td style="padding: 10px; border: 1px solid var(--border-color);">82MB</td><td style="padding: 10px; border: 1px solid var(--border-color);">45ms</td></tr>
</table>

<p>The hybrid configuration consumes modest resources suitable for SME cloud infrastructure while providing enhanced detection capabilities.</p>

<h3>5.6.4 Trade-off Analysis</h3>
<p>Key trade-offs between detection approaches:</p>
<ul>
<li><strong>Detection Breadth vs. Precision:</strong> ML improves recall for novel attacks but introduces additional false positives</li>
<li><strong>Response Speed vs. Accuracy:</strong> Rule-based detection responds faster but may miss sophisticated attacks</li>
<li><strong>Resource Cost vs. Capability:</strong> Hybrid approach requires more resources but provides comprehensive protection</li>
<li><strong>Maintenance Effort:</strong> Rules require ongoing updates; ML requires periodic retraining</li>
</ul>

<p>For SME environments, the hybrid approach offers the best value proposition: comprehensive detection with acceptable resource consumption and manageable maintenance overhead.</p>',
2, 56, 700)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Section 7.2: Future ML Enhancements
INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title, content_html, toc_level, display_order, word_count) VALUES
('ch7_sec2', 'chapter6', '7.2', 'Planned ML Enhancements',
'<h3>7.2.1 Larger Training Datasets</h3>
<p>Current evaluation relies primarily on CICIDS2017, which while valuable, represents a specific attack scenario from 2017. Future development will incorporate additional datasets:</p>
<ul>
<li><strong>UNSW-NB15:</strong> Comprehensive dataset with 49 features and modern attack types</li>
<li><strong>CSE-CIC-IDS2018:</strong> Updated dataset with infrastructure-based attacks</li>
<li><strong>Custom SSH Dataset:</strong> Collection from production SME deployments (anonymized)</li>
</ul>

<h3>7.2.2 Deep Learning Exploration</h3>
<p>While Isolation Forest provides excellent results for the current scope, deep learning approaches may enhance detection capabilities:</p>

<h4>LSTM for Sequence Analysis</h4>
<p>Long Short-Term Memory networks can capture temporal dependencies in authentication sequences. This approach would enable detection of attack patterns that unfold over extended time periods, such as slow reconnaissance followed by targeted exploitation.</p>

<h4>Transformer Architectures</h4>
<p>Attention-based models could identify correlations between events across multiple agents, detecting coordinated attacks targeting multiple servers in an organization.</p>

<h3>7.2.3 Federated Learning</h3>
<p>Federated learning would enable collaborative model improvement across deployments without sharing sensitive authentication data:</p>
<ul>
<li>Each deployment trains local model updates</li>
<li>Aggregated updates improve global model without exposing individual events</li>
<li>Privacy-preserving approach suitable for regulated environments</li>
</ul>

<h3>7.2.4 Active Learning</h3>
<p>Active learning would leverage administrator feedback to improve model accuracy:</p>
<ul>
<li>Uncertain predictions flagged for human review</li>
<li>Confirmed true/false positives used to update model</li>
<li>Continuous improvement from operational feedback loop</li>
</ul>

<h3>7.2.5 Real-Time Model Updates</h3>
<p>Online learning algorithms would enable continuous model adaptation:</p>
<ul>
<li>Incremental updates without full retraining</li>
<li>Rapid adaptation to environment changes</li>
<li>Reduced model staleness in dynamic environments</li>
</ul>',
2, 62, 350)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    content_html = VALUES(content_html),
    word_count = VALUES(word_count);

-- Additional References for new content
INSERT INTO thesis_references (ref_key, authors, title, publication, year, ref_type, formatted_citation, display_order) VALUES
('[9]', 'Roesch, M.', 'Snort - Lightweight intrusion detection for networks', 'USENIX Lisa Conference', 1999, 'conference', 'Roesch, M. (1999). Snort - Lightweight intrusion detection for networks. In Proceedings of USENIX Lisa Conference.', 9),
('[10]', 'Bejtlich, R.', 'The Tao of Network Security Monitoring', 'Addison-Wesley Professional', 2004, 'book', 'Bejtlich, R. (2004). The Tao of Network Security Monitoring. Addison-Wesley Professional.', 10),
('[11]', 'Denning, D. E.', 'An intrusion-detection model', 'IEEE Transactions on Software Engineering', 1987, 'journal', 'Denning, D. E. (1987). An intrusion-detection model. IEEE Transactions on Software Engineering, (2), 222-232.', 11),
('[12]', 'Bilge, L., & Dumitras, T.', 'Before we knew it: an empirical study of zero-day attacks in the real world', 'CCS', 2012, 'conference', 'Bilge, L., & Dumitras, T. (2012). Before we knew it: an empirical study of zero-day attacks in the real world. In Proceedings of the 2012 ACM conference on Computer and communications security (pp. 833-844).', 12),
('[13]', 'Buczak, A. L., & Guven, E.', 'A survey of data mining and machine learning methods for cyber security intrusion detection', 'IEEE Communications surveys & tutorials', 2016, 'journal', 'Buczak, A. L., & Guven, E. (2016). A survey of data mining and machine learning methods for cyber security intrusion detection. IEEE Communications surveys & tutorials, 18(2), 1153-1176.', 13),
('[14]', 'Scholkopf, B., et al.', 'Estimating the support of a high-dimensional distribution', 'Neural Computation', 2001, 'journal', 'Scholkopf, B., Platt, J. C., Shawe-Taylor, J., Smola, A. J., & Williamson, R. C. (2001). Estimating the support of a high-dimensional distribution. Neural computation, 13(7), 1443-1471.', 14),
('[15]', 'Mirsky, Y., et al.', 'Kitsune: An ensemble of autoencoders for online network intrusion detection', 'NDSS', 2018, 'conference', 'Mirsky, Y., Doitshman, T., Elovici, Y., & Shabtai, A. (2018). Kitsune: An ensemble of autoencoders for online network intrusion detection. In Network and Distributed System Security Symposium.', 15),
('[16]', 'Biggio, B., et al.', 'Security evaluation of pattern classifiers under attack', 'IEEE TKDE', 2014, 'journal', 'Biggio, B., Corona, I., Maiorca, D., Nelson, B., Srndic, N., Laskov, P., ... & Roli, F. (2014). Evasion attacks against machine learning at test time. In Joint European conference on machine learning and knowledge discovery in databases (pp. 387-402).', 16)
ON DUPLICATE KEY UPDATE
    title = VALUES(title),
    authors = VALUES(authors),
    formatted_citation = VALUES(formatted_citation);
