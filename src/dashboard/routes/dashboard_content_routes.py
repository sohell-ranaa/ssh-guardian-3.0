"""
SSH Guardian v3.1 - Dashboard Content Routes
API endpoints for guide steps and thesis content
"""
import sys
import io
import re
from pathlib import Path
from flask import Blueprint, jsonify, send_file
from html import unescape

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key

# Import python-docx for DOCX export
try:
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.style import WD_STYLE_TYPE
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

dashboard_content_routes = Blueprint('dashboard_content', __name__)

# Cache TTL - Extended for static content
GUIDE_CACHE_TTL = 86400  # 24 hours


# ==============================================================================
# GUIDE STEPS ENDPOINTS (v3.1 schema)
# ==============================================================================

@dashboard_content_routes.route('/guide/full', methods=['GET'])
def get_full_guide():
    """Get complete guide data including all steps - v3.1 schema"""
    try:
        cache = get_cache()
        cache_k = cache_key('guide', 'full', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # v3.1 schema: step_key, title, description, step_order, is_required, icon, action_url
        cursor.execute("""
            SELECT id, step_key, title, description, step_order, icon, action_url
            FROM guide_steps
            ORDER BY step_order ASC
        """)
        db_steps = cursor.fetchall()

        cursor.close()
        conn.close()

        # Map to frontend expected format with default content
        steps = []
        for db_step in db_steps:
            step = {
                'id': db_step['id'],
                'step_number': db_step['step_order'],
                'step_key': db_step['step_key'],
                'title': db_step['title'],
                'subtitle': db_step['description'],
                'icon': db_step['icon'] or '&#128214;',
                'content_html': _get_default_step_content(db_step['step_key']),
                'tips_html': _get_default_step_tips(db_step['step_key'])
            }
            steps.append(step)

        result = {
            'total_steps': len(steps),
            'steps': steps
        }

        cache.set(cache_k, result, GUIDE_CACHE_TTL)

        return jsonify({'success': True, 'data': result, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/guide/steps', methods=['GET'])
def get_guide_steps():
    """Get all guide steps - v3.1 schema"""
    try:
        cache = get_cache()
        cache_k = cache_key('guide', 'steps', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, step_key, title, description, step_order, icon, action_url
            FROM guide_steps
            ORDER BY step_order ASC
        """)
        db_steps = cursor.fetchall()

        cursor.close()
        conn.close()

        # Map to frontend expected format
        steps = []
        for db_step in db_steps:
            step = {
                'id': db_step['id'],
                'step_number': db_step['step_order'],
                'step_key': db_step['step_key'],
                'title': db_step['title'],
                'subtitle': db_step['description'],
                'icon': db_step['icon'] or '&#128214;',
                'content_html': _get_default_step_content(db_step['step_key']),
                'tips_html': _get_default_step_tips(db_step['step_key'])
            }
            steps.append(step)

        cache.set(cache_k, steps, GUIDE_CACHE_TTL)

        return jsonify({'success': True, 'data': steps, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# THESIS ENDPOINTS (v3.1: restored with actual database tables)
# ==============================================================================

@dashboard_content_routes.route('/thesis/full', methods=['GET'])
def get_full_thesis():
    """Get complete thesis data from database"""
    try:
        cache = get_cache()
        cache_k = cache_key('thesis', 'full', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get metadata
        cursor.execute("SELECT meta_key, meta_value FROM thesis_metadata")
        metadata_rows = cursor.fetchall()
        metadata = {row['meta_key']: row['meta_value'] for row in metadata_rows}

        # Get sections for TOC and content
        cursor.execute("""
            SELECT id, section_key, parent_key, chapter_number, title, content_html,
                   display_order, toc_level, show_in_toc, word_count
            FROM thesis_sections
            WHERE is_active = 1
            ORDER BY display_order ASC
        """)
        sections = cursor.fetchall()

        # Build TOC
        toc = [
            {
                'section_key': s['section_key'],
                'chapter_number': s['chapter_number'] or '',
                'title': s['title'],
                'toc_level': s['toc_level']
            }
            for s in sections if s['show_in_toc']
        ]

        # Get references
        cursor.execute("""
            SELECT id, ref_key, authors, title, publication, year, doi, url, ref_type, formatted_citation
            FROM thesis_references
            WHERE is_active = 1
            ORDER BY display_order ASC
        """)
        references = cursor.fetchall()

        # Calculate stats
        total_words = sum(s['word_count'] or 0 for s in sections)

        cursor.close()
        conn.close()

        result = {
            'metadata': metadata,
            'toc': toc,
            'sections': sections,
            'figures': [],
            'tables': [],
            'references': references,
            'stats': {
                'total_sections': len(sections),
                'total_figures': 0,
                'total_tables': 0,
                'total_references': len(references),
                'total_words': total_words
            }
        }

        cache.set(cache_k, result, GUIDE_CACHE_TTL)

        return jsonify({'success': True, 'data': result, 'from_cache': False})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/export/docx', methods=['GET'])
def export_thesis_docx():
    """Export thesis as DOCX file with professional formatting"""
    if not DOCX_AVAILABLE:
        return jsonify({'success': False, 'error': 'python-docx not installed'}), 500

    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get metadata
        cursor.execute("SELECT meta_key, meta_value FROM thesis_metadata")
        metadata_rows = cursor.fetchall()
        metadata = {row['meta_key']: row['meta_value'] for row in metadata_rows}

        # Get sections
        cursor.execute("""
            SELECT section_key, chapter_number, title, content_html, toc_level
            FROM thesis_sections
            WHERE is_active = 1
            ORDER BY display_order ASC
        """)
        sections = cursor.fetchall()

        # Get references
        cursor.execute("""
            SELECT authors, title, publication, year, doi, url, formatted_citation
            FROM thesis_references
            WHERE is_active = 1
            ORDER BY display_order ASC
        """)
        references = cursor.fetchall()

        cursor.close()
        conn.close()

        # Create document
        doc = Document()

        # Set up styles
        _setup_docx_styles(doc)

        # Title Page
        _add_title_page(doc, metadata)

        # Table of Contents placeholder
        doc.add_page_break()
        toc_heading = doc.add_heading('Table of Contents', level=1)
        toc_heading.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_paragraph('[Table of Contents - Update field after opening in Word]')
        doc.add_paragraph()

        # Sections
        doc.add_page_break()
        for section in sections:
            _add_section_to_docx(doc, section)

        # References
        if references:
            doc.add_page_break()
            doc.add_heading('References', level=1)
            for i, ref in enumerate(references, 1):
                citation = ref.get('formatted_citation') or _format_reference(ref)
                para = doc.add_paragraph()
                para.add_run(f'[{i}] ').bold = True
                para.add_run(citation)
                para.paragraph_format.left_indent = Inches(0.5)
                para.paragraph_format.first_line_indent = Inches(-0.5)

        # Save to buffer
        buffer = io.BytesIO()
        doc.save(buffer)
        buffer.seek(0)

        filename = f"SSH_Guardian_Thesis_{metadata.get('student_id', 'Export')}.docx"

        return send_file(
            buffer,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


def _setup_docx_styles(doc):
    """Set up document styles for professional thesis formatting"""
    # Normal style
    style = doc.styles['Normal']
    style.font.name = 'Times New Roman'
    style.font.size = Pt(12)
    style.paragraph_format.line_spacing = 1.5
    style.paragraph_format.space_after = Pt(8)

    # Heading styles
    for i in range(1, 4):
        heading_style = doc.styles[f'Heading {i}']
        heading_style.font.name = 'Times New Roman'
        heading_style.font.bold = True
        heading_style.font.color.rgb = RGBColor(0, 51, 102)
        if i == 1:
            heading_style.font.size = Pt(16)
        elif i == 2:
            heading_style.font.size = Pt(14)
        else:
            heading_style.font.size = Pt(12)


def _add_title_page(doc, metadata):
    """Add professional title page"""
    # Institution
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = para.add_run(metadata.get('institution', 'Asia Pacific University of Technology & Innovation'))
    run.font.size = Pt(14)
    run.font.bold = True

    doc.add_paragraph()
    doc.add_paragraph()

    # Title
    para = doc.add_paragraph()
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = para.add_run(metadata.get('title', 'SSH Guardian Research Thesis'))
    run.font.size = Pt(18)
    run.font.bold = True
    run.font.color.rgb = RGBColor(0, 51, 102)

    doc.add_paragraph()
    doc.add_paragraph()

    # Student info
    info_items = [
        ('Student Name', metadata.get('student_name', 'Md Sohel Rana')),
        ('Student ID', metadata.get('student_id', 'TP086217')),
        ('Module', metadata.get('module_code', 'CT095-6-M RMCE')),
        ('Supervisor', metadata.get('supervisor', 'TBD')),
        ('Degree', metadata.get('degree', 'Master of Science in Cyber Security')),
        ('Submission Date', metadata.get('submission_date', 'December 2025'))
    ]

    for label, value in info_items:
        para = doc.add_paragraph()
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        para.add_run(f'{label}: ').bold = True
        para.add_run(value)


def _add_section_to_docx(doc, section):
    """Add a thesis section to the document"""
    # Section heading
    chapter_num = section.get('chapter_number', '')
    title = section.get('title', 'Untitled')
    toc_level = section.get('toc_level', 1)

    if chapter_num:
        heading_text = f"Chapter {chapter_num}: {title}"
    else:
        heading_text = title

    doc.add_heading(heading_text, level=min(toc_level, 3))

    # Convert HTML content to plain text paragraphs
    content_html = section.get('content_html', '')
    _html_to_docx(doc, content_html)

    doc.add_paragraph()


def _html_to_docx(doc, html_content):
    """Convert HTML content to Word document paragraphs"""
    if not html_content:
        return

    # Clean up HTML
    text = html_content

    # Handle headings
    text = re.sub(r'<h3[^>]*>(.*?)</h3>', r'\n### \1\n', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<h4[^>]*>(.*?)</h4>', r'\n#### \1\n', text, flags=re.IGNORECASE | re.DOTALL)

    # Handle lists
    text = re.sub(r'<li[^>]*>(.*?)</li>', r'• \1\n', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<[ou]l[^>]*>', '', text, flags=re.IGNORECASE)
    text = re.sub(r'</[ou]l>', '\n', text, flags=re.IGNORECASE)

    # Handle paragraphs
    text = re.sub(r'<p[^>]*>(.*?)</p>', r'\1\n\n', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)

    # Handle bold/italic
    text = re.sub(r'<strong[^>]*>(.*?)</strong>', r'**\1**', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<b[^>]*>(.*?)</b>', r'**\1**', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<em[^>]*>(.*?)</em>', r'*\1*', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<i[^>]*>(.*?)</i>', r'*\1*', text, flags=re.IGNORECASE | re.DOTALL)

    # Remove remaining HTML tags
    text = re.sub(r'<[^>]+>', '', text)

    # Unescape HTML entities
    text = unescape(text)

    # Clean up whitespace
    text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)
    text = text.strip()

    # Add paragraphs to document
    for para_text in text.split('\n\n'):
        para_text = para_text.strip()
        if not para_text:
            continue

        if para_text.startswith('### '):
            doc.add_heading(para_text[4:], level=3)
        elif para_text.startswith('#### '):
            doc.add_heading(para_text[5:], level=4)
        else:
            para = doc.add_paragraph()
            # Handle bold markers
            parts = re.split(r'(\*\*.*?\*\*)', para_text)
            for part in parts:
                if part.startswith('**') and part.endswith('**'):
                    para.add_run(part[2:-2]).bold = True
                else:
                    # Handle italic markers within
                    subparts = re.split(r'(\*[^*]+\*)', part)
                    for subpart in subparts:
                        if subpart.startswith('*') and subpart.endswith('*') and len(subpart) > 2:
                            para.add_run(subpart[1:-1]).italic = True
                        else:
                            para.add_run(subpart)


def _format_reference(ref):
    """Format a reference in APA-like style"""
    parts = []
    if ref.get('authors'):
        parts.append(ref['authors'])
    if ref.get('year'):
        parts.append(f"({ref['year']})")
    if ref.get('title'):
        parts.append(ref['title'])
    if ref.get('publication'):
        parts.append(ref['publication'])
    if ref.get('doi'):
        parts.append(f"doi:{ref['doi']}")
    elif ref.get('url'):
        parts.append(ref['url'])
    return '. '.join(parts)


# ==============================================================================
# HELPER FUNCTIONS - Default Content
# ==============================================================================

def _get_default_step_content(step_key):
    """Get default HTML content for a guide step"""
    content = {
        'welcome': """
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
        """,
        'architecture': """
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
        """,
        'deployment': """
            <p>Deploy SSH Guardian agents on your cloud servers to start monitoring SSH authentication events.</p>
            <h3>Quick Installation</h3>
            <div style="background: var(--background); padding: 16px; border-radius: 8px; margin: 16px 0; overflow-x: auto; border: 1px solid var(--border);">
                <code style="color: var(--azure-blue); font-family: monospace;">curl -sSL https://ssh-guardian.rpu.solutions/install.sh | sudo bash</code>
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
        """,
        'monitoring': """
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
        """,
        'firewall': """
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
        """,
        'intelligence': """
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
        """
    }
    return content.get(step_key, '<p>Content not available for this step.</p>')


def _get_default_step_tips(step_key):
    """Get default tips for a guide step"""
    tips = {
        'welcome': 'Use the Quick Actions cards above to jump directly to key features, or continue through this guide to learn about each component.',
        'architecture': 'The architecture is designed for horizontal scalability - deploy multiple agents while centralizing monitoring in this dashboard.',
        'deployment': 'After installation, the agent appears in "Pending Approval" on the Agents page. Approve it to start receiving events.',
        'monitoring': 'Use filters to narrow events by date, type, agent, or risk level. High-risk events (score > 80) are highlighted.',
        'firewall': 'Enable Auto-Unblock with shorter durations (1-24 hours) to prevent permanent lockouts from legitimate users.',
        'intelligence': "The ML model learns your environment's baseline over time. Allow 1-2 weeks of data before relying heavily on ML scores."
    }
    return tips.get(step_key, '')


