"""
Dashboard Content Routes - API endpoints for thesis and guide content management
"""
import sys
import json
from pathlib import Path
from flask import Blueprint, jsonify, request

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, cache_key, cache_key_hash

dashboard_content_routes = Blueprint('dashboard_content', __name__)

# Cache TTLs - Extended for static content that rarely changes
GUIDE_CACHE_TTL = 86400      # 24 hours for guide steps (rarely changes)
THESIS_CACHE_TTL = 86400     # 24 hours for thesis content (rarely changes)
METADATA_CACHE_TTL = 86400   # 24 hours for metadata (rarely changes)


def invalidate_guide_cache():
    """Invalidate all guide caches"""
    cache = get_cache()
    cache.delete_pattern('guide')


def invalidate_thesis_cache():
    """Invalidate all thesis caches"""
    cache = get_cache()
    cache.delete_pattern('thesis')


# ==============================================================================
# GUIDE STEPS ENDPOINTS
# ==============================================================================

@dashboard_content_routes.route('/guide/steps', methods=['GET'])
def get_guide_steps():
    """Get all active guide steps ordered by step number"""
    try:
        cache = get_cache()
        cache_k = cache_key('guide', 'steps', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, step_number, step_key, title, subtitle, content_html,
                   tips_html, icon, image_url, display_order
            FROM guide_steps
            WHERE is_active = TRUE
            ORDER BY step_number ASC
        """)

        steps = cursor.fetchall()
        cursor.close()
        conn.close()

        cache.set(cache_k, steps, GUIDE_CACHE_TTL)

        return jsonify({'success': True, 'data': steps, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/guide/steps/<int:step_number>', methods=['GET'])
def get_guide_step(step_number):
    """Get a specific guide step by number"""
    try:
        cache = get_cache()
        cache_k = cache_key('guide', 'step', str(step_number))
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, step_number, step_key, title, subtitle, content_html,
                   tips_html, icon, image_url
            FROM guide_steps
            WHERE step_number = %s AND is_active = TRUE
        """, (step_number,))

        step = cursor.fetchone()
        cursor.close()
        conn.close()

        if not step:
            return jsonify({'success': False, 'error': 'Step not found'}), 404

        cache.set(cache_k, step, GUIDE_CACHE_TTL)

        return jsonify({'success': True, 'data': step, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/guide/steps', methods=['POST'])
def create_guide_step():
    """Create a new guide step"""
    try:
        data = request.get_json()

        required_fields = ['step_number', 'step_key', 'title', 'content_html']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO guide_steps (step_number, step_key, title, subtitle, content_html,
                                     tips_html, icon, image_url, display_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['step_number'],
            data['step_key'],
            data['title'],
            data.get('subtitle'),
            data['content_html'],
            data.get('tips_html'),
            data.get('icon'),
            data.get('image_url'),
            data.get('display_order', data['step_number'])
        ))

        conn.commit()
        new_id = cursor.lastrowid
        cursor.close()
        conn.close()

        invalidate_guide_cache()

        return jsonify({'success': True, 'message': 'Step created', 'id': new_id})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/guide/steps/<int:step_id>', methods=['PUT'])
def update_guide_step(step_id):
    """Update a guide step"""
    try:
        data = request.get_json()

        conn = get_connection()
        cursor = conn.cursor()

        # Build dynamic update query
        updates = []
        values = []
        allowed_fields = ['step_number', 'step_key', 'title', 'subtitle', 'content_html',
                          'tips_html', 'icon', 'image_url', 'display_order', 'is_active']

        for field in allowed_fields:
            if field in data:
                updates.append(f"{field} = %s")
                values.append(data[field])

        if not updates:
            return jsonify({'success': False, 'error': 'No fields to update'}), 400

        values.append(step_id)
        query = f"UPDATE guide_steps SET {', '.join(updates)} WHERE id = %s"

        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        conn.close()

        invalidate_guide_cache()

        return jsonify({'success': True, 'message': 'Step updated'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# THESIS SECTIONS ENDPOINTS
# ==============================================================================

@dashboard_content_routes.route('/thesis/sections', methods=['GET'])
def get_thesis_sections():
    """Get all active thesis sections with optional TOC-only mode"""
    try:
        toc_only = request.args.get('toc_only', 'false').lower() == 'true'

        cache = get_cache()
        cache_k = cache_key('thesis', 'sections', f'toc_{toc_only}')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if toc_only:
            cursor.execute("""
                SELECT id, section_key, parent_key, chapter_number, title,
                       toc_level, display_order
                FROM thesis_sections
                WHERE is_active = TRUE AND show_in_toc = TRUE
                ORDER BY display_order ASC
            """)
        else:
            cursor.execute("""
                SELECT id, section_key, parent_key, chapter_number, title,
                       content_html, toc_level, display_order, word_count
                FROM thesis_sections
                WHERE is_active = TRUE
                ORDER BY display_order ASC
            """)

        sections = cursor.fetchall()
        cursor.close()
        conn.close()

        cache.set(cache_k, sections, THESIS_CACHE_TTL)

        return jsonify({'success': True, 'data': sections, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/sections/<section_key>', methods=['GET'])
def get_thesis_section(section_key):
    """Get a specific thesis section by key"""
    try:
        cache = get_cache()
        cache_k = cache_key('thesis', 'section', section_key)
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, section_key, parent_key, chapter_number, title,
                   content_html, toc_level, display_order, word_count
            FROM thesis_sections
            WHERE section_key = %s AND is_active = TRUE
        """, (section_key,))

        section = cursor.fetchone()

        # Also get related figures and tables
        if section:
            cursor.execute("""
                SELECT id, figure_key, figure_number, caption, figure_type,
                       image_url, svg_content, chart_config, code_content,
                       code_language, width
                FROM thesis_figures
                WHERE section_key = %s AND is_active = TRUE
                ORDER BY display_order ASC
            """, (section_key,))
            section['figures'] = cursor.fetchall()

            cursor.execute("""
                SELECT id, table_key, table_number, caption, headers,
                       row_data, footer_html
                FROM thesis_tables
                WHERE section_key = %s AND is_active = TRUE
                ORDER BY display_order ASC
            """, (section_key,))
            tables = cursor.fetchall()
            # Parse JSON fields
            for t in tables:
                if t['headers']:
                    t['headers'] = json.loads(t['headers']) if isinstance(t['headers'], str) else t['headers']
                if t['row_data']:
                    t['row_data'] = json.loads(t['row_data']) if isinstance(t['row_data'], str) else t['row_data']
            section['tables'] = tables

        cursor.close()
        conn.close()

        if not section:
            return jsonify({'success': False, 'error': 'Section not found'}), 404

        cache.set(cache_k, section, THESIS_CACHE_TTL)

        return jsonify({'success': True, 'data': section, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/sections', methods=['POST'])
def create_thesis_section():
    """Create a new thesis section"""
    try:
        data = request.get_json()

        required_fields = ['section_key', 'title', 'content_html']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        # Calculate word count
        import re
        content = re.sub(r'<[^>]+>', '', data['content_html'])
        word_count = len(content.split())

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO thesis_sections (section_key, parent_key, chapter_number, title,
                                         content_html, toc_level, show_in_toc, display_order, word_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['section_key'],
            data.get('parent_key'),
            data.get('chapter_number'),
            data['title'],
            data['content_html'],
            data.get('toc_level', 1),
            data.get('show_in_toc', True),
            data.get('display_order', 0),
            word_count
        ))

        conn.commit()
        new_id = cursor.lastrowid
        cursor.close()
        conn.close()

        invalidate_thesis_cache()

        return jsonify({'success': True, 'message': 'Section created', 'id': new_id})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/sections/<int:section_id>', methods=['PUT'])
def update_thesis_section(section_id):
    """Update a thesis section"""
    try:
        data = request.get_json()

        conn = get_connection()
        cursor = conn.cursor()

        updates = []
        values = []
        allowed_fields = ['section_key', 'parent_key', 'chapter_number', 'title',
                          'content_html', 'toc_level', 'show_in_toc', 'display_order', 'is_active']

        for field in allowed_fields:
            if field in data:
                updates.append(f"{field} = %s")
                values.append(data[field])

        # Recalculate word count if content changed
        if 'content_html' in data:
            import re
            content = re.sub(r'<[^>]+>', '', data['content_html'])
            word_count = len(content.split())
            updates.append("word_count = %s")
            values.append(word_count)

        if not updates:
            return jsonify({'success': False, 'error': 'No fields to update'}), 400

        values.append(section_id)
        query = f"UPDATE thesis_sections SET {', '.join(updates)} WHERE id = %s"

        cursor.execute(query, values)
        conn.commit()
        cursor.close()
        conn.close()

        invalidate_thesis_cache()

        return jsonify({'success': True, 'message': 'Section updated'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# THESIS FIGURES ENDPOINTS
# ==============================================================================

@dashboard_content_routes.route('/thesis/figures', methods=['GET'])
def get_thesis_figures():
    """Get all thesis figures"""
    try:
        section_key = request.args.get('section_key')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if section_key:
            cursor.execute("""
                SELECT id, figure_key, section_key, figure_number, caption, alt_text,
                       figure_type, image_url, svg_content, chart_config,
                       code_content, code_language, width
                FROM thesis_figures
                WHERE section_key = %s AND is_active = TRUE
                ORDER BY display_order ASC
            """, (section_key,))
        else:
            cursor.execute("""
                SELECT id, figure_key, section_key, figure_number, caption, alt_text,
                       figure_type, image_url, svg_content, chart_config,
                       code_content, code_language, width
                FROM thesis_figures
                WHERE is_active = TRUE
                ORDER BY figure_number ASC
            """)

        figures = cursor.fetchall()

        # Parse chart_config JSON
        for fig in figures:
            if fig['chart_config']:
                fig['chart_config'] = json.loads(fig['chart_config']) if isinstance(fig['chart_config'], str) else fig['chart_config']

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'data': figures})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/figures', methods=['POST'])
def create_thesis_figure():
    """Create a new thesis figure"""
    try:
        data = request.get_json()

        required_fields = ['figure_key', 'figure_number', 'caption', 'figure_type']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        chart_config = json.dumps(data.get('chart_config')) if data.get('chart_config') else None

        cursor.execute("""
            INSERT INTO thesis_figures (figure_key, section_key, figure_number, caption, alt_text,
                                        figure_type, image_url, svg_content, chart_config,
                                        code_content, code_language, width, display_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['figure_key'],
            data.get('section_key'),
            data['figure_number'],
            data['caption'],
            data.get('alt_text'),
            data['figure_type'],
            data.get('image_url'),
            data.get('svg_content'),
            chart_config,
            data.get('code_content'),
            data.get('code_language'),
            data.get('width', '100%'),
            data.get('display_order', 0)
        ))

        conn.commit()
        new_id = cursor.lastrowid
        cursor.close()
        conn.close()

        invalidate_thesis_cache()

        return jsonify({'success': True, 'message': 'Figure created', 'id': new_id})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# THESIS TABLES ENDPOINTS
# ==============================================================================

@dashboard_content_routes.route('/thesis/tables', methods=['GET'])
def get_thesis_tables():
    """Get all thesis tables"""
    try:
        section_key = request.args.get('section_key')

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if section_key:
            cursor.execute("""
                SELECT id, table_key, section_key, table_number, caption,
                       headers, row_data, footer_html
                FROM thesis_tables
                WHERE section_key = %s AND is_active = TRUE
                ORDER BY display_order ASC
            """, (section_key,))
        else:
            cursor.execute("""
                SELECT id, table_key, section_key, table_number, caption,
                       headers, row_data, footer_html
                FROM thesis_tables
                WHERE is_active = TRUE
                ORDER BY table_number ASC
            """)

        tables = cursor.fetchall()

        # Parse JSON fields
        for t in tables:
            if t['headers']:
                t['headers'] = json.loads(t['headers']) if isinstance(t['headers'], str) else t['headers']
            if t['row_data']:
                t['row_data'] = json.loads(t['row_data']) if isinstance(t['row_data'], str) else t['row_data']

        cursor.close()
        conn.close()

        return jsonify({'success': True, 'data': tables})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/tables', methods=['POST'])
def create_thesis_table():
    """Create a new thesis table"""
    try:
        data = request.get_json()

        required_fields = ['table_key', 'table_number', 'caption', 'headers', 'row_data']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO thesis_tables (table_key, section_key, table_number, caption,
                                       headers, row_data, footer_html, display_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['table_key'],
            data.get('section_key'),
            data['table_number'],
            data['caption'],
            json.dumps(data['headers']),
            json.dumps(data['row_data']),
            data.get('footer_html'),
            data.get('display_order', 0)
        ))

        conn.commit()
        new_id = cursor.lastrowid
        cursor.close()
        conn.close()

        invalidate_thesis_cache()

        return jsonify({'success': True, 'message': 'Table created', 'id': new_id})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# THESIS REFERENCES ENDPOINTS
# ==============================================================================

@dashboard_content_routes.route('/thesis/references', methods=['GET'])
def get_thesis_references():
    """Get all thesis references"""
    try:
        cache = get_cache()
        cache_k = cache_key('thesis', 'references', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT id, ref_key, authors, title, publication, year, volume, issue,
                   pages, doi, url, accessed_date, ref_type, formatted_citation
            FROM thesis_references
            WHERE is_active = TRUE
            ORDER BY display_order ASC, ref_key ASC
        """)

        references = cursor.fetchall()
        cursor.close()
        conn.close()

        cache.set(cache_k, references, THESIS_CACHE_TTL)

        return jsonify({'success': True, 'data': references, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/references', methods=['POST'])
def create_thesis_reference():
    """Create a new thesis reference"""
    try:
        data = request.get_json()

        required_fields = ['ref_key', 'authors', 'title']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'{field} is required'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO thesis_references (ref_key, authors, title, publication, year, volume,
                                           issue, pages, doi, url, accessed_date, ref_type,
                                           formatted_citation, display_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            data['ref_key'],
            data['authors'],
            data['title'],
            data.get('publication'),
            data.get('year'),
            data.get('volume'),
            data.get('issue'),
            data.get('pages'),
            data.get('doi'),
            data.get('url'),
            data.get('accessed_date'),
            data.get('ref_type', 'other'),
            data.get('formatted_citation'),
            data.get('display_order', 0)
        ))

        conn.commit()
        new_id = cursor.lastrowid
        cursor.close()
        conn.close()

        invalidate_thesis_cache()

        return jsonify({'success': True, 'message': 'Reference created', 'id': new_id})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# THESIS METADATA ENDPOINTS
# ==============================================================================

@dashboard_content_routes.route('/thesis/metadata', methods=['GET'])
def get_thesis_metadata():
    """Get all thesis metadata"""
    try:
        cache = get_cache()
        cache_k = cache_key('thesis', 'metadata', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT meta_key, meta_value, meta_type FROM thesis_metadata")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        # Convert to dictionary
        metadata = {}
        for row in rows:
            value = row['meta_value']
            if row['meta_type'] == 'json':
                value = json.loads(value)
            metadata[row['meta_key']] = value

        cache.set(cache_k, metadata, METADATA_CACHE_TTL)

        return jsonify({'success': True, 'data': metadata, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/metadata/<meta_key>', methods=['PUT'])
def update_thesis_metadata(meta_key):
    """Update a thesis metadata value"""
    try:
        data = request.get_json()

        if 'meta_value' not in data:
            return jsonify({'success': False, 'error': 'meta_value is required'}), 400

        conn = get_connection()
        cursor = conn.cursor()

        meta_value = data['meta_value']
        meta_type = data.get('meta_type', 'text')

        if meta_type == 'json' and not isinstance(meta_value, str):
            meta_value = json.dumps(meta_value)

        cursor.execute("""
            INSERT INTO thesis_metadata (meta_key, meta_value, meta_type)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE meta_value = VALUES(meta_value), meta_type = VALUES(meta_type)
        """, (meta_key, meta_value, meta_type))

        conn.commit()
        cursor.close()
        conn.close()

        # Invalidate cache
        cache = get_cache()
        cache.delete_pattern('thesis:metadata')

        return jsonify({'success': True, 'message': f'Metadata {meta_key} updated'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ==============================================================================
# FULL CONTENT ENDPOINTS (Combined data for frontend)
# ==============================================================================

@dashboard_content_routes.route('/guide/full', methods=['GET'])
def get_full_guide():
    """Get complete guide data including all steps and metadata"""
    try:
        cache = get_cache()
        cache_k = cache_key('guide', 'full', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get all guide steps
        cursor.execute("""
            SELECT id, step_number, step_key, title, subtitle, content_html,
                   tips_html, icon, image_url
            FROM guide_steps
            WHERE is_active = TRUE
            ORDER BY step_number ASC
        """)
        steps = cursor.fetchall()

        cursor.close()
        conn.close()

        result = {
            'total_steps': len(steps),
            'steps': steps
        }

        cache.set(cache_k, result, GUIDE_CACHE_TTL)

        return jsonify({'success': True, 'data': result, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@dashboard_content_routes.route('/thesis/full', methods=['GET'])
def get_full_thesis():
    """Get complete thesis data including all sections, figures, tables, and references"""
    try:
        cache = get_cache()
        cache_k = cache_key('thesis', 'full', 'all')
        cached = cache.get(cache_k)
        if cached is not None:
            return jsonify({'success': True, 'data': cached, 'from_cache': True})

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get metadata
        cursor.execute("SELECT meta_key, meta_value, meta_type FROM thesis_metadata")
        meta_rows = cursor.fetchall()
        metadata = {}
        for row in meta_rows:
            value = row['meta_value']
            if row['meta_type'] == 'json':
                value = json.loads(value)
            metadata[row['meta_key']] = value

        # Get all sections
        cursor.execute("""
            SELECT id, section_key, parent_key, chapter_number, title,
                   content_html, toc_level, display_order, word_count
            FROM thesis_sections
            WHERE is_active = TRUE
            ORDER BY display_order ASC
        """)
        sections = cursor.fetchall()

        # Get TOC
        cursor.execute("""
            SELECT section_key, chapter_number, title, toc_level
            FROM thesis_sections
            WHERE is_active = TRUE AND show_in_toc = TRUE
            ORDER BY display_order ASC
        """)
        toc = cursor.fetchall()

        # Get all figures
        cursor.execute("""
            SELECT id, figure_key, section_key, figure_number, caption, alt_text,
                   figure_type, image_url, svg_content, chart_config,
                   code_content, code_language, width
            FROM thesis_figures
            WHERE is_active = TRUE
            ORDER BY display_order ASC
        """)
        figures = cursor.fetchall()
        for fig in figures:
            if fig['chart_config']:
                fig['chart_config'] = json.loads(fig['chart_config']) if isinstance(fig['chart_config'], str) else fig['chart_config']

        # Get all tables
        cursor.execute("""
            SELECT id, table_key, section_key, table_number, caption,
                   headers, row_data, footer_html
            FROM thesis_tables
            WHERE is_active = TRUE
            ORDER BY display_order ASC
        """)
        tables = cursor.fetchall()
        for t in tables:
            if t['headers']:
                t['headers'] = json.loads(t['headers']) if isinstance(t['headers'], str) else t['headers']
            if t['row_data']:
                t['row_data'] = json.loads(t['row_data']) if isinstance(t['row_data'], str) else t['row_data']

        # Get all references
        cursor.execute("""
            SELECT id, ref_key, authors, title, publication, year, volume, issue,
                   pages, doi, url, accessed_date, ref_type, formatted_citation
            FROM thesis_references
            WHERE is_active = TRUE
            ORDER BY display_order ASC, ref_key ASC
        """)
        references = cursor.fetchall()

        cursor.close()
        conn.close()

        # Calculate total word count
        total_words = sum(s['word_count'] or 0 for s in sections)

        result = {
            'metadata': metadata,
            'toc': toc,
            'sections': sections,
            'figures': figures,
            'tables': tables,
            'references': references,
            'stats': {
                'total_sections': len(sections),
                'total_figures': len(figures),
                'total_tables': len(tables),
                'total_references': len(references),
                'total_words': total_words
            }
        }

        cache.set(cache_k, result, THESIS_CACHE_TTL)

        return jsonify({'success': True, 'data': result, 'from_cache': False})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
