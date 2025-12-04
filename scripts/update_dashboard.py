#!/usr/bin/env python3
"""
Update dashboard.html to use modular CSS/JS and add agents page
"""

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DASHBOARD_FILE = PROJECT_ROOT / "src/dashboard/templates/dashboard.html"
BACKUP_FILE = PROJECT_ROOT / "src/dashboard/templates/dashboard.html.backup"

def backup_dashboard():
    """Create backup of original dashboard"""
    with open(DASHBOARD_FILE, 'r') as f:
        content = f.read()
    with open(BACKUP_FILE, 'w') as f:
        f.write(content)
    print(f"✅ Backup created: {BACKUP_FILE}")

def replace_inline_css_with_link():
    """Replace inline <style> with <link> to CSS file"""
    with open(DASHBOARD_FILE, 'r') as f:
        content = f.read()

    # Replace <style>...</style> with <link>
    new_content = re.sub(
        r'<style>.*?</style>',
        '<link rel="stylesheet" href="/static/css/dashboard.css">',
        content,
        flags=re.DOTALL
    )

    return new_content

def replace_inline_js_with_scripts(content):
    """Replace inline <script> with external <script> tags"""
    # Replace <script>...</script> with multiple <script src="...">
    new_content = re.sub(
        r'<script>.*?</script>',
        '''<script src="/static/js/modules/navigation.js"></script>
    <script src="/static/js/modules/events.js"></script>
    <script src="/static/js/modules/blocking.js"></script>
    <script src="/static/js/modules/agents.js"></script>
    <script src="/static/js/modules/main.js"></script>''',
        content,
        flags=re.DOTALL
    )

    return new_content

def insert_agents_page(content):
    """Insert agents page HTML into the dashboard"""
    # Find where to insert (after Live Events page, before Blocked IPs)
    # Look for the Live Events page closing tag
    insert_marker = '</div>\n\n            <!-- Blocked IPs Page -->'

    if insert_marker in content:
        # Read agents page HTML
        agents_page_file = PROJECT_ROOT / "src/dashboard/templates/pages/agents.html"
        with open(agents_page_file, 'r') as f:
            agents_html = f.read()

        # Insert agents page
        new_content = content.replace(
            insert_marker,
            f'</div>\n\n{agents_html}\n\n            <!-- Blocked IPs Page -->'
        )

        print("✅ Inserted agents page HTML")
        return new_content
    else:
        print("⚠️  Could not find insertion point for agents page")
        return content

def main():
    print("🔄 Updating dashboard.html to use modular structure...")
    print("="*70)

    # Step 1: Backup
    print("\n1️⃣  Creating backup...")
    backup_dashboard()

    # Step 2: Replace inline CSS
    print("\n2️⃣  Replacing inline CSS with external stylesheet...")
    content = replace_inline_css_with_link()
    print("✅ CSS replaced with <link> tag")

    # Step 3: Replace inline JavaScript
    print("\n3️⃣  Replacing inline JavaScript with external scripts...")
    content = replace_inline_js_with_scripts(content)
    print("✅ JavaScript replaced with <script> tags")

    # Step 4: Insert agents page
    print("\n4️⃣  Inserting agents page...")
    content = insert_agents_page(content)

    # Step 5: Write updated dashboard
    print("\n5️⃣  Writing updated dashboard...")
    with open(DASHBOARD_FILE, 'w') as f:
        f.write(content)
    print(f"✅ Updated {DASHBOARD_FILE}")

    # Calculate size reduction
    with open(BACKUP_FILE, 'r') as f:
        original_size = len(f.read())
    new_size = len(content)
    reduction = original_size - new_size
    reduction_pct = (reduction / original_size) * 100

    print("\n" + "="*70)
    print("✅ Dashboard refactoring complete!")
    print(f"\nOriginal size: {original_size:,} bytes")
    print(f"New size: {new_size:,} bytes")
    print(f"Reduction: {reduction:,} bytes ({reduction_pct:.1f}%)")
    print(f"\nBackup saved to: {BACKUP_FILE}")

if __name__ == "__main__":
    main()
