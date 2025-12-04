#!/usr/bin/env python3
"""
Split dashboard.css into component-specific CSS files
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
CSS_DIR = PROJECT_ROOT / "src/dashboard/static/css"
DASHBOARD_CSS = CSS_DIR / "dashboard.css"

# Create components directory
COMPONENTS_DIR = CSS_DIR / "components"
COMPONENTS_DIR.mkdir(exist_ok=True)

def split_css():
    """Split CSS file into component-specific files"""

    with open(DASHBOARD_CSS, 'r') as f:
        content = f.read()

    # Define CSS sections
    sections = {
        'variables.css': (1, 28),  # Root variables and body
        'topbar.css': (29, 127),  # Top bar styles
        'sidebar.css': (128, 233),  # Sidebar styles
        'layout.css': (234, 254),  # Main content layout
        'page-header.css': (255, 270),  # Page header
        'tabs.css': (271, 311),  # Tabs component
        'cards.css': (312, 326),  # Card component
        'stats.css': (327, 361),  # Stats grid
        'scrollbar.css': (362, 378),  # Custom scrollbar
    }

    lines = content.splitlines(keepends=True)

    # Extract each section
    for filename, (start, end) in sections.items():
        section_content = ''.join(lines[start-1:end])
        output_file = COMPONENTS_DIR / filename
        with open(output_file, 'w') as f:
            f.write(section_content)
        print(f"✅ Created {output_file.name} ({end-start+1} lines)")

    # Create main CSS file that imports all components
    main_css = """/* SSH Guardian v3.0 - Main Stylesheet */
/* This file imports all component stylesheets */

@import url('components/variables.css');
@import url('components/topbar.css');
@import url('components/sidebar.css');
@import url('components/layout.css');
@import url('components/page-header.css');
@import url('components/tabs.css');
@import url('components/cards.css');
@import url('components/stats.css');
@import url('components/scrollbar.css');
"""

    main_css_file = CSS_DIR / "dashboard-modular.css"
    with open(main_css_file, 'w') as f:
        f.write(main_css)

    print(f"\n✅ Created {main_css_file.name} (imports all components)")

    # Backup original
    backup_file = CSS_DIR / "dashboard.css.backup"
    with open(DASHBOARD_CSS, 'r') as f:
        content = f.read()
    with open(backup_file, 'w') as f:
        f.write(content)
    print(f"✅ Backup created: {backup_file.name}")

    print("\n" + "="*70)
    print("✅ CSS splitting complete!")
    print("\nNew structure:")
    print("  css/")
    print("  ├── dashboard.css (original - 378 lines)")
    print("  ├── dashboard-modular.css (new - imports all components)")
    print("  └── components/")
    for filename in sections.keys():
        print(f"      ├── {filename}")

    print("\nTo use modular CSS, update dashboard.html:")
    print('  <link rel="stylesheet" href="/static/css/dashboard-modular.css">')

if __name__ == "__main__":
    split_css()
