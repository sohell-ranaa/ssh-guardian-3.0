#!/usr/bin/env python3
"""
Script to refactor dashboard.html into modular components
"""

import re
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DASHBOARD_FILE = PROJECT_ROOT / "src/dashboard/templates/dashboard.html"
STATIC_DIR = PROJECT_ROOT / "src/dashboard/static"
TEMPLATES_DIR = PROJECT_ROOT / "src/dashboard/templates"

def extract_css():
    """Extract CSS to separate file"""
    with open(DASHBOARD_FILE, 'r') as f:
        content = f.read()

    # Extract CSS between <style> and </style>
    css_match = re.search(r'<style>(.*?)</style>', content, re.DOTALL)
    if css_match:
        css_content = css_match.group(1).strip()

        css_file = STATIC_DIR / "css" / "dashboard.css"
        with open(css_file, 'w') as f:
            f.write(css_content)
        print(f"✅ Extracted CSS to {css_file}")
        return css_content
    return None

def extract_javascript_sections():
    """Extract JavaScript sections"""
    with open(DASHBOARD_FILE, 'r') as f:
        content = f.read()

    # Extract JavaScript between <script> and </script>
    js_match = re.search(r'<script>(.*?)</script>', content, re.DOTALL)
    if js_match:
        js_content = js_match.group(1).strip()

        # Split into logical modules
        modules = {
            'navigation': extract_navigation_js(js_content),
            'events': extract_events_js(js_content),
            'blocking': extract_blocking_js(js_content),
            'agents': create_agents_js(),
            'main': extract_main_js(js_content)
        }

        for module_name, module_content in modules.items():
            if module_content:
                js_file = STATIC_DIR / "js" / "modules" / f"{module_name}.js"
                with open(js_file, 'w') as f:
                    f.write(module_content)
                print(f"✅ Created {js_file}")

        return modules
    return None

def extract_navigation_js(js_content):
    """Extract navigation-related JavaScript"""
    # Find navigation functions
    nav_functions = []

    # Navigation initialization
    if 'toggleSidebar' in js_content:
        match = re.search(r'(function toggleSidebar.*?})', js_content, re.DOTALL)
        if match:
            nav_functions.append(match.group(1))

    # Submenu handling
    if 'data-submenu' in js_content:
        match = re.search(r'(document\.querySelectorAll.*?data-submenu.*?}\);)', js_content, re.DOTALL)
        if match:
            nav_functions.append(match.group(1))

    return '\n\n'.join(nav_functions) if nav_functions else None

def extract_events_js(js_content):
    """Extract events-related JavaScript"""
    # Find event loading functions
    if 'loadEvents' in js_content or 'Live Events' in js_content:
        match = re.search(r'(// Live Events.*?// End Live Events)', js_content, re.DOTALL)
        if match:
            return match.group(1)
    return "// Events module - extracted from main dashboard\n"

def extract_blocking_js(js_content):
    """Extract blocking-related JavaScript"""
    # Find blocking functions
    if 'loadBlocks' in js_content or 'quickBlock' in js_content:
        parts = []

        # Load blocks function
        match = re.search(r'(async function loadBlocks.*?})', js_content, re.DOTALL)
        if match:
            parts.append(match.group(1))

        # Quick block function
        match = re.search(r'(async function quickBlock.*?})', js_content, re.DOTALL)
        if match:
            parts.append(match.group(1))

        # Quick unblock function
        match = re.search(r'(async function quickUnblock.*?})', js_content, re.DOTALL)
        if match:
            parts.append(match.group(1))

        return '\n\n'.join(parts) if parts else None
    return "// Blocking module - extracted from main dashboard\n"

def create_agents_js():
    """Create new agents module"""
    return """// Agent Management Module

async function loadAgents() {
    try {
        const response = await fetch('/api/agents/list');
        const data = await response.json();

        if (data.success) {
            displayAgents(data.agents);
        }
    } catch (error) {
        console.error('Error loading agents:', error);
    }
}

function displayAgents(agents) {
    const container = document.getElementById('agents-container');
    if (!container) return;

    if (agents.length === 0) {
        container.innerHTML = '<div class="empty-state">No agents registered</div>';
        return;
    }

    const html = agents.map(agent => `
        <div class="agent-card ${agent.status}">
            <div class="agent-header">
                <h3>${agent.hostname}</h3>
                <span class="agent-status ${agent.status}">${agent.status}</span>
            </div>
            <div class="agent-details">
                <p><strong>Agent ID:</strong> ${agent.agent_id}</p>
                <p><strong>Last Heartbeat:</strong> ${agent.last_heartbeat || 'Never'}</p>
                <p><strong>Events Sent:</strong> ${agent.total_events_sent}</p>
                <p><strong>Health:</strong> ${agent.health_status}</p>
            </div>
            <div class="agent-actions">
                ${!agent.is_approved ? `<button onclick="approveAgent(${agent.id})" class="btn-primary">Approve</button>` : ''}
                ${agent.is_active ? `<button onclick="deactivateAgent(${agent.id})" class="btn-secondary">Deactivate</button>` : ''}
            </div>
        </div>
    `).join('');

    container.innerHTML = html;
}

async function approveAgent(agentId) {
    if (!confirm('Approve this agent?')) return;

    try {
        const response = await fetch(`/api/agents/${agentId}/approve`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            alert('Agent approved successfully');
            loadAgents();
            loadAgentStats();
        } else {
            alert('Failed to approve agent: ' + data.error);
        }
    } catch (error) {
        console.error('Error approving agent:', error);
        alert('Error approving agent');
    }
}

async function deactivateAgent(agentId) {
    if (!confirm('Deactivate this agent?')) return;

    try {
        const response = await fetch(`/api/agents/${agentId}/deactivate`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            alert('Agent deactivated successfully');
            loadAgents();
            loadAgentStats();
        } else {
            alert('Failed to deactivate agent: ' + data.error);
        }
    } catch (error) {
        console.error('Error deactivating agent:', error);
        alert('Error deactivating agent');
    }
}

async function loadAgentStats() {
    try {
        const response = await fetch('/api/agents/stats');
        const data = await response.json();

        if (data.success) {
            displayAgentStats(data.stats);
        }
    } catch (error) {
        console.error('Error loading agent stats:', error);
    }
}

function displayAgentStats(stats) {
    const container = document.getElementById('agent-stats');
    if (!container) return;

    container.innerHTML = `
        <div class="stat-card">
            <div class="stat-label">Total Agents</div>
            <div class="stat-value">${stats.total_agents}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Online</div>
            <div class="stat-value">${stats.online_agents}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Active</div>
            <div class="stat-value">${stats.active_agents}</div>
        </div>
        <div class="stat-card">
            <div class="stat-label">Approved</div>
            <div class="stat-value">${stats.approved_agents}</div>
        </div>
    `;
}

// Initialize agents page when loaded
if (document.getElementById('page-agents')) {
    loadAgents();
    loadAgentStats();

    // Auto-refresh every 30 seconds
    setInterval(() => {
        loadAgents();
        loadAgentStats();
    }, 30000);
}
"""

def extract_main_js(js_content):
    """Extract main app initialization"""
    # Get page routing and initialization code
    parts = []

    # Show page function
    match = re.search(r'(function showPage.*?})', js_content, re.DOTALL)
    if match:
        parts.append(match.group(1))

    # Init function
    match = re.search(r'(function init.*?})', js_content, re.DOTALL)
    if match:
        parts.append(match.group(1))

    # DOMContentLoaded
    match = re.search(r'(document\.addEventListener.*?DOMContentLoaded.*?}\);)', js_content, re.DOTALL)
    if match:
        parts.append(match.group(1))

    return '\n\n'.join(parts) if parts else "// Main initialization\n"

def create_agents_page_html():
    """Create agents page HTML"""
    html = """            <!-- Agents Page -->
            <div id="page-agents" class="page-content" style="display: none;">
                <div class="page-header">
                    <h1 class="page-title">Agent Management</h1>
                    <p class="page-subtitle">Monitor and manage SSH Guardian agents</p>
                </div>

                <div class="stats-grid" id="agent-stats">
                    <!-- Stats loaded by JavaScript -->
                </div>

                <div class="card">
                    <div class="card-title">Registered Agents</div>
                    <div id="agents-container">
                        <!-- Agents loaded by JavaScript -->
                    </div>
                </div>
            </div>
"""
    return html

def main():
    print("🔄 Refactoring dashboard.html into modular components...")
    print("="*70)

    # Create directories if needed
    (STATIC_DIR / "css").mkdir(parents=True, exist_ok=True)
    (STATIC_DIR / "js" / "modules").mkdir(parents=True, exist_ok=True)
    (TEMPLATES_DIR / "pages").mkdir(parents=True, exist_ok=True)

    # Extract CSS
    print("\n📝 Extracting CSS...")
    css_content = extract_css()

    # Extract JavaScript modules
    print("\n📝 Extracting JavaScript modules...")
    js_modules = extract_javascript_sections()

    # Create agents page HTML
    print("\n📝 Creating agents page HTML...")
    agents_html = create_agents_page_html()
    agents_file = TEMPLATES_DIR / "pages" / "agents.html"
    with open(agents_file, 'w') as f:
        f.write(agents_html)
    print(f"✅ Created {agents_file}")

    print("\n" + "="*70)
    print("✅ Refactoring complete!")
    print("\nNext steps:")
    print("1. Update dashboard.html to use <link> and <script> tags")
    print("2. Test the modular dashboard")
    print("3. Add agent management page")

if __name__ == "__main__":
    main()
