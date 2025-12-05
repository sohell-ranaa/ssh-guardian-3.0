"""
SSH Guardian v3.0 - Dashboard Server
Main Flask application with authentication
"""

import os
import sys
from pathlib import Path
from flask import Flask, render_template, redirect, url_for, request
from dotenv import load_dotenv

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))
sys.path.append(str(PROJECT_ROOT / "src" / "api"))
sys.path.append(str(PROJECT_ROOT / "dbs"))

# Load environment variables
load_dotenv(PROJECT_ROOT / ".env")

# Import routes
from routes.auth_routes import auth_bp
from routes.events_routes import events_routes
from routes.blocking_routes import blocking_routes
from routes.agents import agent_routes  # Updated to use modular package
from routes.geoip_routes import geoip_routes
from routes.threat_intel_routes import threat_intel_routes
from routes.ip_stats_routes import ip_stats_routes
from routes.events_analysis_routes import events_analysis_routes
from routes.settings_routes import settings_routes
from routes.integrations_routes import integrations_routes
from routes.api_keys_routes import api_keys_routes
from routes.users_routes import users_routes
from routes.audit_routes import audit_routes
from routes.notification_rules_routes import notification_rules_routes
from routes.notification_history_routes import notification_history_routes
from routes.notification_channels_routes import notification_channels_routes
from routes.daily_reports_routes import daily_reports_routes
from routes.trends_reports_routes import trends_reports_routes
from routes.simulation_routes import simulation_routes
from auth import SessionManager, login_required

# Import API blueprints
sys.path.insert(0, str(PROJECT_ROOT / "src" / "api"))
from events_api import events_api

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24).hex())

# Configuration
app.config['SESSION_COOKIE_NAME'] = 'ssh_guardian_session'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 2592000  # 30 days in seconds

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(events_routes)  # Dashboard events API
app.register_blueprint(blocking_routes)  # Blocking management API
app.register_blueprint(agent_routes, url_prefix='/api')  # Agent management API
app.register_blueprint(geoip_routes)  # GeoIP lookup API
app.register_blueprint(threat_intel_routes)  # Threat Intelligence API
app.register_blueprint(ip_stats_routes, url_prefix='/api/dashboard/ip-stats')  # IP Statistics API
app.register_blueprint(events_analysis_routes, url_prefix='/api/dashboard/events-analysis')  # Events Analysis API
app.register_blueprint(settings_routes, url_prefix='/api/dashboard/settings')  # Settings API
app.register_blueprint(integrations_routes, url_prefix='/api/dashboard/integrations')  # Integrations API
app.register_blueprint(api_keys_routes, url_prefix='/api/dashboard/api-keys')  # API Keys management
app.register_blueprint(users_routes, url_prefix='/api/dashboard/users')  # Users management
app.register_blueprint(audit_routes, url_prefix='/api/dashboard/audit')  # Audit logs
app.register_blueprint(notification_rules_routes, url_prefix='/api/dashboard/notification-rules')  # Notification rules
app.register_blueprint(notification_history_routes, url_prefix='/api/dashboard/notification-history')  # Notification history
app.register_blueprint(notification_channels_routes, url_prefix='/api/dashboard/notification-channels')  # Notification channels
app.register_blueprint(daily_reports_routes, url_prefix='/api/dashboard/daily-reports')  # Daily reports
app.register_blueprint(trends_reports_routes, url_prefix='/api/dashboard/trends-reports')  # Trends reports
app.register_blueprint(simulation_routes, url_prefix='/api/simulation')  # Simulation API
app.register_blueprint(events_api)  # API for agent event submission


@app.route('/')
def index():
    """Root route - redirect to dashboard or login"""
    session_token = request.cookies.get('session_token')

    if session_token:
        session_data = SessionManager.validate_session(session_token)
        if session_data:
            return redirect(url_for('dashboard'))

    return redirect(url_for('login'))


@app.route('/login')
def login():
    """Login page"""
    # Check if already logged in
    session_token = request.cookies.get('session_token')

    if session_token:
        session_data = SessionManager.validate_session(session_token)
        if session_data:
            return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard_modular.html')


@app.route('/agents-test')
def agents_test():
    """Agent management test page"""
    with open('/tmp/test_agents_api.html', 'r') as f:
        return f.read()


@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return redirect(url_for('index'))


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return {'error': 'Internal server error'}, 500


# Health check endpoint
@app.route('/health')
def health():
    """Health check endpoint"""
    from dbs.connection import test_connection

    try:
        db_healthy = test_connection()
        return {
            'status': 'healthy' if db_healthy else 'degraded',
            'version': '3.0.0',
            'database': 'connected' if db_healthy else 'disconnected'
        }, 200 if db_healthy else 503
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e)
        }, 503


if __name__ == '__main__':
    print("=" * 70)
    print("🚀 SSH GUARDIAN v3.0 - DASHBOARD SERVER")
    print("=" * 70)
    print(f"Environment: {os.getenv('ENVIRONMENT', 'development')}")
    print(f"Port: 8081")
    print(f"Database: ssh_guardian_v3")
    print("=" * 70)
    print("✅ Server starting...")
    print("📍 Access at: http://localhost:8081")
    print("=" * 70)

    # Run Flask development server
    app.run(
        host='0.0.0.0',
        port=8081,  # v3 uses port 8081 (v2 uses 8080)
        debug=True,
        threaded=True
    )
