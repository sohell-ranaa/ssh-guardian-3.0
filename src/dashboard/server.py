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
from routes.ml_routes import ml_routes
from routes.ml_training_routes import ml_training_routes
from routes.demo_routes import demo_routes
from routes.pipeline_simulation_routes import pipeline_simulation_routes
from routes.system_routes import system_routes
from routes.cache_settings_routes import cache_settings_routes
from routes.export_routes import export_routes
from routes.event_actions_routes import event_actions_routes
from routes.ip_info_routes import ip_info_routes
from routes.dashboard_content_routes import dashboard_content_routes
from routes.notification_pane_routes import notification_pane_routes
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
app.register_blueprint(ml_routes)  # ML Intelligence API
app.register_blueprint(ml_training_routes)  # ML Training API
app.register_blueprint(demo_routes, url_prefix='/api/demo')  # Demo scenarios API
app.register_blueprint(pipeline_simulation_routes, url_prefix='/api/pipeline-sim')  # Full pipeline simulation API
app.register_blueprint(system_routes, url_prefix='/api/dashboard/system')  # System status & cache API
app.register_blueprint(cache_settings_routes, url_prefix='/api/dashboard/cache-settings')  # Cache settings API
app.register_blueprint(export_routes)  # Data export API
app.register_blueprint(event_actions_routes)  # Event actions API (whitelist, watchlist, notes, reports)
app.register_blueprint(ip_info_routes)  # IP geolocation info API (FreeIPAPI)
app.register_blueprint(dashboard_content_routes, url_prefix='/api/dashboard/content')  # Dashboard content API (thesis/guide)
app.register_blueprint(notification_pane_routes, url_prefix='/api/notifications')  # Notification pane API
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


@app.errorhandler(401)
def unauthorized_error(error):
    """401 Unauthorized error handler"""
    # For API requests, return JSON
    if _is_api_request():
        return {'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}, 401

    # For browser requests, show error page
    return render_template('errors/base_error.html',
        code=401,
        title='Authentication Required',
        message='You need to sign in to access this page. Please log in with your credentials to continue.',
        icon='🔐',
        header_color='#0078D4',
        header_color_dark='#004C87',
        show_login=True,
        error_id=None,
        request_path=request.path,
        timestamp=None
    ), 401


@app.errorhandler(403)
def forbidden_error(error):
    """403 Forbidden error handler"""
    # For API requests, return JSON
    if _is_api_request():
        return {'error': 'Access forbidden', 'code': 'FORBIDDEN'}, 403

    # For browser requests, show error page
    return render_template('errors/base_error.html',
        code=403,
        title='Access Denied',
        message="You don't have permission to access this resource. Contact your administrator if you believe this is an error.",
        icon='🚫',
        header_color='#D13438',
        header_color_dark='#A52A2A',
        show_login=False,
        error_id=None,
        request_path=request.path,
        timestamp=None
    ), 403


@app.errorhandler(404)
def not_found_error(error):
    """404 Not Found error handler"""
    # For API requests, return JSON
    if _is_api_request():
        return {'error': 'Resource not found', 'code': 'NOT_FOUND'}, 404

    # For browser requests, show error page
    return render_template('errors/base_error.html',
        code=404,
        title='Page Not Found',
        message="The page you're looking for doesn't exist or has been moved. Check the URL or navigate back to the dashboard.",
        icon='🔍',
        header_color='#8764B8',
        header_color_dark='#5C4E8E',
        show_login=False,
        error_id=None,
        request_path=request.path,
        timestamp=None
    ), 404


@app.errorhandler(500)
def internal_error(error):
    """500 Internal Server error handler"""
    import uuid
    from datetime import datetime

    error_id = str(uuid.uuid4())[:8].upper()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Log the error
    print(f"❌ [ERROR {error_id}] Internal server error at {request.path}: {error}")

    # For API requests, return JSON
    if _is_api_request():
        return {'error': 'Internal server error', 'code': 'SERVER_ERROR', 'error_id': error_id}, 500

    # For browser requests, show error page
    return render_template('errors/base_error.html',
        code=500,
        title='Something Went Wrong',
        message="We encountered an unexpected error. Our team has been notified. Please try again later or contact support if the problem persists.",
        icon='⚠️',
        header_color='#D13438',
        header_color_dark='#8B0000',
        show_login=False,
        error_id=error_id,
        request_path=request.path,
        timestamp=timestamp
    ), 500


@app.errorhandler(502)
def bad_gateway_error(error):
    """502 Bad Gateway error handler"""
    if _is_api_request():
        return {'error': 'Bad gateway', 'code': 'BAD_GATEWAY'}, 502

    return render_template('errors/base_error.html',
        code=502,
        title='Bad Gateway',
        message="The server received an invalid response. This usually resolves itself. Please try again in a few moments.",
        icon='🔌',
        header_color='#FFB900',
        header_color_dark='#CC9400',
        show_login=False,
        error_id=None,
        request_path=request.path,
        timestamp=None
    ), 502


@app.errorhandler(503)
def service_unavailable_error(error):
    """503 Service Unavailable error handler"""
    if _is_api_request():
        return {'error': 'Service temporarily unavailable', 'code': 'SERVICE_UNAVAILABLE'}, 503

    return render_template('errors/base_error.html',
        code=503,
        title='Service Unavailable',
        message="The service is temporarily unavailable due to maintenance or high load. Please try again in a few minutes.",
        icon='🔧',
        header_color='#FFB900',
        header_color_dark='#CC9400',
        show_login=False,
        error_id=None,
        request_path=request.path,
        timestamp=None
    ), 503


def _is_api_request():
    """Check if request is an API call (expects JSON) or browser request"""
    # Check Accept header
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept and 'text/html' not in accept:
        return True

    # Check X-Requested-With header (AJAX requests)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return True

    # Check if request path starts with /api/
    if request.path.startswith('/api/'):
        return True

    # Check Content-Type for JSON
    content_type = request.headers.get('Content-Type', '')
    if 'application/json' in content_type:
        return True

    return False


# ==============================================================================
# CACHE CONTROL MIDDLEWARE - Universal browser cache prevention
# ==============================================================================

@app.after_request
def add_cache_control_headers(response):
    """
    Add cache control headers to all responses to prevent browser caching
    This ensures users always get fresh data from the server

    Applied to ALL routes universally to solve browser caching issues
    """
    # Only add headers if not already set
    if 'Cache-Control' not in response.headers:
        # For API routes and dynamic content - NEVER cache
        if (request.path.startswith('/api/') or
            request.path.startswith('/dashboard') or
            request.path == '/' or
            request.path.startswith('/login')):

            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

        # For static files (CSS, JS, images) - allow short caching
        elif (request.path.startswith('/static/') or
              request.path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf'))):

            # Cache static files for 1 hour, but revalidate
            response.headers['Cache-Control'] = 'public, max-age=3600, must-revalidate'

        # Default for everything else - no cache
        else:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'

    return response


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
