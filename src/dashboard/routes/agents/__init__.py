"""
SSH Guardian v3.0 - Agent Routes Package
Modular agent API endpoints
"""

from flask import Blueprint

# Create main blueprint
agent_routes = Blueprint('agent_routes', __name__)

# Import all sub-modules to register their routes
from . import auth
from . import registration
from . import heartbeat
from . import logs
from . import management
from . import statistics
from . import firewall
from . import ufw
