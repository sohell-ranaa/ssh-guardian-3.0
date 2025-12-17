"""
SSH Guardian v3.0 - Live Simulation Routes Package
Live attack simulation and target server management
"""

from flask import Blueprint

# Create main blueprint (named differently to avoid conflict with existing simulation_routes)
live_sim_routes = Blueprint('live_sim_routes', __name__)

# Import all sub-modules to register their routes
from . import target_servers
from . import live_simulation
