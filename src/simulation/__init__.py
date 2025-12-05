"""
SSH Guardian v3.0 - Simulation Module
Attack simulation and testing framework
"""

from .simulator import AttackSimulator
from .templates import ATTACK_TEMPLATES, get_template, get_all_templates, get_template_list
from .ip_pools import IPPoolManager, get_pool_manager
from .logger import SimulationLogger
from .event_generator import EventGenerator

__all__ = [
    'AttackSimulator',
    'ATTACK_TEMPLATES',
    'get_template',
    'get_all_templates',
    'get_template_list',
    'IPPoolManager',
    'get_pool_manager',
    'SimulationLogger',
    'EventGenerator',
]
