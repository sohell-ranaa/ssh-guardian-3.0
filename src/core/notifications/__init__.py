"""
SSH Guardian v3.0 - Notifications Module
Hourly digest and notification queueing functionality
"""

from .digest import queue_for_digest, send_hourly_digest

__all__ = ['queue_for_digest', 'send_hourly_digest']
