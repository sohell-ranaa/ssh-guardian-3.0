"""
SSH Guardian v3.0 - Redis Cache Module
High-performance caching for dashboard queries
TTL values configured via .env file
"""

import redis
import json
import hashlib
from typing import Any, Optional, Union
from datetime import datetime, timedelta
import os
import sys
from pathlib import Path

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "dbs"))

# Redis configuration from environment
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)

# Cache TTL values from environment (in seconds)
# Defaults provided if not set in .env
CACHE_TTL = {
    # Real-time data - very short TTL
    'events_list': int(os.getenv('CACHE_TTL_EVENTS_LIST', 15)),
    'events_count': int(os.getenv('CACHE_TTL_EVENTS_COUNT', 15)),
    'dashboard_summary': int(os.getenv('CACHE_TTL_DASHBOARD_SUMMARY', 15)),
    'events_analysis': int(os.getenv('CACHE_TTL_EVENTS_ANALYSIS', 15)),
    'events_timeline': int(os.getenv('CACHE_TTL_EVENTS_TIMELINE', 30)),

    # Frequently changing data
    'events_stats': int(os.getenv('CACHE_TTL_EVENTS_STATS', 30)),
    'ip_history': int(os.getenv('CACHE_TTL_IP_HISTORY', 30)),
    'ml_predictions': int(os.getenv('CACHE_TTL_ML_PREDICTIONS', 60)),
    'blocking': int(os.getenv('CACHE_TTL_BLOCKING', 30)),
    'audit': int(os.getenv('CACHE_TTL_AUDIT', 60)),
    'notifications': int(os.getenv('CACHE_TTL_NOTIFICATIONS', 30)),

    # Semi-static data
    'threat_intel': int(os.getenv('CACHE_TTL_THREAT_INTEL', 300)),
    'geoip': int(os.getenv('CACHE_TTL_GEOIP', 300)),
    'trends': int(os.getenv('CACHE_TTL_TRENDS', 120)),
    'daily_reports': int(os.getenv('CACHE_TTL_DAILY_REPORTS', 300)),
    'ml_models': int(os.getenv('CACHE_TTL_ML_MODELS', 120)),
    'settings': int(os.getenv('CACHE_TTL_SETTINGS', 30)),
}

# GLOBAL CACHE ENABLE/DISABLE TOGGLE from environment
# When False, ALL caching is bypassed - useful for debugging
_GLOBAL_CACHE_ENABLED = os.getenv('CACHE_ENABLED', '1') == '1'

def set_global_cache_enabled(enabled: bool):
    """Enable or disable ALL caching globally"""
    global _GLOBAL_CACHE_ENABLED
    _GLOBAL_CACHE_ENABLED = enabled
    print(f"[Cache] Global caching {'ENABLED' if enabled else 'DISABLED'}")

def is_global_cache_enabled() -> bool:
    """Check if global caching is enabled"""
    return _GLOBAL_CACHE_ENABLED

# Cacheable endpoints - ONLY these get cached (slow/expensive queries)
CACHEABLE_ENDPOINTS = {
    # Threat Intelligence (external API calls, rate-limited)
    'threat_intel_lookup', 'threat_intel_stats',
    # GeoIP (external API calls)
    'geoip_lookup', 'geoip_stats',
    # Trends & Reports (historical data, expensive aggregations)
    'trends_overview', 'trends_daily', 'daily_reports',
    # Events (large dataset, paginated)
    'events_list', 'events_count', 'events_analysis',
    # IP Stats (aggregation queries)
    'ip_stats_list', 'ip_stats_summary',
}


def should_cache(endpoint_key: str) -> bool:
    """
    Check if an endpoint should be cached.
    Returns True if endpoint is in CACHEABLE_ENDPOINTS and global cache is enabled.
    """
    if not _GLOBAL_CACHE_ENABLED:
        return False
    return endpoint_key in CACHEABLE_ENDPOINTS


def get_ttl(cache_type: str = None, endpoint_key: str = None) -> int:
    """
    Get TTL for a cache type.

    Args:
        cache_type: Cache type key (e.g., 'events_list', 'threat_intel')
        endpoint_key: Endpoint key (maps to cache_type for backwards compatibility)

    Returns:
        TTL in seconds
    """
    # Map endpoint_key to cache_type if provided
    if endpoint_key:
        key_mapping = {
            'events_list': 'events_list',
            'events_count': 'events_count',
            'events_analysis': 'events_stats',
            'dashboard_summary': 'dashboard_summary',
            'ip_stats_list': 'blocking',
            'ip_stats_summary': 'blocking',
            'blocking_list': 'blocking',
            'blocking_stats': 'blocking',
            'geoip_lookup': 'geoip',
            'geoip_stats': 'geoip',
            'threat_intel_lookup': 'threat_intel',
            'threat_intel_stats': 'threat_intel',
            'ml_predictions': 'ml_predictions',
            'ml_models': 'ml_models',
            'audit_list': 'audit',
            'audit_stats': 'audit',
            'notifications_list': 'notifications',
            'trends_overview': 'trends',
            'trends_daily': 'trends',
            'daily_reports': 'daily_reports',
        }
        cache_type = key_mapping.get(endpoint_key, cache_type)

    if cache_type:
        return CACHE_TTL.get(cache_type, 300)

    return 300  # Default 5 minutes

# Global Redis connection pool
_redis_pool = None
_redis_client = None


def get_redis_client() -> Optional[redis.Redis]:
    """Get or create Redis client with connection pooling"""
    global _redis_pool, _redis_client

    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except (redis.ConnectionError, redis.TimeoutError):
            _redis_client = None
            _redis_pool = None

    try:
        if _redis_pool is None:
            _redis_pool = redis.ConnectionPool(
                host=REDIS_HOST,
                port=REDIS_PORT,
                db=REDIS_DB,
                password=REDIS_PASSWORD,
                max_connections=20,
                socket_timeout=5,
                socket_connect_timeout=5,
                decode_responses=True
            )

        _redis_client = redis.Redis(connection_pool=_redis_pool)
        _redis_client.ping()
        return _redis_client
    except Exception as e:
        print(f"[Cache] Redis connection failed: {e}")
        return None


def cache_key(*args) -> str:
    """Generate a cache key from arguments"""
    key_parts = [str(arg) for arg in args]
    key_string = ':'.join(key_parts)
    return f"sshg:{key_string}"


def cache_key_hash(*args, **kwargs) -> str:
    """Generate a hashed cache key for complex queries"""
    key_data = json.dumps({'args': args, 'kwargs': kwargs}, sort_keys=True)
    key_hash = hashlib.md5(key_data.encode()).hexdigest()[:12]
    prefix = args[0] if args else 'query'
    return f"sshg:{prefix}:{key_hash}"


class CacheManager:
    """Centralized cache management for SSH Guardian"""

    def __init__(self):
        self.client = get_redis_client()
        self.enabled = self.client is not None

    def get(self, key: str, endpoint_key: str = None) -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: The cache key
            endpoint_key: Optional endpoint_key (kept for backwards compatibility)
        """
        # Check global cache toggle first
        if not _GLOBAL_CACHE_ENABLED:
            return None

        if not self.enabled:
            return None

        try:
            value = self.client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            print(f"[Cache] Get error for {key}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: int = 60) -> bool:
        """Set value in cache with TTL"""
        # Check global cache toggle first
        if not _GLOBAL_CACHE_ENABLED:
            return False

        if not self.enabled:
            return False

        try:
            serialized = json.dumps(value, default=self._json_serializer)
            self.client.setex(key, ttl, serialized)
            return True
        except Exception as e:
            print(f"[Cache] Set error for {key}: {e}")
            return False

    def delete(self, key: str) -> bool:
        """Delete a key from cache"""
        if not self.enabled:
            return False

        try:
            self.client.delete(key)
            return True
        except Exception as e:
            print(f"[Cache] Delete error for {key}: {e}")
            return False

    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern"""
        if not self.enabled:
            return 0

        try:
            keys = self.client.keys(f"sshg:{pattern}*")
            if keys:
                return self.client.delete(*keys)
            return 0
        except Exception as e:
            print(f"[Cache] Delete pattern error for {pattern}: {e}")
            return 0

    def invalidate_events(self):
        """Invalidate all events-related caches"""
        self.delete_pattern('events')
        self.delete_pattern('dashboard')

    def invalidate_ip(self, ip_address: str):
        """Invalidate all caches for a specific IP"""
        self.delete_pattern(f'ip:{ip_address}')
        self.delete_pattern('geoip')
        self.delete_pattern('threat')
        self.delete_pattern('events')  # Events may contain this IP

    def invalidate_blocking(self):
        """Invalidate blocking-related caches"""
        self.delete_pattern('blocking')
        self.delete_pattern('ip_blocks')
        self.delete_pattern('firewall')

    def invalidate_agents(self):
        """Invalidate agent-related caches"""
        self.delete_pattern('agents')
        self.delete_pattern('agent')

    def invalidate_settings(self):
        """Invalidate settings-related caches"""
        self.delete_pattern('settings')
        self.delete_pattern('config')

    def invalidate_notifications(self):
        """Invalidate notification-related caches"""
        self.delete_pattern('notif')
        self.delete_pattern('notification')

    def invalidate_users(self):
        """Invalidate user-related caches"""
        self.delete_pattern('users')
        self.delete_pattern('user')
        self.delete_pattern('roles')

    def invalidate_ml(self):
        """Invalidate ML-related caches"""
        self.delete_pattern('ml')
        self.delete_pattern('model')
        self.delete_pattern('prediction')

    def invalidate_reports(self):
        """Invalidate reports-related caches"""
        self.delete_pattern('reports')
        self.delete_pattern('trends')
        self.delete_pattern('daily')

    def invalidate_audit(self):
        """Invalidate audit-related caches"""
        self.delete_pattern('audit')

    def invalidate_geoip(self):
        """Invalidate GeoIP-related caches"""
        self.delete_pattern('geoip')
        self.delete_pattern('geo')

    def invalidate_threat_intel(self):
        """Invalidate threat intelligence caches"""
        self.delete_pattern('threat')
        self.delete_pattern('intel')

    def get_or_set(self, key: str, func: callable, ttl: int = 60) -> Any:
        """Get from cache or compute and set"""
        cached = self.get(key)
        if cached is not None:
            return cached

        result = func()
        if result is not None:
            self.set(key, result, ttl)
        return result

    def _json_serializer(self, obj):
        """Custom JSON serializer for datetime and Decimal"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if hasattr(obj, '__float__'):
            return float(obj)
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def get_stats(self) -> dict:
        """Get cache statistics"""
        if not self.enabled:
            return {'enabled': False}

        try:
            info = self.client.info('memory')
            keys = self.client.dbsize()
            return {
                'enabled': True,
                'connected': True,
                'memory_used': info.get('used_memory_human', 'N/A'),
                'memory_peak': info.get('used_memory_peak_human', 'N/A'),
                'total_keys': keys
            }
        except Exception as e:
            return {'enabled': True, 'connected': False, 'error': str(e)}


# Global cache manager instance
_cache_manager = None


def get_cache() -> CacheManager:
    """Get or create the global cache manager"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager


# Convenience functions for common operations
def cached_events_list(limit: int, offset: int, filters: dict = None) -> Optional[dict]:
    """Get cached events list"""
    cache = get_cache()
    key = cache_key_hash('events_list', limit=limit, offset=offset, filters=filters)
    return cache.get(key)


def cache_events_list(limit: int, offset: int, filters: dict, data: dict, ttl: int = None):
    """Cache events list result"""
    cache = get_cache()
    key = cache_key_hash('events_list', limit=limit, offset=offset, filters=filters)
    cache.set(key, data, ttl or CACHE_TTL['events_list'])


def cached_events_count(filters: dict = None) -> Optional[int]:
    """Get cached events count"""
    cache = get_cache()
    key = cache_key_hash('events_count', filters=filters)
    return cache.get(key)


def cache_events_count(filters: dict, count: int, ttl: int = None):
    """Cache events count"""
    cache = get_cache()
    key = cache_key_hash('events_count', filters=filters)
    cache.set(key, count, ttl or CACHE_TTL['events_count'])


def cached_stats() -> Optional[dict]:
    """Get cached dashboard stats"""
    cache = get_cache()
    return cache.get(cache_key('events_stats'))


def cache_stats(data: dict, ttl: int = None):
    """Cache dashboard stats"""
    cache = get_cache()
    cache.set(cache_key('events_stats'), data, ttl or CACHE_TTL['events_stats'])


def invalidate_on_new_event():
    """Call this when a new event is inserted"""
    cache = get_cache()
    cache.invalidate_events()


def invalidate_on_block_change():
    """Call this when IP blocks are added/removed"""
    cache = get_cache()
    cache.invalidate_blocking()
    cache.invalidate_events()  # Events list may show blocked status


def invalidate_on_agent_change():
    """Call this when agents are added/updated/removed"""
    cache = get_cache()
    cache.invalidate_agents()


def invalidate_on_settings_change():
    """Call this when settings are updated"""
    cache = get_cache()
    cache.invalidate_settings()


def invalidate_on_notification_change():
    """Call this when notification rules/history changes"""
    cache = get_cache()
    cache.invalidate_notifications()


def invalidate_on_user_change():
    """Call this when users/roles are modified"""
    cache = get_cache()
    cache.invalidate_users()


def invalidate_on_ml_change():
    """Call this when ML models/predictions change"""
    cache = get_cache()
    cache.invalidate_ml()


def invalidate_on_ip_data_change(ip_address: str = None):
    """Call this when IP geo/threat data changes"""
    cache = get_cache()
    if ip_address:
        cache.invalidate_ip(ip_address)
    else:
        cache.invalidate_geoip()
        cache.invalidate_threat_intel()


def clear_all_caches():
    """
    Clear ALL Redis cache keys
    This is a nuclear option for cache problems
    """
    cache = get_cache()
    return cache.delete_pattern('')


# ============================================================================
# AUTO-INVALIDATION DECORATORS & HELPERS
# ============================================================================
# Use these decorators on Flask route functions to automatically invalidate
# cache after database modifications

from functools import wraps

def auto_invalidate(*cache_types):
    """
    Decorator to automatically invalidate cache after a successful operation.

    Usage:
        @auto_invalidate('events', 'blocking')
        def my_route():
            # ... do database operations
            return jsonify({'success': True})

    Available cache_types:
        'events', 'blocking', 'agents', 'settings', 'notifications',
        'users', 'ml', 'reports', 'audit', 'geoip', 'threat_intel', 'all'
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)

            # Check if operation was successful (tuple means (response, status_code))
            if isinstance(result, tuple):
                response, status_code = result[0], result[1] if len(result) > 1 else 200
            else:
                response = result
                status_code = 200

            # Only invalidate on success (2xx status codes)
            if 200 <= status_code < 300:
                cache = get_cache()
                for cache_type in cache_types:
                    if cache_type == 'events':
                        cache.invalidate_events()
                    elif cache_type == 'blocking':
                        cache.invalidate_blocking()
                    elif cache_type == 'agents':
                        cache.invalidate_agents()
                    elif cache_type == 'settings':
                        cache.invalidate_settings()
                    elif cache_type == 'notifications':
                        cache.invalidate_notifications()
                    elif cache_type == 'users':
                        cache.invalidate_users()
                    elif cache_type == 'ml':
                        cache.invalidate_ml()
                    elif cache_type == 'reports':
                        cache.invalidate_reports()
                    elif cache_type == 'audit':
                        cache.invalidate_audit()
                    elif cache_type == 'geoip':
                        cache.invalidate_geoip()
                    elif cache_type == 'threat_intel':
                        cache.invalidate_threat_intel()
                    elif cache_type == 'all':
                        cache.delete_pattern('')

            return result
        return decorated_function
    return decorator


# Map table names to cache invalidation types
TABLE_CACHE_MAP = {
    # Events
    'auth_events': ['events'],
    'auth_events_ml': ['events', 'ml'],
    'auth_events_daily': ['events', 'reports'],

    # Blocking
    'ip_blocks': ['blocking', 'events'],
    'blocking_rules': ['blocking'],
    'blocking_actions': ['blocking', 'events'],

    # Agents
    'agents': ['agents'],
    'agent_heartbeats': ['agents'],
    'agent_ufw_state': ['agents'],
    'agent_ufw_rules': ['agents'],
    'agent_ufw_commands': ['agents'],

    # IP Intelligence
    'ip_geolocation': ['geoip', 'threat_intel', 'events'],

    # Fail2ban
    'fail2ban_state': ['blocking', 'agents'],
    'fail2ban_events': ['blocking', 'agents'],

    # ML
    'ml_models': ['ml'],
    'ml_training_runs': ['ml'],

    # Notifications
    'notification_rules': ['notifications'],
    'notifications': ['notifications'],

    # Users
    'users': ['users'],
    'roles': ['users'],
    'user_sessions': ['users'],

    # Settings
    'system_settings': ['settings'],
    'integrations': ['settings'],

    # Audit
    'audit_logs': ['audit'],
    'ufw_audit_log': ['audit', 'agents'],

    # Reports
    'reports': ['reports'],
}


def invalidate_for_table(table_name: str):
    """
    Invalidate cache for a specific table.
    Call this after any INSERT/UPDATE/DELETE on a table.

    Usage:
        cursor.execute("INSERT INTO ip_blocks ...")
        conn.commit()
        invalidate_for_table('ip_blocks')
    """
    cache_types = TABLE_CACHE_MAP.get(table_name, [])
    if cache_types:
        cache = get_cache()
        for cache_type in cache_types:
            if cache_type == 'events':
                cache.invalidate_events()
            elif cache_type == 'blocking':
                cache.invalidate_blocking()
            elif cache_type == 'agents':
                cache.invalidate_agents()
            elif cache_type == 'settings':
                cache.invalidate_settings()
            elif cache_type == 'notifications':
                cache.invalidate_notifications()
            elif cache_type == 'users':
                cache.invalidate_users()
            elif cache_type == 'ml':
                cache.invalidate_ml()
            elif cache_type == 'reports':
                cache.invalidate_reports()
            elif cache_type == 'audit':
                cache.invalidate_audit()
            elif cache_type == 'geoip':
                cache.invalidate_geoip()
            elif cache_type == 'threat_intel':
                cache.invalidate_threat_intel()


def get_cache_buster_timestamp():
    """
    Get a timestamp to use as cache buster in URLs
    Usage: /api/endpoint?_cb=<timestamp>
    """
    from datetime import datetime
    return int(datetime.now().timestamp() * 1000)  # milliseconds
