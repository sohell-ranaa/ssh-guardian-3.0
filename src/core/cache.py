"""
SSH Guardian v3.0 - Redis Cache Module
High-performance caching for dashboard queries
With configurable TTL from database
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

# Redis configuration from environment or defaults
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
REDIS_DB = int(os.getenv('REDIS_DB', 0))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)

# Cache TTL defaults (in seconds) - OPTIMIZED FOR PERFORMANCE
# Minimum 15 minutes (900s) for all data to reduce DB load
# These are fallback defaults; actual TTLs are loaded from database
CACHE_TTL = {
    # Dynamic data - reduced for live events page
    'events_list': 60,           # 1 minute - events list (for fresher live data)
    'events_count': 900,         # 15 minutes - total count
    'dashboard_summary': 900,    # 15 minutes - dashboard home stats
    'events_analysis': 900,      # 15 minutes - events analysis
    'events_timeline': 900,      # 15 minutes - timeline data

    # Semi-static data - 30 minutes
    'events_stats': 1800,        # 30 minutes - stats summary
    'ip_history': 1800,          # 30 minutes - IP history
    'ml_predictions': 1800,      # 30 minutes - ML results
    'blocking': 900,             # 15 minutes - block list
    'audit': 900,                # 15 minutes - audit logs
    'notifications': 900,        # 15 minutes - notification history

    # Static data - cache for long periods (1-2 hours)
    'threat_intel': 7200,        # 2 hours - threat intel (external API data)
    'geoip': 7200,               # 2 hours - GeoIP data (rarely changes)
    'trends': 3600,              # 1 hour - historical trends
    'daily_reports': 7200,       # 2 hours - daily reports (generated once)
    'ml_models': 7200,           # 2 hours - ML model info
    'settings': 3600,            # 1 hour - settings/config
}

# TTL settings loaded from database (refreshed periodically)
_db_ttl_settings = {}
_ttl_last_loaded = None
_ttl_reload_interval = 300  # Reload TTL settings every 5 minutes


def _load_ttl_from_database():
    """Load TTL settings from cache_settings table"""
    global _db_ttl_settings, _ttl_last_loaded

    try:
        from connection import get_connection
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT endpoint_key, ttl_seconds, is_enabled
            FROM cache_settings
            WHERE is_enabled = TRUE
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        _db_ttl_settings = {row['endpoint_key']: row['ttl_seconds'] for row in rows}
        _ttl_last_loaded = datetime.now()

        # Map endpoint_key to CACHE_TTL keys
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

        # Update CACHE_TTL with database values
        for endpoint_key, ttl in _db_ttl_settings.items():
            cache_key_name = key_mapping.get(endpoint_key, endpoint_key)
            if cache_key_name in CACHE_TTL:
                CACHE_TTL[cache_key_name] = ttl

    except Exception as e:
        print(f"[Cache] Failed to load TTL from database: {e}")


def get_ttl(cache_type: str) -> int:
    """Get TTL for a cache type, loading from DB if needed"""
    global _ttl_last_loaded

    # Reload TTL settings periodically
    if _ttl_last_loaded is None or (datetime.now() - _ttl_last_loaded).total_seconds() > _ttl_reload_interval:
        _load_ttl_from_database()

    return CACHE_TTL.get(cache_type, 300)

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

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
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
        self.delete_pattern('events')  # Events may contain this IP

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
