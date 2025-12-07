"""
Cache Settings Routes - API endpoints for cache configuration management
Allows users to configure TTL, auto-refresh, and view cache statistics
"""
import sys
from pathlib import Path
from flask import Blueprint, jsonify, request
import threading
import time

# Add database path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from cache import get_cache, get_redis_client, increment_ttl_version, CACHEABLE_ENDPOINTS

cache_settings_routes = Blueprint('cache_settings', __name__)

# Background cache warmer thread
_cache_warmer_thread = None
_cache_warmer_running = False


@cache_settings_routes.route('/list', methods=['GET'])
def list_cache_settings():
    """Get all cache settings with current status"""
    conn = None
    cursor = None
    try:
        category = request.args.get('category', '').strip()

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        if category:
            cursor.execute("""
                SELECT * FROM cache_settings
                WHERE category = %s
                ORDER BY priority DESC, endpoint_name
            """, (category,))
        else:
            cursor.execute("""
                SELECT * FROM cache_settings
                ORDER BY category, priority DESC, endpoint_name
            """)

        settings = cursor.fetchall()

        # Convert timestamps to ISO format
        for s in settings:
            if s.get('last_hit_at'):
                s['last_hit_at'] = s['last_hit_at'].isoformat()
            if s.get('last_refresh_at'):
                s['last_refresh_at'] = s['last_refresh_at'].isoformat()
            if s.get('created_at'):
                s['created_at'] = s['created_at'].isoformat()
            if s.get('updated_at'):
                s['updated_at'] = s['updated_at'].isoformat()
            # Calculate hit rate
            total = (s.get('hit_count', 0) or 0) + (s.get('miss_count', 0) or 0)
            s['hit_rate'] = round((s.get('hit_count', 0) or 0) / total * 100, 1) if total > 0 else 0.0

        return jsonify({
            'success': True,
            'data': settings
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@cache_settings_routes.route('/categories', methods=['GET'])
def list_categories():
    """Get all cache categories"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT category, COUNT(*) as count,
                   SUM(CASE WHEN is_enabled THEN 1 ELSE 0 END) as enabled_count,
                   SUM(CASE WHEN auto_refresh_enabled THEN 1 ELSE 0 END) as auto_refresh_count
            FROM cache_settings
            GROUP BY category
            ORDER BY category
        """)

        categories = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify({
            'success': True,
            'data': categories
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/<int:setting_id>', methods=['GET'])
def get_cache_setting(setting_id):
    """Get a specific cache setting"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM cache_settings WHERE id = %s", (setting_id,))
        setting = cursor.fetchone()

        cursor.close()
        conn.close()

        if not setting:
            return jsonify({
                'success': False,
                'error': 'Setting not found'
            }), 404

        # Convert timestamps
        for key in ['last_hit_at', 'last_refresh_at', 'created_at', 'updated_at']:
            if setting.get(key):
                setting[key] = setting[key].isoformat()

        return jsonify({
            'success': True,
            'data': setting
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/<int:setting_id>', methods=['PUT'])
def update_cache_setting(setting_id):
    """Update a cache setting"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get current setting to validate
        cursor.execute("SELECT * FROM cache_settings WHERE id = %s", (setting_id,))
        current = cursor.fetchone()

        if not current:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'Setting not found'
            }), 404

        # Build update query
        allowed_fields = [
            'ttl_seconds', 'auto_refresh_enabled', 'auto_refresh_interval_seconds',
            'incremental_update_enabled', 'is_enabled', 'priority'
        ]

        updates = []
        params = []

        for field in allowed_fields:
            if field in data:
                value = data[field]
                # Validate TTL range
                if field == 'ttl_seconds':
                    min_ttl = current['min_ttl_seconds']
                    max_ttl = current['max_ttl_seconds']
                    if value < min_ttl or value > max_ttl:
                        cursor.close()
                        conn.close()
                        return jsonify({
                            'success': False,
                            'error': f'TTL must be between {min_ttl} and {max_ttl} seconds'
                        }), 400

                updates.append(f"{field} = %s")
                params.append(value)

        if not updates:
            cursor.close()
            conn.close()
            return jsonify({
                'success': False,
                'error': 'No valid fields to update'
            }), 400

        params.append(setting_id)
        update_sql = f"UPDATE cache_settings SET {', '.join(updates)} WHERE id = %s"

        cursor.execute(update_sql, params)
        conn.commit()

        # Fetch updated record
        cursor.execute("SELECT * FROM cache_settings WHERE id = %s", (setting_id,))
        updated = cursor.fetchone()

        cursor.close()
        conn.close()

        # Signal TTL version change for immediate reload
        increment_ttl_version()

        # Invalidate related cache key
        cache = get_cache()
        cache.delete_pattern(current['endpoint_key'])

        return jsonify({
            'success': True,
            'message': 'Setting updated successfully',
            'data': updated
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/bulk-update', methods=['PUT'])
def bulk_update_settings():
    """Update multiple cache settings at once"""
    try:
        data = request.get_json()
        if not data or 'settings' not in data:
            return jsonify({
                'success': False,
                'error': 'No settings provided'
            }), 400

        settings = data['settings']
        if not isinstance(settings, list):
            return jsonify({
                'success': False,
                'error': 'Settings must be a list'
            }), 400

        conn = get_connection()
        cursor = conn.cursor()

        updated_count = 0
        for s in settings:
            if 'id' not in s:
                continue

            # Only update TTL and enabled status in bulk
            if 'ttl_seconds' in s:
                cursor.execute(
                    "UPDATE cache_settings SET ttl_seconds = %s WHERE id = %s",
                    (s['ttl_seconds'], s['id'])
                )
                updated_count += cursor.rowcount
            if 'is_enabled' in s:
                cursor.execute(
                    "UPDATE cache_settings SET is_enabled = %s WHERE id = %s",
                    (s['is_enabled'], s['id'])
                )
                updated_count += cursor.rowcount
            if 'auto_refresh_enabled' in s:
                cursor.execute(
                    "UPDATE cache_settings SET auto_refresh_enabled = %s WHERE id = %s",
                    (s['auto_refresh_enabled'], s['id'])
                )
                updated_count += cursor.rowcount

        conn.commit()
        cursor.close()
        conn.close()

        # Signal TTL version change for immediate reload
        if updated_count > 0:
            increment_ttl_version()

        return jsonify({
            'success': True,
            'message': f'Updated {updated_count} settings'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/reset/<int:setting_id>', methods=['POST'])
def reset_cache_setting(setting_id):
    """Reset a cache setting to its default value"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE cache_settings
            SET ttl_seconds = default_ttl_seconds,
                auto_refresh_enabled = FALSE,
                auto_refresh_interval_seconds = 60,
                incremental_update_enabled = FALSE,
                is_enabled = TRUE
            WHERE id = %s
        """, (setting_id,))

        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()

        if affected == 0:
            return jsonify({
                'success': False,
                'error': 'Setting not found'
            }), 404

        return jsonify({
            'success': True,
            'message': 'Setting reset to defaults'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/reset-all', methods=['POST'])
def reset_all_settings():
    """Reset all cache settings to defaults"""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE cache_settings
            SET ttl_seconds = default_ttl_seconds,
                auto_refresh_enabled = FALSE,
                auto_refresh_interval_seconds = 60,
                incremental_update_enabled = FALSE,
                is_enabled = TRUE
        """)

        conn.commit()
        affected = cursor.rowcount
        cursor.close()
        conn.close()

        # Clear all cache
        cache = get_cache()
        cache.delete_pattern('')

        return jsonify({
            'success': True,
            'message': f'Reset {affected} settings to defaults'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/stats', methods=['GET'])
def get_cache_stats():
    """Get overall cache statistics including live in-memory counts"""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Get aggregate stats from settings
        cursor.execute("""
            SELECT
                COUNT(*) as total_endpoints,
                SUM(CASE WHEN is_enabled THEN 1 ELSE 0 END) as enabled_endpoints,
                SUM(CASE WHEN auto_refresh_enabled THEN 1 ELSE 0 END) as auto_refresh_endpoints,
                SUM(hit_count) as total_hits,
                SUM(miss_count) as total_misses,
                AVG(avg_load_time_ms) as avg_load_time,
                AVG(ttl_seconds) as avg_ttl
            FROM cache_settings
        """)
        db_stats = cursor.fetchone()

        cursor.close()
        conn.close()

        # Get Redis stats
        redis_stats = {}
        client = get_redis_client()
        if client:
            try:
                info = client.info('memory')
                redis_stats = {
                    'used_memory': info.get('used_memory_human', 'N/A'),
                    'used_memory_peak': info.get('used_memory_peak_human', 'N/A'),
                    'connected': True
                }
                # Count cache keys
                keys = client.keys('sshg:*')
                redis_stats['cached_keys'] = len(keys) if keys else 0
            except Exception as e:
                redis_stats = {'connected': False, 'error': str(e)}
        else:
            redis_stats = {'connected': False}

        # Get live hit stats from memory (not yet flushed to DB)
        cache = get_cache()
        live_stats = cache.get_live_hit_stats()

        # Combine DB stats with live in-memory stats
        total_hits = (db_stats.get('total_hits') or 0) + live_stats.get('total_hits', 0)
        total_misses = (db_stats.get('total_misses') or 0) + live_stats.get('total_misses', 0)
        total_requests = total_hits + total_misses
        hit_rate = round(total_hits / total_requests * 100, 1) if total_requests > 0 else 0.0

        return jsonify({
            'success': True,
            'data': {
                'endpoints': {
                    'total': db_stats['total_endpoints'],
                    'enabled': db_stats['enabled_endpoints'],
                    'auto_refresh': db_stats['auto_refresh_endpoints']
                },
                'performance': {
                    'total_hits': total_hits,
                    'total_misses': total_misses,
                    'hit_rate': hit_rate,
                    'avg_load_time_ms': round(float(db_stats['avg_load_time'] or 0), 2),
                    'avg_ttl_seconds': round(float(db_stats['avg_ttl'] or 0), 0),
                    'live_hits': live_stats.get('hits', {}),
                    'live_misses': live_stats.get('misses', {})
                },
                'redis': redis_stats,
                'warmer_running': _cache_warmer_running
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/clear', methods=['POST'])
def clear_cache():
    """Clear all cache data (both Redis and browser)"""
    try:
        client = get_redis_client()
        deleted = 0

        if client:
            keys = client.keys('sshg:*')
            if keys:
                deleted = client.delete(*keys)

            # Reset hit/miss counters
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cache_settings
                SET hit_count = 0, miss_count = 0,
                    last_hit_at = NULL, last_refresh_at = NULL
            """)
            conn.commit()
            cursor.close()
            conn.close()

        # Create response with browser cache-clearing headers
        response = jsonify({
            'success': True,
            'message': f'Cleared {deleted} cache keys',
            'browser_cache_cleared': True
        })

        # Add headers to prevent caching of this response and clear browser cache
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Clear-Site-Data'] = '"cache"'

        return response

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/clear/<endpoint_key>', methods=['POST'])
def clear_endpoint_cache(endpoint_key):
    """Clear cache for a specific endpoint"""
    try:
        cache = get_cache()
        cache.delete_pattern(endpoint_key)

        return jsonify({
            'success': True,
            'message': f'Cleared cache for {endpoint_key}'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/warm', methods=['POST'])
def warm_cache():
    """Start background cache warming for critical endpoints"""
    global _cache_warmer_thread, _cache_warmer_running

    if _cache_warmer_running:
        return jsonify({
            'success': False,
            'message': 'Cache warmer already running'
        })

    def warm_caches():
        global _cache_warmer_running
        _cache_warmer_running = True
        try:
            import requests

            # Get endpoints to warm (priority: high, critical)
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT endpoint_key FROM cache_settings
                WHERE is_enabled = TRUE AND priority IN ('high', 'critical')
                ORDER BY priority DESC
            """)
            endpoints = cursor.fetchall()
            cursor.close()
            conn.close()

            # Map endpoint keys to actual API URLs
            endpoint_urls = {
                'events_list': '/api/dashboard/events/list?limit=50',
                'dashboard_summary': '/api/dashboard/summary',
                'blocking_list': '/api/dashboard/blocking/list',
                'ip_stats_list': '/api/dashboard/ip-stats/list',
                'ip_stats_summary': '/api/dashboard/ip-stats/summary',
                'notifications_list': '/api/dashboard/notifications/list',
                'guide_full': '/api/dashboard/content/guide/full',
                'thesis_full': '/api/dashboard/content/thesis/full'
            }

            base_url = 'http://localhost:8081'

            for ep in endpoints:
                key = ep['endpoint_key']
                if key in endpoint_urls:
                    try:
                        url = base_url + endpoint_urls[key]
                        requests.get(url, timeout=30)
                        print(f"  Warmed: {key}")
                    except Exception as e:
                        print(f"  Failed to warm {key}: {e}")

            print("Cache warming completed!")
        except Exception as e:
            print(f"Cache warming error: {e}")
        finally:
            _cache_warmer_running = False

    _cache_warmer_thread = threading.Thread(target=warm_caches, daemon=True)
    _cache_warmer_thread.start()

    return jsonify({
        'success': True,
        'message': 'Cache warming started in background'
    })


@cache_settings_routes.route('/warmer/status', methods=['GET'])
def get_warmer_status():
    """Get status of background cache warmer"""
    return jsonify({
        'success': True,
        'data': {
            'running': _cache_warmer_running
        }
    })


@cache_settings_routes.route('/warmer/start-auto', methods=['POST'])
def start_auto_warmer():
    """Start automatic background cache refresh based on settings"""
    global _cache_warmer_thread, _cache_warmer_running

    if _cache_warmer_running:
        return jsonify({
            'success': False,
            'message': 'Auto warmer already running'
        })

    def auto_warmer():
        global _cache_warmer_running
        _cache_warmer_running = True

        import requests

        endpoint_urls = {
            'events_list': '/api/dashboard/events/list?limit=50',
            'dashboard_summary': '/api/dashboard/summary',
            'blocking_list': '/api/dashboard/blocking/list',
            'notifications_list': '/api/dashboard/notifications/list',
            'guide_full': '/api/dashboard/content/guide/full',
            'thesis_full': '/api/dashboard/content/thesis/full'
        }

        base_url = 'http://localhost:8081'

        while _cache_warmer_running:
            try:
                # Get auto-refresh endpoints
                conn = get_connection()
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT endpoint_key, auto_refresh_interval_seconds
                    FROM cache_settings
                    WHERE is_enabled = TRUE AND auto_refresh_enabled = TRUE
                """)
                endpoints = cursor.fetchall()
                cursor.close()
                conn.close()

                for ep in endpoints:
                    key = ep['endpoint_key']
                    if key in endpoint_urls:
                        try:
                            url = base_url + endpoint_urls[key]
                            requests.get(url, timeout=30)
                        except Exception:
                            pass

                # Sleep for minimum refresh interval
                time.sleep(30)

            except Exception as e:
                print(f"Auto warmer error: {e}")
                time.sleep(60)

    _cache_warmer_thread = threading.Thread(target=auto_warmer, daemon=True)
    _cache_warmer_thread.start()

    return jsonify({
        'success': True,
        'message': 'Auto cache warmer started'
    })


@cache_settings_routes.route('/warmer/stop', methods=['POST'])
def stop_auto_warmer():
    """Stop the automatic background cache refresh"""
    global _cache_warmer_running

    _cache_warmer_running = False

    return jsonify({
        'success': True,
        'message': 'Auto cache warmer stopped'
    })


@cache_settings_routes.route('/clear-browser-cache', methods=['POST'])
def clear_browser_cache():
    """
    Clear both server-side Redis cache AND instruct browser to clear its cache
    This is a universal endpoint to solve all browser caching issues

    Returns special headers that force browser cache invalidation
    """
    try:
        # Clear server-side Redis cache
        client = get_redis_client()
        redis_keys_deleted = 0

        if client:
            keys = client.keys('sshg:*')
            if keys:
                redis_keys_deleted = client.delete(*keys)

            # Reset hit/miss counters in database
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE cache_settings
                SET hit_count = 0, miss_count = 0,
                    last_hit_at = NULL, last_refresh_at = NULL
            """)
            conn.commit()
            cursor.close()
            conn.close()

        # Create response with browser cache clearing instructions
        response = jsonify({
            'success': True,
            'message': 'All caches cleared successfully',
            'details': {
                'redis_keys_deleted': redis_keys_deleted,
                'browser_cache_cleared': True,
                'action': 'Browser will reload fresh data on next request'
            }
        })

        # Add aggressive cache-busting headers for this response
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['Clear-Site-Data'] = '"cache", "storage"'  # Modern browsers support this

        return response

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@cache_settings_routes.route('/force-reload', methods=['GET'])
def force_reload():
    """
    Endpoint that always returns fresh timestamp to force browser reload
    Frontend can call this to verify cache is working
    """
    from datetime import datetime

    response = jsonify({
        'success': True,
        'timestamp': datetime.now().isoformat(),
        'message': 'This response should never be cached'
    })

    # Aggressive no-cache headers
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    return response


@cache_settings_routes.route('/ttl-map', methods=['GET'])
def get_ttl_map():
    """
    Return current TTL settings for frontend cache indicator.
    This replaces the hardcoded TTL map in cache_indicator.html.

    Returns:
        {
            'success': True,
            'ttl_map': {
                'events': 120,
                'threat_intel': 7200,
                ...
            },
            'cacheable_endpoints': ['threat_intel_lookup', ...]
        }
    """
    try:
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

        # Build TTL map with simplified keys for frontend
        # Map database endpoint_keys to frontend route categories
        key_to_category = {
            'events_list': 'events',
            'events_count': 'events',
            'events_analysis': 'events',
            'dashboard_summary': 'dashboard',
            'threat_intel_lookup': 'threat_intel',
            'threat_intel_stats': 'threat_intel',
            'geoip_lookup': 'geoip',
            'geoip_stats': 'geoip',
            'ip_stats_list': 'ip_stats',
            'ip_stats_summary': 'ip_stats',
            'blocking_list': 'blocking',
            'blocking_stats': 'blocking',
            'trends_overview': 'trends',
            'trends_daily': 'trends',
            'daily_reports': 'reports',
            'ml_predictions': 'ml',
            'ml_models': 'ml',
            'audit_list': 'audit',
            'notifications_list': 'notifications',
            'settings_list': 'settings',
        }

        ttl_map = {}
        for row in rows:
            endpoint_key = row['endpoint_key']
            category = key_to_category.get(endpoint_key, endpoint_key)
            # Use minimum TTL if category already exists (for multiple endpoints per category)
            if category not in ttl_map or row['ttl_seconds'] < ttl_map[category]:
                ttl_map[category] = row['ttl_seconds']

        return jsonify({
            'success': True,
            'ttl_map': ttl_map,
            'cacheable_endpoints': list(CACHEABLE_ENDPOINTS)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
