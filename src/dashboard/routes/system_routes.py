"""
SSH Guardian v3.0 - System Routes
API endpoints for system status, cache management, and settings
"""

from flask import Blueprint, jsonify, request
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "src"))

from src.core.auth import login_required

system_routes = Blueprint('system_routes', __name__)


@system_routes.route('/cache/stats', methods=['GET'])
@login_required
def get_cache_stats():
    """Get Redis cache statistics"""
    try:
        from core.cache import get_cache

        cache = get_cache()
        stats = cache.get_stats()

        return jsonify({
            'success': True,
            'cache': stats
        })
    except ImportError:
        return jsonify({
            'success': True,
            'cache': {
                'enabled': False,
                'connected': False,
                'error': 'Cache module not available'
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@system_routes.route('/cache/clear-stats', methods=['POST'])
@login_required
def clear_stats_cache():
    """Clear dashboard stats cache"""
    try:
        from core.cache import get_cache

        cache = get_cache()
        deleted = cache.delete_pattern('events_stats')
        deleted += cache.delete_pattern('dashboard')

        return jsonify({
            'success': True,
            'message': f'Stats cache cleared ({deleted} keys)'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@system_routes.route('/cache/clear-all', methods=['POST'])
@login_required
def clear_all_cache():
    """Clear all Redis cache"""
    try:
        from core.cache import get_cache, get_redis_client

        client = get_redis_client()
        if client:
            # Get count of keys before flush
            keys_count = client.dbsize()
            # Clear all SSH Guardian keys
            keys = client.keys('sshg:*')
            if keys:
                client.delete(*keys)

            return jsonify({
                'success': True,
                'message': f'All cache cleared ({len(keys)} keys)'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Redis not connected'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@system_routes.route('/cache/clear', methods=['POST'])
@login_required
def clear_cache():
    """Clear cache (single endpoint for frontend use)"""
    try:
        from core.cache import get_cache, get_redis_client

        client = get_redis_client()
        if client:
            # Clear all SSH Guardian keys
            keys = client.keys('sshg:*')
            deleted = 0
            if keys:
                deleted = client.delete(*keys)

            return jsonify({
                'success': True,
                'message': f'Cache cleared ({deleted} keys)',
                'deleted': deleted
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Redis not connected'
            }), 500
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@system_routes.route('/info', methods=['GET'])
@login_required
def get_system_info():
    """Get system information"""
    conn = None
    cursor = None
    try:
        import platform
        import os

        # Get database info
        from dbs.connection import get_connection
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT VERSION() as version")
        db_version = cursor.fetchone()['version']

        cursor.execute("SELECT COUNT(*) as count FROM auth_events")
        total_events = cursor.fetchone()['count']

        return jsonify({
            'success': True,
            'system': {
                'version': '3.0.0',
                'python_version': platform.python_version(),
                'platform': platform.system(),
                'platform_version': platform.release(),
                'database': {
                    'version': db_version,
                    'total_events': total_events
                }
            }
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
