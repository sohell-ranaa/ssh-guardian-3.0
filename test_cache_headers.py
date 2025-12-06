#!/usr/bin/env python3
"""
Test script to verify cache headers are correctly applied
Run this after starting the dashboard server
"""

import sys
import requests
from pathlib import Path

# Test endpoints
TEST_CASES = [
    {
        'name': 'API Route - Events List',
        'url': 'http://localhost:8081/api/dashboard/events/list',
        'expected_cache_control': 'no-store',
        'method': 'GET'
    },
    {
        'name': 'API Route - Dashboard Summary',
        'url': 'http://localhost:8081/api/dashboard/cache-settings/stats',
        'expected_cache_control': 'no-store',
        'method': 'GET'
    },
    {
        'name': 'Force Reload Endpoint',
        'url': 'http://localhost:8081/api/dashboard/cache-settings/force-reload',
        'expected_cache_control': 'no-store',
        'method': 'GET'
    },
    {
        'name': 'Health Check',
        'url': 'http://localhost:8081/health',
        'expected_cache_control': 'no-store',
        'method': 'GET'
    },
]

def test_cache_headers():
    """Test cache headers on various endpoints"""

    print("=" * 80)
    print("CACHE HEADERS TEST - SSH Guardian v3.0")
    print("=" * 80)
    print()

    passed = 0
    failed = 0

    for test in TEST_CASES:
        print(f"Testing: {test['name']}")
        print(f"URL: {test['url']}")

        try:
            if test['method'] == 'GET':
                response = requests.get(test['url'], timeout=5)
            else:
                response = requests.post(test['url'], timeout=5)

            # Check Cache-Control header
            cache_control = response.headers.get('Cache-Control', '')
            pragma = response.headers.get('Pragma', '')
            expires = response.headers.get('Expires', '')

            print(f"  Cache-Control: {cache_control}")
            print(f"  Pragma: {pragma}")
            print(f"  Expires: {expires}")

            # Verify expected behavior
            if test['expected_cache_control'] in cache_control:
                print(f"  ✅ PASS - Correct cache headers")
                passed += 1
            else:
                print(f"  ❌ FAIL - Expected '{test['expected_cache_control']}' in Cache-Control")
                failed += 1

        except requests.exceptions.ConnectionError:
            print(f"  ⚠️  SKIP - Server not running (start with: python3 src/dashboard/server.py)")
            failed += 1
        except Exception as e:
            print(f"  ❌ ERROR - {e}")
            failed += 1

        print()

    print("=" * 80)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 80)

    return failed == 0


def test_browser_cache_clear():
    """Test browser cache clearing endpoint"""

    print("\n" + "=" * 80)
    print("BROWSER CACHE CLEAR TEST")
    print("=" * 80)
    print()

    try:
        url = 'http://localhost:8081/api/dashboard/cache-settings/clear-browser-cache'
        response = requests.post(url, timeout=5)

        print(f"Testing: {url}")
        print(f"Status Code: {response.status_code}")

        # Check response
        data = response.json()
        print(f"Response: {data}")

        # Check headers
        cache_control = response.headers.get('Cache-Control', '')
        clear_site_data = response.headers.get('Clear-Site-Data', '')

        print(f"Cache-Control: {cache_control}")
        print(f"Clear-Site-Data: {clear_site_data}")

        if 'no-store' in cache_control and data.get('success'):
            print("✅ PASS - Browser cache clear endpoint working")
            return True
        else:
            print("❌ FAIL - Browser cache clear endpoint not working correctly")
            return False

    except requests.exceptions.ConnectionError:
        print("⚠️  SKIP - Server not running")
        return False
    except Exception as e:
        print(f"❌ ERROR - {e}")
        return False


def test_force_reload():
    """Test that force-reload always returns fresh data"""

    print("\n" + "=" * 80)
    print("FORCE RELOAD TEST (No Caching)")
    print("=" * 80)
    print()

    try:
        url = 'http://localhost:8081/api/dashboard/cache-settings/force-reload'

        # Make two requests
        print("Making first request...")
        r1 = requests.get(url, timeout=5)
        data1 = r1.json()
        ts1 = data1.get('timestamp')

        import time
        time.sleep(0.1)  # Wait 100ms

        print("Making second request...")
        r2 = requests.get(url, timeout=5)
        data2 = r2.json()
        ts2 = data2.get('timestamp')

        print(f"First timestamp:  {ts1}")
        print(f"Second timestamp: {ts2}")

        if ts1 != ts2:
            print("✅ PASS - Timestamps are different (no caching)")
            return True
        else:
            print("❌ FAIL - Timestamps are the same (caching detected)")
            return False

    except requests.exceptions.ConnectionError:
        print("⚠️  SKIP - Server not running")
        return False
    except Exception as e:
        print(f"❌ ERROR - {e}")
        return False


if __name__ == '__main__':
    print("\n🧪 Starting Cache Headers Test Suite\n")

    # Run all tests
    test1 = test_cache_headers()
    test2 = test_browser_cache_clear()
    test3 = test_force_reload()

    print("\n" + "=" * 80)
    print("FINAL RESULTS")
    print("=" * 80)

    if test1 and test2 and test3:
        print("✅ ALL TESTS PASSED")
        print("\nCache headers are working correctly!")
        print("Browser caching is now properly prevented.")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED")
        print("\nMake sure the server is running:")
        print("  python3 src/dashboard/server.py")
        sys.exit(1)
