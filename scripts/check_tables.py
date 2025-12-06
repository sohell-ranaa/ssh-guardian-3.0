#!/usr/bin/env python3
"""Check if watchlist and whitelist tables exist"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection

conn = get_connection()
cursor = conn.cursor()

try:
    # Check if ip_watchlist table exists
    cursor.execute("SHOW TABLES LIKE 'ip_watchlist'")
    watchlist_exists = cursor.fetchone() is not None
    print(f"ip_watchlist table exists: {watchlist_exists}")

    # Check if ip_whitelist table exists
    cursor.execute("SHOW TABLES LIKE 'ip_whitelist'")
    whitelist_exists = cursor.fetchone() is not None
    print(f"ip_whitelist table exists: {whitelist_exists}")

    # If they exist, show structure
    if watchlist_exists:
        print("\nip_watchlist structure:")
        cursor.execute("DESCRIBE ip_watchlist")
        for row in cursor.fetchall():
            print(f"  {row}")

    if whitelist_exists:
        print("\nip_whitelist structure:")
        cursor.execute("DESCRIBE ip_whitelist")
        for row in cursor.fetchall():
            print(f"  {row}")

finally:
    cursor.close()
    conn.close()
