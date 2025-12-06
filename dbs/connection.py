"""
SSH Guardian v3.0 - Database Connection Module
Centralized database connection with pooling and utilities
"""

import mysql.connector
from mysql.connector import pooling, Error
import socket
import struct
from typing import Optional, Tuple
import os
import sys

# Database Configuration
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 3306)),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", "123123"),
    "database": os.getenv("DB_NAME", "ssh_guardian_v3"),
    "charset": "utf8mb4",
    "collation": "utf8mb4_unicode_ci",
    "autocommit": False,  # Explicit transaction control
    "use_pure": False     # Use C extension for performance
}

# Connection Pool Configuration
POOL_CONFIG = {
    "pool_name": "ssh_guardian_v3_pool",
    "pool_size": int(os.getenv("DB_POOL_SIZE", 32)),  # Max allowed by mysql.connector is 32
    "pool_reset_session": True,
    "connect_timeout": int(os.getenv("DB_TIMEOUT", 10))
}

# Global connection pool
connection_pool = None


def initialize_pool():
    """Initialize the connection pool"""
    global connection_pool

    try:
        connection_pool = pooling.MySQLConnectionPool(
            **POOL_CONFIG,
            **DB_CONFIG
        )
        print(f"✅ Database connection pool '{POOL_CONFIG['pool_name']}' created successfully")
        print(f"   Pool size: {POOL_CONFIG['pool_size']} connections")
        print(f"   Database: {DB_CONFIG['database']}")
        return True
    except Error as e:
        print(f"❌ Error creating connection pool: {e}")
        connection_pool = None
        return False


def get_connection():
    """
    Get a connection from the pool.

    Returns:
        mysql.connector connection object

    Raises:
        Error: If connection cannot be established
    """
    global connection_pool

    try:
        if connection_pool is None:
            initialize_pool()

        if connection_pool:
            conn = connection_pool.get_connection()
            return conn
        else:
            # Fallback to direct connection if pool initialization failed
            print("⚠️  Connection pool not available, using direct connection")
            return mysql.connector.connect(**DB_CONFIG)

    except Error as e:
        print(f"❌ Error getting connection: {e}")
        raise


def test_connection():
    """
    Test database connection and display information.

    Returns:
        bool: True if connection successful, False otherwise
    """
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        # Test basic connection
        cursor.execute("SELECT VERSION() as version, DATABASE() as db_name, USER() as user")
        result = cursor.fetchone()

        # Check v3.0 tables exist
        cursor.execute("""
            SELECT COUNT(*) as table_count
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = %s
            AND TABLE_NAME IN ('auth_events', 'ip_geolocation', 'ip_blocks', 'agents')
        """, (DB_CONFIG['database'],))
        table_check = cursor.fetchone()

        # Get database size
        cursor.execute("""
            SELECT
                ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb
            FROM information_schema.TABLES
            WHERE table_schema = %s
        """, (DB_CONFIG['database'],))
        size_result = cursor.fetchone()

        print("=" * 70)
        print("📊 SSH GUARDIAN v3.0 - DATABASE CONNECTION TEST")
        print("=" * 70)
        print(f"MySQL Version:    {result['version']}")
        print(f"Database:         {result['db_name']}")
        print(f"User:             {result['user']}")
        print(f"Host:             {DB_CONFIG['host']}:{DB_CONFIG['port']}")
        print(f"Pool Size:        {POOL_CONFIG['pool_size']} connections")
        print(f"v3.0 Tables:      {table_check['table_count']}/4 core tables found")
        print(f"Database Size:    {size_result['size_mb']} MB")
        print("=" * 70)

        if table_check['table_count'] >= 4:
            print("✅ Connection successful! v3.0 schema detected")
        else:
            print("⚠️  Connection successful but v3.0 schema not fully created")
            print("   Run migrations: 001_initial_schema.sql and 002_auth_and_system_tables.sql")

        cursor.close()
        conn.close()

        return True

    except Error as e:
        print("=" * 70)
        print("❌ DATABASE CONNECTION FAILED")
        print("=" * 70)
        print(f"Error: {e}")
        print(f"\nConfiguration:")
        print(f"  Host: {DB_CONFIG['host']}")
        print(f"  Port: {DB_CONFIG['port']}")
        print(f"  Database: {DB_CONFIG['database']}")
        print(f"  User: {DB_CONFIG['user']}")
        print("=" * 70)
        return False


# ============================================================================
# IP ADDRESS UTILITIES (Binary <-> Text Conversion)
# ============================================================================

def ip_to_binary(ip_str: str) -> bytes:
    """
    Convert IP address string to binary format for storage.

    Args:
        ip_str: IP address as string (e.g., "192.168.1.1" or "2001:db8::1")

    Returns:
        bytes: Binary representation (4 bytes for IPv4, 16 bytes for IPv6)

    Raises:
        ValueError: If IP address is invalid
    """
    try:
        # Try IPv4 first
        return socket.inet_pton(socket.AF_INET, ip_str)
    except OSError:
        try:
            # Try IPv6
            return socket.inet_pton(socket.AF_INET6, ip_str)
        except OSError:
            raise ValueError(f"Invalid IP address: {ip_str}")


def binary_to_ip(ip_bin: bytes) -> str:
    """
    Convert binary IP address to string format.

    Args:
        ip_bin: Binary IP address (4 or 16 bytes)

    Returns:
        str: IP address as string

    Raises:
        ValueError: If binary data length is invalid
    """
    if len(ip_bin) == 4:
        return socket.inet_ntop(socket.AF_INET, ip_bin)
    elif len(ip_bin) == 16:
        return socket.inet_ntop(socket.AF_INET6, ip_bin)
    else:
        raise ValueError(f"Invalid IP binary length: {len(ip_bin)} (expected 4 or 16)")


def get_ip_version(ip_str: str) -> int:
    """
    Determine if IP address is IPv4 or IPv6.

    Args:
        ip_str: IP address as string

    Returns:
        int: 4 for IPv4, 6 for IPv6

    Raises:
        ValueError: If IP address is invalid
    """
    try:
        socket.inet_pton(socket.AF_INET, ip_str)
        return 4
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, ip_str)
            return 6
        except OSError:
            raise ValueError(f"Invalid IP address: {ip_str}")


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if string is a valid IP address.

    Args:
        ip_str: IP address as string

    Returns:
        bool: True if valid IPv4 or IPv6 address
    """
    try:
        get_ip_version(ip_str)
        return True
    except ValueError:
        return False


# ============================================================================
# DATABASE UTILITIES
# ============================================================================

def execute_query(query: str, params: Optional[Tuple] = None, fetch_one=False, fetch_all=False):
    """
    Execute a query and return results.

    Args:
        query: SQL query to execute
        params: Query parameters (optional)
        fetch_one: If True, return single row
        fetch_all: If True, return all rows

    Returns:
        Result set or None
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(query, params or ())

        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        else:
            result = None

        conn.commit()
        return result

    except Error as e:
        conn.rollback()
        print(f"❌ Query execution error: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def get_table_info(table_name: str):
    """
    Get information about a table.

    Args:
        table_name: Name of the table

    Returns:
        dict: Table information including row count, size, etc.
    """
    query = """
        SELECT
            TABLE_NAME as name,
            TABLE_ROWS as row_count,
            ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS size_mb,
            ENGINE as engine,
            TABLE_COLLATION as collation,
            CREATE_TIME as created_at,
            UPDATE_TIME as updated_at
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s
    """

    return execute_query(query, (DB_CONFIG['database'], table_name), fetch_one=True)


def get_database_stats():
    """
    Get overall database statistics.

    Returns:
        dict: Database statistics
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Total size
        cursor.execute("""
            SELECT
                COUNT(*) as table_count,
                ROUND(SUM(DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS total_size_mb
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = %s
        """, (DB_CONFIG['database'],))
        size_stats = cursor.fetchone()

        # Row counts for major tables
        cursor.execute("SELECT COUNT(*) as count FROM auth_events")
        auth_events_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM ip_geolocation")
        ip_geo_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM ip_blocks WHERE is_active = TRUE")
        active_blocks_count = cursor.fetchone()['count']

        cursor.execute("SELECT COUNT(*) as count FROM agents WHERE is_active = TRUE")
        active_agents_count = cursor.fetchone()['count']

        return {
            'database': DB_CONFIG['database'],
            'table_count': size_stats['table_count'],
            'total_size_mb': size_stats['total_size_mb'],
            'auth_events_count': auth_events_count,
            'ip_geolocation_count': ip_geo_count,
            'active_blocks_count': active_blocks_count,
            'active_agents_count': active_agents_count
        }

    finally:
        cursor.close()
        conn.close()


# ============================================================================
# INITIALIZATION
# ============================================================================

# Initialize pool on module import
initialize_pool()


if __name__ == "__main__":
    """Run connection test when executed directly"""
    print("\n🔍 Testing SSH Guardian v3.0 Database Connection...\n")

    success = test_connection()

    if success:
        print("\n📊 Database Statistics:")
        print("-" * 70)
        try:
            stats = get_database_stats()
            print(f"Total Tables:        {stats['table_count']}")
            print(f"Total Size:          {stats['total_size_mb']} MB")
            print(f"Auth Events:         {stats['auth_events_count']:,}")
            print(f"Unique IPs (GeoIP):  {stats['ip_geolocation_count']:,}")
            print(f"Active IP Blocks:    {stats['active_blocks_count']:,}")
            print(f"Active Agents:       {stats['active_agents_count']:,}")
            print("-" * 70)
        except Exception as e:
            print(f"Unable to fetch statistics: {e}")

    print("\n" + "=" * 70)
    print("IP Utility Functions Test:")
    print("=" * 70)

    # Test IP conversion
    test_ips = ["192.168.1.1", "10.0.0.1", "2001:db8::1"]

    for ip in test_ips:
        try:
            version = get_ip_version(ip)
            binary = ip_to_binary(ip)
            converted_back = binary_to_ip(binary)
            print(f"✅ {ip:20s} -> IPv{version} -> {len(binary)} bytes -> {converted_back}")
        except Exception as e:
            print(f"❌ {ip}: {e}")

    print("=" * 70)

    sys.exit(0 if success else 1)
