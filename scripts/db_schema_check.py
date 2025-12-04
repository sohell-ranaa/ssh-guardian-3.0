"""
Database Schema Checker - Quick reference for all tables
Shows actual column names to prevent mistakes
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


def get_table_schema(table_name):
    """Get column details for a table"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(f"DESCRIBE {table_name}")
        columns = cursor.fetchall()
        return columns
    finally:
        cursor.close()
        conn.close()


def list_all_tables():
    """List all tables in database"""
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SHOW TABLES")
        tables = [row[0] for row in cursor.fetchall()]
        return tables
    finally:
        cursor.close()
        conn.close()


def print_table_schema(table_name):
    """Print schema for a table"""
    columns = get_table_schema(table_name)

    print(f"\n{'='*80}")
    print(f"TABLE: {table_name}")
    print(f"{'='*80}")
    print(f"{'Column Name':<30} {'Type':<25} {'Null':<6} {'Key':<6} {'Default':<15}")
    print(f"{'-'*80}")

    for col in columns:
        print(f"{col['Field']:<30} {col['Type']:<25} {col['Null']:<6} {col['Key']:<6} {str(col['Default']):<15}")

    print(f"{'='*80}\n")


def main():
    print("\n" + "="*80)
    print("SSH Guardian v3.0 - Database Schema Reference")
    print("="*80)

    # Get connection info
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT DATABASE() as db, USER() as user, VERSION() as version")
    info = cursor.fetchone()
    cursor.close()
    conn.close()

    print(f"\nDatabase: {info['db']}")
    print(f"User: {info['user']}")
    print(f"MySQL Version: {info['version']}")
    print(f"Connection: Via connection pool (30 connections)")

    # List all tables
    tables = list_all_tables()
    print(f"\nTotal Tables: {len(tables)}")
    print("Tables:", ", ".join(tables))

    # Important tables for quick reference
    important_tables = [
        'agents',
        'auth_events',
        'ip_geolocation',
        'ip_blocks',
        'users',
        'user_sessions'
    ]

    print("\n" + "="*80)
    print("IMPORTANT TABLE SCHEMAS")
    print("="*80)

    for table in important_tables:
        if table in tables:
            print_table_schema(table)

    # Save to file
    output_file = PROJECT_ROOT / "docs" / "CURRENT_DB_SCHEMA.txt"
    with open(output_file, 'w') as f:
        f.write("="*80 + "\n")
        f.write("SSH Guardian v3.0 - Current Database Schema\n")
        f.write(f"Generated: {info['db']} on {info['version']}\n")
        f.write("="*80 + "\n\n")

        for table in tables:
            f.write(f"\n{'='*80}\n")
            f.write(f"TABLE: {table}\n")
            f.write(f"{'='*80}\n")
            f.write(f"{'Column Name':<30} {'Type':<25} {'Null':<6} {'Key':<6} {'Default':<15}\n")
            f.write(f"{'-'*80}\n")

            columns = get_table_schema(table)
            for col in columns:
                f.write(f"{col['Field']:<30} {col['Type']:<25} {col['Null']:<6} {col['Key']:<6} {str(col['Default']):<15}\n")

            f.write(f"{'='*80}\n\n")

    print(f"\n✅ Full schema saved to: {output_file}")
    print("\n" + "="*80 + "\n")


if __name__ == "__main__":
    main()
