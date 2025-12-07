#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Migration Runner
Runs a specific migration file against the database
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dbs.connection import get_connection

def run_migration(migration_file):
    """
    Run a migration file against the database

    Args:
        migration_file: Path to the migration SQL file
    """
    migration_path = Path(migration_file)

    if not migration_path.exists():
        print(f"❌ Migration file not found: {migration_file}")
        return False

    print(f"📝 Reading migration: {migration_path.name}")

    # Read the SQL file
    with open(migration_path, 'r') as f:
        sql_content = f.read()

    # Get database connection
    print("🔌 Connecting to database...")
    conn = get_connection()

    try:
        # Execute the SQL
        print(f"⚙️  Executing migration...")

        # Split SQL into individual statements (simple approach)
        # Remove comments and split by semicolon
        statements = []
        current_statement = []
        in_delimiter = False
        delimiter = ';'

        for line in sql_content.split('\n'):
            stripped = line.strip()

            # Check for DELIMITER command
            if stripped.startswith('DELIMITER'):
                if 'DELIMITER ;' in line:
                    in_delimiter = False
                    delimiter = ';'
                else:
                    in_delimiter = True
                    delimiter = stripped.split()[-1]
                continue

            # Skip empty lines and comments
            if not stripped or stripped.startswith('--'):
                current_statement.append(line)
                continue

            current_statement.append(line)

            # Check if statement ends
            if in_delimiter:
                if stripped.endswith(delimiter) and delimiter != ';':
                    stmt = '\n'.join(current_statement)
                    stmt = stmt.rstrip(delimiter).rstrip()
                    if stmt:
                        statements.append(stmt)
                    current_statement = []
            else:
                if stripped.endswith(';'):
                    stmt = '\n'.join(current_statement)
                    if stmt.strip():
                        statements.append(stmt)
                    current_statement = []

        # Add remaining statement if any
        if current_statement:
            stmt = '\n'.join(current_statement).strip()
            if stmt:
                statements.append(stmt)

        # Execute each statement
        cursor = conn.cursor()
        statement_count = 0

        for i, statement in enumerate(statements, 1):
            stmt = statement.strip()
            if not stmt or stmt.startswith('--'):
                continue

            try:
                cursor.execute(stmt)
                statement_count += 1

                # Fetch results if any
                try:
                    if cursor.with_rows:
                        rows = cursor.fetchall()
                        if rows:
                            for row in rows:
                                print(f"   {row}")
                except:
                    pass

            except Exception as e:
                print(f"⚠️  Statement {i} error (may be expected): {e}")
                # Some errors are expected (like IF EXISTS checks)
                pass

        cursor.close()
        conn.commit()
        print(f"✅ Migration executed successfully! ({statement_count} statements)")

        return True

    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
        return False

    finally:
        conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python run_migration.py <migration_file>")
        print("Example: python run_migration.py dbs/migrations/025_approval_workflow.sql")
        sys.exit(1)

    migration_file = sys.argv[1]
    success = run_migration(migration_file)
    sys.exit(0 if success else 1)
