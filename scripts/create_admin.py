"""
Create admin user for SSH Guardian v3.0
"""

import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.append(str(PROJECT_ROOT))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))
sys.path.append(str(PROJECT_ROOT / "dbs"))

from dbs.connection import get_connection
from auth import PasswordManager

def create_admin_user(email, password, full_name):
    """Create an admin user"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            print(f"❌ User with email {email} already exists")
            return False

        # Hash password
        password_hash = PasswordManager.hash_password(password)

        # Get Super Admin role ID
        cursor.execute("SELECT id FROM roles WHERE name = 'Super Admin'")
        role = cursor.fetchone()

        if not role:
            print("❌ Super Admin role not found")
            return False

        # Create user
        cursor.execute("""
            INSERT INTO users (email, password_hash, full_name, role_id, is_active, is_email_verified)
            VALUES (%s, %s, %s, %s, TRUE, TRUE)
        """, (email, password_hash, full_name, role['id']))

        conn.commit()

        print("=" * 70)
        print("✅ ADMIN USER CREATED SUCCESSFULLY")
        print("=" * 70)
        print(f"Email:      {email}")
        print(f"Password:   {password}")
        print(f"Name:       {full_name}")
        print(f"Role:       Super Admin")
        print("=" * 70)
        print("You can now login at: http://localhost:8081/login")
        print("=" * 70)

        return True

    except Exception as e:
        conn.rollback()
        print(f"❌ Error creating user: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    print("\n🔐 SSH Guardian v3.0 - Create Admin User\n")

    # Default credentials
    email = input("Email (default: admin@sshguardian.local): ").strip() or "admin@sshguardian.local"
    password = input("Password (default: Admin@123): ").strip() or "Admin@123"
    full_name = input("Full Name (default: System Administrator): ").strip() or "System Administrator"

    print("\nCreating admin user...")
    create_admin_user(email, password, full_name)
