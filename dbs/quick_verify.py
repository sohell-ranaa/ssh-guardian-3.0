#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/rana-workspace/ssh_guardian_v3.0')
from dbs.connection import get_connection

try:
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('DESCRIBE ip_blocks')
    columns = cursor.fetchall()

    print('\n📋 ip_blocks table - Approval Workflow Columns:')
    print('=' * 70)
    approval_cols = ['approval_status', 'approved_by', 'approved_at']
    found = 0
    for col in columns:
        if col['Field'] in approval_cols:
            print(f"  ✅ {col['Field']:20s} {col['Type']:35s} {col['Null']:5s} {col['Default'] or 'NULL'}")
            found += 1

    if found == 0:
        print("  ❌ No approval columns found yet")

    # Check indexes
    cursor.execute("SHOW INDEX FROM ip_blocks WHERE Key_name LIKE '%approval%'")
    indexes = cursor.fetchall()
    if indexes:
        print('\n📇 Approval Indexes:')
        seen = set()
        for idx in indexes:
            if idx['Key_name'] not in seen:
                print(f"  ✅ {idx['Key_name']}")
                seen.add(idx['Key_name'])
    else:
        print('\n📇 No approval indexes found yet')

    cursor.close()
    conn.close()

    if found == 3:
        print('\n✅ Migration verification PASSED - All 3 columns present!')
    else:
        print(f'\n⏳ Migration in progress or pending - {found}/3 columns found')
except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()
