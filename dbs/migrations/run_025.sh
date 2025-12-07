#!/bin/bash
# Run migration 025 - Approval Workflow
# This script executes the migration using docker exec

MIGRATION_FILE="/home/rana-workspace/ssh_guardian_v3.0/dbs/migrations/025_approval_workflow_v2.sql"
CONTAINER_NAME="mysql_server"
DB_USER="root"
DB_PASS="123123"
DB_NAME="ssh_guardian_v3"

echo "📝 Running Migration 025: Approval Workflow"
echo "============================================"

# Check if container is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo "❌ Error: Container $CONTAINER_NAME is not running"
    exit 1
fi

# Check if migration file exists
if [ ! -f "$MIGRATION_FILE" ]; then
    echo "❌ Error: Migration file not found: $MIGRATION_FILE"
    exit 1
fi

echo "✓ Container: $CONTAINER_NAME"
echo "✓ Database: $DB_NAME"
echo "✓ Migration: $(basename $MIGRATION_FILE)"
echo ""

# Execute migration
echo "⚙️  Executing migration..."
cat "$MIGRATION_FILE" | docker exec -i "$CONTAINER_NAME" mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Migration executed successfully!"
    echo ""
    echo "📋 Verifying changes..."
    echo "DESCRIBE ip_blocks;" | docker exec -i "$CONTAINER_NAME" mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" | grep -E "(approval_status|approved_by|approved_at)"
    echo ""
    echo "✅ Done!"
else
    echo "❌ Migration failed!"
    exit 1
fi
