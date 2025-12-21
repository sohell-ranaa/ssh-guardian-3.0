"""
SSH Guardian v3.0 - Agent Log Submission
Handles log batch processing from agents
"""

import uuid
import json
from flask import request, jsonify
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection
from . import agent_routes
from .auth import require_api_key

# Import log processor
try:
    from log_processor import process_log_line
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "core"))
    from log_processor import process_log_line


@agent_routes.route('/agents/logs', methods=['POST'])
@require_api_key
def submit_logs():
    """Receive log batch from agent"""
    try:
        data = request.json
        agent = request.agent

        batch_uuid = data.get('batch_uuid', str(uuid.uuid4()))
        log_lines = data.get('log_lines', [])
        batch_size = len(log_lines)
        source_filename = data.get('source_filename', '/var/log/auth.log')

        if not log_lines:
            return jsonify({
                'success': False,
                'error': 'No log lines provided'
            }), 400

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        batch_id = None

        try:
            # Create batch record
            cursor.execute("""
                INSERT INTO agent_log_batches (
                    batch_uuid, agent_id, log_source, events_count,
                    status, processing_started_at
                ) VALUES (%s, %s, %s, %s, 'processing', NOW())
            """, (batch_uuid, agent['id'], source_filename, batch_size))

            batch_id = cursor.lastrowid
            conn.commit()

            # Process log lines
            events_created = 0
            events_failed = 0
            failed_lines = []

            for log_line in log_lines:
                try:
                    # Process log line through detection engine
                    result = process_log_line(
                        log_line=log_line,
                        source_type='agent',
                        agent_id=agent['id'],
                        agent_batch_id=batch_id
                    )

                    if result and result.get('success'):
                        events_created += 1
                    else:
                        events_failed += 1
                        failed_lines.append({
                            'line': log_line,
                            'error': result.get('error', 'Unknown error') if result else 'Processing failed'
                        })

                except Exception as e:
                    events_failed += 1
                    failed_lines.append({
                        'line': log_line,
                        'error': str(e)
                    })

            # Update batch record with results
            cursor.execute("""
                UPDATE agent_log_batches
                SET events_processed = %s,
                    events_failed = %s,
                    status = 'completed',
                    processing_completed_at = NOW(),
                    processing_duration_ms = TIMESTAMPDIFF(MICROSECOND, processing_started_at, NOW()) / 1000
                WHERE id = %s
            """, (events_created, events_failed, batch_id))

            # Update agent statistics
            cursor.execute("""
                UPDATE agents
                SET total_events_sent = total_events_sent + %s
                WHERE id = %s
            """, (events_created, agent['id']))

            conn.commit()

            return jsonify({
                'success': True,
                'message': 'Log batch processed successfully',
                'batch_uuid': batch_uuid,
                'batch_id': batch_id,
                'batch_size': batch_size,
                'events_created': events_created,
                'events_failed': events_failed,
                'has_failures': events_failed > 0
            })

        except Exception as e:
            # Mark batch as failed
            if batch_id:
                cursor.execute("""
                    UPDATE agent_log_batches
                    SET status = 'failed',
                        error_message = %s,
                        processing_completed_at = NOW()
                    WHERE id = %s
                """, (str(e), batch_id))
                conn.commit()
            raise

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Log submission failed: {str(e)}'
        }), 500
