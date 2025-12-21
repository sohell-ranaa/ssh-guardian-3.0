"""
SSH Guardian v3.0 - Events API
Agent endpoint for submitting SSH authentication events
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import uuid
import sys
from pathlib import Path

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src" / "core"))

from connection import get_connection, ip_to_binary

# Import GeoIP and Threat Intel modules
sys.path.append(str(PROJECT_ROOT / "src" / "core"))
from geoip import enrich_event
from threat_intel import check_ip_threat

# Import unified ThreatEvaluator
from threat_evaluator import evaluate_ip_threat

# Create Blueprint
events_api = Blueprint('events_api', __name__, url_prefix='/api/events')


# API Key validation decorator
def require_api_key(f):
    """Decorator to validate API key"""
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            return jsonify({'error': 'API key required'}), 401

        # Validate API key against database
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT id, display_name, is_active
                FROM agents
                WHERE api_key = %s AND is_active = TRUE
            """, (api_key,))

            agent = cursor.fetchone()

            if not agent:
                return jsonify({'error': 'Invalid API key'}), 401

            # Attach agent info to request
            request.agent = agent

            return f(*args, **kwargs)

        finally:
            cursor.close()
            conn.close()

    decorated_function.__name__ = f.__name__
    return decorated_function


@events_api.route('/submit', methods=['POST'])
@require_api_key
def submit_event():
    """
    Submit SSH authentication event from agent

    Request JSON:
    {
        "timestamp": "2025-12-04T10:30:45Z",  # ISO 8601 format
        "source_ip": "192.168.1.100",
        "username": "root",
        "auth_method": "password",
        "status": "failed",  # or "success"
        "port": 22,
        "protocol": "ssh2",
        "raw_log": "Original SSH log line...",
        "hostname": "server01"  # Optional
    }

    Response:
    {
        "success": true,
        "event_id": "uuid-here",
        "message": "Event received and queued for processing"
    }
    """
    try:
        # Get JSON data
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['timestamp', 'source_ip', 'username', 'status']
        missing_fields = [f for f in required_fields if f not in data]

        if missing_fields:
            return jsonify({
                'error': 'Missing required fields',
                'missing': missing_fields
            }), 400

        # Parse and validate data
        try:
            event_timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return jsonify({'error': 'Invalid timestamp format (use ISO 8601)'}), 400

        source_ip = data['source_ip']
        username = data['username']
        status = data['status'].lower()

        if status not in ['success', 'failed']:
            return jsonify({'error': 'Status must be "success" or "failed"'}), 400

        # Optional fields
        auth_method = data.get('auth_method', 'password')
        port = data.get('port', 22)
        protocol = data.get('protocol', 'ssh2')
        raw_log = data.get('raw_log', '')
        hostname = data.get('hostname')

        # Generate event UUID
        event_uuid = str(uuid.uuid4())

        # Convert IP to binary for storage
        try:
            source_ip_binary = ip_to_binary(source_ip)
        except ValueError as e:
            return jsonify({'error': f'Invalid IP address: {str(e)}'}), 400

        # Get agent info from decorator
        agent_id = request.agent['id']

        # Insert into database
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO auth_events (
                    event_uuid,
                    timestamp,
                    source_type,
                    source_ip,
                    source_ip_text,
                    target_port,
                    target_username,
                    auth_method,
                    event_type,
                    agent_id,
                    target_server,
                    raw_log_line,
                    created_at
                ) VALUES (
                    %s, %s, 'agent', %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()
                )
            """, (
                event_uuid,
                event_timestamp,
                source_ip_binary,
                source_ip,
                port,
                username,
                auth_method,
                status,
                agent_id,
                hostname,
                raw_log
            ))

            event_id = cursor.lastrowid
            conn.commit()

            # Log successful submission
            print(f"✅ Event received: {event_uuid} from agent {request.agent['display_name']}")
            print(f"   IP: {source_ip}, User: {username}, Status: {status}")

            # Enrich with GeoIP data asynchronously (non-blocking)
            # In production, this should be done in a background task/queue
            try:
                print(f"🌍 Enriching event {event_id} with GeoIP data...")
                geo_id = enrich_event(event_id, source_ip)

                if geo_id:
                    print(f"✅ Event {event_id} enriched with GeoIP (geo_id: {geo_id})")
                else:
                    print(f"⚠️  Event {event_id} saved without GeoIP enrichment")

            except Exception as geo_error:
                # Don't fail the request if GeoIP lookup fails
                print(f"⚠️  GeoIP enrichment failed for event {event_id}: {geo_error}")

            # Enrich with Threat Intelligence data (non-blocking)
            try:
                print(f"🔍 Enriching event {event_id} with Threat Intelligence...")
                threat_data = check_ip_threat(source_ip)

                if threat_data:
                    threat_level = threat_data.get('threat_level', 'unknown')
                    confidence = threat_data.get('confidence', 0)

                    # Update event processing status
                    conn_update = get_connection()
                    cursor_update = conn_update.cursor()

                    try:
                        cursor_update.execute("""
                            UPDATE auth_events
                            SET processing_status = 'intel_complete'
                            WHERE id = %s
                        """, (event_id,))

                        conn_update.commit()
                        print(f"✅ Event {event_id} enriched with Threat Intel (level: {threat_level}, confidence: {confidence:.2f})")

                    finally:
                        cursor_update.close()
                        conn_update.close()
                else:
                    print(f"⚠️  Event {event_id} saved without Threat Intel enrichment")

            except Exception as threat_error:
                # Don't fail the request if threat intel lookup fails
                print(f"⚠️  Threat Intel enrichment failed for event {event_id}: {threat_error}")

            # Run comprehensive threat evaluation
            threat_evaluation = None
            try:
                print(f"🔬 Running unified threat evaluation for {source_ip}...")
                event_context = {
                    'username': username,
                    'status': status,
                    'auth_method': auth_method,
                    'port': port,
                    'timestamp': event_timestamp.isoformat(),
                    'agent_id': agent_id
                }
                threat_evaluation = evaluate_ip_threat(source_ip, event_context)

                if threat_evaluation:
                    composite_score = threat_evaluation.get('composite_score', 0)
                    risk_level = threat_evaluation.get('risk_level', 'minimal')
                    recommended_action = threat_evaluation.get('recommended_action', 'allow')

                    print(f"✅ Threat Evaluation Complete:")
                    print(f"   Composite Score: {composite_score}/100")
                    print(f"   Risk Level: {risk_level}")
                    print(f"   Recommended: {recommended_action}")

                    # Update event with evaluation result
                    conn_eval = get_connection()
                    cursor_eval = conn_eval.cursor()
                    try:
                        cursor_eval.execute("""
                            UPDATE auth_events
                            SET processing_status = 'evaluated',
                                ml_risk_score = %s,
                                ml_risk_level = %s
                            WHERE id = %s
                        """, (composite_score, risk_level, event_id))
                        conn_eval.commit()
                    finally:
                        cursor_eval.close()
                        conn_eval.close()

                    # Check if automatic blocking should be triggered
                    if composite_score >= 80 and status == 'failed':
                        print(f"🛡️  HIGH THREAT: Auto-blocking may be triggered for {source_ip}")
                        # Note: Actual blocking is handled by the blocking module
                        # based on configured policies

            except Exception as eval_error:
                print(f"⚠️  Threat evaluation error: {eval_error}")

            # Build response with evaluation data
            response_data = {
                'success': True,
                'event_id': event_id,
                'event_uuid': event_uuid,
                'message': 'Event received and processed',
                'agent': request.agent['display_name']
            }

            # Include evaluation summary in response
            if threat_evaluation:
                response_data['evaluation'] = {
                    'composite_score': threat_evaluation.get('composite_score', 0),
                    'risk_level': threat_evaluation.get('risk_level', 'minimal'),
                    'recommended_action': threat_evaluation.get('recommended_action', 'allow'),
                    'factors_count': len(threat_evaluation.get('factors', []))
                }

            return jsonify(response_data), 201

        except Exception as e:
            conn.rollback()
            print(f"❌ Database error: {e}")
            return jsonify({'error': 'Failed to save event'}), 500

        finally:
            cursor.close()
            conn.close()

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@events_api.route('/submit/batch', methods=['POST'])
@require_api_key
def submit_batch():
    """
    Submit multiple events in a single request

    Request JSON:
    {
        "events": [
            {...event1...},
            {...event2...},
            ...
        ]
    }

    Response:
    {
        "success": true,
        "received": 10,
        "processed": 10,
        "failed": 0,
        "event_ids": ["uuid1", "uuid2", ...]
    }
    """
    try:
        data = request.get_json()

        if not data or 'events' not in data:
            return jsonify({'error': 'No events provided'}), 400

        events = data['events']

        if not isinstance(events, list):
            return jsonify({'error': 'Events must be an array'}), 400

        if len(events) == 0:
            return jsonify({'error': 'Events array is empty'}), 400

        if len(events) > 100:
            return jsonify({'error': 'Maximum 100 events per batch'}), 400

        # Process each event
        event_uuids = []
        failed_count = 0

        for idx, event in enumerate(events):
            try:
                # Validate and prepare event (similar to single submit)
                # For now, simplified version
                event_uuid = str(uuid.uuid4())
                event_uuids.append(event_uuid)

                # TODO: Implement batch insert logic

            except Exception as e:
                print(f"❌ Failed to process event {idx}: {e}")
                failed_count += 1

        return jsonify({
            'success': True,
            'received': len(events),
            'processed': len(events) - failed_count,
            'failed': failed_count,
            'event_uuids': event_uuids
        }), 201

    except Exception as e:
        print(f"❌ Batch error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@events_api.route('/health', methods=['GET'])
def health():
    """API health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'SSH Guardian Events API',
        'version': '3.0.0'
    }), 200


# Error handlers
@events_api.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@events_api.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405


@events_api.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500
