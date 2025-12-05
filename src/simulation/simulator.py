"""
SSH Guardian v3.0 - Attack Simulator
Main simulation execution engine
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))
sys.path.append(str(PROJECT_ROOT / "src"))

from connection import get_connection
from core.log_processor import process_log_line
from .templates import ATTACK_TEMPLATES
from .ip_pools import get_pool_manager
from .logger import SimulationLogger
from .event_generator import EventGenerator


class AttackSimulator:
    """Main simulator class that executes attack scenarios"""

    def __init__(self, verbose: bool = True):
        """
        Initialize the attack simulator

        Args:
            verbose: Whether to print progress to console
        """
        self.verbose = verbose
        self.ip_pool_manager = get_pool_manager()
        self.event_generator = EventGenerator(self.ip_pool_manager)

    def execute(self, template_name: str, custom_params: Optional[Dict] = None,
                user_id: Optional[int] = None, user_email: Optional[str] = None) -> Dict:
        """
        Execute a simulation based on template

        Args:
            template_name: Name of attack template
            custom_params: Override template parameters
            user_id: User executing the simulation
            user_email: User's email

        Returns:
            Simulation result summary
        """
        # Validate template
        if template_name not in ATTACK_TEMPLATES:
            raise ValueError(f"Unknown template: {template_name}")

        template = ATTACK_TEMPLATES[template_name]
        params = template['template'].copy()

        # Override with custom params
        if custom_params:
            params.update(custom_params)

        # Create simulation run record
        run_id = self._create_simulation_run(
            template_name=template_name,
            template_display_name=template['name'],
            config=params,
            user_id=user_id,
            user_email=user_email
        )

        # Initialize logger
        logger = SimulationLogger(run_id, verbose=self.verbose)

        try:
            logger.info('INIT', f"Starting simulation: {template['name']}",
                       metadata={'template': template_name, 'user': user_email})

            # Generate events
            events = self.event_generator.generate_events(params, logger)

            logger.success('GENERATION', f"Generated {len(events)} events for simulation",
                          event_count=len(events))

            # Process events through log processor
            results = self._process_events(events, run_id, params, logger)

            # Analyze results
            summary = self._analyze_results(results, run_id, logger)

            # Complete simulation
            self._complete_simulation(run_id, summary)

            logger.success('COMPLETE', "Simulation completed successfully",
                          metadata=summary)

            return {
                'simulation_id': run_id,
                'status': 'completed',
                'summary': summary,
                'logs': logger.get_logs()
            }

        except Exception as e:
            error_msg = f"Simulation failed: {str(e)}"
            logger.error('ERROR', error_msg, metadata={'exception': str(e)})
            self._fail_simulation(run_id, error_msg)
            raise

    def _create_simulation_run(self, template_name: str, template_display_name: str,
                               config: Dict, user_id: Optional[int],
                               user_email: Optional[str]) -> int:
        """Create simulation run record in database"""
        conn = get_connection()
        cursor = conn.cursor()

        run_uuid = str(uuid.uuid4())
        total_events = config.get('attempts', 0)

        try:
            cursor.execute("""
                INSERT INTO simulation_runs
                (run_uuid, user_id, user_email, template_name, template_display_name,
                 config, status, total_events_planned, started_at)
                VALUES (%s, %s, %s, %s, %s, %s, 'running', %s, NOW())
            """, (
                run_uuid, user_id, user_email, template_name, template_display_name,
                json.dumps(config), total_events
            ))
            conn.commit()
            run_id = cursor.lastrowid
            return run_id
        finally:
            cursor.close()
            conn.close()

    def _process_events(self, events: List[Dict], run_id: int,
                        params: Dict, logger: SimulationLogger) -> List[Dict]:
        """Process events through the log processor"""
        results = []
        server_hostname = params.get('server_hostname', 'simulation-server')

        for idx, event in enumerate(events, 1):
            logger.info('SUBMISSION',
                       f"Processing event {idx}/{len(events)} - {event['source_ip']} -> {event['username']}",
                       ip_address=event['source_ip'],
                       username=event['username'])

            try:
                # Process through log_processor
                result = process_log_line(
                    log_line=event['raw_log_line'],
                    source_type='simulation',
                    simulation_run_id=run_id,
                    target_server_override=server_hostname
                )

                if result['success']:
                    logger.success('SUBMISSION',
                                  f"Event {idx} stored (ID: {result['event_id']})",
                                  metadata={'event_id': result['event_id']})
                    results.append({
                        'event': event,
                        'status': 'success',
                        'event_id': result['event_id'],
                        'event_uuid': result['event_uuid']
                    })
                else:
                    logger.warning('SUBMISSION',
                                  f"Event {idx} failed: {result.get('error', 'Unknown error')}",
                                  metadata={'error': result.get('error')})
                    results.append({
                        'event': event,
                        'status': 'failed',
                        'error': result.get('error')
                    })

            except Exception as e:
                logger.error('SUBMISSION', f"Error processing event {idx}: {str(e)}")
                results.append({
                    'event': event,
                    'status': 'error',
                    'error': str(e)
                })

        return results

    def _analyze_results(self, results: List[Dict], run_id: int,
                        logger: SimulationLogger) -> Dict:
        """Analyze simulation results"""
        logger.info('ANALYSIS', "Analyzing simulation results...")

        successful = len([r for r in results if r['status'] == 'success'])
        failed = len([r for r in results if r['status'] != 'success'])

        # Query database for additional stats
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Count events by type
            cursor.execute("""
                SELECT event_type, COUNT(*) as count
                FROM auth_events
                WHERE simulation_run_id = %s
                GROUP BY event_type
            """, (run_id,))
            event_types = {row['event_type']: row['count'] for row in cursor.fetchall()}

            # Get unique IPs
            cursor.execute("""
                SELECT COUNT(DISTINCT source_ip_text) as unique_ips
                FROM auth_events
                WHERE simulation_run_id = %s
            """, (run_id,))
            unique_ips = cursor.fetchone()['unique_ips']

            summary = {
                'total_events': len(results),
                'successful_submissions': successful,
                'failed_submissions': failed,
                'unique_ips': unique_ips,
                'event_types': event_types,
                'completion_rate': (successful / len(results) * 100) if results else 0
            }

            logger.success('ANALYSIS',
                          f"Results: {successful}/{len(results)} events processed, {unique_ips} unique IPs",
                          metadata=summary)

            return summary

        finally:
            cursor.close()
            conn.close()

    def _complete_simulation(self, run_id: int, summary: Dict):
        """Mark simulation as completed"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE simulation_runs
                SET status = 'completed',
                    completed_at = NOW(),
                    duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW()),
                    events_generated = %s,
                    progress_percent = 100
                WHERE id = %s
            """, (summary.get('successful_submissions', 0), run_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def _fail_simulation(self, run_id: int, error_message: str):
        """Mark simulation as failed"""
        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                UPDATE simulation_runs
                SET status = 'failed',
                    completed_at = NOW(),
                    duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW()),
                    error_message = %s
                WHERE id = %s
            """, (error_message, run_id))
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    def get_simulation_logs(self, run_id: int) -> List[Dict]:
        """Retrieve logs for a specific simulation"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM simulation_logs
                WHERE simulation_run_id = %s
                ORDER BY sequence_number ASC
            """, (run_id,))

            logs = cursor.fetchall()

            # Parse JSON metadata
            for log in logs:
                if log.get('metadata'):
                    try:
                        log['metadata'] = json.loads(log['metadata'])
                    except:
                        pass

            return logs
        finally:
            cursor.close()
            conn.close()

    def get_simulation_status(self, run_id: int) -> Optional[Dict]:
        """Get status of a simulation run"""
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("""
                SELECT * FROM simulation_runs WHERE id = %s
            """, (run_id,))
            return cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

    def list_templates(self) -> List[Dict]:
        """List available simulation templates"""
        from .templates import get_template_list
        return get_template_list()
