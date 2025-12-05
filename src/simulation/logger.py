"""
SSH Guardian v3.0 - Simulation Logger
Tracks simulation execution with detailed logs
"""

import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.append(str(PROJECT_ROOT / "dbs"))

from connection import get_connection


class SimulationLogger:
    """Handles verbose logging for simulation execution"""

    LEVEL_EMOJI = {
        'TRACE': '',
        'DEBUG': '',
        'INFO': '',
        'SUCCESS': '',
        'WARNING': '',
        'ERROR': '',
        'CRITICAL': ''
    }

    def __init__(self, simulation_run_id: int, verbose: bool = True):
        """
        Initialize simulation logger

        Args:
            simulation_run_id: ID of the simulation run
            verbose: Whether to print to console
        """
        self.simulation_run_id = simulation_run_id
        self.verbose = verbose
        self.sequence = 0
        self.logs: List[Dict] = []

    def log(self, stage: str, message: str, level: str = "INFO",
            metadata: Optional[Dict] = None, ip_address: Optional[str] = None,
            username: Optional[str] = None, event_count: Optional[int] = None):
        """
        Log a simulation step

        Args:
            stage: Pipeline stage (init, generate, process, cleanup)
            message: Log message
            level: Log level (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)
            metadata: Additional structured data
            ip_address: Related IP address
            username: Related username
            event_count: Number of events
        """
        self.sequence += 1
        timestamp = datetime.now()
        log_uuid = str(uuid.uuid4())

        log_entry = {
            'log_uuid': log_uuid,
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'sequence': self.sequence,
            'stage': stage,
            'level': level,
            'message': message,
            'ip_address': ip_address,
            'username': username,
            'event_count': event_count,
            'metadata': metadata or {}
        }

        self.logs.append(log_entry)

        # Store in database
        try:
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO simulation_logs
                (simulation_run_id, log_uuid, log_timestamp, sequence_number,
                 stage, level, message, ip_address, username, event_count, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                self.simulation_run_id,
                log_uuid,
                timestamp,
                self.sequence,
                stage,
                level,
                message,
                ip_address,
                username,
                event_count,
                json.dumps(metadata) if metadata else None
            ))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"[Logger] Error storing log: {e}")

        # Print to console if verbose
        if self.verbose:
            emoji = self.LEVEL_EMOJI.get(level, '')
            print(f"{emoji} [{stage}] {message}")

    def get_logs(self) -> List[Dict]:
        """Get all logs for this simulation"""
        return self.logs

    def info(self, stage: str, message: str, **kwargs):
        """Log INFO level message"""
        self.log(stage, message, 'INFO', **kwargs)

    def success(self, stage: str, message: str, **kwargs):
        """Log SUCCESS level message"""
        self.log(stage, message, 'SUCCESS', **kwargs)

    def warning(self, stage: str, message: str, **kwargs):
        """Log WARNING level message"""
        self.log(stage, message, 'WARNING', **kwargs)

    def error(self, stage: str, message: str, **kwargs):
        """Log ERROR level message"""
        self.log(stage, message, 'ERROR', **kwargs)

    def debug(self, stage: str, message: str, **kwargs):
        """Log DEBUG level message"""
        self.log(stage, message, 'DEBUG', **kwargs)
