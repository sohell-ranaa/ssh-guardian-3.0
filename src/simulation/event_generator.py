"""
SSH Guardian v3.0 - Event Generator
Generates SSH log events from simulation templates
"""

import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .ip_pools import IPPoolManager
from .logger import SimulationLogger


class EventGenerator:
    """Generates SSH log events for simulations"""

    def __init__(self, ip_pool_manager: IPPoolManager):
        self.ip_pool_manager = ip_pool_manager

    def generate_events(self, params: Dict, logger: SimulationLogger) -> List[Dict]:
        """
        Generate SSH log events based on template parameters

        Args:
            params: Template parameters
            logger: Simulation logger

        Returns:
            List of event dictionaries with raw_log_line
        """
        events = []

        # Parse IP allocation
        source_ips = self._parse_ip_parameter(
            params.get('source_ip', '192.168.1.1'),
            logger
        )

        # Parse username(s)
        usernames = params.get('username')
        if isinstance(usernames, str):
            usernames = [usernames]
        elif not isinstance(usernames, list):
            usernames = ['root']

        # Determine number of attempts
        total_attempts = self._calculate_total_attempts(params, source_ips, usernames)

        logger.info('PLANNING', f"Will generate {total_attempts} events from {len(source_ips)} IPs",
                   metadata={'ips': len(source_ips), 'total_attempts': total_attempts})

        # Time distribution
        time_window = params.get('time_window_seconds', 60)
        timestamps = self._distribute_timestamps(total_attempts, time_window)

        # Generate events
        event_count = 0
        attempts_per_ip = total_attempts // len(source_ips) if len(source_ips) > 1 else total_attempts

        for ip in source_ips:
            for attempt in range(attempts_per_ip):
                if event_count >= total_attempts:
                    break

                username = usernames[event_count % len(usernames)]
                timestamp = timestamps[event_count]

                event = self._build_event(
                    event_type=params.get('event_type', 'failed'),
                    source_ip=ip,
                    username=username,
                    server_hostname=params.get('server_hostname', 'simulation-server'),
                    port=params.get('port', 22),
                    timestamp=timestamp,
                    failure_reason=params.get('failure_reason', 'invalid_password'),
                    auth_method=params.get('auth_method', 'password')
                )

                events.append(event)
                event_count += 1

        return events

    def _parse_ip_parameter(self, ip_param: str, logger: SimulationLogger) -> List[str]:
        """
        Parse IP parameter which can be:
        - <from_pool:malicious> - single malicious IP
        - <from_pool:malicious:multiple:5> - 5 malicious IPs
        - <from_pool:trusted>
        - <from_pool:random>
        - 192.168.1.1 - specific IP
        """
        if not isinstance(ip_param, str):
            return [str(ip_param)]

        if ip_param.startswith('<from_pool:'):
            parts = ip_param.strip('<>').split(':')
            pool_type = parts[1]

            count = 1
            if len(parts) >= 4 and parts[2] == 'multiple':
                count = int(parts[3])

            logger.info('IP_POOL', f"Fetching {count} IP(s) from {pool_type} pool")

            ips = self.ip_pool_manager.get_ips(pool_type, count)

            logger.success('IP_POOL', f"Selected IPs: {', '.join(ips)}",
                          metadata={'ips': ips, 'pool_type': pool_type})

            return ips
        else:
            return [ip_param]

    def _calculate_total_attempts(self, params: Dict, source_ips: List[str],
                                  usernames: List[str]) -> int:
        """Calculate total number of events to generate"""
        if 'attempts' in params:
            return params['attempts']
        elif 'attempts_per_ip' in params:
            return params['attempts_per_ip'] * len(source_ips)
        elif 'attempts_per_user' in params:
            return params['attempts_per_user'] * len(usernames)
        else:
            return len(source_ips)

    def _distribute_timestamps(self, count: int, time_window_seconds: int) -> List[datetime]:
        """Distribute timestamps across time window"""
        start_time = datetime.now() - timedelta(seconds=time_window_seconds)
        timestamps = []

        for i in range(count):
            offset = (i / max(count - 1, 1)) * time_window_seconds
            # Add small random jitter
            jitter = random.uniform(-2, 2)
            ts = start_time + timedelta(seconds=offset + jitter)
            timestamps.append(ts)

        return timestamps

    def _build_event(self, event_type: str, source_ip: str, username: str,
                     server_hostname: str, port: int, timestamp: datetime,
                     failure_reason: Optional[str] = None,
                     auth_method: str = 'password') -> Dict:
        """Build event dict with raw SSH log line"""

        # Build raw SSH log line that log_processor.py can parse
        pid = random.randint(1000, 65535)
        timestamp_str = timestamp.strftime('%b %d %H:%M:%S')

        if event_type == 'failed':
            if failure_reason == 'invalid_user':
                raw_log_line = (
                    f"{timestamp_str} {server_hostname} sshd[{pid}]: "
                    f"Failed password for invalid user {username} from {source_ip} port {port} ssh2"
                )
            else:
                raw_log_line = (
                    f"{timestamp_str} {server_hostname} sshd[{pid}]: "
                    f"Failed password for {username} from {source_ip} port {port} ssh2"
                )
        elif event_type == 'successful':
            if auth_method == 'publickey':
                raw_log_line = (
                    f"{timestamp_str} {server_hostname} sshd[{pid}]: "
                    f"Accepted publickey for {username} from {source_ip} port {port} ssh2"
                )
            else:
                raw_log_line = (
                    f"{timestamp_str} {server_hostname} sshd[{pid}]: "
                    f"Accepted password for {username} from {source_ip} port {port} ssh2"
                )
        else:
            raw_log_line = (
                f"{timestamp_str} {server_hostname} sshd[{pid}]: "
                f"Invalid user {username} from {source_ip}"
            )

        return {
            'event_type': event_type,
            'source_ip': source_ip,
            'username': username,
            'server_hostname': server_hostname,
            'port': port,
            'timestamp': timestamp,
            'failure_reason': failure_reason,
            'auth_method': auth_method,
            'raw_log_line': raw_log_line
        }
