#!/usr/bin/env python3
"""
SSH Guardian v3.0 - UFW Manager Module
Manages UFW (Uncomplicated Firewall) rules on remote servers.

Features:
- Collect UFW status and rules
- Parse rules into structured format
- Execute UFW commands (allow, deny, delete, etc.)
- Bidirectional sync with server
- Protected ports detection
"""

import subprocess
import re
import json
import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class UFWRule:
    """Represents a single UFW rule"""
    rule_index: int
    action: str  # ALLOW, DENY, REJECT, LIMIT
    direction: str  # IN, OUT
    from_ip: str
    from_port: str
    to_ip: str
    to_port: str
    protocol: str  # tcp, udp, or empty for both
    interface: str
    comment: str
    is_v6: bool
    raw_rule: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class UFWStatus:
    """Overall UFW status"""
    status: str  # active, inactive, not_installed
    default_incoming: str  # allow, deny, reject
    default_outgoing: str
    default_routed: str
    logging_level: str  # off, low, medium, high, full
    ipv6_enabled: bool
    rules_count: int
    ufw_version: str
    last_updated: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ListeningPort:
    """Represents a listening port/service"""
    port: int
    protocol: str
    address: str
    state: str
    pid: int
    process_name: str
    user: str
    is_protected: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)


# ============================================================================
# UFW MANAGER CLASS
# ============================================================================

class UFWManager:
    """Manages UFW firewall rules"""

    # Protected ports - services that should never be blocked
    PROTECTED_SERVICES = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8081: 'SSH Guardian Dashboard',
    }

    def __init__(self):
        self.logger = logging.getLogger('UFWManager')

    def is_installed(self) -> bool:
        """Check if UFW is installed"""
        try:
            result = subprocess.run(
                ['which', 'ufw'],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self) -> str:
        """Get UFW version"""
        try:
            result = subprocess.run(
                ['ufw', 'version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                match = re.search(r'ufw (\d+\.\d+(?:\.\d+)?)', result.stdout)
                if match:
                    return match.group(1)
            return 'unknown'
        except Exception:
            return 'unknown'

    def collect_all(self) -> Dict:
        """Collect all UFW information"""
        try:
            if not self.is_installed():
                return {
                    'status': UFWStatus(
                        status='not_installed',
                        default_incoming='unknown',
                        default_outgoing='unknown',
                        default_routed='unknown',
                        logging_level='unknown',
                        ipv6_enabled=False,
                        rules_count=0,
                        ufw_version='',
                        last_updated=datetime.now().isoformat()
                    ).to_dict(),
                    'rules': [],
                    'listening_ports': self._get_listening_ports(),
                    'collected_at': datetime.now().isoformat()
                }

            status = self._get_status()
            rules = self._get_rules()
            listening_ports = self._get_listening_ports()

            return {
                'status': status,
                'rules': rules,
                'listening_ports': listening_ports,
                'protected_ports': self._get_protected_ports(listening_ports),
                'collected_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting UFW data: {e}")
            return {
                'error': str(e),
                'collected_at': datetime.now().isoformat()
            }

    def _get_status(self) -> Dict:
        """Get UFW status"""
        try:
            result = subprocess.run(
                ['ufw', 'status', 'verbose'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                return UFWStatus(
                    status='inactive',
                    default_incoming='unknown',
                    default_outgoing='unknown',
                    default_routed='unknown',
                    logging_level='unknown',
                    ipv6_enabled=False,
                    rules_count=0,
                    ufw_version=self.get_version(),
                    last_updated=datetime.now().isoformat()
                ).to_dict()

            output = result.stdout

            # Parse status
            status = 'inactive'
            if 'Status: active' in output:
                status = 'active'
            elif 'Status: inactive' in output:
                status = 'inactive'

            # Parse defaults
            default_incoming = 'deny'
            default_outgoing = 'allow'
            default_routed = 'disabled'

            defaults_match = re.search(
                r'Default:\s+(\w+)\s+\(incoming\),\s+(\w+)\s+\(outgoing\)(?:,\s+(\w+)\s+\(routed\))?',
                output
            )
            if defaults_match:
                default_incoming = defaults_match.group(1).lower()
                default_outgoing = defaults_match.group(2).lower()
                if defaults_match.group(3):
                    default_routed = defaults_match.group(3).lower()

            # Parse logging
            logging_level = 'low'
            logging_match = re.search(r'Logging:\s+(\w+)', output)
            if logging_match:
                logging_level = logging_match.group(1).lower()

            # Count rules
            rules_count = len(self._get_rules())

            # Check IPv6
            ipv6_enabled = True
            try:
                with open('/etc/default/ufw', 'r') as f:
                    ufw_defaults = f.read()
                    if 'IPV6=no' in ufw_defaults:
                        ipv6_enabled = False
            except:
                pass

            return UFWStatus(
                status=status,
                default_incoming=default_incoming,
                default_outgoing=default_outgoing,
                default_routed=default_routed,
                logging_level=logging_level,
                ipv6_enabled=ipv6_enabled,
                rules_count=rules_count,
                ufw_version=self.get_version(),
                last_updated=datetime.now().isoformat()
            ).to_dict()

        except Exception as e:
            self.logger.error(f"Error getting UFW status: {e}")
            return {'error': str(e)}

    def _get_rules(self) -> List[Dict]:
        """Get all UFW rules"""
        rules = []

        try:
            # Get numbered rules
            result = subprocess.run(
                ['ufw', 'status', 'numbered'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                return []

            output = result.stdout

            # Parse rules
            # Format: [ 1] 22/tcp                     ALLOW IN    Anywhere
            # or:     [ 1] 22                         ALLOW IN    192.168.1.0/24
            rule_pattern = re.compile(
                r'\[\s*(\d+)\]\s+'  # Rule number
                r'(.+?)\s+'  # To (port/service)
                r'(ALLOW|DENY|REJECT|LIMIT)\s+'  # Action
                r'(IN|OUT|FWD)?\s*'  # Direction
                r'(.+?)$',  # From
                re.MULTILINE
            )

            for match in rule_pattern.finditer(output):
                rule_index = int(match.group(1))
                to_part = match.group(2).strip()
                action = match.group(3)
                direction = match.group(4) or 'IN'
                from_part = match.group(5).strip()

                # Parse to part (port and protocol)
                to_port = ''
                to_ip = 'Anywhere'
                protocol = ''

                # Handle "on eth0" interface
                interface = ''
                if ' on ' in to_part:
                    parts = to_part.split(' on ')
                    to_part = parts[0]
                    interface = parts[1].strip()

                # Parse port/protocol
                if '/' in to_part:
                    port_proto = to_part.split('/')
                    to_port = port_proto[0]
                    protocol = port_proto[1] if len(port_proto) > 1 else ''
                else:
                    to_port = to_part

                # Check for IPv6 rules
                is_v6 = '(v6)' in from_part
                from_part = from_part.replace('(v6)', '').strip()

                # Parse from part
                from_ip = from_part if from_part else 'Anywhere'
                from_port = ''

                # Handle "port X" in from
                if ' port ' in from_ip:
                    parts = from_ip.split(' port ')
                    from_ip = parts[0].strip()
                    from_port = parts[1].strip()

                raw_rule = match.group(0).strip()

                rules.append(UFWRule(
                    rule_index=rule_index,
                    action=action,
                    direction=direction,
                    from_ip=from_ip,
                    from_port=from_port,
                    to_ip=to_ip,
                    to_port=to_port,
                    protocol=protocol,
                    interface=interface,
                    comment='',
                    is_v6=is_v6,
                    raw_rule=raw_rule
                ).to_dict())

        except Exception as e:
            self.logger.error(f"Error getting UFW rules: {e}")

        return rules

    def _get_listening_ports(self) -> List[Dict]:
        """Get all listening ports on the system"""
        ports = []

        try:
            # Try ss command first
            result = subprocess.run(
                ['ss', '-tlnp'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                ports.extend(self._parse_ss_output(result.stdout, 'tcp'))

            # Also get UDP
            result = subprocess.run(
                ['ss', '-ulnp'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                ports.extend(self._parse_ss_output(result.stdout, 'udp'))

        except Exception as e:
            self.logger.error(f"Error getting listening ports: {e}")

        return ports

    def _parse_ss_output(self, output: str, protocol: str) -> List[Dict]:
        """Parse ss command output"""
        ports = []
        lines = output.strip().split('\n')

        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            try:
                state = parts[0]
                local_addr = parts[4] if len(parts) > 4 else ''

                if ':' in local_addr:
                    if local_addr.startswith('['):
                        match = re.match(r'\[([^\]]+)\]:(\d+)', local_addr)
                        if match:
                            address = match.group(1)
                            port = int(match.group(2))
                        else:
                            continue
                    else:
                        parts_addr = local_addr.rsplit(':', 1)
                        address = parts_addr[0] if parts_addr[0] != '*' else '0.0.0.0'
                        port = int(parts_addr[1])
                else:
                    continue

                pid = 0
                process_name = ''
                user = ''

                for part in parts:
                    if part.startswith('users:'):
                        proc_match = re.search(r'\("([^"]+)",pid=(\d+)', part)
                        if proc_match:
                            process_name = proc_match.group(1)
                            pid = int(proc_match.group(2))

                is_protected = port in self.PROTECTED_SERVICES

                ports.append(ListeningPort(
                    port=port,
                    protocol=protocol,
                    address=address,
                    state=state,
                    pid=pid,
                    process_name=process_name,
                    user=user,
                    is_protected=is_protected
                ).to_dict())

            except Exception as e:
                continue

        return ports

    def _get_protected_ports(self, listening_ports: List[Dict]) -> List[Dict]:
        """Identify protected ports"""
        protected = []

        for port, service in self.PROTECTED_SERVICES.items():
            protected.append({
                'port': port,
                'service': service,
                'reason': 'Critical service',
                'is_listening': any(p['port'] == port for p in listening_ports)
            })

        return protected

    # ========================================================================
    # UFW COMMAND EXECUTION
    # ========================================================================

    def execute_command(self, command_type: str, params: Dict) -> Tuple[bool, str]:
        """
        Execute a UFW command

        command_type: allow, deny, reject, limit, delete, enable, disable, reset, reload, default, logging
        params: command parameters
        """
        try:
            if command_type == 'allow':
                return self._allow(params)
            elif command_type == 'deny':
                return self._deny(params)
            elif command_type == 'reject':
                return self._reject(params)
            elif command_type == 'limit':
                return self._limit(params)
            elif command_type == 'delete':
                return self._delete(params)
            elif command_type == 'delete_by_rule':
                return self._delete_by_rule(params)
            elif command_type == 'enable':
                return self._enable()
            elif command_type == 'disable':
                return self._disable()
            elif command_type == 'reset':
                return self._reset()
            elif command_type == 'reload':
                return self._reload()
            elif command_type == 'default':
                return self._set_default(params)
            elif command_type == 'logging':
                return self._set_logging(params)
            elif command_type == 'sync_now':
                return True, 'Sync requested'
            elif command_type == 'raw':
                return self._execute_raw(params)
            else:
                return False, f"Unknown command type: {command_type}"

        except Exception as e:
            self.logger.error(f"Error executing UFW command: {e}")
            return False, str(e)

    def _build_rule_args(self, params: Dict) -> List[str]:
        """Build UFW rule arguments from params"""
        args = []

        # Direction (in/out)
        direction = params.get('direction', 'in').lower()
        if direction == 'out':
            args.append('out')

        # From IP/subnet
        from_ip = params.get('from_ip') or params.get('from')
        if from_ip and from_ip.lower() != 'anywhere':
            args.extend(['from', from_ip])

        # To IP
        to_ip = params.get('to_ip') or params.get('to')
        if to_ip and to_ip.lower() != 'any':
            args.extend(['to', to_ip])

        # Port
        port = params.get('port') or params.get('to_port')
        if port:
            args.extend(['port', str(port)])

        # Protocol
        protocol = params.get('protocol')
        if protocol:
            args.extend(['proto', protocol])

        # Comment
        comment = params.get('comment')
        if comment:
            args.extend(['comment', comment])

        return args

    def _allow(self, params: Dict) -> Tuple[bool, str]:
        """Execute ufw allow command"""
        cmd = ['ufw', 'allow']

        # Simple format: port/protocol
        port = params.get('port')
        protocol = params.get('protocol', '')
        from_ip = params.get('from_ip') or params.get('from')

        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            # Allow from specific IP
            cmd.extend(['from', from_ip])
            if port:
                cmd.extend(['to', 'any', 'port', str(port)])
                if protocol:
                    cmd.extend(['proto', protocol])
        elif port:
            if protocol:
                cmd.append(f"{port}/{protocol}")
            else:
                cmd.append(str(port))
        else:
            return False, "Port is required for allow command"

        return self._run_ufw_command(cmd)

    def _deny(self, params: Dict) -> Tuple[bool, str]:
        """Execute ufw deny command"""
        cmd = ['ufw', 'deny']

        port = params.get('port')
        protocol = params.get('protocol', '')
        from_ip = params.get('from_ip') or params.get('from')

        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            cmd.extend(['from', from_ip])
            if port:
                cmd.extend(['to', 'any', 'port', str(port)])
                if protocol:
                    cmd.extend(['proto', protocol])
        elif port:
            if protocol:
                cmd.append(f"{port}/{protocol}")
            else:
                cmd.append(str(port))
        else:
            # Deny from IP only
            if from_ip:
                cmd.extend(['from', from_ip])
            else:
                return False, "Port or from_ip is required for deny command"

        return self._run_ufw_command(cmd)

    def _reject(self, params: Dict) -> Tuple[bool, str]:
        """Execute ufw reject command"""
        cmd = ['ufw', 'reject']

        port = params.get('port')
        protocol = params.get('protocol', '')

        if port:
            if protocol:
                cmd.append(f"{port}/{protocol}")
            else:
                cmd.append(str(port))
        else:
            return False, "Port is required for reject command"

        return self._run_ufw_command(cmd)

    def _limit(self, params: Dict) -> Tuple[bool, str]:
        """Execute ufw limit command (rate limiting)"""
        cmd = ['ufw', 'limit']

        port = params.get('port')
        protocol = params.get('protocol', 'tcp')

        if port:
            cmd.append(f"{port}/{protocol}")
        else:
            return False, "Port is required for limit command"

        return self._run_ufw_command(cmd)

    def _delete(self, params: Dict) -> Tuple[bool, str]:
        """Delete a rule by number"""
        rule_num = params.get('rule_number') or params.get('rule_index')

        if not rule_num:
            return False, "Rule number is required for delete command"

        cmd = ['ufw', '--force', 'delete', str(rule_num)]
        return self._run_ufw_command(cmd)

    def _delete_by_rule(self, params: Dict) -> Tuple[bool, str]:
        """Delete a rule by specification"""
        action = params.get('action', 'allow').lower()
        port = params.get('port')
        protocol = params.get('protocol', '')
        from_ip = params.get('from_ip')

        cmd = ['ufw', '--force', 'delete', action]

        if from_ip and from_ip.lower() not in ['anywhere', 'any']:
            cmd.extend(['from', from_ip])
            if port:
                cmd.extend(['to', 'any', 'port', str(port)])
                if protocol:
                    cmd.extend(['proto', protocol])
        elif port:
            if protocol:
                cmd.append(f"{port}/{protocol}")
            else:
                cmd.append(str(port))
        else:
            return False, "Port or specification required"

        return self._run_ufw_command(cmd)

    def _enable(self) -> Tuple[bool, str]:
        """Enable UFW"""
        cmd = ['ufw', '--force', 'enable']
        return self._run_ufw_command(cmd)

    def _disable(self) -> Tuple[bool, str]:
        """Disable UFW"""
        cmd = ['ufw', '--force', 'disable']
        return self._run_ufw_command(cmd)

    def _reset(self) -> Tuple[bool, str]:
        """Reset UFW to defaults"""
        cmd = ['ufw', '--force', 'reset']
        return self._run_ufw_command(cmd)

    def _reload(self) -> Tuple[bool, str]:
        """Reload UFW"""
        cmd = ['ufw', 'reload']
        return self._run_ufw_command(cmd)

    def _set_default(self, params: Dict) -> Tuple[bool, str]:
        """Set default policy"""
        direction = params.get('direction', 'incoming')
        policy = params.get('policy', 'deny')

        if direction not in ['incoming', 'outgoing', 'routed']:
            return False, f"Invalid direction: {direction}"

        if policy not in ['allow', 'deny', 'reject']:
            return False, f"Invalid policy: {policy}"

        cmd = ['ufw', 'default', policy, direction]
        return self._run_ufw_command(cmd)

    def _set_logging(self, params: Dict) -> Tuple[bool, str]:
        """Set logging level"""
        level = params.get('level', 'low')

        if level not in ['off', 'low', 'medium', 'high', 'full']:
            return False, f"Invalid logging level: {level}"

        cmd = ['ufw', 'logging', level]
        return self._run_ufw_command(cmd)

    def _execute_raw(self, params: Dict) -> Tuple[bool, str]:
        """Execute a raw UFW command"""
        raw_cmd = params.get('command', '')
        if not raw_cmd:
            return False, "Raw command is required"

        # Security check - only allow ufw commands
        if not raw_cmd.strip().startswith('ufw '):
            return False, "Only ufw commands are allowed"

        # Parse and execute
        parts = raw_cmd.strip().split()
        return self._run_ufw_command(parts)

    def _run_ufw_command(self, cmd: List[str]) -> Tuple[bool, str]:
        """Run a UFW command and return result"""
        try:
            self.logger.info(f"Executing: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout.strip() + result.stderr.strip()

            if result.returncode == 0:
                return True, output or "Command executed successfully"
            else:
                return False, output or "Command failed"

        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    # ========================================================================
    # CONVENIENCE METHODS
    # ========================================================================

    def allow_port(self, port: int, protocol: str = 'tcp') -> Tuple[bool, str]:
        """Allow a port"""
        return self._allow({'port': port, 'protocol': protocol})

    def deny_port(self, port: int, protocol: str = 'tcp') -> Tuple[bool, str]:
        """Deny a port"""
        return self._deny({'port': port, 'protocol': protocol})

    def allow_from_ip(self, ip: str, port: int = None) -> Tuple[bool, str]:
        """Allow all or specific port from an IP"""
        params = {'from_ip': ip}
        if port:
            params['port'] = port
        return self._allow(params)

    def deny_from_ip(self, ip: str) -> Tuple[bool, str]:
        """Block an IP address"""
        return self._deny({'from_ip': ip})

    def delete_rule(self, rule_number: int) -> Tuple[bool, str]:
        """Delete a rule by number"""
        return self._delete({'rule_number': rule_number})

    def get_raw_status(self) -> str:
        """Get raw UFW status output"""
        try:
            result = subprocess.run(
                ['ufw', 'status', 'verbose'],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout
        except Exception as e:
            return str(e)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    manager = UFWManager()
    data = manager.collect_all()

    print(json.dumps(data, indent=2, default=str))
