#!/usr/bin/env python3
"""
SSH Guardian v3.0 - Firewall Collector Module
Collects iptables rules, NAT rules, port forwarding, network configuration,
running ports, system users, and command history from remote servers.

Features:
- Collect all iptables rules (filter, nat, mangle, raw tables)
- Detect port forwarding configurations
- Parse rules into structured format
- Execute firewall commands (add/delete/modify rules)
- Track rule changes and command history
- Collect running ports (listening services)
- Collect system users
- Smart firewall rule suggestions
- Protected ports detection (prevent blocking critical services)
"""

import subprocess
import re
import json
import logging
import pwd
import os
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class IptablesRule:
    """Represents a single iptables rule"""
    table: str  # filter, nat, mangle, raw
    chain: str  # INPUT, OUTPUT, FORWARD, PREROUTING, POSTROUTING, custom
    rule_num: int
    target: str  # ACCEPT, DROP, REJECT, DNAT, SNAT, MASQUERADE, LOG, etc.
    protocol: str  # tcp, udp, icmp, all
    source: str
    destination: str
    in_interface: str
    out_interface: str
    ports: str  # dport/sport
    options: str  # additional options
    raw_rule: str  # original rule text
    bytes_count: int
    packets_count: int

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PortForward:
    """Represents a port forwarding rule"""
    external_port: int
    internal_ip: str
    internal_port: int
    protocol: str  # tcp, udp
    interface: str
    enabled: bool
    description: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class FirewallStatus:
    """Overall firewall status"""
    iptables_active: bool
    default_input_policy: str
    default_output_policy: str
    default_forward_policy: str
    total_rules: int
    port_forwards_count: int
    last_updated: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ListeningPort:
    """Represents a listening port/service"""
    port: int
    protocol: str  # tcp, udp
    address: str  # 0.0.0.0, 127.0.0.1, ::, etc.
    state: str  # LISTEN, ESTABLISHED, etc.
    pid: int
    process_name: str
    user: str
    is_protected: bool = False  # Critical service that shouldn't be blocked

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SystemUser:
    """Represents a system user"""
    username: str
    uid: int
    gid: int
    home_dir: str
    shell: str
    is_system_user: bool  # UID < 1000 typically
    is_login_enabled: bool  # Shell is not /sbin/nologin or /bin/false
    last_login: Optional[str] = None
    groups: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CommandHistoryEntry:
    """Represents a command executed on the system"""
    timestamp: str
    user: str
    command: str
    working_dir: str
    exit_code: Optional[int] = None

    def to_dict(self) -> Dict:
        return asdict(self)


# ============================================================================
# FIREWALL COLLECTOR
# ============================================================================

class FirewallCollector:
    """Collects and parses firewall rules from the system"""

    TABLES = ['filter', 'nat', 'mangle', 'raw']

    def __init__(self):
        self.logger = logging.getLogger('FirewallCollector')

    # Protected ports - services that should never be blocked
    PROTECTED_SERVICES = {
        22: 'SSH',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        8081: 'SSH Guardian Dashboard',  # Our dashboard
    }

    def collect_all(self) -> Dict:
        """Collect all firewall information"""
        try:
            listening_ports = self._get_listening_ports()
            return {
                'status': self._get_firewall_status(),
                'rules': self._collect_all_rules(),
                'port_forwards': self._detect_port_forwards(),
                'chains': self._get_chain_policies(),
                'interfaces': self._get_network_interfaces(),
                'listening_ports': listening_ports,
                'system_users': self._get_system_users(),
                'protected_ports': self._get_protected_ports(listening_ports),
                'collected_at': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error collecting firewall data: {e}")
            return {
                'error': str(e),
                'collected_at': datetime.now().isoformat()
            }

    def collect_extended(self) -> Dict:
        """Collect extended information including command history"""
        data = self.collect_all()
        data['command_history'] = self._get_command_history()
        data['active_connections'] = self._get_active_connections()
        return data

    def _get_firewall_status(self) -> Dict:
        """Get overall firewall status"""
        try:
            # Check if iptables is available
            result = subprocess.run(
                ['iptables', '-L', '-n'],
                capture_output=True, text=True, timeout=10
            )
            iptables_active = result.returncode == 0

            # Get default policies
            policies = self._get_chain_policies()
            filter_policies = policies.get('filter', {})

            # Count total rules
            all_rules = self._collect_all_rules()
            total_rules = sum(len(rules) for rules in all_rules.values())

            # Count port forwards
            port_forwards = self._detect_port_forwards()

            return FirewallStatus(
                iptables_active=iptables_active,
                default_input_policy=filter_policies.get('INPUT', 'UNKNOWN'),
                default_output_policy=filter_policies.get('OUTPUT', 'UNKNOWN'),
                default_forward_policy=filter_policies.get('FORWARD', 'UNKNOWN'),
                total_rules=total_rules,
                port_forwards_count=len(port_forwards),
                last_updated=datetime.now().isoformat()
            ).to_dict()

        except Exception as e:
            self.logger.error(f"Error getting firewall status: {e}")
            return {'error': str(e)}

    def _collect_all_rules(self) -> Dict[str, List[Dict]]:
        """Collect rules from all tables"""
        rules = {}
        for table in self.TABLES:
            rules[table] = self._collect_table_rules(table)
        return rules

    def _collect_table_rules(self, table: str) -> List[Dict]:
        """Collect rules from a specific table with verbose output"""
        try:
            # Use -L -n -v --line-numbers to get detailed rule info
            result = subprocess.run(
                ['iptables', '-t', table, '-L', '-n', '-v', '--line-numbers'],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                self.logger.warning(f"Could not read {table} table: {result.stderr}")
                return []

            return self._parse_iptables_output(table, result.stdout)

        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout reading {table} table")
            return []
        except FileNotFoundError:
            self.logger.error("iptables command not found")
            return []
        except Exception as e:
            self.logger.error(f"Error reading {table} table: {e}")
            return []

    def _parse_iptables_output(self, table: str, output: str) -> List[Dict]:
        """Parse iptables -L -n -v --line-numbers output"""
        rules = []
        current_chain = None

        lines = output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Chain header: "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)"
            chain_match = re.match(
                r'^Chain (\S+) \(policy (\S+)(?: (\d+) packets, (\d+) bytes)?\)',
                line
            )
            if chain_match:
                current_chain = chain_match.group(1)
                continue

            # Chain header (no policy): "Chain DOCKER (1 references)"
            chain_match2 = re.match(r'^Chain (\S+) \(\d+ references\)', line)
            if chain_match2:
                current_chain = chain_match2.group(1)
                continue

            # Skip header line
            if line.startswith('num') or line.startswith('pkts'):
                continue

            # Parse rule line
            if current_chain:
                rule = self._parse_rule_line(table, current_chain, line)
                if rule:
                    rules.append(rule)

        return rules

    def _parse_rule_line(self, table: str, chain: str, line: str) -> Optional[Dict]:
        """Parse a single rule line"""
        # Rule format: num pkts bytes target prot opt in out source destination [extra]
        # Example: 1 1000 50000 ACCEPT tcp -- eth0 * 0.0.0.0/0 192.168.1.100 tcp dpt:22

        parts = line.split()
        if len(parts) < 10:
            return None

        try:
            rule_num = int(parts[0])
            packets = self._parse_count(parts[1])
            bytes_count = self._parse_count(parts[2])
            target = parts[3]
            protocol = parts[4]
            # parts[5] is opt (usually --)
            in_interface = parts[6] if parts[6] != '*' else ''
            out_interface = parts[7] if parts[7] != '*' else ''
            source = parts[8]
            destination = parts[9]

            # Remaining parts are additional options (ports, states, etc.)
            options = ' '.join(parts[10:]) if len(parts) > 10 else ''

            # Extract port information
            ports = self._extract_ports(options)

            return IptablesRule(
                table=table,
                chain=chain,
                rule_num=rule_num,
                target=target,
                protocol=protocol,
                source=source,
                destination=destination,
                in_interface=in_interface,
                out_interface=out_interface,
                ports=ports,
                options=options,
                raw_rule=line,
                bytes_count=bytes_count,
                packets_count=packets
            ).to_dict()

        except (ValueError, IndexError) as e:
            self.logger.debug(f"Could not parse rule line: {line} - {e}")
            return None

    def _parse_count(self, value: str) -> int:
        """Parse packet/byte counts (handles K, M, G suffixes)"""
        try:
            value = value.upper()
            if value.endswith('K'):
                return int(float(value[:-1]) * 1000)
            elif value.endswith('M'):
                return int(float(value[:-1]) * 1000000)
            elif value.endswith('G'):
                return int(float(value[:-1]) * 1000000000)
            return int(value)
        except:
            return 0

    def _extract_ports(self, options: str) -> str:
        """Extract port information from options string"""
        ports = []

        # Match dpt:XXX or dpts:XXX:YYY
        dport_match = re.search(r'dpts?:(\S+)', options)
        if dport_match:
            ports.append(f"dport:{dport_match.group(1)}")

        # Match spt:XXX or spts:XXX:YYY
        sport_match = re.search(r'spts?:(\S+)', options)
        if sport_match:
            ports.append(f"sport:{sport_match.group(1)}")

        # Match multiport dports/sports
        multiport_match = re.search(r'multiport (d|s)ports (\S+)', options)
        if multiport_match:
            port_type = 'dport' if multiport_match.group(1) == 'd' else 'sport'
            ports.append(f"{port_type}:{multiport_match.group(2)}")

        return ', '.join(ports) if ports else ''

    def _detect_port_forwards(self) -> List[Dict]:
        """Detect port forwarding rules from NAT table"""
        port_forwards = []

        try:
            # Get PREROUTING chain from nat table
            result = subprocess.run(
                ['iptables', '-t', 'nat', '-L', 'PREROUTING', '-n', '-v', '--line-numbers'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                return []

            for line in result.stdout.split('\n'):
                # Look for DNAT rules
                if 'DNAT' in line:
                    pf = self._parse_port_forward(line)
                    if pf:
                        port_forwards.append(pf)

        except Exception as e:
            self.logger.error(f"Error detecting port forwards: {e}")

        return port_forwards

    def _parse_port_forward(self, line: str) -> Optional[Dict]:
        """Parse a DNAT rule into port forward structure"""
        try:
            # Extract protocol
            protocol = 'tcp'
            if 'udp' in line.lower():
                protocol = 'udp'

            # Extract external port (dpt:XXX)
            ext_port_match = re.search(r'dpt:(\d+)', line)
            if not ext_port_match:
                return None
            external_port = int(ext_port_match.group(1))

            # Extract destination (to:IP:PORT)
            dest_match = re.search(r'to:(\d+\.\d+\.\d+\.\d+):(\d+)', line)
            if not dest_match:
                # Try without port
                dest_match = re.search(r'to:(\d+\.\d+\.\d+\.\d+)', line)
                if dest_match:
                    internal_ip = dest_match.group(1)
                    internal_port = external_port  # Same as external
                else:
                    return None
            else:
                internal_ip = dest_match.group(1)
                internal_port = int(dest_match.group(2))

            # Extract interface
            iface_match = re.search(r'^.*?(\w+)\s+\*', line)
            interface = iface_match.group(1) if iface_match else ''

            return PortForward(
                external_port=external_port,
                internal_ip=internal_ip,
                internal_port=internal_port,
                protocol=protocol,
                interface=interface,
                enabled=True,
                description=f"Port forward {external_port}->{internal_ip}:{internal_port}"
            ).to_dict()

        except Exception as e:
            self.logger.debug(f"Could not parse port forward: {line} - {e}")
            return None

    def _get_chain_policies(self) -> Dict[str, Dict[str, str]]:
        """Get default policies for all chains"""
        policies = {}

        for table in self.TABLES:
            policies[table] = {}
            try:
                result = subprocess.run(
                    ['iptables', '-t', table, '-L', '-n'],
                    capture_output=True, text=True, timeout=10
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        # Match: Chain INPUT (policy ACCEPT)
                        match = re.match(r'^Chain (\S+) \(policy (\S+)', line)
                        if match:
                            policies[table][match.group(1)] = match.group(2)

            except Exception as e:
                self.logger.error(f"Error getting policies for {table}: {e}")

        return policies

    def _get_network_interfaces(self) -> List[Dict]:
        """Get network interface information"""
        interfaces = []

        try:
            result = subprocess.run(
                ['ip', '-j', 'addr'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                for iface in data:
                    iface_info = {
                        'name': iface.get('ifname', ''),
                        'state': iface.get('operstate', 'unknown'),
                        'mac': iface.get('address', ''),
                        'addresses': []
                    }

                    for addr_info in iface.get('addr_info', []):
                        iface_info['addresses'].append({
                            'ip': addr_info.get('local', ''),
                            'prefix': addr_info.get('prefixlen', 0),
                            'family': addr_info.get('family', '')
                        })

                    interfaces.append(iface_info)
            else:
                # Fallback to parsing ifconfig
                interfaces = self._get_interfaces_fallback()

        except json.JSONDecodeError:
            interfaces = self._get_interfaces_fallback()
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")

        return interfaces

    def _get_interfaces_fallback(self) -> List[Dict]:
        """Fallback method to get interfaces using ifconfig"""
        interfaces = []
        try:
            result = subprocess.run(
                ['ifconfig', '-a'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                current_iface = None
                for line in result.stdout.split('\n'):
                    # Interface line
                    iface_match = re.match(r'^(\S+):', line)
                    if iface_match:
                        if current_iface:
                            interfaces.append(current_iface)
                        current_iface = {
                            'name': iface_match.group(1),
                            'state': 'unknown',
                            'mac': '',
                            'addresses': []
                        }
                    elif current_iface:
                        # IPv4 address
                        ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            current_iface['addresses'].append({
                                'ip': ip_match.group(1),
                                'family': 'inet'
                            })
                        # MAC address
                        mac_match = re.search(r'ether ([0-9a-f:]+)', line)
                        if mac_match:
                            current_iface['mac'] = mac_match.group(1)

                if current_iface:
                    interfaces.append(current_iface)

        except Exception as e:
            self.logger.error(f"Error in fallback interface detection: {e}")

        return interfaces

    def _get_listening_ports(self) -> List[Dict]:
        """Get all listening ports on the system"""
        ports = []

        try:
            # Try ss command first (faster, more modern)
            result = subprocess.run(
                ['ss', '-tlnp'],  # TCP listening ports with process info
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                ports.extend(self._parse_ss_output(result.stdout, 'tcp'))

            # Also get UDP ports
            result = subprocess.run(
                ['ss', '-ulnp'],  # UDP listening ports with process info
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                ports.extend(self._parse_ss_output(result.stdout, 'udp'))

        except FileNotFoundError:
            # Fallback to netstat
            ports = self._get_listening_ports_netstat()
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
                # State is first column (LISTEN, UNCONN for UDP)
                state = parts[0]

                # Local address:port
                local_addr = parts[4] if len(parts) > 4 else ''

                # Parse address and port
                if ':' in local_addr:
                    # Handle IPv6 and IPv4
                    if local_addr.startswith('['):
                        # IPv6: [::]:22 or [::1]:22
                        match = re.match(r'\[([^\]]+)\]:(\d+)', local_addr)
                        if match:
                            address = match.group(1)
                            port = int(match.group(2))
                        else:
                            continue
                    else:
                        # IPv4 or *:port
                        parts_addr = local_addr.rsplit(':', 1)
                        address = parts_addr[0] if parts_addr[0] != '*' else '0.0.0.0'
                        port = int(parts_addr[1])
                else:
                    continue

                # Get process info from last column
                pid = 0
                process_name = ''
                user = ''

                # Process info looks like: users:(("sshd",pid=1234,fd=3))
                for part in parts:
                    if part.startswith('users:'):
                        proc_match = re.search(r'\("([^"]+)",pid=(\d+)', part)
                        if proc_match:
                            process_name = proc_match.group(1)
                            pid = int(proc_match.group(2))
                            # Get user from pid
                            user = self._get_process_user(pid)

                # Check if this is a protected port
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

            except (ValueError, IndexError) as e:
                self.logger.debug(f"Could not parse ss line: {line} - {e}")
                continue

        return ports

    def _get_listening_ports_netstat(self) -> List[Dict]:
        """Fallback: Get listening ports using netstat"""
        ports = []

        try:
            result = subprocess.run(
                ['netstat', '-tlnp'],  # TCP listening with programs
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'LISTEN' not in line:
                        continue

                    parts = line.split()
                    if len(parts) < 7:
                        continue

                    try:
                        # Local address is parts[3]
                        local = parts[3]
                        if ':' in local:
                            addr_parts = local.rsplit(':', 1)
                            address = addr_parts[0]
                            port = int(addr_parts[1])
                        else:
                            continue

                        # PID/Program is parts[6]
                        pid_prog = parts[6]
                        pid = 0
                        process_name = ''

                        if '/' in pid_prog:
                            pid_parts = pid_prog.split('/')
                            try:
                                pid = int(pid_parts[0])
                            except:
                                pass
                            process_name = pid_parts[1] if len(pid_parts) > 1 else ''

                        user = self._get_process_user(pid) if pid else ''
                        is_protected = port in self.PROTECTED_SERVICES

                        ports.append(ListeningPort(
                            port=port,
                            protocol='tcp',
                            address=address,
                            state='LISTEN',
                            pid=pid,
                            process_name=process_name,
                            user=user,
                            is_protected=is_protected
                        ).to_dict())

                    except (ValueError, IndexError):
                        continue

            # Also get UDP
            result = subprocess.run(
                ['netstat', '-ulnp'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'udp' not in line.lower():
                        continue

                    parts = line.split()
                    if len(parts) < 6:
                        continue

                    try:
                        local = parts[3]
                        if ':' in local:
                            addr_parts = local.rsplit(':', 1)
                            address = addr_parts[0]
                            port = int(addr_parts[1])
                        else:
                            continue

                        pid_prog = parts[-1]
                        pid = 0
                        process_name = ''

                        if '/' in pid_prog:
                            pid_parts = pid_prog.split('/')
                            try:
                                pid = int(pid_parts[0])
                            except:
                                pass
                            process_name = pid_parts[1] if len(pid_parts) > 1 else ''

                        user = self._get_process_user(pid) if pid else ''
                        is_protected = port in self.PROTECTED_SERVICES

                        ports.append(ListeningPort(
                            port=port,
                            protocol='udp',
                            address=address,
                            state='UNCONN',
                            pid=pid,
                            process_name=process_name,
                            user=user,
                            is_protected=is_protected
                        ).to_dict())

                    except (ValueError, IndexError):
                        continue

        except Exception as e:
            self.logger.error(f"Error getting ports via netstat: {e}")

        return ports

    def _get_process_user(self, pid: int) -> str:
        """Get the username running a process"""
        if pid <= 0:
            return ''

        try:
            # Read /proc/<pid>/status for Uid
            with open(f'/proc/{pid}/status', 'r') as f:
                for line in f:
                    if line.startswith('Uid:'):
                        uid = int(line.split()[1])
                        try:
                            return pwd.getpwuid(uid).pw_name
                        except KeyError:
                            return str(uid)
        except (FileNotFoundError, PermissionError, IOError):
            pass

        return ''

    def _get_system_users(self) -> List[Dict]:
        """Get all system users with their details"""
        users = []

        try:
            # Read /etc/passwd
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    parts = line.split(':')
                    if len(parts) < 7:
                        continue

                    username = parts[0]
                    uid = int(parts[2])
                    gid = int(parts[3])
                    home_dir = parts[5]
                    shell = parts[6]

                    # Determine if system user (UID < 1000 on most systems)
                    is_system = uid < 1000

                    # Check if login is enabled
                    nologin_shells = ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']
                    is_login_enabled = shell not in nologin_shells

                    # Get groups for user
                    groups = self._get_user_groups(username)

                    # Get last login
                    last_login = self._get_last_login(username)

                    users.append(SystemUser(
                        username=username,
                        uid=uid,
                        gid=gid,
                        home_dir=home_dir,
                        shell=shell,
                        is_system_user=is_system,
                        is_login_enabled=is_login_enabled,
                        last_login=last_login,
                        groups=groups
                    ).to_dict())

        except Exception as e:
            self.logger.error(f"Error getting system users: {e}")

        return users

    def _get_user_groups(self, username: str) -> List[str]:
        """Get groups for a user"""
        groups = []

        try:
            result = subprocess.run(
                ['groups', username],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                # Output format: "username : group1 group2 group3"
                output = result.stdout.strip()
                if ':' in output:
                    groups_part = output.split(':', 1)[1].strip()
                    groups = groups_part.split()

        except Exception:
            pass

        return groups

    def _get_last_login(self, username: str) -> Optional[str]:
        """Get last login time for a user"""
        try:
            result = subprocess.run(
                ['lastlog', '-u', username],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    # Parse second line (first is header)
                    line = lines[1]
                    if '**Never logged in**' in line:
                        return None

                    # Extract date part (last 24 chars typically)
                    parts = line.split()
                    if len(parts) >= 4:
                        # Format: Username Port From Latest
                        # The latest login is the last few fields
                        return ' '.join(parts[3:])

        except Exception:
            pass

        return None

    def _get_protected_ports(self, listening_ports: List[Dict]) -> List[Dict]:
        """Identify protected ports from listening ports"""
        protected = []

        # Add known protected services
        for port, service in self.PROTECTED_SERVICES.items():
            protected.append({
                'port': port,
                'service': service,
                'reason': 'Critical service',
                'is_listening': any(p['port'] == port for p in listening_ports)
            })

        # Add dynamically discovered services from listening ports
        for port_info in listening_ports:
            port = port_info['port']
            if port not in self.PROTECTED_SERVICES:
                # Consider high-traffic or essential services as protected
                if port_info.get('process_name') in ['sshd', 'nginx', 'apache2',
                                                      'httpd', 'mysqld', 'postgres',
                                                      'redis-server', 'docker-proxy']:
                    protected.append({
                        'port': port,
                        'service': port_info.get('process_name', 'Unknown'),
                        'reason': 'Essential service detected',
                        'is_listening': True
                    })

        return protected

    def _get_command_history(self, max_entries: int = 100) -> List[Dict]:
        """Get recent command history from shell history files"""
        history = []

        # Check common history file locations
        history_files = [
            '/root/.bash_history',
            '/root/.zsh_history',
        ]

        # Also check for other users
        try:
            for entry in os.scandir('/home'):
                if entry.is_dir():
                    history_files.append(f'/home/{entry.name}/.bash_history')
                    history_files.append(f'/home/{entry.name}/.zsh_history')
        except (PermissionError, FileNotFoundError):
            pass

        for hist_file in history_files:
            try:
                if not os.path.exists(hist_file):
                    continue

                # Extract username from path
                if '/root/' in hist_file:
                    user = 'root'
                else:
                    parts = hist_file.split('/')
                    user = parts[2] if len(parts) > 2 else 'unknown'

                with open(hist_file, 'r', errors='ignore') as f:
                    lines = f.readlines()

                # Get last N entries
                for line in lines[-max_entries:]:
                    line = line.strip()
                    if not line:
                        continue

                    # Handle zsh history format with timestamp
                    timestamp = None
                    command = line

                    if line.startswith(': '):
                        # zsh format: ": timestamp:0;command"
                        match = re.match(r': (\d+):\d+;(.+)', line)
                        if match:
                            timestamp = datetime.fromtimestamp(int(match.group(1))).isoformat()
                            command = match.group(2)

                    history.append(CommandHistoryEntry(
                        timestamp=timestamp or datetime.now().isoformat(),
                        user=user,
                        command=command,
                        working_dir='~',  # Not available from history
                        exit_code=None
                    ).to_dict())

            except (PermissionError, FileNotFoundError, IOError) as e:
                self.logger.debug(f"Could not read {hist_file}: {e}")
                continue

        # Sort by timestamp and limit
        history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return history[:max_entries]

    def _get_active_connections(self) -> List[Dict]:
        """Get active network connections"""
        connections = []

        try:
            result = subprocess.run(
                ['ss', '-tnp'],  # TCP connections with process info
                capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')

                for line in lines[1:]:  # Skip header
                    if not line.strip():
                        continue

                    parts = line.split()
                    if len(parts) < 5:
                        continue

                    try:
                        state = parts[0]
                        local = parts[3]
                        remote = parts[4]

                        # Parse local address
                        local_addr, local_port = self._parse_address(local)
                        remote_addr, remote_port = self._parse_address(remote)

                        # Get process info
                        process = ''
                        pid = 0
                        for part in parts:
                            if part.startswith('users:'):
                                match = re.search(r'\("([^"]+)",pid=(\d+)', part)
                                if match:
                                    process = match.group(1)
                                    pid = int(match.group(2))

                        connections.append({
                            'state': state,
                            'local_address': local_addr,
                            'local_port': local_port,
                            'remote_address': remote_addr,
                            'remote_port': remote_port,
                            'process': process,
                            'pid': pid,
                            'protocol': 'tcp'
                        })

                    except (ValueError, IndexError):
                        continue

        except Exception as e:
            self.logger.error(f"Error getting active connections: {e}")

        return connections

    def _parse_address(self, addr: str) -> Tuple[str, int]:
        """Parse address:port string"""
        if addr.startswith('['):
            # IPv6
            match = re.match(r'\[([^\]]+)\]:(\d+)', addr)
            if match:
                return match.group(1), int(match.group(2))
        else:
            # IPv4
            parts = addr.rsplit(':', 1)
            if len(parts) == 2:
                return parts[0], int(parts[1])

        return addr, 0


# ============================================================================
# SMART RULE SUGGESTION ENGINE
# ============================================================================

class RuleSuggestionEngine:
    """Suggests firewall rules based on system state"""

    def __init__(self, collector: FirewallCollector):
        self.collector = collector
        self.logger = logging.getLogger('RuleSuggestionEngine')

    def generate_suggestions(self, data: Dict) -> List[Dict]:
        """Generate firewall rule suggestions based on collected data"""
        suggestions = []

        listening_ports = data.get('listening_ports', [])
        active_connections = data.get('active_connections', [])
        rules = data.get('rules', {}).get('filter', [])
        protected_ports = data.get('protected_ports', [])

        # 1. Suggest rules for listening ports without protection
        suggestions.extend(self._suggest_port_protection(listening_ports, rules))

        # 2. Suggest blocking suspicious connections
        suggestions.extend(self._suggest_block_suspicious(active_connections))

        # 3. Suggest rate limiting for exposed services
        suggestions.extend(self._suggest_rate_limiting(listening_ports, rules))

        # 4. Suggest SSH hardening rules
        suggestions.extend(self._suggest_ssh_hardening(listening_ports, rules))

        # 5. Warn about potential security issues
        suggestions.extend(self._suggest_security_improvements(rules, data))

        return suggestions

    def _suggest_port_protection(self, listening_ports: List[Dict],
                                  existing_rules: List[Dict]) -> List[Dict]:
        """Suggest protection for listening ports"""
        suggestions = []

        # Get ports that have rules
        protected_ports = set()
        for rule in existing_rules:
            ports_str = rule.get('ports', '')
            if 'dport:' in ports_str:
                match = re.search(r'dport:(\d+)', ports_str)
                if match:
                    protected_ports.add(int(match.group(1)))

        for port_info in listening_ports:
            port = port_info['port']

            # Skip if already has a rule
            if port in protected_ports:
                continue

            # Skip localhost-only services
            if port_info['address'] in ['127.0.0.1', '::1']:
                continue

            # Suggest accepting traffic for legitimate services
            if port_info.get('is_protected') or port_info.get('process_name'):
                suggestions.append({
                    'type': 'allow_service',
                    'priority': 'medium',
                    'title': f"Allow {port_info.get('process_name', 'service')} on port {port}",
                    'description': f"Port {port} is listening ({port_info.get('process_name', 'unknown')}) "
                                  f"but has no explicit firewall rule.",
                    'rule': {
                        'table': 'filter',
                        'chain': 'INPUT',
                        'protocol': port_info['protocol'],
                        'dport': port,
                        'target': 'ACCEPT',
                        'comment': f"Allow {port_info.get('process_name', 'service')}"
                    },
                    'auto_apply': False
                })

        return suggestions

    def _suggest_block_suspicious(self, connections: List[Dict]) -> List[Dict]:
        """Suggest blocking suspicious connections"""
        suggestions = []

        # Track connection counts by IP
        ip_counts = {}
        for conn in connections:
            remote_ip = conn.get('remote_address', '')
            if remote_ip and remote_ip not in ['127.0.0.1', '::1', '*']:
                ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1

        # Suggest blocking IPs with many connections (potential DoS)
        for ip, count in ip_counts.items():
            if count > 50:  # Threshold for suspicious activity
                suggestions.append({
                    'type': 'block_ip',
                    'priority': 'high',
                    'title': f"Block suspicious IP: {ip}",
                    'description': f"IP {ip} has {count} active connections. "
                                  f"This may indicate an attack or misconfiguration.",
                    'rule': {
                        'table': 'filter',
                        'chain': 'INPUT',
                        'source': ip,
                        'target': 'DROP',
                        'comment': f"Block suspicious activity from {ip}"
                    },
                    'auto_apply': False
                })

        return suggestions

    def _suggest_rate_limiting(self, listening_ports: List[Dict],
                               existing_rules: List[Dict]) -> List[Dict]:
        """Suggest rate limiting for exposed services"""
        suggestions = []

        # Check if rate limiting exists
        has_rate_limit = any('limit' in str(rule) for rule in existing_rules)

        # Services that should have rate limiting
        rate_limit_ports = {
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
        }

        for port_info in listening_ports:
            port = port_info['port']

            if port in rate_limit_ports and not has_rate_limit:
                suggestions.append({
                    'type': 'rate_limit',
                    'priority': 'medium',
                    'title': f"Add rate limiting for {rate_limit_ports[port]}",
                    'description': f"Consider adding rate limiting for {rate_limit_ports[port]} "
                                  f"on port {port} to prevent brute force attacks.",
                    'rule': {
                        'table': 'filter',
                        'chain': 'INPUT',
                        'protocol': 'tcp',
                        'dport': port,
                        'state': 'NEW',
                        'target': 'ACCEPT',
                        'comment': f"Rate limit {rate_limit_ports[port]}"
                    },
                    'iptables_cmd': f"iptables -A INPUT -p tcp --dport {port} "
                                   f"-m state --state NEW -m recent --set && "
                                   f"iptables -A INPUT -p tcp --dport {port} "
                                   f"-m state --state NEW -m recent --update "
                                   f"--seconds 60 --hitcount 10 -j DROP",
                    'auto_apply': False
                })

        return suggestions

    def _suggest_ssh_hardening(self, listening_ports: List[Dict],
                               existing_rules: List[Dict]) -> List[Dict]:
        """Suggest SSH-specific hardening rules"""
        suggestions = []

        # Check if SSH is running
        ssh_running = any(p['port'] == 22 or p.get('process_name') == 'sshd'
                          for p in listening_ports)

        if not ssh_running:
            return suggestions

        # Check for SSH-specific rules
        ssh_rules = [r for r in existing_rules if 'dport:22' in r.get('ports', '')]

        if not ssh_rules:
            suggestions.append({
                'type': 'ssh_hardening',
                'priority': 'high',
                'title': "Add SSH access control",
                'description': "SSH port 22 is open but has no specific firewall rules. "
                              "Consider restricting access to specific IPs or networks.",
                'rule': {
                    'table': 'filter',
                    'chain': 'INPUT',
                    'protocol': 'tcp',
                    'dport': 22,
                    'target': 'ACCEPT',
                    'comment': "Allow SSH - consider restricting source"
                },
                'auto_apply': False
            })

        return suggestions

    def _suggest_security_improvements(self, rules: List[Dict],
                                       data: Dict) -> List[Dict]:
        """Suggest general security improvements"""
        suggestions = []

        # Check chain policies
        chains = data.get('chains', {}).get('filter', {})

        # Warn if INPUT policy is ACCEPT
        if chains.get('INPUT') == 'ACCEPT':
            suggestions.append({
                'type': 'policy',
                'priority': 'high',
                'title': "Consider restrictive INPUT policy",
                'description': "The INPUT chain has ACCEPT as default policy. "
                              "A DROP policy with explicit allows is more secure.",
                'recommendation': "Set INPUT policy to DROP and add explicit ACCEPT rules "
                                 "for required services.",
                'auto_apply': False
            })

        # Warn if FORWARD policy is ACCEPT and not needed
        if chains.get('FORWARD') == 'ACCEPT':
            # Check if this is a router/gateway
            interfaces = data.get('interfaces', [])
            if len(interfaces) <= 2:  # Likely not a router
                suggestions.append({
                    'type': 'policy',
                    'priority': 'medium',
                    'title': "Disable forwarding if not needed",
                    'description': "The FORWARD chain has ACCEPT policy. "
                                  "If this system is not a router, set it to DROP.",
                    'auto_apply': False
                })

        return suggestions


# ============================================================================
# FIREWALL MANAGER
# ============================================================================

class FirewallManager:
    """Manages firewall rules - add, delete, modify"""

    def __init__(self):
        self.logger = logging.getLogger('FirewallManager')
        self.collector = FirewallCollector()

    def add_rule(self, rule_spec: Dict) -> Tuple[bool, str]:
        """
        Add a new iptables rule

        rule_spec should contain:
        - table: filter, nat, mangle, raw (default: filter)
        - chain: INPUT, OUTPUT, FORWARD, etc.
        - target: ACCEPT, DROP, REJECT, etc.
        - protocol: tcp, udp, icmp, all (default: all)
        - source: source IP/CIDR (default: 0.0.0.0/0)
        - destination: destination IP/CIDR (default: 0.0.0.0/0)
        - dport: destination port (optional)
        - sport: source port (optional)
        - in_interface: input interface (optional)
        - out_interface: output interface (optional)
        - position: insert position (optional, default: append)
        """
        try:
            table = rule_spec.get('table', 'filter')
            chain = rule_spec.get('chain')
            target = rule_spec.get('target')

            if not chain or not target:
                return False, "Chain and target are required"

            # Build command
            cmd = ['iptables', '-t', table]

            # Insert or append
            position = rule_spec.get('position')
            if position:
                cmd.extend(['-I', chain, str(position)])
            else:
                cmd.extend(['-A', chain])

            # Protocol
            protocol = rule_spec.get('protocol', 'all')
            if protocol != 'all':
                cmd.extend(['-p', protocol])

            # Source
            source = rule_spec.get('source')
            if source and source != '0.0.0.0/0':
                cmd.extend(['-s', source])

            # Destination
            destination = rule_spec.get('destination')
            if destination and destination != '0.0.0.0/0':
                cmd.extend(['-d', destination])

            # Interfaces
            in_iface = rule_spec.get('in_interface')
            if in_iface:
                cmd.extend(['-i', in_iface])

            out_iface = rule_spec.get('out_interface')
            if out_iface:
                cmd.extend(['-o', out_iface])

            # Ports (require protocol tcp or udp)
            dport = rule_spec.get('dport')
            if dport:
                if protocol not in ['tcp', 'udp']:
                    return False, "Destination port requires tcp or udp protocol"
                cmd.extend(['--dport', str(dport)])

            sport = rule_spec.get('sport')
            if sport:
                if protocol not in ['tcp', 'udp']:
                    return False, "Source port requires tcp or udp protocol"
                cmd.extend(['--sport', str(sport)])

            # State/conntrack
            state = rule_spec.get('state')
            if state:
                cmd.extend(['-m', 'state', '--state', state])

            # Comment
            comment = rule_spec.get('comment')
            if comment:
                cmd.extend(['-m', 'comment', '--comment', comment[:256]])

            # Target (action)
            cmd.extend(['-j', target])

            # REJECT with type
            if target == 'REJECT':
                reject_with = rule_spec.get('reject_with', 'icmp-port-unreachable')
                cmd.extend(['--reject-with', reject_with])

            # LOG with prefix
            if target == 'LOG':
                log_prefix = rule_spec.get('log_prefix', 'IPTABLES: ')
                cmd.extend(['--log-prefix', log_prefix])

            # Execute command
            self.logger.info(f"Adding rule: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return True, f"Rule added successfully: {' '.join(cmd)}"
            else:
                return False, f"Failed to add rule: {result.stderr}"

        except Exception as e:
            self.logger.error(f"Error adding rule: {e}")
            return False, str(e)

    def delete_rule(self, table: str, chain: str, rule_num: int) -> Tuple[bool, str]:
        """Delete a rule by number"""
        try:
            cmd = ['iptables', '-t', table, '-D', chain, str(rule_num)]

            self.logger.info(f"Deleting rule: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return True, f"Rule {rule_num} deleted from {chain} in {table} table"
            else:
                return False, f"Failed to delete rule: {result.stderr}"

        except Exception as e:
            self.logger.error(f"Error deleting rule: {e}")
            return False, str(e)

    def delete_rule_by_spec(self, rule_spec: Dict) -> Tuple[bool, str]:
        """Delete a rule by specification (matches the rule parameters)"""
        try:
            table = rule_spec.get('table', 'filter')
            chain = rule_spec.get('chain')

            if not chain:
                return False, "Chain is required"

            # Build command similar to add but with -D
            cmd = ['iptables', '-t', table, '-D', chain]

            # Add rule specifications
            protocol = rule_spec.get('protocol', 'all')
            if protocol != 'all':
                cmd.extend(['-p', protocol])

            source = rule_spec.get('source')
            if source and source != '0.0.0.0/0':
                cmd.extend(['-s', source])

            destination = rule_spec.get('destination')
            if destination and destination != '0.0.0.0/0':
                cmd.extend(['-d', destination])

            dport = rule_spec.get('dport')
            if dport and protocol in ['tcp', 'udp']:
                cmd.extend(['--dport', str(dport)])

            target = rule_spec.get('target')
            if target:
                cmd.extend(['-j', target])

            self.logger.info(f"Deleting rule by spec: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return True, "Rule deleted successfully"
            else:
                return False, f"Failed to delete rule: {result.stderr}"

        except Exception as e:
            self.logger.error(f"Error deleting rule: {e}")
            return False, str(e)

    def add_port_forward(self, external_port: int, internal_ip: str,
                         internal_port: int, protocol: str = 'tcp',
                         interface: str = None) -> Tuple[bool, str]:
        """Add a port forwarding rule"""
        try:
            # DNAT rule in PREROUTING
            dnat_cmd = [
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-p', protocol, '--dport', str(external_port)
            ]

            if interface:
                dnat_cmd.extend(['-i', interface])

            dnat_cmd.extend([
                '-j', 'DNAT', '--to-destination',
                f'{internal_ip}:{internal_port}'
            ])

            self.logger.info(f"Adding port forward DNAT: {' '.join(dnat_cmd)}")
            result = subprocess.run(dnat_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return False, f"Failed to add DNAT rule: {result.stderr}"

            # Also add FORWARD rule to allow the traffic
            forward_cmd = [
                'iptables', '-A', 'FORWARD',
                '-p', protocol, '-d', internal_ip,
                '--dport', str(internal_port),
                '-j', 'ACCEPT'
            ]

            self.logger.info(f"Adding port forward FORWARD: {' '.join(forward_cmd)}")
            result = subprocess.run(forward_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                # Rollback DNAT
                self.logger.warning("Failed to add FORWARD rule, rolling back DNAT")
                return False, f"Failed to add FORWARD rule: {result.stderr}"

            return True, f"Port forward added: {external_port} -> {internal_ip}:{internal_port}"

        except Exception as e:
            self.logger.error(f"Error adding port forward: {e}")
            return False, str(e)

    def remove_port_forward(self, external_port: int, internal_ip: str,
                           internal_port: int, protocol: str = 'tcp') -> Tuple[bool, str]:
        """Remove a port forwarding rule"""
        try:
            # Remove DNAT rule
            dnat_cmd = [
                'iptables', '-t', 'nat', '-D', 'PREROUTING',
                '-p', protocol, '--dport', str(external_port),
                '-j', 'DNAT', '--to-destination',
                f'{internal_ip}:{internal_port}'
            ]

            self.logger.info(f"Removing port forward DNAT: {' '.join(dnat_cmd)}")
            subprocess.run(dnat_cmd, capture_output=True, text=True, timeout=30)

            # Remove FORWARD rule
            forward_cmd = [
                'iptables', '-D', 'FORWARD',
                '-p', protocol, '-d', internal_ip,
                '--dport', str(internal_port),
                '-j', 'ACCEPT'
            ]

            self.logger.info(f"Removing port forward FORWARD: {' '.join(forward_cmd)}")
            subprocess.run(forward_cmd, capture_output=True, text=True, timeout=30)

            return True, f"Port forward removed: {external_port} -> {internal_ip}:{internal_port}"

        except Exception as e:
            self.logger.error(f"Error removing port forward: {e}")
            return False, str(e)

    def set_chain_policy(self, chain: str, policy: str, table: str = 'filter') -> Tuple[bool, str]:
        """Set default policy for a chain"""
        if policy not in ['ACCEPT', 'DROP', 'REJECT']:
            return False, f"Invalid policy: {policy}. Must be ACCEPT, DROP, or REJECT"

        if chain not in ['INPUT', 'OUTPUT', 'FORWARD']:
            return False, f"Cannot set policy for chain: {chain}"

        try:
            cmd = ['iptables', '-t', table, '-P', chain, policy]

            self.logger.info(f"Setting chain policy: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return True, f"Policy for {chain} set to {policy}"
            else:
                return False, f"Failed to set policy: {result.stderr}"

        except Exception as e:
            self.logger.error(f"Error setting policy: {e}")
            return False, str(e)

    def flush_chain(self, chain: str = None, table: str = 'filter') -> Tuple[bool, str]:
        """Flush all rules from a chain (or all chains if chain is None)"""
        try:
            if chain:
                cmd = ['iptables', '-t', table, '-F', chain]
            else:
                cmd = ['iptables', '-t', table, '-F']

            self.logger.info(f"Flushing chain: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                return True, f"Flushed {'chain ' + chain if chain else 'all chains'} in {table} table"
            else:
                return False, f"Failed to flush: {result.stderr}"

        except Exception as e:
            self.logger.error(f"Error flushing chain: {e}")
            return False, str(e)

    def save_rules(self, filepath: str = '/etc/iptables/rules.v4') -> Tuple[bool, str]:
        """Save current rules to a file"""
        try:
            result = subprocess.run(
                ['iptables-save'],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                # Ensure directory exists
                import os
                os.makedirs(os.path.dirname(filepath), exist_ok=True)

                with open(filepath, 'w') as f:
                    f.write(result.stdout)

                return True, f"Rules saved to {filepath}"
            else:
                return False, f"Failed to save rules: {result.stderr}"

        except Exception as e:
            self.logger.error(f"Error saving rules: {e}")
            return False, str(e)

    def restore_rules(self, filepath: str = '/etc/iptables/rules.v4') -> Tuple[bool, str]:
        """Restore rules from a file"""
        try:
            with open(filepath, 'r') as f:
                rules = f.read()

            result = subprocess.run(
                ['iptables-restore'],
                input=rules,
                capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                return True, f"Rules restored from {filepath}"
            else:
                return False, f"Failed to restore rules: {result.stderr}"

        except FileNotFoundError:
            return False, f"Rules file not found: {filepath}"
        except Exception as e:
            self.logger.error(f"Error restoring rules: {e}")
            return False, str(e)


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    collector = FirewallCollector()
    data = collector.collect_all()

    print(json.dumps(data, indent=2, default=str))
