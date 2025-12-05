"""
SSH Guardian v3.0 - Attack Simulation Templates
Predefined attack scenarios with realistic parameters
"""

from typing import Dict, Any, List

ATTACK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "name": "Brute Force Attack",
        "description": "Multiple rapid failed login attempts from malicious IP targeting common usernames",
        "category": "high_priority",
        "severity": "critical",
        "template": {
            "event_type": "failed",
            "source_ip": "<from_pool:malicious>",
            "username": "root",
            "server_hostname": "prod-web-01",
            "port": 22,
            "failure_reason": "invalid_password",
            "attempts": 15,
            "time_window_seconds": 60,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 85",
                "ip_blocked": True,
                "threat_type": "brute_force"
            }
        }
    },

    "distributed_brute_force": {
        "name": "Distributed Brute Force",
        "description": "Coordinated attack from multiple IPs targeting same username",
        "category": "high_priority",
        "severity": "critical",
        "template": {
            "event_type": "failed",
            "source_ip": "<from_pool:malicious:multiple:5>",
            "username": "admin",
            "server_hostname": "prod-web-01",
            "port": 22,
            "failure_reason": "invalid_password",
            "attempts_per_ip": 5,
            "time_window_seconds": 120,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 80",
                "ip_blocked": True,
                "threat_type": "brute_force"
            }
        }
    },

    "successful_trusted": {
        "name": "Successful Login - Trusted IP",
        "description": "Normal legitimate login from whitelisted IP address",
        "category": "legitimate",
        "severity": "low",
        "template": {
            "event_type": "successful",
            "source_ip": "<from_pool:trusted>",
            "username": "admin",
            "server_hostname": "prod-web-01",
            "port": 22,
            "session_duration": 3600,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": "< 40",
                "ip_blocked": False,
                "threat_type": "normal"
            }
        }
    },

    "successful_malicious": {
        "name": "Successful Login - Malicious IP",
        "description": "Successful authentication from known malicious IP (compromised credentials)",
        "category": "compromise",
        "severity": "critical",
        "template": {
            "event_type": "successful",
            "source_ip": "<from_pool:malicious>",
            "username": "backup",
            "server_hostname": "prod-db-01",
            "port": 22,
            "session_duration": 7200,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 75",
                "ip_blocked": True,
                "threat_type": "intrusion"
            }
        }
    },

    "reconnaissance": {
        "name": "Reconnaissance Scan",
        "description": "Attacker probing multiple usernames from single IP",
        "category": "scanning",
        "severity": "high",
        "template": {
            "event_type": "failed",
            "source_ip": "<from_pool:malicious>",
            "username": ["root", "admin", "user", "test", "guest", "ubuntu", "centos", "oracle"],
            "server_hostname": "prod-web-02",
            "port": 22,
            "failure_reason": "invalid_user",
            "attempts_per_user": 2,
            "time_window_seconds": 180,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 70",
                "ip_blocked": True,
                "threat_type": "reconnaissance"
            }
        }
    },

    "invalid_user": {
        "name": "Invalid User Attempts",
        "description": "Multiple attempts using non-existent usernames",
        "category": "probing",
        "severity": "medium",
        "template": {
            "event_type": "failed",
            "source_ip": "<from_pool:random>",
            "username": ["hacker", "test123", "admin123", "ftp", "oracle"],
            "server_hostname": "prod-app-01",
            "port": 22,
            "failure_reason": "invalid_user",
            "attempts": 10,
            "time_window_seconds": 90,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 60",
                "ip_blocked": True,
                "threat_type": "reconnaissance"
            }
        }
    },

    "geographic_anomaly": {
        "name": "Geographic Anomaly",
        "description": "Successful login from unusual geographic location",
        "category": "anomaly",
        "severity": "high",
        "template": {
            "event_type": "successful",
            "source_ip": "<from_pool:malicious>",
            "username": "developer",
            "server_hostname": "prod-api-01",
            "port": 22,
            "session_duration": 1800,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 65",
                "ip_blocked": False,
                "threat_type": "geographic_anomaly"
            }
        }
    },

    "credential_stuffing": {
        "name": "Credential Stuffing",
        "description": "Automated login attempts with stolen credential lists",
        "category": "credential_attack",
        "severity": "high",
        "template": {
            "event_type": "failed",
            "source_ip": "<from_pool:malicious>",
            "username": ["john", "sarah", "mike", "jennifer", "david", "lisa"],
            "server_hostname": "prod-web-03",
            "port": 22,
            "failure_reason": "invalid_password",
            "attempts_per_user": 3,
            "time_window_seconds": 45,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 80",
                "ip_blocked": True,
                "threat_type": "brute_force"
            }
        }
    },

    "slow_brute_force": {
        "name": "Slow Brute Force",
        "description": "Stealthy brute force with delayed attempts to evade detection",
        "category": "evasion",
        "severity": "medium",
        "template": {
            "event_type": "failed",
            "source_ip": "<from_pool:malicious>",
            "username": "root",
            "server_hostname": "prod-db-02",
            "port": 22,
            "failure_reason": "invalid_password",
            "attempts": 8,
            "time_window_seconds": 600,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 55",
                "ip_blocked": True,
                "threat_type": "brute_force"
            }
        }
    },

    "after_hours_access": {
        "name": "After-Hours Access Attempt",
        "description": "Login attempts during non-business hours (suspicious timing)",
        "category": "temporal_anomaly",
        "severity": "medium",
        "template": {
            "event_type": "successful",
            "source_ip": "<from_pool:random>",
            "username": "admin",
            "server_hostname": "prod-web-01",
            "port": 22,
            "session_duration": 600,
            "auth_method": "password",
            "expected_outcome": {
                "ml_risk_score": ">= 50",
                "ip_blocked": False,
                "threat_type": "temporal_anomaly"
            }
        }
    }
}


def get_template(template_name: str) -> Dict[str, Any]:
    """Get a specific attack template"""
    if template_name not in ATTACK_TEMPLATES:
        raise ValueError(f"Unknown template: {template_name}")
    return ATTACK_TEMPLATES[template_name]


def get_all_templates() -> Dict[str, Dict[str, Any]]:
    """Get all available templates"""
    return ATTACK_TEMPLATES


def get_templates_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """Get templates filtered by category"""
    return {
        name: template
        for name, template in ATTACK_TEMPLATES.items()
        if template.get('category') == category
    }


def get_template_list() -> List[Dict[str, Any]]:
    """Get simplified list of templates for UI"""
    return [
        {
            'id': name,
            'name': template['name'],
            'description': template['description'],
            'category': template['category'],
            'severity': template['severity']
        }
        for name, template in ATTACK_TEMPLATES.items()
    ]
