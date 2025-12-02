"""Cloud network security configuration scanner."""


NETWORK_RULES = [
    {
        "id": "NET-001",
        "name": "Default VPC usage",
        "description": "Default VPC should not be used for production workloads",
        "severity": "High",
        "check_field": "using_default_vpc",
        "expected": False,
        "remediation": "Create custom VPCs with properly configured subnets, NACLs, and route tables.",
        "cis_benchmark": "CIS 4.1",
    },
    {
        "id": "NET-002",
        "name": "SSH restricted access",
        "description": "SSH (port 22) should not be open to 0.0.0.0/0",
        "severity": "Critical",
        "check_field": "ssh_open_to_world",
        "expected": False,
        "remediation": "Restrict SSH access to specific IP ranges or use a bastion host / VPN.",
        "cis_benchmark": "CIS 4.2",
    },
    {
        "id": "NET-003",
        "name": "RDP restricted access",
        "description": "RDP (port 3389) should not be open to 0.0.0.0/0",
        "severity": "Critical",
        "check_field": "rdp_open_to_world",
        "expected": False,
        "remediation": "Restrict RDP access to specific IP ranges or use a VPN.",
        "cis_benchmark": "CIS 4.3",
    },
    {
        "id": "NET-004",
        "name": "VPC flow logs enabled",
        "description": "VPC flow logs should be enabled for network monitoring",
        "severity": "High",
        "check_field": "flow_logs_enabled",
        "expected": True,
        "remediation": "Enable VPC flow logs and send to CloudWatch or S3 for analysis.",
        "cis_benchmark": "CIS 4.4",
    },
    {
        "id": "NET-005",
        "name": "Security group permissiveness",
        "description": "No security group should allow all inbound traffic (0.0.0.0/0 on all ports)",
        "severity": "Critical",
        "check_field": "sg_allow_all_inbound",
        "expected": False,
        "remediation": "Review and restrict security group rules to only required ports and sources.",
        "cis_benchmark": "CIS 4.5",
    },
    {
        "id": "NET-006",
        "name": "Network ACL open admin ports",
        "description": "NACLs should not allow unrestricted ingress to admin ports",
        "severity": "High",
        "check_field": "nacl_open_admin_ports",
        "expected": False,
        "remediation": "Configure NACLs to restrict admin port access to known IP ranges.",
        "cis_benchmark": "CIS 4.6",
    },
    {
        "id": "NET-007",
        "name": "Private subnets for databases",
        "description": "Database instances should be in private subnets",
        "severity": "High",
        "check_field": "db_in_private_subnet",
        "expected": True,
        "remediation": "Move database instances to private subnets without direct internet access.",
        "cis_benchmark": "CIS 4.7",
    },
    {
        "id": "NET-008",
        "name": "WAF enabled",
        "description": "Web Application Firewall should be enabled for public-facing services",
        "severity": "Medium",
        "check_field": "waf_enabled",
        "expected": True,
        "remediation": "Enable WAF with OWASP Top 10 rule sets for public-facing load balancers.",
        "cis_benchmark": "CIS 4.8",
    },
    {
        "id": "NET-009",
        "name": "DDoS protection",
        "description": "DDoS protection service should be enabled",
        "severity": "Medium",
        "check_field": "ddos_protection_enabled",
        "expected": True,
        "remediation": "Enable DDoS protection (e.g., AWS Shield, Azure DDoS Protection).",
        "cis_benchmark": "CIS 4.9",
    },
    {
        "id": "NET-010",
        "name": "TLS enforcement",
        "description": "All external endpoints should enforce TLS 1.2+",
        "severity": "High",
        "check_field": "tls_enforced",
        "expected": True,
        "remediation": "Configure load balancers and CDN to enforce TLS 1.2 or higher.",
        "cis_benchmark": "CIS 4.10",
    },
]


def scan_network(config):
    """Scan network configuration against security rules."""
    findings = []

    for rule in NETWORK_RULES:
        field = rule["check_field"]
        value = config.get(field)

        if value is None:
            findings.append({
                **rule,
                "status": "UNKNOWN",
                "actual": "Not provided",
                "detail": f"Configuration field '{field}' not found",
            })
            continue

        passed = value == rule["expected"]

        findings.append({
            **rule,
            "status": "PASS" if passed else "FAIL",
            "actual": value,
            "detail": f"Expected: {rule['expected']}, Actual: {value}",
        })

    return findings


def get_default_network_config():
    """Return a sample network config for demonstration."""
    return {
        "using_default_vpc": True,
        "ssh_open_to_world": True,
        "rdp_open_to_world": False,
        "flow_logs_enabled": False,
        "sg_allow_all_inbound": True,
        "nacl_open_admin_ports": True,
        "db_in_private_subnet": False,
        "waf_enabled": False,
        "ddos_protection_enabled": False,
        "tls_enforced": True,
    }

