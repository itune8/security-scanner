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
]
