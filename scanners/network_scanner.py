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
]
