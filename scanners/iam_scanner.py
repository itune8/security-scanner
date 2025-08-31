"""IAM (Identity & Access Management) security scanner."""


SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"
SEVERITY_INFO = "Info"

IAM_RULES = [
    {
        "id": "IAM-001",
        "name": "Root account MFA",
        "description": "Root/admin account must have MFA enabled",
        "severity": SEVERITY_CRITICAL,
        "check_field": "root_mfa_enabled",
        "expected": True,
        "remediation": "Enable MFA on the root account immediately. Use a hardware security key for highest security.",
        "cis_benchmark": "CIS 1.5",
    },
]
