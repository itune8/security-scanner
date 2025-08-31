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
    {
        "id": "IAM-002",
        "name": "Password policy minimum length",
        "description": "Password policy should enforce minimum 14 characters",
        "severity": SEVERITY_HIGH,
        "check_field": "min_password_length",
        "expected_min": 14,
        "remediation": "Update password policy to require at least 14 characters.",
        "cis_benchmark": "CIS 1.8",
    },
    {
        "id": "IAM-003",
        "name": "Password rotation policy",
        "description": "Passwords should be rotated within 90 days",
        "severity": SEVERITY_MEDIUM,
        "check_field": "max_password_age_days",
        "expected_max": 90,
        "remediation": "Set maximum password age to 90 days or less.",
        "cis_benchmark": "CIS 1.10",
    },
]
