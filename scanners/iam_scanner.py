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
    {
        "id": "IAM-004",
        "name": "Unused credentials",
        "description": "Credentials not used for 90+ days should be disabled",
        "severity": SEVERITY_MEDIUM,
        "check_field": "unused_credentials_days",
        "expected_max": 90,
        "remediation": "Review and disable credentials that haven't been used in 90 days.",
        "cis_benchmark": "CIS 1.3",
    },
    {
        "id": "IAM-005",
        "name": "Access key rotation",
        "description": "Access keys should be rotated within 90 days",
        "severity": SEVERITY_HIGH,
        "check_field": "access_key_age_days",
        "expected_max": 90,
        "remediation": "Rotate access keys that are older than 90 days.",
        "cis_benchmark": "CIS 1.4",
    },
    {
        "id": "IAM-006",
        "name": "Admin users count",
        "description": "Limit the number of users with full admin privileges",
        "severity": SEVERITY_HIGH,
        "check_field": "admin_user_count",
        "expected_max": 3,
        "remediation": "Review admin privileges and apply least-privilege principle.",
        "cis_benchmark": "CIS 1.16",
    },
    {
        "id": "IAM-007",
        "name": "MFA for all users",
        "description": "All IAM users with console access should have MFA",
        "severity": SEVERITY_HIGH,
        "check_field": "users_without_mfa",
        "expected": 0,
        "remediation": "Enable MFA for all users with console access.",
        "cis_benchmark": "CIS 1.6",
    },
    {
        "id": "IAM-008",
        "name": "Password reuse prevention",
        "description": "Password policy should prevent reuse of last 24 passwords",
        "severity": SEVERITY_MEDIUM,
        "check_field": "password_reuse_prevention",
        "expected_min": 24,
        "remediation": "Set password reuse prevention to 24 or more.",
        "cis_benchmark": "CIS 1.9",
    },
    {
        "id": "IAM-009",
        "name": "Service account key management",
        "description": "Service accounts should use managed keys, not user-created",
        "severity": SEVERITY_MEDIUM,
        "check_field": "user_managed_service_keys",
        "expected": 0,
        "remediation": "Migrate to provider-managed keys for service accounts.",
        "cis_benchmark": "CIS 1.7",
    },
    {
        "id": "IAM-010",
        "name": "Require uppercase in password",
        "description": "Password policy should require uppercase letters",
        "severity": SEVERITY_LOW,
        "check_field": "require_uppercase",
        "expected": True,
        "remediation": "Enable uppercase letter requirement in password policy.",
        "cis_benchmark": "CIS 1.8",
    },
]


def scan_iam(config):
    """Scan IAM configuration against security rules."""
    findings = []

    for rule in IAM_RULES:
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

        passed = False

        if "expected" in rule:
            passed = value == rule["expected"]
        elif "expected_min" in rule:
            passed = value >= rule["expected_min"]
        elif "expected_max" in rule:
            passed = value <= rule["expected_max"]

        findings.append({
            **rule,
            "status": "PASS" if passed else "FAIL",
            "actual": value,
            "detail": (
                f"Expected: {rule.get('expected', rule.get('expected_min', rule.get('expected_max')))}, "
                f"Actual: {value}"
            ),
        })

    return findings


def get_default_iam_config():
    """Return a sample IAM config for demonstration."""
    return {
        "root_mfa_enabled": False,
        "min_password_length": 8,
        "max_password_age_days": 180,
        "unused_credentials_days": 120,
        "access_key_age_days": 150,
        "admin_user_count": 5,
        "users_without_mfa": 3,
        "password_reuse_prevention": 12,
        "user_managed_service_keys": 2,
        "require_uppercase": True,
    }
