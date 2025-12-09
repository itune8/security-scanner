"""Cloud logging and monitoring security scanner."""


LOGGING_RULES = [
    {
        "id": "LOG-001",
        "name": "CloudTrail / Audit logging enabled",
        "description": "Cloud audit logging should be enabled in all regions",
        "severity": "Critical",
        "check_field": "audit_logging_enabled",
        "expected": True,
        "remediation": "Enable audit logging (CloudTrail/Cloud Audit Logs) across all regions.",
        "cis_benchmark": "CIS 2.1",
    },
    {
        "id": "LOG-002",
        "name": "Log file integrity validation",
        "description": "Log file integrity validation should be enabled",
        "severity": "High",
        "check_field": "log_integrity_validation",
        "expected": True,
        "remediation": "Enable log file digest/integrity validation to detect tampering.",
        "cis_benchmark": "CIS 2.2",
    },
    {
        "id": "LOG-003",
        "name": "Logs encrypted at rest",
        "description": "Log storage should be encrypted with KMS",
        "severity": "High",
        "check_field": "logs_encrypted",
        "expected": True,
        "remediation": "Enable KMS encryption for log storage buckets.",
        "cis_benchmark": "CIS 2.3",
    },
]
