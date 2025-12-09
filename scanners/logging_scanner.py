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
]
