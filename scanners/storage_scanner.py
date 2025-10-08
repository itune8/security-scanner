"""Cloud storage security configuration scanner."""


STORAGE_RULES = [
    {
        "id": "STR-001",
        "name": "Public bucket access",
        "description": "Storage buckets should not allow public access",
        "severity": "Critical",
        "check_field": "public_buckets",
        "expected": 0,
        "remediation": "Block all public access on storage buckets. Use pre-signed URLs for temporary access.",
        "cis_benchmark": "CIS 3.1",
    },
]
