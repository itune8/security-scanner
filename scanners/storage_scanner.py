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
    {
        "id": "STR-002",
        "name": "Encryption at rest",
        "description": "All storage buckets should have encryption at rest enabled",
        "severity": "High",
        "check_field": "encryption_at_rest",
        "expected": True,
        "remediation": "Enable server-side encryption (SSE-S3, SSE-KMS, or SSE-C) on all buckets.",
        "cis_benchmark": "CIS 3.2",
    },
    {
        "id": "STR-003",
        "name": "Encryption in transit",
        "description": "Bucket policies should enforce HTTPS-only access",
        "severity": "High",
        "check_field": "enforce_https",
        "expected": True,
        "remediation": "Add bucket policy to deny HTTP requests (aws:SecureTransport = false).",
        "cis_benchmark": "CIS 3.3",
    },
]
