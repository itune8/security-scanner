"""Compliance framework mapping and scoring engine."""

import json

FRAMEWORKS = {
    "CIS Benchmark": {
        "description": "Center for Internet Security cloud security benchmarks",
        "sections": {
            "1.x - IAM": ["IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005",
                          "IAM-006", "IAM-007", "IAM-008", "IAM-009", "IAM-010"],
            "2.x - Logging": ["LOG-001", "LOG-002", "LOG-003", "LOG-004", "LOG-005",
                              "LOG-006", "LOG-007", "LOG-008", "LOG-009", "LOG-010"],
            "3.x - Storage": ["STR-001", "STR-002", "STR-003", "STR-004", "STR-005",
                              "STR-006", "STR-007", "STR-008", "STR-009", "STR-010"],
            "4.x - Networking": ["NET-001", "NET-002", "NET-003", "NET-004", "NET-005",
                                 "NET-006", "NET-007", "NET-008", "NET-009", "NET-010"],
        },
    },
}
