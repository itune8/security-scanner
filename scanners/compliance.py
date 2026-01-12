"""Compliance framework mapping and scoring engine."""

import json
from datetime import datetime


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
    "SOC 2": {
        "description": "Service Organization Control Type 2",
        "sections": {
            "Security": ["IAM-001", "IAM-007", "NET-002", "NET-003", "NET-005",
                         "STR-001", "STR-002", "LOG-001"],
            "Availability": ["NET-009", "STR-007", "NET-008"],
            "Confidentiality": ["STR-002", "STR-003", "LOG-003", "NET-010"],
            "Privacy": ["IAM-002", "IAM-003", "LOG-004"],
        },
    },
    "NIST 800-53": {
        "description": "NIST Security and Privacy Controls",
        "sections": {
            "Access Control (AC)": ["IAM-001", "IAM-002", "IAM-005", "IAM-006",
                                    "IAM-007", "NET-002", "NET-003"],
            "Audit (AU)": ["LOG-001", "LOG-002", "LOG-003", "LOG-004", "LOG-005",
                           "LOG-006", "LOG-007"],
            "System Protection (SC)": ["NET-005", "NET-008", "NET-010",
                                       "STR-002", "STR-003"],
            "Configuration (CM)": ["NET-001", "NET-004", "LOG-010"],
        },
    },
}


def calculate_compliance_score(findings, framework_name="CIS Benchmark"):
    """Calculate compliance score for a given framework."""
    framework = FRAMEWORKS.get(framework_name)
    if not framework:
        return None

    finding_map = {f["id"]: f for f in findings}
    section_scores = {}
    total_pass = 0
    total_checks = 0

    for section, rule_ids in framework["sections"].items():
        section_pass = 0
        section_total = 0

        for rule_id in rule_ids:
            finding = finding_map.get(rule_id)
            if finding:
                section_total += 1
                if finding["status"] == "PASS":
                    section_pass += 1

        score = (section_pass / section_total * 100) if section_total > 0 else 0
        section_scores[section] = {
            "passed": section_pass,
            "total": section_total,
            "score": round(score, 1),
        }
        total_pass += section_pass
        total_checks += section_total

    overall = (total_pass / total_checks * 100) if total_checks > 0 else 0

    return {
        "framework": framework_name,
        "description": framework["description"],
        "overall_score": round(overall, 1),
        "total_passed": total_pass,
        "total_checks": total_checks,
        "sections": section_scores,
    }


def _calculate_risk_score(findings):
    """Calculate overall risk score (0-100, lower is better)."""
    weights = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}
    max_possible = sum(
        weights.get(f.get("severity", "Info"), 0) for f in findings
    )
    actual_risk = sum(
        weights.get(f.get("severity", "Info"), 0)
        for f in findings if f["status"] == "FAIL"
    )
    if max_possible == 0:
        return 0
    return round((actual_risk / max_possible) * 100, 1)


def _prioritize_remediations(failed_findings):
    """Prioritize remediations by severity."""
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(
        failed_findings,
        key=lambda f: severity_order.get(f.get("severity", "Info"), 4),
    )
    return [
        {
            "id": f["id"],
            "name": f["name"],
            "severity": f["severity"],
            "remediation": f["remediation"],
        }
        for f in sorted_findings
    ]


def generate_report(findings, configs):
    """Generate a complete security audit report."""
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    failed_findings = [f for f in findings if f["status"] == "FAIL"]

    for f in failed_findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    passed = sum(1 for f in findings if f["status"] == "PASS")
    failed = len(failed_findings)
    unknown = sum(1 for f in findings if f["status"] == "UNKNOWN")

    compliance_scores = {}
    for fw_name in FRAMEWORKS:
        score = calculate_compliance_score(findings, fw_name)
        if score:
            compliance_scores[fw_name] = score

    risk_score = _calculate_risk_score(findings)

    return {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_checks": len(findings),
            "passed": passed,
            "failed": failed,
            "unknown": unknown,
            "pass_rate": round(passed / len(findings) * 100, 1) if findings else 0,
        },
        "severity_breakdown": severity_counts,
        "risk_score": risk_score,
        "compliance": compliance_scores,
        "findings": findings,
        "top_remediations": _prioritize_remediations(failed_findings),
    }


def export_report_json(report):
    """Export report as JSON string."""
    return json.dumps(report, indent=2, default=str)

