# CloudGuard

Cloud Security Posture Scanner — audits cloud configurations against CIS Benchmarks, SOC 2, and NIST 800-53 compliance frameworks.

## Features

- **IAM Security Scanner** — Checks MFA, password policies, access key rotation, admin privileges, unused credentials
- **Network Security Scanner** — Audits VPC config, security groups, SSH/RDP exposure, flow logs, WAF, TLS enforcement
- **Storage Security Scanner** — Validates bucket access, encryption, versioning, logging, MFA delete, replication
- **Logging & Monitoring Scanner** — Checks audit logging, integrity validation, retention, alerting rules
- **Compliance Dashboard** — Maps findings to CIS Benchmark, SOC 2, and NIST 800-53 with section-level scoring
- **Risk Scoring** — Weighted risk calculation based on finding severity
- **Remediation Engine** — Prioritized fix recommendations with CIS benchmark references
- **Report Export** — Download full audit reports as JSON

## Tech Stack

- Python, Streamlit, Plotly, Pandas, PyYAML

## Quick Start

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Project Structure

```
cloud-security-scanner/
├── app.py                     # Streamlit web application
├── scanners/
│   ├── iam_scanner.py         # IAM security rules & scanner
│   ├── network_scanner.py     # Network security rules & scanner
│   ├── storage_scanner.py     # Storage security rules & scanner
│   ├── logging_scanner.py     # Logging & monitoring rules & scanner
│   └── compliance.py          # Compliance framework mapping & scoring
├── utils/
│   └── visualize.py           # Plotly visualization helpers
└── requirements.txt
```
