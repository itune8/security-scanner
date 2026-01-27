"""CloudGuard — Cloud Security Posture Scanner."""

import streamlit as st
import pandas as pd
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners.iam_scanner import scan_iam, get_default_iam_config, IAM_RULES
from scanners.network_scanner import scan_network, get_default_network_config, NETWORK_RULES
from scanners.storage_scanner import scan_storage, get_default_storage_config, STORAGE_RULES
from scanners.logging_scanner import scan_logging, get_default_logging_config, LOGGING_RULES
from scanners.compliance import (
    generate_report, calculate_compliance_score, export_report_json, FRAMEWORKS,
)
from utils.visualize import (
    plot_risk_gauge, plot_severity_breakdown, plot_pass_fail_donut,
    plot_compliance_radar, plot_section_scores, plot_category_heatmap,
)

st.set_page_config(
    page_title="CloudGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def render_header():
    st.markdown("""
    <div style='text-align: center; padding: 1rem 0;'>
        <h1 style='color: #2c3e50; margin-bottom: 0;'>CloudGuard</h1>
        <p style='color: #7f8c8d; font-size: 1.2rem;'>
            Cloud Security Posture Scanner
        </p>
    </div>
    """, unsafe_allow_html=True)


def render_findings_table(findings):
    """Render findings as a styled table."""
    rows = []
    for f in findings:
        status_icon = {"PASS": "✅", "FAIL": "❌", "UNKNOWN": "❓"}.get(f["status"], "❓")
        sev_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🔵"}.get(f["severity"], "⚪")
        rows.append({
            "Status": f"{status_icon} {f['status']}",
            "ID": f["id"],
            "Check": f["name"],
            "Severity": f"{sev_icon} {f['severity']}",
            "Detail": f["detail"],
            "CIS": f.get("cis_benchmark", ""),
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, height=400)


def render_results_tab():
    st.subheader("Scan Results")
    if "report" not in st.session_state:
        st.info("Run a security scan first to see results.")
        return
    report = st.session_state["report"]
    findings = st.session_state["findings"]
    summary = report["summary"]

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Checks", summary["total_checks"])
    m2.metric("Passed", summary["passed"])
    m3.metric("Failed", summary["failed"], delta=f"-{summary['failed']}", delta_color="inverse")
    m4.metric("Pass Rate", f"{summary['pass_rate']}%")
    m5.metric("Risk Score", f"{report['risk_score']}/100")

    st.divider()
    col1, col2, col3 = st.columns(3)
    with col1:
        st.plotly_chart(plot_risk_gauge(report["risk_score"]), use_container_width=True)
    with col2:
        st.plotly_chart(plot_pass_fail_donut(summary["passed"], summary["failed"], summary["unknown"]), use_container_width=True)
    with col3:
        st.plotly_chart(plot_severity_breakdown(report["severity_breakdown"]), use_container_width=True)

    st.markdown("### Findings Heatmap")
    st.plotly_chart(plot_category_heatmap(findings), use_container_width=True)

    st.markdown("### All Findings")
    filter_status = st.multiselect("Filter by status", ["PASS", "FAIL", "UNKNOWN"], default=["FAIL"])
    filtered = [f for f in findings if f["status"] in filter_status]
    render_findings_table(filtered)


def render_config_editor(category, default_config, rules):
    """Render editable configuration for a scanner category."""
    st.markdown(f"#### {category} Configuration")
    config = {}
    cols_per_row = 3
    rule_chunks = [rules[i:i + cols_per_row] for i in range(0, len(rules), cols_per_row)]
    for chunk in rule_chunks:
        cols = st.columns(cols_per_row)
        for col, rule in zip(cols, chunk):
            field = rule["check_field"]
            default = default_config.get(field, False)
            label = f"{rule['id']}: {rule['name']}"
            with col:
                if isinstance(default, bool):
                    config[field] = st.checkbox(label, value=default, key=f"{category}_{field}")
                elif isinstance(default, int):
                    config[field] = st.number_input(label, value=default, min_value=0, key=f"{category}_{field}")
    return config


def render_scanner_tab():
    st.subheader("Security Configuration Scanner")
    st.markdown("Configure your cloud environment settings below, then run the scan.")

    with st.expander("IAM Settings", expanded=True):
        iam_config = render_config_editor("IAM", get_default_iam_config(), IAM_RULES)
    with st.expander("Network Settings"):
        net_config = render_config_editor("Network", get_default_network_config(), NETWORK_RULES)
    with st.expander("Storage Settings"):
        str_config = render_config_editor("Storage", get_default_storage_config(), STORAGE_RULES)
    with st.expander("Logging & Monitoring Settings"):
        log_config = render_config_editor("Logging", get_default_logging_config(), LOGGING_RULES)

    if st.button("Run Security Scan", type="primary", use_container_width=True):
        with st.spinner("Scanning cloud configuration..."):
            iam_findings = scan_iam(iam_config)
            net_findings = scan_network(net_config)
            str_findings = scan_storage(str_config)
            log_findings = scan_logging(log_config)

            all_findings = iam_findings + net_findings + str_findings + log_findings
            report = generate_report(all_findings, {
                "iam": iam_config, "network": net_config,
                "storage": str_config, "logging": log_config,
            })

        st.session_state["report"] = report
        st.session_state["findings"] = all_findings
        st.rerun()


def main():
    render_header()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔍 Scanner", "📊 Results", "📋 Compliance", "🔧 Remediation", "📁 Import Config",
    ])

    st.divider()
    st.caption("CloudGuard v1.0 | Cloud Security Posture Scanner")


if __name__ == "__main__":
    main()
