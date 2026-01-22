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
        st.info("Scan engine not connected yet.")


def main():
    render_header()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔍 Scanner", "📊 Results", "📋 Compliance", "🔧 Remediation", "📁 Import Config",
    ])

    st.divider()
    st.caption("CloudGuard v1.0 | Cloud Security Posture Scanner")


if __name__ == "__main__":
    main()
