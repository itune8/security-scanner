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


def main():
    render_header()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🔍 Scanner", "📊 Results", "📋 Compliance", "🔧 Remediation", "📁 Import Config",
    ])

    st.divider()
    st.caption("CloudGuard v1.0 | Cloud Security Posture Scanner")


if __name__ == "__main__":
    main()
