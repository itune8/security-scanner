"""Visualization utilities for security dashboard."""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd


SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High": "#e74c3c",
    "Medium": "#f39c12",
    "Low": "#3498db",
    "Info": "#95a5a6",
}

STATUS_COLORS = {
    "PASS": "#2ecc71",
    "FAIL": "#e74c3c",
    "UNKNOWN": "#95a5a6",
}
