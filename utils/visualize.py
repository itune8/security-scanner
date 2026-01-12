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


def plot_risk_gauge(risk_score):
    """Gauge chart for overall risk score."""
    if risk_score <= 30:
        color = "#2ecc71"
        label = "Low Risk"
    elif risk_score <= 60:
        color = "#f39c12"
        label = "Medium Risk"
    else:
        color = "#e74c3c"
        label = "High Risk"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        title={"text": label, "font": {"size": 18}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 2},
            "bar": {"color": color, "thickness": 0.75},
            "steps": [
                {"range": [0, 30], "color": "#d5f5e3"},
                {"range": [30, 60], "color": "#fdebd0"},
                {"range": [60, 100], "color": "#fadbd8"},
            ],
            "threshold": {
                "line": {"color": "black", "width": 3},
                "thickness": 0.8,
                "value": risk_score,
            },
        },
    ))
    fig.update_layout(margin=dict(t=60, b=20), height=250)
    return fig
