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


def plot_severity_breakdown(severity_counts):
    """Bar chart of findings by severity."""
    severities = ["Critical", "High", "Medium", "Low"]
    counts = [severity_counts.get(s, 0) for s in severities]
    colors = [SEVERITY_COLORS[s] for s in severities]
    fig = go.Figure(go.Bar(x=severities, y=counts, marker_color=colors, text=counts, textposition="outside"))
    fig.update_layout(yaxis_title="Failed Checks", margin=dict(t=20, b=30), height=300)
    return fig


def plot_pass_fail_donut(passed, failed, unknown):
    """Donut chart of pass/fail/unknown distribution."""
    fig = go.Figure(go.Pie(
        labels=["Passed", "Failed", "Unknown"],
        values=[passed, failed, unknown],
        marker_colors=["#2ecc71", "#e74c3c", "#95a5a6"],
        hole=0.5, textinfo="label+value",
    ))
    fig.update_layout(margin=dict(t=30, b=30, l=30, r=30), height=300)
    return fig


def plot_compliance_radar(compliance_scores):
    """Radar chart comparing compliance across frameworks."""
    frameworks = list(compliance_scores.keys())
    scores = [compliance_scores[fw]["overall_score"] for fw in frameworks]
    scores.append(scores[0])
    frameworks.append(frameworks[0])
    fig = go.Figure(go.Scatterpolar(
        r=scores, theta=frameworks, fill="toself",
        fillcolor="rgba(52, 152, 219, 0.3)", line=dict(color="#3498db", width=2),
    ))
    fig.update_layout(polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
                      margin=dict(t=40, b=40), height=350)
    return fig


def plot_section_scores(compliance_data):
    """Horizontal bar chart of section scores within a framework."""
    sections = list(compliance_data["sections"].keys())
    scores = [compliance_data["sections"][s]["score"] for s in sections]
    colors = ["#2ecc71" if s >= 70 else "#f39c12" if s >= 40 else "#e74c3c" for s in scores]
    fig = go.Figure(go.Bar(
        x=scores, y=sections, orientation="h", marker_color=colors,
        text=[f"{s:.0f}%" for s in scores], textposition="outside",
    ))
    fig.update_layout(xaxis=dict(title="Compliance %", range=[0, 110]),
                      margin=dict(t=20, b=30, l=150, r=50), height=300)
    return fig
