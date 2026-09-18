"""Small chart renderer for the PDF report - headless matplotlib (Agg
backend), output as base64 PNG data URIs so they can be embedded directly
in the report's HTML via xhtml2pdf."""
from __future__ import annotations

import base64
import io

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

_SEVERITY_COLORS = {"high": "#e5566b", "medium": "#e3a83c", "low": "#3fc07a", "info": "#8592ac"}
_TRIAGE_COLORS = {
    "confirmed_threat": "#e5566b",
    "false_positive": "#3fc07a",
    "unreviewed": "#8592ac",
    "unknown": "#6b7688",
}


def _fig_to_data_uri(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", transparent=True)
    plt.close(fig)
    encoded = base64.b64encode(buf.getvalue()).decode()
    return f"data:image/png;base64,{encoded}"


def severity_bar_chart(counts: dict) -> str:
    labels = ["High", "Medium", "Low", "Info"]
    keys = ["high", "medium", "low", "info"]
    values = [counts.get(k, 0) for k in keys]
    colors = [_SEVERITY_COLORS[k] for k in keys]

    fig, ax = plt.subplots(figsize=(4.6, 2.2))
    bars = ax.barh(labels, values, color=colors)
    ax.invert_yaxis()
    ax.set_xlabel("Findings", color="#000000", fontsize=8.5)
    ax.tick_params(colors="#000000", labelsize=8.5)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.xaxis.grid(True, color="#9aa4b5", linewidth=0.5)
    ax.set_axisbelow(True)
    for bar, value in zip(bars, values, strict=True):
        if value:
            ax.text(bar.get_width() + max(values) * 0.02, bar.get_y() + bar.get_height() / 2,
                     str(value), va="center", fontsize=8.5, color="#000000")
    fig.tight_layout()
    return _fig_to_data_uri(fig)


def triage_pie_chart(counts: dict) -> str:
    labels_map = {
        "confirmed_threat": "Confirmed Threat",
        "false_positive": "False Positive",
        "unreviewed": "Unreviewed",
        "unknown": "Unknown",
    }
    keys = [k for k in labels_map if counts.get(k, 0) > 0]
    if not keys:
        keys = ["unreviewed"]
        counts = {"unreviewed": 1}
    values = [counts.get(k, 0) for k in keys]
    colors = [_TRIAGE_COLORS[k] for k in keys]
    labels = [labels_map[k] for k in keys]

    fig, ax = plt.subplots(figsize=(3.2, 2.4))
    ax.pie(values, labels=labels, colors=colors, autopct="%1.0f%%",
           textprops={"fontsize": 7.5, "color": "#000000"}, wedgeprops={"linewidth": 1, "edgecolor": "#ffffff"})
    ax.axis("equal")
    fig.tight_layout()
    return _fig_to_data_uri(fig)
