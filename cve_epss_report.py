#!/usr/bin/env python3
"""
Sysdig CVE Risk Dashboard
  Top 50 CVEs with EPSS > 50 % (critical / high severity)
  Split into In-Use (fix now) vs Not-In-Use (monitor)
  Executive prioritisation view — charts + risk-scored tables
"""

import os
import re
from datetime import datetime, timezone

import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="CVE Risk Dashboard | Sysdig",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_BASE      = "https://app.au1.sysdig.com"
API_TIMEOUT       = 20
T1_BY_CVE_PATH    = "/api/secure/analytics/v1/data/vulnerabilities/findings/by-cve"
T1_EPSS_THRESHOLD = 0.50   # 50 %
T1_TOP_N          = 50

SEVERITY_COLOR = {
    "Critical":  "#9B3FBF",
    "High":      "#E53935",
    "Medium":    "#FB8C00",
    "Low":       "#1E88E5",
    "Negligible":"#78909C",
}

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#b0bec5", size=12),
    margin=dict(t=40, b=20, l=20, r=20),
)

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
html, body, [class*="css"] { font-family: 'Inter', 'Roboto', sans-serif; }

/* ── Section headers ───────────────────────────────────────────── */
.section-hdr {
    font-size: 1.1rem; font-weight: 700; margin: 0 0 4px;
    padding-bottom: 6px;
}
.section-inuse {
    color: #ef9a9a;
    border-bottom: 3px solid #E53935;
}
.section-notuse {
    color: #fff176;
    border-bottom: 3px solid #FB8C00;
}
.section-desc {
    color: #78909c; font-size: .85rem; margin-bottom: 20px;
}

/* ── Stat cards ─────────────────────────────────────────────────── */
.stat-card {
    background: #1a1f2e; border-radius: 10px; padding: 14px 18px;
    border: 1px solid #2a3040; text-align: center;
}
.stat-val { font-size: 1.8rem; font-weight: 700; color: #fff; }
.stat-lbl { font-size: .72rem; color: #78909c; text-transform: uppercase; letter-spacing: .05em; }

/* ── Error banner ───────────────────────────────────────────────── */
.error-banner {
    background: #2e1a1a; border: 1px solid #e53935; border-radius: 8px;
    padding: 10px 18px; color: #ef9a9a; font-size: .88rem; margin-bottom: 8px;
}

/* ── Risk score pill ─────────────────────────────────────────────── */
.risk-high   { color: #ef5350; font-weight: 700; }
.risk-medium { color: #ffa726; font-weight: 700; }
.risk-low    { color: #66bb6a; font-weight: 700; }

/* ── Divider ────────────────────────────────────────────────────── */
.section-divider {
    border: none; border-top: 1px solid #1e2d3d; margin: 36px 0;
}

[data-testid="stSidebar"] { background: #12161f; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────

for _k, _v in [("t1_cves", []), ("t1_loaded", False), ("t1_errors", [])]:
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🛡️ CVE Risk Dashboard")
    st.markdown("---")

    api_base = st.text_input(
        "Sysdig Base URL",
        value=os.environ.get("SYSDIG_API_BASE", DEFAULT_BASE),
    ).rstrip("/")

    api_token = st.text_input(
        "API Token",
        value=os.environ.get("SYSDIG_API_TOKEN", ""),
        type="password",
        placeholder="Paste your Sysdig API token",
    )

    st.markdown("---")

    if st.button("🔄 Refresh data", use_container_width=True):
        st.session_state.t1_cves   = []
        st.session_state.t1_loaded = False
        st.session_state.t1_errors = []
        st.rerun()

    st.markdown(
        f"<small style='color:#546e7a'>Timeout {API_TIMEOUT}s · "
        f"EPSS ≥ 50% · Sev: Crit/High/Med · Top {T1_TOP_N}<br>"
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</small>",
        unsafe_allow_html=True,
    )

# ─────────────────────────────────────────────────────────────────────────────
# API HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _headers(token: str) -> dict:
    return {
        "Authorization":    f"Bearer {token}",
        "Accept":           "application/json",
        "X-Sysdig-Product": "SDS",
    }


def _fetch_top_cves(base: str, token: str) -> list:
    """
    Paginate /by-cve (max 200/page).
    Collect items with epssScore >= 50%, sorted by EPSS desc.
    Stop when we have T1_TOP_N qualifying or no more pages.
    """
    hdrs   = _headers(token)
    params: dict = {"severity_in": "critical,high,medium", "limit": 200}
    qualifying: list = []

    while True:
        r = requests.get(
            f"{base}{T1_BY_CVE_PATH}",
            headers=hdrs, params=params, timeout=API_TIMEOUT,
        )
        r.raise_for_status()
        payload = r.json()

        for item in payload.get("data", []):
            if float(item.get("epssScore") or 0) >= T1_EPSS_THRESHOLD:
                qualifying.append(item)

        meta   = payload.get("meta") or {}
        cursor = payload.get("cursor") or {}
        if len(qualifying) >= T1_TOP_N or not meta.get("hasMore") or not cursor.get("next"):
            break
        params = {**params, "cursor": cursor["next"]}

    qualifying.sort(key=lambda x: float(x.get("epssScore") or 0), reverse=True)
    return qualifying[:T1_TOP_N]


def _normalize(item: dict) -> dict:
    """Convert a /by-cve API item to internal format with risk score."""
    epss        = float(item.get("epssScore") or 0)
    cvss        = float(item.get("cvssScore") or 0)
    exploitable = bool(item.get("hasExploit"))
    kev         = bool(item.get("hasCisaKev"))

    # Risk score 0-100: EPSS(40) + CVSS(30) + Exploitable(20) + KEV(10)
    risk_score = round(epss * 40 + (cvss / 10) * 30 + exploitable * 20 + kev * 10, 1)

    return {
        "cveId":        item.get("name", "Unknown"),
        "severity":     (item.get("severity") or "Unknown").capitalize(),
        "epssScore":    epss,
        "cvssScore":    cvss,
        "fixAvailable": bool(item.get("isFixAvailable")),
        "exploitable":  exploitable,
        "hasCisaKev":   kev,
        "findingsCount": int(item.get("findingsCount") or 0),
        "inUse":        bool(item.get("inUse") or item.get("isInUse") or False),
        "riskScore":    risk_score,
    }


def load_with_progress(base: str, token: str, status_ctx) -> tuple[list, list]:
    """Single-step fetch: top CVEs from /by-cve → normalise → return."""
    status_ctx.write(
        f"**Querying Findings API** — top CVEs with EPSS > {T1_EPSS_THRESHOLD*100:.0f}% "
        f"(critical/high severity)…"
    )
    items = _fetch_top_cves(base, token)

    if not items:
        return [], [f"No CVEs with EPSS > {T1_EPSS_THRESHOLD*100:.0f}% found."]

    normalised = [_normalize(it) for it in items]
    in_use    = sum(1 for c in normalised if c["inUse"])
    not_use   = sum(1 for c in normalised if not c["inUse"])

    status_ctx.write(
        f"  ✓ **{len(normalised)}** CVE(s) found — "
        f"**{in_use}** in-use · **{not_use}** not-in-use"
    )
    return normalised, []


# ─────────────────────────────────────────────────────────────────────────────
# CHART BUILDERS
# ─────────────────────────────────────────────────────────────────────────────

def chart_severity_donut(df: pd.DataFrame) -> go.Figure:
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    colors = [SEVERITY_COLOR.get(s, "#78909C") for s in counts["severity"]]
    fig = go.Figure(go.Pie(
        labels=counts["severity"],
        values=counts["count"],
        marker=dict(colors=colors, line=dict(width=2, color="#12161f")),
        hole=0.55,
        textinfo="label+value",
        textfont=dict(size=12),
        hovertemplate="%{label}: %{value} CVEs (%{percent})<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=300, showlegend=False)
    return fig


def chart_fix_donut(df: pd.DataFrame) -> go.Figure:
    fix_yes = int(df["fixAvailable"].sum())
    fix_no  = len(df) - fix_yes
    fig = go.Figure(go.Pie(
        labels=["Fix Available", "No Fix Yet"],
        values=[fix_yes, fix_no],
        marker=dict(colors=["#00C853", "#E53935"], line=dict(width=2, color="#12161f")),
        hole=0.55,
        textinfo="label+value",
        textfont=dict(size=12),
        hovertemplate="%{label}: %{value} CVEs (%{percent})<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=300, showlegend=False)
    return fig


def chart_epss_distribution(df: pd.DataFrame) -> go.Figure:
    """Stacked bar: CVE count per EPSS bucket, coloured by severity."""
    bins   = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    labels = ["50-60%", "60-70%", "70-80%", "80-90%", "90-100%"]
    df2 = df.copy()
    df2["epss_bucket"] = pd.cut(
        df2["epssScore"], bins=bins, labels=labels, include_lowest=True
    )
    counts = (
        df2.groupby(["epss_bucket", "severity"], observed=True)
        .size()
        .reset_index(name="count")
    )
    # Maintain a consistent severity order
    sev_order = ["Critical", "High", "Medium", "Low", "Negligible"]
    counts["severity"] = pd.Categorical(counts["severity"], categories=sev_order, ordered=True)
    counts = counts.sort_values(["epss_bucket", "severity"])

    fig = px.bar(
        counts, x="epss_bucket", y="count", color="severity",
        color_discrete_map=SEVERITY_COLOR, barmode="stack",
        labels={"epss_bucket": "EPSS Range", "count": "CVE Count", "severity": "Severity"},
    )
    fig.update_layout(
        **PLOTLY_LAYOUT, height=300,
        xaxis=dict(gridcolor="#1e2d3d"),
        yaxis=dict(gridcolor="#1e2d3d", title="CVE Count"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    return fig


def chart_key_flags(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar: Exploitable / CISA KEV / Has Fix counts."""
    cats   = ["Exploitable",      "CISA KEV",         "Has Fix"]
    values = [
        int(df["exploitable"].sum()),
        int(df["hasCisaKev"].sum()),
        int(df["fixAvailable"].sum()),
    ]
    colors = ["#E53935", "#9B3FBF", "#00C853"]
    fig = go.Figure(go.Bar(
        x=cats, y=values,
        marker=dict(color=colors, line=dict(width=0)),
        text=values, textposition="outside",
        hovertemplate="%{x}: %{y} CVEs<extra></extra>",
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT, height=300,
        yaxis=dict(gridcolor="#1e2d3d", title="CVE Count"),
        xaxis=dict(gridcolor="#1e2d3d"),
        showlegend=False,
    )
    return fig


# ─────────────────────────────────────────────────────────────────────────────
# RENDER HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _render_section(cves: list, label: str, header_class: str) -> None:
    """Render one In-Use or Not-In-Use aggregate section."""
    st.markdown(
        f'<div class="section-hdr {header_class}">{label}</div>',
        unsafe_allow_html=True,
    )

    if not cves:
        st.info("No CVEs in this category.")
        return

    df = pd.DataFrame(cves)
    # Guard against stale session-state cache missing new columns
    for _col, _default in [
        ("exploitable", False), ("hasCisaKev", False),
        ("fixAvailable", False), ("cvssScore", 0.0), ("epssScore", 0.0),
    ]:
        if _col not in df.columns:
            df[_col] = _default

    total       = len(df)
    avg_epss    = df["epssScore"].mean() * 100
    exploitable = int(df["exploitable"].sum())
    kev         = int(df["hasCisaKev"].sum())
    fixable     = int(df["fixAvailable"].sum())

    # ── Metrics row ───────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("CVEs",         total)
    c2.metric("Avg EPSS",    f"{avg_epss:.1f}%")
    c3.metric("Exploitable",  exploitable,  "known exploits")
    c4.metric("CISA KEV",     kev,          "actively exploited")
    c5.metric("Has Fix",      fixable,      f"{fixable/total*100:.0f}% fixable")

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Charts: 2 × 2 grid ────────────────────────────────────────────────────
    r1c1, r1c2 = st.columns(2)
    with r1c1:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;margin-bottom:4px'>"
            "Severity Breakdown</div>",
            unsafe_allow_html=True,
        )
        st.plotly_chart(chart_severity_donut(df), use_container_width=True,
                        config={"displayModeBar": False})
    with r1c2:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;margin-bottom:4px'>"
            "CVEs by EPSS Range &amp; Severity</div>",
            unsafe_allow_html=True,
        )
        st.plotly_chart(chart_epss_distribution(df), use_container_width=True,
                        config={"displayModeBar": False})

    r2c1, r2c2 = st.columns(2)
    with r2c1:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;margin-bottom:4px'>"
            "Fix Availability</div>",
            unsafe_allow_html=True,
        )
        st.plotly_chart(chart_fix_donut(df), use_container_width=True,
                        config={"displayModeBar": False})
    with r2c2:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;margin-bottom:4px'>"
            "Key Risk Flags</div>",
            unsafe_allow_html=True,
        )
        st.plotly_chart(chart_key_flags(df), use_container_width=True,
                        config={"displayModeBar": False})


def _rgba(hex_color: str, alpha: float) -> str:
    """Convert '#rrggbb' + float alpha → 'rgba(r,g,b,alpha)' for Plotly."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha:.2f})"


# Colour palette for CVEs in the explorer (cycles if > 10)






def _t2_hbar(items: dict, x_label: str, color: str) -> go.Figure:
    """Horizontal bar: label → value, sorted ascending."""
    df = pd.DataFrame(
        sorted(items.items(), key=lambda x: x[1]),
        columns=["Label", "Value"],
    )
    fig = go.Figure(go.Bar(
        x=df["Value"], y=df["Label"], orientation="h",
        marker=dict(color=color, line=dict(width=0)),
        text=df["Value"], textposition="outside",
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=max(200, len(items) * 38 + 60),
        xaxis=dict(title=x_label, gridcolor="#1e2d3d"),
        yaxis=dict(showgrid=False),
    )
    return fig



# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — ENGINEERING FIX VIEW (helpers)
# ─────────────────────────────────────────────────────────────────────────────

EXPECTED_COLS = {
    "clusterName", "findings", "imageReference",
    "imageRegistry", "imageRepository", "imageTag",
    "namespaceName", "resourceName",
}


def _eng_load(path_or_file) -> pd.DataFrame:
    """Load from a filesystem path string or a file-like object."""
    df = pd.read_csv(path_or_file)
    missing = EXPECTED_COLS - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing columns: {', '.join(sorted(missing))}")
    df["findings"] = pd.to_numeric(df["findings"], errors="coerce").fillna(0).astype(int)
    df["imageLabel"] = df["imageRepository"].str.split("/").str[-1] + ":" + df["imageTag"]
    return df


def _eng_image_summary(df: pd.DataFrame) -> pd.DataFrame:
    """One row per unique imageReference with aggregated impact stats."""
    agg = (
        df.groupby(["imageRegistry", "imageRepository", "imageTag",
                    "imageReference", "imageLabel"])
        .agg(
            workloads      =("resourceName",  "nunique"),
            clusters       =("clusterName",   "nunique"),
            namespaces     =("namespaceName", "nunique"),
            total_findings =("findings",      "sum"),
            cluster_list   =("clusterName",   lambda x: ", ".join(sorted(x.unique()))),
            ns_list        =("namespaceName", lambda x: ", ".join(sorted(x.unique()))),
        )
        .reset_index()
        .sort_values("total_findings", ascending=False)
        .reset_index(drop=True)
    )
    agg.insert(0, "Priority", range(1, len(agg) + 1))
    return agg


def _eng_repo_summary(df: pd.DataFrame) -> pd.DataFrame:
    """One row per imageRepository (all tags combined)."""
    return (
        df.groupby("imageRepository")
        .agg(
            unique_tags    =("imageTag",      "nunique"),
            workloads      =("resourceName",  "nunique"),
            clusters       =("clusterName",   "nunique"),
            total_findings =("findings",      "sum"),
            tags           =("imageTag",      lambda x: ", ".join(sorted(x.unique()))),
        )
        .reset_index()
        .sort_values("total_findings", ascending=False)
        .reset_index(drop=True)
    )


# ── Engineering charts ────────────────────────────────────────────────────────

def _eng_top_images_bar(img_df: pd.DataFrame, n: int = 25) -> go.Figure:
    top = img_df.head(n).sort_values("total_findings")
    colors = [SEVERITY_COLOR.get("High", "#E53935")] * len(top)
    fig = go.Figure(go.Bar(
        x=top["total_findings"],
        y=top["imageLabel"],
        orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        text=top["total_findings"],
        textposition="outside",
        customdata=top[["workloads", "clusters", "imageReference"]].values,
        hovertemplate=(
            "<b>%{y}</b><br>"
            "Total findings: %{x}<br>"
            "Workloads: %{customdata[0]}<br>"
            "Clusters: %{customdata[1]}<br>"
            "<i>%{customdata[2]}</i><extra></extra>"
        ),
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=max(320, len(top) * 30 + 60),
        xaxis=dict(title="Total Findings", gridcolor="#1e2d3d"),
        yaxis=dict(showgrid=False, tickfont=dict(size=10)),
    )
    return fig


def _eng_cluster_bar(df: pd.DataFrame) -> go.Figure:
    counts = (
        df.groupby("clusterName")["resourceName"]
        .nunique()
        .reset_index()
        .rename(columns={"resourceName": "workloads"})
        .sort_values("workloads")
    )
    fig = go.Figure(go.Bar(
        x=counts["workloads"],
        y=counts["clusterName"],
        orientation="h",
        marker=dict(color="#9B3FBF", line=dict(width=0)),
        text=counts["workloads"],
        textposition="outside",
        hovertemplate="%{y}: %{x} affected workloads<extra></extra>",
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=max(260, len(counts) * 32 + 60),
        xaxis=dict(title="Affected Workloads", gridcolor="#1e2d3d"),
        yaxis=dict(showgrid=False),
    )
    return fig


def _eng_registry_donut(df: pd.DataFrame) -> go.Figure:
    counts = df.groupby("imageRegistry")["imageReference"].nunique().reset_index()
    counts.columns = ["registry", "images"]
    palette = ["#00BFA5", "#E53935", "#9B3FBF", "#FB8C00",
               "#1E88E5", "#00C853", "#FF6F00", "#7C4DFF",
               "#F50057", "#00B0FF", "#76FF03"]
    fig = go.Figure(go.Pie(
        labels=counts["registry"],
        values=counts["images"],
        marker=dict(
            colors=[palette[i % len(palette)] for i in range(len(counts))],
            line=dict(width=2, color="#12161f"),
        ),
        hole=0.55,
        textinfo="label+value",
        textfont=dict(size=10),
        hovertemplate="%{label}<br>%{value} unique images (%{percent})<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=320, showlegend=False,
                      title=dict(text="Unique vulnerable images by registry",
                                 font=dict(size=12, color="#90a4ae"), x=0.5))
    return fig


def _eng_cluster_image_heatmap(df: pd.DataFrame, top_n: int = 30) -> go.Figure:
    """
    Heatmap: rows = top N images (by findings), columns = clusters.
    Cell = workload count in that cluster for that image.
    """
    top_labels = (
        df.groupby("imageLabel")["findings"]
        .sum()
        .nlargest(top_n)
        .index.tolist()
    )
    sub = df[df["imageLabel"].isin(top_labels)]
    pivot = (
        sub.groupby(["imageLabel", "clusterName"])["resourceName"]
        .nunique()
        .reset_index()
        .pivot(index="imageLabel", columns="clusterName", values="resourceName")
        .fillna(0)
        .astype(int)
    )
    # Sort rows by total workloads desc
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=False).index]

    clusters = pivot.columns.tolist()
    images   = pivot.index.tolist()
    z        = pivot.values.tolist()
    text     = [[str(int(v)) if v > 0 else "" for v in row] for row in z]

    fig = go.Figure(go.Heatmap(
        z=z,
        x=clusters,
        y=images,
        text=text,
        texttemplate="%{text}",
        colorscale=[[0, "#12161f"], [0.3, "#1a2744"], [0.7, "#9B3FBF"], [1, "#E53935"]],
        showscale=True,
        colorbar=dict(title=dict(text="Workloads", font=dict(color="#90a4ae")),
                      tickfont=dict(color="#90a4ae")),
        hovertemplate=(
            "<b>%{y}</b><br>"
            "Cluster: %{x}<br>"
            "Workloads: %{z}<extra></extra>"
        ),
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        height=max(400, len(images) * 22 + 120),
        xaxis=dict(title="Cluster", tickangle=-30, gridcolor="#1e2d3d",
                   tickfont=dict(size=10)),
        yaxis=dict(title="Image", autorange="reversed", gridcolor="#1e2d3d",
                   tickfont=dict(size=10)),
    )
    return fig


def _eng_findings_hist(df: pd.DataFrame) -> go.Figure:
    """Bar chart of findings-per-workload distribution."""
    counts = df["findings"].value_counts().sort_index()
    fig = go.Figure(go.Bar(
        x=counts.index.astype(str),
        y=counts.values,
        marker=dict(color="#FB8C00", line=dict(width=0)),
        text=counts.values,
        textposition="outside",
        hovertemplate="Findings per workload: %{x}<br>Count: %{y}<extra></extra>",
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT, height=280,
        xaxis=dict(title="Findings per Workload", gridcolor="#1e2d3d"),
        yaxis=dict(title="Workload Count", gridcolor="#1e2d3d"),
    )
    return fig




# ─────────────────────────────────────────────────────────────────────────────
# MAIN RENDER
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="margin-bottom:20px">
  <h1 style="color:#fff;font-size:1.8rem;font-weight:700;margin:0 0 4px">
    🛡️ Sysdig CVE Risk Dashboard
  </h1>
</div>
""", unsafe_allow_html=True)

tab1, tab2 = st.tabs([
    "📊  CVE Risk Overview",
    "🔧  Engineering Fix View",
])

# ═════════════════════════════════════════════════════════════════════════════
# TAB 1 — CVE RISK OVERVIEW
# ═════════════════════════════════════════════════════════════════════════════

with tab1:
    if not api_token or not api_base:
        st.info("👈 Enter your Sysdig Base URL and API Token in the sidebar to load data.")
        st.stop()

    # ── Data fetch ────────────────────────────────────────────────────────────

    if not st.session_state.t1_loaded:
        with st.status("📡 Loading vulnerability data…", expanded=True) as _st:
            try:
                _cves, _errs = load_with_progress(api_base, api_token, _st)
                st.session_state.t1_cves   = _cves
                st.session_state.t1_errors = _errs
                st.session_state.t1_loaded = True
                if _errs:
                    _st.update(label=f"⚠️ {_errs[0]}", state="error")
                else:
                    _st.update(
                        label=f"✅ Loaded {len(_cves)} CVE(s) — use sidebar to refresh",
                        state="complete",
                        expanded=False,
                    )
            except Exception as _exc:
                st.session_state.t1_errors = [str(_exc)]
                st.session_state.t1_loaded = True
                _st.update(label=f"❌ {_exc}", state="error")

    for err in st.session_state.t1_errors:
        st.markdown(f'<div class="error-banner">⚠️ {err}</div>', unsafe_allow_html=True)

    all_cves = st.session_state.t1_cves
    if not all_cves:
        st.stop()

    in_use_cves  = [c for c in all_cves if c.get("inUse")]
    not_use_cves = [c for c in all_cves if not c.get("inUse")]

    # ── Overall summary ───────────────────────────────────────────────────────

    st.markdown("### Overall Summary")
    st.caption(
        "ℹ️ **Severity** is sourced from the Sysdig analytics API (NVD CVSS v3 classification). "
        "This may differ from the severity shown in Sysdig's Vulnerability Findings page, "
        "which uses vendor-adjusted ratings. EPSS scores and in-use status are accurate."
    )
    ov1, ov2, ov3, ov4, ov5, ov6 = st.columns(6)
    ov1.metric("Total CVEs",   len(all_cves),                                    "EPSS > 50%")
    ov2.metric("In Use",       len(in_use_cves),                                 "runtime exposure")
    ov3.metric("Not In Use",   len(not_use_cves),                                "not actively running")
    ov4.metric("Exploitable",  sum(1 for c in all_cves if c.get("exploitable")), "known exploits")
    ov5.metric("CISA KEV",     sum(1 for c in all_cves if c.get("hasCisaKev")),  "actively exploited")
    ov6.metric("Has Fix",      sum(1 for c in all_cves if c.get("fixAvailable")))

    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)
    _render_section(in_use_cves,  "🔴 In Use — Fix Now",    "section-inuse")
    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)
    _render_section(not_use_cves, "🟡 Not In Use — Monitor", "section-notuse")

# ═════════════════════════════════════════════════════════════════════════════
# TAB 2 — ENGINEERING FIX VIEW
# ═════════════════════════════════════════════════════════════════════════════

with tab2:
    # ── Custom drag-and-drop styling ───────────────────────────────────────────
    st.markdown("""
<style>
[data-testid="stFileUploader"] {
    border: 2px dashed #37474f;
    border-radius: 12px;
    background: #12161f;
    transition: border-color .2s, background .2s;
}
[data-testid="stFileUploader"]:hover {
    border-color: #00C853;
    background: #0d1117;
}
[data-testid="stFileUploaderDropzone"] {
    padding: 40px 24px;
}
[data-testid="stFileUploaderDropzoneInstructions"] {
    color: #78909c !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] svg {
    color: #00C853 !important;
}
</style>
""", unsafe_allow_html=True)

    st.markdown("""
<div style="margin-bottom:22px">
  <h2 style="color:#fff;font-size:1.4rem;font-weight:700;margin:0 0 6px">
    🔧 Engineering Fix View
  </h2>
  <p style="color:#78909c;font-size:.87rem;margin:0">
    Drop the CSV exported from the Sysdig ClickHouse query
    (<code>MATCH Vulnerability … RETURN clusterName, namespaceName, resourceName,
    imageReference, …</code>).
    The dashboard shows exactly which images to rebuild and where to redeploy them.
  </p>
</div>
""", unsafe_allow_html=True)

    # ── Drag-and-drop file uploader ────────────────────────────────────────────
    uploaded = st.file_uploader(
        "Drop your CSV here or click to browse",
        type=["csv"],
        key="eng_file_uploader",
        help="Sysdig ClickHouse vulnerability findings export "
             "(clusterName, namespaceName, resourceName, imageReference, …)",
        label_visibility="visible",
    )

    df_eng = None
    if uploaded is not None:
        try:
            df_eng = _eng_load(uploaded)
            st.success(f"Loaded **{len(df_eng):,}** rows from `{uploaded.name}`")
        except Exception as e:
            st.error(f"Could not load CSV: {e}")

    if df_eng is not None:
        img_df  = _eng_image_summary(df_eng)
        repo_df = _eng_repo_summary(df_eng)

        cve_in_file = "from uploaded query"

        # ── Top-level metrics ─────────────────────────────────────────────
        st.markdown("### Impact Summary")
        e1, e2, e3, e4, e5, e6 = st.columns(6)
        e1.metric("Workloads Affected",   df_eng["resourceName"].nunique())
        e2.metric("Unique Images",         len(img_df), "to rebuild/patch")
        e3.metric("Image Repositories",    df_eng["imageRepository"].nunique())
        e4.metric("Clusters",              df_eng["clusterName"].nunique())
        e5.metric("Namespaces",            df_eng["namespaceName"].nunique())
        e6.metric("Total Findings",        int(df_eng["findings"].sum()))

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        # ── Section 1: What to fix ────────────────────────────────────────
        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:4px'>"
            "🎯 What to Fix — Image Action List</div>"
            "<div style='color:#78909c;font-size:.82rem;margin-bottom:14px'>"
            "Each row is one image that needs to be rebuilt/patched. "
            "Priority is ranked by total findings. "
            "Fix the top rows first — they have the highest exposure.</div>",
            unsafe_allow_html=True,
        )

        # Repository-level summary (collapsed by default)
        with st.expander("📂 Group by Repository (see how many tags per repo need fixing)", expanded=False):
            repo_display = repo_df.rename(columns={
                "imageRepository": "Repository",
                "unique_tags":     "Vulnerable Tags",
                "workloads":       "Workloads",
                "clusters":        "Clusters",
                "total_findings":  "Total Findings",
                "tags":            "Tag Versions",
            })
            st.dataframe(repo_display, use_container_width=True, hide_index=True)

        # Per-image action table
        action_cols = {
            "Priority":       "Priority",
            "imageLabel":     "Image (name:tag)",
            "imageRegistry":  "Registry",
            "workloads":      "Workloads",
            "clusters":       "Clusters",
            "namespaces":     "Namespaces",
            "total_findings": "Total Findings",
            "cluster_list":   "Cluster Names",
            "imageReference": "Full Image Reference",
        }
        action_df = img_df[list(action_cols.keys())].rename(columns=action_cols)

        def _sty_priority(v):
            if v <= 3:  return "color:#ef5350;font-weight:700"
            if v <= 10: return "color:#ffa726;font-weight:700"
            return "color:#90a4ae"

        styled_action = action_df.style.applymap(
            _sty_priority, subset=["Priority"]
        )
        st.dataframe(styled_action, use_container_width=True, hide_index=True,
                     height=min(600, 36 * len(action_df) + 60))

        ts = datetime.now().strftime("%Y%m%d_%H%M")
        dl1, dl2 = st.columns([1, 5])
        with dl1:
            st.download_button(
                "⬇️ Export action list",
                data=action_df.to_csv(index=False),
                file_name=f"fix_action_list_{ts}.csv",
                mime="text/csv",
                key="dl_eng_action",
            )

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        # ── Section 2: Charts ─────────────────────────────────────────────
        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:14px'>"
            "📊 Visual Breakdown</div>",
            unsafe_allow_html=True,
        )

        vt1, vt2, vt3 = st.tabs([
            "🖼️ Top Images",
            "🌐 Cluster Spread",
            "📦 Registry & Findings",
        ])

        with vt1:
            st.markdown(
                "<div style='color:#90a4ae;font-size:.82rem;margin-bottom:6px'>"
                "Top 25 images by total findings count — these are the highest priority rebuilds.</div>",
                unsafe_allow_html=True,
            )
            st.plotly_chart(_eng_top_images_bar(img_df), use_container_width=True,
                            config={"displayModeBar": False})

        with vt2:
            vc1, vc2 = st.columns(2)
            with vc1:
                st.markdown(
                    "<div style='color:#90a4ae;font-size:.82rem;margin-bottom:6px'>"
                    "Affected workloads per cluster.</div>",
                    unsafe_allow_html=True,
                )
                st.plotly_chart(_eng_cluster_bar(df_eng), use_container_width=True,
                                config={"displayModeBar": False})
            with vc2:
                st.markdown(
                    "<div style='color:#90a4ae;font-size:.82rem;margin-bottom:6px'>"
                    "Namespace distribution — which namespaces are most exposed.</div>",
                    unsafe_allow_html=True,
                )
                ns_counts = (
                    df_eng.groupby("namespaceName")["resourceName"]
                    .nunique()
                    .reset_index()
                    .rename(columns={"resourceName": "workloads"})
                    .set_index("namespaceName")["workloads"]
                    .to_dict()
                )
                st.plotly_chart(
                    _t2_hbar(ns_counts, "Workloads", "#1E88E5"),
                    use_container_width=True,
                    config={"displayModeBar": False},
                )

        with vt3:
            vc1, vc2 = st.columns(2)
            with vc1:
                st.plotly_chart(_eng_registry_donut(df_eng), use_container_width=True,
                                config={"displayModeBar": False})
            with vc2:
                st.markdown(
                    "<div style='color:#90a4ae;font-size:.82rem;margin-bottom:6px'>"
                    "Findings-per-workload distribution — "
                    "higher = more vulnerable packages in that workload.</div>",
                    unsafe_allow_html=True,
                )
                st.plotly_chart(_eng_findings_hist(df_eng), use_container_width=True,
                                config={"displayModeBar": False})

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        # ── Section 3: Image × Cluster heatmap ───────────────────────────
        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:4px'>"
            "🟥 Image × Cluster Heatmap</div>"
            "<div style='color:#78909c;font-size:.82rem;margin-bottom:14px'>"
            "Which images are running in which clusters. "
            "Each cell = number of workloads. "
            "Use this to plan your rollout — a row with many filled cells "
            "needs coordinated deployment across multiple teams.</div>",
            unsafe_allow_html=True,
        )
        st.plotly_chart(_eng_cluster_image_heatmap(df_eng), use_container_width=True,
                        config={"displayModeBar": False})

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        # ── Section 4: Per-image workload drill-down ──────────────────────
        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:4px'>"
            "🔍 Per-Image Workload Detail</div>"
            "<div style='color:#78909c;font-size:.82rem;margin-bottom:14px'>"
            "Select an image to see every workload instance that needs to be redeployed "
            "after the image is rebuilt. Use this to create targeted Jira tickets "
            "per cluster or namespace team.</div>",
            unsafe_allow_html=True,
        )

        all_labels = img_df["imageLabel"].tolist()
        sel_image = st.selectbox(
            "Select image",
            options=all_labels,
            format_func=lambda x: x,
            key="eng_img_sel",
        )

        if sel_image:
            sub_df = df_eng[df_eng["imageLabel"] == sel_image].copy()
            sel_ref = sub_df["imageReference"].iloc[0]

            st.markdown(
                f"<div style='background:#1a1f2e;border-radius:8px;padding:12px 18px;"
                f"border-left:4px solid #E53935;margin-bottom:14px'>"
                f"<div style='color:#90a4ae;font-size:.78rem;margin-bottom:2px'>Full image reference</div>"
                f"<div style='color:#fff;font-family:monospace;font-size:.9rem'>{sel_ref}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

            sm1, sm2, sm3, sm4 = st.columns(4)
            sm1.metric("Workloads",     sub_df["resourceName"].nunique())
            sm2.metric("Clusters",      sub_df["clusterName"].nunique())
            sm3.metric("Namespaces",    sub_df["namespaceName"].nunique())
            sm4.metric("Total Findings", int(sub_df["findings"].sum()))

            detail_df = (
                sub_df[["clusterName", "namespaceName", "resourceName", "findings"]]
                .drop_duplicates()
                .sort_values(["clusterName", "namespaceName", "resourceName"])
                .rename(columns={
                    "clusterName":   "Cluster",
                    "namespaceName": "Namespace",
                    "resourceName":  "Workload",
                    "findings":      "Findings",
                })
                .reset_index(drop=True)
            )
            st.dataframe(detail_df, use_container_width=True, hide_index=True,
                         height=min(500, 36 * len(detail_df) + 60))

            st.download_button(
                f"⬇️ Export workloads for {sel_image}",
                data=detail_df.to_csv(index=False),
                file_name=f"workloads_{sel_image.replace(':', '_').replace('/', '_')}_{ts}.csv",
                mime="text/csv",
                key="dl_eng_detail",
            )

    if uploaded is None:
        st.info(
            "👆 Drag and drop your Sysdig ClickHouse CSV export above, or click to browse.\n\n"
            "Expected columns: `clusterName`, `namespaceName`, `resourceName`, "
            "`imageReference`, `imageRegistry`, `imageRepository`, `imageTag`, `findings`."
        )

# ─────────────────────────────────────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────────────────────────────────────

st.markdown(f"""
<div style="margin-top:48px;padding:14px;background:#12161f;border-radius:8px;
            color:#546e7a;font-size:.78rem;text-align:center">
    Sysdig CVE Risk Dashboard &nbsp;·&nbsp; {api_base} &nbsp;·&nbsp;
    Timeout {API_TIMEOUT}s &nbsp;·&nbsp;
    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>
""", unsafe_allow_html=True)
