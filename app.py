#!/usr/bin/env python3
"""
Sysdig Posture Report Analytics - Web Interface

A Streamlit-based web application for analyzing and visualizing security posture
reports and container vulnerability data from Sysdig.

Features:
- Upload and analyze posture compliance reports (CSV format)
- Fetch and visualize registry vulnerability scan results via Sysdig API
- Interactive dashboards with customizable widget layouts
- Trend analysis across multiple report snapshots
- Exportable reports in CSV and JSON formats

Environment Variables:
- SYSDIG_API_TOKEN: API token for authenticating with Sysdig API (required for vulnerability scanning)
- SYSDIG_API_BASE: Base URL for Sysdig API (default: https://api.sysdig.com)

Usage:
    streamlit run app.py

Author: Your Organization
License: MIT
"""

# =============================================================================
# IMPORTS
# =============================================================================

import io
import gzip
import json
import os
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import streamlit as st
from streamlit_sortables import sort_items

# =============================================================================
# STREAMLIT PAGE CONFIGURATION
# =============================================================================

# Configure the Streamlit page layout and metadata
st.set_page_config(
    page_title="Sysdig Analytics Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def extract_date_from_filename(filename: str) -> datetime:
    """
    Extract date from a filename containing an ISO date pattern.

    Args:
        filename: Name of the file (e.g., 'Report_2026-01-31T03_25_25.610Z.csv.gz')

    Returns:
        datetime: Extracted date, or current date if no pattern found

    Example:
        >>> extract_date_from_filename('Report_2026-01-31T03_25_25.csv')
        datetime(2026, 1, 31)
    """
    # Match ISO date pattern: YYYY-MM-DD optionally followed by time
    pattern = r'(\d{4}-\d{2}-\d{2})T?(\d{2}[_:]\d{2}[_:]\d{2})?'
    match = re.search(pattern, filename)
    if match:
        date_str = match.group(1)
        return datetime.strptime(date_str, '%Y-%m-%d')
    # Fallback to current date if no date found
    return datetime.now()


# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Directory for storing fetched vulnerability data snapshots
VULN_DATA_DIR = Path.home() / "sysdig-vuln-data"

# Sysdig API base URL - configurable via environment variable
# Set SYSDIG_API_BASE environment variable to override for different regions:
#   - US: https://api.sysdig.com
#   - EU: https://eu1.app.sysdig.com/api
#   - AU: https://api.au1.sysdig.com
SYSDIG_API_BASE = os.environ.get("SYSDIG_API_BASE", "https://api.sysdig.com")

# Color mapping for vulnerability severity levels (used in charts)
SEVERITY_COLORS = {
    'Critical': '#9b59b6',  # Purple for critical issues
    'High': '#e74c3c',      # Red for high severity
    'Medium': '#f39c12',    # Orange for medium severity
    'Low': '#3498db',       # Blue for low severity
    'Negligible': '#95a5a6',  # Gray for negligible/informational
}

# Ordered list of severity levels from most to least severe
SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Negligible']

# =============================================================================
# CVE RISK DASHBOARD — CONSTANTS
# =============================================================================

CVE_DEFAULT_BASE   = "https://app.au1.sysdig.com"
CVE_API_TIMEOUT    = 20
CVE_BY_CVE_PATH    = "/api/secure/analytics/v1/data/vulnerabilities/findings/by-cve"
CVE_EPSS_THRESHOLD = 0.50   # 50 %
CVE_TOP_N          = 50

CVE_SEVERITY_COLOR = {
    "Critical":   "#9B3FBF",
    "High":       "#E53935",
    "Medium":     "#FB8C00",
    "Low":        "#1E88E5",
    "Negligible": "#78909C",
}

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#b0bec5", size=12),
    margin=dict(t=40, b=20, l=20, r=20),
)

EXPECTED_COLS = {
    "clusterName", "findings", "imageReference",
    "imageRegistry", "imageRepository", "imageTag",
    "namespaceName", "resourceName",
}


# =============================================================================
# SYSDIG API FUNCTIONS
# =============================================================================


def fetch_registry_results(api_token: str, limit: int = 100) -> list[dict]:
    """
    Fetch all registry vulnerability scan results from Sysdig API.

    Uses cursor-based pagination to retrieve all results across multiple
    API calls. Each page contains up to 'limit' results.

    Args:
        api_token: Bearer token for Sysdig API authentication
        limit: Number of results per page (default: 100)

    Returns:
        list[dict]: List of image vulnerability records from the registry scanner

    Raises:
        requests.HTTPError: If API request fails
        requests.Timeout: If request exceeds 60 second timeout
    """
    url = f"{SYSDIG_API_BASE}/secure/vulnerability/v1/registry-results"
    headers = {"Authorization": f"Bearer {api_token}", "Accept": "application/json"}
    all_results = []
    cursor = None

    # Paginate through all results using cursor-based pagination
    while True:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor

        resp = requests.get(url, headers=headers, params=params, timeout=60)
        resp.raise_for_status()
        body = resp.json()

        # Extract data from response and accumulate results
        data = body.get("data", [])
        all_results.extend(data)

        # Check for next page cursor
        page_info = body.get("page", {})
        cursor = page_info.get("next")
        if not cursor:
            break

    return all_results


def save_results_to_disk(results: list[dict], folder: Path = VULN_DATA_DIR) -> Path:
    """
    Save fetched vulnerability results to disk as a timestamped JSON file.

    Creates a snapshot file that can be used later for trend analysis
    or offline viewing.

    Args:
        results: List of vulnerability scan results from API
        folder: Directory to save the snapshot (default: ~/sysdig-vuln-data)

    Returns:
        Path: Path to the saved JSON file
    """
    folder.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filepath = folder / f"registry_vuln_{ts}.json"

    # Create payload with metadata and results
    payload = {
        "fetched_at": datetime.now().isoformat(),
        "total_images": len(results),
        "data": results,
    }
    filepath.write_text(json.dumps(payload, default=str))
    return filepath


def list_saved_snapshots(folder: Path = VULN_DATA_DIR) -> list[dict]:
    """
    List all saved vulnerability snapshot files.

    Scans the snapshot directory for JSON files and returns metadata
    about each snapshot, sorted by date (newest first).

    Args:
        folder: Directory containing snapshot files

    Returns:
        list[dict]: List of snapshot metadata including path, filename,
                   fetch timestamp, and image count
    """
    if not folder.exists():
        return []

    files = sorted(folder.glob("registry_vuln_*.json"), reverse=True)
    snapshots = []

    for f in files:
        try:
            meta = json.loads(f.read_text())
            snapshots.append({
                "path": f,
                "filename": f.name,
                "fetched_at": meta.get("fetched_at", "unknown"),
                "total_images": meta.get("total_images", 0),
            })
        except (json.JSONDecodeError, KeyError):
            # Skip corrupted or invalid files
            continue

    return snapshots


def load_snapshot(filepath) -> list[dict]:
    """
    Load vulnerability data from a JSON snapshot file.

    Supports both file paths and file-like objects (for uploaded files).

    Args:
        filepath: Path to JSON file or file-like object

    Returns:
        tuple: (data list, fetched_at timestamp string)
    """
    # Handle file-like objects (e.g., Streamlit uploaded files)
    if hasattr(filepath, 'read'):
        raw = filepath.read()
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8')
        payload = json.loads(raw)
    else:
        # Handle file path
        payload = json.loads(Path(filepath).read_text())

    return payload.get("data", []), payload.get("fetched_at", "unknown")


def normalize_image_data(results: list[dict]) -> pd.DataFrame:
    """
    Convert raw Sysdig API results into a normalized DataFrame for analysis.

    Transforms the nested API response structure into a flat table format
    suitable for charting and data analysis. Handles field name variations
    across different API versions.

    Args:
        results: List of raw image scan results from Sysdig API

    Returns:
        pd.DataFrame: Normalized data with columns for image info, vulnerability
                     counts by severity, and metadata. Sorted by total
                     vulnerabilities (descending).
    """
    rows = []

    for r in results:
        # Extract vulnerability counts by severity
        # Handle field name variations across API versions
        vuln_sev = r.get("vulnTotalBySeverity",
                         r.get("vulnsBySev",
                                r.get("vulnTotalBySev", {})))
        fix_sev = r.get("fixableVulnsBySeverity",
                        r.get("fixableVulnsBySev", {}))

        # Extract counts for each severity level (handle case variations)
        crit = vuln_sev.get("critical", vuln_sev.get("Critical", 0))
        high = vuln_sev.get("high", vuln_sev.get("High", 0))
        med = vuln_sev.get("medium", vuln_sev.get("Medium", 0))
        low = vuln_sev.get("low", vuln_sev.get("Low", 0))
        neg = vuln_sev.get("negligible", vuln_sev.get("Negligible", 0))
        total_vulns = crit + high + med + low + neg

        # Extract fixable vulnerability counts
        fix_crit = fix_sev.get("critical", fix_sev.get("Critical", 0))
        fix_high = fix_sev.get("high", fix_sev.get("High", 0))
        fix_med = fix_sev.get("medium", fix_sev.get("Medium", 0))
        fix_low = fix_sev.get("low", fix_sev.get("Low", 0))
        fix_neg = fix_sev.get("negligible", fix_sev.get("Negligible", 0))
        total_fixable = fix_crit + fix_high + fix_med + fix_low + fix_neg

        # Get image pull string (the full image reference)
        pull_string = r.get("pullString", r.get("imagePullString", ""))

        # Parse repository and tag from pullString
        # Format: "registry/repo/image:tag" -> repo="registry/repo/image", tag="tag"
        parsed_repo = pull_string
        parsed_tag = ""
        if ":" in pull_string:
            parts = pull_string.rsplit(":", 1)
            parsed_repo = parts[0]
            parsed_tag = parts[1]

        # Build normalized row with all relevant fields
        row = {
            "image_id": r.get("imageId", r.get("resultId", "")),
            "result_id": r.get("resultId", ""),
            "pull_string": pull_string,
            "repository": parsed_repo,
            "tag": parsed_tag or r.get("tag", ""),
            "vendor": r.get("vendor", ""),
            "created_at": r.get("createdAt", ""),
            # Vulnerability counts by severity
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "negligible": neg,
            # Fixable vulnerability counts
            "fix_critical": fix_crit,
            "fix_high": fix_high,
            "fix_medium": fix_med,
            "fix_low": fix_low,
            "fix_negligible": fix_neg,
            # Aggregate counts
            "total_vulns": total_vulns,
            "total_fixable": total_fixable,
            "total_unfixable": total_vulns - total_fixable,
            # Additional metadata
            "exploit_count": r.get("exploitCount", r.get("exploitableCount", 0)),
            "policy_status": r.get("policyStatus", r.get("policyEvaluation", "")),
            "in_use": r.get("inUse", False),
        }

        # Create a short display name for charts (just image name:tag)
        name_part = parsed_repo.split("/")[-1] if "/" in parsed_repo else parsed_repo
        row["display_name"] = f"{name_part}:{parsed_tag}" if parsed_tag else name_part
        rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    # Sort by total vulnerabilities for priority-based analysis
    df = df.sort_values("total_vulns", ascending=False).reset_index(drop=True)
    return df


# =============================================================================
# POSTURE REPORT DATA LOADING
# =============================================================================


def load_data(uploaded_file) -> pd.DataFrame:
    """
    Load posture report CSV data from an uploaded file.

    Supports multiple file formats:
    - Plain CSV files (.csv)
    - Gzipped CSV files (.csv.gz)
    - ZIP archives containing CSV files (.zip)

    Args:
        uploaded_file: Streamlit UploadedFile object

    Returns:
        tuple: (full_dataframe, failing_controls_only_dataframe)

    Raises:
        ValueError: If ZIP archive contains no CSV files
    """
    filename = uploaded_file.name

    # Handle ZIP archives
    if filename.endswith('.zip'):
        with zipfile.ZipFile(uploaded_file, 'r') as z:
            # Find CSV files in the zip (including gzipped ones)
            csv_files = [f for f in z.namelist() if f.endswith('.csv') or f.endswith('.csv.gz')]
            if not csv_files:
                raise ValueError("No CSV files found in the zip archive")

            # Use the first CSV file found
            csv_name = csv_files[0]
            if csv_name.endswith('.gz'):
                with z.open(csv_name) as zf:
                    with gzip.open(zf, 'rt') as f:
                        df = pd.read_csv(f)
            else:
                with z.open(csv_name) as zf:
                    df = pd.read_csv(zf)

    # Handle gzipped CSV files
    elif filename.endswith('.gz'):
        with gzip.open(uploaded_file, 'rt') as f:
            df = pd.read_csv(f)

    # Handle plain CSV files
    else:
        df = pd.read_csv(uploaded_file)

    # Filter to only failing controls for analysis
    df_fail = df[df['Result'] == 'Fail'].copy()

    return df, df_fail


def load_multiple_files(uploaded_files, group_by: str = 'Zones') -> pd.DataFrame:
    """
    Load multiple posture report CSV files for trend analysis.

    Combines data from multiple reports (typically from different dates)
    into a single DataFrame suitable for tracking changes over time.

    Args:
        uploaded_files: List of Streamlit UploadedFile objects
        group_by: Column to group failures by ('Zones' or 'Account Id')

    Returns:
        pd.DataFrame: Combined data with columns for Owner, Total Failures,
                     Unique Controls, Report Date, and Filename
    """
    all_data = []

    for uploaded_file in uploaded_files:
        filename = uploaded_file.name
        report_date = extract_date_from_filename(filename)

        if filename.endswith('.zip'):
            with zipfile.ZipFile(uploaded_file, 'r') as z:
                csv_files = [f for f in z.namelist() if f.endswith('.csv') or f.endswith('.csv.gz')]
                if not csv_files:
                    continue  # Skip zip files without CSVs
                csv_name = csv_files[0]
                if csv_name.endswith('.gz'):
                    with z.open(csv_name) as zf:
                        with gzip.open(zf, 'rt') as f:
                            df = pd.read_csv(f)
                else:
                    with z.open(csv_name) as zf:
                        df = pd.read_csv(zf)
        elif filename.endswith('.gz'):
            with gzip.open(uploaded_file, 'rt') as f:
                df = pd.read_csv(f)
        else:
            df = pd.read_csv(uploaded_file)

        # Filter to only failing controls
        df_fail = df[df['Result'] == 'Fail'].copy()

        # Aggregate by group_by column
        summary = df_fail.groupby(group_by).agg({
            'Control ID': 'count',
            'Control Name': 'nunique'
        }).reset_index()
        summary.columns = ['Owner', 'Total Failures', 'Unique Controls']
        summary['Report Date'] = report_date
        summary['Filename'] = filename

        all_data.append(summary)

    if all_data:
        combined = pd.concat(all_data, ignore_index=True)
        combined = combined.sort_values(['Owner', 'Report Date'])
        return combined
    return pd.DataFrame()


# =============================================================================
# POSTURE ANALYTICS CHART GENERATION
# =============================================================================


def create_executive_charts(df: pd.DataFrame, group_by: str = 'Zones'):
    """
    Create executive-level dashboard charts for posture analytics.

    Generates visualizations showing who contributes most to compliance
    failures, designed for executive stakeholders to identify priority
    areas for remediation.

    Args:
        df: DataFrame containing failing control records
        group_by: Column to group data by ('Zones' for owners, 'Account Id' for accounts)

    Returns:
        tuple: (pie_chart, bar_chart, total_failures, unique_owners,
               unique_accounts, top_owners_df, all_owner_stats_df)
    """
    total_failures = len(df)
    unique_owners = df[group_by].nunique()
    unique_accounts = df['Account Id'].nunique()

    # Aggregate by owner - use different secondary column based on grouping
    secondary_col = 'Account Id' if group_by == 'Zones' else 'Zones'
    owner_stats = df.groupby(group_by).agg({
        'Control ID': 'count',
        secondary_col: lambda x: list(x.unique()),
        'Control Name': lambda x: x.nunique()
    }).reset_index()
    owner_stats.columns = ['Owner', 'Total Failures', 'Related Items', 'Unique Controls']
    owner_stats['Percentage'] = (owner_stats['Total Failures'] / total_failures * 100).round(1)
    owner_stats = owner_stats.sort_values('Total Failures', ascending=False)

    # Top contributors
    top_n = 10
    top_owners = owner_stats.head(top_n).copy()
    others_count = owner_stats.iloc[top_n:]['Total Failures'].sum() if len(owner_stats) > top_n else 0
    others_pct = round(others_count / total_failures * 100, 1)
    top_total_pct = top_owners['Percentage'].sum()

    # Pie chart - convert to string for Account IDs
    pie_labels = [f"{str(o)[:20]}..." if len(str(o)) > 20 else str(o) for o in top_owners['Owner']]
    pie_values = list(top_owners['Total Failures'])
    pie_text = [f"{p}%" for p in top_owners['Percentage']]

    if others_count > 0:
        pie_labels.append(f'Others ({len(owner_stats) - top_n} people)')
        pie_values.append(others_count)
        pie_text.append(f"{others_pct}%")

    colors_pie = ['#e74c3c', '#c0392b', '#e67e22', '#d35400', '#f39c12',
                  '#f1c40f', '#27ae60', '#2ecc71', '#3498db', '#2980b9', '#95a5a6']

    fig_pie = go.Figure(go.Pie(
        labels=pie_labels,
        values=pie_values,
        text=pie_text,
        textinfo='label+text',
        textposition='outside',
        marker_colors=colors_pie[:len(pie_labels)],
        hole=0.4,
        sort=False
    ))
    fig_pie.add_annotation(
        text=f"<b>{total_failures:,}</b><br>Total",
        x=0.5, y=0.5, font_size=16, showarrow=False
    )
    fig_pie.update_layout(
        title=dict(text='<b>Who is Contributing to Compliance Failures?</b>', x=0.5, font=dict(size=16)),
        height=500,
        margin=dict(t=60, b=40, l=40, r=40),
        showlegend=False
    )

    # Horizontal bar chart
    top_owners_sorted = top_owners.sort_values('Total Failures', ascending=True).reset_index(drop=True)
    bar_labels = [(str(o)[:25] + '...' if len(str(o)) > 25 else str(o)) for o in top_owners_sorted['Owner'].tolist()]
    bar_values = top_owners_sorted['Total Failures'].tolist()
    bar_pcts = top_owners_sorted['Percentage'].tolist()
    bar_related = top_owners_sorted['Related Items'].tolist()
    related_label = 'Accounts' if group_by == 'Zones' else 'Zones'

    fig_bar = go.Figure(go.Bar(
        x=bar_values,
        y=bar_labels,
        orientation='h',
        marker_color='#e74c3c',
        text=[f"{v:,} ({p}%)" for v, p in zip(bar_values, bar_pcts)],
        textposition='inside',
        textfont=dict(color='white', size=12),
        insidetextanchor='end',
        hovertext=[f"{o}<br>Failures: {v:,}<br>% of Total: {p}%<br>{related_label}: {', '.join(map(str, a[:3]))}"
                   for o, v, p, a in zip(bar_labels, bar_values, bar_pcts, bar_related)],
        hoverinfo='text'
    ))
    fig_bar.update_layout(
        title=dict(text=f'<b>Top {top_n} Contributors = {top_total_pct:.0f}% of All Failures</b>', x=0.5, font=dict(size=16)),
        height=500,
        margin=dict(t=60, b=60, l=200, r=60),
        xaxis=dict(title='Total Failures', tickformat=',d', rangemode='tozero'),
        yaxis=dict(type='category'),
        plot_bgcolor='#fafafa'
    )

    return fig_pie, fig_bar, total_failures, unique_owners, unique_accounts, top_owners, owner_stats


def create_person_charts(df: pd.DataFrame, top_owners: pd.DataFrame, group_by: str = 'Zones'):
    """
    Create detailed breakdown charts for top contributors.

    For each of the top 5 contributors, generates a horizontal bar chart
    showing their most frequently failing controls by severity.

    Args:
        df: DataFrame containing failing control records
        top_owners: DataFrame with top contributing owners
        group_by: Column used for grouping ('Zones' or 'Account Id')

    Returns:
        list[tuple]: List of (owner_name, plotly_figure) pairs
    """
    person_charts = []
    top_5_owners = top_owners.sort_values('Total Failures', ascending=False).head(5)

    for _, row in top_5_owners.iterrows():
        owner = row['Owner']
        owner_df = df[df[group_by] == owner]

        all_controls = owner_df.groupby(['Control Name', 'Control Severity']).size().reset_index(name='Count')
        total_unique_controls = len(all_controls)

        controls = all_controls.sort_values('Count', ascending=True).tail(8).reset_index(drop=True)

        severity_colors = {'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'}

        ctrl_labels = [(c[:40] + '...' if len(c) > 40 else c) for c in controls['Control Name'].tolist()]
        ctrl_values = controls['Count'].tolist()
        ctrl_severities = controls['Control Severity'].tolist()
        ctrl_colors = [severity_colors.get(s, '#95a5a6') for s in ctrl_severities]

        fig_person = go.Figure(go.Bar(
            x=ctrl_values,
            y=ctrl_labels,
            orientation='h',
            marker_color=ctrl_colors,
            text=[f"{c} ({s})" for c, s in zip(ctrl_values, ctrl_severities)],
            textposition='inside',
            textfont=dict(color='white', size=11),
            insidetextanchor='end',
            hovertext=controls['Control Name'].tolist(),
            hoverinfo='text+x'
        ))

        related_str = ', '.join(map(str, row['Related Items'][:3]))
        if len(row['Related Items']) > 3:
            related_str += f" (+{len(row['Related Items'])-3} more)"
        related_label = 'Accounts' if group_by == 'Zones' else 'Zones'

        fig_person.update_layout(
            title=dict(
                text=f"<b>{str(owner)[:35]}</b><br>{row['Total Failures']:,} failures ({row['Percentage']}%) across {total_unique_controls} controls<br>{related_label}: {related_str}",
                x=0.5, font=dict(size=13)
            ),
            height=400,
            margin=dict(t=90, b=40, l=250, r=60),
            xaxis=dict(title='Total Failures', tickformat=',d', rangemode='tozero'),
            yaxis=dict(tickfont=dict(size=10)),
            plot_bgcolor='#fafafa'
        )
        person_charts.append((owner, fig_person))

    return person_charts


def create_security_charts(df: pd.DataFrame, group_by: str = 'Zones'):
    """
    Create security team dashboard charts for detailed drill-down.

    Generates three visualizations:
    1. Treemap: Hierarchical view of Owner > Severity > Control
    2. Heatmap: Owner vs Control failure matrix
    3. Stacked bar: Severity breakdown by owner

    Args:
        df: DataFrame containing failing control records
        group_by: Column used for grouping ('Zones' or 'Account Id')

    Returns:
        tuple: (treemap_figure, heatmap_figure, severity_bar_figure)
    """
    # Treemap for hierarchical drill-down
    treemap_data = df.groupby([group_by, 'Control Severity', 'Control Name']).size().reset_index(name='Count')

    fig_treemap = px.treemap(
        treemap_data,
        path=[group_by, 'Control Severity', 'Control Name'],
        values='Count',
        color='Control Severity',
        color_discrete_map={'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'},
        title='<b>Security Posture Drill-Down</b><br><sup>Click to explore: Owner > Severity > Control</sup>'
    )
    fig_treemap.update_layout(height=700)
    fig_treemap.update_traces(textinfo='label+value')

    # Heatmap
    pivot = df.pivot_table(
        index=group_by,
        columns='Control Name',
        values='Resource ID',
        aggfunc='count',
        fill_value=0
    )

    top_owners = df[group_by].value_counts().head(20).index
    top_controls = df['Control Name'].value_counts().head(15).index

    pivot_filtered = pivot.loc[
        pivot.index.isin(top_owners),
        pivot.columns.isin(top_controls)
    ]

    fig_heatmap = go.Figure(data=go.Heatmap(
        z=pivot_filtered.values,
        x=[c[:40] + '...' if len(c) > 40 else c for c in pivot_filtered.columns],
        y=[str(i) for i in pivot_filtered.index],
        colorscale='Reds',
        text=pivot_filtered.values,
        texttemplate='%{text}',
        textfont={"size": 10},
        hovertemplate='Owner: %{y}<br>Control: %{x}<br>Failures: %{z}<extra></extra>'
    ))
    fig_heatmap.update_layout(
        title='<b>Owner vs Control Failure Matrix</b>',
        xaxis_title='Control Name',
        yaxis_title='Owner',
        height=600,
        xaxis=dict(tickangle=45, tickfont=dict(size=9)),
        yaxis=dict(tickfont=dict(size=10), type='category')
    )

    # Severity breakdown
    owner_severity = df.groupby([group_by, 'Control Severity']).size().reset_index(name='Count')
    top_10_owners = df[group_by].value_counts().head(10).index.tolist()
    owner_severity_filtered = owner_severity[owner_severity[group_by].isin(top_10_owners)]

    fig_severity = go.Figure()
    for severity in ['High', 'Medium', 'Low', 'Info']:
        sev_data = owner_severity_filtered[owner_severity_filtered['Control Severity'] == severity]
        if not sev_data.empty:
            fig_severity.add_trace(go.Bar(
                name=severity,
                x=sev_data[group_by].astype(str),
                y=sev_data['Count'],
                marker_color={'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'}[severity],
                text=sev_data['Count'],
                textposition='inside'
            ))

    fig_severity.update_layout(
        barmode='stack',
        title='<b>Severity Breakdown by Owner (Top 10)</b>',
        height=500,
        xaxis=dict(tickangle=45, type='category'),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1)
    )

    return fig_treemap, fig_heatmap, fig_severity


def create_trend_charts(trend_data: pd.DataFrame):
    """
    Create trend analysis charts for tracking failures over time.

    Visualizes how compliance failures change across multiple report
    snapshots, helping identify improvement or regression.

    Args:
        trend_data: DataFrame with aggregated failure data per owner/date

    Returns:
        tuple: (line_chart, stacked_area_chart, summary_dataframe)
               Returns (None, None, None) if trend_data is empty
    """
    if trend_data.empty:
        return None, None

    # Get top 10 owners by total failures across all reports
    top_owners = trend_data.groupby('Owner')['Total Failures'].sum().nlargest(10).index.tolist()
    trend_filtered = trend_data[trend_data['Owner'].isin(top_owners)]

    # Line chart - Total Failures over time per owner
    fig_trend = go.Figure()

    for owner in top_owners:
        owner_data = trend_filtered[trend_filtered['Owner'] == owner].sort_values('Report Date')
        fig_trend.add_trace(go.Scatter(
            x=owner_data['Report Date'],
            y=owner_data['Total Failures'],
            mode='lines+markers',
            name=str(owner)[:25] + '...' if len(str(owner)) > 25 else str(owner),
            hovertemplate=f'{owner}<br>Date: %{{x}}<br>Failures: %{{y}}<extra></extra>'
        ))

    fig_trend.update_layout(
        title='<b>Failure Trend Over Time (Top 10 Contributors)</b><br><sup>Goal: See these lines go down!</sup>',
        xaxis_title='Report Date',
        yaxis_title='Total Failures',
        height=500,
        hovermode='x unified',
        legend=dict(orientation='v', yanchor='top', y=1, xanchor='left', x=1.02)
    )

    # Summary table with change indicators
    summary_data = []
    for owner in top_owners:
        owner_data = trend_filtered[trend_filtered['Owner'] == owner].sort_values('Report Date')
        if len(owner_data) >= 2:
            first_val = owner_data.iloc[0]['Total Failures']
            last_val = owner_data.iloc[-1]['Total Failures']
            change = last_val - first_val
            pct_change = ((last_val - first_val) / first_val * 100) if first_val > 0 else 0
            trend = '↓' if change < 0 else ('↑' if change > 0 else '→')
        else:
            first_val = owner_data.iloc[0]['Total Failures'] if len(owner_data) > 0 else 0
            last_val = first_val
            change = 0
            pct_change = 0
            trend = '→'

        summary_data.append({
            'Owner': str(owner),
            'First Report': int(first_val),
            'Latest Report': int(last_val),
            'Change': int(change),
            '% Change': f"{pct_change:.1f}%",
            'Trend': trend
        })

    summary_df = pd.DataFrame(summary_data)

    # Stacked area chart for overall trend
    pivot_trend = trend_filtered.pivot_table(
        index='Report Date',
        columns='Owner',
        values='Total Failures',
        aggfunc='sum',
        fill_value=0
    ).reset_index()

    fig_area = go.Figure()
    for owner in top_owners:
        if owner in pivot_trend.columns:
            fig_area.add_trace(go.Scatter(
                x=pivot_trend['Report Date'],
                y=pivot_trend[owner],
                mode='lines',
                name=str(owner)[:20] + '...' if len(str(owner)) > 20 else str(owner),
                stackgroup='one',
                hovertemplate=f'{owner}<br>Failures: %{{y}}<extra></extra>'
            ))

    fig_area.update_layout(
        title='<b>Cumulative Failure Trend (Stacked Area)</b>',
        xaxis_title='Report Date',
        yaxis_title='Total Failures',
        height=400,
        hovermode='x unified',
        legend=dict(orientation='v', yanchor='top', y=1, xanchor='left', x=1.02)
    )

    return fig_trend, fig_area, summary_df


def create_downloadable_reports(df: pd.DataFrame, owner_stats: pd.DataFrame, group_by: str = 'Zones'):
    """
    Create downloadable CSV reports for offline analysis.

    Generates two reports:
    1. Owner Summary: High-level stats per owner
    2. Actionable Report: Detailed breakdown by owner/account/control

    Args:
        df: DataFrame containing failing control records
        owner_stats: DataFrame with aggregated owner statistics
        group_by: Column used for grouping

    Returns:
        tuple: (owner_export_df, actionable_report_df)
    """
    # Owner summary export
    owner_export = owner_stats.copy()
    owner_export['Related Items'] = owner_export['Related Items'].apply(lambda x: ', '.join(map(str, x)))

    # Actionable report
    action_report = []
    for owner in df[group_by].unique():
        owner_df = df[df[group_by] == owner]
        accounts = owner_df.groupby(['Account Name', 'Account Id']).size().reset_index(name='Failures')

        for _, acc in accounts.iterrows():
            acc_df = owner_df[(owner_df['Account Name'] == acc['Account Name']) &
                             (owner_df['Account Id'] == acc['Account Id'])]

            controls = acc_df.groupby(['Control Name', 'Control Severity', 'Control ID']).agg({
                'Resource Name': ['count', lambda x: ', '.join(x.unique()[:3])]
            }).reset_index()
            controls.columns = ['Control Name', 'Severity', 'Control ID', 'Count', 'Sample Resources']

            for _, ctrl in controls.iterrows():
                action_report.append({
                    'Owner': owner,
                    'Account Name': acc['Account Name'],
                    'Account Id': acc['Account Id'],
                    'Control Name': ctrl['Control Name'],
                    'Control ID': ctrl['Control ID'],
                    'Severity': ctrl['Severity'],
                    'Failure Count': ctrl['Count'],
                    'Sample Resources': ctrl['Sample Resources']
                })

    action_df = pd.DataFrame(action_report)

    return owner_export, action_df


# =============================================================================
# VULNERABILITY ANALYTICS CHART GENERATION
# =============================================================================


def create_vuln_executive_charts(df: pd.DataFrame):
    """
    Create executive dashboard charts for vulnerability analytics.

    Generates multiple visualizations for analyzing container image
    vulnerabilities from registry scans:
    - Top 5 most vulnerable images (stacked bar)
    - Severity distribution (donut chart)
    - Vulnerabilities by vendor
    - Severity breakdown by vendor
    - Priority patching list (Critical + High)
    - Vulnerability distribution histogram

    Args:
        df: Normalized DataFrame from normalize_image_data()

    Returns:
        dict: Chart figures keyed by name (e.g., 'fig_top5', 'fig_severity')
              Also includes aggregate stats: 'total_images', 'total_vulns', 'total_critical'
    """
    if df.empty:
        return {}

    total_images = len(df)
    total_vulns = int(df['total_vulns'].sum())
    total_critical = int(df['critical'].sum())

    charts = {
        "total_images": total_images,
        "total_vulns": total_vulns,
        "total_critical": total_critical,
    }

    # --- 1. Top 5 most vulnerable images (stacked horizontal bar) ---
    top5 = df.head(5).copy()
    top5_sorted = top5.sort_values('total_vulns', ascending=True)
    # Truncate long labels
    top5_sorted = top5_sorted.copy()
    top5_sorted['short_name'] = top5_sorted['display_name'].apply(lambda n: n[:35] + '...' if len(n) > 35 else n)

    fig_top5 = go.Figure()
    for sev in SEVERITY_ORDER:
        col = sev.lower()
        fig_top5.add_trace(go.Bar(
            y=top5_sorted['short_name'],
            x=top5_sorted[col],
            name=sev,
            orientation='h',
            marker_color=SEVERITY_COLORS[sev],
            text=top5_sorted[col],
            textposition='inside',
            hovertext=top5_sorted['display_name'],
            hoverinfo='text+x',
        ))
    fig_top5.update_layout(
        barmode='stack',
        title=dict(text='<b>Top 5 Most Vulnerable Images</b>', x=0.5, xanchor='center', font=dict(size=16)),
        height=500,
        margin=dict(t=60, b=80, l=40, r=40),
        xaxis=dict(title='Vulnerability Count'),
        yaxis=dict(type='category', automargin=True),
        legend=dict(orientation='h', yanchor='top', y=-0.25, xanchor='center', x=0.5),
        plot_bgcolor='#fafafa',
    )
    charts["fig_top5"] = fig_top5

    # --- 2. Severity distribution donut ---
    sev_totals = {s: int(df[s.lower()].sum()) for s in SEVERITY_ORDER}
    sev_labels = [s for s in SEVERITY_ORDER if sev_totals[s] > 0]
    sev_values = [sev_totals[s] for s in sev_labels]
    sev_colors = [SEVERITY_COLORS[s] for s in sev_labels]

    fig_sev = go.Figure(go.Pie(
        labels=sev_labels,
        values=sev_values,
        marker_colors=sev_colors,
        hole=0.45,
        textinfo='percent',
        textposition='inside',
        textfont=dict(color='white', size=12),
        sort=False,
    ))
    fig_sev.add_annotation(
        text=f"<b>{total_vulns:,}</b><br>Total", x=0.5, y=0.5, font_size=15, showarrow=False
    )
    fig_sev.update_layout(
        title=dict(text='<b>Vulnerability Severity Distribution</b>', x=0.5, xanchor='center', font=dict(size=16)),
        height=450,
        margin=dict(t=80, b=40, l=40, r=40),
        legend=dict(orientation='h', yanchor='bottom', y=-0.15, xanchor='center', x=0.5),
    )
    charts["fig_severity"] = fig_sev

    # --- 3. Vulnerability count by vendor ---
    vendor_vulns = df.groupby('vendor').agg(
        images=('vendor', 'size'),
        total_vulns=('total_vulns', 'sum'),
        critical=('critical', 'sum'),
        high=('high', 'sum'),
    ).reset_index().sort_values('total_vulns', ascending=False).head(10)

    if not vendor_vulns.empty:
        vendor_sorted = vendor_vulns.sort_values('total_vulns', ascending=True)
        fig_vendor = go.Figure(go.Bar(
            y=vendor_sorted['vendor'],
            x=vendor_sorted['total_vulns'],
            orientation='h',
            marker_color='#e67e22',
            text=[f"{v:,} ({i} images)" for v, i in zip(vendor_sorted['total_vulns'], vendor_sorted['images'])],
            textposition='inside',
            textfont=dict(color='white', size=12),
            insidetextanchor='end',
        ))
        fig_vendor.update_layout(
            title=dict(text='<b>Vulnerabilities by Registry Vendor</b>', x=0.5, xanchor='center', font=dict(size=16)),
            height=400,
            margin=dict(t=80, b=40, l=40, r=40),
            xaxis=dict(title='Total Vulnerabilities'),
            yaxis=dict(type='category', automargin=True),
            plot_bgcolor='#fafafa',
        )
        charts["fig_vendor"] = fig_vendor

    # --- 4. Severity breakdown per vendor (stacked bar) ---
    if not vendor_vulns.empty:
        top_vendors = vendor_vulns.head(8).sort_values('total_vulns', ascending=True)
        fig_vendor_sev = go.Figure()
        for sev in SEVERITY_ORDER:
            col = sev.lower()
            vendor_sev_data = df.groupby('vendor')[col].sum().reset_index()
            vendor_sev_data = vendor_sev_data[vendor_sev_data['vendor'].isin(top_vendors['vendor'])]
            # Re-sort to match
            vendor_sev_data = vendor_sev_data.set_index('vendor').loc[top_vendors['vendor']].reset_index()
            fig_vendor_sev.add_trace(go.Bar(
                y=vendor_sev_data['vendor'],
                x=vendor_sev_data[col],
                name=sev,
                orientation='h',
                marker_color=SEVERITY_COLORS[sev],
            ))
        fig_vendor_sev.update_layout(
            barmode='stack',
            title=dict(text='<b>Severity Breakdown by Vendor</b>', x=0.5, xanchor='center', font=dict(size=16)),
            height=450,
            margin=dict(t=60, b=80, l=40, r=40),
            xaxis=dict(title='Vulnerability Count'),
            yaxis=dict(type='category', automargin=True),
            legend=dict(orientation='h', yanchor='top', y=-0.25, xanchor='center', x=0.5),
            plot_bgcolor='#fafafa',
        )
        charts["fig_vendor_severity"] = fig_vendor_sev

    # --- 5. Images with most critical + high vulns (priority to patch) ---
    df_priority = df[['display_name', 'critical', 'high', 'pull_string']].copy()
    df_priority['crit_high'] = df_priority['critical'] + df_priority['high']
    df_priority = df_priority[df_priority['crit_high'] > 0].sort_values('crit_high', ascending=False).head(10)

    if not df_priority.empty:
        priority_sorted = df_priority.sort_values('crit_high', ascending=True).copy()
        priority_sorted['short_name'] = priority_sorted['display_name'].apply(lambda n: n[:35] + '...' if len(n) > 35 else n)
        fig_priority = go.Figure()
        fig_priority.add_trace(go.Bar(
            y=priority_sorted['short_name'],
            x=priority_sorted['critical'],
            name='Critical',
            orientation='h',
            marker_color=SEVERITY_COLORS['Critical'],
            hovertext=priority_sorted['display_name'],
            hoverinfo='text+x',
        ))
        fig_priority.add_trace(go.Bar(
            y=priority_sorted['short_name'],
            x=priority_sorted['high'],
            name='High',
            orientation='h',
            marker_color=SEVERITY_COLORS['High'],
            hovertext=priority_sorted['display_name'],
            hoverinfo='text+x',
        ))
        fig_priority.update_layout(
            barmode='stack',
            title=dict(text='<b>Top 10 Images to Patch (Critical + High)</b>', x=0.5, xanchor='center', font=dict(size=16)),
            height=550,
            margin=dict(t=60, b=80, l=40, r=40),
            xaxis=dict(title='Vulnerability Count'),
            yaxis=dict(type='category', automargin=True),
            legend=dict(orientation='h', yanchor='top', y=-0.15, xanchor='center', x=0.5),
            plot_bgcolor='#fafafa',
        )
        charts["fig_priority"] = fig_priority

    # --- 6. Vulnerability density histogram (vulns per image distribution) ---
    fig_hist = go.Figure(go.Histogram(
        x=df['total_vulns'],
        nbinsx=30,
        marker_color='#3498db',
    ))
    fig_hist.update_layout(
        title=dict(text='<b>Vulnerability Distribution Across Images</b>', x=0.5, xanchor='center', font=dict(size=16)),
        height=500,
        margin=dict(t=80, b=60, l=60, r=40),
        xaxis=dict(title='Vulnerabilities per Image'),
        yaxis=dict(title='Number of Images'),
        plot_bgcolor='#fafafa',
    )
    charts["fig_histogram"] = fig_hist

    return charts


def create_vuln_trend_charts(snapshots: list[tuple[str, pd.DataFrame]]):
    """
    Create trend charts comparing vulnerability data across multiple snapshots.

    Visualizes how vulnerability counts change over time to track
    remediation progress or identify new issues.

    Args:
        snapshots: List of (date_string, dataframe) tuples, sorted by date

    Returns:
        dict: Contains trend figures and summary DataFrame:
              - 'fig_total_trend': Total vulnerabilities over time
              - 'fig_severity_trend': Severity breakdown over time
              - 'fig_image_trend': Top 5 images tracked over time
              - 'summary_df': Change summary table
              Returns empty dict if fewer than 2 snapshots provided
    """
    if len(snapshots) < 2:
        return {}

    charts = {}

    # Aggregate totals per snapshot
    trend_rows = []
    for date_str, df in snapshots:
        row = {"date": date_str, "total_vulns": int(df['total_vulns'].sum()), "total_images": len(df)}
        for sev in SEVERITY_ORDER:
            row[sev] = int(df[sev.lower()].sum())
        row["fixable"] = int(df['total_fixable'].sum())
        row["exploitable_images"] = int((df['exploit_count'] > 0).sum())
        trend_rows.append(row)

    trend_df = pd.DataFrame(trend_rows).sort_values("date")

    # --- 1. Total vulnerabilities over time ---
    fig_total = go.Figure(go.Scatter(
        x=trend_df['date'], y=trend_df['total_vulns'],
        mode='lines+markers+text',
        text=trend_df['total_vulns'].apply(lambda v: f"{v:,}"),
        textposition='top center',
        line=dict(color='#e74c3c', width=3),
        marker=dict(size=10),
    ))
    fig_total.update_layout(
        title=dict(text='<b>Total Vulnerabilities Over Time</b>', x=0.5, xanchor='center', font=dict(size=16)),
        height=400,
        xaxis=dict(title='Snapshot Date'),
        yaxis=dict(title='Total Vulnerabilities'),
        plot_bgcolor='#fafafa',
    )
    charts["fig_total_trend"] = fig_total

    # --- 2. Severity breakdown over time (stacked area) ---
    fig_sev_trend = go.Figure()
    for sev in reversed(SEVERITY_ORDER):
        fig_sev_trend.add_trace(go.Scatter(
            x=trend_df['date'], y=trend_df[sev],
            name=sev, mode='lines',
            stackgroup='one',
            line=dict(color=SEVERITY_COLORS[sev]),
        ))
    fig_sev_trend.update_layout(
        title=dict(text='<b>Severity Breakdown Over Time</b>', x=0.5, xanchor='center', font=dict(size=16)),
        height=400,
        xaxis=dict(title='Snapshot Date'),
        yaxis=dict(title='Vulnerability Count'),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1),
        hovermode='x unified',
        plot_bgcolor='#fafafa',
    )
    charts["fig_severity_trend"] = fig_sev_trend

    # --- 3. Top 5 images tracked over time ---
    # Use images from the latest snapshot
    latest_df = snapshots[-1][1]
    top5_names = latest_df.head(5)['display_name'].tolist()

    fig_img_trend = go.Figure()
    for img_name in top5_names:
        img_vals = []
        for date_str, df in snapshots:
            match = df[df['display_name'] == img_name]
            img_vals.append(int(match['total_vulns'].sum()) if not match.empty else 0)
        fig_img_trend.add_trace(go.Scatter(
            x=trend_df['date'].tolist(), y=img_vals,
            mode='lines+markers',
            name=img_name[:30],
        ))
    fig_img_trend.update_layout(
        title=dict(text='<b>Top 5 Images - Vulnerability Trend</b>', x=0.5, xanchor='center', font=dict(size=16)),
        height=400,
        xaxis=dict(title='Snapshot Date'),
        yaxis=dict(title='Total Vulnerabilities'),
        legend=dict(orientation='v', yanchor='top', y=1, xanchor='left', x=1.02),
        hovermode='x unified',
        plot_bgcolor='#fafafa',
    )
    charts["fig_image_trend"] = fig_img_trend

    # --- 4. Summary table with change indicators ---
    if len(trend_df) >= 2:
        first = trend_df.iloc[0]
        last = trend_df.iloc[-1]
        summary_rows = []
        for sev in SEVERITY_ORDER:
            f_val = int(first[sev])
            l_val = int(last[sev])
            change = l_val - f_val
            pct = ((change / f_val) * 100) if f_val > 0 else 0
            trend = "Improving" if change < 0 else ("Worsening" if change > 0 else "Stable")
            arrow = "v" if change < 0 else ("^" if change > 0 else "-")
            summary_rows.append({
                "Severity": sev,
                "First Snapshot": f_val,
                "Latest Snapshot": l_val,
                "Change": change,
                "% Change": f"{pct:+.1f}%",
                "Trend": arrow,
            })
        charts["summary_df"] = pd.DataFrame(summary_rows)

    return charts


# =============================================================================
# VULNERABILITY DASHBOARD UI CONFIGURATION
# =============================================================================

# Default widget display order for the vulnerability dashboard
DEFAULT_VULN_WIDGET_ORDER = [
    "Top 5 Most Vulnerable Images",
    "Severity Distribution",
    "Vulnerabilities by Vendor",
    "Severity Breakdown by Vendor",
    "Top 10 Images to Patch",
    "Vulnerability Distribution",
]

DEFAULT_VULN_WIDGET_WIDTHS = {name: "half" for name in DEFAULT_VULN_WIDGET_ORDER}

# Map widget names to chart keys returned by create_vuln_executive_charts
WIDGET_CHART_KEYS = {
    "Top 5 Most Vulnerable Images": "fig_top5",
    "Severity Distribution": "fig_severity",
    "Vulnerabilities by Vendor": "fig_vendor",
    "Severity Breakdown by Vendor": "fig_vendor_severity",
    "Top 10 Images to Patch": "fig_priority",
    "Vulnerability Distribution": "fig_histogram",
}


def _init_vuln_layout_state():
    """Initialize session state for dashboard layout if not already set."""
    if "vuln_widget_order" not in st.session_state:
        st.session_state.vuln_widget_order = list(DEFAULT_VULN_WIDGET_ORDER)
    if "vuln_widget_widths" not in st.session_state:
        st.session_state.vuln_widget_widths = dict(DEFAULT_VULN_WIDGET_WIDTHS)
    if "vuln_widget_visible" not in st.session_state:
        st.session_state.vuln_widget_visible = set(DEFAULT_VULN_WIDGET_ORDER)


def _render_dashboard_widgets(charts: dict):
    """Render widgets in user-configured order and width."""
    order = st.session_state.vuln_widget_order
    widths = st.session_state.vuln_widget_widths
    visible = st.session_state.vuln_widget_visible

    half_buffer = []  # (name, fig) pairs waiting for a column partner

    def _flush_half_buffer():
        nonlocal half_buffer
        if not half_buffer:
            return
        if len(half_buffer) == 1:
            name, fig = half_buffer[0]
            col1, col2 = st.columns(2)
            with col1:
                with st.expander(name, expanded=True):
                    st.plotly_chart(fig, use_container_width=True)
        else:
            col1, col2 = st.columns(2)
            with col1:
                with st.expander(half_buffer[0][0], expanded=True):
                    st.plotly_chart(half_buffer[0][1], use_container_width=True)
            with col2:
                with st.expander(half_buffer[1][0], expanded=True):
                    st.plotly_chart(half_buffer[1][1], use_container_width=True)
        half_buffer = []

    for widget_name in order:
        if widget_name not in visible:
            continue

        chart_key = WIDGET_CHART_KEYS.get(widget_name)
        if not chart_key or chart_key not in charts:
            continue

        fig = charts[chart_key]
        width = widths.get(widget_name, "half")

        if width == "full":
            _flush_half_buffer()
            with st.expander(widget_name, expanded=True):
                st.plotly_chart(fig, use_container_width=True)
        else:
            half_buffer.append((widget_name, fig))
            if len(half_buffer) == 2:
                _flush_half_buffer()

    _flush_half_buffer()


# =============================================================================
# PAGE RENDERING FUNCTIONS
# =============================================================================


def vuln_analytics_page():
    """
    Render the Vulnerability Analytics page.

    This page provides:
    - API integration to fetch registry scan results from Sysdig
    - Interactive dashboard with customizable widget layouts
    - Trend analysis when multiple snapshots are available
    - Data explorer for searching and filtering images
    - Export functionality for CSV and JSON formats
    """
    st.title("Registry Vulnerability Analytics")
    st.markdown("Fetch and analyze container image vulnerabilities from the Sysdig registry scanner.")

    _init_vuln_layout_state()
    api_token = os.environ.get("SYSDIG_API_TOKEN", "")

    # --- Sidebar controls ---
    with st.sidebar:
        st.header("Vulnerability Scanner")

        if api_token:
            st.success("API token found (SYSDIG_API_TOKEN)")
        else:
            st.error("SYSDIG_API_TOKEN env var not set")
            st.markdown("Set it before launching:\n```\nexport SYSDIG_API_TOKEN=your_token\n```")

        st.markdown("---")
        query_freq = st.selectbox(
            "Recommended query frequency",
            options=["Daily", "Weekly"],
            index=1,
            help="How often you plan to fetch fresh data. This is informational only.",
        )

        fetch_clicked = st.button(
            "Fetch Latest Data",
            disabled=not api_token,
            help="Query the Sysdig API and save results locally",
            type="primary",
        )

        st.markdown("---")
        st.subheader("Saved Snapshots")
        snapshots = list_saved_snapshots()
        if snapshots:
            st.markdown(f"**{len(snapshots)}** snapshot(s) in `~/sysdig-vuln-data/`")
            for s in snapshots[:5]:
                st.text(f"  {s['filename'][:35]}  ({s['total_images']} imgs)")
        else:
            st.markdown("No snapshots saved yet. Click **Fetch Latest Data** to start.")

        st.markdown("---")
        st.subheader("Upload Snapshots for Trends")
        uploaded_snapshots = st.file_uploader(
            "Upload saved JSON snapshots",
            type=["json"],
            accept_multiple_files=True,
            help="Upload previously downloaded snapshot JSONs to compare over time.",
            key="vuln_uploader",
        )

        # --- Dashboard layout controls ---
        st.markdown("---")
        st.subheader("Dashboard Layout")

        st.caption("Drag to reorder widgets:")
        new_order = sort_items(
            st.session_state.vuln_widget_order,
            direction="vertical",
            key="vuln_sort",
        )
        if new_order != st.session_state.vuln_widget_order:
            st.session_state.vuln_widget_order = new_order
            st.rerun()

        st.markdown("---")
        st.caption("Show / hide widgets:")
        visible_selection = st.multiselect(
            "Visible widgets",
            options=st.session_state.vuln_widget_order,
            default=list(st.session_state.vuln_widget_visible),
            key="vuln_visible_select",
            label_visibility="collapsed",
        )
        st.session_state.vuln_widget_visible = set(visible_selection)

        st.markdown("---")
        st.caption("Widget width:")
        for wname in st.session_state.vuln_widget_order:
            if wname not in st.session_state.vuln_widget_visible:
                continue
            current = st.session_state.vuln_widget_widths.get(wname, "half")
            is_full = st.toggle(
                f"{wname}",
                value=(current == "full"),
                key=f"width_{wname}",
                help="Toggle full width",
            )
            st.session_state.vuln_widget_widths[wname] = "full" if is_full else "half"

        st.markdown("---")
        if st.button("Reset Layout", key="reset_layout"):
            st.session_state.vuln_widget_order = list(DEFAULT_VULN_WIDGET_ORDER)
            st.session_state.vuln_widget_widths = dict(DEFAULT_VULN_WIDGET_WIDTHS)
            st.session_state.vuln_widget_visible = set(DEFAULT_VULN_WIDGET_ORDER)
            st.rerun()

    # --- Handle fetch ---
    if fetch_clicked and api_token:
        with st.spinner("Fetching registry results from Sysdig API (this may take a moment)..."):
            try:
                results = fetch_registry_results(api_token)
                filepath = save_results_to_disk(results)
                st.success(f"Fetched **{len(results)}** images. Saved to `{filepath.name}`")
                st.rerun()
            except requests.HTTPError as e:
                st.error(f"API error: {e.response.status_code} - {e.response.text[:300]}")
                return
            except Exception as e:
                st.error(f"Error fetching data: {e}")
                return

    # --- Determine data sources ---
    # Collect all available snapshots: local files + uploaded files
    all_snapshots = []  # list of (date_str, df)

    # Load from local saved files
    for s in snapshots:
        try:
            data, fetched_at = load_snapshot(s["path"])
            df = normalize_image_data(data)
            if not df.empty:
                all_snapshots.append((fetched_at, df))
        except Exception:
            continue

    # Load from uploaded files
    if uploaded_snapshots:
        for uf in uploaded_snapshots:
            try:
                data, fetched_at = load_snapshot(uf)
                df = normalize_image_data(data)
                if not df.empty:
                    all_snapshots.append((fetched_at, df))
            except Exception:
                continue

    # Deduplicate by date string and sort
    seen_dates = set()
    unique_snapshots = []
    for date_str, df in all_snapshots:
        if date_str not in seen_dates:
            seen_dates.add(date_str)
            unique_snapshots.append((date_str, df))
    all_snapshots = sorted(unique_snapshots, key=lambda x: x[0])

    if not all_snapshots:
        st.info("No data available. Use **Fetch Latest Data** in the sidebar to query the Sysdig API, or upload saved JSON snapshots.")
        return

    # Use the most recent snapshot for the dashboard
    latest_date, latest_df = all_snapshots[-1]
    has_trends = len(all_snapshots) >= 2

    # --- Build tabs ---
    if has_trends:
        tab_dash, tab_trend, tab_explore, tab_dl = st.tabs(
            ["Dashboard", "Trend Analysis", "Data Explorer", "Download"]
        )
    else:
        tab_dash, tab_explore, tab_dl = st.tabs(
            ["Dashboard", "Data Explorer", "Download"]
        )

    # === Dashboard tab ===
    with tab_dash:
        charts = create_vuln_executive_charts(latest_df)
        if not charts:
            st.warning("No vulnerability data to display.")
            return

        st.markdown(f"*Snapshot: {latest_date}*")

        # KPI row (always pinned at top)
        c1, c2, c3, c4, c5 = st.columns(5)
        total_high = int(latest_df['high'].sum())
        total_med = int(latest_df['medium'].sum())

        c1.metric("Images Scanned", f"{charts['total_images']:,}")
        c2.metric("Total Vulns", f"{charts['total_vulns']:,}")
        c3.metric("Critical", f"{charts['total_critical']:,}")
        c4.metric("High", f"{total_high:,}")
        c5.metric("Medium", f"{total_med:,}")

        st.markdown("---")

        # Customizable widget area
        _render_dashboard_widgets(charts)

    # === Trend Analysis tab ===
    if has_trends:
        with tab_trend:
            st.markdown(f"### Vulnerability Trends ({len(all_snapshots)} snapshots)")
            trend_charts = create_vuln_trend_charts(all_snapshots)

            if "fig_total_trend" in trend_charts:
                st.plotly_chart(trend_charts["fig_total_trend"], use_container_width=True)

            if "summary_df" in trend_charts:
                st.markdown("---")
                st.markdown("### Change Summary")

                def color_trend(val):
                    if val == 'v':
                        return 'color: green; font-weight: bold'
                    elif val == '^':
                        return 'color: red; font-weight: bold'
                    return ''

                st.dataframe(
                    trend_charts["summary_df"].style.applymap(color_trend, subset=['Trend']),
                    use_container_width=True, hide_index=True,
                )

            if "fig_severity_trend" in trend_charts:
                st.markdown("---")
                st.plotly_chart(trend_charts["fig_severity_trend"], use_container_width=True)

            if "fig_image_trend" in trend_charts:
                st.markdown("---")
                st.plotly_chart(trend_charts["fig_image_trend"], use_container_width=True)

    # === Data Explorer tab ===
    with tab_explore:
        st.markdown("### All Scanned Images")
        st.markdown(f"*{len(latest_df)} images from snapshot {latest_date}*")

        # Search filter
        search = st.text_input("Search images", placeholder="Filter by name, vendor, or pull string...")
        display_df = latest_df.copy()
        if search:
            mask = (
                display_df['display_name'].str.contains(search, case=False, na=False) |
                display_df['vendor'].str.contains(search, case=False, na=False) |
                display_df['pull_string'].str.contains(search, case=False, na=False)
            )
            display_df = display_df[mask]

        show_cols = ['display_name', 'vendor', 'critical', 'high', 'medium', 'low',
                     'negligible', 'total_vulns', 'created_at']
        st.dataframe(
            display_df[show_cols].rename(columns={
                'display_name': 'Image', 'vendor': 'Vendor',
                'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low',
                'negligible': 'Negligible', 'total_vulns': 'Total',
                'created_at': 'Scanned At',
            }),
            use_container_width=True, hide_index=True, height=600,
        )

    # === Download tab ===
    with tab_dl:
        st.markdown("### Export Data")

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Image Summary CSV")
            csv_data = latest_df.to_csv(index=False)
            st.download_button(
                label="Download Image Summary",
                data=csv_data,
                file_name=f"vuln_image_summary_{latest_date[:10]}.csv",
                mime="text/csv",
            )

        with col2:
            st.markdown("#### Raw JSON Snapshot")
            # Re-read the latest local snapshot if available
            if snapshots:
                raw = Path(snapshots[0]["path"]).read_text()
                st.download_button(
                    label="Download Latest JSON Snapshot",
                    data=raw,
                    file_name=snapshots[0]["filename"],
                    mime="application/json",
                )
            else:
                st.info("Fetch data first to enable JSON download.")


def posture_analytics_page():
    """
    Render the Posture Analytics page for compliance report analysis.

    This page provides:
    - CSV file upload for posture compliance reports
    - Executive dashboard showing top contributors to failures
    - Security drill-down with treemap and heatmap views
    - Trend analysis when multiple reports are uploaded
    - Downloadable CSV reports for offline use
    """
    st.title("Sysdig Posture Report Analytics")
    st.markdown("Upload your posture report CSV to generate executive and security dashboards.")

    # Sidebar for file upload
    with st.sidebar:
        st.header("Upload Data")
        st.markdown("**Drag & drop multiple files** to see trends over time")
        uploaded_files = st.file_uploader(
            "Choose CSV files",
            type=['csv', 'gz', 'zip'],
            accept_multiple_files=True,
            help="Upload one or more CSV/gzipped CSV/zip files. Multiple files enable trend analysis."
        )

        if uploaded_files:
            st.success(f"Loaded {len(uploaded_files)} file(s)")
            with st.expander("View uploaded files"):
                for f in uploaded_files:
                    date = extract_date_from_filename(f.name)
                    st.text(f"  {f.name[:40]}... ({date.strftime('%Y-%m-%d')})")

        st.header("Grouping Options")
        group_by = st.selectbox(
            "Group failures by",
            options=['Zones', 'Account Id'],
            index=0,
            help="Select how to group failures: by Zones (owner) or by Account Id"
        )

    if not uploaded_files:
        st.info("Please upload CSV file(s) using the sidebar to get started.")

        st.markdown("---")
        st.markdown("### How to use")
        st.markdown("""
        1. Export your posture report(s) from Sysdig as CSV
        2. **Drag & drop** one or more files into the upload area
        3. View the generated dashboards below
        4. **Upload multiple reports** from different dates to see failure trends over time
        5. Download summary reports as needed
        """)
        return

    # Determine if we have multiple files for trend analysis
    has_multiple_files = len(uploaded_files) > 1

    # Use the most recent file for single-file analysis
    sorted_files = sorted(uploaded_files, key=lambda f: extract_date_from_filename(f.name), reverse=True)
    latest_file = sorted_files[0]

    # Load and process data for the latest file
    with st.spinner("Loading and processing data..."):
        try:
            df_full, df = load_data(latest_file)
            if has_multiple_files:
                for f in uploaded_files:
                    f.seek(0)
                trend_data = load_multiple_files(uploaded_files, group_by)
        except Exception as e:
            st.error(f"Error loading file: {e}")
            return

    # Display metrics
    st.markdown("---")
    fig_pie, fig_bar, total_failures, unique_owners, unique_accounts, top_owners, owner_stats = create_executive_charts(df, group_by)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Failures", f"{total_failures:,}")
    group_label = "Unique Zones" if group_by == 'Zones' else "Unique Accounts"
    col2.metric(group_label, f"{unique_owners}")
    col3.metric("Total Accounts", f"{unique_accounts}")
    col4.metric("Reports Loaded", f"{len(uploaded_files)}")

    # Tabs for different views
    if has_multiple_files:
        tab1, tab2, tab3, tab4 = st.tabs(["Trend Analysis", "Executive Dashboard", "Security Drill-Down", "Download Reports"])
    else:
        tab1, tab2, tab3 = st.tabs(["Executive Dashboard", "Security Drill-Down", "Download Reports"])

    if has_multiple_files:
        with tab1:
            st.markdown("### Failure Trend Analysis")
            st.markdown(f"Analyzing **{len(uploaded_files)} reports** to track failures over time.")

            fig_trend, fig_area, summary_df = create_trend_charts(trend_data)

            if fig_trend:
                st.plotly_chart(fig_trend, use_container_width=True)

                st.markdown("---")
                st.markdown("### Progress Summary")
                st.markdown("**Goal:** See failure counts decrease over time (negative change = improvement)")

                def highlight_trend(val):
                    if val == '↓':
                        return 'color: green; font-weight: bold'
                    elif val == '↑':
                        return 'color: red; font-weight: bold'
                    return ''

                st.dataframe(
                    summary_df.style.applymap(highlight_trend, subset=['Trend']),
                    use_container_width=True,
                    hide_index=True
                )

                st.markdown("---")
                st.markdown("### Cumulative View")
                st.plotly_chart(fig_area, use_container_width=True)

        exec_tab = tab2
        security_tab = tab3
        download_tab = tab4
    else:
        exec_tab = tab1
        security_tab = tab2
        download_tab = tab3

    with exec_tab:
        st.markdown("### Executive Summary: Who Should We Engage First?")
        st.markdown(f"*Showing data from: {latest_file.name}*")

        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(fig_pie, use_container_width=True)
        with col2:
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("---")
        st.markdown("### Top 5 Contributors - What Controls to Fix First")

        st.markdown("""
        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <span><span style="background:#e74c3c; padding: 2px 10px; border-radius: 4px; color: white;">High</span></span>
            <span><span style="background:#f39c12; padding: 2px 10px; border-radius: 4px; color: white;">Medium</span></span>
            <span><span style="background:#3498db; padding: 2px 10px; border-radius: 4px; color: white;">Low</span></span>
            <span><span style="background:#95a5a6; padding: 2px 10px; border-radius: 4px; color: white;">Info</span></span>
        </div>
        """, unsafe_allow_html=True)

        person_charts = create_person_charts(df, top_owners, group_by)

        cols = st.columns(2)
        for i, (owner, fig) in enumerate(person_charts):
            with cols[i % 2]:
                st.plotly_chart(fig, use_container_width=True)

    with security_tab:
        st.markdown("### Security Posture Drill-Down")

        fig_treemap, fig_heatmap, fig_severity = create_security_charts(df, group_by)

        st.plotly_chart(fig_treemap, use_container_width=True)

        st.markdown("---")
        st.markdown("### Owner vs Control Failure Matrix")
        st.plotly_chart(fig_heatmap, use_container_width=True)

        st.markdown("---")
        st.markdown("### Severity Breakdown by Owner")
        st.plotly_chart(fig_severity, use_container_width=True)

    with download_tab:
        st.markdown("### Download Reports")

        owner_export, action_df = create_downloadable_reports(df, owner_stats, group_by)

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("#### Owner Summary")
            st.dataframe(owner_export.head(10), use_container_width=True)
            csv1 = owner_export.to_csv(index=False)
            st.download_button(
                label="Download Owner Summary CSV",
                data=csv1,
                file_name="owner_summary.csv",
                mime="text/csv"
            )

        with col2:
            st.markdown("#### Actionable Report")
            st.dataframe(action_df.head(10), use_container_width=True)
            csv2 = action_df.to_csv(index=False)
            st.download_button(
                label="Download Actionable Report CSV",
                data=csv2,
                file_name="actionable_report.csv",
                mime="text/csv"
            )



# =============================================================================
# CVE RISK DASHBOARD — API & CHART HELPERS
# =============================================================================


def _cve_headers(token: str) -> dict:
    return {
        "Authorization":    f"Bearer {token}",
        "Accept":           "application/json",
        "X-Sysdig-Product": "SDS",
    }


def _fetch_top_cves(base: str, token: str) -> list:
    """Paginate /by-cve; collect items with EPSS >= threshold."""
    hdrs   = _cve_headers(token)
    params = {"severity_in": "critical,high,medium", "limit": 200}
    qualifying = []
    while True:
        r = requests.get(f"{base}{CVE_BY_CVE_PATH}", headers=hdrs,
                         params=params, timeout=CVE_API_TIMEOUT)
        r.raise_for_status()
        payload = r.json()
        for item in payload.get("data", []):
            if float(item.get("epssScore") or 0) >= CVE_EPSS_THRESHOLD:
                qualifying.append(item)
        meta   = payload.get("meta") or {}
        cursor = payload.get("cursor") or {}
        if (len(qualifying) >= CVE_TOP_N
                or not meta.get("hasMore")
                or not cursor.get("next")):
            break
        params = {**params, "cursor": cursor["next"]}
    qualifying.sort(key=lambda x: float(x.get("epssScore") or 0), reverse=True)
    return qualifying[:CVE_TOP_N]


def _normalize_cve(item: dict) -> dict:
    epss        = float(item.get("epssScore") or 0)
    cvss        = float(item.get("cvssScore") or 0)
    exploitable = bool(item.get("hasExploit"))
    kev         = bool(item.get("hasCisaKev"))
    risk_score  = round(epss * 40 + (cvss / 10) * 30 + exploitable * 20 + kev * 10, 1)
    return {
        "cveId":         item.get("name", "Unknown"),
        "severity":      (item.get("severity") or "Unknown").capitalize(),
        "epssScore":     epss,
        "cvssScore":     cvss,
        "fixAvailable":  bool(item.get("isFixAvailable")),
        "exploitable":   exploitable,
        "hasCisaKev":    kev,
        "findingsCount": int(item.get("findingsCount") or 0),
        "inUse":         bool(item.get("inUse") or item.get("isInUse") or False),
        "riskScore":     risk_score,
    }


def _load_cves_with_progress(base: str, token: str, status_ctx) -> tuple:
    status_ctx.write(
        f"**Querying Findings API** — top CVEs with EPSS > "
        f"{CVE_EPSS_THRESHOLD*100:.0f}% (critical/high/medium)…"
    )
    items = _fetch_top_cves(base, token)
    if not items:
        return [], [f"No CVEs with EPSS > {CVE_EPSS_THRESHOLD*100:.0f}% found."]
    normalised = [_normalize_cve(it) for it in items]
    in_use  = sum(1 for c in normalised if c["inUse"])
    not_use = sum(1 for c in normalised if not c["inUse"])
    status_ctx.write(
        f"  ✓ **{len(normalised)}** CVE(s) — "
        f"**{in_use}** in-use · **{not_use}** not-in-use"
    )
    return normalised, []


def _cve_chart_severity_donut(df) -> go.Figure:
    counts = df["severity"].value_counts().reset_index()
    counts.columns = ["severity", "count"]
    colors = [CVE_SEVERITY_COLOR.get(s, "#78909C") for s in counts["severity"]]
    fig = go.Figure(go.Pie(
        labels=counts["severity"], values=counts["count"],
        marker=dict(colors=colors, line=dict(width=2, color="#12161f")),
        hole=0.55, textinfo="label+value", textfont=dict(size=12),
        hovertemplate="%{label}: %{value} CVEs (%{percent})<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=300, showlegend=False)
    return fig


def _cve_chart_fix_donut(df) -> go.Figure:
    fix_yes = int(df["fixAvailable"].sum())
    fix_no  = len(df) - fix_yes
    fig = go.Figure(go.Pie(
        labels=["Fix Available", "No Fix Yet"], values=[fix_yes, fix_no],
        marker=dict(colors=["#00C853", "#E53935"], line=dict(width=2, color="#12161f")),
        hole=0.55, textinfo="label+value", textfont=dict(size=12),
        hovertemplate="%{label}: %{value} CVEs (%{percent})<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=300, showlegend=False)
    return fig


def _cve_chart_epss_dist(df) -> go.Figure:
    bins   = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    labels = ["50-60%", "60-70%", "70-80%", "80-90%", "90-100%"]
    df2 = df.copy()
    df2["epss_bucket"] = pd.cut(df2["epssScore"], bins=bins,
                                labels=labels, include_lowest=True)
    counts = (
        df2.groupby(["epss_bucket", "severity"], observed=True)
        .size().reset_index(name="count")
    )
    sev_order = ["Critical", "High", "Medium", "Low", "Negligible"]
    counts["severity"] = pd.Categorical(counts["severity"],
                                        categories=sev_order, ordered=True)
    counts = counts.sort_values(["epss_bucket", "severity"])
    fig = px.bar(
        counts, x="epss_bucket", y="count", color="severity",
        color_discrete_map=CVE_SEVERITY_COLOR, barmode="stack",
        labels={"epss_bucket": "EPSS Range", "count": "CVE Count", "severity": "Severity"},
    )
    fig.update_layout(**PLOTLY_LAYOUT, height=300,
                      xaxis=dict(gridcolor="#1e2d3d"),
                      yaxis=dict(gridcolor="#1e2d3d", title="CVE Count"),
                      legend=dict(orientation="h", yanchor="bottom",
                                  y=1.02, xanchor="right", x=1))
    return fig


def _cve_chart_key_flags(df) -> go.Figure:
    cats   = ["Exploitable", "CISA KEV", "Has Fix"]
    values = [int(df["exploitable"].sum()),
              int(df["hasCisaKev"].sum()),
              int(df["fixAvailable"].sum())]
    fig = go.Figure(go.Bar(
        x=cats, y=values,
        marker=dict(color=["#E53935", "#9B3FBF", "#00C853"], line=dict(width=0)),
        text=values, textposition="outside",
        hovertemplate="%{x}: %{y} CVEs<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=300,
                      yaxis=dict(gridcolor="#1e2d3d", title="CVE Count"),
                      xaxis=dict(gridcolor="#1e2d3d"), showlegend=False)
    return fig


def _cve_render_section(cves: list, label: str, header_class: str) -> None:
    st.markdown(f'''<div class="section-hdr {header_class}">{label}</div>''',
                unsafe_allow_html=True)
    if not cves:
        st.info("No CVEs in this category.")
        return
    df = pd.DataFrame(cves)
    for _col, _default in [("exploitable", False), ("hasCisaKev", False),
                            ("fixAvailable", False), ("cvssScore", 0.0),
                            ("epssScore", 0.0)]:
        if _col not in df.columns:
            df[_col] = _default
    total       = len(df)
    avg_epss    = df["epssScore"].mean() * 100
    exploitable = int(df["exploitable"].sum())
    kev         = int(df["hasCisaKev"].sum())
    fixable     = int(df["fixAvailable"].sum())
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("CVEs",        total)
    c2.metric("Avg EPSS",   f"{avg_epss:.1f}%")
    c3.metric("Exploitable", exploitable, "known exploits")
    c4.metric("CISA KEV",    kev,         "actively exploited")
    c5.metric("Has Fix",     fixable,     f"{fixable/total*100:.0f}% fixable")
    st.markdown("<br>", unsafe_allow_html=True)
    r1c1, r1c2 = st.columns(2)
    with r1c1:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;"
            "margin-bottom:4px'>Severity Breakdown</div>", unsafe_allow_html=True)
        st.plotly_chart(_cve_chart_severity_donut(df), use_container_width=True,
                        config={"displayModeBar": False})
    with r1c2:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;"
            "margin-bottom:4px'>CVEs by EPSS Range &amp; Severity</div>",
            unsafe_allow_html=True)
        st.plotly_chart(_cve_chart_epss_dist(df), use_container_width=True,
                        config={"displayModeBar": False})
    r2c1, r2c2 = st.columns(2)
    with r2c1:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;"
            "margin-bottom:4px'>Fix Availability</div>", unsafe_allow_html=True)
        st.plotly_chart(_cve_chart_fix_donut(df), use_container_width=True,
                        config={"displayModeBar": False})
    with r2c2:
        st.markdown(
            "<div style='text-align:center;color:#90a4ae;font-size:.83rem;"
            "margin-bottom:4px'>Key Risk Flags</div>", unsafe_allow_html=True)
        st.plotly_chart(_cve_chart_key_flags(df), use_container_width=True,
                        config={"displayModeBar": False})


def _rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha:.2f})"


def _t2_hbar(items: dict, x_label: str, color: str) -> go.Figure:
    df = pd.DataFrame(sorted(items.items(), key=lambda x: x[1]),
                      columns=["Label", "Value"])
    fig = go.Figure(go.Bar(
        x=df["Value"], y=df["Label"], orientation="h",
        marker=dict(color=color, line=dict(width=0)),
        text=df["Value"], textposition="outside",
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT,
                      height=max(200, len(items) * 38 + 60),
                      xaxis=dict(title=x_label, gridcolor="#1e2d3d"),
                      yaxis=dict(showgrid=False))
    return fig


def _eng_load(path_or_file) -> pd.DataFrame:
    df = pd.read_csv(path_or_file)
    missing = EXPECTED_COLS - set(df.columns)
    if missing:
        raise ValueError(f"CSV is missing columns: {', '.join(sorted(missing))}")
    df["findings"] = pd.to_numeric(df["findings"], errors="coerce").fillna(0).astype(int)
    df["imageLabel"] = df["imageRepository"].str.split("/").str[-1] + ":" + df["imageTag"]
    return df


def _eng_image_summary(df) -> pd.DataFrame:
    agg = (
        df.groupby(["imageRegistry", "imageRepository", "imageTag",
                    "imageReference", "imageLabel"])
        .agg(workloads      =("resourceName",  "nunique"),
             clusters       =("clusterName",   "nunique"),
             namespaces     =("namespaceName", "nunique"),
             total_findings =("findings",      "sum"),
             cluster_list   =("clusterName",   lambda x: ", ".join(sorted(x.unique()))),
             ns_list        =("namespaceName", lambda x: ", ".join(sorted(x.unique()))))
        .reset_index()
        .sort_values("total_findings", ascending=False)
        .reset_index(drop=True)
    )
    agg.insert(0, "Priority", range(1, len(agg) + 1))
    return agg


def _eng_repo_summary(df) -> pd.DataFrame:
    return (
        df.groupby("imageRepository")
        .agg(unique_tags    =("imageTag",      "nunique"),
             workloads      =("resourceName",  "nunique"),
             clusters       =("clusterName",   "nunique"),
             total_findings =("findings",      "sum"),
             tags           =("imageTag",      lambda x: ", ".join(sorted(x.unique()))))
        .reset_index()
        .sort_values("total_findings", ascending=False)
        .reset_index(drop=True)
    )


def _eng_top_images_bar(img_df, n: int = 25) -> go.Figure:
    top = img_df.head(n).sort_values("total_findings")
    fig = go.Figure(go.Bar(
        x=top["total_findings"], y=top["imageLabel"], orientation="h",
        marker=dict(color="#E53935", line=dict(width=0)),
        text=top["total_findings"], textposition="outside",
        customdata=top[["workloads", "clusters", "imageReference"]].values,
        hovertemplate=(
            "<b>%{y}</b><br>Total findings: %{x}<br>"
            "Workloads: %{customdata[0]}<br>Clusters: %{customdata[1]}<br>"
            "<i>%{customdata[2]}</i><extra></extra>"
        ),
    ))
    fig.update_layout(**PLOTLY_LAYOUT,
                      height=max(320, len(top) * 30 + 60),
                      xaxis=dict(title="Total Findings", gridcolor="#1e2d3d"),
                      yaxis=dict(showgrid=False, tickfont=dict(size=10)))
    return fig


def _eng_cluster_bar(df) -> go.Figure:
    counts = (
        df.groupby("clusterName")["resourceName"].nunique()
        .reset_index().rename(columns={"resourceName": "workloads"})
        .sort_values("workloads")
    )
    fig = go.Figure(go.Bar(
        x=counts["workloads"], y=counts["clusterName"], orientation="h",
        marker=dict(color="#9B3FBF", line=dict(width=0)),
        text=counts["workloads"], textposition="outside",
        hovertemplate="%{y}: %{x} affected workloads<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT,
                      height=max(260, len(counts) * 32 + 60),
                      xaxis=dict(title="Affected Workloads", gridcolor="#1e2d3d"),
                      yaxis=dict(showgrid=False))
    return fig


def _eng_registry_donut(df) -> go.Figure:
    counts = df.groupby("imageRegistry")["imageReference"].nunique().reset_index()
    counts.columns = ["registry", "images"]
    palette = ["#00BFA5", "#E53935", "#9B3FBF", "#FB8C00",
               "#1E88E5", "#00C853", "#FF6F00", "#7C4DFF"]
    fig = go.Figure(go.Pie(
        labels=counts["registry"], values=counts["images"],
        marker=dict(colors=[palette[i % len(palette)] for i in range(len(counts))],
                    line=dict(width=2, color="#12161f")),
        hole=0.55, textinfo="label+value", textfont=dict(size=10),
        hovertemplate="%{label}<br>%{value} unique images (%{percent})<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=320, showlegend=False,
                      title=dict(text="Unique vulnerable images by registry",
                                 font=dict(size=12, color="#90a4ae"), x=0.5))
    return fig


def _eng_cluster_image_heatmap(df, top_n: int = 30) -> go.Figure:
    top_labels = (
        df.groupby("imageLabel")["findings"].sum()
        .nlargest(top_n).index.tolist()
    )
    sub   = df[df["imageLabel"].isin(top_labels)]
    pivot = (
        sub.groupby(["imageLabel", "clusterName"])["resourceName"].nunique()
        .reset_index()
        .pivot(index="imageLabel", columns="clusterName", values="resourceName")
        .fillna(0).astype(int)
    )
    pivot = pivot.loc[pivot.sum(axis=1).sort_values(ascending=False).index]
    z     = pivot.values.tolist()
    text  = [[str(int(v)) if v > 0 else "" for v in row] for row in z]
    fig   = go.Figure(go.Heatmap(
        z=z, x=pivot.columns.tolist(), y=pivot.index.tolist(),
        text=text, texttemplate="%{text}",
        colorscale=[[0, "#12161f"], [0.3, "#1a2744"], [0.7, "#9B3FBF"], [1, "#E53935"]],
        showscale=True,
        colorbar=dict(title=dict(text="Workloads", font=dict(color="#90a4ae")),
                      tickfont=dict(color="#90a4ae")),
        hovertemplate=(
            "<b>%{y}</b><br>Cluster: %{x}<br>Workloads: %{z}<extra></extra>"
        ),
    ))
    fig.update_layout(**PLOTLY_LAYOUT,
                      height=max(400, len(pivot) * 22 + 120),
                      xaxis=dict(title="Cluster", tickangle=-30,
                                 gridcolor="#1e2d3d", tickfont=dict(size=10)),
                      yaxis=dict(title="Image", autorange="reversed",
                                 gridcolor="#1e2d3d", tickfont=dict(size=10)))
    return fig


def _eng_findings_hist(df) -> go.Figure:
    counts = df["findings"].value_counts().sort_index()
    fig = go.Figure(go.Bar(
        x=counts.index.astype(str), y=counts.values,
        marker=dict(color="#FB8C00", line=dict(width=0)),
        text=counts.values, textposition="outside",
        hovertemplate="Findings per workload: %{x}<br>Count: %{y}<extra></extra>",
    ))
    fig.update_layout(**PLOTLY_LAYOUT, height=280,
                      xaxis=dict(title="Findings per Workload", gridcolor="#1e2d3d"),
                      yaxis=dict(title="Workload Count", gridcolor="#1e2d3d"))
    return fig


# =============================================================================
# CVE RISK OVERVIEW PAGE
# =============================================================================


def cve_risk_page():
    """CVE Risk Overview — top CVEs with EPSS > 50%, split In-Use / Not-In-Use."""

    # ── Shared CSS for CVE pages ──────────────────────────────────────────────
    st.markdown("""
<style>
.section-hdr { font-size:1.1rem;font-weight:700;margin:0 0 4px;padding-bottom:6px; }
.section-inuse  { color:#ef9a9a;border-bottom:3px solid #E53935; }
.section-notuse { color:#fff176;border-bottom:3px solid #FB8C00; }
.section-divider { border:none;border-top:1px solid #1e2d3d;margin:36px 0; }
.stat-card { background:#1a1f2e;border-radius:10px;padding:14px 18px;
             border:1px solid #2a3040;text-align:center; }
.stat-val { font-size:1.8rem;font-weight:700;color:#fff; }
.stat-lbl { font-size:.72rem;color:#78909c;text-transform:uppercase;
            letter-spacing:.05em; }
.error-banner { background:#2e1a1a;border:1px solid #e53935;border-radius:8px;
                padding:10px 18px;color:#ef9a9a;font-size:.88rem;margin-bottom:8px; }
</style>
""", unsafe_allow_html=True)

    # ── Session state ─────────────────────────────────────────────────────────
    for _k, _v in [("t1_cves", []), ("t1_loaded", False), ("t1_errors", [])]:
        if _k not in st.session_state:
            st.session_state[_k] = _v

    # ── Sidebar ───────────────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown("### CVE Risk Settings")
        api_base = st.text_input(
            "Sysdig Base URL",
            value=os.environ.get("SYSDIG_API_BASE", CVE_DEFAULT_BASE),
            key="cve_api_base",
        ).rstrip("/")
        api_token = st.text_input(
            "API Token",
            value=os.environ.get("SYSDIG_API_TOKEN", ""),
            type="password",
            placeholder="Paste your Sysdig API token",
            key="cve_api_token",
        )
        st.markdown("---")
        if st.button("🔄 Refresh CVE data", use_container_width=True, key="cve_refresh"):
            st.session_state.t1_cves   = []
            st.session_state.t1_loaded = False
            st.session_state.t1_errors = []
            st.rerun()
        st.markdown(
            f"<small style='color:#546e7a'>Timeout {CVE_API_TIMEOUT}s · "
            f"EPSS ≥ {CVE_EPSS_THRESHOLD*100:.0f}% · Top {CVE_TOP_N}<br>"
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</small>",
            unsafe_allow_html=True,
        )

    # ── Page header ───────────────────────────────────────────────────────────
    st.markdown("""
<div style="margin-bottom:20px">
  <h1 style="color:#fff;font-size:1.8rem;font-weight:700;margin:0 0 4px">
    📊 CVE Risk Overview
  </h1>
  <p style="color:#78909c;font-size:.9rem;margin:0">
    Top CVEs with EPSS &gt; 50% — split by runtime exposure.
    Sourced from Sysdig analytics API (NVD CVSS v3 severity).
  </p>
</div>
""", unsafe_allow_html=True)

    if not api_token or not api_base:
        st.info("👈 Enter your Sysdig Base URL and API Token in the sidebar to load data.")
        return

    # ── Data fetch ────────────────────────────────────────────────────────────
    if not st.session_state.t1_loaded:
        with st.status("📡 Loading vulnerability data…", expanded=True) as _st:
            try:
                _cves, _errs = _load_cves_with_progress(api_base, api_token, _st)
                st.session_state.t1_cves   = _cves
                st.session_state.t1_errors = _errs
                st.session_state.t1_loaded = True
                if _errs:
                    _st.update(label=f"⚠️ {_errs[0]}", state="error")
                else:
                    _st.update(label=f"✅ Loaded {len(_cves)} CVE(s)",
                               state="complete", expanded=False)
            except Exception as _exc:
                st.session_state.t1_errors = [str(_exc)]
                st.session_state.t1_loaded = True
                _st.update(label=f"❌ {_exc}", state="error")

    for err in st.session_state.t1_errors:
        st.markdown(f'<div class="error-banner">⚠️ {err}</div>', unsafe_allow_html=True)

    all_cves = st.session_state.t1_cves
    if not all_cves:
        return

    in_use_cves  = [c for c in all_cves if c.get("inUse")]
    not_use_cves = [c for c in all_cves if not c.get("inUse")]

    # ── Overall summary ───────────────────────────────────────────────────────
    st.markdown("### Overall Summary")
    st.caption(
        "ℹ️ Severity sourced from Sysdig analytics API (NVD CVSS v3). "
        "May differ from Sysdig Vulnerability Findings page (vendor-adjusted ratings)."
    )
    ov1, ov2, ov3, ov4, ov5, ov6 = st.columns(6)
    ov1.metric("Total CVEs",  len(all_cves),                                    "EPSS > 50%")
    ov2.metric("In Use",      len(in_use_cves),                                 "runtime exposure")
    ov3.metric("Not In Use",  len(not_use_cves),                                "not actively running")
    ov4.metric("Exploitable", sum(1 for c in all_cves if c.get("exploitable")), "known exploits")
    ov5.metric("CISA KEV",    sum(1 for c in all_cves if c.get("hasCisaKev")),  "actively exploited")
    ov6.metric("Has Fix",     sum(1 for c in all_cves if c.get("fixAvailable")))

    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)
    _cve_render_section(in_use_cves,  "🔴 In Use — Fix Now",    "section-inuse")
    st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)
    _cve_render_section(not_use_cves, "🟡 Not In Use — Monitor", "section-notuse")


# =============================================================================
# ENGINEERING FIX VIEW PAGE
# =============================================================================


def engineering_fix_page():
    """Engineering Fix View — image-level action list from ClickHouse CSV."""

    st.markdown("""
<style>
[data-testid="stFileUploader"] {
    border: 2px dashed #37474f; border-radius: 12px;
    background: #12161f; transition: border-color .2s, background .2s;
}
[data-testid="stFileUploader"]:hover {
    border-color: #00C853; background: #0d1117;
}
[data-testid="stFileUploaderDropzone"] { padding: 40px 24px; }
[data-testid="stFileUploaderDropzoneInstructions"] { color: #78909c !important; }
[data-testid="stFileUploaderDropzoneInstructions"] svg { color: #00C853 !important; }
.section-divider { border:none;border-top:1px solid #1e2d3d;margin:36px 0; }
</style>
""", unsafe_allow_html=True)

    st.markdown("""
<div style="margin-bottom:22px">
  <h1 style="color:#fff;font-size:1.8rem;font-weight:700;margin:0 0 6px">
    🔧 Engineering Fix View
  </h1>
  <p style="color:#78909c;font-size:.87rem;margin:0">
    Drop the CSV exported from the Sysdig ClickHouse query
    (<code>MATCH Vulnerability … RETURN clusterName, namespaceName, resourceName,
    imageReference, …</code>).
    Shows exactly which images to rebuild and where to redeploy them.
  </p>
</div>
""", unsafe_allow_html=True)

    uploaded = st.file_uploader(
        "Drop your CSV here or click to browse",
        type=["csv"],
        key="eng_file_uploader",
        help="Sysdig ClickHouse vulnerability findings export",
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
        ts = datetime.now().strftime("%Y%m%d_%H%M")

        st.markdown("### Impact Summary")
        e1, e2, e3, e4, e5, e6 = st.columns(6)
        e1.metric("Workloads Affected",  df_eng["resourceName"].nunique())
        e2.metric("Unique Images",        len(img_df), "to rebuild/patch")
        e3.metric("Image Repositories",   df_eng["imageRepository"].nunique())
        e4.metric("Clusters",             df_eng["clusterName"].nunique())
        e5.metric("Namespaces",           df_eng["namespaceName"].nunique())
        e6.metric("Total Findings",       int(df_eng["findings"].sum()))

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:4px'>"
            "🎯 What to Fix — Image Action List</div>"
            "<div style='color:#78909c;font-size:.82rem;margin-bottom:14px'>"
            "Each row is one image that needs to be rebuilt/patched. "
            "Priority is ranked by total findings.</div>",
            unsafe_allow_html=True,
        )

        with st.expander("📂 Group by Repository", expanded=False):
            st.dataframe(repo_df.rename(columns={
                "imageRepository": "Repository",
                "unique_tags":     "Vulnerable Tags",
                "workloads":       "Workloads",
                "clusters":        "Clusters",
                "total_findings":  "Total Findings",
                "tags":            "Tag Versions",
            }), use_container_width=True, hide_index=True)

        action_cols = {
            "Priority": "Priority", "imageLabel": "Image (name:tag)",
            "imageRegistry": "Registry", "workloads": "Workloads",
            "clusters": "Clusters", "namespaces": "Namespaces",
            "total_findings": "Total Findings", "cluster_list": "Cluster Names",
            "imageReference": "Full Image Reference",
        }
        action_df = img_df[list(action_cols.keys())].rename(columns=action_cols)

        def _sty_priority(v):
            if v <= 3:  return "color:#ef5350;font-weight:700"
            if v <= 10: return "color:#ffa726;font-weight:700"
            return "color:#90a4ae"

        st.dataframe(action_df.style.applymap(_sty_priority, subset=["Priority"]),
                     use_container_width=True, hide_index=True,
                     height=min(600, 36 * len(action_df) + 60))

        dl1, _ = st.columns([1, 5])
        with dl1:
            st.download_button("⬇️ Export action list",
                               data=action_df.to_csv(index=False),
                               file_name=f"fix_action_list_{ts}.csv",
                               mime="text/csv", key="dl_eng_action")

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:14px'>"
            "📊 Visual Breakdown</div>", unsafe_allow_html=True)

        vt1, vt2, vt3 = st.tabs(["🖼️ Top Images", "🌐 Cluster Spread", "📦 Registry & Findings"])

        with vt1:
            st.plotly_chart(_eng_top_images_bar(img_df), use_container_width=True,
                            config={"displayModeBar": False})
        with vt2:
            vc1, vc2 = st.columns(2)
            with vc1:
                st.plotly_chart(_eng_cluster_bar(df_eng), use_container_width=True,
                                config={"displayModeBar": False})
            with vc2:
                ns_counts = (
                    df_eng.groupby("namespaceName")["resourceName"].nunique()
                    .reset_index().rename(columns={"resourceName": "workloads"})
                    .set_index("namespaceName")["workloads"].to_dict()
                )
                st.plotly_chart(_t2_hbar(ns_counts, "Workloads", "#1E88E5"),
                                use_container_width=True, config={"displayModeBar": False})
        with vt3:
            vc1, vc2 = st.columns(2)
            with vc1:
                st.plotly_chart(_eng_registry_donut(df_eng), use_container_width=True,
                                config={"displayModeBar": False})
            with vc2:
                st.plotly_chart(_eng_findings_hist(df_eng), use_container_width=True,
                                config={"displayModeBar": False})

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:4px'>"
            "🟥 Image × Cluster Heatmap</div>"
            "<div style='color:#78909c;font-size:.82rem;margin-bottom:14px'>"
            "Which images are running in which clusters. Each cell = workload count.</div>",
            unsafe_allow_html=True)
        st.plotly_chart(_eng_cluster_image_heatmap(df_eng), use_container_width=True,
                        config={"displayModeBar": False})

        st.markdown("<hr class='section-divider'>", unsafe_allow_html=True)

        st.markdown(
            "<div style='font-size:1.05rem;font-weight:700;color:#fff;margin-bottom:4px'>"
            "🔍 Per-Image Workload Detail</div>"
            "<div style='color:#78909c;font-size:.82rem;margin-bottom:14px'>"
            "Select an image to see every workload that needs redeployment.</div>",
            unsafe_allow_html=True)

        sel_image = st.selectbox("Select image", options=img_df["imageLabel"].tolist(),
                                 key="eng_img_sel")
        if sel_image:
            sub_df  = df_eng[df_eng["imageLabel"] == sel_image].copy()
            sel_ref = sub_df["imageReference"].iloc[0]
            st.markdown(
                f"<div style='background:#1a1f2e;border-radius:8px;padding:12px 18px;"
                f"border-left:4px solid #E53935;margin-bottom:14px'>"
                f"<div style='color:#90a4ae;font-size:.78rem;margin-bottom:2px'>Full image reference</div>"
                f"<div style='color:#fff;font-family:monospace;font-size:.9rem'>{sel_ref}</div>"
                f"</div>", unsafe_allow_html=True)
            sm1, sm2, sm3, sm4 = st.columns(4)
            sm1.metric("Workloads",      sub_df["resourceName"].nunique())
            sm2.metric("Clusters",       sub_df["clusterName"].nunique())
            sm3.metric("Namespaces",     sub_df["namespaceName"].nunique())
            sm4.metric("Total Findings", int(sub_df["findings"].sum()))
            detail_df = (
                sub_df[["clusterName", "namespaceName", "resourceName", "findings"]]
                .drop_duplicates()
                .sort_values(["clusterName", "namespaceName", "resourceName"])
                .rename(columns={"clusterName": "Cluster", "namespaceName": "Namespace",
                                 "resourceName": "Workload", "findings": "Findings"})
                .reset_index(drop=True)
            )
            st.dataframe(detail_df, use_container_width=True, hide_index=True,
                         height=min(500, 36 * len(detail_df) + 60))
            st.download_button(
                f"⬇️ Export workloads for {sel_image}",
                data=detail_df.to_csv(index=False),
                file_name=f"workloads_{sel_image.replace(':', '_').replace('/', '_')}_{ts}.csv",
                mime="text/csv", key="dl_eng_detail")

    else:
        st.info(
            "👆 Drag and drop your Sysdig ClickHouse CSV export above, or click to browse.\n\n"
            "Expected columns: `clusterName`, `namespaceName`, `resourceName`, "
            "`imageReference`, `imageRegistry`, `imageRepository`, `imageTag`, `findings`."
        )


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================


def main():
    """Main entry point — sidebar navigation routes to the selected tool."""
    with st.sidebar:
        st.markdown("## 🛡️ Sysdig Analytics Suite")
        st.markdown("---")
        mode = st.radio(
            "Select Tool",
            options=[
                "📋  Posture Analytics",
                "🔍  Registry Vulnerabilities",
                "📊  CVE Risk Overview",
                "🔧  Engineering Fix View",
            ],
            index=0,
            help="Switch between security tools",
        )
        st.markdown("---")

    if mode == "📋  Posture Analytics":
        posture_analytics_page()
    elif mode == "🔍  Registry Vulnerabilities":
        vuln_analytics_page()
    elif mode == "📊  CVE Risk Overview":
        cve_risk_page()
    else:
        engineering_fix_page()


if __name__ == "__main__":
    main()

