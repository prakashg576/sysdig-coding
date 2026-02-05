#!/usr/bin/env python3
"""
Sysdig Posture Report Analytics - Web Interface
Streamlit app for uploading CSV files and viewing dashboards.
"""

import io
import gzip
import json
import os
import re
import zipfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import streamlit as st
from streamlit_sortables import sort_items


st.set_page_config(
    page_title="Sysdig Posture Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


def extract_date_from_filename(filename: str) -> datetime:
    """Extract date from filename like 'Report_2026-01-31T03_25_25.610Z.csv.gz'."""
    # Try to find ISO date pattern in filename
    pattern = r'(\d{4}-\d{2}-\d{2})T?(\d{2}[_:]\d{2}[_:]\d{2})?'
    match = re.search(pattern, filename)
    if match:
        date_str = match.group(1)
        return datetime.strptime(date_str, '%Y-%m-%d')
    # Fallback to current date if no date found
    return datetime.now()


VULN_DATA_DIR = Path.home() / "sysdig-vuln-data"
SYSDIG_API_BASE = "https://api.au1.sysdig.com"
SEVERITY_COLORS = {
    'Critical': '#9b59b6',
    'High': '#e74c3c',
    'Medium': '#f39c12',
    'Low': '#3498db',
    'Negligible': '#95a5a6',
}
SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Negligible']


def fetch_registry_results(api_token: str, limit: int = 100) -> list[dict]:
    """Fetch all registry vulnerability results using cursor-based pagination."""
    url = f"{SYSDIG_API_BASE}/secure/vulnerability/v1/registry-results"
    headers = {"Authorization": f"Bearer {api_token}", "Accept": "application/json"}
    all_results = []
    cursor = None

    while True:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor

        resp = requests.get(url, headers=headers, params=params, timeout=60)
        resp.raise_for_status()
        body = resp.json()

        data = body.get("data", [])
        all_results.extend(data)

        page_info = body.get("page", {})
        cursor = page_info.get("next")
        if not cursor:
            break

    return all_results


def save_results_to_disk(results: list[dict], folder: Path = VULN_DATA_DIR) -> Path:
    """Save fetched results as a timestamped JSON file."""
    folder.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filepath = folder / f"registry_vuln_{ts}.json"
    payload = {
        "fetched_at": datetime.now().isoformat(),
        "total_images": len(results),
        "data": results,
    }
    filepath.write_text(json.dumps(payload, default=str))
    return filepath


def list_saved_snapshots(folder: Path = VULN_DATA_DIR) -> list[dict]:
    """List saved JSON snapshot files sorted by date descending."""
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
            continue
    return snapshots


def load_snapshot(filepath) -> list[dict]:
    """Load image results from a JSON snapshot file."""
    if hasattr(filepath, 'read'):
        raw = filepath.read()
        if isinstance(raw, bytes):
            raw = raw.decode('utf-8')
        payload = json.loads(raw)
    else:
        payload = json.loads(Path(filepath).read_text())
    return payload.get("data", []), payload.get("fetched_at", "unknown")


def normalize_image_data(results: list[dict]) -> pd.DataFrame:
    """Convert raw API results into a flat DataFrame for charting."""
    rows = []
    for r in results:
        # Handle actual API field: vulnTotalBySeverity (lowercase keys)
        vuln_sev = r.get("vulnTotalBySeverity",
                         r.get("vulnsBySev",
                                r.get("vulnTotalBySev", {})))
        fix_sev = r.get("fixableVulnsBySeverity",
                        r.get("fixableVulnsBySev", {}))

        # API uses lowercase severity keys
        crit = vuln_sev.get("critical", vuln_sev.get("Critical", 0))
        high = vuln_sev.get("high", vuln_sev.get("High", 0))
        med = vuln_sev.get("medium", vuln_sev.get("Medium", 0))
        low = vuln_sev.get("low", vuln_sev.get("Low", 0))
        neg = vuln_sev.get("negligible", vuln_sev.get("Negligible", 0))
        total_vulns = crit + high + med + low + neg

        fix_crit = fix_sev.get("critical", fix_sev.get("Critical", 0))
        fix_high = fix_sev.get("high", fix_sev.get("High", 0))
        fix_med = fix_sev.get("medium", fix_sev.get("Medium", 0))
        fix_low = fix_sev.get("low", fix_sev.get("Low", 0))
        fix_neg = fix_sev.get("negligible", fix_sev.get("Negligible", 0))
        total_fixable = fix_crit + fix_high + fix_med + fix_low + fix_neg

        pull_string = r.get("pullString", r.get("imagePullString", ""))

        # Parse repository and tag from pullString (e.g. "registry/repo/image:tag")
        parsed_repo = pull_string
        parsed_tag = ""
        if ":" in pull_string:
            parts = pull_string.rsplit(":", 1)
            parsed_repo = parts[0]
            parsed_tag = parts[1]

        row = {
            "image_id": r.get("imageId", r.get("resultId", "")),
            "result_id": r.get("resultId", ""),
            "pull_string": pull_string,
            "repository": parsed_repo,
            "tag": parsed_tag or r.get("tag", ""),
            "vendor": r.get("vendor", ""),
            "created_at": r.get("createdAt", ""),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "negligible": neg,
            "fix_critical": fix_crit,
            "fix_high": fix_high,
            "fix_medium": fix_med,
            "fix_low": fix_low,
            "fix_negligible": fix_neg,
            "total_vulns": total_vulns,
            "total_fixable": total_fixable,
            "total_unfixable": total_vulns - total_fixable,
            "exploit_count": r.get("exploitCount", r.get("exploitableCount", 0)),
            "policy_status": r.get("policyStatus", r.get("policyEvaluation", "")),
            "in_use": r.get("inUse", False),
        }
        # Build a short display name from pullString
        name_part = parsed_repo.split("/")[-1] if "/" in parsed_repo else parsed_repo
        row["display_name"] = f"{name_part}:{parsed_tag}" if parsed_tag else name_part
        rows.append(row)

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df = df.sort_values("total_vulns", ascending=False).reset_index(drop=True)
    return df


def load_data(uploaded_file) -> pd.DataFrame:
    """Load CSV data from uploaded file."""
    filename = uploaded_file.name

    if filename.endswith('.zip'):
        with zipfile.ZipFile(uploaded_file, 'r') as z:
            # Find CSV files in the zip
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
    elif filename.endswith('.gz'):
        with gzip.open(uploaded_file, 'rt') as f:
            df = pd.read_csv(f)
    else:
        df = pd.read_csv(uploaded_file)

    # Filter to only failing controls
    df_fail = df[df['Result'] == 'Fail'].copy()

    return df, df_fail


def load_multiple_files(uploaded_files, group_by: str = 'Zones') -> pd.DataFrame:
    """Load multiple CSV files and combine them with dates for trend analysis."""
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


def create_executive_charts(df: pd.DataFrame, group_by: str = 'Zones'):
    """Create executive dashboard charts."""

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
    """Create per-person breakdown charts."""

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
    """Create security team dashboard charts."""

    # Treemap
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
    """Create trend analysis charts showing failures over time."""

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
    """Create downloadable CSV reports."""

    # Owner summary
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


# ---------------------------------------------------------------------------
# Vulnerability Analytics Charts
# ---------------------------------------------------------------------------

def create_vuln_executive_charts(df: pd.DataFrame):
    """Create executive vulnerability dashboard charts. Returns dict of figures."""
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
    """Create trend charts from multiple snapshots. Each entry is (date_str, df)."""
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


# ---------------------------------------------------------------------------
# Vulnerability Analytics UI
# ---------------------------------------------------------------------------

def vuln_analytics_page():
    """Render the Vulnerability Analytics page."""
    st.title("Registry Vulnerability Analytics")
    st.markdown("Fetch and analyze container image vulnerabilities from the Sysdig registry scanner.")

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

        # KPI row
        c1, c2, c3, c4, c5 = st.columns(5)
        total_high = int(latest_df['high'].sum())
        total_med = int(latest_df['medium'].sum())

        c1.metric("Images Scanned", f"{charts['total_images']:,}")
        c2.metric("Total Vulns", f"{charts['total_vulns']:,}")
        c3.metric("Critical", f"{charts['total_critical']:,}")
        c4.metric("High", f"{total_high:,}")
        c5.metric("Medium", f"{total_med:,}")

        st.markdown("---")

        # Row 1: Top 5 + Severity donut
        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(charts["fig_top5"], use_container_width=True)
        with col2:
            st.plotly_chart(charts["fig_severity"], use_container_width=True)

        st.markdown("---")

        # Row 2: Vendor breakdown + Severity by vendor
        col3, col4 = st.columns(2)
        with col3:
            if "fig_vendor" in charts:
                st.plotly_chart(charts["fig_vendor"], use_container_width=True)
        with col4:
            if "fig_vendor_severity" in charts:
                st.plotly_chart(charts["fig_vendor_severity"], use_container_width=True)

        st.markdown("---")

        # Row 3: Priority to patch + Distribution histogram
        col5, col6 = st.columns(2)
        with col5:
            if "fig_priority" in charts:
                st.plotly_chart(charts["fig_priority"], use_container_width=True)
            else:
                st.info("No critical or high severity vulnerabilities found.")
        with col6:
            if "fig_histogram" in charts:
                st.plotly_chart(charts["fig_histogram"], use_container_width=True)

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
    """Render the Posture Analytics page (original functionality)."""
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


def main():
    """Main entry point with mode selector."""
    with st.sidebar:
        st.header("Sysdig Analytics")
        mode = st.radio(
            "Select Dashboard",
            options=["Posture Analytics", "Vulnerability Analytics"],
            index=0,
            help="Switch between posture compliance and registry vulnerability dashboards",
        )
        st.markdown("---")

    if mode == "Posture Analytics":
        posture_analytics_page()
    else:
        vuln_analytics_page()


if __name__ == "__main__":
    main()
