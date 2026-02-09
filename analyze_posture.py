#!/usr/bin/env python3
"""
Sysdig Posture Report Analytics - Command Line Tool

A command-line utility for generating executive and security team dashboards
from Sysdig posture compliance reports in CSV format.

This script processes posture report data and generates:
- Executive dashboard (HTML) showing top contributors to failures
- Security drill-down treemap (HTML) for hierarchical analysis
- Owner-Control heatmap (HTML) for detailed failure patterns
- Severity breakdown charts (HTML)
- CSV exports for offline analysis

Usage:
    python analyze_posture.py [data_dir] [output_dir]

    data_dir:   Directory containing CSV/CSV.GZ posture reports (default: "data")
    output_dir: Directory for generated outputs (default: "output")

Example:
    python analyze_posture.py ./reports ./dashboards

Author: Your Organization
License: MIT
"""

# =============================================================================
# IMPORTS
# =============================================================================

import gzip
import glob
import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# =============================================================================
# DATA LOADING FUNCTIONS
# =============================================================================


def extract_and_load_data(data_dir: str = "data") -> pd.DataFrame:
    """
    Load posture report data from CSV files in the specified directory.

    Automatically handles both plain CSV and gzipped CSV files. If a .csv.gz
    file is found, it will be extracted before loading.

    Args:
        data_dir: Directory path containing the CSV files

    Returns:
        pd.DataFrame: DataFrame containing only failing controls (Result == 'Fail')

    Raises:
        FileNotFoundError: If no CSV or CSV.GZ files are found
    """
    # Find CSV files (both plain and gzipped)
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))
    gz_files = glob.glob(os.path.join(data_dir, "*.csv.gz"))

    if gz_files:
        gz_path = gz_files[0]
        csv_path = gz_path.replace(".gz", "")

        # Extract if CSV doesn't exist
        if not os.path.exists(csv_path):
            print(f"Extracting {gz_path}...")
            with gzip.open(gz_path, 'rb') as f_in:
                with open(csv_path, 'wb') as f_out:
                    f_out.write(f_in.read())

        data_file = csv_path
    elif csv_files:
        data_file = csv_files[0]
    else:
        raise FileNotFoundError(f"No CSV or CSV.GZ files found in {data_dir}")

    print(f"Loading data from {data_file}...")
    df = pd.read_csv(data_file)

    # Filter to only failing controls
    df_fail = df[df['Result'] == 'Fail'].copy()
    print(f"Total records: {len(df)}, Failing controls: {len(df_fail)}")

    return df_fail


# =============================================================================
# DASHBOARD GENERATION FUNCTIONS
# =============================================================================


def generate_executive_dashboard(df: pd.DataFrame, output_dir: str = "output"):
    """
    Generate executive-level dashboard as a standalone HTML file.

    Creates an interactive dashboard showing:
    - Pie chart of failure distribution by owner
    - Horizontal bar chart of top 10 contributors
    - Per-person breakdown charts for top 5 owners

    Also generates a CSV summary of owner statistics.

    Args:
        df: DataFrame containing failing control records
        output_dir: Directory to save output files

    Returns:
        pd.DataFrame: Owner statistics DataFrame
    """
    Path(output_dir).mkdir(exist_ok=True)

    total_failures = len(df)
    unique_owners = df['Zones'].nunique()
    unique_accounts = df['Account Id'].nunique()

    # Aggregate by owner
    owner_stats = df.groupby('Zones').agg({
        'Control ID': 'count',
        'Account Id': lambda x: list(x.unique()),
        'Control Name': lambda x: x.nunique()
    }).reset_index()
    owner_stats.columns = ['Owner', 'Total Failures', 'Account IDs', 'Unique Controls']
    owner_stats['Percentage'] = (owner_stats['Total Failures'] / total_failures * 100).round(1)
    owner_stats['Cumulative %'] = owner_stats['Total Failures'].sort_values(ascending=False).cumsum() / total_failures * 100
    owner_stats = owner_stats.sort_values('Total Failures', ascending=False)

    # Top contributors
    top_n = 10
    top_owners = owner_stats.head(top_n).copy()
    others_count = owner_stats.iloc[top_n:]['Total Failures'].sum() if len(owner_stats) > top_n else 0
    others_pct = (others_count / total_failures * 100).round(1)
    top_total_pct = top_owners['Percentage'].sum()

    # Figure 1: Pie chart - Who contributes to failures (executive priority view)
    pie_labels = [f"{o[:20]}..." if len(o) > 20 else o for o in top_owners['Owner']]
    pie_values = list(top_owners['Total Failures'])
    pie_text = [f"{p}%" for p in top_owners['Percentage']]

    if others_count > 0:
        pie_labels.append(f'Others ({len(owner_stats) - top_n} people)')
        pie_values.append(others_count)
        pie_text.append(f"{others_pct}%")

    colors_pie = ['#e74c3c', '#c0392b', '#e67e22', '#d35400', '#f39c12',
                  '#f1c40f', '#27ae60', '#2ecc71', '#3498db', '#2980b9', '#95a5a6']

    fig1 = go.Figure(go.Pie(
        labels=pie_labels,
        values=pie_values,
        text=pie_text,
        textinfo='label+text',
        textposition='outside',
        marker_colors=colors_pie[:len(pie_labels)],
        hole=0.4,
        sort=False
    ))
    fig1.add_annotation(
        text=f"<b>{total_failures:,}</b><br>Total",
        x=0.5, y=0.5, font_size=16, showarrow=False
    )
    fig1.update_layout(
        title=dict(text='<b>Who is Contributing to Compliance Failures?</b>',
                   x=0.5, font=dict(size=16)),
        height=500,
        margin=dict(t=60, b=40, l=40, r=40),
        showlegend=False,
        paper_bgcolor='white'
    )

    # Figure 2: Horizontal bar - Top contributors
    fig2 = go.Figure()

    # Sort and create explicit lists to ensure alignment
    top_owners_sorted = top_owners.sort_values('Total Failures', ascending=True).reset_index(drop=True)

    # Create lists (ascending order so highest appears at top of horizontal bar chart)
    bar_labels = [(o[:25] + '...' if len(o) > 25 else o) for o in top_owners_sorted['Owner'].tolist()]
    bar_values = top_owners_sorted['Total Failures'].tolist()
    bar_pcts = top_owners_sorted['Percentage'].tolist()
    bar_accounts = top_owners_sorted['Account IDs'].tolist()

    # Bar for failure counts
    fig2.add_trace(go.Bar(
        x=bar_values,
        y=bar_labels,
        orientation='h',
        marker_color='#e74c3c',
        text=[f"{v:,} ({p}%)" for v, p in zip(bar_values, bar_pcts)],
        textposition='inside',
        textfont=dict(color='white', size=12),
        insidetextanchor='end',
        name='Failures',
        hovertext=[f"{o}<br>Failures: {v:,}<br>% of Total: {p}%<br>Accounts: {', '.join(map(str, a[:3]))}"
                   for o, v, p, a in zip(bar_labels, bar_values, bar_pcts, bar_accounts)],
        hoverinfo='text'
    ))

    fig2.update_layout(
        title=dict(text=f'<b>Top {top_n} Contributors = {top_total_pct:.0f}% of All Failures</b>',
                   x=0.5, font=dict(size=16)),
        height=500,
        margin=dict(t=60, b=60, l=200, r=120),
        xaxis=dict(title='Total Failures', tickformat=',d', rangemode='tozero'),
        paper_bgcolor='white',
        plot_bgcolor='#fafafa',
        showlegend=False
    )

    # Generate per-person breakdown for security team
    person_charts = []
    top_5_owners = top_owners.sort_values('Total Failures', ascending=False).head(5)

    for i, (_, row) in enumerate(top_5_owners.iterrows()):
        owner = row['Owner']
        owner_df = df[df['Zones'] == owner]

        # Get all controls failing for this person
        all_controls = owner_df.groupby(['Control Name', 'Control Severity']).size().reset_index(name='Count')
        total_unique_controls = len(all_controls)

        # Top 8 controls for display
        controls = all_controls.sort_values('Count', ascending=True).tail(8).reset_index(drop=True)

        severity_colors = {'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'}

        # Create explicit lists
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

        accounts_str = ', '.join(map(str, row['Account IDs'][:3]))
        if len(row['Account IDs']) > 3:
            accounts_str += f" (+{len(row['Account IDs'])-3} more)"

        fig_person.update_layout(
            title=dict(
                text=f"<b>{owner[:35]}</b><br>{row['Total Failures']:,} failures ({row['Percentage']}%) across {total_unique_controls} controls | Showing top 8<br>Accounts: {accounts_str}",
                x=0.5, font=dict(size=13)
            ),
            height=420,
            margin=dict(t=90, b=40, l=250, r=100),
            xaxis=dict(title='Total Failures', tickformat=',d', rangemode='tozero'),
            yaxis=dict(tickfont=dict(size=10)),
            paper_bgcolor='white',
            plot_bgcolor='#fafafa'
        )
        person_charts.append(fig_person)

    # Generate HTML
    person_divs = '\n'.join([f'<div class="chart-container person-chart" id="person{i}"></div>'
                             for i in range(len(person_charts))])
    person_plots = '\n'.join([f"Plotly.newPlot('person{i}', {fig.to_json()}.data, {fig.to_json()}.layout, config);"
                              for i, fig in enumerate(person_charts)])

    html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Executive Security Posture Dashboard</title>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #ecf0f1;
        }}
        .header {{
            text-align: center;
            padding: 25px;
            background: linear-gradient(135deg, #c0392b, #e74c3c);
            color: white;
            border-radius: 10px;
            margin-bottom: 25px;
            max-width: 1600px;
            margin-left: auto;
            margin-right: auto;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
        }}
        .header .stats {{
            font-size: 18px;
            opacity: 0.95;
        }}
        .header .stats strong {{
            font-size: 22px;
        }}
        .section-title {{
            max-width: 1600px;
            margin: 30px auto 15px auto;
            padding: 15px 20px;
            background: #2c3e50;
            color: white;
            border-radius: 8px;
            font-size: 18px;
        }}
        .executive-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            max-width: 1600px;
            margin: 0 auto 30px auto;
        }}
        .person-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            max-width: 1600px;
            margin: 0 auto;
        }}
        .chart-container {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border: 2px solid #bdc3c7;
            overflow: hidden;
        }}
        .chart-container:hover {{
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            border-color: #e74c3c;
        }}
        .legend {{
            max-width: 1600px;
            margin: 20px auto;
            padding: 15px;
            background: white;
            border-radius: 8px;
            display: flex;
            justify-content: center;
            gap: 30px;
            font-size: 14px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Executive Security Posture Dashboard</h1>
        <div class="stats">
            <strong>{total_failures:,}</strong> Total Compliance Failures across
            <strong>{unique_owners}</strong> Owners in
            <strong>{unique_accounts}</strong> Accounts
        </div>
    </div>

    <div class="section-title">
        Executive Summary: Who Should We Engage First?
    </div>
    <div class="executive-grid">
        <div class="chart-container" id="chart1"></div>
        <div class="chart-container" id="chart2"></div>
    </div>

    <div class="section-title">
        Action Plan: Top 5 Contributors - What Controls to Fix First
    </div>
    <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background:#e74c3c"></div> High Severity</div>
        <div class="legend-item"><div class="legend-color" style="background:#f39c12"></div> Medium Severity</div>
        <div class="legend-item"><div class="legend-color" style="background:#3498db"></div> Low Severity</div>
        <div class="legend-item"><div class="legend-color" style="background:#95a5a6"></div> Info</div>
    </div>
    <div class="person-grid">
        {person_divs}
    </div>

    <script>
        var config = {{responsive: true, displayModeBar: true, displaylogo: false}};
        Plotly.newPlot('chart1', {fig1.to_json()}.data, {fig1.to_json()}.layout, config);
        Plotly.newPlot('chart2', {fig2.to_json()}.data, {fig2.to_json()}.layout, config);
        {person_plots}
    </script>
</body>
</html>'''

    output_path = os.path.join(output_dir, "executive_dashboard.html")
    with open(output_path, 'w') as f:
        f.write(html_content)
    print(f"Executive dashboard saved to: {output_path}")

    # Also save summary table
    owner_stats_export = owner_stats.copy()
    owner_stats_export['Account IDs'] = owner_stats_export['Account IDs'].apply(lambda x: ', '.join(map(str, x)))
    summary_path = os.path.join(output_dir, "owner_summary.csv")
    owner_stats_export.to_csv(summary_path, index=False)
    print(f"Owner summary saved to: {summary_path}")

    return owner_stats


def generate_security_team_dashboard(df: pd.DataFrame, output_dir: str = "output"):
    """Generate detailed dashboard for security team with drill-down capability."""

    Path(output_dir).mkdir(exist_ok=True)

    # Create detailed breakdown: Owner -> Account -> Controls
    detailed = df.groupby(['Zones', 'Account Name', 'Account Id', 'Control Name', 'Control Severity']).agg({
        'Resource Name': 'count',
        'Resource ID': lambda x: list(x.unique())[:5]  # Sample resources
    }).reset_index()
    detailed.columns = ['Owner', 'Account Name', 'Account Id', 'Control Name', 'Severity', 'Failure Count', 'Sample Resources']
    detailed = detailed.sort_values(['Owner', 'Failure Count'], ascending=[True, False])

    # Create treemap for hierarchical view
    treemap_data = df.groupby(['Zones', 'Control Severity', 'Control Name']).size().reset_index(name='Count')

    fig_treemap = px.treemap(
        treemap_data,
        path=['Zones', 'Control Severity', 'Control Name'],
        values='Count',
        color='Control Severity',
        color_discrete_map={'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'},
        title='<b>Security Posture Drill-Down</b><br><sup>Click to explore: Owner > Severity > Control</sup>'
    )
    fig_treemap.update_layout(height=800, width=1400)
    fig_treemap.update_traces(textinfo='label+value')

    treemap_path = os.path.join(output_dir, "security_drilldown.html")
    fig_treemap.write_html(treemap_path)
    print(f"Security drill-down saved to: {treemap_path}")

    # Create detailed heatmap: Owner vs Control
    pivot = df.pivot_table(
        index='Zones',
        columns='Control Name',
        values='Resource ID',
        aggfunc='count',
        fill_value=0
    )

    # Limit to top owners and controls for readability
    top_owners = df['Zones'].value_counts().head(20).index
    top_controls = df['Control Name'].value_counts().head(15).index

    pivot_filtered = pivot.loc[
        pivot.index.isin(top_owners),
        pivot.columns.isin(top_controls)
    ]

    fig_heatmap = go.Figure(data=go.Heatmap(
        z=pivot_filtered.values,
        x=[c[:40] + '...' if len(c) > 40 else c for c in pivot_filtered.columns],
        y=pivot_filtered.index,
        colorscale='Reds',
        text=pivot_filtered.values,
        texttemplate='%{text}',
        textfont={"size": 10},
        hovertemplate='Owner: %{y}<br>Control: %{x}<br>Failures: %{z}<extra></extra>'
    ))

    fig_heatmap.update_layout(
        title='<b>Owner vs Control Failure Matrix</b><br><sup>Identify which controls are failing for each owner</sup>',
        xaxis_title='Control Name',
        yaxis_title='Owner',
        height=700,
        width=1400,
        xaxis=dict(tickangle=45, tickfont=dict(size=9)),
        yaxis=dict(tickfont=dict(size=10))
    )

    heatmap_path = os.path.join(output_dir, "owner_control_matrix.html")
    fig_heatmap.write_html(heatmap_path)
    print(f"Owner-Control matrix saved to: {heatmap_path}")

    # Create actionable report grouped by owner
    action_report = []
    for owner in df['Zones'].unique():
        owner_df = df[df['Zones'] == owner]
        accounts = owner_df.groupby(['Account Name', 'Account Id']).size().reset_index(name='Failures')

        for _, acc in accounts.iterrows():
            acc_df = owner_df[(owner_df['Account Name'] == acc['Account Name']) &
                             (owner_df['Account Id'] == acc['Account Id'])]

            controls = acc_df.groupby(['Control Name', 'Control Severity', 'Control ID']).agg({
                'Resource Name': ['count', lambda x: ', '.join(x.unique()[:3])]
            }).reset_index()
            controls.columns = ['Control Name', 'Severity', 'Control ID', 'Count', 'Sample Resources']
            controls = controls.sort_values('Count', ascending=False)

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
    action_df = action_df.sort_values(['Owner', 'Severity', 'Failure Count'],
                                       ascending=[True, True, False],
                                       key=lambda x: x.map({'High': 0, 'Medium': 1, 'Low': 2, 'Info': 3}) if x.name == 'Severity' else x)

    action_path = os.path.join(output_dir, "actionable_report.csv")
    action_df.to_csv(action_path, index=False)
    print(f"Actionable report saved to: {action_path}")

    # Create per-owner breakdown charts
    fig_owner_detail = make_subplots(
        rows=1, cols=2,
        subplot_titles=('Top 10 Owners - Control Breakdown', 'Severity by Owner'),
        specs=[[{"type": "bar"}, {"type": "bar"}]],
        horizontal_spacing=0.12
    )

    # Stacked bar: Owner vs Severity
    owner_severity = df.groupby(['Zones', 'Control Severity']).size().reset_index(name='Count')
    top_10_owners = df['Zones'].value_counts().head(10).index.tolist()
    owner_severity = owner_severity[owner_severity['Zones'].isin(top_10_owners)]

    for severity in ['High', 'Medium', 'Low', 'Info']:
        sev_data = owner_severity[owner_severity['Control Severity'] == severity]
        if not sev_data.empty:
            fig_owner_detail.add_trace(
                go.Bar(
                    name=severity,
                    x=sev_data['Zones'],
                    y=sev_data['Count'],
                    marker_color={'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'}[severity],
                    text=sev_data['Count'],
                    textposition='inside'
                ),
                row=1, col=1
            )

    # Owner contact info with account details
    owner_accounts = df.groupby('Zones').agg({
        'Account Id': lambda x: ', '.join(map(str, x.unique())),
        'Account Name': lambda x: ', '.join(x.unique())
    }).reset_index()
    owner_accounts.columns = ['Owner', 'Account IDs', 'Account Names']

    contact_path = os.path.join(output_dir, "owner_accounts.csv")
    owner_accounts.to_csv(contact_path, index=False)
    print(f"Owner accounts list saved to: {contact_path}")

    fig_owner_detail.update_layout(
        barmode='stack',
        title='<b>Owner Detail View</b><br><sup>Severity breakdown for top owners</sup>',
        height=500,
        width=1200,
        showlegend=True,
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1)
    )
    fig_owner_detail.update_xaxes(tickangle=45)

    detail_path = os.path.join(output_dir, "owner_severity_breakdown.html")
    fig_owner_detail.write_html(detail_path)
    print(f"Owner severity breakdown saved to: {detail_path}")

    return detailed


def print_top_findings(df: pd.DataFrame):
    """Print top findings to console."""

    print("\n" + "="*80)
    print("TOP FINDINGS SUMMARY")
    print("="*80)

    # Top 5 owners with most failures
    print("\n--- TOP 5 OWNERS WITH MOST FAILING CONTROLS ---")
    owner_counts = df.groupby('Zones').agg({
        'Control ID': 'count',
        'Account Id': lambda x: ', '.join(map(str, x.unique()[:3]))
    }).reset_index()
    owner_counts.columns = ['Owner', 'Failure Count', 'Account IDs']
    owner_counts = owner_counts.sort_values('Failure Count', ascending=False).head(5)

    for i, row in owner_counts.iterrows():
        print(f"  {row['Owner']}: {row['Failure Count']} failures")
        print(f"    Account IDs: {row['Account IDs']}")

    # Top 5 failing controls
    print("\n--- TOP 5 FAILING CONTROLS ---")
    control_counts = df.groupby(['Control Name', 'Control ID', 'Control Severity']).size().reset_index(name='Count')
    control_counts = control_counts.sort_values('Count', ascending=False).head(5)

    for i, row in control_counts.iterrows():
        print(f"  [{row['Control Severity']}] {row['Control Name']}")
        print(f"    Control ID: {row['Control ID']}, Failures: {row['Count']}")

    print("\n" + "="*80)


def main():
    """Main entry point."""

    data_dir = sys.argv[1] if len(sys.argv) > 1 else "data"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "output"

    print(f"Sysdig Posture Report Analyzer")
    print(f"Data directory: {data_dir}")
    print(f"Output directory: {output_dir}")
    print("-" * 40)

    # Load data
    df = extract_and_load_data(data_dir)

    # Print summary to console
    print_top_findings(df)

    # Generate dashboards
    print("\nGenerating dashboards...")
    generate_executive_dashboard(df, output_dir)
    generate_security_team_dashboard(df, output_dir)

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE!")
    print("="*80)
    print(f"\nOpen these files in your browser:")
    print(f"  1. Executive Dashboard:    {output_dir}/executive_dashboard.html")
    print(f"  2. Security Drill-Down:    {output_dir}/security_drilldown.html")
    print(f"  3. Owner-Control Matrix:   {output_dir}/owner_control_matrix.html")
    print(f"  4. Owner Severity View:    {output_dir}/owner_severity_breakdown.html")
    print(f"\nCSV Reports:")
    print(f"  - {output_dir}/owner_summary.csv")
    print(f"  - {output_dir}/actionable_report.csv")
    print(f"  - {output_dir}/owner_accounts.csv")


if __name__ == "__main__":
    main()
