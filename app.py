#!/usr/bin/env python3
"""
Sysdig Posture Report Analytics - Web Interface
Streamlit app for uploading CSV files and viewing dashboards.
"""

import io
import gzip

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st


st.set_page_config(
    page_title="Sysdig Posture Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


def load_data(uploaded_file) -> pd.DataFrame:
    """Load CSV data from uploaded file."""
    filename = uploaded_file.name

    if filename.endswith('.gz'):
        with gzip.open(uploaded_file, 'rt') as f:
            df = pd.read_csv(f)
    else:
        df = pd.read_csv(uploaded_file)

    # Filter to only failing controls
    df_fail = df[df['Result'] == 'Fail'].copy()

    return df, df_fail


def create_executive_charts(df: pd.DataFrame):
    """Create executive dashboard charts."""

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
    owner_stats = owner_stats.sort_values('Total Failures', ascending=False)

    # Top contributors
    top_n = 10
    top_owners = owner_stats.head(top_n).copy()
    others_count = owner_stats.iloc[top_n:]['Total Failures'].sum() if len(owner_stats) > top_n else 0
    others_pct = (others_count / total_failures * 100).round(1)
    top_total_pct = top_owners['Percentage'].sum()

    # Pie chart
    pie_labels = [f"{o[:20]}..." if len(o) > 20 else o for o in top_owners['Owner']]
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
    bar_labels = [(o[:25] + '...' if len(o) > 25 else o) for o in top_owners_sorted['Owner'].tolist()]
    bar_values = top_owners_sorted['Total Failures'].tolist()
    bar_pcts = top_owners_sorted['Percentage'].tolist()
    bar_accounts = top_owners_sorted['Account IDs'].tolist()

    fig_bar = go.Figure(go.Bar(
        x=bar_values,
        y=bar_labels,
        orientation='h',
        marker_color='#e74c3c',
        text=[f"{v:,} ({p}%)" for v, p in zip(bar_values, bar_pcts)],
        textposition='inside',
        textfont=dict(color='white', size=12),
        insidetextanchor='end',
        hovertext=[f"{o}<br>Failures: {v:,}<br>% of Total: {p}%<br>Accounts: {', '.join(map(str, a[:3]))}"
                   for o, v, p, a in zip(bar_labels, bar_values, bar_pcts, bar_accounts)],
        hoverinfo='text'
    ))
    fig_bar.update_layout(
        title=dict(text=f'<b>Top {top_n} Contributors = {top_total_pct:.0f}% of All Failures</b>', x=0.5, font=dict(size=16)),
        height=500,
        margin=dict(t=60, b=60, l=200, r=60),
        xaxis=dict(title='Total Failures', tickformat=',d', rangemode='tozero'),
        plot_bgcolor='#fafafa'
    )

    return fig_pie, fig_bar, total_failures, unique_owners, unique_accounts, top_owners, owner_stats


def create_person_charts(df: pd.DataFrame, top_owners: pd.DataFrame):
    """Create per-person breakdown charts."""

    person_charts = []
    top_5_owners = top_owners.sort_values('Total Failures', ascending=False).head(5)

    for _, row in top_5_owners.iterrows():
        owner = row['Owner']
        owner_df = df[df['Zones'] == owner]

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

        accounts_str = ', '.join(map(str, row['Account IDs'][:3]))
        if len(row['Account IDs']) > 3:
            accounts_str += f" (+{len(row['Account IDs'])-3} more)"

        fig_person.update_layout(
            title=dict(
                text=f"<b>{owner[:35]}</b><br>{row['Total Failures']:,} failures ({row['Percentage']}%) across {total_unique_controls} controls<br>Accounts: {accounts_str}",
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


def create_security_charts(df: pd.DataFrame):
    """Create security team dashboard charts."""

    # Treemap
    treemap_data = df.groupby(['Zones', 'Control Severity', 'Control Name']).size().reset_index(name='Count')

    fig_treemap = px.treemap(
        treemap_data,
        path=['Zones', 'Control Severity', 'Control Name'],
        values='Count',
        color='Control Severity',
        color_discrete_map={'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'},
        title='<b>Security Posture Drill-Down</b><br><sup>Click to explore: Owner > Severity > Control</sup>'
    )
    fig_treemap.update_layout(height=700)
    fig_treemap.update_traces(textinfo='label+value')

    # Heatmap
    pivot = df.pivot_table(
        index='Zones',
        columns='Control Name',
        values='Resource ID',
        aggfunc='count',
        fill_value=0
    )

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
        title='<b>Owner vs Control Failure Matrix</b>',
        xaxis_title='Control Name',
        yaxis_title='Owner',
        height=600,
        xaxis=dict(tickangle=45, tickfont=dict(size=9)),
        yaxis=dict(tickfont=dict(size=10))
    )

    # Severity breakdown
    owner_severity = df.groupby(['Zones', 'Control Severity']).size().reset_index(name='Count')
    top_10_owners = df['Zones'].value_counts().head(10).index.tolist()
    owner_severity_filtered = owner_severity[owner_severity['Zones'].isin(top_10_owners)]

    fig_severity = go.Figure()
    for severity in ['High', 'Medium', 'Low', 'Info']:
        sev_data = owner_severity_filtered[owner_severity_filtered['Control Severity'] == severity]
        if not sev_data.empty:
            fig_severity.add_trace(go.Bar(
                name=severity,
                x=sev_data['Zones'],
                y=sev_data['Count'],
                marker_color={'High': '#e74c3c', 'Medium': '#f39c12', 'Low': '#3498db', 'Info': '#95a5a6'}[severity],
                text=sev_data['Count'],
                textposition='inside'
            ))

    fig_severity.update_layout(
        barmode='stack',
        title='<b>Severity Breakdown by Owner (Top 10)</b>',
        height=500,
        xaxis=dict(tickangle=45),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='right', x=1)
    )

    return fig_treemap, fig_heatmap, fig_severity


def create_downloadable_reports(df: pd.DataFrame, owner_stats: pd.DataFrame):
    """Create downloadable CSV reports."""

    # Owner summary
    owner_export = owner_stats.copy()
    owner_export['Account IDs'] = owner_export['Account IDs'].apply(lambda x: ', '.join(map(str, x)))

    # Actionable report
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


def main():
    st.title("Sysdig Posture Report Analytics")
    st.markdown("Upload your posture report CSV to generate executive and security dashboards.")

    # Sidebar for file upload
    with st.sidebar:
        st.header("Upload Data")
        uploaded_file = st.file_uploader(
            "Choose a CSV file",
            type=['csv', 'gz'],
            help="Upload a CSV or gzipped CSV file from Sysdig posture report"
        )

        if uploaded_file:
            st.success(f"Loaded: {uploaded_file.name}")

    if not uploaded_file:
        st.info("Please upload a CSV file using the sidebar to get started.")

        st.markdown("---")
        st.markdown("### How to use")
        st.markdown("""
        1. Export your posture report from Sysdig as CSV
        2. Upload the file using the sidebar
        3. View the generated dashboards below
        4. Download summary reports as needed
        """)
        return

    # Load and process data
    with st.spinner("Loading and processing data..."):
        try:
            df_full, df = load_data(uploaded_file)
        except Exception as e:
            st.error(f"Error loading file: {e}")
            return

    # Display metrics
    st.markdown("---")
    fig_pie, fig_bar, total_failures, unique_owners, unique_accounts, top_owners, owner_stats = create_executive_charts(df)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Failures", f"{total_failures:,}")
    col2.metric("Unique Owners", f"{unique_owners}")
    col3.metric("Accounts", f"{unique_accounts}")

    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["Executive Dashboard", "Security Drill-Down", "Download Reports"])

    with tab1:
        st.markdown("### Executive Summary: Who Should We Engage First?")

        col1, col2 = st.columns(2)
        with col1:
            st.plotly_chart(fig_pie, use_container_width=True)
        with col2:
            st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown("---")
        st.markdown("### Top 5 Contributors - What Controls to Fix First")

        # Severity legend
        st.markdown("""
        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <span><span style="background:#e74c3c; padding: 2px 10px; border-radius: 4px; color: white;">High</span></span>
            <span><span style="background:#f39c12; padding: 2px 10px; border-radius: 4px; color: white;">Medium</span></span>
            <span><span style="background:#3498db; padding: 2px 10px; border-radius: 4px; color: white;">Low</span></span>
            <span><span style="background:#95a5a6; padding: 2px 10px; border-radius: 4px; color: white;">Info</span></span>
        </div>
        """, unsafe_allow_html=True)

        person_charts = create_person_charts(df, top_owners)

        cols = st.columns(2)
        for i, (owner, fig) in enumerate(person_charts):
            with cols[i % 2]:
                st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.markdown("### Security Posture Drill-Down")

        fig_treemap, fig_heatmap, fig_severity = create_security_charts(df)

        st.plotly_chart(fig_treemap, use_container_width=True)

        st.markdown("---")
        st.markdown("### Owner vs Control Failure Matrix")
        st.plotly_chart(fig_heatmap, use_container_width=True)

        st.markdown("---")
        st.markdown("### Severity Breakdown by Owner")
        st.plotly_chart(fig_severity, use_container_width=True)

    with tab3:
        st.markdown("### Download Reports")

        owner_export, action_df = create_downloadable_reports(df, owner_stats)

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


if __name__ == "__main__":
    main()
