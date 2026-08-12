import sys
import json
from datetime import datetime
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.modules.utils import load_config
from app.modules.project_manager import ProjectManager
from app.utils.theme import inject_theme, app_header, get_palette

CONFIG = load_config()

inject_theme()
app_header("📊", "Dashboard", "Review scan results, key metrics and recent activity for the active project.")

if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance

current_project = project_manager.get_current_project_name()
if not current_project:
    st.warning("No project selected. Go to Projects.")
    st.stop()

st.markdown(f"### Project: **{current_project}**")

if st.button("🔄 Refresh"):
    st.rerun()
st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def dedupe_df(df, scan_type):
    if not isinstance(df, pd.DataFrame) or df.empty:
        return df
    # Columns holding lists/dicts (e.g. nuclei Extracted_Results) are unhashable
    # and would crash drop_duplicates() - exclude them from dedupe.
    hashable = [c for c in df.columns
                if not df[c].map(lambda v: isinstance(v, (list, dict))).any()]
    if not hashable:
        return df
    if scan_type in ['live_hosts', 'js_files', 'js_discovered_endpoints', 'gf_vuln_urls', 'paramspider_urls']:
        if 'URL' in hashable:
            return df.drop_duplicates(subset=['URL'], keep='last')
    if scan_type == 'subdomain_takeovers':
        if 'Host' in hashable and 'Service' in hashable:
            return df.drop_duplicates(subset=['Host', 'Service'], keep='last')
    if scan_type == 'ports':
        if 'Host' in hashable and 'Port' in hashable:
            return df.drop_duplicates(subset=['Host', 'Port'], keep='last')
    if scan_type == 'webanalyze_techs':
        if 'URL' in hashable and 'Technology' in hashable:
            return df.drop_duplicates(subset=['URL', 'Technology'], keep='last')
    return df.drop_duplicates(subset=hashable)


def get_recent_scans(limit=10):
    project_path = project_manager.get_current_project_path()
    if not project_path or not project_path.is_dir():
        return []
    scans = []
    for target_dir in project_path.iterdir():
        if not target_dir.is_dir() or target_dir.name.startswith('.'):
            continue
        target_name = target_dir.name.replace('_', '.')
        for scan_file in target_dir.glob('*_results.json'):
            try:
                ts = scan_file.stat().st_mtime
                with open(scan_file, 'r') as f:
                    data = json.load(f)
            except (OSError, ValueError):
                continue
            if isinstance(data, list):
                records = len(data)
            elif isinstance(data, dict):
                records = sum(len(v) for v in data.values() if isinstance(v, list))
            else:
                records = 0
            scans.append({
                'Scan Type': scan_file.name.replace('_results.json', '').replace('_', ' ').title(),
                'Target': target_name,
                'Records': records,
                'Last Modified': datetime.fromtimestamp(ts),
            })
    scans.sort(key=lambda r: r['Last Modified'], reverse=True)
    return scans[:limit]


# ---- Process results (disk is the single source of truth) ----
all_results = project_manager.get_all_results_for_current_project()

metrics = {"subdomains": 0, "open_ports": 0, "js_files": 0, "vulnerabilities": 0, "takeovers": 0}
target_summary = {}
severity_counts = {}
scan_details = []

for scan_type, targets_data in all_results.items():
    for target, data in targets_data.items():
        if target not in target_summary:
            target_summary[target] = {"subdomains": 0, "open_ports": 0, "js_files": 0, "vulnerabilities": 0, "takeovers": 0}
        if isinstance(data, pd.DataFrame):
            df = dedupe_df(data, scan_type)
            count = len(df)
            if scan_type == 'live_hosts':
                metrics["subdomains"] += count
                target_summary[target]["subdomains"] = count
            elif scan_type == 'ports':
                metrics["open_ports"] += count
                target_summary[target]["open_ports"] = count
            elif scan_type == 'subdomain_takeovers':
                metrics["takeovers"] += count
                target_summary[target]["takeovers"] = count
            elif scan_type in ['gf_vuln_urls', 'vulnerabilities']:
                metrics["vulnerabilities"] += count
                target_summary[target]["vulnerabilities"] = count
                if 'Severity' in df.columns:
                    for sev, c in df['Severity'].value_counts().items():
                        severity_counts[sev] = severity_counts.get(sev, 0) + c
            scan_details.append({"type": scan_type.replace('_', ' ').title(), "target": target, "count": count, "data": df})
        elif isinstance(data, dict):
            # nested JS analysis
            js_count = 0
            total_count = 0
            for sub_type, sub_df in data.items():
                if isinstance(sub_df, pd.DataFrame):
                    df_deduped = dedupe_df(sub_df, sub_type)
                    total_count += len(df_deduped)
                    if sub_type == 'js_files':
                        js_count = len(df_deduped)
                        metrics["js_files"] += js_count
                        target_summary[target]["js_files"] = js_count
            scan_details.append({"type": "JS Analysis", "target": target, "count": total_count, "data": data})

# ---- Display metrics ----
st.subheader("📈 Key Metrics")
cols = st.columns(5)
metrics_list = [("Subdomains", "subdomains", "🌐"), ("Open Ports", "open_ports", "🔌"),
                ("JS Files", "js_files", "📜"), ("Vulnerabilities", "vulnerabilities", "⚠️"), ("Takeovers", "takeovers", "🎯")]
for i, (label, key, icon) in enumerate(metrics_list):
    cols[i].metric(f"{icon} {label}", metrics[key])

# ---- Charts ----
p = get_palette()
chart_kwargs = dict(paper_bgcolor=p['plotly_bg'], plot_bgcolor=p['plotly_bg'],
                    font=dict(color=p['plotly_text']))
if any(metrics.values()):
    st.subheader("📊 Scan Results Distribution")
    chart_data = pd.DataFrame({
        "Scan Type": ["Subdomains", "Open Ports", "JS Files", "Vulnerabilities", "Takeovers"],
        "Count": [metrics["subdomains"], metrics["open_ports"], metrics["js_files"], metrics["vulnerabilities"], metrics["takeovers"]]
    })
    bar = go.Figure(data=[go.Bar(x=chart_data["Scan Type"], y=chart_data["Count"],
                                 marker_color=p['accent'])])
    bar.update_layout(margin=dict(l=10, r=10, t=10, b=10), **chart_kwargs)
    st.plotly_chart(bar, width='stretch')

if severity_counts:
    st.subheader("🔍 Vulnerability Severity")
    fig = go.Figure(data=[go.Pie(labels=list(severity_counts.keys()), values=list(severity_counts.values()),
                                 marker=dict(colors=['#e5484d', '#f5a524', '#f7d354', '#3ddc97', '#8b5cf6']))])
    fig.update_layout(legend=dict(orientation="h", yanchor="bottom", y=-0.2), **chart_kwargs)
    st.plotly_chart(fig, width='stretch')

# ---- Target summary ----
st.subheader("🎯 Target Overview")
if target_summary:
    df_target = pd.DataFrame.from_dict(target_summary, orient='index')
    st.dataframe(df_target.style.highlight_max(axis=0, color='#3498db'), width='stretch')

# ---- Detailed results ----
st.subheader("🔍 Detailed Results")
if scan_details:
    for detail in scan_details:
        with st.expander(f"**{detail['type']}** – {detail['target']} ({detail['count']} items)"):
            if isinstance(detail['data'], pd.DataFrame):
                st.dataframe(detail['data'], width='stretch')
            elif isinstance(detail['data'], dict):
                for sub_type, df in detail['data'].items():
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        st.markdown(f"**{sub_type.replace('_', ' ').title()}**")
                        st.dataframe(df, width='stretch')
else:
    st.info("No scan results yet.")

# ---- Recent Activity ----
st.subheader("🕒 Recent Activity")
recent = get_recent_scans(limit=10)
if recent:
    st.dataframe(pd.DataFrame(recent), width='stretch')
else:
    st.info("No scans saved yet.")