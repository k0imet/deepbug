import streamlit as st
import pandas as pd
import sys
from pathlib import Path
import plotly.graph_objects as go

# Add the modules directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'modules'))

from modules.project_manager import ProjectManager
from modules.utils import load_config, setup_logging

# Load configuration and setup logging
CONFIG = load_config()
setup_logging(CONFIG)

st.set_page_config(layout="wide", page_title="Dashboard")

# Initialize ProjectManager
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager: ProjectManager = st.session_state.project_manager_instance

# Sync current project with session state
if 'current_project_name' not in st.session_state:
    st.session_state.current_project_name = project_manager.get_current_project_name()
elif st.session_state.current_project_name != project_manager.get_current_project_name():
    st.session_state.current_project_name = project_manager.get_current_project_name()

# Get current project
current_project = st.session_state.get('current_project_name')
if not current_project:
    st.sidebar.warning("No project selected. Please go to 'Projects' to create or load one.")
    st.info("Please select or create a project on the 'Projects' page to view the dashboard.")
    st.stop()

st.title("📊 Dashboard")
st.markdown(f"### Project: **{current_project}**")
st.markdown("View scan results and metrics for the current project.")

# --- Data Processing Functions ---
def process_scan_results(all_results: dict, vuln_state: dict = None) -> dict:
    """Process raw scan results into structured summary data."""
    summary = {
        "metrics": {
            "subdomains": 0,
            "open_ports": 0,
            "js_files": 0,
            "vulnerabilities": 0,
            "takeovers": 0,
            "endpoints": 0
        },
        "scan_details": [],
        "target_summary": {},
        "ongoing_scans": [],
        "severity_counts": {}
    }

    # Process historical results from ProjectManager
    for scan_type, targets_data in all_results.items():
        for target, results in targets_data.items():
            if target not in summary["target_summary"]:
                summary["target_summary"][target] = {
                    "subdomains": 0,
                    "open_ports": 0,
                    "js_files": 0,
                    "vulnerabilities": 0,
                    "takeovers": 0
                }

            if isinstance(results, pd.DataFrame):
                count = len(results)
                
                if scan_type == "live_hosts":
                    summary["metrics"]["subdomains"] += count
                    summary["target_summary"][target]["subdomains"] = count
                elif scan_type == "ports":
                    summary["metrics"]["open_ports"] += count
                    summary["target_summary"][target]["open_ports"] = count
                elif scan_type == "subdomain_takeovers":
                    summary["metrics"]["takeovers"] += count
                    summary["target_summary"][target]["takeovers"] = count
                elif scan_type == "gf_vuln_urls":
                    summary["metrics"]["vulnerabilities"] += count
                    summary["target_summary"][target]["vulnerabilities"] = count
                    if 'Severity' in results.columns:
                        severity_counts = results['Severity'].value_counts().to_dict()
                        for severity, count in severity_counts.items():
                            summary["severity_counts"][severity] = summary["severity_counts"].get(severity, 0) + count

                summary["scan_details"].append({
                    "type": scan_type.replace('_', ' ').title(),
                    "target": target,
                    "count": count,
                    "data": results
                })

            elif isinstance(results, dict):  # For nested results like JS analysis
                js_file_count = 0
                details = {}
                
                for sub_type, df in results.items():
                    if isinstance(df, pd.DataFrame):
                        sub_count = len(df)
                        details[sub_type] = sub_count
                        
                        if sub_type == "js_files":
                            js_file_count = sub_count
                            summary["metrics"]["js_files"] += sub_count
                            summary["target_summary"][target]["js_files"] = sub_count
                        elif sub_type == "js_discovered_endpoints":
                            summary["metrics"]["endpoints"] += sub_count

                summary["scan_details"].append({
                    "type": scan_type.replace('_', ' ').title(),
                    "target": target,
                    "count": js_file_count,
                    "details": details,
                    "data": results
                })

    # Process ongoing vulnerability scan from Scanner page
    vuln_state = vuln_state or {}
    if vuln_state.get('status') == 'running':
        summary["ongoing_scans"].append({
            "type": "Vulnerability Scan",
            "progress": vuln_state.get('progress', 0.0),
            "message": vuln_state.get('message', ''),
            "target": vuln_state.get('target', 'Unknown')
        })
    elif vuln_state.get('status') == 'completed' and vuln_state.get('results') is not None:
        target = vuln_state.get('target', 'Unknown')
        results = vuln_state['results']
        count = len(results)
        summary["metrics"]["vulnerabilities"] += count
        summary["target_summary"].setdefault(target, {"vulnerabilities": 0})["vulnerabilities"] = count
        if 'Severity' in results.columns:
            severity_counts = results['Severity'].value_counts().to_dict()
            for severity, count in severity_counts.items():
                summary["severity_counts"][severity] = summary["severity_counts"].get(severity, 0) + count
        summary["scan_details"].append({
            "type": "Vulnerabilities",
            "target": target,
            "count": count,
            "data": results
        })

    return summary

# --- Main Dashboard Content ---
all_project_results = project_manager.get_all_results_for_current_project()
vuln_state = st.session_state.get('scan_status', {})

# Process results (no caching to avoid UnhashableParamError)
summary = process_scan_results(all_project_results, vuln_state)

# --- Ongoing Scans Display ---
if summary["ongoing_scans"]:
    st.subheader("⏳ Ongoing Scans")
    for scan in summary["ongoing_scans"]:
        st.write(f"**{scan['type']}** (Target: {scan['target']}): {scan['message']}")
        st.progress(scan['progress'])
    st.info("Vulnerability scans may be running from the Scanner page. Check back or click 'Refresh Dashboard' to see updated results.")
    st.markdown("---")

# Refresh button
if st.button("Refresh Dashboard", key="refresh_dashboard"):
    st.rerun()

# --- Metrics Display ---
st.subheader("📈 Key Metrics")
cols = st.columns(5)
metrics = [
    ("Subdomains", "subdomains", "🌐"),
    ("Open Ports", "open_ports", "🔌"),
    ("JS Files", "js_files", "📜"),
    ("Vulnerabilities", "vulnerabilities", "⚠️"),
    ("Takeovers", "takeovers", "🎯")
]

for i, (title, key, icon) in enumerate(metrics):
    cols[i].metric(f"{icon} {title}", summary["metrics"][key])

# --- Visualizations ---
if any(summary["metrics"][key] > 0 for key in ["subdomains", "open_ports", "js_files", "vulnerabilities", "takeovers"]):
    st.subheader("📊 Scan Results Distribution")
    st.markdown("Bar chart showing the count of scan results by type across all targets.")
    
    # Create DataFrame for bar chart
    chart_data = pd.DataFrame({
        "Scan Type": ["Subdomains", "Open Ports", "JS Files", "Vulnerabilities", "Takeovers"],
        "Count": [
            summary["metrics"]["subdomains"],
            summary["metrics"]["open_ports"],
            summary["metrics"]["js_files"],
            summary["metrics"]["vulnerabilities"],
            summary["metrics"]["takeovers"]
        ]
    })
    st.bar_chart(chart_data.set_index("Scan Type"))

if summary["severity_counts"]:
    st.subheader("🔍 Vulnerability Severity Distribution")
    st.markdown("Pie chart showing the distribution of vulnerabilities by severity.")
    
    # Create Plotly pie chart
    fig = go.Figure(data=[
        go.Pie(
            labels=list(summary["severity_counts"].keys()),
            values=list(summary["severity_counts"].values()),
            marker=dict(
                colors=['#F44336', '#FFC107', '#2196F3', '#4CAF50'],
                line=dict(color='#000000', width=1)
            )
        )
    ])
    fig.update_layout(
        legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5)
    )
    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# --- Target Summary ---
st.subheader("🎯 Target Overview")
if summary["target_summary"]:
    target_df = pd.DataFrame.from_dict(summary["target_summary"], orient='index')
    st.dataframe(
        target_df.style.highlight_max(axis=0, color='#000000'),
        use_container_width=True
    )
else:
    st.info("No target-specific data available yet.")

st.markdown("---")

# --- Detailed Scan Results ---
st.subheader("🔍 Detailed Results")

if not all_project_results and not summary["scan_details"]:
    st.info("No scan results found for the current project yet. Go to 'Reconnaissance' or 'Vulnerability Scanner' to start scanning!")
else:
    # Group by scan type for better organization
    scan_types = {detail["type"] for detail in summary["scan_details"]}
    
    for scan_type in sorted(scan_types):
        type_details = [d for d in summary["scan_details"] if d["type"] == scan_type]
        
        with st.expander(f"**{scan_type}** (Total: {sum(d['count'] for d in type_details)})"):
            for detail in type_details:
                st.markdown(f"##### 🎯 Target: `{detail['target']}`")
                
                if "details" in detail:  # For complex results like JS analysis
                    st.json(detail["details"])
                    
                    for sub_type, df in detail["data"].items():
                        if isinstance(df, pd.DataFrame) and not df.empty:
                            st.markdown(f"**{sub_type.replace('_', ' ').title()}**")
                            st.dataframe(df, use_container_width=True)
                elif isinstance(detail["data"], pd.DataFrame):
                    if not detail["data"].empty:
                        # Apply styling only if Severity column exists
                        style = (
                            detail["data"].style.apply(
                                lambda x: ['background-color: yellow' if x.get('Severity') == 'HIGH' else '' for _ in x],
                                axis=1
                            )
                            if 'Severity' in detail["data"].columns
                            else detail["data"].style
                        )
                        st.dataframe(style, use_container_width=True)
                    else:
                        st.info(f"No data available for {scan_type} on {detail['target']}")
                
                st.markdown("---")