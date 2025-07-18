import streamlit as st
import pandas as pd
import sys
from pathlib import Path
from urllib.parse import urlparse
import threading
import queue

# Add the modules directory to the Python path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'modules'))

from scanner import VulnerabilityScanner
from project_manager import ProjectManager
from utils import load_config, setup_logging, is_valid_url, validate_domain, validate_ip

# Load configuration and setup logging
CONFIG = load_config()
setup_logging(CONFIG)

st.set_page_config(layout="wide", page_title="Vulnerability Scanner")

# Initialize ProjectManager - Ensure it's done only once and persisted
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager: ProjectManager = st.session_state.project_manager_instance

# Initialize VulnerabilityScanner
scanner_tool = VulnerabilityScanner(CONFIG)

st.title("🛡️ Vulnerability Scanner")
st.markdown("Run automated vulnerability scans using integrated tools. Scans run in the background, so you can navigate to other pages.")

# Sync current project with session state
if 'current_project_name' not in st.session_state:
    st.session_state.current_project_name = project_manager.get_current_project_name()
elif st.session_state.current_project_name != project_manager.get_current_project_name():
    st.session_state.current_project_name = project_manager.get_current_project_name()

current_project = st.session_state.get('current_project_name')
if not current_project:
    st.sidebar.warning("No project selected. Please go to the 'Projects' page to create or load one.")
    st.info("Please select or create a project on the 'Projects' page to use the scanner.")
    st.stop()
else:
    st.sidebar.success(f"Active Project: **{current_project}**")

# Initialize scan state in session_state
if 'scan_status' not in st.session_state:
    st.session_state.scan_status = 'idle'  # Options: 'idle', 'running', 'completed', 'failed'
    st.session_state.scan_progress = 0.0
    st.session_state.scan_message = ''
    st.session_state.scan_results = None
    st.session_state.scan_error = None
    st.session_state.scan_thread = None
    st.session_state.scan_queue = queue.Queue()

# --- Scan Input ---
st.subheader("Scan Target Selection")

# Get all targets from project
all_project_targets = project_manager.get_all_targets_for_current_project()
live_urls = []
selected_target = None

if all_project_targets:
    # Let user select which target to get live hosts from
    selected_target = st.selectbox(
        "Select target domain to load live hosts from:",
        options=list(all_project_targets.keys()),
        key="target_selector"
    )
    
    # Load live hosts for selected target
    if selected_target:
        live_hosts_df = project_manager.load_scan_results('live_hosts', selected_target)
        if isinstance(live_hosts_df, pd.DataFrame) and not live_hosts_df.empty:
            if 'URL' in live_hosts_df.columns:
                live_urls = live_hosts_df['URL'].tolist()
            else:
                st.warning("Live hosts data exists but doesn't contain a 'URL' column.")

# Target selection method
target_selection = st.radio(
    "Select target input method:",
    ("Single URL", "Use Live Hosts from Reconnaissance"),
    horizontal=True
)

targets = []
if target_selection == "Single URL":
    scan_target = st.text_input("Enter target URL (e.g., https://example.com):", key="scanner_target_input")
    if scan_target:
        if is_valid_url(scan_target) or validate_domain(scan_target) or validate_ip(scan_target):
            targets = [scan_target]
        else:
            st.error("Invalid target. Please enter a valid URL, domain, or IP address.")
else:
    if live_urls:
        st.info(f"Found {len(live_urls)} live hosts from reconnaissance for {selected_target}.")
        # Let user select which live hosts to include
        selected_urls = st.multiselect(
            "Select URLs to scan (default: all):",
            live_urls,
            default=live_urls,
            key="live_hosts_selector"
        )
        targets = selected_urls
    else:
        st.warning(f"No live hosts found for {selected_target}. Please run a subdomain scan first.")
        st.info("Falling back to single URL input.")
        scan_target = st.text_input("Enter target URL (e.g., https://example.com):", key="fallback_target_input")
        if scan_target:
            if is_valid_url(scan_target) or validate_domain(scan_target) or validate_ip(scan_target):
                targets = [scan_target]
            else:
                st.error("Invalid target. Please enter a valid URL, domain, or IP address.")

# --- Scan Options ---
st.subheader("Scan Configuration")

# Dynamically get Nuclei template categories
nuclei_templates_base_path = Path(CONFIG['tools']['paths'].get('nuclei_templates', ''))
template_categories = [""] # Start with an empty option for "all templates"

if nuclei_templates_base_path.is_dir():
    # List immediate subdirectories (categories)
    for item in nuclei_templates_base_path.iterdir():
        if item.is_dir():
            template_categories.append(item.name)
    template_categories.sort()

selected_template_category = st.selectbox(
    "Select Nuclei Template Category:",
    options=template_categories,
    help="Select a category to run templates from (e.g., 'cves', 'vulnerabilities'). Leave blank to run all default templates."
)

custom_template_path = st.text_input(
    "Or enter a specific Nuclei template path/name (e.g., 'http/exposed-panels/admin-panel.yaml'):",
    help="This will override the selected category if provided. Path should be relativeShithead to your nuclei-templates directory or a full path to a .yaml file."
)

st.markdown("---")

# --- Scan Status Display ---
if st.session_state.scan_status == 'running':
    st.info("A scan is currently running in the background. You can navigate to other pages, and results will be available here when complete.")
    progress_bar = st.progress(st.session_state.scan_progress, text=st.session_state.scan_message)
elif st.session_state.scan_status == 'completed':
    st.success("Scan completed! Results are displayed below.")
elif st.session_state.scan_status == 'failed':
    st.error(f"Scan failed: {st.session_state.scan_error}")
elif st.session_state.scan_status == 'idle':
    st.info("No scan is currently running.")

# --- Start Scan ---
scan_button = st.button("Start Vulnerability Scan", key="start_vuln_scan_button")

if scan_button:
    if st.session_state.scan_status == 'running':
        st.error("A scan is already running. Please wait for it to complete before starting a new one.")
    elif not targets:
        st.error("Please select or enter at least one valid target for scanning.")
    else:
        # Reset scan state
        st.session_state.scan_status = 'running'
        st.session_state.scan_progress = 0.0
        st.session_state.scan_message = "Initializing scan..."
        st.session_state.scan_results = None
        st.session_state.scan_error = None

        # Determine the final template path to pass to scanner_tool
        final_template_to_scan = None
        if custom_template_path:
            final_template_to_scan = custom_template_path
        elif selected_template_category:
            final_template_to_scan = selected_template_category
        
        # Define the scan function to run in a separate thread
        def run_scan(targets, template_path, queue):
            def update_progress(percentage: float, message: str):
                queue.put(('progress', percentage, message))
            
            try:
                vulnerabilities_df = scanner_tool.run_nuclei_scan(
                    targets=targets,
                    template_path=template_path,
                    progress_callback=update_progress
                )
                queue.put(('result', vulnerabilities_df))
            except Exception as e:
                queue.put(('error', str(e)))
        
        # Start the scan in a background thread
        scan_thread = threading.Thread(target=run_scan, args=(targets, final_template_to_scan, st.session_state.scan_queue))
        scan_thread.daemon = True  # Daemon thread to avoid blocking app shutdown
        scan_thread.start()
        st.session_state.scan_thread = scan_thread
        st.info("Scan started in the background. You can navigate to other pages, and results will be available here when complete.")
        st.rerun()

# --- Check for Scan Updates ---
# Process queue for progress updates or results
while not st.session_state.scan_queue.empty():
    item = st.session_state.scan_queue.get()
    if item[0] == 'progress':
        st.session_state.scan_progress = min(item[1], 1.0)
        st.session_state.scan_message = item[2]
    elif item[0] == 'result':
        st.session_state.scan_status = 'completed'
        st.session_state.scan_results = item[1]
        st.session_state.scan_thread = None
    elif item[0] == 'error':
        st.session_state.scan_status = 'failed'
        st.session_state.scan_error = item[1]
        st.session_state.scan_thread = None
    st.session_state.scan_queue.task_done()

# --- Display Scan Results ---
if st.session_state.scan_status == 'completed' and st.session_state.scan_results is not None:
    vulnerabilities_df = st.session_state.scan_results
    if not vulnerabilities_df.empty:
        st.subheader("Vulnerability Scan Results")
        st.dataframe(vulnerabilities_df, use_container_width=True)
        
        # Create a summary by severity
        if 'Severity' in vulnerabilities_df.columns:
            severity_summary = vulnerabilities_df['Severity'].value_counts().reset_index()
            severity_summary.columns = ['Severity', 'Count']
            st.subheader("Vulnerability Summary by Severity")
            st.dataframe(severity_summary, use_container_width=True)
        
        # Save results for each target
        for target in targets:
            target_domain = target
            if target.startswith(('http://', 'https://')):
                parsed = urlparse(target)
                target_domain = parsed.netloc or target
            
            target_vulns = vulnerabilities_df[vulnerabilities_df['Host'].str.contains(target_domain, case=False, na=False)]
            if not target_vulns.empty:
                try:
                    project_manager.save_scan_results("vulnerabilities", target_domain, target_vulns)
                except Exception as e:
                    st.error(f"Failed to save results for {target_domain}: {e}")
        
        st.info(f"Vulnerability scan results saved to project '{current_project}'.")
    else:
        st.info("No vulnerabilities found for the selected targets with the current templates.")