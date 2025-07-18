import streamlit as st
import pandas as pd
import sys
from pathlib import Path
import logging
from modules.utils import load_config, setup_logging, validate_domain, validate_ip, is_valid_url
from project_manager import ProjectManager
from modules.tools.subdomain_scanner import SubdomainScanner
from modules.tools.port_scanner import PortScanner
from modules.tools.js_analyzer import JSAnalyzer
from modules.tools.webanalyze_scanner import WebanalyzeScanner
from modules.tools.gf_scanner import GFScanner

# Load configuration and setup logging
CONFIG = load_config()
setup_logging(CONFIG)
logger = logging.getLogger(__name__)

st.set_page_config(layout="wide", page_title="Reconnaissance Tools")

# Initialize ProjectManager
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance

st.title("🕵️ Reconnaissance Tools")
st.markdown("Perform various reconnaissance tasks on your target. Scans will run synchronously and display results upon completion.")

# Sync current project with session state
if 'current_project_name' not in st.session_state:
    st.session_state.current_project_name = project_manager.get_current_project_name()
elif st.session_state.current_project_name != project_manager.get_current_project_name():
    st.session_state.current_project_name = project_manager.get_current_project_name()

# Display current project status
current_project_name = st.session_state.get('current_project_name')
if current_project_name:
    st.sidebar.success(f"Active Project: **{current_project_name}**")
else:
    st.sidebar.warning("No project selected. Please go to 'Projects' to create or load one.")
    st.info("Please select or create a project on the 'Projects' page to use reconnaissance tools.")
    st.stop()

# Input for the target domain
st.subheader("Target Configuration")

all_project_targets_data = project_manager.get_all_targets_for_current_project()
available_targets = sorted(list(all_project_targets_data.keys()))

selected_target_domain = None
if available_targets:
    target_selection_method = st.radio(
        "Select Target Input Method:",
        ("Select from existing project targets", "Enter New Target Domain"),
        key="recon_target_method"
    )
    if target_selection_method == "Select from existing project targets":
        selected_target_domain = st.selectbox(
            "Select a target domain from your project:",
            [''] + available_targets,
            key="recon_select_target"
        )
        if selected_target_domain == '':
            selected_target_domain = None
    else:
        selected_target_domain = st.text_input("Enter New Target Domain (e.g., example.com):", key="recon_new_target")
else:
    selected_target_domain = st.text_input("Enter Target Domain (e.g., example.com):", key="recon_new_target_only")

target_domain = selected_target_domain.strip() if selected_target_domain else ""

if not target_domain or not validate_domain(target_domain):
    st.warning("Please enter a valid target domain to proceed with reconnaissance scans.")
    st.stop()

# Initialize scanners
subdomain_scanner = SubdomainScanner(CONFIG)
port_scanner = PortScanner(CONFIG)
js_analyzer = JSAnalyzer(CONFIG)
webanalyze_scanner = WebanalyzeScanner(CONFIG)
gf_scanner = GFScanner(CONFIG)

# Create tabs
recon_tab, port_scan_tab, js_analysis_tab, tech_detection_tab, vuln_detection_tab = st.tabs([
    "Subdomain & Takeover Scan",
    "Port Scanning",
    "JavaScript Analysis",
    "Technology Detection",
    "Vulnerability Detection"
])

# --- Subdomain & Takeover Scan Tab ---
with recon_tab:
    st.subheader(f"Subdomain & Takeover Scan for: `{target_domain}`")
    st.info("Discover subdomains and check for subdomain takeovers.")

    if st.button("Run Subdomain Scan", key="run_subdomain_scan"):
        with st.spinner("Running subdomain scan..."):
            progress_bar = st.progress(0.0, text="Initializing...")
            try:
                subdomains_df_dict = {
                    "subfinder_subdomains": pd.DataFrame(),
                    "amass_subdomains": pd.DataFrame(),
                    "resolved_subdomains": pd.DataFrame(),
                    "live_hosts": pd.DataFrame()
                }

                progress_bar.progress(0.2, "Running Subfinder...")
                subfinder_results = subdomain_scanner._run_subfinder(target_domain)
                if subfinder_results:
                    subdomains_df_dict["subfinder_subdomains"] = pd.DataFrame({'Subdomain': subfinder_results})

                progress_bar.progress(0.4, "Running Amass...")
                amass_results = subdomain_scanner._run_amass(target_domain)
                if amass_results:
                    subdomains_df_dict["amass_subdomains"] = pd.DataFrame({'Subdomain': amass_results})

                all_subdomains = list(set(subfinder_results + amass_results))

                progress_bar.progress(0.6, "Resolving DNS records...")
                dns_results = subdomain_scanner._run_dnsx(all_subdomains)
                if dns_results:
                    subdomains_df_dict["resolved_subdomains"] = pd.DataFrame(dns_results)

                progress_bar.progress(0.8, "Probing HTTP services...")
                http_results = subdomain_scanner._run_httpx(all_subdomains)
                if http_results:
                    subdomains_df_dict["live_hosts"] = pd.DataFrame(http_results)

                progress_bar.progress(1.0, "Scan completed!")
                st.success(f"Subdomain scan for {target_domain} completed!")
                
                if any(not df.empty for df in subdomains_df_dict.values()):
                    for key, df in subdomains_df_dict.items():
                        if not df.empty:
                            st.markdown(f"#### {key.replace('_', ' ').title()}")
                            st.dataframe(df, use_container_width=True)
                            project_manager.save_scan_results(key, target_domain, df)
                else:
                    st.info(f"No subdomains or live hosts found for {target_domain}.")
            except Exception as e:
                st.error(f"Subdomain scan failed: {str(e)}")

    st.markdown("---")
    st.subheader("Current Project Subdomain Results")
    current_results_displayed = False
    
    display_keys = ["subfinder_subdomains", "amass_subdomains", "resolved_subdomains", "live_hosts"]
    
    for key in display_keys:
        current_df = project_manager.load_scan_results(key, target_domain)
        if isinstance(current_df, pd.DataFrame) and not current_df.empty:
            st.markdown(f"##### {key.replace('_', ' ').title()}")
            st.dataframe(current_df, use_container_width=True)
            current_results_displayed = True
    
    if not current_results_displayed:
        st.info("No subdomain results saved for this target in the current project.")

    st.markdown("---")
    st.subheader("Subdomain Takeover Scan")
    st.info("Manually check for potential subdomain takeovers using DNScheck.")

    if st.button("Run Subdomain Takeover Scan", key="run_subdomain_takeover_scan"):
        resolved_subdomains_df = project_manager.load_scan_results('resolved_subdomains', target_domain)
        if isinstance(resolved_subdomains_df, pd.DataFrame) and not resolved_subdomains_df.empty:
            with st.spinner("Running subdomain takeover scan..."):
                progress_bar = st.progress(0.0, text="Starting takeover scan...")
                try:
                    takeover_results = subdomain_scanner.run_subdomain_takeover_scan(
                        resolved_subdomains_df,
                        progress_callback=lambda p, s: progress_bar.progress(p, s)
                    )
                    progress_bar.progress(1.0, "Takeover scan completed!")
                    
                    if not takeover_results.empty:
                        st.success(f"Found {len(takeover_results)} potential takeovers!")
                        st.dataframe(takeover_results, use_container_width=True)
                        project_manager.save_scan_results('subdomain_takeovers', target_domain, takeover_results)
                    else:
                        st.info("No takeovers detected.")
                except Exception as e:
                    st.error(f"Takeover scan failed: {str(e)}")
        else:
            st.warning("No resolved subdomains found. Run a subdomain scan first.")

    takeover_results = project_manager.load_scan_results('subdomain_takeovers', target_domain)
    if isinstance(takeover_results, pd.DataFrame) and not takeover_results.empty:
        st.markdown("---")
        st.subheader("Current Takeover Results")
        st.dataframe(takeover_results, use_container_width=True)
    else:
        st.info("No takeover results saved for this target.")

# --- Port Scanning Tab ---
with port_scan_tab:
    st.subheader(f"Port Scanning for: `{target_domain}`")
    st.info("Identify open ports on the target domain/IP using Nmap or Masscan.")

    port_scan_target_input = st.text_input("Enter Target for Port Scan (domain or IP):", target_domain, key="port_scan_specific_target")
    port_scan_tool = st.selectbox(
        "Select Port Scanning Tool:",
        ("nmap", "masscan"),
        key="port_scan_tool",
        help="Nmap provides detailed results but can be slower. Masscan is faster for initial discovery of many hosts."
    )

    if st.button("Run Port Scan", key="run_port_scan"):
        if not port_scan_target_input:
            st.error("Please enter a target for port scanning.")
        elif not validate_domain(port_scan_target_input) and not validate_ip(port_scan_target_input):
            st.error("Please enter a valid domain or IP address for port scanning.")
        else:
            with st.spinner("Running port scan..."):
                progress_bar = st.progress(0.0, text="Starting port scan...")
                try:
                    ports_df = port_scanner.run_port_scan(
                        target=port_scan_target_input,
                        tool=port_scan_tool,
                        progress_callback=lambda p, s: progress_bar.progress(p, s)
                    )
                    progress_bar.progress(1.0, "Port scan completed!")
                    
                    if not ports_df.empty:
                        st.success(f"Found {len(ports_df)} open ports for {port_scan_target_input}.")
                        st.dataframe(ports_df, use_container_width=True)
                        project_manager.save_scan_results('ports', port_scan_target_input, ports_df)
                    else:
                        st.info(f"No open ports found for {port_scan_target_input}.")
                except Exception as e:
                    st.error(f"Port scan failed: {str(e)}")

    current_ports_from_project = project_manager.load_scan_results('ports', port_scan_target_input)
    if isinstance(current_ports_from_project, pd.DataFrame) and not current_ports_from_project.empty:
        st.markdown("---")
        st.subheader("Current Project Port Scan Results")
        st.dataframe(current_ports_from_project, use_container_width=True)
    else:
        st.info("No port scan results saved for this target in the current project.")

# --- JavaScript Analysis Tab ---
with js_analysis_tab:
    st.subheader(f"JavaScript Analysis for: `{target_domain}`")
    st.info("Extract JavaScript files, identify endpoints, and discover sensitive data using Fakjs.")

    current_live_hosts_df = project_manager.load_scan_results('live_hosts', target_domain)
    urls_for_js_analysis = []
    if isinstance(current_live_hosts_df, pd.DataFrame) and not current_live_hosts_df.empty:
        if 'URL' in current_live_hosts_df.columns:
            urls_for_js_analysis = current_live_hosts_df['URL'].tolist()
        else:
            st.warning("Live hosts DataFrame doesn't contain 'URL' column. Trying to use index (may not be URLs).")
            urls_for_js_analysis = current_live_hosts_df.index.tolist()
    
    urls_for_js_analysis = [url for url in urls_for_js_analysis if is_valid_url(url)]
    urls_for_js_analysis = list(set(urls_for_js_analysis))

    if not urls_for_js_analysis:
        st.warning("No active URLs found for JavaScript analysis. Using main domain as fallback.")
        urls_for_js_analysis = [f"https://{target_domain}"]
        if f"http://{target_domain}" not in urls_for_js_analysis:
            urls_for_js_analysis.append(f"http://{target_domain}")
    
    st.info(f"Will analyze JavaScript from {len(urls_for_js_analysis)} URLs.")

    if st.button("Run JavaScript Analysis", key="run_js_analysis"):
        with st.spinner("Running JavaScript analysis..."):
            progress_bar = st.progress(0.0, text="Starting JS analysis...")
            try:
                js_results = js_analyzer.analyze_js_for_project(
                    urls_for_js_analysis,
                    progress_callback=lambda p, s: progress_bar.progress(p, s)
                )
                progress_bar.progress(1.0, "JS analysis completed!")
                
                if any(isinstance(df, pd.DataFrame) and not df.empty for df in js_results.values()):
                    st.success("JavaScript analysis completed!")
                    
                    if not js_results["js_files"].empty:
                        st.subheader("Discovered JavaScript Files")
                        st.dataframe(js_results["js_files"], use_container_width=True)
                        project_manager.save_scan_results('js_files', target_domain, js_results["js_files"])
                    
                    if not js_results["discovered_endpoints"].empty:
                        st.subheader("Discovered Endpoints")
                        st.dataframe(js_results["discovered_endpoints"], use_container_width=True)
                        project_manager.save_scan_results('js_discovered_endpoints', target_domain, js_results["discovered_endpoints"])

                    if not js_results["sensitive_data_findings"].empty:
                        st.subheader("Sensitive Data Findings (Fakjs)")
                        st.dataframe(js_results["sensitive_data_findings"], use_container_width=True)
                        project_manager.save_scan_results('js_sensitive_data_findings', target_domain, js_results["sensitive_data_findings"])
                else:
                    st.info("No JavaScript analysis results found.")
            except Exception as e:
                st.error(f"JavaScript analysis failed: {str(e)}")

    st.markdown("---")
    st.subheader("Existing JavaScript Analysis Results")
    
    js_result_types_to_load = {
        'js_files': "Discovered JavaScript Files",
        'js_discovered_endpoints': "Discovered Endpoints",
        'js_sensitive_data_findings': "Sensitive Data Findings (Fakjs)"
    }
    any_results_loaded = False
    
    for key_suffix, display_title in js_result_types_to_load.items():
        df = project_manager.load_scan_results(key_suffix, target_domain)
        if isinstance(df, pd.DataFrame) and not df.empty:
            st.markdown(f"#### {display_title}")
            st.dataframe(df, use_container_width=True)
            any_results_loaded = True
    
    if not any_results_loaded:
        st.info("No JavaScript analysis results saved for this target in the current project.")

# --- Technology Detection Tab ---
with tech_detection_tab:
    st.subheader(f"Technology Detection for: `{target_domain}`")
    st.info("Detect web technologies used by the target using Webanalyze.")

    urls_for_tech_detection = []
    current_live_hosts_df = project_manager.load_scan_results('live_hosts', target_domain)
    if isinstance(current_live_hosts_df, pd.DataFrame) and 'URL' in current_live_hosts_df.columns:
        urls_for_tech_detection.extend(current_live_hosts_df['URL'].tolist())
            
    urls_for_tech_detection = list(set(urls_for_tech_detection))

    st.markdown("---")
    st.info("It is recommended to update Webanalyze definitions regularly.")

    if st.button("Update Webanalyze Definitions", key="update_webanalyze_defs"):
        with st.spinner("Updating Webanalyze definitions..."):
            progress_bar = st.progress(0.0, text="Updating definitions...")
            try:
                success = webanalyze_scanner.update_technologies(
                    progress_callback=lambda p, s: progress_bar.progress(p, s)
                )
                progress_bar.progress(1.0, "Update completed!")
                if success:
                    st.success("Webanalyze definitions updated successfully!")
                else:
                    st.error("Failed to update Webanalyze definitions.")
            except Exception as e:
                st.error(f"Webanalyze definitions update failed: {str(e)}")

    if not urls_for_tech_detection:
        st.warning("No active URLs found from subdomain enumeration for Technology Detection. Run a 'Subdomain Scan' first.")
        urls_for_tech_detection = [f"https://{target_domain}", f"http://{target_domain}"]
        st.info(f"Proceeding with main target domain: {target_domain} for technology detection.")
    else:
        st.write(f"Preparing to detect technologies on {len(urls_for_tech_detection)} URLs.")

    if st.button("Run Technology Detection", key="run_tech_detection"):
        with st.spinner("Running technology detection..."):
            progress_bar = st.progress(0.0, text="Starting Webanalyze scan...")
            try:
                tech_df = webanalyze_scanner.perform_scan(
                    urls_for_tech_detection,
                    progress_callback=lambda p, s: progress_bar.progress(p, s)
                )
                progress_bar.progress(1.0, "Technology detection completed!")
                
                if not tech_df.empty:
                    st.success(f"Found {len(tech_df)} technologies for {target_domain}.")
                    st.dataframe(tech_df, use_container_width=True)
                    project_manager.save_scan_results('webanalyze_techs', target_domain, tech_df)
                else:
                    st.info(f"No technologies detected for {target_domain}.")
            except Exception as e:
                st.error(f"Technology detection failed: {str(e)}")

    current_tech_results_from_project = project_manager.load_scan_results('webanalyze_techs', target_domain)
    if isinstance(current_tech_results_from_project, pd.DataFrame) and not current_tech_results_from_project.empty:
        st.markdown("---")
        st.subheader("Current Project Technology Detection Results")
        st.dataframe(current_tech_results_from_project, use_container_width=True)
    else:
        st.info("No technology detection results saved for this target in the current project.")

# --- Vulnerability Detection Tab ---
with vuln_detection_tab:
    st.subheader(f"Vulnerability Detection for: `{target_domain}`")
    st.info("Perform vulnerability detection using Paramspider and GF with multiple patterns for SQLi, XSS, LFI, etc.")

    urls_for_vuln_detection = []
    current_live_hosts_df = project_manager.load_scan_results('live_hosts', target_domain)
    if isinstance(current_live_hosts_df, pd.DataFrame) and 'URL' in current_live_hosts_df.columns:
        urls_for_vuln_detection.extend(current_live_hosts_df['URL'].tolist())
    
    current_js_endpoints_df = project_manager.load_scan_results('js_discovered_endpoints', target_domain)
    if isinstance(current_js_endpoints_df, pd.DataFrame) and 'Endpoint' in current_js_endpoints_df.columns:
        urls_for_vuln_detection.extend(current_js_endpoints_df['Endpoint'].tolist())

    urls_for_vuln_detection = list(set(urls_for_vuln_detection))
    urls_for_vuln_detection = [url for url in urls_for_vuln_detection if is_valid_url(url)]
    
    if not urls_for_vuln_detection:
        st.warning("No active URLs discovered from previous subdomain or JS scans. Vulnerability detection might not find many targets.")
        urls_for_vuln_detection = [f"https://{target_domain}", f"http://{target_domain}"]
        st.info(f"Proceeding with main target domain: {target_domain} for vulnerability detection (no other active URLs found).")
    else:
        st.info(f"Preparing to scan {len(urls_for_vuln_detection)} URLs for vulnerabilities.")

    if st.button("Run Vulnerability Detection", key="run_vuln_detection"):
        if not target_domain:
            st.warning("Please select a target domain first.")
        else:
            with st.spinner("Running vulnerability detection..."):
                progress_bar = st.progress(0.0, text="Starting vulnerability scan workflow (Paramspider -> GF)...")
                try:
                    vuln_results = gf_scanner.perform_scan(
                        urls_for_vuln_detection,
                        progress_callback=lambda p, s: progress_bar.progress(p, s)
                    )
                    progress_bar.progress(1.0, "Vulnerability scan completed!")
                    
                    if not vuln_results["paramspider_urls"].empty:
                        st.subheader("Discovered URLs with Parameters (Paramspider)")
                        st.dataframe(vuln_results["paramspider_urls"], use_container_width=True)
                        project_manager.save_scan_results('paramspider_urls', target_domain, vuln_results["paramspider_urls"])
                    else:
                        st.info("Paramspider did not discover any URLs with parameters.")

                    if not vuln_results["gf_filtered_urls"].empty:
                        st.subheader("GF Filtered URLs (Potential Vulnerabilities)")
                        st.dataframe(vuln_results["gf_filtered_urls"], use_container_width=True)
                        project_manager.save_scan_results('gf_vuln_urls', target_domain, vuln_results["gf_filtered_urls"])
                    else:
                        st.info("GF did not find any URLs matching vulnerability patterns.")

                    if any(isinstance(df, pd.DataFrame) and not df.empty for df in vuln_results.values()):
                        st.success(f"Vulnerability scan for {target_domain} complete with findings!")
                    else:
                        st.info(f"Vulnerability scan for {target_domain} completed. No vulnerabilities found.")
                except Exception as e:
                    st.error(f"Vulnerability detection failed: {str(e)}")

    st.subheader("Existing Vulnerability Scan Results")
    existing_paramspider_urls = project_manager.load_scan_results('paramspider_urls', target_domain)
    if isinstance(existing_paramspider_urls, pd.DataFrame) and not existing_paramspider_urls.empty:
        st.markdown("##### Discovered URLs with Parameters (Paramspider)")
        st.dataframe(existing_paramspider_urls, use_container_width=True)
    
    existing_gf_vuln_urls = project_manager.load_scan_results('gf_vuln_urls', target_domain)
    if isinstance(existing_gf_vuln_urls, pd.DataFrame) and not existing_gf_vuln_urls.empty:
        st.markdown("##### GF Filtered URLs (Potential Vulnerabilities)")
        st.dataframe(existing_gf_vuln_urls, use_container_width=True)
        st.write("**Matched Patterns:** Each URL is associated with the GF pattern it matched (e.g., sqli, xss, lfi, open-redirect) in the 'Matched_Pattern' column.")

    if existing_paramspider_urls.empty and existing_gf_vuln_urls.empty:
        st.info("No vulnerability scan results saved for this target in the current project.")