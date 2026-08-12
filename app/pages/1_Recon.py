import streamlit as st
import pandas as pd
import json
import sys
import os as _os_mod
from pathlib import Path
from typing import List, Dict, Any

_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.utils.url_utils import urlparse
from app.modules.project_manager import ProjectManager
from app.modules.utils import load_config, setup_logging, validate_domain, validate_ip, is_valid_url
from app.modules.tools.subdomain_scanner import SubdomainScanner
from app.modules.tools.port_scanner import PortScanner
from app.modules.tools.js_analyzer import JSAnalyzer
from app.modules.tools.webanalyze_scanner import WebanalyzeScanner
from app.modules.tools.gf_scanner import GFScanner
from app.modules.tools.cloud_enum import CloudScanner
from app.modules.tools.param_miner import ParamMiner
from app.modules.tools.cors_scanner import CORSHeadersScanner
from app.modules.tools.graphql_scanner import GraphQLScanner
from app.modules.tools.idor_scanner import IDORScanner
from app.modules.tools.dependency_confusion import DependencyConfusionScanner
from app.modules.tools.kxss_scanner import KXSSScanner
from app.modules.tools.pp_validator import PrototypePollutionValidator
from app.modules.tools.dom_xss_validator import DOMXSSValidator
from app.modules.tools.cors_validator import CORSValidator
from app.modules.tools.open_redirect_validator import OpenRedirectValidator
from app.modules.tools.ssrf_validator import SSRFValidator
from app.modules.tools.mass_assignment_scanner import MassAssignmentScanner
from app.modules.tools.csti_scanner import CSTIScanner
from app.modules.tools.supply_chain_auditor import SupplyChainAuditor
from app.modules.tools.url_cleaner import URLCleaner
from app.modules.tools.wayback_url_hunter import WaybackURLHunter
from app.modules.tools.active_crawler import ActiveCrawler
from app.modules.recon import Reconnaissance

from app.utils.ui_helpers import render_df, analysis_result
from app.utils.alive_filter import filter_alive_urls
from app.utils.theme import inject_theme, app_header

CONFIG = load_config()
setup_logging(CONFIG)
inject_theme()
app_header("🕵️", "Reconnaissance", "Subdomain enumeration, ports, JS analysis, vulnerability detection and more.")

# ---------------------------------------------------------------------
# Project & session
# ---------------------------------------------------------------------
if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance

if 'current_project_name' not in st.session_state:
    st.session_state.current_project_name = project_manager.get_current_project_name()
elif st.session_state.current_project_name != project_manager.get_current_project_name():
    st.session_state.current_project_name = project_manager.get_current_project_name()

current_project = st.session_state.get('current_project_name')
if not current_project:
    st.warning("📂 No project selected. Select or create a project on the 'Projects' page first.")
    st.stop()

# Scope manager
scope_manager = project_manager.get_scope_manager()

# ---------------------------------------------------------------------
# Target selection (per-project session keys: switching projects resets)
# ---------------------------------------------------------------------
st.subheader("🎯 Target")

_pkey = f"recon_target_{current_project}"

all_project_targets = list(project_manager.get_all_targets_for_current_project().keys())

if all_project_targets:
    target_method = st.radio("Select target:", ("Existing", "New"), horizontal=True,
                             key=f"recon_target_method_{current_project}")
    if target_method == "Existing":
        selected_target = st.selectbox("Target:", [""] + all_project_targets,
                                       key=f"recon_select_target_{current_project}")
        target_domain = selected_target.strip() if selected_target else ""
    else:
        target_domain = st.text_input("New target domain:",
                                      key=f"recon_new_target_{current_project}").strip()
else:
    target_domain = st.text_input("Target domain (e.g., example.com):",
                                  key=f"recon_new_target_{current_project}").strip()

# Persist the chosen target per project
if target_domain and validate_domain(target_domain):
    st.session_state[_pkey] = target_domain

if not target_domain or not validate_domain(target_domain):
    st.warning("Enter a valid domain.")
    st.stop()

if target_domain:
    project_manager.add_target_to_current_project(target_domain)

# ---------------------------------------------------------------------
# Scope display (if configured)
# ---------------------------------------------------------------------
if scope_manager:
    rules = scope_manager.get_rules()
    if rules['in_scope'] or rules['wildcard_scope'] or rules['exclusions']:
        with st.expander("🎯 Scope Rules"):
            cols = st.columns(3)
            with cols[0]:
                st.markdown("**In Scope**")
                for r in rules['wildcard_scope']:
                    st.markdown(f"`✅ *.{r}`")
                for r in rules['in_scope']:
                    st.markdown(f"`✅ {r}`")
            with cols[1]:
                st.markdown("**Exclusions**")
                for r in rules['exclusions']:
                    st.markdown(f"`❌ {r}`")
            with cols[2]:
                st.markdown("**Status**")
                in_scope = scope_manager.is_in_scope(target_domain)
                st.markdown(f"`{'🟢 IN SCOPE' if in_scope else '🔴 OUT OF SCOPE'}`")

# ---------------------------------------------------------------------
# Initialise scanners
# ---------------------------------------------------------------------
subdomain_scanner = SubdomainScanner(CONFIG)
port_scanner = PortScanner(CONFIG)
js_analyzer = JSAnalyzer(CONFIG)
webanalyze_scanner = WebanalyzeScanner(CONFIG)
gf_scanner = GFScanner(CONFIG)
cloud_scanner = CloudScanner(CONFIG)
param_miner = ParamMiner(CONFIG)
cors_scanner = CORSHeadersScanner(CONFIG)
graphql_scanner = GraphQLScanner(CONFIG)
idor_scanner = IDORScanner(CONFIG)
dependency_scanner = DependencyConfusionScanner(CONFIG)
kxss_scanner = KXSSScanner(CONFIG)
pp_validator = PrototypePollutionValidator(CONFIG)
mass_assignment_scanner = MassAssignmentScanner(CONFIG)
csti_scanner = CSTIScanner(CONFIG)
supply_chain_auditor = SupplyChainAuditor(CONFIG)
url_cleaner = URLCleaner(CONFIG)
recon_runner = Reconnaissance(CONFIG)

js_analyzer.scope_hosts = {target_domain}

# Diagnostic: shows which subdomain_scanner.py is actually loaded (stale-import detector)
import app.modules.tools.subdomain_scanner as _sd_mod
st.caption(f"subdomain_scanner loaded from: `{_sd_mod.__file__}`"
           + ("" if hasattr(_sd_mod.SubdomainScanner, '_run_httpx_with_ports')
              else " — ⚠️ STALE VERSION (no `_run_httpx_with_ports`). Restart Streamlit and replace the file."))

# ---------------------------------------------------------------------
# FULL RECON (one-click pipeline)
# ---------------------------------------------------------------------
with st.expander("🚀 Full Recon (one-click pipeline)"):
    st.caption("Subdomain enum → takeover check → live-host probing → tech detection → JS analysis → port scan. "
               "Scope-aware; only probed live hosts go to the expensive stages.")
    if st.button("🚀 Run Full Recon", key="run_full_recon"):
        with st.spinner("Running full reconnaissance pipeline..."):
            progress = st.progress(0.0, text="Starting...")
            try:
                results = recon_runner.full_recon_scan(
                    target_domain,
                    progress_callback=lambda p, m: progress.progress(min(max(p, 0.0), 1.0), text=m),
                    scope_manager=scope_manager
                )
                saved_keys = []
                # Per-source subdomain results (subfinder_subdomains, resolved_subdomains, live_hosts, ...)
                for key, df in (recon_runner._last_subdomain_results or {}).items():
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        project_manager.save_scan_results(key, target_domain, df)
                        saved_keys.append(key)
                for result_key, save_key in [('subdomain_takeovers', 'subdomain_takeovers'),
                                             ('web_technologies', 'web_technologies'),
                                             ('open_ports', 'ports')]:
                    df = results.get(result_key)
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        project_manager.save_scan_results(save_key, target_domain, df)
                        saved_keys.append(save_key)
                js_results = results.get('js_analysis') or {}
                for key, df in js_results.items():
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        project_manager.save_scan_results(key, target_domain, df)
                        saved_keys.append(key)

                st.success(f"Full recon complete. Saved {len(saved_keys)} result set(s).")
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Subdomains", len(results.get('subdomains', [])))
                m2.metric("Takeovers", len(results.get('subdomain_takeovers', [])))
                m3.metric("Live URLs", len(results.get('web_technologies', [])))
                m4.metric("Open Ports", len(results.get('open_ports', [])))
            except Exception as e:
                st.error(f"Full recon failed: {e}")

# ---------------------------------------------------------------------
# CONSOLIDATED TABS (8 instead of 12)
# ---------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs([
    "🌐 Subdomain & Takeover",
    "🔌 Port & Service Scan",
    "📜 JavaScript Analysis",
    "🔍 Vulnerability Detection",
    "☁️ Cloud & Infra",
    "🔑 Parameter Mining",
    "🛡️ Security Headers",
    "🧬 Advanced Scans"
])

# =====================================================================
# TAB 1: Subdomain & Takeover
# =====================================================================
with tab1:
    st.subheader(f"Subdomain Enumeration: `{target_domain}`")

    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        use_amass = st.checkbox("Amass", value=True, help=f"Capped at {5} min (set below)")
        use_subfinder = st.checkbox("Subfinder", value=True, help="Capped at 3 min")
    with col2:
        enable_ct = st.checkbox("CT Logs", value=True, help="Certificate Transparency")
        enable_perm = st.checkbox("Permutations", value=False, help="dnsgen/altdns/builtin - slow, capped at 3000")
        enable_wildcard = st.checkbox("Filter Wildcards", value=True)
    with col3:
        custom_ports = st.text_input("Httpx extra ports:", "8080,8443",
                                      help="Comma-separated. Default: 80,443. Fewer ports = much faster probing.")
        amass_cap = st.number_input("Amass time cap (min):", 1, 15, 5, key="amass_cap")

    st.caption("⚡ Passive sources run in parallel. Only DNS-resolved hosts get HTTP probed.")

    if st.button("🚀 Run Subdomain Scan", key="run_subdomain_scan"):
        with st.spinner("Scanning..."):
            progress_bar = st.progress(0.0, text="Starting...")
            try:
                import asyncio
                import concurrent.futures

                # Parse custom ports
                extra_ports = [p.strip() for p in custom_ports.split(",") if p.strip().isdigit()]

                # ---- Phase 1: passive enumeration IN PARALLEL ----
                # Wall time = slowest single source, not the sum of all three.
                progress_bar.progress(0.05, "Passive enumeration (parallel: subfinder + amass + CT)...")
                all_subdomains = []

                def _fetch_ct():
                    return asyncio.run(subdomain_scanner._fetch_ct_logs(target_domain))

                futures = {}
                with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
                    if use_subfinder:
                        futures[ex.submit(subdomain_scanner._run_subfinder, target_domain)] = ('subfinder_subdomains', 'Subfinder')
                    if use_amass:
                        futures[ex.submit(subdomain_scanner._run_amass, target_domain, None, amass_cap)] = ('amass_subdomains', 'Amass')
                    if enable_ct:
                        futures[ex.submit(_fetch_ct)] = ('ct_logs_subdomains', 'CT Logs')

                    done = 0
                    for fut in concurrent.futures.as_completed(futures):
                        save_key, label = futures[fut]
                        done += 1
                        try:
                            found = fut.result() or []
                        except Exception as e:
                            st.caption(f"⚠️ {label} failed: {e}")
                            found = []
                        if found:
                            found = subdomain_scanner._sanitize_subdomain_list(found)
                            found = subdomain_scanner.scope_validator.filter_subdomains(found)
                            all_subdomains.extend(found)
                            df = pd.DataFrame({'Subdomain': found})
                            project_manager.save_scan_results(save_key, target_domain, df)
                        progress_bar.progress(0.05 + 0.35 * (done / max(len(futures), 1)),
                                              f"Passive: {label} done ({len(found)}).")

                all_subdomains = sorted(set(all_subdomains))
                if not all_subdomains:
                    st.info("No subdomains found.")
                    progress_bar.progress(1.0, "Done.")
                    st.stop()

                # ---- Phase 2: permutations (optional, capped in the scanner) ----
                if enable_perm:
                    progress_bar.progress(0.45, "Permutations (capped at 3000)...")
                    perm_results = subdomain_scanner._run_permutation_scan(target_domain, all_subdomains)
                    if perm_results:
                        perm_results = subdomain_scanner._sanitize_subdomain_list(perm_results)
                        perm_results = subdomain_scanner.scope_validator.filter_subdomains(perm_results)
                        all_subdomains = sorted(set(all_subdomains) | set(perm_results))

                # ---- SCOPE GATE: out-of-scope subdomains die here, before any
                # resolution/probing and before any results are saved downstream ----
                _before_scope = len(all_subdomains)
                all_subdomains = project_manager.filter_targets_by_scope(all_subdomains)
                if len(all_subdomains) < _before_scope:
                    st.caption(f"🎯 Scope: dropped {_before_scope - len(all_subdomains)} out-of-scope subdomains")
                if not all_subdomains:
                    st.warning("All discovered subdomains are out of scope. Nothing to scan.")
                    progress_bar.progress(1.0, "Done.")
                    st.stop()

                # ---- Phase 3: ONE DNS resolution pass (reused for wildcard filtering) ----
                progress_bar.progress(0.60, f"Resolving {len(all_subdomains)} subdomains...")
                dns_results = subdomain_scanner._run_dnsx(all_subdomains) or []

                # Wildcard filter on the same result set - no second resolution pass
                if enable_wildcard and dns_results:
                    progress_bar.progress(0.72, "Filtering wildcards...")
                    _filter = getattr(subdomain_scanner, '_filter_wildcard_from_dnsx', None)
                    if _filter:
                        dns_results = _filter(dns_results, target_domain)

                if dns_results:
                    df = pd.DataFrame(dns_results)
                    project_manager.save_scan_results('resolved_subdomains', target_domain, df)

                # ---- Phase 4: HTTP probe RESOLVED hosts only ----
                # Probing unresolved hosts is the single biggest time sink - skip them.
                resolved_hosts = [r['hostname'] for r in dns_results if r.get('hostname')]
                probe_targets = resolved_hosts if resolved_hosts else all_subdomains
                if not resolved_hosts:
                    st.caption("⚠️ dnsx unavailable/failed - probing all subdomains (slower).")

                progress_bar.progress(0.80, f"Probing HTTP/S on {len(probe_targets)} resolved hosts...")
                _probe = getattr(subdomain_scanner, '_run_httpx_with_ports', None)
                if _probe:
                    http_results = _probe(probe_targets, extra_ports)
                else:
                    st.caption("⚠️ Loaded SubdomainScanner lacks `_run_httpx_with_ports` — using default ports. Restart Streamlit / update subdomain_scanner.py.")
                    http_results = subdomain_scanner._run_httpx(probe_targets)
                if http_results:
                    df = pd.DataFrame(http_results)
                    project_manager.save_scan_results('live_hosts', target_domain, df)

                progress_bar.progress(1.0, "Complete!")
                st.success(f"Found {len(all_subdomains)} subdomains, {len(dns_results)} resolved, {len(http_results)} live hosts.")

            except Exception as e:
                st.error(f"Scan failed: {str(e)}")

    # Display results
    st.markdown("---")
    for key, label in [('subfinder_subdomains', 'Subfinder'), ('amass_subdomains', 'Amass'),
                       ('ct_logs_subdomains', 'CT Logs'), ('resolved_subdomains', 'Resolved DNS'),
                       ('live_hosts', 'Live Hosts')]:
        df = project_manager.load_scan_results(key, target_domain)
        if isinstance(df, pd.DataFrame) and not df.empty:
            with st.expander(f"{label} ({len(df)})"):
                st.dataframe(df, use_container_width=True)

    # Takeover
    st.markdown("---")
    st.subheader("🔁 Subdomain Takeover")
    if st.button("Run Takeover Check", key="run_takeover"):
        resolved_df = project_manager.load_scan_results('resolved_subdomains', target_domain)
        if isinstance(resolved_df, pd.DataFrame) and not resolved_df.empty:
            with st.spinner("Checking..."):
                progress = st.progress(0.0)
                takeover_df = subdomain_scanner.run_subdomain_takeover_scan(
                    resolved_df, progress_callback=lambda p, m: progress.progress(p, m)
                )
                if not takeover_df.empty:
                    st.success(f"Found {len(takeover_df)} potential takeovers!")
                    st.dataframe(takeover_df, use_container_width=True)
                    project_manager.save_scan_results('subdomain_takeovers', target_domain, takeover_df)
                else:
                    st.info("No takeovers detected.")
        else:
            st.warning("Run subdomain scan first.")

    takeover_df = project_manager.load_scan_results('subdomain_takeovers', target_domain)
    if isinstance(takeover_df, pd.DataFrame) and not takeover_df.empty:
        st.markdown("**Stored Takeover Findings**")
        st.dataframe(takeover_df, use_container_width=True)

# =====================================================================
# TAB 2: Port & Service Scan
# =====================================================================
with tab2:
    st.subheader(f"Port Scanning: `{target_domain}`")

    col1, col2 = st.columns(2)
    with col1:
        port_target = st.text_input("Target:", target_domain, key="port_target")
        tool = st.selectbox("Tool:", ["nmap", "masscan", "naabu"], key="port_tool")
    with col2:
        port_range = st.text_input("Port range:", "1-65535", key="port_range")
        st.caption("Nmap: '1-1000' or '80,443,8080'. Masscan: rate limited.")

    if st.button("🔍 Run Port Scan", key="run_port_scan"):
        if not port_target:
            st.error("Enter a target.")
        elif not (validate_domain(port_target) or validate_ip(port_target)):
            st.error("Invalid target.")
        else:
            with st.spinner(f"Running {tool}..."):
                progress = st.progress(0.0)
                try:
                    ports_df = port_scanner.run_port_scan(
                        target=port_target, tool=tool, port_range=port_range,
                        progress_callback=lambda p, m: progress.progress(p, m)
                    )
                    if not ports_df.empty:
                        st.success(f"Found {len(ports_df)} open ports.")
                        st.dataframe(ports_df, use_container_width=True)
                        project_manager.save_scan_results('ports', port_target, ports_df)
                    else:
                        st.info("No open ports found.")
                except Exception as e:
                    st.error(f"Port scan failed: {e}")

    ports_df = project_manager.load_scan_results('ports', port_target)
    if isinstance(ports_df, pd.DataFrame) and not ports_df.empty:
        st.markdown("**Stored Results**")
        st.dataframe(ports_df, use_container_width=True)

# =====================================================================
# TAB 3: JavaScript Analysis v3.0 (Steroids)
# =====================================================================
with tab3:
    st.subheader(f"📜 JavaScript Analysis v3.0: `{target_domain}`")

    live_df = project_manager.load_scan_results('live_hosts', target_domain)
    urls = []
    if isinstance(live_df, pd.DataFrame) and 'URL' in live_df.columns:
        urls = [u for u in live_df['URL'].tolist() if is_valid_url(u)]
    if not urls:
        urls = [f"https://{target_domain}", f"http://{target_domain}"]

    st.info(f"Analyzing {len(urls)} URLs with v3.0 engine (framework detection, prototype pollution, DOM clobbering, postMessage analysis, dangerous patterns, JSONP, dynamic rendering, CSP gadgets).")

    btn_cols = st.columns([2, 2, 3])
    run_js = btn_cols[0].button("📜 Run JS Analysis", key="run_js",
                                help="Discover endpoints, secrets, vectors. Fast — no live probing.")
    run_val = btn_cols[1].button("🔎 Validate Endpoints", key="run_js_validate",
                                 help="Probe discovered endpoints: live status, allowed methods, drop soft-404s.")

    # -- separate validation pass over already-discovered endpoints --
    if run_val:
        stored = project_manager.load_scan_results('js_discovered_endpoints', target_domain)
        if not isinstance(stored, pd.DataFrame) or stored.empty:
            st.warning("No discovered endpoints to validate — run JS Analysis first.")
        else:
            with st.spinner("Validating endpoints (live status, methods, soft-404)..."):
                progress = st.progress(0.0)
                try:
                    eps = [{'url': r.get('endpoint', ''), 'method': r.get('method', 'GET'),
                            'severity': r.get('severity', 'info'),
                            'confidence': r.get('confidence', 'medium'),
                            'source_url': r.get('source_url', ''),
                            'suspicious_indicators': []}
                           for _, r in stored.iterrows() if r.get('endpoint')]
                    done = js_analyzer.validate_endpoints(
                        eps, progress_callback=lambda p, m: progress.progress(min(p, 1.0), m))
                    by_url = {d.get('url'): d for d in done}
                    for col in ('live_status', 'alive', 'allow_methods', 'soft_404'):
                        stored[col] = stored['endpoint'].map(
                            lambda u: by_url.get(u, {}).get(col, ''))
                    # carry back any severity/indicator escalation from probing
                    stored['severity'] = stored.apply(
                        lambda r: by_url.get(r['endpoint'], {}).get('severity', r.get('severity', 'info')),
                        axis=1)
                    project_manager.save_scan_results('js_discovered_endpoints', target_domain, stored)
                    kept = sum(1 for d in done if str(d.get('live_status', '')).isdigit())
                    soft = sum(1 for d in done if d.get('soft_404'))
                    st.success(f"Validated {len(done)} endpoints — {kept} live, {soft} soft-404 flagged.")
                except Exception as e:
                    st.error(f"Validation failed: {e}")
                    import traceback
                    st.code(traceback.format_exc())

    if run_js:
        with st.spinner("Analyzing JS with steroids..."):
            progress = st.progress(0.0)
            try:
                results = js_analyzer.analyze_js_for_project(urls, progress_callback=lambda p, m: progress.progress(p, m), validate=False)
                saved = False
                for key, df in results.items():
                    if isinstance(df, pd.DataFrame) and not df.empty:
                        project_manager.save_scan_results(key, target_domain, df)
                        saved = True
                if saved:
                    # Build summary
                    total_endpoints = len(results.get('js_discovered_endpoints', pd.DataFrame()))
                    critical = len(results.get('js_priority_endpoints', pd.DataFrame()))
                    secrets = len(results.get('js_sensitive_data_findings', pd.DataFrame()))
                    frameworks = len(results.get('js_frameworks', pd.DataFrame()))
                    proto = len(results.get('js_prototype_pollution', pd.DataFrame()))
                    clobber = len(results.get('js_dom_clobbering', pd.DataFrame()))
                    postmsg = len(results.get('js_postmessage_issues', pd.DataFrame()))
                    dangerous = len(results.get('js_dangerous_patterns', pd.DataFrame()))
                    jsonp = len(results.get('js_jsonp_endpoints', pd.DataFrame()))

                    st.success(
                        f"JS v3.0 complete! 🎯 {total_endpoints} endpoints | "
                        f"🔴 {critical} critical | 🔑 {secrets} secrets | "
                        f"📦 {frameworks} frameworks | ⚠️ {proto} proto vectors | "
                        f"🌊 {clobber} clobbering | 📨 {postmsg} postMessage | "
                        f"☠️ {dangerous} dangerous | 🔗 {jsonp} JSONP"
                    )
                else:
                    st.info("No JS findings.")
            except Exception as e:
                st.error(f"JS analysis failed: {e}")
                import traceback
                st.code(traceback.format_exc())

    # ---- RESULTS: sub-tabbed so no single section dominates the page ----
    st.markdown("---")
    js_sub1, js_sub2, js_sub3, js_sub4, js_sub5, js_sub6, js_sub7, js_sub8, js_sub9 = st.tabs([
        "📊 Overview", "🔑 Secrets & Patterns", "⚠️ Client-Side Vectors", "📂 Endpoints",
        "🧪 PP Validation", "🖥️ DOM XSS", "🌐 CORS", "↩️ Open Redirect", "📡 SSRF"
    ])

    # Preload all stored frames once
    frameworks_df = project_manager.load_scan_results('js_frameworks', target_domain)
    proto_df = project_manager.load_scan_results('js_prototype_pollution', target_domain)
    dangerous_df = project_manager.load_scan_results('js_dangerous_patterns', target_domain)
    secrets_df = project_manager.load_scan_results('js_sensitive_data_findings', target_domain)
    priority_df = project_manager.load_scan_results('js_priority_endpoints', target_domain)
    clobber_df = project_manager.load_scan_results('js_dom_clobbering', target_domain)
    postmsg_df = project_manager.load_scan_results('js_postmessage_issues', target_domain)
    jsonp_df = project_manager.load_scan_results('js_jsonp_endpoints', target_domain)
    rendering_df = project_manager.load_scan_results('js_dynamic_rendering', target_domain)
    csp_df = project_manager.load_scan_results('js_csp_gadgets', target_domain)
    endpoints_df = project_manager.load_scan_results('js_discovered_endpoints', target_domain)
    graphql_df = project_manager.load_scan_results('js_graphql_endpoints', target_domain)
    ws_df = project_manager.load_scan_results('js_websocket_endpoints', target_domain)
    maps_df = project_manager.load_scan_results('js_source_maps', target_domain)

    def _has(df):
        return isinstance(df, pd.DataFrame) and not df.empty

    # ================= OVERVIEW =================
    with js_sub1:
        metric_cols = st.columns(4)
        with metric_cols[0]:
            st.metric("📦 Frameworks", len(frameworks_df) if _has(frameworks_df) else 0)
        with metric_cols[1]:
            st.metric("⚠️ Proto Pollution", len(proto_df) if _has(proto_df) else 0,
                      delta="HIGH" if _has(proto_df) else None)
        with metric_cols[2]:
            st.metric("☠️ Dangerous", len(dangerous_df) if _has(dangerous_df) else 0)
        with metric_cols[3]:
            st.metric("🔑 Secrets", len(secrets_df) if _has(secrets_df) else 0)

        if _has(priority_df):
            st.markdown("#### 🔴 Priority Endpoints")
            st.dataframe(priority_df, use_container_width=True)
            st.download_button("📥 Download CSV", priority_df.to_csv(index=False),
                               f"{target_domain}_priority.csv", "text/csv", key="dl_js_priority")

        if _has(frameworks_df):
            st.markdown("#### 📦 Detected Frameworks")
            fw_cols = st.columns(min(len(frameworks_df), 4))
            for idx, row in frameworks_df.iterrows():
                with fw_cols[idx % 4]:
                    st.markdown(f"**{row.get('framework', 'Unknown').upper()}** `v{row.get('version', 'unknown')}`")
                    st.caption(f"Source: {row.get('source', '')[:40]}...")

        if not any(_has(d) for d in (priority_df, frameworks_df, proto_df, secrets_df)):
            st.info("No analysis results yet - run JS Analysis above.")

    # ================= SECRETS & PATTERNS =================
    with js_sub2:
        if _has(secrets_df):
            st.markdown("#### 🔑 Secrets")
            if 'type' in secrets_df.columns:
                st.bar_chart(secrets_df['type'].value_counts())
            display_df = secrets_df.copy()
            if 'value' in display_df.columns:
                display_df['value'] = display_df['value'].apply(
                    lambda x: str(x)[:8] + '...' + str(x)[-4:] if len(str(x)) > 12 else x)
            st.dataframe(display_df, use_container_width=True)
            st.download_button("📥 Download Secrets", secrets_df.to_csv(index=False),
                               f"{target_domain}_secrets.csv", "text/csv", key="dl_js_secrets")

        if _has(dangerous_df):
            st.markdown("#### ☠️ Dangerous Patterns")
            if 'pattern_name' in dangerous_df.columns:
                st.bar_chart(dangerous_df['pattern_name'].value_counts())
            st.dataframe(dangerous_df, use_container_width=True)

        if _has(jsonp_df):
            st.markdown("#### 🔗 JSONP Endpoints")
            st.info("May be vulnerable to XSS via callback manipulation.")
            st.dataframe(jsonp_df, use_container_width=True)

        if _has(rendering_df):
            st.markdown("#### 🎭 Dynamic Rendering")
            st.warning("Dynamic rendering engine detected - check for SSRF via headless browser endpoints.")
            st.dataframe(rendering_df, use_container_width=True)

        if _has(csp_df):
            st.markdown("#### 🔓 CSP Gadgets")
            st.dataframe(csp_df, use_container_width=True)

        if not any(_has(d) for d in (secrets_df, dangerous_df, jsonp_df, rendering_df, csp_df)):
            st.info("No secrets or dangerous patterns found yet.")

    # ================= CLIENT-SIDE VECTORS =================
    with js_sub3:
        if _has(proto_df):
            st.markdown("#### ⚠️ Prototype Pollution Vectors")
            st.error("🚨 Unsafe object merging / `__proto__` access detected - confirm in the **PP Validation** tab.")
            for idx, row in proto_df.head(10).iterrows():
                st.markdown(f"**Line {row.get('line', '?')}**: `{row.get('context', '')[:100]}...`")
                st.caption(f"Pattern: {row.get('pattern', '')}")
            st.dataframe(proto_df, use_container_width=True)

        if _has(clobber_df):
            st.markdown("#### 🌊 DOM Clobbering")
            st.warning("Named properties may override JS variables.")
            st.dataframe(clobber_df, use_container_width=True)

        if _has(postmsg_df):
            st.markdown("#### 📨 PostMessage Issues")
            st.error("🚨 Handlers without `event.origin` validation - cross-origin data theft risk.")
            st.dataframe(postmsg_df, use_container_width=True)

        if not any(_has(d) for d in (proto_df, clobber_df, postmsg_df)):
            st.info("No client-side vectors found yet.")

    # ================= ENDPOINTS =================
    with js_sub4:
        if _has(endpoints_df):
            ep_view = endpoints_df.copy()

            # soft-404s: hidden by default (validation marks them True)
            if 'soft_404' in ep_view.columns:
                soft_mask = ep_view['soft_404'].fillna(False).astype(bool)
            else:
                soft_mask = pd.Series(False, index=ep_view.index)

            # how many were actually validated (3-digit live_status)
            if 'live_status' in ep_view.columns:
                validated_mask = ep_view['live_status'].astype(str).str.fullmatch(r'\d{3}')
                validated_mask = validated_mask.fillna(False)
            else:
                validated_mask = pd.Series(False, index=ep_view.index)

            top = st.columns([1, 1, 1, 2])
            top[0].metric("📂 Endpoints", len(ep_view))
            top[1].metric("✅ Validated", int(validated_mask.sum()))
            top[2].metric("🚮 Soft-404", int(soft_mask.sum()))
            with top[3]:
                show_soft = st.checkbox(f"Show {int(soft_mask.sum())} soft-404s",
                                        value=False, key="js_show_soft404")
                only_interesting = st.checkbox("Only interesting (401/403/405/5xx)",
                                               value=False, key="js_only_interesting")

            if int(validated_mask.sum()) == 0:
                st.caption("⏳ Endpoints not validated yet — Status / Allowed / Soft404 fill in "
                           "after you run **Validate Endpoints** above.")

            view = ep_view if show_soft else ep_view[~soft_mask]

            # keep endpoints where the server confirmed the route exists but
            # gated/blocked it - the interesting ones to test manually
            def _status_bucket(s):
                s = str(s)
                if s in ('401', '403'): return 0     # auth-gated -> top
                if s == '405':          return 1     # method not allowed
                if s.startswith('5'):   return 2     # server error
                if s == '200':          return 3
                if s in ('', 'nan', 'None'): return 5
                return 4
            if only_interesting and 'live_status' in view.columns:
                view = view[view['live_status'].astype(str).isin(
                    ['401', '403', '405', '500', '501', '502', '503'])]

            if 'live_status' in view.columns:
                view = view.assign(_o=view['live_status'].map(_status_bucket))
                sort_cols = ['_o'] + (['severity'] if 'severity' in view.columns else [])
                view = view.sort_values(sort_cols).drop(columns='_o')

            st.markdown(f"#### 📂 Endpoints ({len(view)})")
            preferred = ['endpoint', 'method', 'live_status', 'allow_methods', 'soft_404',
                         'alive', 'severity', 'auth', 'confidence', 'suspicious_indicators',
                         'source_url']
            cols = [c for c in preferred if c in view.columns]
            cols += [c for c in view.columns if c not in cols]  # keep any extras
            st.dataframe(
                view[cols], use_container_width=True, hide_index=True,
                column_config={
                    'endpoint': st.column_config.TextColumn('Endpoint', width='large'),
                    'method': st.column_config.TextColumn('Method', width='small'),
                    'live_status': st.column_config.TextColumn('Status', width='small',
                        help='Live HTTP status. 401/403 = auth-gated, 405 = wrong method, 5xx = server error'),
                    'allow_methods': st.column_config.TextColumn('Allowed',
                        help='Methods advertised via OPTIONS / Allow header'),
                    'soft_404': st.column_config.CheckboxColumn('Soft404', width='small',
                        help='Returned 200 but body matches the host 404 page'),
                    'alive': st.column_config.CheckboxColumn('Alive', width='small'),
                },
            )
            st.download_button("📥 Download Endpoints CSV", view[cols].to_csv(index=False),
                               f"{target_domain}_endpoints.csv", "text/csv", key="dl_js_endpoints")
        if _has(graphql_df):
            st.markdown(f"#### 🧬 GraphQL ({len(graphql_df)})")
            st.dataframe(graphql_df, use_container_width=True)
        if _has(ws_df):
            st.markdown(f"#### 📡 WebSockets ({len(ws_df)})")
            st.dataframe(ws_df, use_container_width=True)
        if _has(maps_df):
            st.markdown(f"#### 🗺️ Source Maps ({len(maps_df)})")
            st.warning("Source maps may contain original source code and hardcoded secrets.")
            st.dataframe(maps_df, use_container_width=True)
        if not any(_has(d) for d in (endpoints_df, graphql_df, ws_df, maps_df)):
            st.info("No endpoints discovered yet.")

    # ================= PP VALIDATION =================
    with js_sub5:
        st.caption("Active confirmation of PP vectors: injects `__proto__` canaries via query/hash/JSON body "
                   "and checks if `Object.prototype` gets polluted (headless browser = definitive proof).")

        pp_urls = list(urls)  # live hosts / fallback from the top of this tab
        if _has(endpoints_df) and 'endpoint' in endpoints_df.columns:
            pp_urls.extend(endpoints_df['endpoint'].tolist())
        # Static PP vectors from the analyzer point at juicy files - prioritize their origins
        if _has(proto_df) and 'source' in proto_df.columns:
            pp_urls.extend(proto_df['source'].tolist())
        pp_urls = project_manager.filter_targets_by_scope(
            list(dict.fromkeys([u for u in pp_urls if is_valid_url(u)])))

        if pp_validator.has_playwright:
            st.caption(f"✅ Browser confirmation ready (`{pp_validator.chromium_path}`) | {len(pp_urls)} URLs queued")
        else:
            st.caption("⚠️ Headless browser unavailable (`pip install playwright` + chromium) - reflection heuristics only")

        if pp_urls and st.button("🧪 Run PP Validation", key="run_pp_validation"):
            with st.spinner("Injecting __proto__ canaries..."):
                progress = st.progress(0.0, text="Starting...")
                try:
                    pp_results = pp_validator.validate_sync(
                        pp_urls, progress_callback=lambda p, m: progress.progress(min(p, 1.0), text=m))
                    if pp_results:
                        pp_df = pd.DataFrame(pp_results)
                        confirmed = pp_df[pp_df['Result'] == 'CONFIRMED']
                        potential = pp_df[pp_df['Result'] == 'POTENTIAL']
                        c1, c2 = st.columns(2)
                        c1.metric("🚨 CONFIRMED", len(confirmed))
                        c2.metric("⚠️ Potential", len(potential))
                        if not confirmed.empty:
                            st.error(f"🚨 Object.prototype pollution CONFIRMED on {len(confirmed)} vector(s)!")
                        st.dataframe(pp_df, use_container_width=True)
                        project_manager.save_scan_results('pp_validation', target_domain, pp_df)
                        st.download_button("📥 Download PP Results", pp_df.to_csv(index=False),
                                           f"{target_domain}_pp_validation.csv", "text/csv", key="dl_pp")
                    else:
                        st.success("No prototype pollution confirmed on the tested URLs.")
                except Exception as e:
                    st.error(f"PP validation failed: {e}")

        pp_df = project_manager.load_scan_results('pp_validation', target_domain)
        if _has(pp_df):
            with st.expander(f"Stored PP Validation Results ({len(pp_df)})"):
                st.dataframe(pp_df, use_container_width=True)

    # ================= ACTIVE VALIDATION SUB-TABS =================
    # Stored results first; a collapsible run block per validator.
    # Candidate pool = live hosts + JS endpoints (+ optional custom URLs).
    for _sub, _key, _validator, _label in [
        (js_sub6, 'dom_xss_validation', DOMXSSValidator(CONFIG), 'DOM XSS'),
        (js_sub7, 'cors_validation', CORSValidator(CONFIG), 'CORS'),
        (js_sub8, 'open_redirect_validation', OpenRedirectValidator(CONFIG), 'Open Redirect'),
        (js_sub9, 'ssrf_validation', SSRFValidator(CONFIG), 'SSRF'),
    ]:
        with _sub:
            st.caption(f"Active {_label} validation - confirms candidates found by the static scanners "
                       "(headless-browser proof for DOM sinks, live header probes for the rest).")
            stored_df = project_manager.load_scan_results(_key, target_domain)
            if _has(stored_df):
                with st.expander(f"Stored {_label} Validation Results ({len(stored_df)})"):
                    st.dataframe(stored_df, use_container_width=True)
            with st.expander(f"🧪 Run {_label} Validation"):
                custom_val_urls = st.text_area("Custom URLs (one per line, optional):",
                                               height=80, key=f"{_key}_custom_urls")
                cand_urls = list(urls)
                if _has(endpoints_df) and 'endpoint' in endpoints_df.columns:
                    cand_urls.extend(endpoints_df['endpoint'].tolist())
                if custom_val_urls.strip():
                    cand_urls.extend(u.strip() for u in custom_val_urls.splitlines() if is_valid_url(u.strip()))
                cand_urls = project_manager.filter_targets_by_scope(
                    list(dict.fromkeys([u for u in cand_urls if is_valid_url(u)])))
                st.caption(f"{len(cand_urls)} candidate URL(s) queued.")
                if st.button(f"🚀 Run {_label} Validation", key=f"run_{_key}"):
                    if not cand_urls:
                        st.info("No candidate URLs. Run the JS analysis or paste URLs above.")
                    else:
                        with st.spinner(f"Validating {_label}..."):
                            val_progress = st.progress(0.0, text="Starting...")
                            try:
                                val_results = _validator.validate_sync(
                                    cand_urls,
                                    progress_callback=lambda p, m: val_progress.progress(
                                        min(max(p, 0.0), 1.0), text=m))
                                if val_results:
                                    val_df = pd.DataFrame(val_results)
                                    project_manager.save_scan_results(_key, target_domain, val_df)
                                    confirmed = len(val_df[val_df['Result'] == 'CONFIRMED']) if 'Result' in val_df else 0
                                    probable = len(val_df[val_df['Result'] == 'PROBABLE']) if 'Result' in val_df else 0
                                    vc1, vc2 = st.columns(2)
                                    vc1.metric("🚨 CONFIRMED", confirmed)
                                    vc2.metric("⚠️ Probable/Potential", probable)
                                    if confirmed:
                                        st.error(f"🚨 {confirmed} {_label} issue(s) CONFIRMED - verify manually!")
                                    st.dataframe(val_df, use_container_width=True)
                                    st.download_button("📥 Download Results", val_df.to_csv(index=False),
                                                       f"{target_domain}_{_key}.csv", "text/csv",
                                                       key=f"dl_{_key}")
                                else:
                                    st.success(f"No {_label} findings on the tested URLs.")
                            except Exception as e:
                                st.error(f"{_label} validation failed: {e}")

# =====================================================================
# TAB 4: Vulnerability Detection (GF + kxss)
# =====================================================================
with tab4:
    st.subheader(f"Vulnerability Detection: `{target_domain}`")

    urls = []
    live_df = project_manager.load_scan_results('live_hosts', target_domain)
    if isinstance(live_df, pd.DataFrame) and 'URL' in live_df.columns:
        urls.extend(live_df['URL'].tolist())
    js_endpoints = project_manager.load_scan_results('js_discovered_endpoints', target_domain)
    if isinstance(js_endpoints, pd.DataFrame) and 'endpoint' in js_endpoints.columns:
        urls.extend(js_endpoints['endpoint'].tolist())
    param_miner_df = project_manager.load_scan_results('param_miner', target_domain)
    if isinstance(param_miner_df, pd.DataFrame) and 'URL' in param_miner_df.columns:
        urls.extend(param_miner_df['URL'].tolist())
    # Archived Wayback URLs from ParamSpider OSINT - real params seen in the wild
    hist_pm_df = project_manager.load_scan_results('param_miner_historical', target_domain)
    if isinstance(hist_pm_df, pd.DataFrame) and 'URL' in hist_pm_df.columns:
        urls.extend(hist_pm_df['URL'].tolist())
    urls = list(set([u for u in urls if is_valid_url(u)]))
    if not urls:
        urls = [f"https://{target_domain}", f"http://{target_domain}"]

    st.info(f"Scanning {len(urls)} URLs.")

    available_categories = gf_scanner.list_available_categories()
    pattern_count = len(getattr(gf_scanner, 'patterns', {}))
    if available_categories:
        default_cats = [c for c in ['xss', 'sqli', 'ssrf', 'lfi', 'rce', 'secrets', 'idor'] if c in available_categories]
        if not default_cats:
            default_cats = available_categories[:1]
        selected_cats = st.multiselect("Categories:", options=available_categories, default=default_cats, key="gf_categories")
        st.caption(f"{pattern_count} patterns loaded (built-in library"
                   + (f" + `{gf_scanner.gf_dir}`" if gf_scanner.gf_dir.exists() else " only — drop more in ~/.gf for extra coverage")
                   + ")")
    else:
        selected_cats = None
        st.warning("No GF patterns available at all — this should not happen with the built-in library.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔍 Run GF Scan", key="run_vuln_detection"):
            with st.spinner("Running GF..."):
                progress = st.progress(0.0)
                try:
                    results = gf_scanner.perform_scan(urls, progress_callback=lambda p, m: progress.progress(p, m), selected_categories=selected_cats)
                    saved = False
                    for key, df in results.items():
                        if isinstance(df, pd.DataFrame) and not df.empty:
                            project_manager.save_scan_results(key, target_domain, df)
                            saved = True
                    if saved:
                        st.success("GF scan complete.")
                        xss_count = len(results.get('gf_xss_candidates', pd.DataFrame()))
                        if xss_count > 0:
                            st.info(f"🎯 {xss_count} XSS candidates found! Check the XSS Confirmation section below.")
                    else:
                        st.info("No findings.")
                except Exception as e:
                    st.error(f"Scan failed: {e}")

    with col2:
        xss_df = project_manager.load_scan_results('gf_xss_candidates', target_domain)
        if isinstance(xss_df, pd.DataFrame) and not xss_df.empty:
            st.success(f"✅ {len(xss_df)} XSS candidates ready")

    # Display results
    st.markdown("---")
    for key, label in [
        ('gf_xss_candidates', '🔴 XSS'),
        ('gf_sqli_candidates', '🟠 SQLi'),
        ('gf_ssrf_candidates', '🟡 SSRF'),
        ('gf_lfi_candidates', '🟢 LFI'),
        ('gf_rce_candidates', '🔵 RCE'),
        ('gf_ssti_candidates', '🟤 SSTI'),
        ('gf_secrets_candidates', '🟣 Secrets'),
        ('gf_idor_candidates', '⚫ IDOR'),
        ('gf_api_candidates', '📡 API'),
        ('gf_debug_candidates', '⚪ Debug'),
        ('gf_sensitive_files_candidates', '🟥 Sensitive Files'),
    ]:
        df = project_manager.load_scan_results(key, target_domain)
        if isinstance(df, pd.DataFrame) and not df.empty:
            with st.expander(f"{label} ({len(df)})"):
                st.dataframe(df, use_container_width=True)
                csv = df.to_csv(index=False)
                st.download_button(f"📥 {label}", csv, f"{target_domain}_{key}.csv", "text/csv", key=f"dl_{key}")

    # XSS Confirmation (kxss) - integrated into same tab
    st.markdown("---")
    st.subheader("🎯 XSS Confirmation (kxss)")

    kxss_available = kxss_scanner.kxss_path.is_file()
    if not kxss_available:
        st.error("kxss not found. Install: `go install github.com/Emoe/kxss@latest`")
    else:
        xss_candidates = []
        if isinstance(xss_df, pd.DataFrame) and not xss_df.empty:
            xss_candidates = xss_df['URL'].tolist()

        manual_urls = st.text_area("Or paste URLs:", height=80, key="kxss_manual")
        if manual_urls.strip():
            xss_candidates.extend([u.strip() for u in manual_urls.split('\n') if is_valid_url(u.strip())])

        xss_candidates = list(dict.fromkeys(xss_candidates))

        if xss_candidates:
            st.info(f"Ready to probe {len(xss_candidates)} URLs with kxss")
            if st.button("🎯 Run kxss", key="run_kxss"):
                with st.spinner("Probing with kxss..."):
                    progress = st.progress(0.0)
                    try:
                        kxss_results = kxss_scanner.probe_xss_candidates_sync(xss_candidates, progress_callback=lambda p, m: progress.progress(p, m))
                        if not kxss_results.empty:
                            project_manager.save_scan_results('kxss_confirmed_xss', target_domain, kxss_results)
                            st.success(f"Found {len(kxss_results)} confirmed reflections!")

                            crit = len(kxss_results[kxss_results['severity'] == 'CRITICAL'])
                            high = len(kxss_results[kxss_results['severity'] == 'HIGH'])
                            c1, c2, c3 = st.columns(3)
                            c1.metric("🚨 CRITICAL", crit)
                            c2.metric("🔥 HIGH", high)
                            c3.metric("Total", len(kxss_results))

                            st.dataframe(kxss_results, use_container_width=True)
                            csv = kxss_results.to_csv(index=False)
                            st.download_button("📥 Download kxss Results", csv, f"{target_domain}_kxss.csv", "text/csv")
                        else:
                            st.info("No XSS reflections found.")
                    except Exception as e:
                        st.error(f"kxss failed: {e}")
        else:
            st.info("No XSS candidates. Run GF scan first or paste URLs.")

    kxss_df_stored = project_manager.load_scan_results('kxss_confirmed_xss', target_domain)
    if isinstance(kxss_df_stored, pd.DataFrame) and not kxss_df_stored.empty:
        with st.expander(f"Stored kxss Findings ({len(kxss_df_stored)})"):
            st.dataframe(kxss_df_stored, use_container_width=True)

    # CSTI/SSTI Confirmation (Beyond XSS ch.15) - same candidate pool as kxss
    st.markdown("---")
    st.subheader("🧩 Template Injection (CSTI/SSTI)")
    st.caption("Injects arithmetic template probes (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`...) into query params - "
               "an evaluated `49` is a confirmed injection, with engine fingerprinting.")

    # Self-sufficient candidate loading (kxss section vars only exist when kxss is installed)
    csti_candidates = []
    for scan_key in ['gf_filtered_urls', 'gf_xss_candidates', 'param_miner_historical']:
        _df = project_manager.load_scan_results(scan_key, target_domain)
        if isinstance(_df, pd.DataFrame) and 'URL' in _df.columns:
            csti_candidates.extend(_df['URL'].tolist())
    csti_candidates = project_manager.filter_targets_by_scope(
        list(dict.fromkeys([u for u in csti_candidates if is_valid_url(u) and '=' in u])))

    if csti_candidates:
        st.info(f"Ready to probe {len(csti_candidates)} URLs for template injection")
        if st.button("🧩 Run CSTI/SSTI Scan", key="run_csti"):
            with st.spinner("Injecting template probes..."):
                progress = st.progress(0.0, text="Starting...")
                try:
                    csti_results = csti_scanner.scan(
                        csti_candidates, progress_callback=lambda p, m: progress.progress(min(p, 1.0), text=m))
                    if csti_results:
                        csti_df = pd.DataFrame(csti_results)
                        confirmed = csti_df[csti_df['Result'] == 'CONFIRMED']
                        c1, c2 = st.columns(2)
                        c1.metric("🚨 CONFIRMED", len(confirmed))
                        c2.metric("⚠️ Potential", len(csti_df) - len(confirmed))
                        if not confirmed.empty:
                            st.error(f"🚨 Template injection CONFIRMED on {len(confirmed)} endpoint(s)!")
                            for _, r in confirmed.head(5).iterrows():
                                st.markdown(f"- `{r['URL']}` param `{r['Parameter']}` → engine: **{r['Engine']}**")
                        st.dataframe(csti_df, use_container_width=True)
                        project_manager.save_scan_results('csti_findings', target_domain, csti_df)
                        st.download_button("📥 Download CSTI Results", csti_df.to_csv(index=False),
                                           f"{target_domain}_csti.csv", "text/csv", key="dl_csti")
                    else:
                        st.success("No template injection detected on the tested URLs.")
                except Exception as e:
                    st.error(f"CSTI scan failed: {e}")
    else:
        st.info("No URLs with parameters. Run GF scan / ParamSpider first.")

    csti_df = project_manager.load_scan_results('csti_findings', target_domain)
    if isinstance(csti_df, pd.DataFrame) and not csti_df.empty:
        with st.expander(f"Stored CSTI Results ({len(csti_df)})"):
            st.dataframe(csti_df, use_container_width=True)

# =====================================================================
# TAB 5: Cloud & Infra
# =====================================================================
with tab5:
    st.subheader(f"Cloud Enumeration: `{target_domain}`")

    if st.button("☁️ Run Cloud Scan", key="run_cloud"):
        with st.spinner("Enumerating..."):
            progress = st.progress(0.0)
            try:
                results = cloud_scanner.scan(target_domain, progress_callback=lambda p, m: progress.progress(p, m))
                if any(results.values()):
                    total = sum(len(v) for v in results.values())
                    public = [i for v in results.values() for i in v if i.get("public")]
                    if public:
                        st.error(f"🚨 {len(public)} PUBLICLY LISTABLE bucket(s) found - verify manually, these are reportable!")
                    st.success(f"Cloud scan complete: {total} resources.")
                    for provider, findings in results.items():
                        if findings:
                            st.markdown(f"**{provider.upper()}** ({len(findings)})")
                            st.dataframe(pd.DataFrame(findings), use_container_width=True)
                            project_manager.save_scan_results(f"cloud_{provider}", target_domain, pd.DataFrame(findings))
                else:
                    st.info("No cloud resources found.")
            except Exception as e:
                st.error(f"Cloud scan failed: {e}")

    for provider in ['aws', 'azure', 'gcp']:
        df = project_manager.load_scan_results(f"cloud_{provider}", target_domain)
        if isinstance(df, pd.DataFrame) and not df.empty:
            with st.expander(f"{provider.upper()} ({len(df)})"):
                st.dataframe(df, use_container_width=True)

# =====================================================================
# TAB 6: Parameter Mining
# =====================================================================
with tab6:
    st.subheader(f"Parameter Mining: `{target_domain}`")

    urls = []
    live_df = project_manager.load_scan_results('live_hosts', target_domain)
    if isinstance(live_df, pd.DataFrame) and 'URL' in live_df.columns:
        urls.extend(live_df['URL'].tolist())
    js_endpoints = project_manager.load_scan_results('js_discovered_endpoints', target_domain)
    if isinstance(js_endpoints, pd.DataFrame) and 'endpoint' in js_endpoints.columns:
        urls.extend(js_endpoints['endpoint'].tolist())
    urls = sorted(set([u for u in urls if is_valid_url(u)]))
    if not urls:
        urls = [f"https://{target_domain}", f"http://{target_domain}"]

    # --- Archived/crawled URL collection (gau / waybackurls / katana) ---
    coll_df = project_manager.load_scan_results('collected_urls', target_domain)
    if isinstance(coll_df, pd.DataFrame) and 'URL' in coll_df.columns:
        urls = sorted(set(urls) | {u for u in coll_df['URL'].tolist() if is_valid_url(u)})

    with st.expander(f"🗃️ URL Collection (archives + crawler) — {len(coll_df) if isinstance(coll_df, pd.DataFrame) and not coll_df.empty else 0} stored"):
        uc1, uc2 = st.columns(2)
        with uc1:
            use_archives = st.checkbox("Archives (gau, waybackurls)", value=True, key="uc_archives")
        with uc2:
            use_crawler = st.checkbox("Active crawl (katana)", value=False, key="uc_crawler",
                                      help="Crawls the live site - noisy, only enable when allowed.")
        if st.button("🗃️ Collect URLs", key="run_url_collect"):
            with st.spinner("Collecting URLs..."):
                progress = st.progress(0.0, text="Starting...")
                try:
                    all_urls = []
                    if use_archives:
                        wb_hunter = WaybackURLHunter(CONFIG)
                        wb_res = wb_hunter.scan_sync(
                            target_domain,
                            scope_hosts=[target_domain],
                            progress_callback=lambda p, m: progress.progress(min(p, 0.5), m))
                        all_urls.extend(wb_res.get('urls', []))
                        st.caption(f"📚 Archives: {wb_res.get('totals', {}).get('urls', 0)} URLs "
                                   f"({wb_res.get('sources', {})})")
                    if use_crawler:
                        progress.progress(0.5, "Active crawl (katana/gau)...")
                        crawler = ActiveCrawler(CONFIG)
                        cr_res = crawler.scan_sync(scope_hosts=[target_domain],
                                                   targets=[f"https://{target_domain}"])
                        all_urls.extend(cr_res.get('urls', []))
                        st.caption(f"🕷️ Crawler: {cr_res.get('raw_total', 0)} raw URLs "
                                   f"({cr_res.get('sources', {})})")
                    progress.progress(0.9, "Cleaning & deduplicating...")
                    all_urls = url_cleaner.clean_urls(all_urls)
                    urls_df = pd.DataFrame({'URL': all_urls})
                    if not urls_df.empty:
                        # Scope enforcement before saving/feeding downstream
                        in_scope_urls = project_manager.filter_targets_by_scope(urls_df['URL'].tolist())
                        urls_df = urls_df[urls_df['URL'].isin(in_scope_urls)].reset_index(drop=True)
                        project_manager.save_scan_results('collected_urls', target_domain, urls_df)
                        st.success(f"Collected {len(urls_df)} unique URLs.")
                        st.dataframe(urls_df.head(200), use_container_width=True)
                    else:
                        st.info("No URLs collected (tools missing or archives empty).")
                except Exception as e:
                    st.error(f"URL collection failed: {e}")

    # --- Tool status with resolved paths ---
    x8_path = getattr(param_miner, 'x8_path', None)
    arjun_path = getattr(param_miner, 'arjun_path', None)
    ps_path = getattr(param_miner, 'paramspider_path', None)

    if x8_path:
        engine_line = f"✅ x8 `{x8_path}` (primary)"
    elif arjun_path:
        engine_line = f"✅ Arjun `{arjun_path}` (primary)"
    else:
        engine_line = "⚠️ Built-in async fuzzer (install x8 or arjun for better coverage)"
    osint_line = f"✅ ParamSpider `{ps_path}` (OSINT)" if ps_path else "❌ ParamSpider (no historical OSINT)"
    st.caption(engine_line + "  |  " + osint_line)

    # --- Run options ---
    opt1, opt2, opt3 = st.columns([1, 1, 2])
    with opt1:
        max_urls = st.slider("Max URLs to fuzz:", 5, 200, min(25, max(5, len(urls))), key="pm_max_urls",
                             help="Active fuzzing is noisy - focus on key endpoints.")
    with opt2:
        enable_osint = st.checkbox("Historical OSINT", value=bool(ps_path), key="pm_osint",
                                   help="ParamSpider: mine archived URLs from Wayback for known params.")
    with opt3:
        manual_pm_urls = st.text_area("Extra URLs (one per line):", height=68, key="pm_manual_urls")

    fuzz_urls = list(urls)
    if manual_pm_urls.strip():
        fuzz_urls.extend(u.strip() for u in manual_pm_urls.splitlines() if is_valid_url(u.strip()))
    fuzz_urls = list(dict.fromkeys(fuzz_urls))[:max_urls]

    st.info(f"Ready to fuzz {len(fuzz_urls)} URLs (of {len(urls)} collected).")

    if st.button("🔑 Run Parameter Mining", key="run_param_miner"):
        param_miner.enable_osint = enable_osint and bool(ps_path)
        with st.spinner("Mining parameters..."):
            progress = st.progress(0.0, text="Starting...")
            try:
                results = param_miner.mine_parameters_sync(
                    fuzz_urls,
                    progress_callback=lambda p, m: progress.progress(min(p, 1.0), text=m)
                )

                stats = getattr(param_miner, 'last_stats', {})
                errors = getattr(param_miner, 'last_errors', [])

                if results:
                    total_params = sum(len(v) for v in results.values())
                    st.success(f"Found {total_params} parameters across {len(results)} URLs.")
                    rows = []
                    for url, params in results.items():
                        for p in params:
                            rows.append({
                                'URL': url,
                                'Parameter': p['parameter'],
                                'Value': p.get('value') or '',
                                'Status': p.get('status', ''),
                                'Reason': p.get('reason', ''),
                                'Tool': p.get('tool', ''),
                            })
                    df = pd.DataFrame(rows)
                    st.dataframe(df, use_container_width=True)
                    project_manager.save_scan_results('param_miner', target_domain, df)
                    csv = df.to_csv(index=False)
                    st.download_button("📥 Download CSV", csv, f"{target_domain}_params.csv", "text/csv", key="dl_param_miner")
                else:
                    st.info("No hidden parameters found on the tested URLs.")
                    # The "why" matters more than the zero - show it upfront
                    if stats.get('hint'):
                        st.warning(f"💡 {stats['hint']}")
                    if stats.get('x8_baselines'):
                        bl = stats['x8_baselines']
                        st.caption("x8 baseline responses: " + " | ".join(f"`{code}` × {n}" for code, n in sorted(bl.items())))

                # ---- Historical OSINT yield (ParamSpider / Wayback) ----
                # On WAF-fronted targets this is often the ONLY yield - always show it.
                hist_params = getattr(param_miner, 'last_historical_params', [])
                hist_urls = getattr(param_miner, 'last_historical_urls', [])
                if hist_params:
                    with st.expander(f"🕰️ Historical parameters from Wayback ({len(hist_params)})", expanded=not results):
                        st.caption("Seen on real archived URLs of this target - feed these to GF/kxss or test them manually.")
                        st.dataframe(pd.DataFrame({'Parameter': hist_params}), use_container_width=True)
                        st.download_button("📥 Download historical params", "\n".join(hist_params),
                                           f"{target_domain}_historical_params.txt", "text/plain", key="dl_hist_params")
                if hist_urls:
                    hist_df = pd.DataFrame({'URL': hist_urls})
                    project_manager.save_scan_results('param_miner_historical', target_domain, hist_df)
                    st.caption(f"💾 {len(hist_urls)} archived URLs saved - they now feed the Vulnerability Detection tab.")
                    with st.expander(f"🔗 Archived URLs with parameters ({len(hist_urls)})"):
                        st.dataframe(hist_df, use_container_width=True)
                        st.download_button("📥 Download URLs", hist_df.to_csv(index=False),
                                           f"{target_domain}_historical_urls.csv", "text/csv", key="dl_hist_urls")

                # Diagnostics: why did/didn't it work
                if stats or errors:
                    with st.expander("🩺 Run diagnostics"):
                        if stats:
                            st.json(stats)
                        if errors:
                            st.warning(f"{len(errors)} tool error(s):")
                            for e in errors[:20]:
                                st.text(e)
            except Exception as e:
                st.error(f"Parameter mining failed: {e}")

    df = project_manager.load_scan_results('param_miner', target_domain)
    if isinstance(df, pd.DataFrame) and not df.empty:
        with st.expander(f"Stored Results ({len(df)})"):
            st.dataframe(df, use_container_width=True)

    hist_df = project_manager.load_scan_results('param_miner_historical', target_domain)
    if isinstance(hist_df, pd.DataFrame) and not hist_df.empty:
        with st.expander(f"🕰️ Stored Historical URLs ({len(hist_df)})"):
            st.dataframe(hist_df, use_container_width=True)

# =====================================================================
# TAB 7: Security Headers (CORS + Headers merged)
# =====================================================================
with tab7:
    st.subheader(f"Security Headers & CORS: `{target_domain}`")

    live_df = project_manager.load_scan_results('live_hosts', target_domain)
    urls = []
    if isinstance(live_df, pd.DataFrame) and 'URL' in live_df.columns:
        urls = [u for u in live_df['URL'].tolist() if is_valid_url(u)]
    if not urls:
        urls = [f"https://{target_domain}", f"http://{target_domain}"]

    if st.button("🛡️ Run Scan", key="run_cors"):
        with st.spinner("Scanning..."):
            progress = st.progress(0.0)
            try:
                results = cors_scanner.scan(urls, progress_callback=lambda p, m: progress.progress(p, m))
                rows = []
                for url, data in results.items():
                    if 'error' in data:
                        rows.append({'URL': url, 'Error': data['error']})
                    else:
                        rows.append({
                            'URL': url, 'Status': data['status'],
                            'CORS Misconfigured': data['cors']['is_misconfigured'],
                            'CORS Severity': data['cors'].get('severity', ''),
                            'CORS Note': data['cors'].get('note', ''),
                            'ACAO': data['cors']['access_control_allow_origin'],
                            'CSP': data['security_headers'].get('content-security-policy', ''),
                            'HSTS': data['security_headers'].get('strict-transport-security', ''),
                            'X-Frame-Options': data['security_headers'].get('x-frame-options', ''),
                            'Missing Headers': ', '.join(data['missing_headers']) if data['missing_headers'] else 'None'
                        })
                if rows:
                    df = pd.DataFrame(rows)
                    st.dataframe(df, use_container_width=True)
                    project_manager.save_scan_results('cors_headers', target_domain, df)
                    misconfigured = df[df['CORS Misconfigured'] == True]
                    if not misconfigured.empty:
                        st.warning(f"Found {len(misconfigured)} URLs with misconfigured CORS!")
                else:
                    st.info("No results.")
            except Exception as e:
                st.error(f"Scan failed: {e}")

    df = project_manager.load_scan_results('cors_headers', target_domain)
    if isinstance(df, pd.DataFrame) and not df.empty:
        with st.expander(f"Stored Results ({len(df)})"):
            st.dataframe(df, use_container_width=True)

# =====================================================================
# TAB 8: Advanced Scans (GraphQL + IDOR + Dependency Confusion)
# =====================================================================
with tab8:
    st.subheader(f"Advanced Scans: `{target_domain}`")

    # GraphQL
    st.markdown("### 🧬 GraphQL Scanner")
    live_df = project_manager.load_scan_results('live_hosts', target_domain)
    urls = []
    if isinstance(live_df, pd.DataFrame) and 'URL' in live_df.columns:
        for url in live_df['URL'].tolist():
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if base not in urls:
                urls.append(base)
    if not urls:
        urls = [f"https://{target_domain}", f"http://{target_domain}"]

    if st.button("🧬 Run GraphQL Scan", key="run_graphql"):
        with st.spinner("Scanning..."):
            progress = st.progress(0.0)
            try:
                results = graphql_scanner.scan(urls, progress_callback=lambda p, m: progress.progress(p, m))
                if results['endpoints']:
                    st.success(f"Found {len(results['endpoints'])} GraphQL endpoints.")
                    st.dataframe(pd.DataFrame({'Endpoint': results['endpoints']}), use_container_width=True)
                    project_manager.save_scan_results('graphql_endpoints', target_domain, pd.DataFrame({'Endpoint': results['endpoints']}))

                if results['analysis']:
                    for ep, analysis in results['analysis'].items():
                        with st.expander(f"Schema: {ep}"):
                            c1, c2, c3 = st.columns(3)
                            c1.metric("Types", analysis.get('total_types', 0))
                            c2.metric("Queries", analysis.get('query_fields', 0))
                            c3.metric("Mutations", analysis.get('mutation_fields', 0))

                            dangerous = analysis.get('dangerous_fields', {})
                            if dangerous:
                                st.warning("⚠️ Dangerous Fields")
                                for t, fields in dangerous.items():
                                    st.markdown(f"**{t}**: {', '.join(fields)}")

                            security = analysis.get('security', {})
                            if security and security.get('notes'):
                                st.error("🚨 Misconfigurations")
                                for note in security['notes']:
                                    st.markdown(f"- {note}")
            except Exception as e:
                st.error(f"GraphQL scan failed: {e}")

    graphql_stored = project_manager.load_scan_results('graphql_endpoints', target_domain)
    if isinstance(graphql_stored, pd.DataFrame) and not graphql_stored.empty:
        with st.expander(f"Stored GraphQL Endpoints ({len(graphql_stored)})"):
            st.dataframe(graphql_stored, use_container_width=True)

    # IDOR
    st.markdown("---")
    st.markdown("### 🔐 IDOR / BOLA Scanner")
    urls = []
    for scan_type in ['live_hosts', 'js_discovered_endpoints', 'param_miner']:
        df = project_manager.load_scan_results(scan_type, target_domain)
        if isinstance(df, pd.DataFrame):
            if 'URL' in df.columns:
                urls.extend(df['URL'].tolist())
            elif 'endpoint' in df.columns:
                urls.extend(df['endpoint'].tolist())
    urls = list(set([u for u in urls if is_valid_url(u)]))

    if urls:
        st.info(f"Testing {len(urls)} URLs for IDOR.")
        st.caption("IDOR/BOLA testing requires two authenticated sessions from different user accounts. "
                   "Paste each account's Cookie header below.")
        col_a, col_b = st.columns(2)
        with col_a:
            cookie_a = st.text_input("Session A cookie (User A - resource owner):", key="idor_cookie_a", type="password")
        with col_b:
            cookie_b = st.text_input("Session B cookie (User B - attacker):", key="idor_cookie_b", type="password")

        if not cookie_a or not cookie_b:
            st.warning("Provide both session cookies to run the IDOR scan.")
        elif st.button("🔐 Run IDOR Scan", key="run_idor"):
            with st.spinner("Scanning..."):
                progress = st.progress(0.0)
                try:
                    import requests as _requests
                    sess_a = _requests.Session()
                    sess_a.headers.update({'Cookie': cookie_a, 'User-Agent': 'DeepBug-IDOR/1.0'})
                    sess_b = _requests.Session()
                    sess_b.headers.update({'Cookie': cookie_b, 'User-Agent': 'DeepBug-IDOR/1.0'})
                    idor_scanner.set_sessions(sess_a, sess_b)
                    idor_df = idor_scanner.scan(urls, progress_callback=lambda p, m: progress.progress(p, m))
                    if not idor_df.empty:
                        st.success(f"Found {len(idor_df)} potential IDOR vulnerabilities.")
                        st.dataframe(idor_df, use_container_width=True)
                        project_manager.save_scan_results('idor_findings', target_domain, idor_df)
                    else:
                        st.info("No IDOR detected.")
                except Exception as e:
                    st.error(f"IDOR scan failed: {e}")
    else:
        st.warning("No URLs found. Run other scans first.")

    idor_stored = project_manager.load_scan_results('idor_findings', target_domain)
    if isinstance(idor_stored, pd.DataFrame) and not idor_stored.empty:
        with st.expander(f"Stored IDOR Findings ({len(idor_stored)})"):
            st.dataframe(idor_stored, use_container_width=True)

    # Dependency Confusion
    st.markdown("---")
    st.markdown("### 📦 Dependency Confusion")
    js_files_df = project_manager.load_scan_results('js_files', target_domain)
    dep_urls = []
    if isinstance(js_files_df, pd.DataFrame) and 'url' in js_files_df.columns:
        dep_urls = js_files_df['url'].tolist()

    if dep_urls:
        st.info(f"Checking {len(dep_urls)} URLs for dependencies.")
        if st.button("📦 Run Dependency Scan", key="run_dep"):
            with st.spinner("Scanning..."):
                progress = st.progress(0.0)
                try:
                    dep_df = dependency_scanner.scan(dep_urls, progress_callback=lambda p, m: progress.progress(p, m))
                    if not dep_df.empty:
                        st.success(f"Found {len(dep_df)} potential dependency confusion risks.")
                        st.dataframe(dep_df, use_container_width=True)
                        project_manager.save_scan_results('dependency_confusion', target_domain, dep_df)
                    else:
                        st.info("No risks found.")
                except Exception as e:
                    st.error(f"Dependency scan failed: {e}")
    else:
        st.warning("No JS files found. Run JS Analysis first.")

    dep_stored = project_manager.load_scan_results('dependency_confusion', target_domain)
    if isinstance(dep_stored, pd.DataFrame) and not dep_stored.empty:
        with st.expander(f"Stored Dependency Confusion Results ({len(dep_stored)})"):
            st.dataframe(dep_stored, use_container_width=True)

    # Supply Chain / SRI Audit
    st.markdown("---")
    st.markdown("### 🔗 Supply Chain Audit (SRI)")
    st.caption("Crawls live pages for third-party scripts/stylesheets loaded WITHOUT integrity= - "
               "a compromised CDN then executes JS in your origin. Also flags known-hostile CDNs "
               "(polyfill.io, rawgit) and cleartext resources.")

    sc_urls = []
    live_df3 = project_manager.load_scan_results('live_hosts', target_domain)
    if isinstance(live_df3, pd.DataFrame) and 'URL' in live_df3.columns:
        sc_urls.extend(live_df3['URL'].tolist())
    sc_urls = project_manager.filter_targets_by_scope(
        list(dict.fromkeys([u for u in sc_urls if is_valid_url(u)])))

    if sc_urls:
        st.info(f"Auditing {len(sc_urls)} pages.")
        if st.button("🔗 Run Supply Chain Audit", key="run_supply_chain"):
            with st.spinner("Auditing external resources..."):
                progress = st.progress(0.0, text="Starting...")
                try:
                    sc_results = supply_chain_auditor.scan(
                        sc_urls, progress_callback=lambda p, m: progress.progress(min(p, 1.0), text=m))
                    if sc_results:
                        sc_df = pd.DataFrame(sc_results)
                        crit = len(sc_df[sc_df['Risk'] == 'CRITICAL'])
                        high = len(sc_df[sc_df['Risk'] == 'HIGH'])
                        c1, c2, c3 = st.columns(3)
                        c1.metric("🚨 CRITICAL", crit)
                        c2.metric("🔥 HIGH", high)
                        c3.metric("Total risks", len(sc_df))
                        if crit:
                            st.error(f"🚨 {crit} CRITICAL supply-chain exposure(s) - known-hostile CDN!")
                        st.dataframe(sc_df, use_container_width=True)
                        project_manager.save_scan_results('supply_chain', target_domain, sc_df)
                        st.download_button("📥 Download Results", sc_df.to_csv(index=False),
                                           f"{target_domain}_supply_chain.csv", "text/csv", key="dl_sc")
                    else:
                        st.success("All third-party resources are integrity-protected. Clean.")
                except Exception as e:
                    st.error(f"Supply chain audit failed: {e}")
    else:
        st.warning("No live hosts found. Run subdomain scan first.")

    sc_df = project_manager.load_scan_results('supply_chain', target_domain)
    if isinstance(sc_df, pd.DataFrame) and not sc_df.empty:
        with st.expander(f"Stored Supply Chain Results ({len(sc_df)})"):
            st.dataframe(sc_df, use_container_width=True)

    # Mass Assignment & Type Juggling
    st.markdown("---")
    st.markdown("### 💉 Mass Assignment & Type Juggling")
    st.caption("Sam Curry style: injects privilege/business-logic fields the client never sends "
               "(admin, role, price...) and type-confuses query params. Response diffs expose "
               "backends that blindly honor them.")

    ma_urls = []
    for scan_type in ['js_discovered_endpoints', 'live_hosts', 'param_miner']:
        df = project_manager.load_scan_results(scan_type, target_domain)
        if isinstance(df, pd.DataFrame):
            if 'endpoint' in df.columns:
                ma_urls.extend(df['endpoint'].tolist())
            elif 'URL' in df.columns:
                ma_urls.extend(df['URL'].tolist())
    ma_urls = project_manager.filter_targets_by_scope(
        list(dict.fromkeys([u for u in ma_urls if is_valid_url(u)])))

    if ma_urls:
        st.info(f"Testing {len(ma_urls)} endpoints.")
        if st.button("💉 Run Mass Assignment Scan", key="run_mass_assignment"):
            with st.spinner("Injecting privilege fields..."):
                progress = st.progress(0.0, text="Starting...")
                try:
                    ma_results = mass_assignment_scanner.scan(
                        ma_urls, progress_callback=lambda p, m: progress.progress(min(p, 1.0), text=m))
                    if ma_results:
                        ma_df = pd.DataFrame(ma_results)
                        high = len(ma_df[ma_df['Severity'] == 'HIGH'])
                        if high:
                            st.error(f"🚨 {high} HIGH severity mass-assignment lead(s) - verify manually!")
                        st.dataframe(ma_df, use_container_width=True)
                        project_manager.save_scan_results('mass_assignment', target_domain, ma_df)
                        st.download_button("📥 Download Results", ma_df.to_csv(index=False),
                                           f"{target_domain}_mass_assignment.csv", "text/csv", key="dl_ma")
                    else:
                        st.success("No mass-assignment or type-juggling signals on the tested endpoints.")
                except Exception as e:
                    st.error(f"Mass assignment scan failed: {e}")
    else:
        st.warning("No endpoints found. Run other scans first.")

    ma_df = project_manager.load_scan_results('mass_assignment', target_domain)
    if isinstance(ma_df, pd.DataFrame) and not ma_df.empty:
        with st.expander(f"Stored Mass Assignment Results ({len(ma_df)})"):
            st.dataframe(ma_df, use_container_width=True)