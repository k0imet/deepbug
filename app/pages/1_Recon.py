import streamlit as st
import pandas as pd
import json
import sys
import time
import os as _os_mod
from pathlib import Path
from typing import List, Dict, Any

_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from app.utils.url_utils import urlparse
from urllib.parse import parse_qs
from app.modules.project_manager import ProjectManager
from app.modules.utils import load_config, setup_logging, validate_domain, validate_ip, is_valid_url
from app.modules.tools.subdomain_scanner import SubdomainScanner
from app.modules.tools.port_scanner import PortScanner
from app.modules.tools.js_analyzer import JSAnalyzer
from app.modules.tools.api_key_scanner import ApiKeyScanner
from app.modules.tools.webanalyze_scanner import WebanalyzeScanner
from app.modules.tools.gf_scanner import GFScanner
from app.modules.tools.cloud_enum import CloudScanner
from app.modules.tools.param_miner import ParamMiner
from app.modules.tools.cors_scanner import CORSHeadersScanner
from app.modules.tools.graphql_scanner import GraphQLScanner
from app.modules.tools.live_rest_validator import LiveRestValidator
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
from app.modules.tools.asn_dns_osint import ASNDNSOsint
from app.modules.tools.github_subdomains import GitHubSubdomains
from app.modules.tools.config_sensitive_scanner import ConfigSensitiveScanner
from app.modules.tools.open_redirect_scanner import OpenRedirectScanner
from app.modules.tools.git_disclosure_scanner import GitDisclosureScanner
from app.modules.tools.jwt_scanner import JWTScanner
from app.modules.tools.auth_gateway_scanner import AuthGatewayScanner
from app.modules.tools.bypass_403 import Bypass403Engine
from app.modules.tools.github_leak_scanner import GitHubLeakScanner
from app.modules.tools.classifier import classify_and_rank
from app.modules.tools.secret_chainer import SecretChainer
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
_target_valid = validate_domain(target_domain) or validate_ip(target_domain)
if target_domain and _target_valid:
    st.session_state[_pkey] = target_domain

if not target_domain or not _target_valid:
    st.warning("Enter a valid domain or IP (e.g., example.com or 127.0.0.1).")
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
api_key_scanner = ApiKeyScanner(CONFIG)
webanalyze_scanner = WebanalyzeScanner(CONFIG)
gf_scanner = GFScanner(CONFIG)
cloud_scanner = CloudScanner(CONFIG)
param_miner = ParamMiner(CONFIG)
cors_scanner = CORSHeadersScanner(CONFIG)
graphql_scanner = GraphQLScanner(CONFIG)
live_rest_validator = LiveRestValidator(CONFIG)
idor_scanner = IDORScanner(CONFIG)
dependency_scanner = DependencyConfusionScanner(CONFIG)
kxss_scanner = KXSSScanner(CONFIG)
pp_validator = PrototypePollutionValidator(CONFIG)
mass_assignment_scanner = MassAssignmentScanner(CONFIG)
csti_scanner = CSTIScanner(CONFIG)
supply_chain_auditor = SupplyChainAuditor(CONFIG)
url_cleaner = URLCleaner(CONFIG)
recon_runner = Reconnaissance(CONFIG)
asn_osint_scanner = ASNDNSOsint(CONFIG)
github_subdomains_scanner = GitHubSubdomains(CONFIG)
config_sensitive_scanner = ConfigSensitiveScanner(CONFIG)
open_redirect_scanner = OpenRedirectScanner(CONFIG)
git_disclosure_scanner = GitDisclosureScanner(CONFIG)
jwt_scanner = JWTScanner()
auth_gateway_scanner = AuthGatewayScanner()
bypass403_engine = Bypass403Engine(CONFIG)
github_leak_scanner = GitHubLeakScanner(CONFIG)
secret_chainer = SecretChainer(CONFIG)

# Host-gate the JS downloader with the project's scope rules when configured
# (wildcards + explicit in-scope), falling back to the target domain.
js_analyzer.scope_hosts = set(scope_manager.get_scope_hosts()) if (scope_manager and (scope_manager.in_scope or scope_manager.wildcard_scope)) else {target_domain}

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
                # Per-source subdomain results are part of the returned dict -
                # save every DataFrame the pipeline produced.
                for key, df in results.items():
                    if key.startswith('_'):
                        continue
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

    enum_mode = st.radio(
        "Enumeration mode:",
        ["Full subdomain scan", "Single URL (skip enumeration)"],
        horizontal=True, key="enum_mode",
        help="Single URL mode skips subdomain discovery entirely - the given "
             "URL is probed and flows straight into ports/JS/vuln/param steps.")

    if enum_mode == "Single URL (skip enumeration)":
        single_url = st.text_input(
            "In-scope URL (e.g. https://example.com or example.com):",
            key="single_url_input",
            placeholder=f"https://{target_domain}")
        s2 = st.columns(2)
        with s2[0]:
            single_ports = st.text_input("Extra ports (comma-separated, optional):", "",
                                         key="single_url_ports",
                                         help="Default: the URL's scheme port (443 for https, 80 for http).")
        with s2[1]:
            st.caption("Probes the host once; result is saved as `live_hosts` and flows into "
                       "Ports, JS Analysis, Vulnerability Detection, Parameter Mining and the Scanner.")
        if st.button("🚀 Probe Single URL", key="run_single_url"):
            with st.spinner("Probing..."):
                progress_bar = st.progress(0.0, text="Starting...")
                try:
                    from urllib.parse import urlparse as _up
                    raw = (single_url or '').strip()
                    if not raw.startswith(('http://', 'https://')):
                        raw = f'https://{raw}'
                    p = _up(raw)
                    host = (p.hostname or '').lower()
                    scheme = p.scheme.lower()
                    if not host or scheme not in ('http', 'https'):
                        st.error(f"Invalid URL: {single_url}")
                    elif not project_manager.filter_targets_by_scope([raw]):
                        st.error(f"🚫 {raw} is out of scope for this project.")
                    else:
                        port_list = []
                        if p.port:
                            port_list.append(str(p.port))
                        else:
                            port_list.append('443' if scheme == 'https' else '80')
                        for x in (single_ports or '').split(','):
                            x = x.strip()
                            if x.isdigit():
                                port_list.append(x)
                        port_list = list(dict.fromkeys(port_list))
                        progress_bar.progress(0.4, f"Probing {host} on ports {','.join(port_list)}...")
                        _probe = getattr(subdomain_scanner, 'probe_live_hosts_chunked', None)
                        if _probe:
                            http_results = _probe([host], extra_ports=port_list,
                                                  chunk_size=50, concurrency=10, rate_limit=50,
                                                  progress_callback=lambda p, m: progress_bar.progress(0.4 + p * 0.4, text=m))
                        else:
                            http_results = subdomain_scanner._run_httpx_with_ports([host], extra_ports=port_list)
                        # Ensure the user's exact URL survives even if the probe
                        # returned a normalized variant.
                        rows = [dict(r) for r in http_results]
                        if not any(str(r.get('URL', '')).rstrip('/') == raw.rstrip('/') for r in rows):
                            rows.insert(0, {'URL': raw, 'Input': host, 'StatusCode': '',
                                            'Title': '', 'WebServer': '', 'ContentLength': '', 'Technologies': ''})
                        if rows:
                            progress_bar.progress(0.95, "Saving...")
                            project_manager.save_scan_results('live_hosts', target_domain, pd.DataFrame(rows))
                            project_manager.save_scan_results('resolved_subdomains', target_domain,
                                                              pd.DataFrame([{'Subdomain': host, 'IP': ''}]))
                            st.success(f"✅ Single URL ready: {host} probed on {','.join(port_list)} — "
                                       f"{len(rows)} URL(s) saved as live_hosts. Continue in the other tabs.")
                        else:
                            st.warning("Probe returned no results — check the URL is reachable.")
                        progress_bar.progress(1.0, "Done.")
                except Exception as e:
                    st.error(f"Single URL probe failed: {e}")
    else:

        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            use_amass = st.checkbox("Amass", value=True, help=f"Capped at {5} min (set below)")
            use_subfinder = st.checkbox("Subfinder", value=True, help="Capped at 3 min")
        with col2:
            enable_ct = st.checkbox("CT Logs", value=True, help="Certificate Transparency")
            enable_perm = st.checkbox("Permutations", value=False, help="dnsgen/altdns/builtin - slow, capped at 3000")
            enable_wildcard = st.checkbox("Filter Wildcards", value=True)
        with col3:
            custom_ports = st.text_input("Httpx extra ports:", "",
                                          help="Comma-separated. Default: 443 only (fast). Add e.g. 80,8080,8443 to probe more.")
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
                    _probe = getattr(subdomain_scanner, 'probe_live_hosts_chunked', None)
                    if _probe:
                        # Chunked probing: httpx runs on manageable batches and the
                        # results are merged - avoids httpx blowing up on thousands
                        # of subdomains at once.
                        http_results = _probe(
                            probe_targets, extra_ports=extra_ports or None,
                            chunk_size=150, concurrency=25, rate_limit=150,
                            progress_callback=lambda p, m: progress_bar.progress(0.80 + p * 0.19, text=m))
                    else:
                        _probe_legacy = getattr(subdomain_scanner, '_run_httpx_with_ports', None)
                        if _probe_legacy:
                            http_results = _probe_legacy(probe_targets, extra_ports=extra_ports or None)
                        else:
                            st.caption("⚠️ Loaded SubdomainScanner is stale — using default ports. Restart Streamlit / update subdomain_scanner.py.")
                            http_results = subdomain_scanner._run_httpx(probe_targets)
                    progress_bar.progress(0.995, "Finalizing live hosts...")
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

        # ---- ASN & DNS OSINT ----
        st.markdown("---")
        asn_df = project_manager.load_scan_results('asn_osint', target_domain)
        if isinstance(asn_df, pd.DataFrame) and not asn_df.empty:
            with st.expander(f"🛰️ ASN & DNS OSINT ({len(asn_df)})"):
                st.dataframe(asn_df, use_container_width=True)
        with st.expander("🛰️ Run ASN & DNS OSINT"):
            st.caption("Keyless passive OSINT: BGPView ASN/prefix mapping, Hackertarget reverse lookups and "
                       "DoH SPF/DMARC/DKIM/MX queries — finds origin IPs and infrastructure behind CDNs.")
            if st.button("🛰️ Run", key="asn_osint_run"):
                with st.spinner("Querying BGPView / DoH / reverse lookups..."):
                    try:
                        res = asn_osint_scanner.scan_sync(target_domain)
                        rows = []
                        for a in res.get('asns', []):
                            rows.append({'Type': 'ASN', 'Value': a.get('asn', ''), 'Detail': a.get('org', '')})
                        for ip in res.get('origin_ips', []):
                            rows.append({'Type': 'Origin IP', 'Value': ip, 'Detail': 'apex A record'})
                        for rng in res.get('ipv4_ranges', []):
                            rows.append({'Type': 'IPv4 Range', 'Value': rng, 'Detail': 'ASN prefix'})
                        for rng in res.get('ipv6_ranges', []):
                            rows.append({'Type': 'IPv6 Range', 'Value': rng, 'Detail': 'ASN prefix'})
                        spf = res.get('spf', {})
                        if spf.get('record'):
                            rows.append({'Type': 'SPF', 'Value': spf['record'], 'Detail': f"all={spf.get('all', '')}"})
                        for inc in spf.get('include', []):
                            rows.append({'Type': 'SPF Include', 'Value': inc, 'Detail': ''})
                        for h in res.get('mx_hosts', []):
                            rows.append({'Type': 'MX Host', 'Value': h, 'Detail': ''})
                        dmarc = res.get('dmarc', {})
                        if dmarc.get('record'):
                            rows.append({'Type': 'DMARC', 'Value': dmarc['record'],
                                         'Detail': f"p={dmarc.get('p', '')}"})
                        for dk in res.get('dkim', []):
                            rows.append({'Type': 'DKIM', 'Value': dk.get('selector', ''),
                                         'Detail': (dk.get('record') or '')[:120]})
                        new_asn_df = pd.DataFrame(rows)
                        if not new_asn_df.empty:
                            project_manager.save_scan_results('asn_osint', target_domain, new_asn_df)
                            st.success(f"ASN/DNS OSINT complete — {len(new_asn_df)} records ({res.get('totals', {})})")
                            st.dataframe(new_asn_df, use_container_width=True)
                        else:
                            st.info("No ASN/DNS OSINT data returned.")
                    except Exception as e:
                        st.error(f"ASN & DNS OSINT failed: {e}")

        # ---- GitHub Subdomain OSINT ----
        st.markdown("---")
        gh_sub_df = project_manager.load_scan_results('github_subdomains', target_domain)
        if isinstance(gh_sub_df, pd.DataFrame) and not gh_sub_df.empty:
            with st.expander(f"🐙 GitHub Subdomain OSINT ({len(gh_sub_df)})"):
                st.dataframe(gh_sub_df, use_container_width=True)
        with st.expander("🐙 Run GitHub Subdomain OSINT"):
            st.caption("Queries the public GitHub search API (repo/commit metadata) for hostnames of this apex. "
                       "No token needed; code search requires GITHUB_TOKEN.")
            if st.button("🐙 Run", key="github_subdomains_run"):
                with st.spinner("Querying GitHub search API..."):
                    try:
                        res = github_subdomains_scanner.scan_sync(target_domain)
                        subs = res.get('subdomains', [])
                        new_gh_df = pd.DataFrame({'Subdomain': subs, 'Source': ['GitHub'] * len(subs)}) \
                            if subs else pd.DataFrame(columns=['Subdomain', 'Source'])
                        if not new_gh_df.empty:
                            project_manager.save_scan_results('github_subdomains', target_domain, new_gh_df)
                            st.success(f"Found {len(subs)} GitHub-derived subdomains ({res.get('sources')})")
                            st.dataframe(new_gh_df, use_container_width=True)
                        else:
                            st.info("No subdomains found via GitHub metadata.")
                    except Exception as e:
                        st.error(f"GitHub subdomain OSINT failed: {e}")

        st.markdown("---")
        st.subheader("🟢 Manual Live Host Probe")
        resolved_df = project_manager.load_scan_results('resolved_subdomains', target_domain)
        candidates = []
        if isinstance(resolved_df, pd.DataFrame) and not resolved_df.empty:
            if 'Subdomain' in resolved_df.columns:
                candidates = resolved_df['Subdomain'].dropna().astype(str).tolist()
            elif 'hostname' in resolved_df.columns:
                candidates = resolved_df['hostname'].dropna().astype(str).tolist()
            else:
                candidates = resolved_df.iloc[:, 0].dropna().astype(str).tolist()
        last_probe = ""
        try:
            lh_file = project_manager.get_current_project_path() / target_domain.replace('.', '_') / 'live_hosts_results.json'
            if lh_file.exists():
                last_probe = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lh_file.stat().st_mtime))
        except OSError:
            pass
        st.caption(f"Re-runs httpx on the **saved** resolved subdomains only — {len(candidates)} host(s) "
                   f"from `resolved_subdomains`." + (f" Last probe: **{last_probe}**." if last_probe else ""))
        mp1, mp2 = st.columns([1, 1])
        with mp1:
            manual_ports = st.text_input("Ports (comma-separated, default 443):", "", key="manual_probe_ports",
                                         help="Leave empty for 443 only. Add e.g. 80,8080 to probe more.")
        with mp2:
            if st.button("🟢 Probe Live Hosts", key="manual_probe_run", type="primary",
                         disabled=not candidates):
                with st.spinner("Probing..."):
                    progress_bar = st.progress(0.0, text="Starting...")
                    status_ph = st.empty()
                    import time as _t
                    _started = _t.time()
                    _log = []

                    def _probe_cb(p, m):
                        status_ph.caption(f"🟢 RUNNING — {m} · {_t.time() - _started:.0f}s elapsed")
                        progress_bar.progress(p, text=m)
                        if m and m not in _log:
                            _log.append(m)

                    try:
                        extra = [p.strip() for p in manual_ports.split(',') if p.strip().isdigit()]
                        http_results = subdomain_scanner.probe_live_hosts_chunked(
                            candidates, extra_ports=extra or None,
                            chunk_size=150, concurrency=25, rate_limit=150,
                            progress_callback=_probe_cb)
                        if http_results:
                            project_manager.save_scan_results('live_hosts', target_domain, pd.DataFrame(http_results))
                            status_ph.caption(f"✅ DONE — {len(http_results)} live hosts in "
                                              f"{_t.time() - _started:.0f}s.")
                            st.success(f"✅ {len(http_results)} live hosts saved to `live_hosts`.")
                            st.dataframe(pd.DataFrame(http_results), use_container_width=True)
                        else:
                            status_ph.caption(f"❌ DONE — 0 live hosts in {_t.time() - _started:.0f}s.")
                            st.warning("No live hosts found on the saved subdomains — "
                                       "check connectivity or add ports (e.g. 80,8080).")
                        if _log:
                            with st.expander("🩺 Probe log"):
                                for line in _log:
                                    st.caption(line)
                    except Exception as e:
                        status_ph.caption(f"❌ FAILED — {_t.time() - _started:.0f}s.")
                        st.error(f"Manual probe failed: {e}")
            else:
                st.caption("No saved `resolved_subdomains` yet — run the subdomain scan (or Single URL mode) first.")

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
        elif not project_manager.filter_targets_by_scope([port_target]):
            st.error(f"🚫 {port_target} is out of scope for this project.")
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
                    api_keys = len(results.get('js_api_keys', pd.DataFrame()))
                    frameworks = len(results.get('js_frameworks', pd.DataFrame()))
                    proto = len(results.get('js_prototype_pollution', pd.DataFrame()))
                    clobber = len(results.get('js_dom_clobbering', pd.DataFrame()))
                    postmsg = len(results.get('js_postmessage_issues', pd.DataFrame()))
                    dangerous = len(results.get('js_dangerous_patterns', pd.DataFrame()))
                    jsonp = len(results.get('js_jsonp_endpoints', pd.DataFrame()))

                    st.success(
                        f"JS v3.0 complete! 🎯 {total_endpoints} endpoints | "
                        f"🔴 {critical} critical | 🔑 {secrets} secrets | 🔐 {api_keys} API keys | "
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
    js_sub1, js_sub2, js_sub3, js_sub4, js_sub5, js_sub6, js_sub7, js_sub8, js_sub9, js_sub10 = st.tabs([
        "📊 Overview", "🔑 Secrets & Patterns", "⚠️ Client-Side Vectors", "📂 Endpoints",
        "🧪 PP Validation", "🖥️ DOM XSS", "🌐 CORS", "↩️ Open Redirect", "📡 SSRF",
        "🔐 API Keys"
    ])

    # Preload all stored frames once. Individual js_* keys are written by the
    # page's own runs; the combined nested 'js_analysis' dict is written by the
    # Full Recon pipeline / legacy runs — fall back to it so data always renders.
    _js_nested = project_manager.load_scan_results('js_analysis', target_domain)

    def _load_js(key: str, sub: str = '') -> pd.DataFrame:
        df = project_manager.load_scan_results(key, target_domain)
        if not isinstance(df, pd.DataFrame) or df.empty:
            if isinstance(_js_nested, dict) and (sub or key) in _js_nested:
                df = _js_nested[sub or key]
        if not isinstance(df, pd.DataFrame) or df.empty:
            return df
        df = df.copy()
        # Normalize URL-ish columns so the display guards work regardless of
        # which writer produced the frame.
        if key == 'js_discovered_endpoints' and 'endpoint' not in df.columns and 'URL' in df.columns:
            df = df.rename(columns={'URL': 'endpoint'})
        if key == 'js_files' and 'url' not in df.columns and 'URL' in df.columns:
            df = df.rename(columns={'URL': 'url'})
        return df

    frameworks_df = _load_js('js_frameworks', 'js_frameworks')
    proto_df = _load_js('js_prototype_pollution', 'js_prototype_pollution')
    dangerous_df = _load_js('js_dangerous_patterns', 'js_dangerous_patterns')
    secrets_df = _load_js('js_sensitive_data_findings', 'js_sensitive_data_findings')
    priority_df = _load_js('js_priority_endpoints', 'js_priority_endpoints')
    clobber_df = _load_js('js_dom_clobbering', 'js_dom_clobbering')
    postmsg_df = _load_js('js_postmessage_issues', 'js_postmessage_issues')
    jsonp_df = _load_js('js_jsonp_endpoints', 'js_jsonp_endpoints')
    rendering_df = _load_js('js_dynamic_rendering', 'js_dynamic_rendering')
    csp_df = _load_js('js_csp_gadgets', 'js_csp_gadgets')
    endpoints_df = _load_js('js_discovered_endpoints', 'js_discovered_endpoints')
    graphql_df = _load_js('js_graphql_endpoints', 'js_graphql_endpoints')
    ws_df = _load_js('js_websocket_endpoints', 'js_websocket_endpoints')
    maps_df = _load_js('js_source_maps', 'js_source_maps')

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

        # ---- JWT audit ----
        jwt_df = project_manager.load_scan_results('jwt_audit', target_domain)
        if _has(jwt_df):
            with st.expander(f"🔐 JWT Audit ({len(jwt_df)})"):
                st.dataframe(jwt_df, use_container_width=True)
        with st.expander("🔐 Run JWT Audit"):
            st.caption("Fetches JS files and audits any JWT-looking tokens found: decodes header/payload, "
                       "flags alg=none and offline-cracks HS256 tokens against a weak-key list. "
                       "Forged tokens are never sent anywhere.")
            js_files_df = project_manager.load_scan_results('js_files', target_domain)
            js_file_urls = []
            if isinstance(js_files_df, pd.DataFrame) and 'url' in js_files_df.columns:
                js_file_urls = [u for u in js_files_df['url'].tolist() if is_valid_url(u)]
            if not js_file_urls:
                js_file_urls = [u for u in urls if is_valid_url(u)]
            st.caption(f"{len(js_file_urls)} candidate JS/URL(s) queued.")
            if st.button("🔐 Run JWT Audit", key="jwt_audit_run"):
                if not js_file_urls:
                    st.info("No JS file URLs. Run JS Analysis first.")
                else:
                    with st.spinner("Fetching and auditing JWTs..."):
                        try:
                            rows = jwt_scanner.scan_sync(js_file_urls)
                            new_jwt_df = pd.DataFrame(rows) if rows else pd.DataFrame()
                            if not new_jwt_df.empty:
                                project_manager.save_scan_results('jwt_audit', target_domain, new_jwt_df)
                                cracked = int((new_jwt_df['cracked_key'].astype(str) != '').sum())
                                if cracked:
                                    st.error(f"🔑 {cracked} FORGEABLE JWT(s) — weak signing key cracked!")
                                st.dataframe(new_jwt_df, use_container_width=True)
                            else:
                                st.info("No JWTs found in the fetched bodies.")
                        except Exception as e:
                            st.error(f"JWT audit failed: {e}")

        # ---- Secret chain validation ----
        chain_df = project_manager.load_scan_results('secret_chain', target_domain)
        if _has(chain_df):
            with st.expander(f"🔗 Secret Chain Validation ({len(chain_df)})"):
                st.dataframe(chain_df, use_container_width=True)
        with st.expander("🔗 Run Secret Chain Validation"):
            st.caption("Takes the top leaked-secret candidates and performs ONE read-only probe against each "
                       "provider API (GitHub/Stripe/Slack/Twilio/Google...). No writes, no brute-force.")
            if st.button("🔗 Run", key="secret_chain_run"):
                secret_rows = secrets_df.head(10).to_dict('records') if _has(secrets_df) else []
                if not secret_rows:
                    st.info("No secrets to validate — run JS Analysis first.")
                else:
                    with st.spinner(f"Validating {len(secret_rows)} secrets against provider APIs..."):
                        try:
                            res = secret_chainer.scan_sync(secret_rows)
                            scanned = res.get('scanned', [])
                            new_chain_df = pd.DataFrame(scanned) if scanned else pd.DataFrame()
                            verified = len(res.get('findings', []))
                            if not new_chain_df.empty:
                                project_manager.save_scan_results('secret_chain', target_domain, new_chain_df)
                                if verified:
                                    st.error(f"🚨 {verified} LIVE secret(s) confirmed — rotate immediately!")
                                st.dataframe(new_chain_df, use_container_width=True)
                            else:
                                st.info("No secrets had a matching validation chain.")
                        except Exception as e:
                            st.error(f"Secret chain validation failed: {e}")

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

    # ================= API KEYS (precise keyhacks corpus) =================
    with js_sub10:
        st.caption("Precise API-key detection against the **streaak/keyhacks** corpus "
                   "(105 key-format regexes across 89 services). Only known key formats "
                   "for named services are flagged — no generic entropy guessing.")

        api_df = _load_js('js_api_keys', 'js_api_keys')
        ak_found = 0
        if _has(api_df):
            ak_found = len(api_df)
            ak_c1, ak_c2, ak_c3, ak_c4 = st.columns(4)
            ak_c1.metric("🔐 API Keys", ak_found)
            critical_ak = int((api_df['severity'].astype(str) == 'CRITICAL').sum()) if 'severity' in api_df else 0
            ak_c2.metric("🚨 Critical", critical_ak)
            ak_c3.metric("🏷️ Services", api_df['service'].nunique() if 'service' in api_df else 0)
            ak_c4.metric("📄 Sources", api_df['source'].nunique() if 'source' in api_df else 0)

            if 'service' in api_df.columns:
                svc_counts = api_df['service'].value_counts()
                if len(svc_counts) > 8:
                    svc_counts = svc_counts.head(8)
                st.bar_chart(svc_counts)

            ak_view = api_df.copy()
            if 'value' in ak_view.columns:
                ak_view['value'] = ak_view['value'].apply(
                    lambda x: str(x)[:8] + '...' + str(x)[-4:] if len(str(x)) > 12 else x)
            if 'verification' in ak_view.columns:
                ak_view['verification'] = ak_view['verification'].apply(
                    lambda x: str(x)[:120] + ('...' if len(str(x)) > 120 else ''))
            st.dataframe(ak_view, use_container_width=True)
            st.download_button("📥 Download API Keys", api_df.to_csv(index=False),
                               f"{target_domain}_api_keys.csv", "text/csv", key="dl_js_api_keys")

            if 'verification' in api_df.columns:
                with st.expander("🔎 Verification commands for the matches above"):
                    seen_cmds = set()
                    for _, row in api_df.iterrows():
                        cmd = str(row.get('verification', '')).strip()
                        if not cmd or cmd in seen_cmds:
                            continue
                        seen_cmds.add(cmd)
                        st.markdown(f"**{row.get('service', '')}** / `{row.get('key_name', '')}`")
                        st.code(cmd, language='bash')

        # ---- standalone run: re-scan the cached JS bodies ----
        with st.expander("🚀 Run API Key Scan"):
            js_files_df = project_manager.load_scan_results('js_files', target_domain)
            ak_cached = []
            ak_urls = []
            if isinstance(js_files_df, pd.DataFrame) and not js_files_df.empty:
                if 'content' in js_files_df.columns:
                    ak_cached = [(r.get('url', ''), r.get('content', ''))
                                 for _, r in js_files_df.iterrows()
                                 if r.get('url') and isinstance(r.get('content'), str) and r.get('content')]
                if not ak_cached and 'url' in js_files_df.columns:
                    ak_urls = [u for u in js_files_df['url'].tolist() if is_valid_url(u)]
            if not ak_urls:
                ak_urls = [u for u in urls if is_valid_url(u)]
            if ak_cached:
                st.caption(f"⚡ {len(ak_cached)} JS file(s) **cached from JS Analysis** — scanning "
                           "content in place, no re-fetch. Results are saved as `js_api_keys`.")
            else:
                st.caption(f"{len(ak_urls)} JS URL(s) — no cached bodies found (re-run JS Analysis to "
                           "cache them), so these will be fetched live.")
            if st.button("🔐 Run API Key Scan", key="run_api_key_scan"):
                if not ak_cached and not ak_urls:
                    st.info("No JS files to scan. Run JS Analysis first.")
                else:
                    with st.spinner("Scanning JS for API keys..."):
                        ak_progress = st.progress(0.0, text="Starting...")
                        try:
                            if ak_cached:
                                scanned = []
                                for idx, (u, body) in enumerate(ak_cached):
                                    scanned.extend(api_key_scanner.scan_js_content(body, u))
                                    ak_progress.progress((idx + 1) / len(ak_cached),
                                                         text=f"Scanned {idx + 1}/{len(ak_cached)} cached files")
                                errors = []
                            else:
                                ak_res = api_key_scanner.scan_urls(
                                    ak_urls,
                                    progress_callback=lambda p, m: ak_progress.progress(
                                        min(max(p, 0.0), 1.0), text=m))
                                scanned = ak_res.get('scanned', [])
                                errors = ak_res.get('errors', [])
                            if scanned:
                                ak_new_df = pd.DataFrame(scanned)
                                project_manager.save_scan_results('js_api_keys', target_domain, ak_new_df)
                                n_crit = int((ak_new_df['severity'].astype(str) == 'CRITICAL').sum())
                                st.error(f"🔑 {len(scanned)} API key(s) found — {n_crit} CRITICAL. Verify manually!")
                                st.dataframe(ak_new_df, use_container_width=True)
                            else:
                                n_src = len(ak_cached) if ak_cached else len(ak_urls)
                                st.info(f"No API keys found across {n_src} JS file(s).")
                            if 'errors' in dir() and errors:
                                with st.expander(f"⚠️ {len(errors)} fetch error(s)"):
                                    st.code('\n'.join(errors[:20]))
                        except Exception as e:
                            st.error(f"API key scan failed: {e}")
                            import traceback
                            st.code(traceback.format_exc())

        if not _has(api_df) and 'run_api_key_scan' not in st.session_state:
            st.info("No API-key findings yet — run **JS Analysis** (now includes API-key scanning) "
                    "or use the standalone scan above.")

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
    urls = project_manager.filter_targets_by_scope(urls)
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
        xss_candidates = project_manager.filter_targets_by_scope(xss_candidates)

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

    # ---- Sensitive Config Exposure ----
    st.markdown("---")
    st.subheader("⚙️ Sensitive Config Exposure")
    cfg_sens_df = project_manager.load_scan_results('config_sensitive', target_domain)
    if isinstance(cfg_sens_df, pd.DataFrame) and not cfg_sens_df.empty:
        with st.expander(f"Stored Config Exposure Results ({len(cfg_sens_df)})"):
            st.dataframe(cfg_sens_df, use_container_width=True)
    with st.expander("⚙️ Run Sensitive Config Exposure"):
        st.caption("Probes actuator/env/.env/swagger paths on live origins — a row becomes a finding only "
                   "with hard evidence markers in the body (propertySources, sensitive KEY=value...).")
        cfg_live_df = project_manager.load_scan_results('live_hosts', target_domain)
        cfg_urls = []
        if isinstance(cfg_live_df, pd.DataFrame) and 'URL' in cfg_live_df.columns:
            cfg_urls = [u for u in cfg_live_df['URL'].tolist() if is_valid_url(u)]
        if not cfg_urls:
            manual_cfg = st.text_input("Comma-separated URLs:", key="config_sensitive_urls")
            cfg_urls = [u.strip() for u in manual_cfg.split(",") if is_valid_url(u.strip())]
        cfg_urls = project_manager.filter_targets_by_scope(cfg_urls)
        st.caption(f"{len(cfg_urls)} live host URL(s) queued.")
        if st.button("⚙️ Run", key="config_sensitive_run"):
            if not cfg_urls:
                st.info("No live hosts found. Run subdomain scan first or paste URLs above.")
            else:
                with st.spinner("Probing sensitive config paths..."):
                    try:
                        res = config_sensitive_scanner.scan_sync(cfg_urls)
                        new_cfg_df = pd.DataFrame(res.get('rows', []))
                        if not new_cfg_df.empty:
                            project_manager.save_scan_results('config_sensitive', target_domain, new_cfg_df)
                            findings = len(res.get('findings', []))
                            if findings:
                                st.error(f"🚨 {findings} evidence-backed exposure(s) found!")
                            st.dataframe(new_cfg_df, use_container_width=True)
                        else:
                            st.info("No config endpoints probed.")
                    except Exception as e:
                        st.error(f"Config exposure scan failed: {e}")

    # ---- Open Redirect Candidates ----
    st.markdown("---")
    st.subheader("↩️ Open Redirect Candidates")
    or_df = project_manager.load_scan_results('open_redirect_candidates', target_domain)
    if isinstance(or_df, pd.DataFrame) and not or_df.empty:
        with st.expander(f"Stored Open Redirect Candidates ({len(or_df)})"):
            st.dataframe(or_df, use_container_width=True)
    with st.expander("↩️ Run Open Redirect Scan"):
        st.caption(f"Swaps redirect-style param values with the canary host `{open_redirect_scanner.canary}` "
                   "and flags any response that echoes it — passive, in-scope only.")
        if st.button("↩️ Run", key="open_redirect_run"):
            with st.spinner("Probing redirect parameters..."):
                try:
                    res = open_redirect_scanner.scan_sync(urls)
                    new_or_df = pd.DataFrame(res.get('findings', []))
                    if not new_or_df.empty:
                        project_manager.save_scan_results('open_redirect_candidates', target_domain, new_or_df)
                        st.success(f"Found {len(new_or_df)} open-redirect candidates!")
                        st.dataframe(new_or_df, use_container_width=True)
                    else:
                        st.info(f"No redirect candidates on {res.get('totals', {}).get('urls', 0)} tested URLs.")
                except Exception as e:
                    st.error(f"Open redirect scan failed: {e}")

    # ---- Git Disclosure ----
    st.markdown("---")
    st.subheader("🗂️ Git Disclosure")
    git_df = project_manager.load_scan_results('git_disclosure', target_domain)
    if isinstance(git_df, pd.DataFrame) and not git_df.empty:
        with st.expander(f"Stored Git Disclosure Results ({len(git_df)})"):
            st.dataframe(git_df, use_container_width=True)
    with st.expander("🗂️ Run Git Disclosure Scan"):
        st.caption("Probes `/.git/HEAD` on each base origin and walks the commit/tree/blob chain to pull "
                   "high-value files (.env, credentials, keys) — a limited git-dumper-lite.")
        if st.button("🗂️ Run", key="git_disclosure_run"):
            with st.spinner("Probing .git directories..."):
                try:
                    res = git_disclosure_scanner.scan_sync(urls)
                    rows = []
                    for r in res.get('results', []):
                        if r.get('exposed'):
                            for f in r.get('files', []):
                                rows.append({
                                    'Base': r.get('base', ''), 'Branch': r.get('branch', ''),
                                    'Exposed': True, 'File': f.get('path', ''),
                                    'Secrets': ', '.join(f.get('secrets', [])),
                                    'Snippet': f.get('snippet', '')[:160],
                                })
                        else:
                            rows.append({'Base': r.get('base', ''), 'Branch': '', 'Exposed': False,
                                         'File': '', 'Secrets': '', 'Snippet': r.get('note', '')})
                    new_git_df = pd.DataFrame(rows)
                    exposed = res.get('totals', {}).get('exposed', 0)
                    if not new_git_df.empty or exposed:
                        project_manager.save_scan_results('git_disclosure', target_domain, new_git_df)
                        if exposed:
                            st.error(f"🚨 {exposed} exposed .git repository(ies) — full source disclosure!")
                        st.success(f"Git disclosure scan complete: {res.get('totals', {})}")
                        st.dataframe(new_git_df, use_container_width=True)
                    else:
                        st.info("No git disclosure findings.")
                except Exception as e:
                    st.error(f"Git disclosure scan failed: {e}")

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
    urls = project_manager.filter_targets_by_scope(urls)
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

    if x8_path:
        xc1, xc2 = st.columns(2)
        with xc1:
            x8_conc = st.slider("x8 concurrency (requests/URL):", 3, 40,
                                int(CONFIG.get('param_miner', {}).get('x8_concurrency', 15)),
                                key="pm_x8_conc", help="Per-URL parallelism. Lower it on WAF-fronted targets.")
        with xc2:
            x8_procs = st.slider("Parallel x8 processes:", 1, 8,
                                 int(CONFIG.get('param_miner', {}).get('x8_processes', 4)),
                                 key="pm_x8_procs", help="How many URLs are fuzzed at once.")
        t1, t2 = st.columns([2, 3])
        with t1:
            test_x8 = st.button("🧪 Test x8 (raw output)", key="pm_test_x8",
                                help="Run x8 once against the first URL and show its raw stdout + parsed JSON - "
                                     "proves the binary, flags and parser all work.")
        with t2:
            st.caption("Diagnose x8 before a full run: shows the exact console output and parsed findings.")
        if test_x8:
            test_url = urls[0] if urls else f"https://{target_domain}"
            with st.spinner(f"Running x8 self-test against {test_url}..."):
                diag = param_miner.x8_self_test(test_url)
            if diag.get('ok'):
                st.success(f"x8 self-test passed (exit {diag.get('exit_code')}) — binary, flags and parser OK.")
            else:
                st.error(f"x8 self-test failed: {diag.get('error') or diag.get('stderr')}")
            with st.expander("🧪 Raw x8 output", expanded=True):
                st.caption(f"Command: `x8 -u {test_url} -w <wordlist> -X GET -c 5 -O json`")
                if diag.get('stdout'):
                    st.text(diag['stdout'][-1500:])
                if diag.get('stderr'):
                    st.warning(diag['stderr'][-800:])
                if diag.get('json_output'):
                    st.json(diag['json_output'])

    fuzz_urls = list(urls)
    if manual_pm_urls.strip():
        fuzz_urls.extend(u.strip() for u in manual_pm_urls.splitlines() if is_valid_url(u.strip()))
    fuzz_urls = project_manager.filter_targets_by_scope(fuzz_urls)
    fuzz_urls = list(dict.fromkeys(fuzz_urls))[:max_urls]

    st.info(f"Ready to fuzz {len(fuzz_urls)} URLs (of {len(urls)} collected).")

    if st.button("🔑 Run Parameter Mining", key="run_param_miner"):
        param_miner.enable_osint = enable_osint and bool(ps_path)
        param_miner.x8_concurrency = x8_conc if x8_path else param_miner.x8_concurrency
        param_miner.x8_processes = x8_procs if x8_path else param_miner.x8_processes
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
                                'Method': p.get('method', 'GET'),
                                'Parameter': p['parameter'],
                                'Injection': p.get('injection_place', ''),
                                'Value': p.get('value') or '',
                                'Status': p.get('status', ''),
                                'Reason': p.get('reason', ''),
                                'Tool': p.get('tool', ''),
                            })
                    df = pd.DataFrame(rows)
                    st.dataframe(df, use_container_width=True)
                    st.caption("`Injection` = where the parameter lives (Path/Query/Body/Header) · `Reason` = why x8 flagged it "
                               "(e.g. Reflected, status/size delta). Copy the URL into Burp/Caido to validate.")
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

                # Always show run stats - "did x8 actually run, and what did it say?"
                st.caption(
                    f"⚙️ Run stats: engine=`{stats.get('engine', '?')}` · "
                    f"{stats.get('urls_tested', 0)} URLs fuzzed · "
                    f"{stats.get('total_params', 0)} params found · "
                    f"wordlist={stats.get('wordlist_size', 0)} · "
                    f"OSINT params={stats.get('historical_params', 0)} · "
                    f"tool errors={len(errors)}"
                )
                x8_out = getattr(param_miner, '_x8_stdout', {})
                if x8_out and stats.get('engine') == 'x8':
                    with st.expander(f"🩺 x8 console output ({len(x8_out)} URLs)"):
                        for u, tail in list(x8_out.items())[:10]:
                            st.caption(u)
                            st.code(tail, language="text")

                # ---- Historical OSINT yield (ParamSpider / Wayback) ----
                # On WAF-fronted targets this is often the ONLY yield - always show it.
                # Params are joined to the exact archived URLs they appeared on,
                # so they are actionable (not a bare list of names).
                hist_params = getattr(param_miner, 'last_historical_params', [])
                hist_urls = getattr(param_miner, 'last_historical_urls', [])
                hist_pairs = []
                for u in hist_urls:
                    try:
                        parsed = urlparse(u)
                        for name, vals in parse_qs(parsed.query).items():
                            hist_pairs.append({
                                'URL': u,
                                'Parameter': name,
                                'Sample Value': vals[0] if vals else '',
                            })
                    except Exception:
                        continue
                if hist_pairs:
                    hist_df = pd.DataFrame(hist_pairs).drop_duplicates(subset=['URL', 'Parameter'])
                    project_manager.save_scan_results('param_miner_historical', target_domain, hist_df)
                    with st.expander(f"🕰️ Historical params from Wayback ({len(hist_df)} on {len(hist_urls)} archived URLs)",
                                     expanded=not results):
                        st.caption("Each row shows the exact archived URL the parameter was seen on - paste it into "
                                   "Burp/Caido or feed to GF/kxss. Also saved to disk for the Vulnerability Detection tab.")
                        st.dataframe(hist_df, use_container_width=True)
                        st.download_button("📥 Download historical params (URL + param)",
                                           hist_df.to_csv(index=False),
                                           f"{target_domain}_historical_params.csv", "text/csv", key="dl_hist_params")
                elif hist_params:
                    st.caption(f"🕰️ {len(hist_params)} historical parameter names seen (no query-string URLs retained).")

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
    urls = project_manager.filter_targets_by_scope(urls)
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
    # feed known GraphQL endpoints from JS analysis straight in
    for scan_type, col in (('js_graphql_endpoints', 'endpoint'),
                           ('js_discovered_endpoints', 'endpoint')):
        df = project_manager.load_scan_results(scan_type, target_domain)
        if isinstance(df, pd.DataFrame) and col in df.columns:
            for u in df[col].dropna().astype(str):
                low = u.lower()
                if 'graphql' in low or 'gql' in low:
                    urls.append(u)
    urls = list(dict.fromkeys(urls))
    urls = project_manager.filter_targets_by_scope(urls)
    if not urls:
        urls = [f"https://{target_domain}", f"http://{target_domain}"]
    st.caption(f"Probing {len(urls)} candidate base(s) — introspection, security probes, and "
               "clairvoyance schema reconstruction (introspection-disabled targets). "
               "Results persist under graphql_endpoints / graphql_schemas / "
               "graphql_clairvoyance / graphql_security.")

    if st.button("🧬 Run GraphQL Scan", key="run_graphql"):
        with st.spinner("Scanning..."):
            progress = st.progress(0.0)
            try:
                results = graphql_scanner.scan(urls, progress_callback=lambda p, m: progress.progress(p, m))
                if results['endpoints']:
                    st.success(f"Found {len(results['endpoints'])} GraphQL endpoints.")
                    st.dataframe(pd.DataFrame({'Endpoint': results['endpoints']}), use_container_width=True)
                    project_manager.save_scan_results('graphql_endpoints', target_domain, pd.DataFrame({'Endpoint': results['endpoints']}))

                if results['schemas']:
                    rows = [{'endpoint': ep, 'schema': json.dumps(s)} for ep, s in results['schemas'].items()]
                    project_manager.save_scan_results('graphql_schemas', target_domain, pd.DataFrame(rows))

                if results['clairvoyance']:
                    rows = []
                    for ep, recon in results['clairvoyance'].items():
                        types = {n: {'fields': list(info.get('fields', []))}
                                 for n, info in recon.get('types', {}).items()}
                        rows.append({
                            'endpoint': ep, 'viable': bool(recon.get('viable')),
                            'root_query': recon.get('root_query', ''),
                            'root_mutation': recon.get('root_mutation', ''),
                            'requests': int(recon.get('requests_made', 0)),
                            'note': recon.get('note', ''),
                            'type_count': len(recon.get('types', {})),
                            'types': json.dumps(types),
                        })
                    project_manager.save_scan_results('graphql_clairvoyance', target_domain, pd.DataFrame(rows))

                if results['security']:
                    rows = [{'endpoint': ep, 'notes': '\n'.join(sec.get('notes', [])),
                             'details': json.dumps(sec)} for ep, sec in results['security'].items()]
                    project_manager.save_scan_results('graphql_security', target_domain, pd.DataFrame(rows))

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

                if results['clairvoyance']:
                    for ep, recon in results['clairvoyance'].items():
                        with st.expander(f"🔮 Clairvoyance (schema reconstruction): {ep}"):
                            st.markdown(f"**Viable**: {recon.get('viable')} · "
                                        f"**Root query**: `{recon.get('root_query')}` · "
                                        f"**Root mutation**: `{recon.get('root_mutation')}` · "
                                        f"**Requests**: {recon.get('requests_made')}")
                            st.markdown(f"*{recon.get('note', '')}*")
                            if recon.get('types'):
                                with st.expander(f"{len(recon['types'])} reconstructed type(s)"):
                                    for tname, info in recon['types'].items():
                                        fields = ', '.join(info.get('fields', [])[:25])
                                        st.markdown(f"- **{tname}**: `{fields}`")
            except Exception as e:
                st.error(f"GraphQL scan failed: {e}")
                import traceback
                st.code(traceback.format_exc())

    graphql_stored = project_manager.load_scan_results('graphql_endpoints', target_domain)
    if isinstance(graphql_stored, pd.DataFrame) and not graphql_stored.empty:
        with st.expander(f"Stored GraphQL Endpoints ({len(graphql_stored)})"):
            st.dataframe(graphql_stored, use_container_width=True)

    gql_sec_stored = project_manager.load_scan_results('graphql_security', target_domain)
    if isinstance(gql_sec_stored, pd.DataFrame) and not gql_sec_stored.empty:
        with st.expander(f"⚠️ Stored GraphQL Security Findings ({len(gql_sec_stored)})"):
            for _, r in gql_sec_stored.iterrows():
                notes = str(r.get('notes', '')).strip()
                if notes:
                    st.markdown(f"**{r.get('endpoint', '')}**")
                    for line in notes.splitlines():
                        st.markdown(f"- {line}")

    gql_clair_stored = project_manager.load_scan_results('graphql_clairvoyance', target_domain)
    if isinstance(gql_clair_stored, pd.DataFrame) and not gql_clair_stored.empty:
        with st.expander(f"🔮 Stored Clairvoyance Results ({len(gql_clair_stored)})"):
            for _, r in gql_clair_stored.iterrows():
                st.markdown(f"**{r.get('endpoint', '')}** — viable={r.get('viable')} "
                            f"root_q=`{r.get('root_query', '')}` root_m=`{r.get('root_mutation', '')}` "
                            f"({r.get('requests', 0)} req, {r.get('type_count', 0)} types)")
                note = str(r.get('note', '')).strip()
                if note:
                    st.caption(note)
                types_raw = r.get('types', '')
                if isinstance(types_raw, str) and types_raw and types_raw != '{}':
                    try:
                        types = json.loads(types_raw)
                        with st.expander(f"{len(types)} reconstructed type(s)"):
                            for tname, info in types.items():
                                fields = ', '.join(info.get('fields', [])[:25])
                                st.markdown(f"- **{tname}**: `{fields}`")
                    except Exception:
                        pass

    gql_schema_stored = project_manager.load_scan_results('graphql_schemas', target_domain)
    if isinstance(gql_schema_stored, pd.DataFrame) and not gql_schema_stored.empty:
        with st.expander(f"📦 Stored GraphQL Schemas ({len(gql_schema_stored)})"):
            for _, r in gql_schema_stored.iterrows():
                st.markdown(f"- `{r.get('endpoint', '')}` ({len(str(r.get('schema', '')))} bytes)")

    # IDOR
    st.markdown("---")
    st.markdown("### 🚦 REST Validation Battery")
    st.caption("Proves injection on high-value REST endpoints: baseline request vs. "
               "single-shot NoSQL/SQL probes on login/auth/search/CRUD endpoints "
               "(GET only + one POST attempt per login form). Flags server errors, "
               "DB-error signatures and auth-bypass status flips. Results saved as "
               "`live_validation_results`.")
    rv_endpoints = project_manager.load_scan_results('js_discovered_endpoints', target_domain)
    rv_rows = []
    if isinstance(rv_endpoints, pd.DataFrame) and not rv_endpoints.empty:
        rv_rows = rv_endpoints.to_dict('records')
    rv_manual = st.text_area("Extra URLs (one per line, optional):", height=60,
                             key="rv_manual_urls")
    if rv_manual.strip():
        for u in rv_manual.splitlines():
            u = u.strip()
            if is_valid_url(u):
                rv_rows.append({'endpoint': u, 'method': 'GET'})
    rv_filtered = set(project_manager.filter_targets_by_scope(
        [r.get('endpoint', '') for r in rv_rows]))
    rv_rows = [r for r in rv_rows if r.get('endpoint', '') in rv_filtered]
    st.caption(f"{len(rv_rows)} candidate endpoint(s) on this target queued.")
    if st.button("🚦 Run REST Validation", key="run_rest_validation"):
        if not rv_rows:
            st.info("No endpoints — run JS Analysis first.")
        else:
            with st.spinner("Validating REST endpoints..."):
                rv_progress = st.progress(0.0, text="Starting...")
                try:
                    rv_target_host = ''
                    if isinstance(target_domain, str) and target_domain:
                        rv_target_host = target_domain.lower().rstrip('.')
                    from app.modules.integrations.auth_session import AuthSession as _RVAuth
                    _rv_auth = _RVAuth.load(project_manager.get_current_project_path(), target_domain)
                    findings = live_rest_validator.scan(
                        rv_rows, target_host=rv_target_host,
                        session=(_rv_auth if _rv_auth is not None and _rv_auth.authenticated else None),
                        progress_callback=lambda p, m: rv_progress.progress(
                            min(max(p, 0.0), 1.0), text=m))
                    if findings:
                        rv_df = pd.DataFrame(findings)
                        project_manager.save_scan_results('live_validation_results',
                                                          target_domain, rv_df)
                        n_high = int((rv_df['severity'].astype(str) == 'HIGH').sum())
                        st.error(f"🚨 {len(findings)} injection candidate(s) — {n_high} HIGH. "
                                 "Verify manually before reporting.")
                        st.dataframe(rv_df, use_container_width=True)
                        st.download_button("📥 Download", rv_df.to_csv(index=False),
                                           f"{target_domain}_live_validation.csv",
                                           "text/csv", key="dl_rv")
                    else:
                        st.success(f"No injection signals across {len(rv_rows)} endpoint(s).")
                except Exception as e:
                    st.error(f"REST validation failed: {e}")
                    import traceback
                    st.code(traceback.format_exc())

    rv_stored = project_manager.load_scan_results('live_validation_results', target_domain)
    if isinstance(rv_stored, pd.DataFrame) and not rv_stored.empty:
        with st.expander(f"Stored REST Validation Results ({len(rv_stored)})"):
            st.dataframe(rv_stored, use_container_width=True)

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
    urls = project_manager.filter_targets_by_scope(urls)

    if urls:
        st.info(f"Testing {len(urls)} URLs for IDOR.")
        # Prefer stored AuthSessions (owner + attacker) over pasted cookies
        from app.modules.integrations.auth_session import AuthSession as _AuthSession
        _as_owner = _AuthSession.load(project_manager.get_current_project_path(), target_domain)
        _as_attacker = None
        if _as_owner is not None:
            _as_attacker = _AuthSession.load(project_manager.get_current_project_path(),
                                             f'{target_domain}-attacker')
        _use_sessions = bool(_as_owner is not None and _as_attacker is not None
                             and _as_owner.authenticated and _as_attacker.authenticated)
        if _use_sessions:
            st.caption(f"Using stored AuthSessions: `{target_domain}` (owner) + "
                       f"`{target_domain}-attacker` — differential IDOR test.")
        else:
            st.caption("IDOR/BOLA testing requires two authenticated sessions from different user accounts. "
                       "Create them in Integrations → 🔐 Auth Sessions (owner target + "
                       "`<target>-attacker`), or paste each account's Cookie header below.")
        col_a, col_b = st.columns(2)
        with col_a:
            cookie_a = st.text_input("Session A cookie (User A - resource owner):", key="idor_cookie_a", type="password")
        with col_b:
            cookie_b = st.text_input("Session B cookie (User B - attacker):", key="idor_cookie_b", type="password")

        if not _use_sessions and (not cookie_a or not cookie_b):
            st.warning("Provide both session cookies (or two AuthSessions) to run the IDOR scan.")
        elif st.button("🔐 Run IDOR Scan", key="run_idor"):
            with st.spinner("Scanning..."):
                progress = st.progress(0.0)
                try:
                    import requests as _requests
                    if _use_sessions:
                        sess_a = _as_owner.requests_session()
                        sess_b = _as_attacker.requests_session()
                    else:
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

    # ---- Auth Gateway Probes ----
    st.markdown("---")
    st.markdown("### 🚪 Auth Gateway Probes")
    st.caption("Probes the legacy-protocol matrix (xmlrpc, OWA, actuator, Tomcat manager...) on each origin — "
               "a non-404 answer means an auth gateway may be bypassable via protocol confusion. GET-only.")
    ag_df = project_manager.load_scan_results('auth_gateway', target_domain)
    if isinstance(ag_df, pd.DataFrame) and not ag_df.empty:
        with st.expander(f"Stored Auth Gateway Probes ({len(ag_df)})"):
            st.dataframe(ag_df, use_container_width=True)
    ag_urls = []
    ag_live = project_manager.load_scan_results('live_hosts', target_domain)
    if isinstance(ag_live, pd.DataFrame) and 'URL' in ag_live.columns:
        for u in ag_live['URL'].tolist():
            p = urlparse(u)
            base = f"{p.scheme}://{p.netloc}"
            if base not in ag_urls:
                ag_urls.append(base)
    if not ag_urls:
        ag_urls = [f"https://{target_domain}", f"http://{target_domain}"]
    st.caption(f"{len(ag_urls)} origin(s) queued.")
    if st.button("🚪 Run Auth Gateway Probes", key="auth_gateway_run"):
        with st.spinner("Probing legacy protocol endpoints..."):
            try:
                rows = auth_gateway_scanner.scan_sync(ag_urls)
                new_ag_df = pd.DataFrame(rows) if rows else pd.DataFrame()
                if not new_ag_df.empty:
                    project_manager.save_scan_results('auth_gateway', target_domain, new_ag_df)
                    alive = int(new_ag_df['alive'].sum())
                    st.success(f"{len(new_ag_df)} responding endpoint(s), {alive} alive")
                    st.dataframe(new_ag_df, use_container_width=True)
                else:
                    st.info("No legacy endpoints answered.")
            except Exception as e:
                st.error(f"Auth gateway probe failed: {e}")

    # ---- 403 Bypass ----
    st.markdown("---")
    st.markdown("### 🛡️ 403 Bypass")
    st.caption("Header spoofs (X-Original-URL, X-Forwarded-Host...) and path mutations against 401/403/405 "
               "endpoints — flags when the status leaves the deny set. Purely passive probing.")
    b403_df = project_manager.load_scan_results('bypass403', target_domain)
    if isinstance(b403_df, pd.DataFrame) and not b403_df.empty:
        with st.expander(f"Stored 403 Bypass Results ({len(b403_df)})"):
            st.dataframe(b403_df, use_container_width=True)
    b403_urls = []
    for scan_type in ['js_discovered_endpoints', 'live_hosts', 'param_miner']:
        df = project_manager.load_scan_results(scan_type, target_domain)
        if isinstance(df, pd.DataFrame):
            if 'endpoint' in df.columns:
                b403_urls.extend(df['endpoint'].tolist())
            elif 'URL' in df.columns:
                b403_urls.extend(df['URL'].tolist())
    b403_urls = project_manager.filter_targets_by_scope(
        list(dict.fromkeys([u for u in b403_urls if is_valid_url(u)])))
    st.caption(f"{len(b403_urls)} endpoint(s) queued.")
    if st.button("🛡️ Run 403 Bypass", key="bypass403_run"):
        if not b403_urls:
            st.warning("No endpoints found. Run other scans first.")
        else:
            with st.spinner("Probing bypass techniques..."):
                try:
                    res = bypass403_engine.scan_sync(b403_urls)
                    rows = []
                    for r in res.get('results', []):
                        for b in r.get('bypasses', []):
                            rows.append({
                                'URL': r.get('url', ''),
                                'Baseline': r.get('baseline_status', ''),
                                'Technique': b.get('technique', ''),
                                'Status': b.get('status', ''),
                                'Length': b.get('length', ''),
                                'Bypass URL': b.get('url', ''),
                            })
                    new_b403_df = pd.DataFrame(rows)
                    if not new_b403_df.empty:
                        project_manager.save_scan_results('bypass403', target_domain, new_b403_df)
                        st.success(f"Found {len(new_b403_df)} bypass technique(s) on "
                                   f"{res.get('totals', {}).get('bypassed_urls', 0)} URL(s)!")
                        st.dataframe(new_b403_df, use_container_width=True)
                    else:
                        st.info("No 403 bypasses found.")
                except Exception as e:
                    st.error(f"403 bypass scan failed: {e}")

    # ---- GitHub Leak Search ----
    st.markdown("---")
    st.markdown("### 🐙 GitHub Leak Search")
    st.caption("GitHub dorking for the apex: code/issues/commit search for secrets referencing the domain. "
               "Rate-limit aware; can take ~1 min.")
    gl_df = project_manager.load_scan_results('github_leaks', target_domain)
    if isinstance(gl_df, pd.DataFrame) and not gl_df.empty:
        with st.expander(f"Stored GitHub Leaks ({len(gl_df)})"):
            st.dataframe(gl_df, use_container_width=True)
    if st.button("🐙 Run GitHub Leak Search", key="github_leaks_run"):
        with st.spinner("Dorking GitHub (can take ~1 min)..."):
            try:
                res = github_leak_scanner.scan_sync(target_domain)
                new_gl_df = pd.DataFrame(res.get('findings', []))
                if not new_gl_df.empty:
                    project_manager.save_scan_results('github_leaks', target_domain, new_gl_df)
                    st.success(f"Found {len(new_gl_df)} leak candidate(s) — "
                               f"{res.get('totals', {}).get('secrets', 0)} secrets sniffed")
                    st.dataframe(new_gl_df, use_container_width=True)
                else:
                    st.info("No GitHub leaks found.")
                    if res.get('errors'):
                        st.caption("⚠️ " + " | ".join(res['errors'][:5]))
            except Exception as e:
                st.error(f"GitHub leak search failed: {e}")

    # ---- Endpoint Classifier ----
    st.markdown("---")
    st.markdown("### 🧮 Endpoint Classifier")
    st.caption("Runs every discovered endpoint/param through the technique-library routing tables and ranks "
               "the attack surface by likely vulnerability classes and priority.")
    cls_df = project_manager.load_scan_results('classified_endpoints', target_domain)
    if isinstance(cls_df, pd.DataFrame) and not cls_df.empty:
        with st.expander(f"Stored Classified Endpoints ({len(cls_df)})"):
            st.dataframe(cls_df, use_container_width=True)
    cls_endpoints = []
    for scan_type in ['js_discovered_endpoints', 'live_hosts', 'param_miner']:
        df = project_manager.load_scan_results(scan_type, target_domain)
        if isinstance(df, pd.DataFrame):
            if 'endpoint' in df.columns:
                cls_endpoints.extend(df['endpoint'].tolist())
            elif 'URL' in df.columns:
                cls_endpoints.extend(df['URL'].tolist())
    cls_endpoints = list(dict.fromkeys([u for u in cls_endpoints if is_valid_url(u)]))
    st.caption(f"{len(cls_endpoints)} endpoint(s) queued.")
    if st.button("🧮 Run Classifier", key="classifier_run"):
        if not cls_endpoints:
            st.warning("No endpoints found. Run other scans first.")
        else:
            with st.spinner("Classifying and ranking endpoints..."):
                try:
                    ranked = classify_and_rank(cls_endpoints)
                    new_cls_df = pd.DataFrame(ranked)
                    if not new_cls_df.empty:
                        project_manager.save_scan_results('classified_endpoints', target_domain, new_cls_df)
                        st.success(f"Classified {len(new_cls_df)} endpoint(s).")
                        st.dataframe(new_cls_df, use_container_width=True)
                    else:
                        st.info("Nothing to classify.")
                except Exception as e:
                    st.error(f"Endpoint classification failed: {e}")