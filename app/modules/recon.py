# modules/recon.py

import pandas as pd
from typing import Dict, List, Optional, Callable, Any

# Import the specialized tools from modules.tools.
# Dual import keeps both `modules.X` (streamlit pages) and `app.modules.X`
# (headless tests) working.
try:
    from app.modules.tools.subdomain_scanner import SubdomainScanner
    from app.modules.tools.port_scanner import PortScanner
    from app.modules.tools.js_analyzer import JSAnalyzer
    from app.modules.tools.webanalyze_scanner import WebanalyzeScanner
except ImportError:  # pragma: no cover - streamlit pages import as `modules.tools`
    from modules.tools.subdomain_scanner import SubdomainScanner
    from modules.tools.port_scanner import PortScanner
    from modules.tools.js_analyzer import JSAnalyzer
    from modules.tools.webanalyze_scanner import WebanalyzeScanner

# Use the new logger
from app.utils.logger import get_logger
logger = get_logger()


class Reconnaissance:
    def __init__(self, config: Dict):
        self.config = config
        self.subdomain_scanner = SubdomainScanner(config)
        self.port_scanner = PortScanner(config)
        self.js_analyzer = JSAnalyzer(config)
        self.webanalyze_scanner = WebanalyzeScanner(config)

    def run_subdomain_enumeration(self, domain: str, use_amass: bool = True, use_subfinder: bool = True,
                                  progress_callback: Optional[Callable[[float, str], None]] = None,
                                  scope_manager=None) -> pd.DataFrame:
        """
        Run subdomain enumeration with optional scope filtering.

        Args:
            domain: Target domain to enumerate
            use_amass: Whether to use Amass
            use_subfinder: Whether to use Subfinder
            progress_callback: Optional progress callback
            scope_manager: Optional ScopeManager for filtering results
        """
        logger.info(f"Starting subdomain enumeration for {domain}...")
        try:
            # Use the enhanced perform_subdomain_scan if available
            if hasattr(self.subdomain_scanner, 'perform_subdomain_scan'):
                results = self.subdomain_scanner.perform_subdomain_scan(
                    domain,
                    progress_callback=progress_callback,
                    enable_ct=True,
                    enable_permutation=True,
                    enable_wildcard_filter=True
                )
                # Combine all subdomain sources
                all_subs = set()
                for key in ['subfinder_subdomains', 'amass_subdomains', 'ct_logs_subdomains', 'permutation_subdomains']:
                    df = results.get(key, pd.DataFrame())
                    if not df.empty and 'Subdomain' in df.columns:
                        all_subs.update(df['Subdomain'].tolist())

                # Apply scope filtering if provided
                if scope_manager:
                    filtered = scope_manager.filter_targets(list(all_subs))
                    logger.info(f"Scope filtering: {len(all_subs)} -> {len(filtered)} subdomains")
                    all_subs = set(filtered)

                subdomains_df = pd.DataFrame([{'Subdomain': s} for s in sorted(all_subs)])
            else:
                # Fallback to legacy method
                subdomains_df = self.subdomain_scanner.run_subdomain_scan(domain, use_amass, use_subfinder, progress_callback)

                if scope_manager and not subdomains_df.empty:
                    filtered = scope_manager.filter_targets(subdomains_df['Subdomain'].tolist())
                    subdomains_df = pd.DataFrame([{'Subdomain': s} for s in filtered])

            logger.info(f"Completed subdomain enumeration for {domain}. Found {len(subdomains_df)} active subdomains.")
            return subdomains_df
        except Exception as e:
            logger.error(f"Error during subdomain enumeration for {domain}: {e}")
            if progress_callback:
                progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    def run_subdomain_takeover_scan(self, subdomains: List[str],
                                    progress_callback: Optional[Callable[[float, str], None]] = None,
                                    scope_manager=None) -> pd.DataFrame:
        if not subdomains:
            logger.info("No subdomains provided for takeover scan.")
            return pd.DataFrame()

        # Apply scope filtering
        if scope_manager:
            subdomains = scope_manager.filter_targets(subdomains)
            logger.info(f"Takeover scan: {len(subdomains)} subdomains after scope filtering")

        logger.info(f"Starting subdomain takeover scan for {len(subdomains)} subdomains...")
        try:
            # run_subdomain_takeover_scan expects a DataFrame (hostname/Subdomain/first col)
            df = subdomains if isinstance(subdomains, pd.DataFrame) else pd.DataFrame({'Subdomain': subdomains})
            takeover_df = self.subdomain_scanner.run_subdomain_takeover_scan(df, progress_callback)
            # Consistent column name: Dashboard dedupes takeovers on Host+Service
            if not takeover_df.empty and 'Host' not in takeover_df.columns and 'Domain' in takeover_df.columns:
                takeover_df = takeover_df.copy()
                takeover_df['Host'] = takeover_df['Domain']
            logger.info(f"Completed subdomain takeover scan. Found {len(takeover_df)} potential takeovers.")
            return takeover_df
        except Exception as e:
            logger.error(f"Error during subdomain takeover scan: {e}")
            if progress_callback:
                progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    def run_port_scan(self, target: str, tool: str = "nmap",
                      progress_callback: Optional[Callable[[float, str], None]] = None,
                      scope_manager=None) -> pd.DataFrame:
        # Check scope before scanning
        if scope_manager and not scope_manager.is_in_scope(target):
            logger.warning(f"Target {target} is out of scope. Skipping port scan.")
            return pd.DataFrame()

        logger.info(f"Starting port scan for {target} using {tool}...")
        try:
            ports_df = self.port_scanner.run_port_scan(target, tool, progress_callback)
            # Consistent column name: Dashboard dedupes ports on Host+Port
            if not ports_df.empty and 'Host' not in ports_df.columns and 'Target' in ports_df.columns:
                ports_df = ports_df.copy()
                ports_df['Host'] = ports_df['Target']
            logger.info(f"Completed port scan for {target}. Found {len(ports_df)} open ports.")
            return ports_df
        except Exception as e:
            logger.error(f"Error during port scan for {target}: {e}")
            if progress_callback:
                progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    def run_js_analysis(self, urls: List[str],
                        progress_callback: Optional[Callable[[float, str], None]] = None,
                        scope_manager=None) -> Dict[str, pd.DataFrame]:
        # Filter URLs by scope
        if scope_manager:
            urls = scope_manager.filter_targets(urls)
            logger.info(f"JS analysis: {len(urls)} URLs after scope filtering")

        if not urls:
            logger.info("No URLs provided for JavaScript analysis.")
            return {}
        logger.info(f"Starting JS analysis for {len(urls)} URLs...")
        try:
            js_results = self.js_analyzer.analyze_js_for_project(urls, progress_callback)
            logger.info(f"Completed JS analysis for {len(urls)} URLs.")
            return js_results
        except Exception as e:
            logger.error(f"Error during JS analysis: {e}")
            if progress_callback:
                progress_callback(0, f"Error: {e}")
            return {}

    def run_web_tech_scan(self, urls: List[str],
                          progress_callback: Optional[Callable[[float, str], None]] = None,
                          scope_manager=None) -> pd.DataFrame:
        # Filter URLs by scope
        if scope_manager:
            urls = scope_manager.filter_targets(urls)
            logger.info(f"Web tech scan: {len(urls)} URLs after scope filtering")

        if not urls:
            logger.info("No URLs provided for web technology scan.")
            return pd.DataFrame()
        logger.info(f"Starting web technology scan for {len(urls)} URLs...")
        try:
            webtech_df = self.webanalyze_scanner.run_scan(urls, progress_callback)
            logger.info(f"Completed web technology scan for {len(urls)} URLs.")
            return webtech_df
        except Exception as e:
            logger.error(f"Error during web technology scan: {e}")
            if progress_callback:
                progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    def full_recon_scan(self, domain: str,
                        progress_callback: Optional[Callable[[float, str], None]] = None,
                        scope_manager=None) -> Dict[str, Any]:
        """
        Run full reconnaissance scan with optional scope enforcement.

        Args:
            domain: Target domain
            progress_callback: Optional progress callback
            scope_manager: Optional ScopeManager for filtering results
        """
        # Check if domain is in scope
        if scope_manager and not scope_manager.is_in_scope(domain):
            logger.error(f"Domain {domain} is out of scope. Aborting full recon scan.")
            raise ValueError(f"Domain {domain} is out of scope")

        all_results = {}
        if progress_callback:
            progress_callback(0.05, "Starting Full Recon Scan...")
        if progress_callback:
            progress_callback(0.1, "Running Subdomain Enumeration...")
        subdomains_df = self.run_subdomain_enumeration(domain, progress_callback=progress_callback, scope_manager=scope_manager)
        all_results['subdomains'] = subdomains_df
        active_subdomains = subdomains_df['Subdomain'].tolist() if not subdomains_df.empty else []
        logger.info(f"Full Recon: Found {len(active_subdomains)} active subdomains.")

        if active_subdomains:
            if progress_callback:
                progress_callback(0.3, "Running Subdomain Takeover Scan...")
            takeover_df = self.run_subdomain_takeover_scan(active_subdomains, progress_callback=progress_callback, scope_manager=scope_manager)
            all_results['subdomain_takeovers'] = takeover_df
            logger.info(f"Full Recon: Found {len(takeover_df)} potential subdomain takeovers.")

        http_urls = [f"http://{s}" for s in active_subdomains] + [f"https://{s}" for s in active_subdomains]
        if http_urls:
            if progress_callback:
                progress_callback(0.5, "Running Web Technology Scan...")
            webtech_df = self.run_web_tech_scan(http_urls, progress_callback=progress_callback, scope_manager=scope_manager)
            all_results['web_technologies'] = webtech_df
            logger.info(f"Full Recon: Detected technologies on {len(webtech_df)} URLs.")

            if progress_callback:
                progress_callback(0.7, "Running JavaScript Analysis...")
            js_results = self.run_js_analysis(http_urls, progress_callback=progress_callback, scope_manager=scope_manager)
            all_results['js_analysis'] = js_results
            logger.info(f"Full Recon: Performed JS analysis on {len(http_urls)} URLs.")

        if progress_callback:
            progress_callback(0.9, "Running Port Scan on main domain (Nmap)...")
        ports_df = self.run_port_scan(domain, tool="nmap", progress_callback=progress_callback, scope_manager=scope_manager)
        all_results['open_ports'] = ports_df
        logger.info(f"Full Recon: Found {len(ports_df)} open ports on main domain.")

        if progress_callback:
            progress_callback(1.0, "Full Recon Scan Completed!")
        logger.info(f"Full reconnaissance scan completed for {domain}.")
        return all_results