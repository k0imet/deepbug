# modules/recon.py

import logging
import pandas as pd
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path

# Import the specialized tools from modules.tools
from modules.tools.subdomain_scanner import SubdomainScanner
from modules.tools.port_scanner import PortScanner
from modules.tools.js_analyzer import JSAnalyzer
from modules.tools.webanalyze_scanner import WebanalyzeScanner

logger = logging.getLogger(__name__)

class Reconnaissance:
    def __init__(self, config: Dict):
        self.config = config
        self.subdomain_scanner = SubdomainScanner(config)
        self.port_scanner = PortScanner(config)
        self.js_analyzer = JSAnalyzer(config)
        self.webanalyze_scanner = WebanalyzeScanner(config) # Initialize WebanalyzeScanner

    def run_subdomain_enumeration(self, domain: str, use_amass: bool = True, use_subfinder: bool = True,
                                  progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        """
        Runs subdomain enumeration and verification.
        Args:
            domain (str): The target domain.
            use_amass (bool): Whether to use Amass.
            use_subfinder (bool): Whether to use Subfinder.
            progress_callback (Optional[Callable]): Callback for UI progress updates.
        Returns:
            pd.DataFrame: DataFrame of active subdomains.
        """
        logger.info(f"Starting subdomain enumeration for {domain}...")
        try:
            subdomains_df = self.subdomain_scanner.run_subdomain_scan(domain, use_amass, use_subfinder, progress_callback)
            logger.info(f"Completed subdomain enumeration for {domain}. Found {len(subdomains_df)} active subdomains.")
            return subdomains_df
        except Exception as e:
            logger.error(f"Error during subdomain enumeration for {domain}: {e}")
            if progress_callback: progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    def run_subdomain_takeover_scan(self, subdomains: List[str],
                                    progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        """
        Runs subdomain takeover scan using Nuclei.
        Args:
            subdomains (List[str]): List of subdomains to scan.
            progress_callback (Optional[Callable]): Callback for UI progress updates.
        Returns:
            pd.DataFrame: DataFrame of potential subdomain takeover findings.
        """
        if not subdomains:
            logger.info("No subdomains provided for takeover scan.")
            return pd.DataFrame()

        logger.info(f"Starting subdomain takeover scan for {len(subdomains)} subdomains...")
        try:
            takeover_df = self.subdomain_scanner.run_subdomain_takeover_scan(subdomains, progress_callback)
            logger.info(f"Completed subdomain takeover scan. Found {len(takeover_df)} potential takeovers.")
            return takeover_df
        except Exception as e:
            logger.error(f"Error during subdomain takeover scan: {e}")
            if progress_callback: progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    def run_port_scan(self, target: str, tool: str = "nmap",
                      progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        """
        Runs a port scan on the given target.
        Args:
            target (str): The target IP or domain.
            tool (str): The tool to use ('nmap' or 'masscan').
            progress_callback (Optional[Callable]): Callback for UI progress updates.
        Returns:
            pd.DataFrame: DataFrame of open ports.
        """
        logger.info(f"Starting port scan for {target} using {tool}...")
        try:
            ports_df = self.port_scanner.run_port_scan(target, tool, progress_callback)
            logger.info(f"Completed port scan for {target}. Found {len(ports_df)} open ports.")
            return ports_df
        except Exception as e:
            logger.error(f"Error during port scan for {target}: {e}")
            if progress_callback: progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    def run_js_analysis(self, urls: List[str],
                        progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, pd.DataFrame]:
        """
        Performs JavaScript analysis on the given URLs.
        Args:
            urls (List[str]): List of URLs to analyze.
            progress_callback (Optional[Callable]): Callback for UI progress updates.
        Returns:
            Dict[str, pd.DataFrame]: Dictionary of DataFrames for different JS analysis aspects.
        """
        if not urls:
            logger.info("No URLs provided for JavaScript analysis.")
            return {}

        logger.info(f"Starting JS analysis for {len(urls)} URLs...")
        try:
            js_results = self.js_analyzer.analyze_js(urls, progress_callback)
            logger.info(f"Completed JS analysis for {len(urls)} URLs.")
            return js_results
        except Exception as e:
            logger.error(f"Error during JS analysis: {e}")
            if progress_callback: progress_callback(0, f"Error: {e}")
            return {}

    def run_web_tech_scan(self, urls: List[str],
                          progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        """
        Runs web technology detection on the given URLs using Webanalyze.
        Args:
            urls (List[str]): List of URLs to analyze.
            progress_callback (Optional[Callable]): Callback for UI progress updates.
        Returns:
            pd.DataFrame: DataFrame of detected technologies.
        """
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
            if progress_callback: progress_callback(0, f"Error: {e}")
            return pd.DataFrame()

    # You can add more complex reconnaissance workflows here,
    # combining multiple tools or steps.
    def full_recon_scan(self, domain: str,
                        progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        """
        Performs a comprehensive reconnaissance scan for a given domain.
        This is a conceptual method that integrates multiple scans.
        """
        all_results = {}
        
        if progress_callback: progress_callback(0.05, "Starting Full Recon Scan...")

        # Step 1: Subdomain Enumeration
        if progress_callback: progress_callback(0.1, "Running Subdomain Enumeration...")
        subdomains_df = self.run_subdomain_enumeration(domain, progress_callback=progress_callback)
        all_results['subdomains'] = subdomains_df
        active_subdomains = subdomains_df['Subdomain'].tolist() if not subdomains_df.empty else []
        logger.info(f"Full Recon: Found {len(active_subdomains)} active subdomains.")

        # Step 2: Subdomain Takeover Scan
        if active_subdomains:
            if progress_callback: progress_callback(0.3, "Running Subdomain Takeover Scan...")
            takeover_df = self.run_subdomain_takeover_scan(active_subdomains, progress_callback=progress_callback)
            all_results['subdomain_takeovers'] = takeover_df
            logger.info(f"Full Recon: Found {len(takeover_df)} potential subdomain takeovers.")

        # Step 3: Web Technology Scan on active subdomains (assuming HTTP/S)
        http_urls = [f"http://{s}" for s in active_subdomains] + [f"https://{s}" for s in active_subdomains]
        if http_urls:
            if progress_callback: progress_callback(0.5, "Running Web Technology Scan...")
            webtech_df = self.run_web_tech_scan(http_urls, progress_callback=progress_callback)
            all_results['web_technologies'] = webtech_df
            logger.info(f"Full Recon: Detected technologies on {len(webtech_df)} URLs.")
            
        # Step 4: JS Analysis on detected URLs (can be refined to specific URLs)
        # For simplicity, let's use the same HTTP URLs for JS analysis
        if http_urls:
            if progress_callback: progress_callback(0.7, "Running JavaScript Analysis...")
            js_results = self.run_js_analysis(http_urls, progress_callback=progress_callback)
            all_results['js_analysis'] = js_results
            logger.info(f"Full Recon: Performed JS analysis on {len(http_urls)} URLs.")


        # Step 5: Port Scan (could target main domain or specific IPs from subdomains)
        # For this example, let's target the main domain's IP or a few key subdomains' IPs
        # This part might need further refinement based on how you want to handle IPs
        # For simplicity, just target the main domain for now.
        if progress_callback: progress_callback(0.9, "Running Port Scan on main domain (Nmap)...")
        # In a real scenario, you'd get the IP of the main domain first
        # For now, let's just use the domain name, Nmap will resolve it.
        ports_df = self.run_port_scan(domain, tool="nmap", progress_callback=progress_callback)
        all_results['open_ports'] = ports_df
        logger.info(f"Full Recon: Found {len(ports_df)} open ports on main domain.")

        if progress_callback: progress_callback(1.0, "Full Recon Scan Completed!")
        logger.info(f"Full reconnaissance scan completed for {domain}.")
        
        return all_results