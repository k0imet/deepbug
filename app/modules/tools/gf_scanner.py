import subprocess
import logging
import json
import tempfile
import re
from pathlib import Path
import pandas as pd
from typing import List, Dict, Any, Optional, Callable, Union
import urllib.parse

logger = logging.getLogger(__name__)

class GFScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.paramspider_path = Path(self.config['tools']['paths'].get('paramspider', ''))
        self.gf_path = Path(self.config['tools']['paths'].get('gf', ''))

        self._check_tool_paths()

    def _check_tool_paths(self):
        """Checks if required tool paths exist and logs warnings."""
        required_tools = {
            "paramspider": self.paramspider_path,
            "gf": self.gf_path
        }
        for tool_name, path_obj in required_tools.items():
            if not path_obj.exists():
                logger.warning(f"GFScanner: {tool_name} executable or directory not found at: {path_obj}. Some features may be unavailable.")

    def _run_command(self, cmd: Union[str, List[str]], tool_name: str, timeout: int = 300, progress_callback: Optional[Callable[[float, str], None]] = None, stdin_data: Optional[str] = None) -> str:
        """
        Helper method to run shell commands safely with error handling and logging.
        """
        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        cmd_str = ' '.join(cmd_list)
        logger.info(f"Running command for {tool_name}: {cmd_str}")
        if progress_callback:
            progress_callback(0, f"Running {tool_name}...")

        try:
            process = subprocess.Popen(
                cmd_list,
                stdin=subprocess.PIPE if stdin_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=stdin_data, timeout=timeout)

            if process.returncode != 0:
                logger.error(f"{tool_name} failed with exit code {process.returncode}: {stderr.strip()}")
                if progress_callback:
                    progress_callback(0, f"Error: {tool_name} failed: {stderr.strip()}")
                raise RuntimeError(f"{tool_name} failed: {stderr.strip()}")
            
            if progress_callback:
                progress_callback(1, f"{tool_name} completed.")
            return stdout
        except FileNotFoundError:
            logger.error(f"{tool_name} tool not found. Please check your config.json.")
            if progress_callback:
                progress_callback(0, f"Error: {tool_name} not found.")
            raise RuntimeError(f"{tool_name} executable not found. Check config.")
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logger.error(f"{tool_name} timed out after {timeout} seconds. Stderr: {stderr.strip()}")
            if progress_callback:
                progress_callback(0, f"Error: {tool_name} timed out.")
            raise RuntimeError(f"{tool_name} timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"An unexpected error occurred while running {tool_name}: {e}")
            if progress_callback:
                progress_callback(0, f"Error: {tool_name} encountered an unexpected error.")
            raise RuntimeError(f"An unexpected error occurred while running {tool_name}: {e}")

    def _extract_domain_without_protocol(self, url: str) -> str:
        """Extracts domain without protocol or path."""
        parsed = urllib.parse.urlparse(url)
        if not parsed.netloc:
            return url.split('/')[0]
        return parsed.netloc.split(':')[0]

    def _get_root_domains(self, urls: List[str]) -> List[str]:
        """
        Extracts the root domains from a list of URLs.
        e.g., "www.sub.example.com" -> "example.com"
        """
        root_domains = set()
        for url in urls:
            domain = self._extract_domain_without_protocol(url)
            parts = domain.split('.')
            if len(parts) >= 2:
                root_domains.add(".".join(parts[-2:]))
            else:
                root_domains.add(domain)
        return list(root_domains)

    def _is_subdomain_of_any(self, domain: str, root_domains: List[str]) -> bool:
        """Checks if a domain is a subdomain of any of the given root domains."""
        for root in root_domains:
            if domain == root or domain.endswith(f".{root}"):
                return True
        return False

    def _run_paramspider(self, urls: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[str]:
        """Runs paramspider to find URLs with parameters, restricted to subdomains of initial targets."""
        if not self.paramspider_path.is_file():
            logger.error("Paramspider path not configured or not an executable.")
            if progress_callback:
                progress_callback(0, "Error: Paramspider tool not found or configured.")
            return []

        discovered_urls = []
        
        initial_root_domains = self._get_root_domains(urls)
        if not initial_root_domains:
            logger.warning("Could not determine root domains from initial URLs. Paramspider might run broadly.")
            
        unique_domains_for_paramspider = []
        for url in urls:
            domain = self._extract_domain_without_protocol(url)
            if self._is_subdomain_of_any(domain, initial_root_domains):
                unique_domains_for_paramspider.append(domain)
        unique_domains_for_paramspider = list(set(unique_domains_for_paramspider))

        if not unique_domains_for_paramspider:
            logger.info("No unique relevant domains to run Paramspider on after filtering.")
            return []

        for i, domain in enumerate(unique_domains_for_paramspider):
            status_label = f"Running Paramspider on {domain} ({i+1}/{len(unique_domains_for_paramspider)})"
            if progress_callback:
                progress_callback(0.05 + (i / len(unique_domains_for_paramspider)) * 0.20, status_label) 

            paramspider_cmd = [
                str(self.paramspider_path),
                "-d", domain
            ]
            
            try:
                paramspider_output = self._run_command(paramspider_cmd, 'Paramspider', timeout=600)
                
                for line in paramspider_output.splitlines():
                    line = line.strip()
                    if line.startswith('http') and '?' in line:
                        extracted_host = urllib.parse.urlparse(line).netloc.split(':')[0]
                        if self._is_subdomain_of_any(extracted_host, initial_root_domains):
                            discovered_urls.append(line)
                        else:
                            logger.debug(f"Paramspider found out-of-scope URL: {line}")
            except RuntimeError as e:
                logger.warning(f"Paramspider failed for domain {domain}: {e}")
                if progress_callback:
                    progress_callback(0, f"Warning: Paramspider failed for {domain}")
                continue 
        
        final_urls = list(set(discovered_urls))
        logger.info(f"Paramspider found {len(final_urls)} URLs with parameters within scope.")
        return final_urls

    def _run_gf(self, urls: List[str], patterns: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, str]]:
        """Filters URLs using multiple gf patterns and returns findings with pattern details."""
        if not self.gf_path.is_file():
            logger.error("GF path not configured or not an executable.")
            if progress_callback:
                progress_callback(0, "Error: GF tool not found or configured.")
            return []

        if not urls or not patterns:
            return []

        filtered_findings = []
        temp_input_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as tf:
                tf.write('\n'.join(urls))
                temp_input_file = tf.name
            
            for i, pattern in enumerate(patterns):
                gf_cmd = [
                    str(self.gf_path),
                    pattern,
                    temp_input_file
                ]
                
                if progress_callback:
                    progress_callback(0.25 + (i / len(patterns)) * 0.15, f"Running GF with '{pattern}' pattern...")
                
                gf_output = self._run_command(gf_cmd, 'GF')
                matched_urls = [line.strip() for line in gf_output.splitlines() if line.strip()]
                for url in matched_urls:
                    filtered_findings.append({"URL": url, "Matched_Pattern": pattern})

            logger.info(f"GF found {len(filtered_findings)} URLs across {len(patterns)} patterns.")
            return list({tuple(d.items()) for d in filtered_findings})  # Remove duplicates while preserving dict structure
        except Exception as e:
            logger.error(f"Error running GF: {e}")
            if progress_callback:
                progress_callback(0, f"Error: GF failed: {e}")
            return []
        finally:
            if temp_input_file and Path(temp_input_file).exists():
                Path(temp_input_file).unlink(missing_ok=True)

    def perform_scan(self, target_urls: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, pd.DataFrame]:
        """
        Orchestrates the scan using paramspider and gf with multiple vulnerability patterns.
        Returns a dictionary of pandas DataFrames for each tool's findings.
        """
        from modules.utils import format_results 

        all_scan_results = {
            "paramspider_urls": pd.DataFrame(),
            "gf_filtered_urls": pd.DataFrame()
        }

        if not target_urls:
            logger.info("No URLs provided for scan.")
            if progress_callback:
                progress_callback(1.0, "No URLs provided for scan.")
            return all_scan_results

        # Define common vulnerability-related gf patterns
        gf_patterns = [
            "sqli",
            "xss",
            "lfi",
            "open-redirect",
            "rce",
            "ssrf",
            "idor"
        ]
        logger.info(f"Using GF patterns: {gf_patterns}")

        progress_callback(0.05, "Running Paramspider to discover URLs with parameters...")
        paramspider_urls = self._run_paramspider(target_urls, progress_callback)
        if paramspider_urls:
            all_scan_results["paramspider_urls"] = format_results([{"URL": url} for url in paramspider_urls], "raw_urls") 
        else:
            logger.info("Paramspider did not find any URLs with parameters. Proceeding with original URLs for GF.")
            paramspider_urls = target_urls 
            if progress_callback:
                progress_callback(0.25, "Paramspider found no new URLs. Using initial URLs for GF.")

        urls_for_gf = paramspider_urls

        if urls_for_gf:
            progress_callback(0.25, "Filtering URLs with GF for various vulnerabilities...")
            gf_findings = self._run_gf(urls_for_gf, gf_patterns, progress_callback)
            if gf_findings:
                all_scan_results["gf_filtered_urls"] = format_results(gf_findings, "gf_findings")
            else:
                logger.info("GF did not find any URLs matching vulnerability patterns.")
        else:
            logger.info("No URLs to pass to GF.")

        progress_callback(1.0, "Scan completed.")
        return all_scan_results