import subprocess
import logging
import json
import re
from pathlib import Path
import pandas as pd
from typing import List, Dict, Any, Optional, Callable, Set
import urllib.parse
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from tldextract import extract

logger = logging.getLogger(__name__)

class JSAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.subjs_path = Path(self.config['tools']['paths'].get('subjs', ''))
        self.getjs_path = Path(self.config['tools']['paths'].get('getjs', ''))
        self.linkfinder_path = Path(self.config['tools']['paths'].get('linkfinder', ''))
        self.fakjs_path = Path(self.config['tools']['paths'].get('fakjs', ''))  # New path for Fakjs
        self.max_workers = self.config.get('js_analysis', {}).get('max_workers', 5)

        self._check_tool_paths()

    def _check_tool_paths(self):
        """Checks if required tool paths exist and logs warnings."""
        required_tools = {
            "subjs": self.subjs_path,
            "getjs": self.getjs_path,
            "linkfinder": self.linkfinder_path,
            "fakjs": self.fakjs_path,  # Added Fakjs
        }
        for tool_name, path_obj in required_tools.items():
            if not path_obj.exists():
                logger.warning(f"JSAnalyzer: {tool_name} executable or directory not found at: {path_obj}. Some JS analysis features may be unavailable.")
            if str(path_obj) == '.':
                logger.warning(f"JSAnalyzer: {tool_name} path is set to '.', which is highly unreliable. Please provide a full absolute path in config.json.")

    def _run_command(self, cmd: List[str], tool_name: str, timeout: int = 300, progress_callback: Optional[Callable[[float, str], None]] = None) -> str:
        """Helper method to run shell commands safely."""
        cmd_str = ' '.join(cmd)
        logger.info(f"Running command for {tool_name}: {cmd_str}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=timeout)

            if process.returncode != 0:
                logger.error(f"{tool_name} failed with exit code {process.returncode}: {stderr.strip()}")
                if process.returncode == 127:  # Command not found
                    logger.error(f"Error: {tool_name} command not found in PATH or not executable.")
                raise RuntimeError(f"{tool_name} failed: {stderr.strip()}")
            
            return stdout
        except FileNotFoundError:
            logger.error(f"{tool_name} tool not found. Please check your config.json or ensure it's in your system's PATH.")
            raise RuntimeError(f"{tool_name} executable not found.")
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logger.error(f"{tool_name} timed out after {timeout} seconds. Stderr: {stderr.strip()}")
            raise RuntimeError(f"{tool_name} timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"An unexpected error occurred while running {tool_name}: {e}")
            raise RuntimeError(f"An unexpected error occurred while running {tool_name}: {e}")

    def _get_root_domains(self, urls: List[str]) -> Set[str]:
        """Extracts the root domains from a list of URLs using tldextract."""
        root_domains = set()
        for url in urls:
            if not isinstance(url, str) or not url.strip():
                logger.warning(f"Skipping invalid URL for root domain extraction: '{url}' (type: {type(url)})")
                continue

            try:
                extracted = extract(url)
                if extracted.domain and extracted.suffix:
                    root_domains.add(f"{extracted.domain}.{extracted.suffix}")
                elif extracted.domain:
                    root_domains.add(extracted.domain)
            except Exception as e:
                logger.warning(f"Could not parse URL for root domain using tldextract: '{url}' - {e}")
        return root_domains

    def _is_in_scope(self, url: str, root_domains: Set[str]) -> bool:
        """Checks if a URL's domain is a subdomain of any of the given root domains."""
        if not isinstance(url, str) or not url.strip():
            logger.debug(f"Skipping invalid URL for scope check: '{url}'")
            return False

        try:
            extracted = extract(url)
            domain = extracted.registered_domain
            if not domain:
                parsed_url = urllib.parse.urlparse(url)
                domain = parsed_url.netloc.split(':')[0]
                if not domain:
                    return False

            for root in root_domains:
                if domain == root or domain.endswith(f".{root}"):
                    return True
            return False
        except Exception as e:
            logger.debug(f"Error checking scope for URL '{url}': {e}")
            return False

    def _process_url_with_getjs(self, url: str, root_domains: Set[str]) -> Set[str]:
        """Helper for running getJS on a single URL."""
        discovered_js_files_for_url = set()
        try:
            getjs_cmd = [
                str(self.getjs_path),
                "-url",
                url
            ]
            getjs_output = self._run_command(getjs_cmd, 'getJS', timeout=self.config.get('js_analysis', {}).get('getjs_timeout', 300))
            
            for line in getjs_output.splitlines():
                line = line.strip()
                if line and (line.startswith("http://") or line.startswith("https://") or line.endswith(".js") or line.startswith('/_next/static') or re.match(r"^/[a-zA-Z0-9_\-./]+\.js$", line)):
                    if line.startswith('/'):
                        parsed_base = urllib.parse.urlparse(url)
                        base_url_for_join = f"{parsed_base.scheme}://{parsed_base.netloc}"
                        absolute_line = urllib.parse.urljoin(base_url_for_join, line)
                    else:
                        absolute_line = line

                    if self._is_in_scope(absolute_line, root_domains):
                        discovered_js_files_for_url.add(absolute_line)
                    else:
                        logger.debug(f"getJS found out-of-scope JS file: {absolute_line}")
                else:
                    logger.debug(f"getJS ignored non-URL/JS-like output: {line}")
        except RuntimeError as e:
            logger.error(f"getJS failed for {url}: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during getJS scan for {url}: {e}")
        return discovered_js_files_for_url

    def _run_getjs(self, target_urls: List[str], root_domains: Set[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> Set[str]:
        """Runs getJS to find JavaScript files from a list of URLs (with concurrency)."""
        if not self.getjs_path.is_file():
            logger.warning("getJS path not configured or not an executable. Skipping getJS scan.")
            return set()

        valid_target_urls = [url for url in target_urls if isinstance(url, str) and url.strip()]
        if not valid_target_urls:
            logger.info("No valid URLs provided to getJS after filtering. Skipping scan.")
            return set()

        discovered_js_files = set()
        total_urls = len(valid_target_urls)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._process_url_with_getjs, url, root_domains): url for url in valid_target_urls}
            
            completed_tasks = 0
            for future in as_completed(futures):
                url = futures[future]
                completed_tasks += 1
                current_progress_segment = 0.20
                current_progress = 0.05 + (completed_tasks / total_urls) * current_progress_segment
                if progress_callback:
                    progress_callback(current_progress, f"Running getJS on {url} ({completed_tasks}/{total_urls})...")
                
                try:
                    js_files_for_url = future.result()
                    discovered_js_files.update(js_files_for_url)
                except Exception as e:
                    logger.error(f"Error processing getJS for {url}: {e}")

        logger.info(f"getJS discovered {len(discovered_js_files)} potential in-scope JS files.")
        return discovered_js_files

    def _run_subjs(self, js_urls: List[str], root_domains: Set[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> Set[str]:
        """Runs subjs to extract endpoints from a list of JavaScript URLs."""
        if not self.subjs_path.is_file():
            logger.warning("Subjs path not configured or not an executable. Skipping Subjs scan.")
            return set()

        valid_js_urls = [url for url in js_urls if isinstance(url, str) and url.strip()]
        if not valid_js_urls:
            logger.info("No valid JS URLs provided to Subjs after filtering. Skipping scan.")
            return set()

        extracted_endpoints = set()
        
        temp_input_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as tf:
                tf.write('\n'.join(valid_js_urls))
                temp_input_file = tf.name

            subjs_cmd = [
                str(self.subjs_path),
                "-i", temp_input_file,
                "-t", "30"
            ]

            if progress_callback:
                progress_callback(0.30, f"Running Subjs on {len(valid_js_urls)} JS files...")
            
            subjs_output = self._run_command(subjs_cmd, 'Subjs', timeout=self.config.get('js_analysis', {}).get('subjs_timeout', 900))

            for line in subjs_output.splitlines():
                line = line.strip()
                if line:
                    if self._is_in_scope(line, root_domains):
                        extracted_endpoints.add(line)
                    else:
                        logger.debug(f"Subjs found out-of-scope endpoint: {line}")
            
            logger.info(f"Subjs extracted {len(extracted_endpoints)} in-scope endpoints.")
            return extracted_endpoints
        except RuntimeError as e:
            logger.error(f"Subjs failed: {e}")
            return set()
        finally:
            if temp_input_file and Path(temp_input_file).exists():
                Path(temp_input_file).unlink(missing_ok=True)

    def _process_url_with_linkfinder(self, url: str, root_domains: Set[str]) -> Set[str]:
        """Helper for running Linkfinder on a single URL."""
        extracted_endpoints_for_url = set()
        try:
            linkfinder_cmd = [
                str(self.linkfinder_path),
                "-i", url,
                "-o", "cli"
            ]
            linkfinder_output = self._run_command(linkfinder_cmd, 'Linkfinder', timeout=self.config.get('js_analysis', {}).get('linkfinder_timeout', 600))

            for line in linkfinder_output.splitlines():
                line = line.strip()
                if line.startswith("http://") or line.startswith("https://") or line.startswith("/"):
                    if line.startswith("/"):
                        parsed_base = urllib.parse.urlparse(url)
                        absolute_url = urllib.parse.urljoin(f"{parsed_base.scheme}://{parsed_base.netloc}", line)
                        if self._is_in_scope(absolute_url, root_domains):
                            extracted_endpoints_for_url.add(absolute_url)
                        else:
                            logger.debug(f"Linkfinder found out-of-scope (relative converted) endpoint: {absolute_url}")
                    else:
                        if self._is_in_scope(line, root_domains):
                            extracted_endpoints_for_url.add(line)
                        else:
                            logger.debug(f"Linkfinder found out-of-scope endpoint: {line}")
        except RuntimeError as e:
            logger.error(f"Linkfinder failed for {url}: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during Linkfinder scan for {url}: {e}")
        return extracted_endpoints_for_url

    def _run_linkfinder(self, js_urls: List[str], root_domains: Set[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> Set[str]:
        """Runs Linkfinder to extract endpoints from a list of JavaScript URLs (with concurrency)."""
        if not self.linkfinder_path.is_file():
            logger.warning("Linkfinder path not configured or not an executable. Skipping Linkfinder scan.")
            return set()

        valid_js_urls = [url for url in js_urls if isinstance(url, str) and url.strip()]
        if not valid_js_urls:
            logger.info("No valid JS URLs provided to Linkfinder after filtering. Skipping scan.")
            return set()

        extracted_endpoints = set()
        total_urls = len(valid_js_urls)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._process_url_with_linkfinder, url, root_domains): url for url in valid_js_urls}

            completed_tasks = 0
            for future in as_completed(futures):
                url = futures[future]
                completed_tasks += 1
                current_progress_segment = 0.15
                current_progress = 0.45 + (completed_tasks / total_urls) * current_progress_segment
                if progress_callback:
                    progress_callback(current_progress, f"Running Linkfinder on {url} ({completed_tasks}/{total_urls})...")
                
                try:
                    endpoints_for_url = future.result()
                    extracted_endpoints.update(endpoints_for_url)
                except Exception as e:
                    logger.error(f"Error processing Linkfinder for {url}: {e}")

        logger.info(f"Linkfinder extracted {len(extracted_endpoints)} in-scope endpoints.")
        return extracted_endpoints

    def _parse_fakjs_line(self, line: str, current_url: str = None) -> Optional[Dict[str, str]]:
        """
        Parses a line from Fakjs output, associating findings with the current URL.
        Handles [Url & Path] — {URL} and subsequent lines as context or findings.
        """
        line = line.strip()
        if not line:
            return None

        # Match [Url & Path] — {URL} pattern
        url_match = re.match(r'\[Url\s+&\s+Path\]\s+—\s+\{(https?://[^\}]+)\}', line)
        if url_match:
            return {"type": "URL", "value": url_match.group(1), "source_url": url_match.group(1)}

        # Handle subsequent lines as dependencies or potential sensitive data
        if current_url:
            # Check for library/dependency names or potential sensitive data
            if re.match(r'^[a-zA-Z0-9\-_\.]+$', line) and len(line) > 2:  # Basic filter for valid names
                return {"type": "Dependency", "value": line, "source_url": current_url}
            elif any(keyword in line.lower() for keyword in ['tgz', 'github', 'issue', 'token', 'key', 'secret', 'password', 'auth']):
                return {"type": "Potential_Sensitive_Data", "value": line, "source_url": current_url}

        logger.debug(f"Fakjs: Skipped line (no match): '{line}'")
        return None

    def _run_fakjs(self, js_urls: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, str]]:
        """Runs Fakjs to find sensitive data in JavaScript files, preserving URL context."""
        if not self.fakjs_path.is_file():
            logger.warning("Fakjs path not configured or not an executable. Skipping Fakjs scan.")
            return []

        valid_js_urls = [url for url in js_urls if isinstance(url, str) and url.strip()]
        if not valid_js_urls:
            logger.info("No valid JS URLs provided to Fakjs after filtering. Skipping scan.")
            return []

        sensitive_data_findings = []
        temp_input_file = None

        try:
            # Create a temporary file for input URLs
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as tf:
                for url in valid_js_urls:
                    tf.write(f"{url}\n")
                temp_input_file = tf.name
            logger.debug(f"Fakjs: Temporary input file created at: {temp_input_file}")

            # Run Fakjs with the target file
            fakjs_cmd = [
                str(self.fakjs_path),
                "-target", temp_input_file
            ]
            if progress_callback:
                progress_callback(0.70, f"Running Fakjs on {len(valid_js_urls)} JS files for sensitive data...")

            # Capture stdout
            fakjs_output = self._run_command(fakjs_cmd, 'Fakjs', timeout=self.config.get('js_analysis', {}).get('fakjs_timeout', 1200))
            logger.debug(f"Fakjs raw stdout (first 1000 chars): {fakjs_output[:1000]}...")

            # Parse output line by line, tracking the current URL
            current_url = None
            for line in fakjs_output.splitlines():
                parsed_finding = self._parse_fakjs_line(line, current_url)
                if parsed_finding:
                    if parsed_finding.get("type") == "URL":
                        current_url = parsed_finding["value"]  # Update current URL when a new one is found
                    sensitive_data_findings.append(parsed_finding)
                    logger.debug(f"Fakjs: Added finding: {parsed_finding}")

            logger.info(f"Fakjs found {len(sensitive_data_findings)} potential findings.")
            return sensitive_data_findings
        except RuntimeError as e:
            logger.error(f"Fakjs failed: {e}")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred in Fakjs: {e}", exc_info=True)
            return []
        finally:
            if temp_input_file and Path(temp_input_file).exists():
                logger.debug(f"Fakjs: Deleting temporary input file: {temp_input_file}")
                Path(temp_input_file).unlink(missing_ok=True)

    def analyze_js_for_project(self, target_urls: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, pd.DataFrame]:
        """Orchestrates the JavaScript analysis workflow."""
        all_js_results = {
            "js_files": pd.DataFrame(columns=["File URL"]),
            "discovered_endpoints": pd.DataFrame(columns=["Endpoint"]),
            "sensitive_data_findings": pd.DataFrame(columns=["Type", "Value", "Source URL"])
        }

        filtered_target_urls = [url for url in target_urls if isinstance(url, str) and url.strip()]

        if not filtered_target_urls:
            logger.info("No valid URLs provided for JavaScript analysis after initial filtering.")
            if progress_callback:
                progress_callback(1.0, "No URLs provided for JavaScript analysis.")
            return all_js_results

        root_domains = self._get_root_domains(filtered_target_urls)
        if not root_domains:
            logger.warning("Could not determine root domain(s) from target URLs. JS scope filtering may be limited.")
            
        logger.info(f"Identified root domains for scoping: {root_domains}")

        all_discovered_js_files = set()
        all_discovered_endpoints = set()
        all_sensitive_data_findings_list = []

        # Step 1: Discover JS files
        if self.getjs_path.is_file():
            progress_callback(0.05, f"Starting getJS scan on {len(filtered_target_urls)} initial target URLs...")
            js_files_from_getjs = self._run_getjs(filtered_target_urls, root_domains, progress_callback)
            all_discovered_js_files.update(js_files_from_getjs)
        else:
            logger.warning("getJS not configured. Only explicit .js URLs in target_urls will be analyzed.")
            for url in filtered_target_urls:
                if url.endswith(".js"):
                    if self._is_in_scope(url, root_domains):
                        all_discovered_js_files.add(url)
                else:
                    logger.debug(f"Skipping non-JS URL '{url}' as getJS is not configured.")
        
        if not all_discovered_js_files:
            logger.info("No JavaScript files discovered. Skipping further JS analysis.")
            if progress_callback:
                progress_callback(1.0, "No JS files found.")
            return all_js_results
            
        final_js_files_for_analysis = sorted(list(all_discovered_js_files))

        # Step 2: Extract endpoints with Subjs
        if self.subjs_path.is_file():
            progress_callback(0.25, f"Extracting endpoints from {len(final_js_files_for_analysis)} JS files using Subjs...")
            endpoints_from_subjs = self._run_subjs(final_js_files_for_analysis, root_domains, progress_callback)
            all_discovered_endpoints.update(endpoints_from_subjs)
        else:
            logger.warning("Subjs not configured. Skipping Subjs scan.")

        # Step 3: Extract endpoints with Linkfinder
        if self.linkfinder_path.is_file():
            progress_callback(0.45, f"Extracting endpoints from {len(final_js_files_for_analysis)} JS files using Linkfinder...")
            endpoints_from_linkfinder = self._run_linkfinder(final_js_files_for_analysis, root_domains, progress_callback)
            all_discovered_endpoints.update(endpoints_from_linkfinder)
        else:
            logger.warning("Linkfinder not configured. Skipping Linkfinder scan.")

        # Step 4: Find sensitive data with Fakjs
        if self.fakjs_path.is_file():
            progress_callback(0.65, f"Scanning {len(final_js_files_for_analysis)} JS files for sensitive data...")
            sensitive_data_from_fakjs = self._run_fakjs(final_js_files_for_analysis, progress_callback)
            all_sensitive_data_findings_list.extend(sensitive_data_from_fakjs)
        else:
            logger.warning("Fakjs not configured. Skipping Fakjs scan.")

        # Format results into DataFrames
        if all_discovered_js_files:
            all_js_results["js_files"] = pd.DataFrame(
                {"File URL": sorted(list(all_discovered_js_files))}
            )
            
        if all_discovered_endpoints:
            all_js_results["discovered_endpoints"] = pd.DataFrame(
                {"Endpoint": sorted(list(all_discovered_endpoints))}
            )
            
        if all_sensitive_data_findings_list:
            # Use unique findings based on the (type, value, source_url) tuple to avoid duplicates
            unique_findings = set()
            deduplicated_findings = []
            for f in all_sensitive_data_findings_list:
                finding_tuple = (f.get("type", "Unknown"), f.get("value", ""), f.get("source_url", ""))
                if finding_tuple not in unique_findings:
                    unique_findings.add(finding_tuple)
                    deduplicated_findings.append(f)

            # Sort by type then by value for consistent output
            deduplicated_findings_sorted = sorted(deduplicated_findings, key=lambda x: (x.get("type", ""), x.get("value", ""), x.get("source_url", "")))
            
            all_js_results["sensitive_data_findings"] = pd.DataFrame(deduplicated_findings_sorted)

        progress_callback(1.0, "JavaScript analysis completed.")
        return all_js_results