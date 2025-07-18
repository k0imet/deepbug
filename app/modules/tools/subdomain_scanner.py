import subprocess
import logging
from pathlib import Path
import pandas as pd
from typing import List, Dict, Any, Optional, Callable, Union
import re
import tempfile
import json
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class SubdomainScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.subfinder_path = Path(self.config['tools']['paths'].get('subfinder', 'subfinder'))
        self.dnsx_path = Path(self.config['tools']['paths'].get('dnsx', 'dnsx'))
        self.httpx_path = Path(self.config['tools']['paths'].get('httpx', 'httpx'))
        self.amass_path = Path(self.config['tools']['paths'].get('amass', 'amass'))
        self.subdover_path = Path(self.config['tools']['paths'].get('subdover', 'subdover'))
        
        self._check_tool_paths()

    def _check_tool_paths(self):
        """Checks if required tool paths exist and logs warnings."""
        required_tools = {
            "subfinder": self.subfinder_path,
            "dnsx": self.dnsx_path,
            "httpx": self.httpx_path,
            "amass": self.amass_path,
            "subdover": self.subdover_path
        }
        for tool_name, path_obj in required_tools.items():
            if not path_obj.exists():
                logger.warning(f"SubdomainScanner: {tool_name} executable not found at: {path_obj}. Related features will be disabled.")

    def _run_command(self, cmd: Union[str, List[str]], tool_name: str, timeout: int = 300, 
                    progress_callback: Optional[Callable[[float, str], None]] = None, 
                    stdin_data: Optional[str] = None) -> str:
        """Helper method to run shell commands safely with error handling and logging."""
        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        logger.info(f"Running command for {tool_name}: {' '.join(cmd_list)}")
        
        if progress_callback:
            progress_callback(0, f"Starting {tool_name}...")

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
                error_msg = f"{tool_name} failed with exit code {process.returncode}: {stderr.strip()}"
                logger.error(error_msg)
                if progress_callback:
                    progress_callback(0, f"Error: {error_msg}")
                raise RuntimeError(error_msg)
            
            if progress_callback:
                progress_callback(1, f"{tool_name} completed.")
            return stdout
        except FileNotFoundError:
            error_msg = f"{tool_name} tool not found. Please check your config."
            logger.error(error_msg)
            if progress_callback:
                progress_callback(0, f"Error: {error_msg}")
            raise RuntimeError(error_msg)
        except subprocess.TimeoutExpired:
            process.kill()
            error_msg = f"{tool_name} timed out after {timeout} seconds."
            logger.error(error_msg)
            if progress_callback:
                progress_callback(0, f"Error: {error_msg}")
            raise RuntimeError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error running {tool_name}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if progress_callback:
                progress_callback(0, f"Error: {error_msg}")
            raise RuntimeError(error_msg)

    def _run_subfinder(self, domain: str, progress_callback: Optional[Callable[[float, str], None]] = None) -> List[str]:
        """Runs subfinder to find subdomains."""
        if not self.subfinder_path.is_file():
            logger.warning("Subfinder not found, skipping.")
            return []

        cmd = [
            str(self.subfinder_path),
            '-d', domain,
            '-silent'
        ]
        
        try:
            output = self._run_command(
                cmd, 
                'Subfinder',
                timeout=600,
                progress_callback=lambda p, s: progress_callback(p * 0.15, s) if progress_callback else None
            )
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception as e:
            logger.error(f"Subfinder failed: {e}")
            return []

    def _run_amass(self, domain: str, progress_callback: Optional[Callable[[float, str], None]] = None) -> List[str]:
        """Runs Amass in passive mode to find subdomains."""
        if not self.amass_path.is_file():
            logger.warning("Amass not found, skipping.")
            return []

        cmd = [
            str(self.amass_path),
            'enum',
            '-d', domain,
            '-passive',
            '-silent'
        ]
        
        try:
            output = self._run_command(
                cmd,
                'Amass',
                timeout=900,
                progress_callback=lambda p, s: progress_callback(0.15 + p * 0.25, s) if progress_callback else None
            )
            return [line.strip() for line in output.splitlines() if line.strip()]
        except Exception as e:
            logger.error(f"Amass failed: {e}")
            return []

    def _run_dnsx(self, subdomains: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, str]]:
        """Runs dnsx to resolve subdomains and get DNS records."""
        if not self.dnsx_path.is_file() or not subdomains:
            return []

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(subdomains))

            cmd = [
                str(self.dnsx_path),
                '-l', temp_file,
                '-a', '-cname',
                '-json',
                '-silent'
            ]

            output = self._run_command(
                cmd,
                'Dnsx',
                timeout=300,
                progress_callback=lambda p, s: progress_callback(0.4 + p * 0.3, s) if progress_callback else None
            )

            results = []
            for line in output.splitlines():
                try:
                    data = json.loads(line)
                    results.append({
                        'hostname': data.get('host', ''),
                        'ip': ', '.join(data.get('a', [])),
                        'cname': ', '.join(data.get('cname', []))
                    })
                except Exception as e:
                    logger.warning(f"Error parsing dnsx output: {e}")
            return results
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    def _run_httpx(self, subdomains: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, Any]]:
        """Probes subdomains with httpx to find live hosts."""
        if not self.httpx_path.is_file() or not subdomains:
            return []

        temp_input = temp_output = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_in:
                temp_input = f_in.name
                f_in.write('\n'.join(subdomains))

            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_out:
                temp_output = f_out.name

            cmd = [
                str(self.httpx_path),
                '-l', temp_input,
                '-json',
                '-o', temp_output,
                '-silent',
                '-follow-redirects',
                '-title',
                '-tech-detect',
                '-status-code',
                '-content-length',
                '-web-server',
                '-ports', '80,443,8080,8443,3000,8009,8081,9443,8180',  # Added common HTTP ports
                '-t', '100'
            ]

            self._run_command(
                cmd,
                'Httpx',
                timeout=900,
                progress_callback=lambda p, s: progress_callback(0.7 + p * 0.3, s) if progress_callback else None
            )

            results = []
            with open(temp_output, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        results.append({
                            'URL': data.get('url', ''),
                            'Input': data.get('input', ''),
                            'StatusCode': data.get('status-code', ''),
                            'Title': data.get('title', ''),
                            'WebServer': data.get('webserver', ''),
                            'ContentLength': data.get('content-length', ''),
                            'Technologies': ', '.join(data.get('tech', []))
                        })
                    except Exception as e:
                        logger.warning(f"Error parsing httpx output: {e}")
            return results
        finally:
            for f in [temp_input, temp_output]:
                if f and Path(f).exists():
                    Path(f).unlink()

    def _run_subdover(self, subdomains: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, str]]:
        """Runs subdover to identify subdomain takeovers."""
        if not self.subdover_path.is_file() or not subdomains:
            return []

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(subdomains))

            cmd = [
                str(self.subdover_path),
                '-l', temp_file,
                '--format', 'json'  # Attempt JSON, but we'll handle text fallback
            ]

            output = self._run_command(
                cmd,
                'Subdover',
                timeout=300,
                progress_callback=progress_callback
            )
            
            logger.debug(f"Subdover raw output: {output}")
            
            # Parse subdover output for both "Not Vulnerable" and "Vulnerable" cases
            vulnerabilities = []
            for line in output.splitlines():
                # Match "Not Vulnerable" lines
                not_vulnerable_match = re.match(r'Not Vulnerable: (\S+) => (\S+) \(None\)', line)
                if not_vulnerable_match:
                    subdomain, cname = not_vulnerable_match.groups()
                    vulnerabilities.append({
                        'Domain': subdomain,
                        'CNAME': cname,
                        'Type': 'not_vulnerable',
                        'Confidence': 'high',
                        'Evidence': line.strip()
                    })
                # Match "Vulnerable" lines (assuming similar format)
                vulnerable_match = re.match(r'Vulnerable: (\S+) => (\S+) \(None\)', line)
                if vulnerable_match:
                    subdomain, cname = vulnerable_match.groups()
                    vulnerabilities.append({
                        'Domain': subdomain,
                        'CNAME': cname,
                        'Type': 'vulnerable',
                        'Confidence': 'high',
                        'Evidence': line.strip()
                    })

            return vulnerabilities
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    def perform_subdomain_scan(self, domain: str, progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, pd.DataFrame]:
        """Orchestrates the complete subdomain scanning workflow."""
        from modules.utils import format_results

        results = {
            "subfinder_subdomains": pd.DataFrame(columns=['Subdomain']),
            "amass_subdomains": pd.DataFrame(columns=['Subdomain']),
            "resolved_subdomains": pd.DataFrame(columns=['hostname', 'ip', 'cname']),
            "live_hosts": pd.DataFrame(columns=['URL', 'Input', 'StatusCode', 'Title', 'WebServer', 'ContentLength', 'Technologies']),
            "subdover_vulnerabilities": pd.DataFrame(columns=['Domain', 'CNAME', 'Type', 'Confidence', 'Evidence'])  # Updated columns
        }

        if not domain:
            logger.warning("No domain provided for scan")
            return results

        # Phase 1: Subdomain discovery
        if progress_callback:
            progress_callback(0.05, "Running Subfinder...")
        subfinder_results = self._run_subfinder(domain, progress_callback)
        if subfinder_results:
            results["subfinder_subdomains"] = pd.DataFrame([{'Subdomain': s} for s in subfinder_results])

        if progress_callback:
            progress_callback(0.20, "Running Amass...")
        amass_results = self._run_amass(domain, progress_callback)
        if amass_results:
            results["amass_subdomains"] = pd.DataFrame([{'Subdomain': s} for s in amass_results])

        all_subdomains = list(set(subfinder_results + amass_results))
        if not all_subdomains:
            logger.info("No subdomains found")
            return results

        # Phase 2: DNS resolution
        if progress_callback:
            progress_callback(0.40, "Resolving DNS records...")
        dns_results = self._run_dnsx(all_subdomains, progress_callback)
        if dns_results:
            results["resolved_subdomains"] = pd.DataFrame(dns_results)

        # Phase 3: HTTP probing
        if progress_callback:
            progress_callback(0.70, "Probing HTTP services...")
        http_results = self._run_httpx(all_subdomains, progress_callback)
        if http_results:
            results["live_hosts"] = pd.DataFrame(http_results)

        # Phase 4: Subdomain takeover checking with subdover
        if progress_callback:
            progress_callback(0.95, "Checking for subdomain takeovers with Subdover...")
        subdover_results = self._run_subdover(all_subdomains)
        if subdover_results:
            results["subdover_vulnerabilities"] = pd.DataFrame(subdover_results)

        if progress_callback:
            progress_callback(1.0, "Scan completed")
        return results

    def run_subdomain_takeover_scan(self, subdomains_df: pd.DataFrame, progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        """
        Check for subdomain takeovers using subdover on dnsx-resolved subdomains.
        
        Args:
            subdomains_df (pd.DataFrame): DataFrame containing resolved subdomains (e.g., from dnsx)
            progress_callback (function): Callback for progress updates
            
        Returns:
            pd.DataFrame: DataFrame containing takeover findings
        """
        if not self.subdover_path.is_file():
            raise RuntimeError("Subdover tool not found. Please check your configuration.")

        if progress_callback:
            progress_callback(0, "Preparing subdomain takeover scan...")

        # Extract subdomains from DataFrame and log for debugging
        if 'hostname' in subdomains_df.columns:  # Prioritize 'hostname' from dnsx
            subdomains = subdomains_df['hostname'].tolist()
        elif 'Subdomain' in subdomains_df.columns:
            subdomains = subdomains_df['Subdomain'].tolist()
        else:
            # Fallback to first column
            subdomains = subdomains_df.iloc[:, 0].tolist()
        logger.debug(f"Subdomains for takeover scan (from dnsx): {subdomains}")

        if not subdomains:
            return pd.DataFrame(columns=['Domain', 'CNAME', 'Type', 'Confidence', 'Evidence'])  # Updated columns

        # Run subdover scan
        if progress_callback:
            progress_callback(20, "Running Subdover takeover scan...")

        try:
            subdover_results = self._run_subdover(
                subdomains,
                progress_callback=lambda p, s: progress_callback(20 + p * 70, s) if progress_callback else None
            )

            if progress_callback:
                progress_callback(100, "Takeover scan complete!")

            return pd.DataFrame(subdover_results) if subdover_results else pd.DataFrame()

        except Exception as e:
            logger.error(f"Error in takeover scan: {str(e)}", exc_info=True)
            if progress_callback:
                progress_callback(100, f"Error: {str(e)}")
            raise RuntimeError(f"Takeover scan failed: {str(e)}")