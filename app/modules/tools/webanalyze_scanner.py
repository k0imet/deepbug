# modules/tools/webanalyze_scanner.py (enhanced and corrected version)

import subprocess
import logging
import json
from pathlib import Path
import tempfile
import pandas as pd
from typing import Dict, List, Optional, Callable, Union
import urllib.parse

logger = logging.getLogger(__name__)

class WebanalyzeScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.webanalyze_path = Path(self.config['tools']['paths'].get('webanalyze', 'webanalyze'))
        
        # Validate path and version
        if not self.webanalyze_path.is_file():
            logger.warning(f"Webanalyze executable not found at: {self.webanalyze_path}")
        else:
            self._verify_webanalyze_version()

    def _verify_webanalyze_version(self):
        """Check if Webanalyze is working and get its version."""
        try:
            result = subprocess.run(
                [str(self.webanalyze_path), '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"Webanalyze version: {result.stdout.strip()}")
            else:
                logger.warning(f"Webanalyze version check failed: {result.stderr.strip()}")
        except Exception as e:
            logger.warning(f"Could not verify Webanalyze version: {str(e)}")

    def _run_command(self, cmd: Union[str, List[str]], tool_name: str, timeout: int = 600, 
                     progress_callback: Optional[Callable[[float, str], None]] = None, 
                     stdin_data: Optional[str] = None) -> str:
        """Enhanced command runner with detailed logging."""
        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        logger.info(f"Running command: {' '.join(cmd_list)}")

        try:
            process = subprocess.Popen(
                cmd_list,
                stdin=subprocess.PIPE if stdin_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=stdin_data, timeout=timeout)

            # Log full output for debugging
            logger.debug(f"Command stdout: {stdout[:500]}...")  # Log first 500 chars
            logger.debug(f"Command stderr: {stderr.strip()}")

            if process.returncode != 0:
                error_msg = f"{tool_name} failed with exit code {process.returncode}: {stderr.strip()}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            return stdout
        except Exception as e:
            logger.error(f"Error running {tool_name}: {str(e)}", exc_info=True)
            raise RuntimeError(f"Failed to run {tool_name}: {str(e)}")

    def perform_scan(self, urls: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        """
        Enhanced technology detection with better diagnostics.
        Returns:
            pd.DataFrame: Columns - ['URL', 'Detected URL', 'Technology', 'Version', 'Categories', 'Confidence']
        """
        if not self.webanalyze_path.is_file():
            logger.error("Webanalyze executable not found")
            if progress_callback:
                progress_callback(1.0, "Webanalyze tool not installed")
            return pd.DataFrame()

        if not urls:
            logger.warning("No URLs provided for scanning")
            if progress_callback:
                progress_callback(1.0, "No URLs provided")
            return pd.DataFrame()

        # Step 1: Prepare targets
        if progress_callback:
            progress_callback(0.05, "Preparing targets...")
        
        domains = set()
        domain_url_map = {}
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                if parsed.netloc:
                    domain = parsed.netloc.split(':')[0]  # Remove port if present
                    domains.add(domain)
                    domain_url_map[domain] = url
            except Exception as e:
                logger.warning(f"Invalid URL {url}: {str(e)}")

        if not domains:
            logger.error("No valid domains extracted from URLs")
            if progress_callback:
                progress_callback(1.0, "No valid domains found")
            return pd.DataFrame()

        # Step 2: Run Webanalyze
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(domains))
                logger.debug(f"Created temp file with {len(domains)} domains: {temp_file}")

            # Corrected command: Removed the unsupported '-timeout' flag
            cmd = [
                str(self.webanalyze_path),
                '-hosts', temp_file,
                '-output', 'json',
                '-silent',
                '-redirect',
                '-crawl', '2',
                '-worker', '4'
            ]

            if progress_callback:
                progress_callback(0.1, f"Scanning {len(domains)} domains...")

            # The timeout for the subprocess is handled here, in the _run_command method call
            output = self._run_command(cmd, 'Webanalyze', timeout=900)
            logger.debug(f"Raw Webanalyze output: {output[:500]}...")  # Log first part

            # Step 3: Process results
            if progress_callback:
                progress_callback(0.8, "Processing results...")

            results = []
            for line in output.splitlines():
                try:
                    data = json.loads(line.strip())
                    host = data.get('host', data.get('hostname', 'unknown'))
                    original_url = domain_url_map.get(host, f"http://{host}")

                    for match in data.get('matches', []):
                        app = match.get('app', {})
                        results.append({
                            'URL': original_url,
                            'Detected URL': data.get('url', original_url),
                            'Technology': app.get('name', match.get('app_name', 'unknown')),
                            'Version': match.get('version', ''),
                            'Categories': ', '.join(app.get('category_names', [])),
                            'Confidence': match.get('confidence', ''),
                            'Website': app.get('website', '')
                        })
                except Exception as e:
                    logger.warning(f"Error processing line: {line[:100]}... Error: {str(e)}")

            if progress_callback:
                progress_callback(1.0, "Scan completed")

            return pd.DataFrame(results) if results else pd.DataFrame(
                columns=['URL', 'Detected URL', 'Technology', 'Version', 'Categories', 'Confidence', 'Website']
            )

        except Exception as e:
            logger.error(f"Scan failed: {str(e)}", exc_info=True)
            if progress_callback:
                progress_callback(1.0, f"Scan failed: {str(e)}")
            return pd.DataFrame()
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink(missing_ok=True)

    def update_technologies(self, progress_callback: Optional[Callable[[float, str], None]] = None) -> bool:
        """Update technology fingerprints with detailed progress."""
        if not self.webanalyze_path.is_file():
            logger.error("Webanalyze executable not found")
            return False

        try:
            if progress_callback:
                progress_callback(0, "Starting update...")

            cmd = [str(self.webanalyze_path), '-update']
            output = self._run_command(cmd, 'Webanalyze Update', timeout=300)
            
            if "updated successfully" in output.lower():
                logger.info("Technologies updated successfully")
                if progress_callback:
                    progress_callback(1.0, "Update successful")
                return True
            else:
                logger.warning(f"Update may have failed. Output: {output.strip()}")
                if progress_callback:
                    progress_callback(1.0, "Update may have failed")
                return False
        except Exception as e:
            logger.error(f"Update failed: {str(e)}", exc_info=True)
            if progress_callback:
                progress_callback(1.0, f"Update failed: {str(e)}")
            return False