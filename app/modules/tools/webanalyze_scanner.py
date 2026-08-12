# modules/tools/webanalyze_scanner.py

import subprocess
import json
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional, Callable, Any
import tempfile
import os

from app.utils.logger import get_logger
from app.utils.subprocess_runner import run_command

logger = get_logger()


class WebanalyzeScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.webanalyze_path = Path(self.config['tools']['paths'].get('webanalyze', 'webanalyze'))
        self.technologies_json = Path(self.config.get('technologies_file', 'technologies.json'))
        if not self.webanalyze_path.is_file():
            logger.warning(f"Webanalyze executable not found at: {self.webanalyze_path}")

    def update_technologies(self, progress_callback: Optional[Callable] = None) -> bool:
        """Update the technologies definition file."""
        if progress_callback:
            progress_callback(0.1, "Updating Webanalyze technologies...")
        try:
            cmd = [str(self.webanalyze_path), '-update']
            stdout, stderr, ret = run_command(cmd, timeout=60)
            if ret == 0:
                logger.info("Webanalyze technologies updated successfully.")
                if progress_callback:
                    progress_callback(1.0, "Update completed.")
                return True
            else:
                logger.error(f"Failed to update Webanalyze: {stderr}")
                return False
        except Exception as e:
            logger.error(f"Error updating Webanalyze: {e}")
            return False

    def perform_scan(self, urls: List[str], progress_callback: Optional[Callable] = None) -> pd.DataFrame:
        """Run webanalyze on a list of URLs."""
        if not self.webanalyze_path.is_file():
            logger.error("Webanalyze not found.")
            return pd.DataFrame()

        if not urls:
            return pd.DataFrame()

        # Write URLs to temp file (webanalyze uses -hosts flag)
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(urls))

            cmd = [
                str(self.webanalyze_path),
                '-hosts', temp_file,
                '-output', 'json',
                '-redirect'  # follow redirects
            ]
            # If we have a custom technologies file, add it
            if self.technologies_json.is_file():
                cmd.extend(['-apps', str(self.technologies_json)])

            if progress_callback:
                progress_callback(0.2, "Running Webanalyze scan...")

            stdout, stderr, ret = run_command(cmd, timeout=300)
            if ret != 0:
                logger.error(f"Webanalyze scan failed: {stderr}")
                return pd.DataFrame()

            # Parse JSON output
            try:
                data = json.loads(stdout)
                # Expected format: list of results per host
                rows = []
                for entry in data:
                    host = entry.get('host', '')
                    for tech in entry.get('technologies', []):
                        rows.append({
                            'URL': host,
                            'Technology': tech.get('name', ''),
                            'Version': tech.get('version', ''),
                            'Category': ', '.join(tech.get('categories', [])),
                            'Confidence': tech.get('confidence', 0)
                        })
                df = pd.DataFrame(rows)
                if progress_callback:
                    progress_callback(1.0, "Scan completed.")
                return df
            except json.JSONDecodeError:
                logger.warning("Webanalyze output is not JSON. Trying to parse as text.")
                # Fallback: parse human-readable output
                rows = []
                current_host = None
                for line in stdout.splitlines():
                    if line.startswith('[*]') and 'scanning' in line:
                        # Extract host
                        parts = line.split()
                        if len(parts) > 1:
                            current_host = parts[-1]
                    elif ' - ' in line and current_host:
                        # e.g., "  - Apache (2.4.41) [Web Server]"
                        tech_part = line.strip().split(' - ')
                        if len(tech_part) > 1:
                            tech_info = tech_part[1]
                            # parse: name (version) [category]
                            match = re.match(r'([^(]+)(?:\(([^)]+)\))?\s*\[([^\]]+)\]', tech_info)
                            if match:
                                name, version, category = match.groups()
                                rows.append({
                                    'URL': current_host,
                                    'Technology': name.strip(),
                                    'Version': version.strip() if version else '',
                                    'Category': category.strip(),
                                    'Confidence': ''
                                })
                df = pd.DataFrame(rows)
                return df

        except Exception as e:
            logger.error(f"Webanalyze scan error: {e}")
            return pd.DataFrame()
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    # Legacy method for compatibility with pages/2_Recon.py
    def run_scan(self, urls: List[str], progress_callback: Optional[Callable] = None) -> pd.DataFrame:
        return self.perform_scan(urls, progress_callback)