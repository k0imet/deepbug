# modules/scanner.py

import json
import shutil
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional
import os

# Phase 1 imports
from app.utils.logger import get_logger
from app.utils.subprocess_runner import run_command
from app.utils.cache import load_cache, save_cache

# Dual import keeps both `modules.X` (streamlit pages) and `app.modules.X`
# (headless tests) working.
try:
    from app.modules.utils import parse_nuclei_output, load_config
except ImportError:  # pragma: no cover - streamlit pages import as `modules.utils`
    from modules.utils import parse_nuclei_output, load_config

logger = get_logger()


class VulnerabilityScanner:
    # Stable output schema for run_nuclei_scan().
    NUCLEI_SCHEMA = ['Template_ID', 'Name', 'Severity', 'Matched_At', 'Target',
                     'Extracted_Results', 'Curl_Command']

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.nuclei_templates_path = Path(
            self.config.get('tools', {}).get('paths', {}).get('nuclei_templates', '')
        ).expanduser()
        # Resolve the nuclei binary: configured path first, then PATH lookup.
        self.nuclei_path = self._resolve_nuclei_binary(
            self.config.get('tools', {}).get('paths', {}).get('nuclei', '')
        )
        if not self.nuclei_path.is_file():
            logger.error(f"Nuclei executable not found at: {self.nuclei_path}")
        if not self.nuclei_templates_path.is_dir():
            logger.warning(f"Nuclei templates directory not found at: {self.nuclei_templates_path}")

    @staticmethod
    def _resolve_nuclei_binary(configured_path: str) -> Path:
        """Config path -> PATH ('nuclei') via shutil.which. Falls back to the
        configured value (or 'nuclei') so run-time error messages stay clear."""
        if configured_path:
            full = Path(configured_path).expanduser()
            if full.is_file():
                return full
            via_path = shutil.which('nuclei')
            if via_path:
                return Path(via_path)
            return full
        via_path = shutil.which('nuclei')
        return Path(via_path) if via_path else Path('nuclei')

    def _run_command_with_progress(self, command: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> str:
        """Run command and capture output. Returns stdout string."""
        stdout, stderr, ret = run_command(command, timeout=600)
        if ret != 0:
            logger.error(f"Command failed: {' '.join(command)} - {stderr}")
            raise RuntimeError(f"Command failed with exit code {ret}: {stderr}")
        if progress_callback:
            progress_callback(0.8, "Scan completed, parsing results...")
        return stdout

    def _parse_nuclei_output_to_df(self, raw_output: str) -> pd.DataFrame:
        """Parse raw Nuclei output (JSONL) into a stable-schema DataFrame."""
        findings = parse_nuclei_output(raw_output)
        if not findings:
            return pd.DataFrame(columns=self.NUCLEI_SCHEMA)
        df = pd.DataFrame(findings)
        column_mapping = {
            'template_id': 'Template_ID',
            'name': 'Name',
            'severity': 'Severity',
            'matched_at': 'Matched_At',
            'target': 'Target',
            'extracted_results': 'Extracted_Results',
            'curl_command': 'Curl_Command'
        }
        rename_dict = {k: v for k, v in column_mapping.items() if k in df.columns}
        if rename_dict:
            df.rename(columns=rename_dict, inplace=True)
        # Ensure essential columns exist
        for col in self.NUCLEI_SCHEMA:
            if col not in df.columns:
                df[col] = ''
        # Target fallback: host part of Matched_At when the JSON lacked 'host'
        if 'Target' in df.columns:
            df['Target'] = df.apply(
                lambda r: r['Target'] or (r['Matched_At'].split('://')[-1].split('/')[0]
                                          if r['Matched_At'] else ''), axis=1)
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        df['Severity'] = df['Severity'].str.upper()
        df['Severity_Order'] = df['Severity'].map(severity_order).fillna(5)
        df.sort_values('Severity_Order', inplace=True)
        df.drop('Severity_Order', axis=1, inplace=True)
        df = df[self.NUCLEI_SCHEMA].reset_index(drop=True)
        logger.info(f"Parsed {len(df)} Nuclei findings.")
        return df

    def validate_template_path(self, path: str, is_workflow: bool = False) -> bool:
        if not path:
            return True
        full_path = Path(path) if Path(path).is_absolute() else self.nuclei_templates_path / path
        if is_workflow:
            return full_path.exists() and full_path.suffix in ('.yaml', '.yml')
        else:
            if full_path.is_file():
                return full_path.suffix in ('.yaml', '.yml')
            return full_path.exists() and any(full_path.glob('**/*.yaml'))

    def run_nuclei_scan(
        self,
        targets: List[str],
        template_path: str = "",
        is_workflow: bool = False,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> pd.DataFrame:
        if not targets:
            logger.warning("No targets provided")
            return pd.DataFrame()

        # Only a missing nuclei BINARY is fatal - missing templates must not
        # crash the scan (nuclei simply runs without an explicit -t flag).
        if not self.nuclei_path.is_file():
            raise RuntimeError(
                f"Nuclei executable not found at '{self.nuclei_path}'. "
                "Install nuclei and/or set 'tools.paths.nuclei' in config.json."
            )

        # Load config to check experimental flags
        config = load_config()
        enable_resume = config.get('experimental', {}).get('enable_resume', False)

        # Build a cache key based on targets and template_path
        cache_key = f"nuclei_{'_'.join(sorted(targets))}_{template_path or 'default'}"
        if enable_resume:
            cached = load_cache('nuclei', cache_key)
            if cached is not None:
                logger.info(f"Using cached Nuclei results for {targets[0] if len(targets)==1 else 'multiple targets'}")
                return pd.DataFrame(cached) if cached else pd.DataFrame()

        # Build command
        command = [str(self.nuclei_path), '-jsonl', '-silent']
        if template_path:
            if not self.validate_template_path(template_path, is_workflow):
                error_msg = f"Invalid {'workflow' if is_workflow else 'template'} path: {template_path}"
                logger.error(error_msg)
                if progress_callback:
                    progress_callback(1.0, error_msg)
                return pd.DataFrame()
            flag = '-w' if is_workflow else '-t'
            full_path = template_path if Path(template_path).is_absolute() else str(self.nuclei_templates_path / template_path)
            command.extend([flag, full_path])
        elif self.nuclei_templates_path.is_dir():
            # No explicit template: use the configured templates dir when present.
            command.extend(['-t', str(self.nuclei_templates_path)])
            logger.info(f"Using configured nuclei templates dir: {self.nuclei_templates_path}")
        else:
            logger.warning(
                f"Nuclei templates dir not found at '{self.nuclei_templates_path}' - "
                "running nuclei without an explicit template directory."
            )

        # Add targets
        temp_target_file = None
        try:
            if len(targets) == 1:
                command.extend(['-u', targets[0]])
            else:
                temp_target_file = Path("nuclei_targets_temp.txt")
                temp_target_file.write_text('\n'.join(targets))
                command.extend(['-list', str(temp_target_file)])

            if progress_callback:
                progress_callback(0.1, f"Starting Nuclei scan on {len(targets)} target(s)...")

            raw_output = self._run_command_with_progress(command, progress_callback)
            df = self._parse_nuclei_output_to_df(raw_output)
            if progress_callback:
                progress_callback(1.0, f"Nuclei scan completed. {len(df)} finding(s).")

            # Cache results if enabled
            if enable_resume and not df.empty:
                save_cache('nuclei', cache_key, df.to_dict('records'), ttl=7200)

            return df

        except Exception as e:
            logger.error(f"Nuclei scan failed: {str(e)}")
            if progress_callback:
                progress_callback(1.0, f"Error: {str(e)}")
            return pd.DataFrame()
        finally:
            if temp_target_file and temp_target_file.exists():
                temp_target_file.unlink()