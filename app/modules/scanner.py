import subprocess
import json
import pandas as pd
import logging
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional, Union
import os

class VulnerabilityScanner:
    """
    A wrapper class for running Nuclei vulnerability scans with improved template handling.
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.nuclei_path = Path(self.config.get('tools', {}).get('paths', {}).get('nuclei', 'nuclei')).expanduser()
        self.nuclei_templates_path = Path(self.config.get('tools', {}).get('paths', {}).get('nuclei_templates', '')).expanduser()
        
        if not self.nuclei_path.is_file() and 'nuclei' not in os.getenv('PATH', ''):
            logging.error(f"Nuclei executable not found at: {self.nuclei_path}")
        if not self.nuclei_templates_path.is_dir():
            logging.warning(f"Nuclei templates directory not found at: {self.nuclei_templates_path}")

    def _run_command(self, command: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[str]:
        """Helper to run shell commands and capture output."""
        output_lines = []
        try:
            process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.STDOUT, 
                text=True, 
                encoding='utf-8', 
                bufsize=1
            )
            
            for line in iter(process.stdout.readline, ''):
                line = line.strip()
                if line:
                    output_lines.append(line)
                    if progress_callback:
                        progress_callback(0.5, f"Scanning... ({line})")

            process.wait()
            if process.returncode != 0:
                raise RuntimeError(f"Nuclei command failed with exit code {process.returncode}")
            
            return output_lines
        except Exception as e:
            logging.error(f"Error running command: {' '.join(command)} - {str(e)}")
            raise

    def _parse_nuclei_output(self, raw_output: List[str]) -> pd.DataFrame:
        """Parse Nuclei JSONL output into DataFrame."""
        findings = []
        for line in raw_output:
            try:
                data = json.loads(line)
                if 'template-id' in data and 'info' in data:
                    info = data.get('info', {})
                    findings.append({
                        'Template_ID': data.get('template-id'),
                        'Name': info.get('name'),
                        'Severity': info.get('severity', 'UNKNOWN').upper(),
                        'Host': data.get('host'),
                        'Matched_At': data.get('matched-at'),
                        'Description': info.get('description'),
                        'Tags': ', '.join(info.get('tags', [])),
                        'Reference': ', '.join(info.get('reference', [])),
                        'Full_Details': json.dumps(data)
                    })
            except json.JSONDecodeError:
                logging.warning(f"Skipping non-JSON line: {line}")
        return pd.DataFrame(findings)

    def validate_template_path(self, path: str, is_workflow: bool = False) -> bool:
        """Validate if template/workflow path exists and contains valid files."""
        if not path:  # Empty path means use default templates
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
        template_path: Optional[str] = None, 
        is_workflow: bool = False,
        progress_callback: Optional[Callable[[float, str], None]] = None
    ) -> pd.DataFrame:
        """
        Run Nuclei scan with proper template/workflow handling.
        
        Args:
            targets: List of target URLs/IPs
            template_path: Relative/Absolute path to templates/workflows
            is_workflow: Whether the path points to workflow templates
        """
        if not targets:
            logging.warning("No targets provided")
            return pd.DataFrame()

        # Build base command
        command = [str(self.nuclei_path), '-jsonl', '-silent']
        
        # Add template/workflow flag if specified
        if template_path:
            if not self.validate_template_path(template_path, is_workflow):
                error_msg = f"Invalid {'workflow' if is_workflow else 'template'} path: {template_path}"
                logging.error(error_msg)
                if progress_callback:
                    progress_callback(1.0, error_msg)
                return pd.DataFrame()
            
            flag = '-w' if is_workflow else '-t'
            full_path = template_path if Path(template_path).is_absolute() else str(self.nuclei_templates_path / template_path)
            command.extend([flag, full_path])

        # Handle targets
        temp_target_file = None
        try:
            if len(targets) == 1:
                command.extend(['-u', targets[0]])
            else:
                temp_target_file = Path("nuclei_targets_temp.txt")
                temp_target_file.write_text('\n'.join(targets))
                command.extend(['-list', str(temp_target_file)])

            if progress_callback:
                progress_callback(0.1, f"Starting scan on {len(targets)} target(s)...")

            raw_output = self._run_command(command, progress_callback)
            return self._parse_nuclei_output(raw_output)

        except Exception as e:
            logging.error(f"Scan failed: {str(e)}")
            if progress_callback:
                progress_callback(1.0, f"Error: {str(e)}")
            return pd.DataFrame()
        finally:
            if temp_target_file and temp_target_file.exists():
                temp_target_file.unlink()