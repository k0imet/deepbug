# modules/tools/port_scanner.py

import subprocess
import pandas as pd
import logging
from typing import List, Dict, Union, Callable, Any, Optional
from pathlib import Path
import re # For parsing nmap/masscan/naabu output

logger = logging.getLogger(__name__)

class PortScanner:
    def __init__(self, config: Dict):
        self.config = config
        # FIX: Add default empty string to .get() to prevent Path(None) TypeError
        self.nmap_path = Path(self.config['tools']['paths'].get('nmap', ''))
        self.masscan_path = Path(self.config['tools']['paths'].get('masscan', ''))
        self.naabu_path = Path(self.config['tools']['paths'].get('naabu', '')) # Added Naabu path

        for path_attr in ['nmap_path', 'masscan_path', 'naabu_path']: # Include naabu_path in check
            path = getattr(self, path_attr)
            # Check if the path actually points to an existing file
            if not path.is_file():
                logger.warning(f"{path_attr.replace('_path', '').replace('_', ' ').title()} executable not found at: {path}. Please check config.json or ensure it's in your system's PATH.")

    def _run_command(self, cmd: Union[str, List[str]], tool_name: str, timeout: int = 600, progress_callback: Optional[Callable[[float, str], None]] = None) -> str:
        """
        Helper method to run shell commands safely with error handling and logging.
        Args:
            cmd (Union[str, List[str]]): The command string or list of arguments.
            tool_name (str): The name of the tool being run (for logging).
            timeout (int): Maximum time in seconds to wait for the command to complete.
            progress_callback (Optional[Callable]): Callback function to update UI progress.
        Returns:
            str: The standard output of the command.
        Raises:
            RuntimeError: If the command fails or times out.
        """
        cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
        logger.info(f"Running command for {tool_name}: {cmd_str}")
        if progress_callback:
            progress_callback(0, f"Running {tool_name}...")

        try:
            result = subprocess.run(
                cmd,
                shell=True, # Keeping shell=True because 'cmd' is constructed as a string in run_port_scan
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True # Raise CalledProcessError if return code is non-zero
            )
            if progress_callback:
                progress_callback(1, f"{tool_name} completed.")
            return result.stdout
        except FileNotFoundError:
            logger.error(f"{tool_name} tool not found. Please check your config.json.")
            if progress_callback:
                progress_callback(0, f"Error: {tool_name} not found.")
            raise RuntimeError(f"{tool_name} executable not found. Check config.")
        except subprocess.CalledProcessError as e:
            logger.error(f"{tool_name} failed with exit code {e.returncode}: {e.stderr.strip()}")
            if progress_callback:
                progress_callback(0, f"Error: {tool_name} failed: {e.stderr.strip()}")
            raise RuntimeError(f"{tool_name} failed: {e.stderr.strip()}")
        except subprocess.TimeoutExpired:
            logger.error(f"{tool_name} timed out after {timeout} seconds.")
            if progress_callback:
                progress_callback(0, f"Error: {tool_name} timed out.")
            raise RuntimeError(f"{tool_name} timed out after {timeout} seconds")
        except Exception as e:
            logger.error(f"An unexpected error occurred while running {tool_name}: {e}")
            if progress_callback:
                progress_callback(0, f"Error: {tool_name} encountered an unexpected error.")
            raise RuntimeError(f"An unexpected error occurred while running {tool_name}: {e}")

    def run_port_scan(self, target: str, tool: str = "nmap", progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        """
        Performs port scanning on the target using Nmap, Masscan, or Naabu.
        Args:
            target (str): The target IP or domain.
            tool (str): 'nmap', 'masscan', or 'naabu'.
            progress_callback (Optional[Callable]): Callback for UI progress updates.
        Returns:
            pd.DataFrame: DataFrame of open ports.
        """
        from modules.utils import format_results # Import locally

        if tool == "nmap":
            if not self.nmap_path.is_file():
                logger.error(f"Nmap executable not found at {self.nmap_path}. Cannot perform Nmap scan.")
                raise FileNotFoundError(f"Nmap executable not found at {self.nmap_path}")
            
            # -p- for all 65535 ports, -Pn to skip host discovery (useful for targets that block ping),
            # -sV for service/version detection, -oG for greppable output.
            cmd = f"{self.nmap_path} -p- -sV -T4 --open {target} -oG -"
            output = self._run_command(cmd, 'Nmap', timeout=900, progress_callback=progress_callback) # Nmap can be slow
            return self._parse_nmap_greppable_output(output, target)

        elif tool == "masscan":
            if not self.masscan_path.is_file():
                logger.error(f"Masscan executable not found at {self.masscan_path}. Cannot perform Masscan scan.")
                raise FileNotFoundError(f"Masscan executable not found at {self.masscan_path}")
            
            # --rate 1000 for 1000 packets/sec (adjust as needed), -p 0-65535 for all ports
            cmd = f"{self.masscan_path} {target} -p0-65535 --rate {self.config['tools']['rate_limits'].get('masscan', 1000)} --wait 0"
            output = self._run_command(cmd, 'Masscan', timeout=300, progress_callback=progress_callback)
            return self._parse_masscan_output(output, target)

        elif tool == "naabu": # New Naabu integration
            if not self.naabu_path.is_file():
                logger.error(f"Naabu executable not found at {self.naabu_path}. Cannot perform Naabu scan.")
                raise FileNotFoundError(f"Naabu executable not found at {self.naabu_path}")
            
            # Naabu -host <target> -p - for all ports, -silent for minimal output
            # For a quick scan to identify open ports, naabu -p - is good.
            # To integrate with Nmap for service detection, you'd typically pipe Naabu output to Nmap.
            # For simplicity here, we'll just get the basic open ports from Naabu.
            # A more advanced setup might use -nmap-cli with naabu.
            cmd = f"{self.naabu_path} -host {target} -p - -silent"
            # Naabu is very fast, so a shorter timeout is generally fine, but keep it reasonable.
            output = self._run_command(cmd, 'Naabu', timeout=120, progress_callback=progress_callback)
            return self._parse_naabu_output(output, target)

        else:
            raise ValueError(f"Unsupported port scanning tool: {tool}")

    def _parse_nmap_greppable_output(self, output: str, target: str) -> pd.DataFrame:
        """Parses Nmap greppable output into a DataFrame."""
        ports = []
        # Example line: Host: 192.168.1.1 ()    Ports: 22/open/tcp//ssh//OpenSSH 7.6p1 Ubuntu 4/
        for line in output.split('\n'):
            if 'Ports:' in line:
                match = re.search(r'Ports: (.*)', line)
                if match:
                    port_str = match.group(1)
                    # Split ports by comma or tab, then parse each port detail
                    # This regex tries to capture port, state, proto, and service
                    port_details = re.findall(r'(\d+)/([a-z]+)/([a-z]+)//([\w\s.-]*?)(?:/|\Z)', port_str)
                    for port, state, proto, service in port_details:
                        ports.append({
                            "Target": target,
                            "Port": f"{port}/{proto}",
                            "State": state,
                            "Service": service.strip() or "unknown"
                        })
        if not ports:
            logger.info(f"No open ports parsed from Nmap output for {target}.")
        return pd.DataFrame(ports)

    def _parse_masscan_output(self, output: str, target: str) -> pd.DataFrame:
        """Parses Masscan output into a DataFrame."""
        ports = []
        # Example line: Discovered open port 80/tcp on 192.168.1.1
        for line in output.split('\n'):
            match = re.search(r'open port (\d+)/(\w+) on (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                port = match.group(1)
                proto = match.group(2)
                ip = match.group(3)
                ports.append({
                    "Target": ip, # Masscan often gives IP
                    "Port": f"{port}/{proto}",
                    "State": "open",
                    "Service": "unknown" # Masscan doesn't identify services
                })
        if not ports:
            logger.info(f"No open ports parsed from Masscan output for {target}.")
        return pd.DataFrame(ports)

    def _parse_naabu_output(self, output: str, target: str) -> pd.DataFrame:
        """Parses Naabu's simple output (host:port) into a DataFrame."""
        ports = []
        # Example line: 192.168.1.1:80
        # If -json is used, the output format changes, but for simplicity, we'll parse the default.
        for line in output.split('\n'):
            line = line.strip()
            if line:
                # Naabu output format is typically 'ip:port' or 'domain:port'
                # We need to extract the port, and assume TCP unless specified otherwise (Naabu defaults to SYN scan - TCP)
                match = re.match(r'(.+):(\d+)$', line)
                if match:
                    host_or_ip = match.group(1)
                    port = match.group(2)
                    ports.append({
                        "Target": host_or_ip,
                        "Port": f"{port}/tcp", # Naabu primarily does TCP SYN scans
                        "State": "open",
                        "Service": "unknown" # Naabu primarily identifies open ports, not services by default
                    })
        if not ports:
            logger.info(f"No open ports parsed from Naabu output for {target}.")
        return pd.DataFrame(ports)