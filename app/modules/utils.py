# modules/utils.py

import json
import logging
import re
from pathlib import Path
import pandas as pd
from typing import Dict, Any, Union, List, Optional
import urllib.parse
import sys

# Setup a logger for the utils module itself
utils_logger = logging.getLogger(__name__)

def setup_logging(config: Dict):
    """Configures the logging based on the provided configuration."""
    log_level_str = config.get('logging', {}).get('level', 'INFO').upper()
    log_file = config.get('logging', {}).get('file', 'bugbountybot.log')

    log_level = getattr(logging, log_level_str, logging.INFO)

    # Ensure log directory exists if log_file specifies one
    log_file_path = Path(log_file)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout) # To also output to console
        ]
    )
    utils_logger.info(f"Logging configured with level {log_level_str} to file {log_file}")



def load_config() -> Dict:
    """
    Loads the configuration from config.json.
    Searches in common locations: current dir, app dir, parent dir.
    """
    current_dir = Path(__file__).parent
    app_root_dir = current_dir.parent.parent

    possible_config_paths = [
        app_root_dir / "config.json",
        current_dir.parent / "config.json",
        current_dir / "config.json" # <--- ADD THIS LINE if config.json is directly in 'modules'
        # Or if it's in a 'config' subfolder within 'modules' as your tree implies:
        # current_dir / "config" / "config.json" # <--- THIS ONE based on your tree
    ]

    loaded_config = {}
    for config_path in possible_config_paths:
        if config_path.is_file():
            try:
                with open(config_path, 'r') as f:
                    loaded_config = json.load(f)
                utils_logger.info(f"Successfully loaded configuration from {config_path}")
                break # Stop at the first successfully loaded config
            except json.JSONDecodeError as e:
                utils_logger.error(f"Error decoding config file {config_path}: {e}")
            except Exception as e:
                utils_logger.error(f"Error loading config file {config_path}: {e}")
    
    # Define a robust default configuration structure
    default_config = {
        "logging": {"level": "INFO", "file": "bugbountybot.log"},
        "project_settings": {"base_projects_dir": "./projects"},
        "tools": {
            "paths": {
                "subfinder": "",
                "dnsx": "",
                "nuclei": "", # <--- ENSURE NUCLEI HAS A DEFAULT (even if empty string)
                "nuclei_templates": "",
                "nmap": "",
                "masscan": "",
                "gau": "",
                "getallurls": "",
                "katana": "",
                "waybackurls": "",
                "subjs": "",
                "webanalyze": "",
                "httpx": "",
                "getjs": "",
                "gf": "",
                "linkfinder": "",
                "paramspider": "",
                "sqltimer": "",
                "amass": ""
            },
            "rate_limits": {"masscan": 1000},
            "sqltimer": {"sleep_time": 5, "threads": 10, "timeout_multiplier": 6, "timeout_buffer": 10}
        },
        "output_formats": {"default": "csv"}
    }

    # Merge loaded_config into default_config (deep merge for nested dictionaries)
    # This ensures that any missing keys in loaded_config are filled by default_config
    # and existing keys in loaded_config override defaults.
    def deep_merge(dict1, dict2):
        for k, v in dict2.items():
            if k in dict1 and isinstance(dict1[k], dict) and isinstance(v, dict):
                dict1[k] = deep_merge(dict1[k], v)
            else:
                dict1[k] = v
        return dict1

    final_config = deep_merge(default_config, loaded_config)

    if not loaded_config:
        utils_logger.critical("No valid config.json found or failed to load. Using default configuration.")
    
    return final_config


def validate_domain(domain: str) -> bool:
    """Basic validation for a domain name."""
    if not domain:
        return False
    # Regex for a somewhat robust domain validation (allows subdomains, common TLDs)
    domain_regex = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
    )
    return bool(domain_regex.match(domain))

def validate_ip(ip_address: str) -> bool:
    """Basic validation for an IPv4 address."""
    if not ip_address:
        return False
    # Regex for IPv4
    ip_regex = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    return bool(ip_regex.match(ip_address))

# --- IMPORTANT CHANGE HERE ---
def is_valid_url(url: str) -> Optional[str]: # Change return type hint to Optional[str]
    """
    Checks if a string is a valid HTTP/HTTPS URL.
    Returns the URL string if valid, otherwise returns None.
    """
    if not isinstance(url, str) or not url.strip():
        return None
    
    parsed_url = urllib.parse.urlparse(url.strip())
    
    # Check if scheme and netloc exist
    if all([parsed_url.scheme, parsed_url.netloc]):
        # Further refine: only allow http or https schemes
        if parsed_url.scheme in ['http', 'https']:
            return url.strip() # Return the original, valid URL
    
    # If scheme is missing, try to prepend it and re-validate
    if not parsed_url.scheme:
        temp_url_https = f"https://{url.strip()}"
        temp_parsed_https = urllib.parse.urlparse(temp_url_https)
        if all([temp_parsed_https.scheme, temp_parsed_https.netloc]) and temp_parsed_https.scheme == 'https':
            return temp_url_https # Return the URL with prepended HTTPS
        
        temp_url_http = f"http://{url.strip()}"
        temp_parsed_http = urllib.parse.urlparse(temp_url_http)
        if all([temp_parsed_http.scheme, temp_parsed_http.netloc]) and temp_parsed_http.scheme == 'http':
            return temp_url_http # Return the URL with prepended HTTP

    return None # If no valid URL could be formed or validated

def format_results(data: List[Dict[str, Any]], scan_type: str) -> pd.DataFrame:
    """
    Formats a list of dictionaries into a pandas DataFrame based on scan type.
    This function helps standardize output for Streamlit display and saving.
    """
    if not data:
        return pd.DataFrame()

    df = pd.DataFrame(data)

    if scan_type == "raw_subdomains":
        # Ensure 'Subdomain' column exists, otherwise rename a suitable one or add empty
        if 'Subdomain' not in df.columns:
            if 'hostname' in df.columns:
                df.rename(columns={'hostname': 'Subdomain'}, inplace=True)
            elif 'url' in df.columns:
                df['Subdomain'] = df['url'].apply(lambda x: urllib.parse.urlparse(x).netloc)
            else:
                df['Subdomain'] = "N/A"
        df = df[['Subdomain']].drop_duplicates()
    elif scan_type == "resolved_subdomains":
        # Expected columns: hostname, ip, cname
        cols = ['hostname', 'ip', 'cname']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates()
    elif scan_type == "live_hosts":
        # Expected columns: URL, StatusCode, Title, WebServer
        cols = ['URL', 'StatusCode', 'Title', 'WebServer', 'ContentLength']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates(subset=['URL'])
    elif scan_type == "ports":
        # Expected columns: Host, Port, State, Service
        cols = ['Host', 'Port', 'State', 'Service']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates()
    elif scan_type == "js_files":
        # Expected columns: URL, Status, Content_Length
        cols = ['URL', 'Status', 'Content_Length', 'Source']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates()
    elif scan_type == "endpoints":
        # Expected columns: Endpoint, Source_File
        cols = ['Endpoint', 'Source_File', 'Found_From']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates()
    elif scan_type == "sensitive_data":
        # Expected columns: Type, Value, Source_File
        cols = ['Type', 'Value', 'Source_File', 'Found_From']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates()
    elif scan_type == "webanalyze_techs":
        # Expected columns: URL, Category, Technology, Version
        cols = ['URL', 'Category', 'Technology', 'Version', 'Confidence']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates()
    elif scan_type == "sqli_findings":
        # Expected columns: Tool, URL, Vulnerability, Severity, Parameter, Payload, Details
        cols = ['Tool', 'URL', 'Vulnerability', 'Severity', 'Parameter', 'Payload', 'Details']
        for col in cols:
            if col not in df.columns:
                df[col] = "N/A"
        df = df[cols].drop_duplicates(subset=['URL', 'Vulnerability', 'Parameter', 'Payload']) # Use a combination for uniqueness
    else:
        utils_logger.warning(f"Unknown scan_type '{scan_type}' for formatting results. Returning raw DataFrame.")

    return df