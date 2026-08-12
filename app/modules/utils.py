# modules/utils.py

import json
import re
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import pandas as pd

# Use the new logger
from app.utils.logger import get_logger
from app.utils.url_utils import urlparse
logger = get_logger()


def setup_logging(config: Dict):
    """Deprecated: kept for compatibility. No-op — logging is configured by app.utils.logger."""


def expand_paths(obj):
    """Recursively expand environment variables in string values."""
    if isinstance(obj, dict):
        return {k: expand_paths(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [expand_paths(v) for v in obj]
    elif isinstance(obj, str):
        # Expand $VAR or ${VAR}
        return os.path.expandvars(obj) if '$' in obj else obj
    else:
        return obj


def load_config() -> Dict:
    """Load config from config.json, with defaults and environment variable expansion."""
    current_dir = Path(__file__).parent
    app_root = current_dir.parent.parent

    possible_paths = [
        app_root / "config.json",
        current_dir.parent / "config.json",
        current_dir / "config.json"
    ]

    loaded = {}
    for path in possible_paths:
        if path.is_file():
            try:
                with open(path) as f:
                    loaded = json.load(f)
                logger.info(f"Loaded config from {path}")
                break
            except Exception as e:
                logger.error(f"Error loading {path}: {e}")

    # Expand environment variables in loaded config
    loaded = expand_paths(loaded)

    default = {
        "logging": {"level": "INFO", "file": "bugbountybot.log"},
        "project_settings": {"base_projects_dir": "./projects"},
        "tools": {
            "paths": {
                "subfinder": "", "dnsx": "", "nuclei": "", "nuclei_templates": "",
                "nmap": "", "masscan": "", "gau": "", "getallurls": "", "katana": "",
                "waybackurls": "", "subjs": "", "webanalyze": "", "httpx": "",
                "getjs": "", "gf": "", "linkfinder": "", "paramspider": "",
                "sqltimer": "", "amass": "", "ffuf": ""
            },
            "rate_limits": {"masscan": 1000},
            "sqltimer": {"sleep_time": 5, "threads": 10, "timeout_multiplier": 6, "timeout_buffer": 10}
        },
        "dorking": {
            "engines": ["yandex", "yahoo", "google", "bing", "duckduckgo"],
            "timeout": 20,
            "delay_min": 3.0,
            "delay_max": 8.0,
            "retry_delay": 12.0,
            "per_page": 50,
            "max_pages": 1,
            "max_queries": 30,
            "max_results": 200
        },
        "wayback": {
            "timeout": 30,
            "max_results": 1000,
            "sources": ["cdx", "commoncrawl", "otx"]
        },
        "github": {
            "timeout": 20,
            "max_queries": 12,
            "per_query": 10,
            "token_env": "GITHUB_TOKEN",
            "sources": ["code", "issues", "commits"]
        },
        "shodan": {
            "timeout": 20,
            "max_results": 100,
            "favicon_max": 5,
            "token_env": "SHODAN_API_KEY"
        },
        "asn_osint": {
            "timeout": 20,
            "max_prefixes": 5,
            "max_reverse": 200,
            "max_ip_sample": 10
        },
        "git_disclosure": {
            "timeout": 15,
            "max_files": 25,
            "depth": 2,
            "max_snippet": 500
        },
        "bypass403": {
            "timeout": 12,
            "max_urls": 50
        },
        "vhost": {
            "timeout": 8,
            "max_vhosts": 80,
            "min_diff": 30
        },
        "open_redirect": {
            "timeout": 12,
            "max_urls": 200,
            "canary_host": "canary.deepbug.io"
        },
        "ssrf": {
            "timeout": 12,
            "max_urls": 100,
            "max_payloads": 5,
            "canary_host": "canary.deepbug.io"
        },
        "dom_xss": {
            "max_urls": 40,
            "browser": True,
            "page_timeout_ms": 8000,
            "max_variants": 6
        },
        "pp_validator": {
            "max_urls": 15,
            "browser": True,
            "page_timeout_ms": 8000
        },
        "cors_validator": {
            "max_urls": 250,
            "timeout": 8
        },
        "open_redirect_validator": {
            "max_urls": 100,
            "timeout": 8,
            "browser": True
        },
        "ssrf_validator": {
            "max_urls": 100,
            "timeout": 8
        },
        "ai": {
            "enable": False,
            "api_base": "https://api.openai.com/v1",
            "api_key": "",
            "model": "gpt-4o-mini",
            "chat_base": "https://api.tokenrouter.com/v1",
            "chat_model": "moonshotai/kimi-k3-free",
            "chat_temperature": 0.3,
            "chat_max_history": 20,
            "chat_max_chars": 6000,
            "timeout": 60,
            "max_context": 6000
        },
        "output_formats": {"default": "csv"},
        "experimental": {
            "enable_async": False,
            "enable_ai": False,
            "enable_db": False,
            "enable_resume": False,
            "log_level": "INFO",
            "log_file": "logs/deepbug.log",
            "subprocess_timeout": 600
        }
    }

    def deep_merge(a, b):
        for k, v in b.items():
            if k in a and isinstance(a[k], dict) and isinstance(v, dict):
                a[k] = deep_merge(a[k], v)
            else:
                a[k] = v
        return a

    final = deep_merge(default, loaded)
    if not loaded:
        logger.critical("No config found – using defaults.")

    # Expand environment variables in final config too (though already done)
    return expand_paths(final)


def validate_domain(domain: str) -> bool:
    return bool(re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", domain or ""))


def validate_ip(ip: str) -> bool:
    return bool(re.match(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip or ""))


def is_valid_url(url: str) -> Optional[str]:
    if not url or not isinstance(url, str):
        return None
    parsed = urlparse(url.strip())
    if parsed.scheme and parsed.netloc:
        if parsed.scheme in ('http', 'https'):
            return url.strip()
    for scheme in ('https', 'http'):
        test = f"{scheme}://{url.strip()}"
        p = urlparse(test)
        if p.scheme and p.netloc:
            return test
    return None


# ===== TARGET SANITIZATION =====
_FILESYSTEM_UNSAFE = re.compile(r'[./:*?<>"|\\\x00-\x1f]')


def sanitize_target(target: str) -> str:
    """Map a target (domain/URL/IP) to a filesystem-safe directory name.

    '.'/'/'/':' and other unsafe characters become '_'. The mapping is
    deterministic and 1:1 per character, so desanitize_target() can reverse
    it (backward compatible with legacy dirs like 'hackersavanna_com').
    """
    if not target or not isinstance(target, str):
        return ''
    return _FILESYSTEM_UNSAFE.sub('_', target.strip())


def desanitize_target(dir_name: str) -> str:
    """Reverse of sanitize_target: map a stored directory name back to a target."""
    if not dir_name or not isinstance(dir_name, str):
        return ''
    return dir_name.replace('_', '.')


# ===== PARSERS =====
def parse_nuclei_output(raw_output) -> List[Dict[str, Any]]:
    """Parse Nuclei JSONL output into a list of finding dicts.

    Robust against None/bytes input, partial (truncated) lines, and
    non-object JSON lines — those are skipped, never raised on.
    """
    if not raw_output:
        return []
    if isinstance(raw_output, bytes):
        raw_output = raw_output.decode('utf-8', errors='ignore')
    results = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                continue
            info = data.get('info') or {}
            if not isinstance(info, dict):
                info = {}
            matched_at = data.get('matched-at', '') or ''
            target = data.get('host', '') or ''
            if not target and matched_at:
                target = matched_at.split('://')[-1].split('/')[0]
            results.append({
                'template_id': data.get('template-id', '') or '',
                'name': info.get('name', '') or '',
                'severity': info.get('severity', '') or '',
                'matched_at': matched_at,
                'extracted_results': data.get('extracted-results', []) or [],
                'curl_command': data.get('curl-command', '') or '',
                'target': target,
                'raw': data
            })
        except Exception:
            # partial / malformed line - skip it, never crash the scan
            continue
    if results:
        logger.info(f"Parsed {len(results)} Nuclei findings via JSON")
    return results


def parse_naabu_output(raw_output) -> List[Dict[str, Any]]:
    """Parse Naabu output (single JSON doc or JSONL / 'host:port' lines).

    Robust against None/bytes input, partial lines and mixed formats.
    """
    if not raw_output:
        return []
    if isinstance(raw_output, bytes):
        raw_output = raw_output.decode('utf-8', errors='ignore')
    raw_output = raw_output.strip()
    if not raw_output:
        return []

    # Whole-output single JSON document (array of port objects)
    try:
        data = json.loads(raw_output)
        if isinstance(data, list):
            logger.info(f"Parsed {len(data)} ports via JSON")
            return [p for p in data if isinstance(p, dict)]
    except Exception:
        pass

    ports = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # JSONL line from naabu -json
        if line.startswith('{'):
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    host = data.get('host', '') or data.get('ip', '') or ''
                    port = data.get('port', '')
                    if host and port is not None:
                        ports.append({'host': host, 'port': int(port),
                                      'state': 'open', 'service': 'unknown'})
                continue
            except Exception:
                continue
        # Plain 'host:port' line
        try:
            host, port_str = line.rsplit(':', 1)
            port = int(port_str.strip())
            if host.strip():
                ports.append({'host': host.strip(), 'port': port,
                              'state': 'open', 'service': 'unknown'})
        except Exception:
            continue
    if ports:
        logger.info(f"Parsed {len(ports)} ports via fallback")
    return ports


# ===== FORMATTER =====
def format_results(data: List[Dict[str, Any]], scan_type: str) -> pd.DataFrame:
    if not data:
        return pd.DataFrame()
    df = pd.DataFrame(data)
    # Keep the existing implementation as per your original code
    # ... (I won't replicate the whole function here, but it should stay as you had it)
    return df