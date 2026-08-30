# app/utils/user_agents.py

import random
import json
import os
from pathlib import Path


def _load_ua_tag() -> str:
    """Program identification tag appended to outgoing User-Agents.

    Defaults to empty. Some bug bounty programs mandate an attribution tag
    (e.g. '-ProgramName-account') so traffic is attributable — set
    `tools.user_agent_tag` in config.json when a program requires it.
    """
    try:
        config_path = Path(__file__).resolve().parents[2] / 'app' / 'modules' / 'config.json'
        if config_path.is_file():
            cfg = json.loads(config_path.read_text())
            return str(cfg.get('tools', {}).get('user_agent_tag', '') or '')
    except Exception:
        pass
    return os.environ.get('DEEPBUG_UA_TAG', '')


PROGRAM_UA_TAG = _load_ua_tag()


def get_bug_bounty_headers(project_path: Path | None = None) -> dict:
    """Return required program attribution headers (e.g. X-Bug-Bounty).

    Priority:
    1. Per-project .bug_bounty file (dynamic, set via Recon tab)
    2. tools.bug_bounty_header / tools.custom_headers in config.json (static)
    3. env DEEPBUG_BUG_BOUNTY
    """
    # 1. Per-project dynamic header — check explicit path or current project
    try:
        if project_path is None:
            # Try to resolve current project from projects dir
            config_path = Path(__file__).resolve().parents[2] / 'app' / 'modules' / 'config.json'
            if config_path.is_file():
                cfg = json.loads(config_path.read_text())
                base = Path(cfg.get('project_settings', {}).get('base_projects_dir', 'projects')).expanduser()
                cur_file = base / ".current_project_name.txt"
                if cur_file.is_file():
                    cur_name = cur_file.read_text().strip()
                    if cur_name:
                        project_path = base / cur_name
        if project_path is not None:
            hdr_file = Path(project_path) / ".bug_bounty"
            if hdr_file.is_file():
                val = hdr_file.read_text().strip()
                if val:
                    if ":" in val:
                        name, value = val.split(":", 1)
                        if value.strip():
                            return {name.strip(): value.strip()}
                    elif val:
                        return {"X-Bug-Bounty": val}
    except Exception:
        pass
    # 2. Static config
    try:
        config_path = Path(__file__).resolve().parents[2] / 'app' / 'modules' / 'config.json'
        if config_path.is_file():
            cfg = json.loads(config_path.read_text())
            tools = cfg.get('tools', {})
            if 'bug_bounty_header' in tools and isinstance(tools['bug_bounty_header'], dict):
                hdr = tools['bug_bounty_header']
                name = hdr.get('name', 'X-Bug-Bounty')
                value = hdr.get('value', '')
                if value:
                    return {name: value}
            if 'custom_headers' in tools and isinstance(tools['custom_headers'], dict):
                headers = {str(k): str(v) for k, v in tools['custom_headers'].items() if v}
                if headers:
                    return headers
    except Exception:
        pass
    env_val = os.environ.get('DEEPBUG_BUG_BOUNTY', '')
    if env_val:
        return {'X-Bug-Bounty': env_val}
    return {}


USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
]


def get_user_agent() -> str:
    return random.choice(USER_AGENTS) + PROGRAM_UA_TAG


def detect_waf_block(resp) -> bool:
    """
    Heuristic: check status code 403/406 and common WAF headers.
    """
    if hasattr(resp, 'status_code'):
        if resp.status_code in (403, 406):
            return True
        server = resp.headers.get('Server', '').lower()
        waf_headers = ['cloudflare', 'akamai', 'incapsula', 'sucuri', 'aws', 'waf']
        if any(h in server for h in waf_headers):
            return True
    return False
