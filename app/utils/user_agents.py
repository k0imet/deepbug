# app/utils/user_agents.py

import random

# Program identification tag mandated by the GRW Trading FZE bounty program
# (YesWeHack). Appended to every outgoing User-Agent so traffic is attributable.
PROGRAM_UA_TAG = ' -BugBounty-bitoasis '

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