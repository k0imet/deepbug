from app.utils.user_agents import PROGRAM_UA_TAG
import requests
import json
from typing import List, Dict, Optional, Callable
from urllib.parse import urlparse

from app.utils.logger import get_logger

logger = get_logger()

class CORSHeadersScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DeepBug-CORS-Scanner/1.0' + PROGRAM_UA_TAG
        })

    def scan(self, urls: List[str],
             progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Dict]:
        """
        Scan each URL for CORS and security headers.
        Returns a dict: {url: {"cors": ..., "headers": ...}}
        """
        results = {}
        total = len(urls)

        for idx, url in enumerate(urls):
            if progress_callback:
                progress_callback(idx / total, f"Scanning {url}")

            try:
                # Make a GET request with Origin header to test CORS
                # First, get base response without Origin
                resp_base = self.session.get(url, timeout=10, allow_redirects=False)
                # Then with Origin set to a dummy domain
                resp_origin = self.session.get(
                    url,
                    headers={'Origin': 'https://evil.com'},
                    timeout=10,
                    allow_redirects=False
                )

                # Collect headers - 'requests' preserves header case, so normalize
                # to lowercase keys for case-insensitive lookups below.
                base_headers = {k.lower(): v for k, v in resp_base.headers.items()}
                origin_headers = {k.lower(): v for k, v in resp_origin.headers.items()}

                # Check CORS
                cors_info = {
                    'access_control_allow_origin': origin_headers.get('access-control-allow-origin'),
                    'access_control_allow_methods': origin_headers.get('access-control-allow-methods'),
                    'access_control_allow_credentials': origin_headers.get('access-control-allow-credentials'),
                    'is_misconfigured': False,
                    'status': resp_base.status_code
                }
                # Misconfigured if ACAO is '*' or matches the evil origin
                acao = cors_info['access_control_allow_origin']
                if acao == '*' or (acao and 'evil.com' in acao):
                    cors_info['is_misconfigured'] = True

                # Security headers
                security_headers = {
                    'content-security-policy': base_headers.get('content-security-policy'),
                    'strict-transport-security': base_headers.get('strict-transport-security'),
                    'x-frame-options': base_headers.get('x-frame-options'),
                    'x-content-type-options': base_headers.get('x-content-type-options'),
                    'referrer-policy': base_headers.get('referrer-policy'),
                    'x-permitted-cross-domain-policies': base_headers.get('x-permitted-cross-domain-policies'),
                }
                missing = [h for h, v in security_headers.items() if v is None]

                results[url] = {
                    'cors': cors_info,
                    'security_headers': security_headers,
                    'missing_headers': missing,
                    'status': resp_base.status_code
                }

            except Exception as e:
                logger.warning(f"Failed to scan {url}: {e}")
                results[url] = {'error': str(e)}

        if progress_callback:
            progress_callback(1.0, "CORS/headers scan complete.")
        return results