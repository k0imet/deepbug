from app.utils.user_agents import PROGRAM_UA_TAG
"""
endpoint_validator.py — static + live validation to cut endpoint false positives.

Two layers:
  1. sanitize_endpoints()  — static filter. Kills the junk the regex fallback
     mints: package specs ('graphql-tag'), MIME types, i18n keys, static assets,
     unresolved template literals ('${base}/x'), bare schemes.
  2. EndpointValidator     — async live probing. Classifies by HTTP status so
     dead 404/410 paths drop out and auth-protected (401/403) / method-real (405)
     paths get surfaced. Includes per-host soft-404 baselining.

SAFETY: only GET / OPTIONS are ever sent — never the discovered state-changing
method. Validation can never mutate a live target. Templated URLs ('/{id}',
'/api/v1/:id/') are probed with a benign substituted value and tagged
template=True so the original template is preserved as an IDOR lead; relative
and ws/wss URLs are marked unknown, not probed.
"""

import re
import asyncio
import secrets as _secrets
import aiohttp
from typing import Dict, List, Optional, Set
from app.utils.url_utils import urlparse


_TEMPLATE_TOKEN_RE = re.compile(r"\{[^}]+\}|:[a-zA-Z_][a-zA-Z0-9_]*(?=/|$)")
_UUID_HINT_RE = re.compile(r"uuid|guid|token|key", re.IGNORECASE)
_GUID_BENIGN = "00000000-0000-0000-0000-000000000000"


STATIC_EXT = re.compile(
    r"\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|less|png|jpe?g|gif|svg|webp|avif|ico|"
    r"bmp|woff2?|ttf|eot|otf|map|mp4|webm|mp3|wav|pdf|zip|gz|tar|html?|xml|md)"
    r"(?:[?#]|$)",
    re.IGNORECASE,
)

_LONE = {"/", "//", "http://", "https://", "ws://", "wss://"}


def looks_like_endpoint(url: str) -> bool:
    """Static shape check. True only for absolute paths or absolute URLs."""
    if not url:
        return False
    url = url.strip()
    # must be an absolute path or absolute URL — this single rule kills the bulk
    # of regex noise (package names, MIME types, translation keys, CSS values)
    if not url.startswith(("/", "http://", "https://", "ws://", "wss://")):
        return False
    if url in _LONE:
        return False
    # unresolved interpolation leftovers from AST/template extraction
    if "${" in url or "{{" in url or url.count("{") != url.count("}"):
        return False
    if any(c in url for c in (" ", "\n", "\t", "<", ">", "`", "\\")):
        return False
    if STATIC_EXT.search(url):
        return False
    return True


def _benign_template_value(token: str) -> str:
    """Map a template token to a benign, non-mutating substitute value."""
    name = token.strip("{}:").lower()
    if _UUID_HINT_RE.search(name):
        return _GUID_BENIGN
    if "slug" in name or "name" in name:
        return "test"
    return "1"


def _substitute_template(url: str) -> Optional[str]:
    """Replace every {param} / :param token with a benign value. Returns None
    for URLs that stay unprobeable (e.g. malformed brackets)."""
    if "{" in url or "}" in url:
        if url.count("{") != url.count("}"):
            return None
    if not _TEMPLATE_TOKEN_RE.search(url):
        return None
    return _TEMPLATE_TOKEN_RE.sub(lambda m: _benign_template_value(m.group(0)), url)


def sanitize_endpoints(requests: List[Dict]) -> List[Dict]:
    """Filter a list of ApiRequest dicts down to plausible endpoints."""
    out: List[Dict] = []
    for r in requests:
        # always keep source-map markers regardless of shape
        if "source_map_available" in (r.get("suspicious_indicators") or []):
            out.append(r)
            continue
        if looks_like_endpoint(r.get("url", "")):
            out.append(r)
    return out


class EndpointValidator:
    def __init__(self, allowed_hosts: Optional[Set[str]] = None,
                 concurrency: int = 40, timeout: int = 8,
                 drop_dead: bool = True, user_agent: Optional[str] = None):
        self.allowed_hosts = {h.lower() for h in allowed_hosts} if allowed_hosts else None
        self.timeout = timeout
        self.drop_dead = drop_dead
        self.sem = asyncio.Semaphore(concurrency)
        self.headers = {"User-Agent": (user_agent or "deepbug-endpoint-validator/1.0") + PROGRAM_UA_TAG}
        self._baselines: Dict[str, Dict] = {}
        self._baseline_locks: Dict[str, asyncio.Lock] = {}

    def _in_scope(self, host: str) -> bool:
        if not host:
            return False
        if self.allowed_hosts is None:
            return True
        host = host.lower()
        return any(host == h or host.endswith("." + h) for h in self.allowed_hosts)

    async def _baseline(self, session: aiohttp.ClientSession, root: str) -> Dict:
        """Request a random path per host to detect catch-all 200 pages (soft 404)."""
        lock = self._baseline_locks.setdefault(root, asyncio.Lock())
        async with lock:
            if root in self._baselines:
                return self._baselines[root]
            info = {"status": None, "length": None}
            probe = f"{root}/{_secrets.token_hex(16)}"
            try:
                async with self.sem:
                    async with session.get(probe, timeout=self.timeout,
                                           allow_redirects=False) as resp:
                        body = await resp.read()
                        info = {"status": resp.status, "length": len(body)}
            except Exception:
                pass
            self._baselines[root] = info
            return info

    async def _probe(self, session: aiohttp.ClientSession, req: Dict) -> Dict:
        url = req.get("url", "")

        # templated path tokens: substitute a benign value and probe, keeping
        # the original template (with the placeholder) as the IDOR lead
        substituted = _substitute_template(url)
        if substituted is not None and substituted != url:
            req["template_original"] = url
            req["template"] = True
            url = substituted
        if substituted is None and ("{" in url or "}" in url):
            req.update(alive=None, live_status="unprobeable")
            return req
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            req.update(alive=None, live_status="unprobeable")
            return req
        if not self._in_scope(parsed.hostname or ""):
            req.update(alive=None, live_status="out_of_scope")
            return req

        root = f"{parsed.scheme}://{parsed.netloc}"
        base = await self._baseline(session, root)

        status = length = None
        allow = ""
        try:
            async with self.sem:
                async with session.get(url, timeout=self.timeout,
                                       allow_redirects=False) as resp:
                    body = await resp.read()
                    status, length = resp.status, len(body)
                    allow = resp.headers.get("Allow", "")
        except asyncio.TimeoutError:
            req.update(alive=None, live_status="timeout")
            return req
        except Exception:
            req.update(alive=None, live_status="error")
            return req

        # OPTIONS for real allowed-method enumeration (safe, non-mutating)
        if not allow:
            try:
                async with self.sem:
                    async with session.options(url, timeout=self.timeout,
                                               allow_redirects=False) as o:
                        allow = o.headers.get("Allow", "") or allow
            except Exception:
                pass

        soft = self._is_soft_404(status, length, base)
        req["live_status"] = status
        req["allow_methods"] = allow
        req["soft_404"] = soft
        req["alive"] = self._classify(req, status, soft)
        return req

    @staticmethod
    def _is_soft_404(status, length, base) -> bool:
        if status != 200 or not base or base.get("status") != 200:
            return False
        bl, ln = base.get("length"), length
        if bl is None or ln is None:
            return False
        if bl == 0:
            return ln == 0
        return abs(ln - bl) / max(bl, 1) < 0.05  # near-identical to a bogus path

    @staticmethod
    def _classify(req: Dict, status, soft) -> Optional[bool]:
        if status is None:
            return None
        if status in (404, 410):
            return False
        if status == 200 and soft:
            return False
        ind = req.setdefault("suspicious_indicators", [])
        if status in (401, 403):
            ind.append("auth_protected_live")   # real, gated endpoint — prime target
            return True
        if status == 405:
            ind.append("method_real_405")        # path exists, wrong verb
            return True
        if 200 <= status < 400:
            return True
        if status == 429 or 500 <= status < 600:
            return True                          # exists; throttled or erroring
        return None

    async def validate(self, endpoints: List[Dict]) -> List[Dict]:
        conn = aiohttp.TCPConnector(limit=0, ssl=False)
        async with aiohttp.ClientSession(headers=self.headers, connector=conn) as s:
            results = await asyncio.gather(*[self._probe(s, e) for e in endpoints])
        if self.drop_dead:
            return [r for r in results if r.get("alive") is not False]
        return list(results)