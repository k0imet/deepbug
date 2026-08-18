"""
endpoint_engine.py — Extraction + smart validation for deepbug's JS analyzer.
=============================================================================
Drop-in upgrade focused on:
  1. High-recall endpoint EXTRACTION from JS (LinkFinder-grade regex set +
     method inference from fetch/axios/XHR/$.ajax call sites).
  2. Coverage FEEDERS: source-map unpacking + webpack lazy-chunk enumeration,
     so extraction sees code that isn't in the main bundle.
  3. Smart VALIDATION: per-host soft-404 baselining, method enumeration via
     OPTIONS + Allow/ACAM headers, and a keep/drop classifier that removes
     boring dead 404s while KEEPING interesting ones (401/403/405/5xx/redirect
     -to-auth, dangerous methods enabled, juicy path keywords).

Design notes
------------
* SAFETY: validation probes with GET / HEAD / OPTIONS only. It NEVER fires
  state-changing verbs (POST/PUT/PATCH/DELETE) at a live target — the intended
  method from the JS is *reported*, not *replayed*. A recon tool must not mutate
  the target.
* Output dicts match the JSAnalyzer schema so they slot into the existing
  _flatten_api_request / DataFrame conversion with no changes.
* No dependency on the private deepbug modules, so it runs standalone/testable.
"""

from __future__ import annotations

from app.utils.user_agents import PROGRAM_UA_TAG
import re
import json
import base64
import random
import string
import asyncio
import hashlib
from typing import List, Dict, Any, Optional, Set, Tuple
from app.utils.url_utils import urljoin, urlparse

import aiohttp


# =====================================================================
# EXTRACTION
# =====================================================================

# Extensions/mime-ish fragments we do NOT want to treat as endpoints.
_JUNK_EXT = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3",
    ".map",  # source maps handled separately, not as API endpoints
)

# Words that look like paths but are almost always noise.
_JUNK_EXACT = {
    "/", "//", "text/html", "text/plain", "application/json",
    "application/x-www-form-urlencoded", "multipart/form-data",
    "image/png", "image/jpeg", "image/svg+xml", "*/*",
}

# LinkFinder-style master regex: quoted strings that look like paths/URLs.
# Captures absolute URLs, root-relative (/x), relative (../x, ./x) and bare
# api-ish paths (api/v1/users). Deliberately permissive; filtered afterwards.
_LINK_REGEX = re.compile(
    r"""(?:"|'|`)
        (
            (?:https?:)?//[^"'`\s><)]{3,}          # protocol-relative or absolute URL
          | /[a-zA-Z0-9_?&=/\-#.%]{1,}             # root-relative path
          | (?:\.\./|\./)[a-zA-Z0-9_?&=/\-#.%]{1,} # relative path
          | [a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_?&=/\-#.%]{1,}  # bare a/b/c path
        )
        (?:"|'|`)
    """,
    re.VERBOSE,
)

# template literals with ${...} interpolation - the minified-Angular/fetch
# form: `${hostServer}/rest/products/search?q=${e}`. Interpolation is stripped,
# keeping the canonical path + query string for later validation/probing.
_TEMPLATE_LINK = re.compile(r"`([^`]{1,160})`")
_INTERPOLATION = re.compile(r"\$\{[^}]*\}")


def _clean_template_literal(s: str) -> str:
    """Strip ${...} interpolations; collapse a removed host prefix into /."""
    out = _INTERPOLATION.sub("", s).strip()
    if out.startswith("//"):
        return "/" + out[2:]
    return out


def _iter_template_links(js: str):
    """Yield the content of every backtick literal that contains ${...}.

    Tries EVERY backtick as a literal opener (not just finditer's greedy
    pairing): minified code like `a`;code(`b`) has unrelated literals whose
    closing/opening backticks sit next to code, and a greedy pair match would
    consume the real opener of the second literal.
    """
    ticks = [m.start() for m in re.finditer(r"`", js)]
    for i in range(len(ticks) - 1):
        content = js[ticks[i] + 1:ticks[i + 1]]
        if not content or len(content) > 160:
            continue
        if "${" in content:
            yield content

# fetch("url", {...method...}) / fetch(`url`, ...)
_FETCH_REGEX = re.compile(
    r"""fetch\s*\(\s*(?:"|'|`)([^"'`]+)(?:"|'|`)\s*
        (?:,\s*(\{[^;]{0,400}?\}))?          # optional options object (bounded)
    """,
    re.VERBOSE | re.DOTALL,
)

# axios.get("url"...) / axios.post(...) / axios({url, method})
_AXIOS_VERB_REGEX = re.compile(
    r"""axios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*
        (?:"|'|`)([^"'`]+)(?:"|'|`)""",
    re.VERBOSE | re.IGNORECASE,
)
# capture the whole config object so we can read both url and method from it
_AXIOS_CFG_REGEX = re.compile(
    r"""axios\s*\(\s*(\{[^}]{0,400}?\})""",
    re.VERBOSE | re.IGNORECASE | re.DOTALL,
)

# jQuery $.ajax({ url:"", type/method:"" }) and $.get/$.post
_JQ_AJAX_REGEX = re.compile(
    r"""\$\s*\.\s*ajax\s*\(\s*\{([^}]{0,500}?)\}""",
    re.VERBOSE | re.DOTALL,
)
_JQ_SHORTHAND_REGEX = re.compile(
    r"""\$\s*\.\s*(get|post)\s*\(\s*(?:"|'|`)([^"'`]+)(?:"|'|`)""",
    re.IGNORECASE,
)

# XHR: xhr.open('POST', '/url')
_XHR_REGEX = re.compile(
    r"""\.\s*open\s*\(\s*(?:"|'|`)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)(?:"|'|`)\s*,\s*
        (?:"|'|`)([^"'`]+)(?:"|'|`)""",
    re.VERBOSE | re.IGNORECASE,
)

_METHOD_IN_OBJ = re.compile(r"""method\s*:\s*(?:"|'|`)([A-Za-z]+)(?:"|'|`)""", re.IGNORECASE)
_TYPE_IN_OBJ = re.compile(r"""(?:type|method)\s*:\s*(?:"|'|`)([A-Za-z]+)(?:"|'|`)""", re.IGNORECASE)
_URL_IN_OBJ = re.compile(r"""url\s*:\s*(?:"|'|`)([^"'`]+)(?:"|'|`)""", re.IGNORECASE)
_AUTH_HINT = re.compile(r"""authorization|bearer|x-api-key|x-auth|cookie""", re.IGNORECASE)

# Path keywords that raise interest.
_JUICY = (
    "admin", "internal", "debug", "graphql", "actuator", "swagger",
    "api-docs", "openapi", "token", "secret", "key", "password", "passwd",
    "config", "backup", "export", "import", "upload", "download", "delete",
    "user", "users", "account", "role", "perm", "priv", "sudo", "root",
    "console", "dashboard", "metrics", "health", "env", ".git", "wp-json",
    "v1", "v2", "v3", "webhook", "callback", "redirect", "proxy", "fetch",
)


def _looks_like_endpoint(candidate: str) -> bool:
    c = candidate.strip()
    if not c or c in _JUNK_EXACT:
        return False
    low = c.lower()
    # strip query/fragment when checking extension
    path_only = low.split("?", 1)[0].split("#", 1)[0]
    if path_only.endswith(_JUNK_EXT):
        return False
    # pure version strings like 1.2.3
    if re.fullmatch(r"[\d.]+", c):
        return False
    # a bare word with no slash, no dot-api hint → skip (too noisy)
    if "/" not in c and "." not in c:
        return False
    # data URIs, mailto, tel
    if low.startswith(("data:", "mailto:", "tel:", "blob:", "javascript:")):
        return False
    return True


class EndpointExtractor:
    """Regex-based endpoint extraction with method inference."""

    def extract(self, js: str, source_url: str = "") -> List[Dict[str, Any]]:
        found: Dict[Tuple[str, str], Dict[str, Any]] = {}

        def add(url: str, method: str, how: str, auth: bool = False, conf: str = "medium"):
            url = url.strip()
            if not _looks_like_endpoint(url):
                return
            key = (method.upper(), url)
            existing = found.get(key)
            if existing is None:
                found[key] = {
                    "url": url,
                    "method": method.upper(),
                    "auth": "hinted" if auth else "",
                    "extraction_method": how,
                    "confidence": conf,
                    "source_url": source_url,
                }
            else:
                # upgrade confidence / auth if a stronger signal appears
                if auth and not existing["auth"]:
                    existing["auth"] = "hinted"
                if conf == "high":
                    existing["confidence"] = "high"

        # --- call-site extractors (give us method + high confidence) ---
        for m in _FETCH_REGEX.finditer(js):
            url = m.group(1)
            opts = m.group(2) or ""
            method = "GET"
            mm = _METHOD_IN_OBJ.search(opts)
            if mm:
                method = mm.group(1)
            add(url, method, "fetch", auth=bool(_AUTH_HINT.search(opts)), conf="high")

        for m in _AXIOS_VERB_REGEX.finditer(js):
            add(m.group(2), m.group(1), "axios", conf="high")
        for m in _AXIOS_CFG_REGEX.finditer(js):
            obj = m.group(1)
            um = _URL_IN_OBJ.search(obj)
            if not um:
                continue
            mm = _METHOD_IN_OBJ.search(obj)
            add(um.group(1), mm.group(1) if mm else "GET", "axios",
                auth=bool(_AUTH_HINT.search(obj)), conf="high")

        for m in _JQ_AJAX_REGEX.finditer(js):
            body = m.group(1)
            um = _URL_IN_OBJ.search(body)
            if not um:
                continue
            tm = _TYPE_IN_OBJ.search(body)
            method = tm.group(1) if tm else "GET"
            add(um.group(1), method, "jquery.ajax",
                auth=bool(_AUTH_HINT.search(body)), conf="high")
        for m in _JQ_SHORTHAND_REGEX.finditer(js):
            add(m.group(2), m.group(1), "jquery", conf="high")

        for m in _XHR_REGEX.finditer(js):
            add(m.group(2), m.group(1), "xhr", conf="high")

        # --- generic string harvest (high recall, lower confidence) ---
        for m in _LINK_REGEX.finditer(js):
            add(m.group(1), "GET", "string", conf="low")

        # --- template literals with ${...} interpolation ---
        for raw in _iter_template_links(js):
            cleaned = _clean_template_literal(raw)
            if cleaned.startswith("/"):
                add(cleaned, "GET", "template", conf="medium")

        return list(found.values())


# =====================================================================
# COVERAGE FEEDERS: source maps + webpack chunks
# =====================================================================

_SOURCEMAP_URL = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")

# webpack chunk filename map: e.g. {"123":"abcd","456":"ef01"} used with a
# template like "static/js/" + e + "." + <map>[e] + ".chunk.js"
_WP_CHUNK_MAP = re.compile(r"\{(?:\s*\"?\d+\"?\s*:\s*\"[0-9a-f]{6,}\"\s*,?){2,}\}")
_WP_TEMPLATE = re.compile(
    r"""["']([\w./\-]*?)["']\s*\+\s*\w+\s*\+\s*["']\.["']\s*\+\s*
        \{?[^}]*\}?\s*\[?\w*\]?\s*\+\s*["'](\.[\w.]*?(?:chunk\.)?js)["']""",
    re.VERBOSE,
)
# simpler: capture publicPath assignment
_WP_PUBLICPATH = re.compile(r"""\.p\s*=\s*["']([^"']+)["']""")


def extract_sourcemap_url(js: str, js_url: str) -> Optional[str]:
    m = _SOURCEMAP_URL.search(js)
    if not m:
        return None
    ref = m.group(1).strip()
    if ref.startswith("data:"):
        return ref  # inline map; unpack handles the data URI
    return urljoin(js_url, ref)


def unpack_sourcemap(map_text_or_uri: str) -> Tuple[List[str], List[Tuple[str, str]]]:
    """
    Returns (source_paths, [(path, content), ...]) from a source map.
    Accepts a raw JSON string OR an inline data: URI.
    - source_paths reveal internal file/dir structure (often leaks routes).
    - contents are original source you can re-run through EndpointExtractor.
    """
    text = map_text_or_uri
    if text.startswith("data:"):
        # data:application/json;base64,<...>  or  data:...,<urlencoded>
        try:
            header, payload = text.split(",", 1)
            if "base64" in header:
                text = base64.b64decode(payload).decode("utf-8", "ignore")
            else:
                from urllib.parse import unquote
                text = unquote(payload)
        except Exception:
            return [], []
    try:
        data = json.loads(text)
    except Exception:
        return [], []

    sources = data.get("sources", []) or []
    contents = data.get("sourcesContent", []) or []
    paths = [str(s) for s in sources]
    pairs: List[Tuple[str, str]] = []
    for i, src in enumerate(sources):
        if i < len(contents) and contents[i]:
            pairs.append((str(src), contents[i]))
    return paths, pairs


def enumerate_webpack_chunks(js: str, base_url: str) -> List[str]:
    """
    Best-effort enumeration of lazy-loaded webpack chunk URLs from the runtime.
    Returns absolute candidate URLs to fetch and analyze.
    """
    chunk_ids: Dict[str, str] = {}
    for mm in _WP_CHUNK_MAP.finditer(js):
        blob = mm.group(0)
        for k, v in re.findall(r'"?(\d+)"?\s*:\s*"([0-9a-f]{6,})"', blob):
            chunk_ids[k] = v
    if not chunk_ids:
        return []

    # Determine filename template. Common CRA/webpack5 form:
    #   "static/js/" + chunkId + "." + {..}[chunkId] + ".chunk.js"
    prefix, suffix = "static/js/", ".chunk.js"
    tm = _WP_TEMPLATE.search(js)
    if tm:
        prefix = tm.group(1) or prefix
        suffix = tm.group(2) or suffix

    pp = _WP_PUBLICPATH.search(js)
    public_path = pp.group(1) if pp else ""

    urls = []
    for cid, chash in chunk_ids.items():
        rel = f"{prefix}{cid}.{chash}{suffix}"
        if public_path and not public_path.startswith(("http", "//")):
            rel = urljoin(public_path if public_path.endswith("/") else public_path + "/", rel)
        elif public_path:
            rel = public_path.rstrip("/") + "/" + rel.lstrip("/")
        urls.append(urljoin(base_url, rel))
    return sorted(set(urls))


# =====================================================================
# SMART VALIDATION
# =====================================================================

# Statuses that are INTERESTING even though the endpoint isn't a plain 200.
_INTERESTING_STATUS = {401, 403, 405, 407, 429, 500, 501, 502, 503}
_DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


def _rand_path() -> str:
    return "/" + "".join(random.choices(string.ascii_lowercase + string.digits, k=24))


def _body_fingerprint(text: str) -> str:
    """
    Normalize a response body into a stable fingerprint so two soft-404s
    (which differ only by the requested path) hash identically.
    """
    t = text.lower()
    t = re.sub(r"[0-9a-f]{8,}", "", t)      # ids / hashes
    t = re.sub(r"\d+", "", t)                # numbers (incl. echoed path chars)
    t = re.sub(r"[a-z0-9]{16,}", "", t)      # long tokens
    t = re.sub(r"\s+", " ", t).strip()
    # bucket by length so minor variation doesn't break the match
    bucket = len(t) // 64
    return hashlib.sha1(f"{bucket}:{t[:400]}".encode("utf-8", "ignore")).hexdigest()


class SmartEndpointValidator:
    """
    Async validator that classifies endpoints by real HTTP behaviour.

    Per host it first learns the soft-404 signature (does a random path return
    200?), then probes each endpoint with HEAD/GET/OPTIONS, enumerates allowed
    methods, and marks each result alive/interesting/dead so the caller can
    drop boring 404s and keep the rest.
    """

    def __init__(
        self,
        allowed_hosts: Optional[Set[str]] = None,
        global_concurrency: int = 40,
        per_host_concurrency: int = 8,
        timeout: int = 8,
        verify_ssl: bool = False,
        drop_dead: bool = True,
        user_agent: str = "Mozilla/5.0 (compatible; deepbug/3.1)" + PROGRAM_UA_TAG,
        budget_seconds: int = 240,
        progress_callback=None,
    ):
        self.budget_seconds = budget_seconds
        self.progress_callback = progress_callback
        self.allowed_hosts = allowed_hosts
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=timeout / 2)
        self.verify_ssl = verify_ssl
        self.drop_dead = drop_dead
        self.headers = {"User-Agent": user_agent}
        self._global = asyncio.Semaphore(global_concurrency)
        self._per_host_limit = per_host_concurrency
        self._host_sems: Dict[str, asyncio.Semaphore] = {}
        self._soft404: Dict[str, Optional[str]] = {}   # host -> fingerprint or None
        self._soft404_futs: Dict[str, "asyncio.Future"] = {}  # host -> in-flight learn future
        self._baseline_lock = asyncio.Lock()

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        sem = self._host_sems.get(host)
        if sem is None:
            sem = asyncio.Semaphore(self._per_host_limit)
            self._host_sems[host] = sem
        return sem

    def _in_scope(self, host: str) -> bool:
        if not self.allowed_hosts:
            return True
        host = host.lower()
        return any(host == h or host.endswith("." + h) for h in self.allowed_hosts)

    async def _request(self, session, method, url) -> Optional[aiohttp.ClientResponse]:
        try:
            return await session.request(
                method, url, allow_redirects=False,
                ssl=self.verify_ssl, timeout=self.timeout,
            )
        except Exception:
            return None

    async def _learn_soft404(self, session, host_url: str, host: str):
        # Per-host memoized future: only ONE coroutine probes per host; everyone
        # else awaits the same result. (The old probe-outside-lock pattern made
        # every endpoint fire 2 extra probes - a thundering herd.)
        async with self._baseline_lock:
            fut = self._soft404_futs.get(host)
            if fut is None:
                fut = asyncio.get_event_loop().create_future()
                self._soft404_futs[host] = fut
                owner = True
            else:
                owner = False

        if not owner:
            await fut
            return

        try:
            fps = []
            for _ in range(2):
                probe = urljoin(host_url, _rand_path())
                resp = await self._request(session, "GET", probe)
                if resp is None:
                    continue
                status = resp.status
                body = await resp.text(errors="ignore")
                resp.release()
                if status == 200:
                    fps.append(_body_fingerprint(body))
            # Soft-404 confirmed only if BOTH random paths 200'd with same shape.
            sig = fps[0] if len(fps) == 2 and fps[0] == fps[1] else None
            async with self._baseline_lock:
                self._soft404[host] = sig
            fut.set_result(sig)
        except Exception as e:
            async with self._baseline_lock:
                self._soft404[host] = None
            if not fut.done():
                fut.set_result(None)
            logger.debug(f"soft404 learn failed for {host}: {e}")

    def _deadline_exceeded(self) -> bool:
        import time as _time
        return getattr(self, "_deadline", None) is not None and _time.monotonic() > self._deadline

    async def _validate_one(self, session, ep: Dict[str, Any]) -> Dict[str, Any]:
        url = ep["url"]
        parsed = urlparse(url)
        host = parsed.hostname or ""

        # Hard time budget: stop probing, keep the endpoint marked unvalidated
        if self._deadline_exceeded():
            ep["live_status"] = "unvalidated_budget"
            ep.setdefault("alive", None)
            ep.setdefault("allow_methods", "")
            ep.setdefault("soft_404", False)
            return ep

        ep.setdefault("alive", None)
        ep.setdefault("live_status", "")
        ep.setdefault("allow_methods", "")
        ep.setdefault("soft_404", False)
        indicators = list(ep.get("suspicious_indicators") or [])

        if not host or not self._in_scope(host):
            ep["live_status"] = "out_of_scope"
            ep["alive"] = None
            ep["_keep"] = False
            return ep

        host_url = f"{parsed.scheme}://{host}"
        async with self._global, self._host_sem(host):
            await self._learn_soft404(session, host_url, host)
            soft_sig = self._soft404.get(host)

            # GET + OPTIONS fire concurrently (OPTIONS enumerates methods,
            # never fires state-changing verbs). HEAD fallback if GET fails.
            get_coro = self._request(session, "GET", url)
            opt_coro = self._request(session, "OPTIONS", url)
            resp, opt = await asyncio.gather(get_coro, opt_coro)

            used = "GET"
            if resp is None:
                resp = await self._request(session, "HEAD", url)
                used = "HEAD"
            if resp is None:
                if opt is not None:
                    opt.release()
                ep["alive"] = False
                ep["live_status"] = "dead"
                ep["_keep"] = not self.drop_dead
                return ep

            status = resp.status
            body = await resp.text(errors="ignore") if used == "GET" else ""
            location = resp.headers.get("Location", "")
            resp.release()

            allow = ""
            if opt is not None:
                allow = (opt.headers.get("Allow")
                         or opt.headers.get("Access-Control-Allow-Methods") or "")
                opt.release()

        ep["live_status"] = str(status)
        ep["allow_methods"] = allow.strip()

        # --- soft-404 / dead classification ---
        is_soft404 = False
        if status == 200 and soft_sig is not None:
            if _body_fingerprint(body) == soft_sig:
                is_soft404 = True
        ep["soft_404"] = is_soft404

        keep = True
        severity = ep.get("severity", "info")

        if status == 404 or is_soft404:
            ep["alive"] = False
            keep = not self.drop_dead
            if is_soft404:
                indicators.append("soft_404")
        elif status == 200:
            ep["alive"] = True
            severity = _bump(severity, "low")
        elif status in (301, 302, 303, 307, 308):
            ep["alive"] = True
            loc = location.lower()
            if any(w in loc for w in ("login", "signin", "auth", "sso")):
                indicators.append("redirect_to_auth")   # gated, worth authz testing
                severity = _bump(severity, "medium")
            else:
                indicators.append(f"redirect->{location[:80]}")
                if location.startswith(("http://", "https://")) and host not in location:
                    indicators.append("possible_open_redirect")
                    severity = _bump(severity, "medium")
        elif status in _INTERESTING_STATUS:
            ep["alive"] = True
            if status in (401, 403):
                indicators.append("auth_gated")          # IDOR/authz candidate
                severity = _bump(severity, "medium")
            elif status == 405:
                indicators.append("method_not_allowed")  # endpoint exists
                severity = _bump(severity, "low")
            elif status == 429:
                indicators.append("rate_limited")
            elif 500 <= status <= 503:
                indicators.append(f"server_error_{status}")  # injection/DoS smell
                severity = _bump(severity, "medium")
        else:
            ep["alive"] = True

        # --- method-based escalation ---
        allow_upper = {m.strip().upper() for m in allow.split(",") if m.strip()}
        dangerous = allow_upper & _DANGEROUS_METHODS
        if dangerous:
            indicators.append("dangerous_methods:" + ",".join(sorted(dangerous)))
            severity = _bump(severity, "high")

        # --- path-keyword escalation ---
        low_url = url.lower()
        hits = [w for w in _JUICY if w in low_url]
        if hits:
            indicators.append("juicy:" + ",".join(hits[:5]))
            if any(h in ("admin", "internal", "graphql", "actuator", "token",
                         "secret", "debug", ".git", "console") for h in hits):
                severity = _bump(severity, "high")
            else:
                severity = _bump(severity, "medium")

        ep["severity"] = severity
        ep["suspicious_indicators"] = indicators
        ep["_keep"] = keep
        return ep

    async def validate(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        import time as _time
        self._deadline = _time.monotonic() + self.budget_seconds
        deadline = self._deadline
        kept: List[Dict[str, Any]] = []
        total = len(endpoints)
        batch = 60

        conn = aiohttp.TCPConnector(ssl=self.verify_ssl, limit=0)
        async with aiohttp.ClientSession(headers=self.headers, connector=conn) as session:
            i = 0
            while i < total:
                # Time budget: keep whatever is validated so far, mark the rest
                if _time.monotonic() > deadline:
                    logger.warning(f"Validation budget exhausted after {i}/{total} endpoints - "
                                   f"remaining marked unvalidated")
                    for ep in endpoints[i:]:
                        ep = dict(ep)
                        ep["live_status"] = "unvalidated_budget"
                        ep.setdefault("alive", None)
                        kept.append(ep)
                    break
                chunk = endpoints[i:i + batch]
                results = await asyncio.gather(
                    *[self._validate_one(session, dict(ep)) for ep in chunk]
                )
                for r in results:
                    if r.pop("_keep", True):
                        kept.append(r)
                i += batch
                if self.progress_callback:
                    self.progress_callback(min(i, total) / total,
                                           f"Validating endpoints... {min(i, total)}/{total}")
        # rank interesting first
        kept.sort(key=lambda r: (_sev_rank(r.get("severity", "info")),
                                 len(r.get("suspicious_indicators") or [])),
                  reverse=True)
        return kept


# --- severity helpers ---
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _sev_rank(s: str) -> int:
    return _SEV_ORDER.get((s or "info").lower(), 0)


def _bump(current: str, floor: str) -> str:
    return current if _sev_rank(current) >= _sev_rank(floor) else floor


# =====================================================================
# SWAGGER / OPENAPI SUPPORT
# =====================================================================

# Spec URLs referenced inside JS (swagger-ui-init, config, literals).
_SWAGGER_SPEC_PATTERNS = [
    re.compile(r"""["']([^"']*(?:swagger|openapi)[^"']*\.(?:json|yaml|yml))["']""", re.I),
    re.compile(r"""["']([^"']*/v[23]/api-docs[^"']*)["']""", re.I),
    re.compile(r"""["']([^"']*/api-docs(?:/[^"']*)?)["']""", re.I),
    re.compile(r"""SwaggerUIBundle\s*\(\s*\{[^}]*?url\s*:\s*["']([^"']+)["']""", re.I | re.S),
    re.compile(r"""(?:spec|specUrl|swaggerUrl|configUrl)\s*:\s*["']([^"']+)["']""", re.I),
]

# Markers that an API-doc UI is present (worth probing even without a spec URL).
_API_DOC_UI_MARKERS = re.compile(
    r"SwaggerUIBundle|swagger-ui|redoc|RapiDoc|rapidoc|stoplight|api-docs", re.I
)

# Well-known spec locations to probe per host even if never referenced in JS.
SWAGGER_WELLKNOWN = [
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/swagger-ui/index.html", "/swagger-ui.html", "/api/openapi.json",
    "/.well-known/openapi.json", "/docs/openapi.json",
]


def find_swagger_specs(js: str, js_url: str) -> Tuple[List[str], bool]:
    """
    Returns (candidate_spec_urls, api_doc_ui_present).
    Absolutizes spec URLs against js_url.
    """
    specs: Set[str] = set()
    for pat in _SWAGGER_SPEC_PATTERNS:
        for m in pat.finditer(js):
            ref = m.group(1).strip()
            if ref and not ref.startswith(("data:", "#")):
                specs.add(urljoin(js_url, ref))
    ui_present = bool(_API_DOC_UI_MARKERS.search(js))
    return sorted(specs), ui_present


def swagger_probe_candidates(base_url: str) -> List[Dict[str, Any]]:
    """Endpoint dicts for the well-known spec paths, so the validator can probe them."""
    out = []
    for path in SWAGGER_WELLKNOWN:
        out.append(normalize_endpoint({
            "url": urljoin(base_url, path),
            "method": "GET",
            "extraction_method": "swagger-probe",
            "confidence": "low",
            "suspicious_indicators": ["swagger_wellknown_probe"],
            "source_url": base_url,
        }))
    return out


def _resolve_ref(ref: str, spec: Dict) -> Dict:
    """Resolve a local $ref ('#/components/schemas/X' or '#/definitions/X'). Shallow."""
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return {}
    node: Any = spec
    for part in ref[2:].split("/"):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return {}
    return node if isinstance(node, dict) else {}


def _schema_props(schema: Dict, spec: Dict) -> Dict[str, str]:
    """Top-level property names -> type, resolving one level of $ref."""
    if not isinstance(schema, dict):
        return {}
    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], spec)
    props = schema.get("properties")
    if not isinstance(props, dict):
        return {}
    out = {}
    for name, meta in props.items():
        if isinstance(meta, dict):
            out[name] = meta.get("type") or ("object" if "$ref" in meta else "unknown")
    return out


def _openapi_base(spec: Dict, spec_url: str) -> str:
    # OpenAPI 3.x
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        u = servers[0].get("url", "")
        if u:
            return urljoin(spec_url, u) if u.startswith("/") or not u.startswith("http") else u
    # Swagger 2.0
    host = spec.get("host")
    basepath = spec.get("basePath", "") or ""
    if host:
        scheme = (spec.get("schemes") or ["https"])[0]
        return f"{scheme}://{host}{basepath}"
    if basepath:
        return urljoin(spec_url, basepath)
    # fall back to the spec's own origin
    p = urlparse(spec_url)
    return f"{p.scheme}://{p.netloc}" if p.netloc else ""


def parse_openapi_spec(spec: Any, spec_url: str = "") -> List[Dict[str, Any]]:
    """
    Turn an OpenAPI 3.x OR Swagger 2.0 spec (already-parsed dict) into endpoint dicts.
    This is the high-value payoff: a full, authoritative path+method+param inventory.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _openapi_base(spec, spec_url)
    global_sec = bool(spec.get("security"))
    verbs = ("get", "post", "put", "patch", "delete", "head", "options")
    out: List[Dict[str, Any]] = []

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared_params = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in verbs or not isinstance(op, dict):
                continue
            full_url = _join_url(base, path)
            qp: Dict[str, str] = {}
            body_schema: Dict[str, str] = {}
            params = shared_params + (op.get("parameters", []) if isinstance(op.get("parameters"), list) else [])
            for p in params:
                if not isinstance(p, dict):
                    continue
                loc = p.get("in")
                if loc == "query":
                    qp[p.get("name", "")] = p.get("type") or (p.get("schema", {}) or {}).get("type", "") or "string"
                elif loc == "body":
                    body_schema.update(_schema_props(p.get("schema", {}), spec))
            rb = op.get("requestBody")
            if isinstance(rb, dict):
                for _ctype, cval in (rb.get("content") or {}).items():
                    if isinstance(cval, dict):
                        body_schema.update(_schema_props(cval.get("schema", {}), spec))

            sec = op.get("security", None)
            authed = bool(sec) or (sec is None and global_sec)

            ind = ["from_openapi_spec"]
            for name in list(qp.keys()) + list(body_schema.keys()):
                if any(s in name.lower() for s in ("role", "admin", "is_staff", "permission", "superuser")):
                    ind.append(f"sensitive_field:{name}")
            sev = "info"
            low = (full_url + " " + " ".join(qp) + " " + " ".join(body_schema)).lower()
            if any(j in low for j in _JUICY):
                sev = "medium"
            if method.upper() in _DANGEROUS_METHODS:
                sev = _bump(sev, "medium")

            out.append(normalize_endpoint({
                "url": full_url,
                "method": method.upper(),
                "auth": "spec-security" if authed else None,
                "query_params": qp,
                "body_schema": body_schema,
                "severity": sev,
                "confidence": "high",           # authoritative: the spec declares it exists
                "extraction_method": "openapi",
                "suspicious_indicators": ind,
                "source_url": spec_url,
            }))
    return out


def _join_url(base: str, path: str) -> str:
    if not base:
        return path
    if path.startswith("http"):
        return path
    return base.rstrip("/") + "/" + path.lstrip("/")


# =====================================================================
# CONFLICT-FREE MERGE (JSApiExplorer output + EndpointExtractor + specs)
# =====================================================================

_UNIFIED_DEFAULTS = {
    "source_url": "", "url": "", "method": "GET", "headers": {}, "body": None,
    "body_schema": {}, "auth": None, "cookies": [], "query_params": {},
    "graphql_operation": None, "graphql_type": None, "websocket": False,
    "cors_with_credentials": False, "severity": "info", "suspicious_indicators": [],
    "confidence": "medium", "extraction_method": "", "alive": None,
    "live_status": "", "allow_methods": "", "soft_404": False,
}

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
# extraction-method precedence when two records collide (higher wins the label)
_EXTRACT_RANK = {
    "": 0, "string": 1, "regex": 2, "swagger-probe": 2,
    "fetch": 3, "axios": 3, "jquery": 3, "jquery.ajax": 3, "xhr": 3,
    "sourcemap": 4, "ast": 5, "openapi": 6, "ast_semantic": 7,
}


def normalize_endpoint(d: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce any endpoint dict (either extractor / spec) into the unified schema."""
    out = {}
    for k, default in _UNIFIED_DEFAULTS.items():
        v = d.get(k, default)
        out[k] = list(v) if isinstance(default, list) else (dict(v) if isinstance(default, dict) else v)
    # keep any extra keys we don't model (forward-compatible)
    for k, v in d.items():
        if k not in out:
            out[k] = v
    return out


def _key_of(ep: Dict[str, Any], source_url: str = "") -> Tuple[str, str]:
    """Dedup key: (METHOD, scheme://host/path) — path-level, query merged separately."""
    url = ep.get("url", "") or ""
    if url and not url.startswith("http") and (ep.get("source_url") or source_url):
        url = urljoin(ep.get("source_url") or source_url, url)
    p = urlparse(url)
    path = (p.path or "").rstrip("/") or "/"
    host = p.netloc.lower()
    norm = f"{p.scheme}://{host}{path}" if host else path
    return (ep.get("method", "GET").upper(), norm)


def _merge_pair(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge b into a, keeping the strongest signal from each field."""
    # confidence: keep highest
    if _CONF_RANK.get(b.get("confidence"), 1) > _CONF_RANK.get(a.get("confidence"), 1):
        a["confidence"] = b["confidence"]
    # extraction_method: keep highest-precedence label
    if _EXTRACT_RANK.get(b.get("extraction_method"), 0) > _EXTRACT_RANK.get(a.get("extraction_method"), 0):
        a["extraction_method"] = b["extraction_method"]
    # severity: keep max
    if _sev_rank(b.get("severity", "info")) > _sev_rank(a.get("severity", "info")):
        a["severity"] = b["severity"]
    # prefer a real absolute URL over a relative one
    if (not a["url"].startswith("http")) and b.get("url", "").startswith("http"):
        a["url"] = b["url"]
    # auth / graphql / websocket / cors: prefer truthy
    for f in ("auth", "graphql_type", "graphql_operation"):
        if not a.get(f) and b.get(f):
            a[f] = b[f]
    for f in ("websocket", "cors_with_credentials"):
        a[f] = a.get(f) or b.get(f)
    # dict fields: fill/union
    for f in ("headers", "query_params", "body_schema", "body", "params", "path_params"):
        merged = dict(b.get(f) or {}) if isinstance(b.get(f), dict) else (b.get(f) or [])
        av = a.get(f)
        if isinstance(merged, dict):
            base = dict(b.get(f) or {})
            base.update(a.get(f) or {})   # a wins on conflicts
            a[f] = base
        elif isinstance(merged, list):
            seen2 = {json.dumps(x, sort_keys=True) for x in (av or [])}
            for x in (merged or []):
                if isinstance(x, dict) and json.dumps(x, sort_keys=True) not in seen2:
                    a.setdefault(f, []).append(x)
                    seen2.add(json.dumps(x, sort_keys=True))
    # indicators: ordered union
    seen = set(a.get("suspicious_indicators") or [])
    for ind in (b.get("suspicious_indicators") or []):
        if ind not in seen:
            a.setdefault("suspicious_indicators", []).append(ind)
            seen.add(ind)
    # body: prefer non-null
    if a.get("body") is None and b.get("body") is not None:
        a["body"] = b["body"]
    # v3.4 semantic enrichment: propagate extras from either candidate
    for f in ("url_template", "canonical_path", "content_type", "auth_type",
              "auth_source", "objects", "security_signals", "interest_score",
              "line", "function", "file_upload", "raw"):
        av = a.get(f)
        bv = b.get(f)
        if not av and bv:
            a[f] = bv
        elif isinstance(av, list) and bv and any(bx not in av for bx in (bv if isinstance(bv, list) else [bv])):
            for bx in (bv if isinstance(bv, list) else [bv]):
                if bx not in av:
                    av.append(bx)
    # auth nested dict
    aa = a.get("auth")
    ba = b.get("auth")
    if isinstance(aa, dict) and isinstance(ba, dict):
        for k, v in ba.items():
            if not aa.get(k) and v:
                aa[k] = v
    return a


def merge_endpoints(*sources: List[Dict[str, Any]], source_url: str = "") -> List[Dict[str, Any]]:
    """
    Merge any number of endpoint lists (JSApiExplorer dicts, EndpointExtractor dicts,
    OpenAPI-derived dicts) into one deduplicated, uniformly-shaped list.
    Records sharing (method, host+path) are merged, keeping the strongest signal.
    Order-independent and idempotent.
    """
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for lst in sources:
        for raw in (lst or []):
            ep = normalize_endpoint(raw)
            key = _key_of(ep, source_url)
            if key in merged:
                merged[key] = _merge_pair(merged[key], ep)
            else:
                merged[key] = ep
    return list(merged.values())