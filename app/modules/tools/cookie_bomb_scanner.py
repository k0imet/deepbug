# modules/tools/cookie_bomb_scanner.py
# Analytics cookie-bomb detector — the "gclid=AAAA*4000" self-DoS.
#
#  PASSIVE (always safe):
#   * fetches each target's HTML + inline/external JS (scope-gated, no auth)
#   * detects analytics providers by script src / inline markers
#   * finds cookie sinks: document.cookie assignments fed by location.search
#     / URLSearchParams — the exact sink Kazmi's hunt used.
#
#  ACTIVE (manual lab only, one request at a time):
#   * probe() builds  ?<param>=<payload>  and checks whether Set-Cookie
#     reflects the oversized value without truncation. A second request
#     replays the cookie and checks for 400/413/414/431.
#
#  All probes are scope + private-IP gated. No subdomain cookie tossing.
#  Finding shape: {url, provider, param, sink, confidence, evidence}
#  Probe shape:   {url, param, size, set_cookie, reflected, follow_status, verdict}

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any, Set, Tuple
from urllib.parse import urlsplit, urljoin, parse_qs
from ipaddress import ip_address, ip_network, IPv4Address
from html.parser import HTMLParser
from pathlib import Path

from app.utils.url_utils import urlparse as _urlparse, urljoin as _urljoin
from app.utils.logger import get_logger
try:
    from app.utils.user_agents import get_bug_bounty_headers
except ImportError:
    def get_bug_bounty_headers():
        return {}

# ------------------------------------------------------------------
# Analytics provider signatures (passive HTML/JS fingerprint)
# ------------------------------------------------------------------
ANALYTICS_SIGNATURES: Dict[str, List[str]] = {
    "google_analytics": [
        "googletagmanager.com/gtag/js",
        "googletagmanager.com/gtm.js",
        "google-analytics.com/analytics.js",
        "google-analytics.com/ga.js",
        "gtag(", "GoogleAnalyticsObject",
    ],
    "google_ads": [
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "gclid",
    ],
    "facebook_pixel": [
        "connect.facebook.net",
        "facebook.com/tr",
        "fbq(",
    ],
    "microsoft_clarity": [
        "clarity.ms",
        "bing.com/bat.js",
        "msclkid",
    ],
    "tiktok_pixel": [
        "tiktok.com/i18n/pixel",
        "ttq.",
    ],
}

# Tracking params Kazmi used — also the most common marketing params that
# sites blindly copy into cookies.
TRACKING_PARAMS: List[str] = [
    "gclid", "gbraid", "wbraid", "dclid",
    "fbclid", "msclkid",
    "utm_source", "utm_medium", "utm_campaign",
    "utm_term", "utm_content",
]

# Cookie sinks: JS that writes attacker-controlled query data into cookies.
# Kept intentionally narrow — we flag only when a cookie write is fed by a
# location.* / URLSearchParams read in the same file.
_COOKIE_WRITE_RE = re.compile(r'document\.cookie\s*=', re.I)
_QUERY_SOURCE_RE = re.compile(
    r'(?:location\.(?:search|href|hash)|URLSearchParams|get\(["\'](?:'
    + "|".join(re.escape(p) for p in TRACKING_PARAMS)
    + r')["\']\))',
    re.I,
)
_SET_COOKIE_PARAM_RE = re.compile(
    r'Set-Cookie[^;]{0,400}(?:gclid|fbclid|utm_|dclid|msclkid|wbraid|gbraid)',
    re.I,
)


def _detect_analytics(html: str, headers: Dict[str, str]) -> List[str]:
    blob = (html or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    blob_low = blob.lower()
    found: List[str] = []
    for provider, markers in ANALYTICS_SIGNATURES.items():
        for m in markers:
            if m.lower() in blob_low:
                found.append(provider)
                break
    return sorted(set(found))


def _find_cookie_sinks(js_content: str) -> List[Dict[str, str]]:
    if not js_content or "document.cookie" not in js_content:
        return []
    sinks: List[Dict[str, str]] = []
    # Heuristic: file contains BOTH a cookie write AND a query-param read.
    if _COOKIE_WRITE_RE.search(js_content) and _QUERY_SOURCE_RE.search(js_content):
        for m in _COOKIE_WRITE_RE.finditer(js_content):
            start = max(0, m.start() - 200)
            ctx = js_content[start:m.end() + 400].replace("\n", " ")[:600]
            # Confidence: does the window around the sink also contain a param read?
            window = js_content[max(0, m.start() - 800): m.end() + 800]
            has_source = bool(_QUERY_SOURCE_RE.search(window))
            sinks.append({
                "sink": "document.cookie",
                "confidence": "high" if has_source else "low",
                "context": ctx,
            })
            if len(sinks) >= 5:
                break
    return sinks


class _AssetParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts: List[str] = []
        self.inline: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = {str(k).lower(): (v or "") for k, v in attrs}
        if tag.lower() == "script" and a.get("src"):
            self.scripts.append(a["src"])

    def handle_data(self, data):
        if data and len(data.strip()) > 30:
            # capture inline JS blocks
            if "document.cookie" in data or "URLSearchParams" in data or "location.search" in data:
                self.inline.append(data)


class CookieBombScanner:
    """Passive analytics + cookie-sink detector with opt-in single-request probe."""

    def __init__(self, config: Dict):
        cfg = config.get("cookie_bomb", {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get("timeout", 12))
        self.max_urls = int(cfg.get("max_urls", 100))
        self.concurrency = int(cfg.get("concurrency", 10))
        self.default_payload_size = int(cfg.get("default_payload_size", 4000))
        self.scope_hosts: Optional[Set[str]] = None
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            **get_bug_bounty_headers(),
        }

    # ------------------------------------------------------------------
    # Scope / private-IP guards (mirrors JSAnalyzer)
    # ------------------------------------------------------------------
    def _host_in_scope(self, url: str) -> bool:
        if not self.scope_hosts:
            return True
        try:
            host = (_urlparse(url).hostname or "").lower()
        except Exception:
            return False
        if not host:
            return False
        return any(host == h or host.endswith("." + h) for h in self.scope_hosts)

    def _host_allowed(self, url: str) -> bool:
        try:
            host = (urlsplit(url).hostname or "").strip("[]")
        except Exception:
            return False
        if not host:
            return False
        try:
            ip = ip_address(host)
        except ValueError:
            return True
        cgn = ip_network("100.64.0.0/10") if isinstance(ip, IPv4Address) else None
        blocked = (ip.is_private or ip.is_loopback or ip.is_link_local or
                   ip.is_reserved or ip.is_multicast or
                   (cgn is not None and ip in cgn))
        if not blocked:
            return True
        if self.scope_hosts and host in self.scope_hosts:
            return True
        return False

    # ------------------------------------------------------------------
    # Passive scan
    # ------------------------------------------------------------------
    async def scan(self, urls: List[str],
                   progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        urls = [u for u in (urls or []) if u.startswith(("http://", "https://"))]
        urls = urls[: self.max_urls]
        if not urls:
            return {"analytics": [], "sinks": [], "totals": {"urls": 0}}

        sem = asyncio.Semaphore(self.concurrency)
        conn = aiohttp.TCPConnector(ssl=False)
        analytics_rows: List[Dict] = []
        sink_rows: List[Dict] = []

        async with aiohttp.ClientSession(connector=conn, headers=self.headers) as session:
            tasks = [self._scan_one(session, sem, u) for u in urls]
            for idx, coro in enumerate(asyncio.as_completed(tasks)):
                try:
                    a_rows, s_rows = await coro
                    analytics_rows.extend(a_rows)
                    sink_rows.extend(s_rows)
                except Exception as e:
                    logger.debug(f"cookie-bomb scan failed for one target: {e}")
                if progress_callback:
                    progress_callback((idx + 1) / len(tasks), f"Checked {idx+1}/{len(tasks)}")

        return {
            "analytics": analytics_rows,
            "sinks": sink_rows,
            "totals": {"urls": len(urls), "analytics_hosts": len({r["url"] for r in analytics_rows}),
                       "sink_files": len(sink_rows)},
        }

    def scan_sync(self, urls: List[str],
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(urls, progress_callback))

    async def _scan_one(self, session: aiohttp.ClientSession,
                        sem: asyncio.Semaphore, url: str) -> Tuple[List[Dict], List[Dict]]:
        if not self._host_in_scope(url) or not self._host_allowed(url):
            return [], []
        analytics_rows: List[Dict] = []
        sink_rows: List[Dict] = []
        try:
            async with sem:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                       allow_redirects=False, ssl=False) as resp:
                    headers = dict(resp.headers)
                    ctype = headers.get("Content-Type", "").lower()
                    body = ""
                    if "text/html" in ctype or url.rstrip("/").endswith((".html", ".htm")) or resp.status in (200, 304):
                        try:
                            body = await resp.text(errors="ignore")
                        except Exception:
                            body = ""
                    # Also handle 200 with HTML even if ctype is generic
                    if not body and resp.status == 200:
                        try:
                            body = await resp.text(errors="ignore")
                        except Exception:
                            body = ""
        except Exception as e:
            logger.debug(f"fetch failed {url}: {e}")
            return [], []

        providers = _detect_analytics(body, headers)
        for p in providers:
            analytics_rows.append({
                "url": url,
                "provider": p,
                "evidence": p,
                "confidence": "high",
            })

        # Inline JS sinks
        if body:
            parser = _AssetParser()
            try:
                parser.feed(body)
            except Exception:
                pass
            for chunk in parser.inline:
                for sink in _find_cookie_sinks(chunk):
                    sink_rows.append({
                        "url": url,
                        "source_url": url + "#inline",
                        "sink": sink["sink"],
                        "confidence": sink["confidence"],
                        "context": sink["context"][:500],
                    })
            # Best-effort: fetch up to 3 same-origin JS files for sink analysis
            base = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
            for src in parser.scripts[:3]:
                js_url = _urljoin(url, src)
                if not self._host_in_scope(js_url) or not self._host_allowed(js_url):
                    continue
                # only same-origin for passive scan (avoid 3rd-party noise)
                if urlsplit(js_url).netloc.lower() != urlsplit(url).netloc.lower():
                    continue
                try:
                    async with sem:
                        async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                               allow_redirects=False, ssl=False) as jr:
                            if jr.status in (200, 304):
                                js_body = await jr.text(errors="ignore")
                                for sink in _find_cookie_sinks(js_body):
                                    sink_rows.append({
                                        "url": url,
                                        "source_url": js_url,
                                        "sink": sink["sink"],
                                        "confidence": sink["confidence"],
                                        "context": sink["context"][:500],
                                    })
                except Exception:
                    continue

        return analytics_rows, sink_rows

    # ------------------------------------------------------------------
    # Active probe (single request, manual lab)
    # ------------------------------------------------------------------
    async def probe(self, url: str, param: str = "gclid", size: int = 4000,
                    char: str = "A") -> Dict[str, Any]:
        """Send ?<param>=<char*size> and report Set-Cookie reflection."""
        param = (param or "gclid").strip() or "gclid"
        size = max(1, min(int(size), 16000))
        char = (char or "A")[0]
        payload = char * size

        if not self._host_in_scope(url) or not self._host_allowed(url):
            return {"url": url, "param": param, "size": size, "verdict": "blocked_scope",
                    "set_cookie": [], "reflected": False, "follow_status": None,
                    "evidence": "Target outside scope or private IP not in scope"}

        # Build probe URL
        sep = "&" if "?" in url else "?"
        probe_url = f"{url}{sep}{param}={payload}"

        set_cookies: List[str] = []
        reflected = False
        follow_status: Optional[int] = None
        verdict = "not_vulnerable"

        conn = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=conn, headers=self.headers) as session:
                async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                                       allow_redirects=False, ssl=False) as resp:
                    # Collect all Set-Cookie headers
                    raw = resp.headers
                    # aiohttp exposes getall for multi-value headers
                    try:
                        set_cookies = raw.getall("Set-Cookie", [])
                    except Exception:
                        sc = raw.get("Set-Cookie")
                        set_cookies = [sc] if sc else []
                    # Check reflection: does any Set-Cookie contain a long run of the payload char?
                    needle = char * min(200, size)
                    for sc in set_cookies:
                        if needle in sc or (param.lower() in sc.lower() and payload[:100] in sc):
                            reflected = True
                            break
                    # Also check if cookie length suggests no truncation
                    if not reflected:
                        for sc in set_cookies:
                            # Heuristic: Set-Cookie value length close to payload size
                            if len(sc) >= size * 0.8:
                                reflected = True
                                break

                # Follow-up: replay the reflected cookie (if any) and see if server chokes
                if reflected and set_cookies:
                    # Build Cookie header from the reflected cookies (first 1-2)
                    cookie_parts = []
                    for sc in set_cookies[:2]:
                        # Take name=value part before ;
                        nv = sc.split(";", 1)[0].strip()
                        if nv:
                            cookie_parts.append(nv)
                    cookie_header = "; ".join(cookie_parts)
                    # Truncate to avoid actually DoSing ourselves with huge header in logs
                    # but still send enough to trigger server limit
                    try:
                        async with session.get(url, headers={**self.headers, "Cookie": cookie_header},
                                               timeout=aiohttp.ClientTimeout(total=self.timeout),
                                               allow_redirects=False, ssl=False) as r2:
                            follow_status = r2.status
                            if r2.status in (400, 413, 414, 431, 500, 502):
                                verdict = "likely_vulnerable"
                            elif reflected:
                                verdict = "reflected_no_dos"
                    except Exception as e:
                        verdict = f"follow_error: {type(e).__name__}"
                elif reflected:
                    verdict = "reflected_no_dos"
                else:
                    verdict = "not_vulnerable"
        except Exception as e:
            return {"url": url, "param": param, "size": size, "verdict": f"error: {type(e).__name__}: {e}",
                    "set_cookie": [], "reflected": False, "follow_status": None,
                    "evidence": str(e)[:300]}

        return {
            "url": url,
            "param": param,
            "size": size,
            "set_cookie": set_cookies[:5],
            "reflected": reflected,
            "follow_status": follow_status,
            "verdict": verdict,
            "probe_url": probe_url[:500],
        }

    def probe_sync(self, url: str, param: str = "gclid", size: int = 4000,
                   char: str = "A") -> Dict[str, Any]:
        return _run_coro(self.probe(url, param, size, char))


def _run_coro(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()
