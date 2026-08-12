# modules/tools/dorking_scanner.py
# Search-engine dorking (Yandex / Google / Bing) for bug bounty recon.
#
# Why Yandex first: it is the most automation-tolerant of the major engines
# (its `|` OR syntax works the same as Google's). It DOES run SmartCaptcha
# from datacenter IPs on yandex.com (a bare script UA and no `numdoc` param
# keeps us out; Chrome-like UAs get HTTP 400; `numdoc` triggers captcha), so
# "captcha detected" is treated as a graceful per-engine stop, not a failure.
# Google and Bing are offered as secondary engines - both are captcha-gated
# when hammered. Yahoo joins as an automation-tolerant fallback (results
# arrive wrapped in r.search.yahoo.com/RU= links, which we unwrap).
#
# Design:
#   * Fully async (aiohttp) with per-engine pacing (randomized delay between
#     queries) - search engines rate-limit hard, so queries run SEQUENTIALLY.
#   * Each SERP page is parsed for result URLs (engine-specific extractors
#     with a generic anchor fallback), tracking params stripped, engine/tracker
#     domains dropped.
#   * Subdomains are harvested from result hostnames AND from SERP display
#     text (engines show the URL path items), so one query surfaces many hosts.
#   * EVERYTHING is scope-filtered: with scope rules present, only hosts under
#     the configured zones survive; otherwise the target apex zone is used.
#   * Output is a flat dict: {'subdomains': [...], 'urls': [...], 'queries_run',
#     'blocked': [...], 'errors': [...], 'totals': {...}} - ready for the page
#     and for saving via ProjectManager.

import re
import time
import html
import asyncio
import random
import aiohttp
from typing import Dict, List, Optional, Callable, Set, Tuple, Any
from urllib.parse import quote, urlparse, unquote

from app.utils.logger import get_logger
from app.utils.user_agents import PROGRAM_UA_TAG,  USER_AGENTS

logger = get_logger()

# Yandex.com from datacenter egress rejects browser-like UAs outright (HTTP 400
# or a SmartCaptcha redirect), but serves the real SERP to a plain script UA
# (verified in live probes: bare aiohttp UA -> full SERP, numdoc=50 -> captcha).
# Wire one such UA in specifically for the failed-then-retry path, mirroring
# aiohttp's own default User-Agent format so it is indistinguishable from the
# library traffic Yandex ignores.
_AIOHTTP_STYLE_UA = f"Python/3.13 aiohttp/{aiohttp.__version__}" + PROGRAM_UA_TAG


# ---------------------------------------------------------------------
# DORK CATALOG - each entry is a Yandex/Google-compatible query with
# {domain} as the placeholder. `|` = OR on both engines.
# ---------------------------------------------------------------------
DORK_CATALOG: Dict[str, List[str]] = {
    'subdomains': [
        'site:{domain} -www -m. -mobile.',
        'site:*.{domain} -www',
        'site:{domain} -www -blog -shop -cdn -mail',
    ],
    'sensitive_files': [
        'site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini | ext:env',
        'site:{domain} ext:sql | ext:dbf | ext:mdb | ext:db | ext:dump',
        'site:{domain} ext:log | ext:bak | ext:old | ext:swp | ext:temp | ext:tmp',
        'site:{domain} inurl:backup | inurl:backups | inurl:dump | inurl:old | inurl:archive',
        'site:{domain} "index of" /admin | "index of" /backup | "index of" /config | "index of" /database',
        'site:{domain} intitle:"index of" "conf" | intitle:"index of" "passwd"',
        'site:{domain} inurl:.git | inurl:.svn | inurl:.hg',
        'site:{domain} inurl:phpinfo.php',
        'site:{domain} ext:env "APP_KEY" | ext:env "DB_PASSWORD" | ext:env "SECRET"',
    ],
    'security_txt': [
        # security.txt files often pin the bug bounty program + contact,
        # policy and preferred disclosure route for that exact host
        'site:{domain} inurl:security.txt',
        'site:{domain} inurl:.well-known/security.txt',
        'site:{domain} intitle:"security.txt"',
    ],
    'admin_panels': [
        'site:{domain} inurl:admin | inurl:login | inurl:panel | inurl:dashboard | inurl:console',
        'site:{domain} intitle:"login" intitle:"admin"',
        'site:{domain} inurl:phpmyadmin | inurl:adminer | inurl:phpPgAdmin | inurl:admin-console',
        'site:{domain} intitle:"swagger ui" | inurl:swagger | inurl:api-docs | inurl:openapi.json',
        'site:{domain} inurl:graphql | inurl:/graphiql | inurl:graphql-playground',
        'site:{domain} intitle:kibana | intitle:grafana | intitle:jenkins | intitle:sonarqube',
        'site:{domain} inurl:webmin | inurl:plesk | inurl:cpanel | inurl:vesta',
    ],
    'dev_staging': [
        'site:{domain} inurl:dev | inurl:test | inurl:staging | inurl:preprod | inurl:uat | inurl:qa',
        'site:{domain} inurl:internal | inurl:intranet | inurl:debug | inurl:admin.local',
        'site:{domain} inurl:staging -www -blog',
        'site:{domain} intitle:development | intitle:staging | intitle:"test environment"',
    ],
    'cloud_storage': [
        'site:s3.amazonaws.com "{domain}" | site:s3.amazonaws.com "*.{domain}"',
        'site:blob.core.windows.net "{domain}"',
        'site:storage.googleapis.com "{domain}"',
        'site:firebasestorage.googleapis.com "{domain}"',
        '"{domain}" inurl:s3.amazonaws.com | "{domain}" inurl:blob.core.windows.net',
    ],
    'redirects_params': [
        'site:{domain} inurl:redirect | inurl:url= | inurl:next= | inurl:return= | inurl:dest= | inurl:goto=',
        'site:{domain} inurl:redirect_url | inurl:callback | inurl:continue | inurl:returnto',
        'site:{domain} inurl:proxy | inurl:fetch | inurl:load | inurl:imageurl',
    ],
    'secrets_keys': [
        'site:{domain} intext:"api_key" | intext:"apikey" | intext:"api-key" | intext:"API KEY"',
        'site:{domain} intext:"secret" intext:"token"',
        'site:{domain} intext:"BEGIN RSA PRIVATE KEY" | intext:"BEGIN PRIVATE KEY" | intext:"BEGIN OPENSSH PRIVATE KEY"',
        'site:{domain} intext:"aws_access_key_id" | intext:"AKIA"',
        'site:{domain} intext:"password" inurl:config | intext:"password" inurl:settings | intext:"password" inurl:db',
    ],
    'docs_exposure': [
        'site:{domain} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx intitle:confidential | intitle:internal',
        'site:{domain} ext:pdf intext:password | ext:pdf intext:secret | ext:pdf intext:login',
        'site:{domain} inurl:jira | inurl:confluence | inurl:wiki | inurl:sharepoint | inurl:docs',
        'site:{domain} intitle:"internal" intitle:docs | intitle:"employee"',
    ],
    'login_pages': [
        'site:{domain} inurl:login | inurl:signin | inurl:auth | inurl:sso | inurl:oauth | inurl:connect',
        'site:{domain} intitle:"sign in" | intitle:"log in" | intitle:"member login"',
    ],
    'errors_debug': [
        'site:{domain} intext:"stack trace" | intext:"stacktrace"',
        'site:{domain} intext:"exception" inurl:error | intext:"fatal error" inurl:debug',
        'site:{domain} intitle:"500 internal server error" | intitle:"404 not found" inurl:error',
    ],
}

# Engines that appear in SERPs but are never real targets.
_NOISE_DOMAIN_RE = re.compile(
    r'(?:^|\.)(?:google|googleusercontent|googlesyndication|bing|msn|microsoft|'
    r'microsoftonline|live|yandex|yandex\.net|yastatic|yabs|doubleclick|'
    r'duckduckgo|yahoo|search\.yahoo|guce|facebook|fbcdn|twitter|x\.com|instagram|'
    r'linkedin|youtube|wikipedia|'
    r'archive\.org|reddit|quora|stackoverflow|githubusercontent|adobe|'
    r'apple|mozilla|msn|bing\.com|skype|office)\.(?:com|net|org|ru|io|dev)$',
    re.IGNORECASE,
)

_SUPPORTED_ENGINES = ('yandex', 'google', 'bing', 'duckduckgo', 'yahoo')

# Tracking params that pollute URL dedup / GF signal.
_TRACK_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'gclid', 'yclid', 'fbclid', 'msclkid', 'gs_lcrp', 'dclid', 'olvkw',
    'kw', 'ei', 'oq', 'sclient', 'ved', 'gs_lp', 'yclid', 'etext', 'hist',
}


def _clean_url(raw: str) -> Optional[str]:
    """Unescape, URL-decode, strip tracking params, drop junk. Returns None for junk."""
    try:
        u = html.unescape(raw).strip().strip('"').strip("'")
        if not u.startswith(('http://', 'https://')):
            return None
        u = unquote(u)  # engines percent-encode the query inside /url?q= links
        p = urlparse(u)
        host = (p.hostname or '').lower()
        if not host:
            return None
        if _NOISE_DOMAIN_RE.search(host):
            return None
        base = f"{p.scheme}://{p.netloc}{p.path}"
        if p.query:
            kept = [(k, v) for k, v in
                    (pair.split('=', 1) if '=' in pair else (pair, '')
                     for pair in p.query.split('&')) if k.lower() not in _TRACK_PARAMS]
            query = '&'.join(f'{k}={v}' for k, v in kept)
            return base + (f'?{query}' if query else '')
        return base
    except Exception:
        return None


class DorkScanner:
    """
    Async search-engine dorking with scope enforcement.

    Usage:
        scanner = DorkScanner(config)
        results = scanner.scan_sync(domain, queries=DorkScanner.default_queries(),
                                    engines=['yandex', 'google', 'bing'],
                                    progress_callback=..., scope_hosts=['example.com'])
    """

    def __init__(self, config: Dict):
        cfg = config.get('dorking', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 20))
        self.delay_min = float(cfg.get('delay_min', 3.0))
        self.delay_max = float(cfg.get('delay_max', 8.0))
        self.retry_delay = float(cfg.get('retry_delay', 12.0))
        self.per_page = int(cfg.get('per_page', 50))
        self.max_pages = int(cfg.get('max_pages', 1))
        self.max_queries = int(cfg.get('max_queries', 30))
        self.max_results = int(cfg.get('max_results', 200))
        self.user_agents = [ua + PROGRAM_UA_TAG for ua in USER_AGENTS] or [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' + PROGRAM_UA_TAG,
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 '
            '(KHTML, like Gecko) Version/17.1 Safari/605.1.15' + PROGRAM_UA_TAG,
            'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0' + PROGRAM_UA_TAG,
        ]
        self._pace: Dict[str, float] = {}  # per-engine last-query timestamp

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    @staticmethod
    def default_queries(categories: Optional[List[str]] = None) -> List[str]:
        """Flatten the catalog (optionally filtered by category) into query list."""
        queries = []
        for cat, qs in DORK_CATALOG.items():
            if categories and cat not in categories:
                continue
            queries.extend(qs)
        return queries

    @staticmethod
    def categories() -> List[str]:
        return list(DORK_CATALOG.keys())

    @staticmethod
    def build_query_urls(domain: str, queries: Optional[List[str]] = None,
                         engines: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """Expanded, ready-to-open engine URLs for the same dork queries.

        Engines captcha-gate bots, so these are offered as one-click browser
        links: the user opens each in their own browser (solving any captcha
        there) and reviews results manually. Returns a list of
        {'engine', 'query', 'url'} dicts.
        """
        queries = queries or []
        engines = [e for e in (engines or ['yandex', 'google', 'bing'])
                   if e in _SUPPORTED_ENGINES]
        links: List[Dict[str, str]] = []
        for q in queries:
            query = q.format(domain=domain.strip().lower())
            for engine in engines:
                url = DorkScanner._engine_search_url(engine, query)
                if url:
                    links.append({'engine': engine, 'query': query, 'url': url})
        return links

    @staticmethod
    def _engine_search_url(engine: str, query: str, per_page: int = 0) -> str:
        if engine == 'yandex':
            # NOTE: numdoc ranks on yandex.com triggers SmartCaptcha from
            # datacenter IPs - pagination is done via &p= so per_page is NOT
            # appended here (default 10 results, page 1).
            return 'https://yandex.com/search/?text=' + quote(query)
        if engine == 'google':
            url = 'https://www.google.com/search?q=' + quote(query) + '&hl=en&filter=0'
            return url + (f'&num={per_page}' if per_page else '')
        if engine == 'bing':
            url = 'https://www.bing.com/search?q=' + quote(query) + '&setlang=en&FORM=PERE'
            return url + (f'&count={per_page}' if per_page else '')
        if engine == 'duckduckgo':
            return 'https://html.duckduckgo.com/html/?q=' + quote(query) + '&kl=us-en'
        if engine == 'yahoo':
            url = 'https://search.yahoo.com/search?p=' + quote(query) + '&ei=UTF-8'
            return url + (f'&n={per_page}' if per_page else '')
        return ''

    async def scan(self, domain: str,
                   queries: Optional[List[str]] = None,
                   engines: Optional[List[str]] = None,
                   progress_callback: Optional[Callable[[float, str], None]] = None,
                   scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        domain = domain.strip().lower()
        if not domain:
            return self._empty_result()
        queries = queries or self.default_queries()
        queries = queries[:self.max_queries]
        engines = [e for e in (engines or list(_SUPPORTED_ENGINES))
                   if e in _SUPPORTED_ENGINES]

        # '*' in scope_hosts = GLOBAL discovery mode: no zone filtering (used
        # for security.txt / program-discovery dorks that span the open web).
        global_scope = '*' in (scope_hosts or [])
        scope_hosts = [h.lower().rstrip('.') for h in (scope_hosts or [domain])
                       if h and h != '*']

        def _in_zone(host: str) -> bool:
            if global_scope:
                return True
            host = host.lower().rstrip('.')
            return any(host == s or host.endswith('.' + s) for s in scope_hosts)

        result = self._empty_result()
        result['scope_zone'] = sorted(scope_hosts)

        if not engines or not queries:
            return result

        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }

        blocked: Set[str] = set()
        engine_hits: Dict[str, int] = {e: 0 for e in engines}
        queries_run: List[Dict] = []
        seen_urls: Set[str] = set()
        seen_hosts: Set[str] = set()

        # One session per engine (cookies stay engine-local so a captcha cookie
        # from one engine never leaks to another), UA rotated per request.
        sessions: Dict[str, aiohttp.ClientSession] = {}

        async def _query(engine: str, query: str):
            if engine not in sessions:
                sessions[engine] = aiohttp.ClientSession(headers=headers)
            url = self._engine_search_url(engine, query, self.per_page)
            return await self._query_engine(
                sessions[engine], engine, query, url,
                headers={'User-Agent': random.choice(self.user_agents)})

        try:
            total = len(queries)
            done = 0
            for q in queries:
                query = q.format(domain=domain)
                for engine in engines:
                    if engine in blocked:
                        continue
                    # per-engine pacing: randomized delay between queries
                    last = self._pace.get(engine, 0)
                    elapsed = time.monotonic() - last
                    want = random.uniform(self.delay_min, self.delay_max)
                    if elapsed < want:
                        await asyncio.sleep(want - elapsed)
                    self._pace[engine] = time.monotonic()

                    urls, is_blocked, err = await _query(engine, query)

                    # One retry with backoff - transient throttles often lift;
                    # only give up on the engine if the re-check fails too.
                    if not urls and is_blocked and not err:
                        logger.warning(
                            f"Dorking: {engine} captcha on {query!r}; "
                            f"retrying once after {self.retry_delay:.0f}s")
                        await asyncio.sleep(self.retry_delay)
                        self._pace[engine] = time.monotonic()
                        urls, is_blocked, err = await _query(engine, query)

                    if is_blocked:
                        blocked.add(engine)
                        result['blocked'].append(engine)
                        logger.warning(f"Dorking: {engine} blocked/captcha on query {query!r}")
                        continue
                    if err:
                        result['errors'].append(f"{engine}: {err}")
                        logger.debug(f"Dorking {engine} error: {err}")
                        continue

                    engine_hits[engine] += len(urls)
                    for u in urls:
                        if u in seen_urls:
                            continue
                        seen_urls.add(u)
                        host = (urlparse(u).hostname or '').lower().rstrip('.')
                        if not host or not _in_zone(host):
                            continue
                        result['urls'].append(u)
                        if host != domain and host not in seen_hosts:
                            seen_hosts.add(host)
                            result['subdomains'].append(host)
                    if progress_callback and urls:
                        progress_callback(min(done / max(total, 1), 0.98),
                                          f"[{engine}] {len(urls)} hits on {query[:60]}")
                    queries_run.append({'engine': engine, 'query': query, 'hits': len(urls)})

                done += 1
                if progress_callback:
                    progress_callback(done / max(total, 1),
                                      f"Dorked {done}/{total} queries "
                                      f"({len(result['urls'])} URLs, "
                                      f"{len(result['subdomains'])} subdomains)")
        finally:
            for s in sessions.values():
                await s.close()

        # cap + sort
        result['urls'] = sorted(set(result['urls']))[:self.max_results]
        result['subdomains'] = sorted(set(result['subdomains']))
        result['queries_run'] = queries_run
        result['engine_hits'] = engine_hits
        result['totals'] = {
            'queries': len(queries_run),
            'urls': len(result['urls']),
            'subdomains': len(result['subdomains']),
            'engines_blocked': len(result['blocked']),
        }
        logger.info(f"Dorking done: {len(result['subdomains'])} subdomains, "
                    f"{len(result['urls'])} URLs, {len(result['queries_run'])} queries run")
        return result

    def scan_sync(self, domain: str,
                  queries: Optional[List[str]] = None,
                  engines: Optional[List[str]] = None,
                  progress_callback: Optional[Callable[[float, str], None]] = None,
                  scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        """Sync wrapper for streamlit."""
        return _run_coro(self.scan(domain, queries, engines, progress_callback, scope_hosts))

    # ------------------------------------------------------------------
    # Engine internals
    # ------------------------------------------------------------------
    async def _query_engine(self, session: aiohttp.ClientSession,
                            engine: str, query: str, url: str,
                            headers: Optional[Dict[str, str]] = None) -> Tuple[List[str], bool, str]:
        """Returns (urls, is_blocked, error). Exactly one of those is truthy."""
        try:
            if not url:
                return [], False, f'unknown engine {engine}'

            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                if resp.status in (403, 429, 503):
                    return [], True, f'HTTP {resp.status}'
                # Yandex answers 400 to browser-like UAs from datacenter IPs.
                # Retry ONCE with the aiohttp-style UA that it serves normally.
                if resp.status == 400 and engine == 'yandex':
                    await asyncio.sleep(2.0)
                    async with session.get(
                            url,
                            headers={**headers, 'User-Agent': _AIOHTTP_STYLE_UA},
                            timeout=aiohttp.ClientTimeout(total=self.timeout)) as r2:
                        resp = r2
                if resp.status in (403, 429, 503):
                    return [], True, f'HTTP {resp.status}'
                if resp.status not in (200,):
                    return [], False, f'HTTP {resp.status}'
                content_type = resp.headers.get('content-type', '')
                if 'text' not in content_type and 'html' not in content_type:
                    return [], False, f'unexpected content-type {content_type}'
                page = await resp.text(errors='ignore')
        except asyncio.TimeoutError:
            return [], False, 'timeout'
        except aiohttp.ClientError as e:
            return [], False, str(e)[:120]
        except Exception as e:
            return [], False, f'{type(e).__name__}: {e}'

        if _is_captcha_page(engine, page):
            return [], True, 'captcha'

        raw = _extract_serp_links(engine, page)
        urls = []
        for r in raw:
            u = _clean_url(r)
            if u and u not in urls:
                urls.append(u)
        return urls, False, ''

    def _empty_result(self) -> Dict[str, Any]:
        return {
            'subdomains': [], 'urls': [], 'queries_run': [],
            'blocked': [], 'errors': [], 'engine_hits': {},
            'totals': {'queries': 0, 'urls': 0, 'subdomains': 0, 'engines_blocked': 0},
            'scope_zone': [],
        }


# ---------------------------------------------------------------------
# SERP parsing helpers
# ---------------------------------------------------------------------
_GENERIC_ANCHOR_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
_GOOGLE_URLQ_RE = re.compile(r'/url\?q=([^&"\']+)')
_BING_ANCHOR_RE = re.compile(r'<h2[^>]*>\s*<a[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
_YANDEX_ORGANIC_RE = re.compile(
    r'<a[^>]+class=["\'][^"\']*organic__url[^"\']*["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE)
# Modern Yandex markup: organic titles are <a href="..."><h2> (the legacy
# organic__url class no longer exists in the SERP)
_YANDEX_TITLE_RE = re.compile(
    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>\s*<h2[^>]*>', re.IGNORECASE)
_YANDEX_PATH_RE = re.compile(r'<span[^>]*class=["\'][^"\']*Path-Item[^"\']*["\'][^>]*>(.*?)</span>',
                             re.IGNORECASE | re.DOTALL)
_DDG_RESULT_RE = re.compile(
    r'<a[^>]+class=["\'][^"\']*result__a[^"\']*["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE)
_DDG_REDIRECT_RE = re.compile(r'[?&]uddg=([^&]+)')
_YAHOO_REDIRECT_RE = re.compile(r'https?://r\.search\.yahoo\.com/[^"\']*?\bRU=([^/]+)', re.IGNORECASE)


def _resolve_ddg_link(href: str) -> str:
    """DDG wraps results in /l/?uddg=<url> redirects - unwrap to the real URL."""
    if '/l/?' in href:
        m = _DDG_REDIRECT_RE.search(href)
        if m:
            return unquote(m.group(1))
    return href


def _resolve_yahoo_link(href: str) -> str:
    """Yahoo wraps every result in r.search.yahoo.com/_ylt=.../RU=<enc-url>/RK=...
    Unwrap the RU payload to the real target URL."""
    if 'r.search.yahoo.com' in href:
        m = _YAHOO_REDIRECT_RE.search(href)
        if m:
            try:
                return unquote(m.group(1))
            except Exception:
                return href
    return href


def _is_captcha_page(engine: str, page: str) -> bool:
    low = page.lower()
    if engine == 'yandex':
        return 'captcha' in low and ('robot' in low or 'human' in low or 'smartcaptcha' in low)
    if engine == 'google':
        return ('unusual traffic' in low or 'recaptcha' in low or '/sorry/index' in low
                or 'consent.google.com' in low or 'before you continue to google' in low)
    if engine == 'bing':
        return 'captcha' in low and ('verification' in low or 'robot' in low)
    if engine == 'duckduckgo':
        return 'anomaly' in low or 'captcha' in low or 'blocked' in low
    if engine == 'yahoo':
        return 'unusual traffic' in low or 'captcha' in low or 'denied' in low \
            or 'verify you are human' in low
    return 'captcha' in low


def _extract_serp_links(engine: str, page: str) -> List[str]:
    if engine == 'google':
        links = _GOOGLE_URLQ_RE.findall(page)
        if not links:
            links = [m for m in _GENERIC_ANCHOR_RE.findall(page)
                     if m.startswith(('http://', 'https://'))]
    elif engine == 'bing':
        links = [m for m in _BING_ANCHOR_RE.findall(page)
                 if m.startswith(('http://', 'https://'))]
        if not links:
            links = [m for m in _GENERIC_ANCHOR_RE.findall(page)
                     if m.startswith(('http://', 'https://'))]
    elif engine == 'duckduckgo':
        links = [_resolve_ddg_link(m) for m in _DDG_RESULT_RE.findall(page)]
        if not links:
            links = [m for m in _GENERIC_ANCHOR_RE.findall(page)
                     if m.startswith(('http://', 'https://'))]
    elif engine == 'yahoo':
        links = [_resolve_yahoo_link(m) for m in _GENERIC_ANCHOR_RE.findall(page)
                 if m.startswith(('http://', 'https://'))]
    else:  # yandex
        links = _YANDEX_ORGANIC_RE.findall(page)
        if not links:
            # modern markup: title anchors (h2 directly under <a href>)
            links = _YANDEX_TITLE_RE.findall(page)
        if not links:
            links = [m for m in _GENERIC_ANCHOR_RE.findall(page)
                     if m.startswith(('http://', 'https://'))]
    return links


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()
