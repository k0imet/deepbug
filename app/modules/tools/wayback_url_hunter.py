# modules/tools/wayback_url_hunter.py
# Historical URL hunting - the "waybackurls / gau" trick from infosecwriteups:
# the Internet never forgets. Dead subdomains and old endpoints are pulled from
# three free passive archives and pushed back into the recon pipeline.
#
#   * Web Archive CDX API   - all captured URLs for the zone
#   * Common Crawl index    - newest crawl index, status:200 only
#   * AlienVault OTX        - domain URL list endpoint
#
# Everything is scope-filtered (host-suffix against scope_hosts / apex zone),
# tracking params stripped, static media dropped. Output feeds the endpoint
# engine and the subdomain pipeline:
#
#   {'urls': [...], 'subdomains': [...], 'sources': {...}, 'totals': {...}}

import re
import html
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any
from urllib.parse import urlparse, unquote

from app.utils.logger import get_logger

logger = get_logger()

# Media/static assets that never carry finding signal.
_STATIC_EXT = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.avif',
    '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.webm', '.avi', '.mov', '.wav',
}

_TRACK_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'gclid', 'yclid', 'fbclid', 'msclkid', 'dclid', 'olvkw',
    'sclient', 'ved', 'spm', 'from', 'action_object_map', 'ref',
}

_COMMON_CRAWL_INDEX_URL = 'https://index.commoncrawl.org/collinfo.json'
_CDX_API = 'https://web.archive.org/cdx/search/cdx'
_OTX_API = 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list'


def _clean_url(raw: str) -> Optional[str]:
    """Normalize + de-pollute an archived URL. None for junk/static."""
    try:
        u = html.unescape(str(raw)).strip()
        u = unquote(u)
        if not u.startswith(('http://', 'https://')):
            return None
        p = urlparse(u)
        host = (p.hostname or '').lower().rstrip('.')
        if not host:
            return None
        base = f"{p.scheme}://{p.netloc}{p.path}"
        if p.path.lower().endswith(tuple(_STATIC_EXT)):
            return None
        if p.query:
            kept = [(k, v) for k, v in
                    (pair.split('=', 1) if '=' in pair else (pair, '')
                     for pair in p.query.split('&')) if k.lower() not in _TRACK_PARAMS]
            query = '&'.join(f'{k}={v}' for k, v in kept)
            return base + (f'?{query}' if query else '')
        return base
    except Exception:
        return None


class WaybackURLHunter:
    """
    Historical/archival URL discovery with scope enforcement.

    Usage:
        hunter = WaybackURLHunter(config)
        results = hunter.scan_sync('example.com', scope_hosts=['example.com'])
    """

    def __init__(self, config: Dict):
        cfg = config.get('wayback', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 30))
        self.max_results = int(cfg.get('max_results', 1000))
        sources = cfg.get('sources', ['cdx', 'commoncrawl', 'otx'])
        self.sources = [s for s in sources if s in ('cdx', 'commoncrawl', 'otx')] or ['cdx']
        self._cc_index: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, domain: str,
                   progress_callback: Optional[Callable[[float, str], None]] = None,
                   scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        domain = (domain or '').strip().lower().rstrip('.')
        if not domain:
            return self._empty_result()
        scope_hosts = [h.lower().rstrip('.') for h in (scope_hosts or [domain]) if h and h != '*']

        def _in_zone(host: str) -> bool:
            host = host.lower().rstrip('.')
            return any(host == s or host.endswith('.' + s) for s in scope_hosts)

        result = self._empty_result()
        result['scope_zone'] = sorted(scope_hosts)
        result['target'] = domain

        seen_urls: set = set()
        seen_hosts: set = set()
        source_counts = {s: 0 for s in self.sources}
        errors: List[str] = []

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            total_sources = len(self.sources)
            for idx, source in enumerate(self.sources):
                try:
                    if source == 'cdx':
                        raw = await self._fetch_cdx(session, domain, self.max_results)
                    elif source == 'commoncrawl':
                        raw = await self._fetch_common_crawl(session, domain, self.max_results)
                    else:
                        raw = await self._fetch_otx(session, domain, self.max_results)
                except Exception as e:
                    errors.append(f"{source}: {e}")
                    logger.debug(f"Wayback {source} error: {e}")
                    raw = []

                if progress_callback:
                    progress_callback(idx / max(total_sources, 1),
                                      f"[{source}] {len(raw)} raw hits for {domain}")

                for r in raw:
                    u = _clean_url(r)
                    if not u:
                        continue
                    host = (urlparse(u).hostname or '').lower().rstrip('.')
                    if not _in_zone(host):
                        continue
                    if u in seen_urls:
                        continue
                    seen_urls.add(u)
                    result['urls'].append(u)
                    if host != domain and host not in seen_hosts:
                        seen_hosts.add(host)
                        result['subdomains'].append(host)
                    source_counts[source] += 1

        result['urls'] = sorted(result['urls'])[:self.max_results]
        result['subdomains'] = sorted(result['subdomains'])
        result['sources'] = source_counts
        result['errors'] = errors
        result['totals'] = {'urls': len(result['urls']), 'subdomains': len(result['subdomains']),
                            'sources_used': len(self.sources)}
        logger.info(f"Wayback done: {len(result['urls'])} URLs, "
                    f"{len(result['subdomains'])} subdomains from {source_counts}")
        return result

    def scan_sync(self, domain: str,
                  progress_callback: Optional[Callable[[float, str], None]] = None,
                  scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(domain, progress_callback, scope_hosts))

    # ------------------------------------------------------------------
    # Source fetchers (overridable for tests)
    # ------------------------------------------------------------------
    async def _fetch_cdx(self, session: aiohttp.ClientSession,
                         domain: str, limit: int) -> List[str]:
        params = {
            'url': f'{domain}/*',
            'output': 'json',
            'fl': 'original',
            'collapse': 'urlkey',
            'filter': 'statuscode:200',
            'limit': limit,
            'fastLatest': 'true',
        }
        async with session.get(_CDX_API, params=params) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
        return [row[0] for row in data if isinstance(row, list) and row] if isinstance(data, list) else []

    async def _fetch_common_crawl(self, session: aiohttp.ClientSession,
                                  domain: str, limit: int) -> List[str]:
        if not self._cc_index:
            async with session.get(_COMMON_CRAWL_INDEX_URL) as resp:
                if resp.status != 200:
                    return []
                try:
                    indexes = await resp.json()
                except Exception:
                    return []
            if not isinstance(indexes, list) or not indexes:
                return []
            self._cc_index = indexes[0].get('id', '')  # newest crawl is first
        if not self._cc_index:
            return []
        url = f'https://index.commoncrawl.org/{self._cc_index}-index'
        params = {'url': f'{domain}/*', 'output': 'json', 'filter': 'status:200', 'limit': limit}
        async with session.get(url, params=params) as resp:
            if resp.status != 200:
                return []
            text = await resp.text(errors='ignore')
        urls = []
        for line in text.splitlines():
            try:
                import json as _json
                urls.append(_json.loads(line).get('url', ''))
            except Exception:
                continue
        return urls

    async def _fetch_otx(self, session: aiohttp.ClientSession,
                         domain: str, limit: int) -> List[str]:
        urls = []
        page = 1
        while page <= 20 and len(urls) < limit:
            async with session.get(_OTX_API.format(domain=domain),
                                   params={'limit': min(limit, 500), 'page': page}) as resp:
                if resp.status != 200:
                    break
                data = await resp.json(content_type=None)
            entries = data.get('url_list', []) if isinstance(data, dict) else []
            if not entries:
                break
            urls.extend(e.get('url', '') for e in entries if isinstance(e, dict))
            page += 1
        return urls

    def _empty_result(self) -> Dict[str, Any]:
        return {'urls': [], 'subdomains': [], 'sources': {},
                'errors': [], 'totals': {'urls': 0, 'subdomains': 0, 'sources_used': 0},
                'scope_zone': [], 'target': ''}


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()
