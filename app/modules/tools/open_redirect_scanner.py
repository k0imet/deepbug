# modules/tools/open_redirect_scanner.py
# Open-redirect detection (the "probe redirects with context" trick): swap
# redirect-style parameter values with a canary host and watch where the
# server wants to send us.
#
#   * Param list   - url, redirect, next, return, dest, goto, target, ...
#   * Techniques   - raw (unencoded), plain, URL-encoded, protocol-relative
#   * Detection    - Location header OR body containing the canary while the
#                     request still stays on the origin host (we never follow
#                     the redirect off-target)
#
# Passive and in-scope only. A canary host you control (config 'canary_host')
# makes verification trivial: if `canary.deepbug.io` receives the hit, it's
# exploitable.
#   {'findings': [{url, param, technique, status, location, evidence}],
#    'totals': {...}}

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any
from urllib.parse import urlparse, urlencode, parse_qsl, quote, urljoin

from app.utils.logger import get_logger

logger = get_logger()

_REDIRECT_PARAMS = ['g', 'r', 'l', 'to', 'link2', 'target_url', 'redirect_url', 'redirect_uri',
    'url', 'redirect', 'next', 'return', 'return_url', 'return_to', 'dest',
    'destination', 'goto', 'target', 'rurl', 'qurl', 'link', 'out', 'view',
    'dir', 'continue', 'callback', 'redir', 'redirect_url', 'image_url',
    'imageurl', 'load', 'proxy', 'u', 'url2', 'go', 'jump', 'forward',
    'ref', 'from_url', 'path', 'page', 'fetch', 'endpoint', 'data', 'src',
]


class OpenRedirectScanner:
    """
    Canary-based open-redirect scanner.

    Usage:
        scanner = OpenRedirectScanner(config)
        results = scanner.scan_sync(['https://example.com/x?next=/login'],
                                    canary='canary.deepbug.io')
    """

    def __init__(self, config: Dict):
        cfg = config.get('open_redirect', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 12))
        self.max_urls = int(cfg.get('max_urls', 200))
        self.canary = cfg.get('canary_host', 'canary.deepbug.io')

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, urls: List[str],
                   canary: Optional[str] = None,
                   progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        canary = (canary or self.canary or 'canary.invalid').strip().lower()
        urls = urls or []
        findings: List[Dict] = []
        total = len(urls)
        checked = 0
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for raw in urls[:self.max_urls]:
                checked += 1
                for candidate in _redirect_variants(raw, canary):
                    status, location, body = await self._probe(session, candidate['url'])
                    if not location and not body:
                        continue
                    if _location_matches_canary(location, candidate['url'], canary):
                        findings.append({
                            'url': candidate['url'],
                            'param': candidate['param'],
                            'technique': candidate['technique'],
                            'status': status,
                            'location': location,
                            'evidence': f'Location: {location}',
                        })
                if progress_callback:
                    progress_callback(checked / max(total, 1),
                                      f'{len(findings)} redirects on {raw[:50]}')
        return {
            'findings': findings,
            'totals': {'urls': checked, 'findings': len(findings),
                       'parameters': _REDIRECT_PARAMS},
        }

    def scan_sync(self, urls: List[str], canary: Optional[str] = None,
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(urls, canary, progress_callback))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _probe(self, session: aiohttp.ClientSession, url: str) -> tuple:
        try:
            async with session.get(url, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                body = await resp.text(errors='ignore')
                return resp.status, resp.headers.get('Location', ''), body
        except Exception:
            return 0, '', ''

    def _empty_result(self) -> Dict[str, Any]:
        return {'findings': [], 'totals': {'urls': 0, 'findings': 0,
                                           'parameters': _REDIRECT_PARAMS}}


def _redirect_variants(raw: str, canary: str) -> List[Dict]:
    """Build (param, technique, url) test cases for a URL with redirect params."""
    p = urlparse(raw)
    if not p.hostname:
        return []
    if not p.query:
        return []
    base = f'{p.scheme}://{p.netloc}{p.path}'
    variants = []
    pairs = parse_qsl(p.query, keep_blank_values=True)
    for index, (k, _v) in enumerate(pairs):
        if k.lower() not in _REDIRECT_PARAMS:
            continue
        target = f'https://{canary}/'
        encoded_values = (
            ('raw', quote(target, safe=':/')),
            ('encoded', quote(target, safe='')),
            ('double', quote(quote(target, safe=''), safe='')),
            ('proto_relative', quote(f'//{canary}/', safe='/')),
        )
        for technique, encoded_value in encoded_values:
            chunks = []
            for pair_index, (pk, pv) in enumerate(pairs):
                key = quote(str(pk), safe='')
                value = encoded_value if pair_index == index else quote(str(pv), safe='')
                chunks.append(f'{key}={value}')
            qs = '&'.join(chunks)
            variants.append({'param': k, 'technique': technique,
                             'url': f'{base}?{qs}' + (f'#{p.fragment}' if p.fragment else '')})
    return variants


def _location_matches_canary(location: str, request_url: str, canary: str) -> bool:
    if not location:
        return False
    try:
        destination = urlparse(urljoin(request_url, location.replace('\\', '/')))
        return (destination.hostname or '').rstrip('.').lower() == canary.rstrip('.').lower()
    except Exception:
        return False


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()
