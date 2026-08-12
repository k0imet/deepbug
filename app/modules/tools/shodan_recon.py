# modules/tools/shodan_recon.py
# Shodan-powered asset discovery + the favicon hash trick from infosecwriteups:
# organizations reuse ONE favicon across every subdomain/staging/CDN asset, so
# the MurmurHash3 of that icon is a cheap global fingerprint that DNS brute
# force will never find.
#
#   * Favicon fingerprint  - fetch <host>/favicon.ico, compute mmh3 hash
#   * Shodan DNS domain    - subdomains Shodan has seen for the zone (any key)
#   * Shodan search        - http.favicon.hash:<h> -> in-zone hostnames
#
# Token comes from SHODAN_API_KEY env (config 'shodan.token_env'); everything
# degrades gracefully without a key (favicon hash is still printed for manual use).
#
#   {'subdomains': [...], 'favicon_hash': 123, 'favicon_url': ...,
#    'api_used': bool, 'errors': [...], 'totals': {...}}

import os
import base64
import asyncio
import re
import aiohttp
from typing import Dict, List, Optional, Callable, Any

from app.utils.logger import get_logger

logger = get_logger()

_SHODAN_API = 'https://api.shodan.io'


def _mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86_32 (signed int32, matches the `mmh3` lib)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    r1, r2, m, n = 15, 13, 5, 0xE6546B64
    h = seed & 0xFFFFFFFF
    length = len(data)
    nblocks = length // 4
    for i in range(nblocks):
        block = int.from_bytes(data[i * 4:i * 4 + 4], 'little')
        block = (block * c1) & 0xFFFFFFFF
        block = ((block << r1) | (block >> (32 - r1))) & 0xFFFFFFFF
        block = (block * c2) & 0xFFFFFFFF
        h ^= block
        h = ((h << r2) | (h >> (32 - r2))) & 0xFFFFFFFF
        h = (h * m + n) & 0xFFFFFFFF
    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << r1) | (k1 >> (32 - r1))) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h ^= k1
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    if h & 0x80000000:
        h -= 0x100000000
    return h


def _favicon_hash(data: bytes) -> int:
    """Shodan's favicon fingerprint: mmh3 of base64-encoded favicon bytes."""
    return _mmh3_x86_32(base64.b64encode(data))


class ShodanRecon:
    """
    Favicon fingerprint + Shodan API asset discovery, scope-filtered.

    Usage:
        recon = ShodanRecon(config)
        results = recon.scan_sync('example.com', scope_hosts=['example.com'])
    """

    def __init__(self, config: Dict):
        cfg = config.get('shodan', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 20))
        self.max_results = int(cfg.get('max_results', 100))
        self.favicon_max = int(cfg.get('favicon_max', 5))
        self.token_env = cfg.get('token_env', 'SHODAN_API_KEY')
        self.token = (os.environ.get(self.token_env) or os.environ.get('SHODAN_API_KEY') or '').strip()
        self.api_used = bool(self.token)

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
        result['api_used'] = self.api_used
        errors: List[str] = []

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            try:
                fav_url, fav_hash = await self._fingerprint_favicon(session, domain)
                if fav_hash:
                    result['favicon_hash'] = fav_hash
                    result['favicon_url'] = fav_url
                else:
                    errors.append('no favicon found')
            except Exception as e:
                errors.append(f'favicon: {e}')

            if progress_callback:
                progress_callback(0.33, f'favicon hash: {result["favicon_hash"]}')

            if self.api_used:
                try:
                    for host in await self._shodan_dns(session, domain):
                        host = host.lower().rstrip('.')
                        if _in_zone(host):
                            result['subdomains'].append(host)
                except Exception as e:
                    errors.append(f'shodan dns: {e}')
                if result['favicon_hash']:
                    try:
                        for host in await self._shodan_search(
                                session, f'http.favicon.hash:{result["favicon_hash"]}'):
                            host = host.lower().rstrip('.')
                            if _in_zone(host):
                                result['subdomains'].append(host)
                    except Exception as e:
                        errors.append(f'shodan favicon search: {e}')
                try:
                    for host in await self._shodan_search(
                            session, f'ssl.cert.subject.cn:"{domain}"'):
                        host = host.lower().rstrip('.')
                        if _in_zone(host):
                            result['subdomains'].append(host)
                except Exception as e:
                    errors.append(f'shodan ssl search: {e}')

            if progress_callback:
                progress_callback(0.95, f'{len(result["subdomains"])} shodan/favicon hits')

        result['subdomains'] = sorted(set(result['subdomains']))[:self.max_results]
        result['errors'] = errors[:10]
        result['totals'] = {'subdomains': len(result['subdomains']),
                            'api_used': self.api_used,
                            'favicon': result['favicon_hash']}
        logger.info(f'Shodan/favicon done: {len(result["subdomains"])} subdomains, '
                    f'favicon={result["favicon_hash"]}')
        return result

    def scan_sync(self, domain: str,
                  progress_callback: Optional[Callable[[float, str], None]] = None,
                  scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(domain, progress_callback, scope_hosts))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _fingerprint_favicon(self, session: aiohttp.ClientSession,
                                   domain: str) -> tuple:
        candidates = [f'https://{domain}/favicon.ico', f'http://{domain}/favicon.ico']
        # discover icons linked from the homepage
        try:
            async with session.get(f'https://{domain}/', timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    text = await r.text(errors='ignore')
                    for href in re.findall(r'(?:href|src)=["\']([^"\']*favicon[^"\']*)["\']', text):
                        if href.startswith('//'):
                            href = 'https:' + href
                        elif href.startswith('/'):
                            href = f'https://{domain}' + href
                        candidates.append(href)
        except Exception:
            pass
        seen = set()
        for url in candidates:
            if url in seen or len(seen) >= self.favicon_max:
                continue
            seen.add(url)
            try:
                async with session.get(url, allow_redirects=True,
                                       timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        body = await resp.read()
                        if 0 < len(body) < 1_000_000:
                            return url, _favicon_hash(body)
            except Exception:
                continue
        return '', None

    async def _shodan_dns(self, session: aiohttp.ClientSession, domain: str) -> List[str]:
        params = {'key': self.token}
        async with session.get(f'{_SHODAN_API}/dns/domain/{domain}', params=params) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
        subs = (data or {}).get('subdomains', []) if isinstance(data, dict) else []
        return [f'{s}.{domain}' for s in subs if s]

    async def _shodan_search(self, session: aiohttp.ClientSession, query: str) -> List[str]:
        params = {'query': query, 'key': self.token}
        async with session.get(f'{_SHODAN_API}/shodan/host/search', params=params) as resp:
            if resp.status != 200:
                return []
            data = await resp.json(content_type=None)
        hosts: List[str] = []
        if isinstance(data, dict):
            for match in data.get('matches', []) or []:
                for h in (match.get('hostnames') or []):
                    if h:
                        hosts.append(h)
        return hosts

    def _empty_result(self) -> Dict[str, Any]:
        return {'subdomains': [], 'favicon_hash': None, 'favicon_url': '',
                'api_used': False, 'errors': [],
                'totals': {'subdomains': 0, 'api_used': False, 'favicon': None},
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