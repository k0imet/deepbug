# modules/tools/bypass_403.py
# 403-bypass engine (the classic "don't ignore 403s" trick from
# infosecwriteups): a 403 on an admin path often hides a live backend that
# honors alternate routing/headers instead of proper auth.
#
#   * Header tricks   - X-Original-URL / X-Rewrite-URL (path relay), IPv4
#                       spoof headers, X-Forwarded-Host: localhost
#   * Path mutations  - trailing slash, //-prefix, %2e dot segments, `..;/`
#                       path params, uppercase last segment
#
# A variant "bypasses" when status leaves 403/401/405 for something that still
# served a real body. Purely passive probing - nothing is modified.
#   {'results': [{url, baseline_status, bypasses: [{technique, status, length}]}],
#    'totals': {...}}

import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any
from urllib.parse import urlparse

from app.utils.logger import get_logger

logger = get_logger()

_SPOOF_HEADERS = {
    'X-Forwarded-For': '127.0.0.1',
    'X-Real-IP': '127.0.0.1',
    'X-Custom-IP-Authorization': '127.0.0.1',
    'X-Client-IP': '127.0.0.1',
    'X-Originating-IP': '127.0.0.1',
    'X-Remote-IP': '127.0.0.1',
    'X-Forwarded-Host': 'localhost',
    'X-Host': 'localhost',
}

_DENY_STATUSES = (0, 403, 429, 502, 503, 504)
_FREE_STATUSES = (200, 301, 302, 307, 308, 401, 405, 400)


def _breakdown(raw: str):
    p = urlparse(raw)
    base = f'{p.scheme}://{p.netloc}'
    path = p.path or '/'
    return base, path


def _pathmanip(base: str, path: str) -> List[tuple]:
    """Returns (technique, url) path-mutation candidates for routing bypass."""
    name = path.rstrip('/').rsplit('/', 1)[-1]
    cands = [
        ('trailing_slash', base + path + '/'),
        ('double_slash', base + '/' + path.lstrip('/')),
        ('encoded_dot', base + '/' + '%2e/' + path.lstrip('/')),
        ('encoded_slash', base + '/' + '%2e%2e/' + path.lstrip('/')),
        ('dotdot_slash', base + '/' + path.replace('/', '/..;/')),
        ('path_param', base + path + ';.'),
        ('upper_case', base + '/' + path.rsplit('/', 1)[0].rstrip('/') + '/' + name.upper()),
    ]
    seen = set()
    out = []
    for t, u in cands:
        if u not in seen:
            seen.add(u)
            out.append((t, u))
    return out


class Bypass403Engine:
    """
    403 bypass probing engine.

    Usage:
        bypass = Bypass403(config)
        results = bypass.scan_sync(['https://example.com/admin'])
    """

    def __init__(self, config: Dict):
        cfg = config.get('bypass403', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 12))
        self.max_urls = int(cfg.get('max_urls', 50))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, urls: List[str],
                   progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        results: List[Dict] = []
        total = len(urls)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for i, raw in enumerate(urls[:self.max_urls]):
                base, path = _breakdown(raw)
                base_status, base_len = await self._probe(session, raw, {})
                entry = {'url': raw, 'baseline_status': base_status, 'bypasses': []}

                if base_status in (403, 401, 405):
                    candidates = [(t, u, {}) for t, u in _pathmanip(base, path)]
                    candidates += [(f'header:{h}', raw, {h: v}) for h, v in _SPOOF_HEADERS.items()]
                    for h in ('X-Original-URL', 'X-Rewrite-URL'):
                        candidates.append((f'header:{h}', raw, {h: path}))
                    for technique, url, hdr in candidates:
                        s2, l2 = await self._probe(session, url, hdr)
                        if _is_freed(s2, l2, base_status):
                            entry['bypasses'].append(
                                {'technique': technique, 'status': s2,
                                 'length': l2, 'url': url})
                            if progress_callback:
                                progress_callback((i + 1) / max(total, 1),
                                                  f'[{technique}] {s2} on {url[:60]}')
                results.append(entry)
                if progress_callback:
                    progress_callback((i + 1) / max(total, 1),
                                      f'checked {raw[:60]} ({base_status})')

        freed = [r for r in results if r['bypasses']]
        totals = {
            'urls_tested': len(results),
            'bypassed_urls': len(freed),
            'bypass_attempts': sum(len(r['bypasses']) for r in freed),
        }
        logger.info(f'bypass403 done: {totals}')
        return {'results': freed, 'totals': totals}

    def scan_sync(self, urls: List[str],
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(urls, progress_callback))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _probe(self, session: aiohttp.ClientSession, url: str,
                     headers: Dict[str, str]) -> tuple:
        try:
            async with session.get(url, headers=headers or None, allow_redirects=False) as resp:
                body = await resp.content.read()
                return resp.status, len(body)
        except Exception:
            return 0, 0

    def _empty_result(self) -> Dict[str, Any]:
        return {'results': [], 'totals': {'urls_tested': 0, 'bypassed_urls': 0,
                                          'bypass_attempts': 0}}


def _is_freed(status: int, length: int, baseline: int) -> bool:
    if status == baseline or status in _DENY_STATUSES or status >= 500:
        return False
    # A successful representation is confirmation-quality. Authentication
    # challenges, validation errors, and redirects are differentials worth
    # manual review, but are not authorization bypasses.
    if 200 <= status < 300:
        return True
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
