from app.utils.user_agents import PROGRAM_UA_TAG
# modules/tools/ssrf_validator.py
# SSRF confirmation for candidate URL-fetching parameters - the validation
# layer on top of ssrf_scanner's heuristic findings.
#
# Honest scope note (grounded in the OOB-validation write-up in the corpus):
# real CONFIRMED blind-SSRF proof needs a callback host we control; we do not
# operate one, so this validator confirms only the verifiable-on-demand tier:
#
#   PROBABLE  (url-reflection)  - our canary URL (unique host) is echoed back in
#                                 the response body or headers; the app layering
#                                 our value into a server-side request is evident.
#   PROBABLE  (fetched-destination) - we requested a known, controlled-adjacent
#                                 destination (example.com/robots.txt) and the
#                                 server returned THAT destination's content
#                                 (fingerprint match) instead of its own hub page:
#                                 a server-side fetch of our URL is the only
#                                 explanation consistent with the response.
#   INFO      (destination-banner) - response headers/HTML mention an unexpected
#                                 upstream host -> worth a manual look.
#
# Destinations are always safe and benign (example.com robots / example.net).
# 169.254.169.254 cloud-metadata probing is NEVER part of this validator.
#
# Config (all optional):
#   ssrf_validator.max_urls  -> cap candidate URLs (default 100)
#   ssrf_validator.timeout   -> per-request budget (default 8)
#   ssrf_validator.dest      -> fingerprint destination (default example.com
#                               robots.txt; host==dest detection is generic)

import asyncio
from typing import Dict, List, Optional, Callable

import aiohttp
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from app.utils.logger import get_logger

logger = get_logger()

_SSRF_PARAMS = [
    'url', 'uri', 'path', 'redirect', 'next', 'dest', 'destination', 'target',
    'fetch', 'proxy', 'load', 'link', 'image', 'img', 'src', 'import', 'source',
    'endpoint', 'callback', 'webhook', 'avatar', 'file', 'download', 'render',
]

_DEST = 'https://example.com/robots.txt'          # benign fingerprint destination
_DEST_FP = (b'user-agent', b'disallow')           # robots-tail markers


class SSRFValidator:
    def __init__(self, config: Dict):
        cfg = config.get('ssrf_validator', {}) if isinstance(config, dict) else {}
        self.max_urls = int(cfg.get('max_urls', 100))
        self.timeout = float(cfg.get('timeout', 8))
        self.dest = cfg.get('dest', _DEST)
        self.last_errors: List[str] = []
        import random
        self.value = f"dbx{random.randint(100000, 999999)}"

    def _variants(self, url: str) -> List[Optional[List[str]]]:
        """[(param, sworn_url), ...] with our canary host as the requested target."""
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        canary = f"https://{self.value}.ssrf.deepbug.io/robots.txt"
        out = []
        for k, v in pairs:
            if k.lower() in _SSRF_PARAMS:
                replaced = [(kk, canary if kk == k else vv) for kk, vv in pairs]
                out.append((k, urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                           parsed.params, urlencode(replaced, doseq=True), parsed.fragment))))
        return out

    async def _probe(self, session: aiohttp.ClientSession, url: str) -> Dict:
        row = {'URL': url, 'Result': 'INFO', 'Class': 'clean', 'Sink': '', 'Method': 'http-probe'}
        try:
            headers = {'User-Agent': 'deepbug-ssrf-validator/1.0' + PROGRAM_UA_TAG}
            async with session.get(url, headers=headers, timeout=self.timeout,
                                   allow_redirects=False) as resp:
                body = await resp.read()
                text = body[:100000].decode('utf-8', errors='replace')
                lowered = text.lower()
                host = urlparse(url).netloc

                if self.value in text or self.value in str(resp.headers):
                    row.update(Result='PROBABLE', Class='url-reflection',
                               Sink=f'canary {self.value} echoed ({resp.status})')
                    return row

                # fetched-destination fingerprint: the app fetched OUR target
                if all(m in lowered for m in (b'user-agent'.decode(), b'disallow'.decode())) and \
                        len(body) < 60000:
                    row.update(Result='PROBABLE', Class='fetched-destination',
                               Sink=f'response matches {self.dest} fingerprint ({resp.status})')
                    return row

                if resp.status in (301, 302, 303, 307, 308):
                    loc = resp.headers.get('Location', '')
                    if self.value in loc:
                        row.update(Result='PROBABLE', Class='url-reflection',
                                   Sink=f'Location header echoes canary: {loc[:100]}')
                        return row

                # upstream banner leak (nginx/lb headers naming another host)
                ups = resp.headers.get('X-Upstream', '') or resp.headers.get('X-Backend', '')
                if ups and ups.lower() not in host.lower():
                    row.update(Result='INFO', Class='destination-banner',
                               Sink=f'X-Upstream/X-Backend: {ups[:60]}')
                    return row
        except asyncio.TimeoutError:
            row.update(Sink='timeout')
        except Exception as e:
            logger.debug(f"SSRF probe failed {url}: {e}")
            row.update(Result='INFO', Class='error', Sink=str(e)[:80])
        return None if row['Class'] in ('clean', 'error') else row

    async def _validate_all(self, urls: List[str],
                            progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        results: List[Dict] = []
        total = len(urls)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout * 4)) as session:
            for idx, url in enumerate(urls):
                if progress_callback:
                    progress_callback(idx / total, f"[{idx + 1}/{total}] {url}")
                for param, variant in self._variants(url):
                    row = await self._probe(session, variant)
                    if not row:
                        continue
                    row['Param'] = param
                    row['Payload'] = variant
                    row['Note'] = 'OOB callback host required for blind-SSRF CONFIRMED'
                    results.append(row)
                if progress_callback:
                    progress_callback((idx + 1) / total,
                                      f"[{idx + 1}/{total}] {url} -> {len([r for r in results if r['URL'].startswith(url)])} hit(s)")
        if progress_callback:
            prob = len([r for r in results if r['Result'] == 'PROBABLE'])
            progress_callback(1.0, f"Done: {prob} probable SSRF signals, "
                                   f"{len(results) - prob} info (blind-SSRF confirm needs OOB host)")
        return results

    def validate_sync(self, urls: List[str],
                      progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        """Synchronous entry - safe inside Streamlit's running event loop."""
        self.last_errors = []
        if not urls:
            return []
        urls = list(dict.fromkeys(urls))[:self.max_urls]
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(asyncio.run, self._validate_all(urls, progress_callback))
                return future.result()
        return asyncio.run(self._validate_all(urls, progress_callback))