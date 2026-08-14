from app.utils.user_agents import PROGRAM_UA_TAG
# modules/tools/ssrf_validator.py
# SSRF confirmation for candidate URL-fetching parameters - the validation
# layer on top of ssrf_scanner's heuristic findings.
#
# Confirmation tiers:
#
#   CONFIRMED (oob-callback) - an external OOB callback host (webhook.site by
#                              default) records a request to our unique canary
#                              URL: the app provably made a server-side request
#                              to an attacker-chosen URL. The gold standard for
#                              blind SSRF.
#   PROBABLE  (url-reflection)  - our canary URL (unique host) is echoed back in
#                                 the response body or headers.
#   PROBABLE  (fetched-destination) - the server returned a controlled
#                                 destination's content (fingerprint match).
#   INFO      (destination-banner) - response headers/HTML mention an unexpected
#                                 upstream host -> worth a manual look.
#
# Destinations are always safe and benign. 169.254.169.254 cloud-metadata
# probing is NEVER part of this validator.
#
# Config (all optional):
#   ssrf_validator.max_urls  -> cap candidate URLs (default 100)
#   ssrf_validator.timeout   -> per-request budget (default 8)
#   ssrf_validator.dest      -> fingerprint destination (default example.com
#                               robots.txt; host==dest detection is generic)
#   ssrf_validator.oob_uuid  -> webhook.site token UUID. When set, canaries
#                               become https://webhook.site/{uuid}?v={value}
#                               and the request log is polled after the probes
#                               to upgrade findings to CONFIRMED on callback.
#   ssrf_validator.oob_poll_wait -> seconds to wait before polling (default 6)

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
        self.oob_uuid = str(cfg.get('oob_uuid', '') or '').strip()
        self.oob_poll_wait = float(cfg.get('oob_poll_wait', 6))
        self.oob_base = f"https://webhook.site/{self.oob_uuid}" if self.oob_uuid else ""

    # ------------------------------------------------------------------ OOB
    async def _poll_oob(self, session: aiohttp.ClientSession) -> List[str]:
        """Poll webhook.site for callbacks carrying our canary value.
        Returns the list of matched callback URLs."""
        if not self.oob_uuid:
            return []
        hits = []
        try:
            await asyncio.sleep(self.oob_poll_wait)
            url = f"https://webhook.site/token/{self.oob_uuid}/requests"
            async with session.get(url, timeout=15) as r:
                if r.status != 200:
                    return []
                data = await r.json(content_type=None)
            for req in (data or {}).get('data', []) or []:
                hay = str(req.get('url', '')) + str(req.get('query', ''))
                if self.value in hay:
                    hits.append(str(req.get('url', ''))[:160])
        except Exception as e:
            logger.debug(f"OOB poll failed: {e}")
        return hits

    def _variants(self, url: str) -> List[Optional[List[str]]]:
        """[(param, sworn_url), ...] with our canary as the requested target.
        With an OOB configured, the canary is a webhook.site URL carrying our
        unique value in the query - a callback is definitive blind-SSRF proof."""
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if self.oob_base:
            canary = f"{self.oob_base}?v={self.value}"
        else:
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
            # OOB: poll the callback host once and upgrade matching findings
            if self.oob_uuid and results:
                if progress_callback:
                    progress_callback(0.97, "Polling OOB callback host (webhook.site)...")
                callbacks = await self._poll_oob(session)
                if callbacks:
                    for row in results:
                        if row.get('Result') in ('INFO', 'PROBABLE'):
                            row.update(Result='CONFIRMED', Class='oob-callback',
                                       Sink=f'callback received: {callbacks[0]}',
                                       Note='blind SSRF: server-side request to attacker URL observed on OOB host')
        if progress_callback:
            prob = len([r for r in results if r['Result'] in ('PROBABLE', 'CONFIRMED')])
            progress_callback(1.0, f"Done: {prob} probable/confirmed SSRF signals, "
                                   f"{len([r for r in results if r['Result'] == 'CONFIRMED'])} OOB-confirmed")
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