# modules/tools/open_redirect_validator.py
# Open-redirect CONFIRMATION on top of open_redirect_scanner's candidates.
#
# Two phases per candidate URL:
#   HTTP     - swap redirect-style params for a unique canary URL; if the
#              Location header (or a 3xx chain) ends on the canary host ->
#              CONFIRMED (server-side open redirect).
#   Browser  - when the response bodies reference the canary (JS handed it to
#              location.href / location.assign / meta refresh), load it in
#              headless Chromium and compare the FINAL URL against the canary
#              host -> CONFIRMED (client-side open redirect).
#
# Canary hosts are unique-per-run and never operated - confirmation only needs
# the final-URL host to match our random marker, so no callback infra required.
# Only GET requests are ever sent.
#
# Config (all optional):
#   open_redirect_validator.max_urls  -> cap candidate URLs (default 100)
#   open_redirect_validator.timeout   -> per-request budget (default 8)
#   open_redirect_validator.browser   -> enable headless JS redirect check (default True)

import asyncio
import random
import re
import urllib.parse
from typing import Dict, List, Optional, Callable

import aiohttp

from app.utils.logger import get_logger

logger = get_logger()

_REDIRECT_PARAMS = ['g', 'r', 'l', 'to', 'link2', 'target_url', 'redirect_url', 'redirect_uri',
    'url', 'redirect', 'next', 'return', 'return_url', 'return_to', 'dest',
    'destination', 'goto', 'target', 'rurl', 'qurl', 'link', 'out', 'view',
    'dir', 'continue', 'callback', 'redir', 'redirect_url', 'image_url',
    'imageurl', 'load', 'proxy', 'u', 'url2', 'go', 'jump', 'forward',
    'ref', 'from_url', 'path', 'page', 'fetch', 'endpoint', 'data', 'src',
]


class OpenRedirectValidator:
    def __init__(self, config: Dict):
        cfg = config.get('open_redirect_validator', {}) if isinstance(config, dict) else {}
        self.max_urls = int(cfg.get('max_urls', 100))
        self.timeout = float(cfg.get('timeout', 8))
        self.enable_browser = bool(cfg.get('browser', True))
        self.chromium_path = None
        self.has_playwright = False
        if self.enable_browser:
            try:
                from app.modules.tools.dom_xss_validator import DOMXSSValidator
                probe = DOMXSSValidator(config)
                self.chromium_path = probe.chromium_path
                self.has_playwright = probe.has_playwright
            except Exception as e:
                logger.debug(f"OpenRedirectValidator: browser backend unavailable: {e}")
        self.last_errors: List[str] = []
        self.value = f"dbx{random.randint(100000, 999999)}"
        self.oob_uuid = str(cfg.get('oob_uuid', '') or '').strip()
        self.oob_poll_wait = float(cfg.get('oob_poll_wait', 6))
        self.oob_base = f"https://webhook.site/{self.oob_uuid}" if self.oob_uuid else ""

    @staticmethod
    def _canary_host(value: str) -> str:
        return f"{value}.redirect.deepbug.io"

    def _bind_canary(self) -> str:
        self.value = f"dbx{random.randint(100000, 999999)}"
        return self.value

    def _variants(self, url: str, canary: str) -> List[str]:
        """Rewrite redirect-style params with the canary; raw + encoded + protocol-relative."""
        parsed = urllib.parse.urlparse(url)
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        out: List[str] = []
        if self.oob_base:
            # OOB mode: the redirect must land on a host we can observe
            targets = [f"{self.oob_base}?v={self.value}",
                       f"//webhook.site/{self.oob_uuid}?v={self.value}",
                       self.oob_base]
        else:
            targets = [f"https://{canary}/", f"//{canary}/", f"https://{canary}"]
        for k, _ in pairs:
            key = k.lower()
            if key not in _REDIRECT_PARAMS:
                continue
            for t in targets:
                replaced = [(kk, t if kk.lower() == key else vv) for kk, vv in pairs]
                nq = urllib.parse.urlencode(replaced, doseq=True)
                raw_nq = nq.replace('%2F', '/').replace('%3A', ':').replace('%2F', '/')
                out.append(urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, raw_nq, parsed.fragment)))
        return out

    @staticmethod
    def _judge(status: int, final: str, sent: str, canary: str, method: str) -> Optional[Dict]:
        if not final or not sent:
            return None
        if final.lower() == sent.lower():
            return None  # no navigation happened - canary is only where we sent it
        final_l = final.lower()
        if canary in final_l:
            parsed = urllib.parse.urlparse(final_l)
            if parsed.netloc and canary in parsed.netloc.lower():
                return {'Result': 'CONFIRMED', 'Class': 'redirect-offsite',
                        'Sink': f'{status} -> {final[:120]}', 'Method': method}
            return {'Result': 'PROBABLE', 'Class': 'redirect-onsite',
                    'Sink': f'{status} -> {final[:120]}', 'Method': method}
        return None

    @staticmethod
    def _judge_request(request_url: str, sent: str, canary: str) -> Optional[Dict]:
        """A request the BROWSER made (proves a JS/meta/HTTP navigation fired),
        even if the target host does not resolve."""
        if not request_url or not sent:
            return None
        if request_url.lower().startswith(sent.lower()):
            return None  # the original page request itself
        parsed = urllib.parse.urlparse(request_url)
        if parsed.netloc and canary in parsed.netloc.lower():
            return {'Result': 'CONFIRMED', 'Class': 'redirect-offsite',
                    'Sink': f'browser requested -> {request_url[:120]}', 'Method': 'headless-browser'}
        if canary in request_url.lower():
            return {'Result': 'PROBABLE', 'Class': 'redirect-onsite',
                    'Sink': f'browser requested -> {request_url[:120]}', 'Method': 'headless-browser'}
        return None

    async def _http_probe(self, session: aiohttp.ClientSession, url: str,
                          canary: str) -> Optional[Dict]:
        try:
            async with session.get(url, timeout=self.timeout,
                                   allow_redirects=False) as resp:
                loc = (resp.headers.get('Location') or '').strip()
                status = resp.status
                if loc:
                    if self.oob_base and self.value in loc and 'webhook.site' in loc:
                        # OOB mode: redirect leaves to webhook.site carrying our
                        # canary -> offsite by construction
                        hit = {'Result': 'CONFIRMED', 'Class': 'redirect-offsite',
                               'Sink': f'{status} -> {loc[:120]}', 'Method': 'http-location'}
                    else:
                        match_key = self.value if self.oob_base else canary
                        hit = self._judge(status, loc, url, match_key, 'http-location')
                    if hit:
                        hit['URL'] = url
                        return hit
                if status in (301, 302, 303, 307, 308) and not loc:
                    # browser-negotiated redirect, no location - browser phase
                    return {'URL': url, 'status': status}
                body = (await resp.text(errors='replace'))[:20000]
                if canary.lower() in body.lower():
                    # server echoed our canary without redirecting via Location:
                    # likely a JS redirect or a dashboard echo - hand to browser
                    return {'URL': url, 'body_canary': True}
                if status < 400:
                    # live page: may still JS-redirect (location.href = param) -
                    # confirm in the browser even without an HTTP redirect
                    return {'URL': url, 'status': status}
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logger.debug(f"Open redirect HTTP probe failed {url}: {e}")
            return None
        return None

    async def _poll_oob(self, session: aiohttp.ClientSession) -> List[str]:
        """Poll webhook.site for callbacks carrying our canary value."""
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
    def _browser_probe(self, url: str, canary: str) -> Optional[Dict]:
        from playwright.sync_api import sync_playwright
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    executable_path=str(self.chromium_path),
                    args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'])
                try:
                    page = browser.new_page()
                    captured: List[Dict] = []

                    def _on_request(req):
                        try:
                            if canary.lower() in req.url.lower():
                                captured.append(req.url)
                        except Exception:
                            pass

                    page.on('request', _on_request)
                    page.goto(url, timeout=10000, wait_until='load')
                    page.wait_for_timeout(1200)
                    for req_url in captured:
                        hit = self._judge_request(req_url, url, canary)
                        if hit:
                            hit['URL'] = url
                            return hit
                    final = page.url
                    hit = self._judge(200, final, url, canary, 'headless-browser')
                    if hit:
                        hit['URL'] = url
                    return hit
                finally:
                    browser.close()
        except Exception as e:
            logger.debug(f"Open redirect browser probe failed {url}: {e}")
            self.last_errors.append(f"{url}: {str(e)[:120]}")
            return None

    async def _validate_all(self, urls: List[str],
                            progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        results: List[Dict] = []
        seen: set = set()
        total = len(urls)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout * 4)) as session:
            for idx, url in enumerate(urls):
                if progress_callback:
                    progress_callback(idx / total, f"[{idx + 1}/{total}] {url}")
                canary_host = self._canary_host(self.value)
                for candidate in self._variants(url, canary_host):
                    row = await self._http_probe(session, candidate, canary_host)
                    if not row:
                        continue
                    if (row.get('body_canary') or row.get('status') is not None) and self.has_playwright:
                        hit = await asyncio.to_thread(self._browser_probe, candidate, canary_host)
                        if hit:
                            key = (hit['URL'], hit['Result'])
                            if key not in seen:
                                seen.add(key)
                                results.append(hit)
                    else:
                        key = (row['URL'], row['Result'])
                        if key not in seen:
                            seen.add(key)
                            results.append(row)
                if progress_callback:
                    progress_callback((idx + 1) / total,
                                      f"[{idx + 1}/{total}] {url} -> {len([r for r in results if r['URL'].startswith(url)])} hit(s)")
            # OOB: confirm end-to-end navigation to the external host
            if self.oob_uuid and results:
                if progress_callback:
                    progress_callback(0.97, "Polling OOB callback host (webhook.site)...")
                callbacks = await self._poll_oob(session)
                if callbacks:
                    results.append({
                        'URL': 'OOB callback', 'Result': 'CONFIRMED',
                        'Class': 'oob-callback',
                        'Sink': f'redirect followed to external host: {callbacks[0]}',
                        'Method': 'oob-callback',
                        'Note': 'end-to-end: navigation landed on webhook.site with our canary',
                    })
        if progress_callback:
            confirmed = len([r for r in results if r['Result'] == 'CONFIRMED'])
            progress_callback(1.0, f"Done: {confirmed} confirmed open redirects, {len(results) - confirmed} potential")
        return results

    def validate_sync(self, urls: List[str],
                      progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        """Synchronous entry - safe inside Streamlit's running event loop."""
        self.last_errors = []
        self._bind_canary()
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