# modules/tools/pp_validator.py
# Active prototype pollution VALIDATION - the "kxss for proto pollution".
# The JS analyzer finds candidate sinks statically; this module proves them.
#
# Two phases per target URL:
#   Phase B (browser, definitive): inject ?__proto__[canary]=value variants,
#           load the page in headless Chromium, evaluate ({}).canary.
#           If the canary lands on Object.prototype -> CONFIRMED.
#   Phase A (reflection, heuristic): POST JSON bodies with __proto__ keys to
#           API-ish endpoints; reflection of the canary -> POTENTIAL
#           (server-side parsers / templates that merge user JSON).
#
# Config (all optional):
#   pp_validator.max_urls        -> cap URLs validated per run (default 15)
#   pp_validator.browser         -> enable browser confirmation (default True)
#   pp_validator.page_timeout_ms -> per-page load budget (default 8000)
#   tools.paths.chromium         -> browser binary (default: auto-detect)

import asyncio
import json
import random
import re
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Callable
from app.utils.url_utils import urlparse
from urllib.parse import urlencode, parse_qsl, urlunparse

import httpx

from app.utils.logger import get_logger

logger = get_logger()

# Payload key paths that reach Object.prototype through vulnerable deep-merges.
# {m} = marker key, {v} = marker value.
QUERY_PAYLOADS = [
    "__proto__[{m}]={v}",
    "__proto__.{m}={v}",
    "constructor[prototype][{m}]={v}",
    "constructor.prototype.{m}={v}",
]
HASH_PAYLOADS = [
    "__proto__[{m}]={v}",
    "constructor.prototype.{m}={v}",
]


class PrototypePollutionValidator:
    def __init__(self, config: Dict):
        self.config = config
        pp_cfg = config.get('pp_validator', {})
        self.max_urls = int(pp_cfg.get('max_urls', 15))
        self.enable_browser = bool(pp_cfg.get('browser', True))
        self.page_timeout = int(pp_cfg.get('page_timeout_ms', 8000))

        self.marker = 'deepbug_pp'
        self.value = f"dbpp{random.randint(10000, 99999)}"

        self.chromium_path = self._resolve_chromium(config.get('tools', {}).get('paths', {}).get('chromium'))
        self.has_playwright = False
        if self.enable_browser:
            try:
                import playwright.sync_api  # noqa: F401
                self.has_playwright = self.chromium_path is not None
            except ImportError:
                logger.warning("PPValidator: playwright not installed - browser confirmation disabled "
                               "(pip install playwright). Reflection heuristics still active.")
        self.last_errors: List[str] = []

    @staticmethod
    def _resolve_chromium(configured: Optional[str]) -> Optional[Path]:
        candidates = []
        if configured:
            candidates.append(Path(configured).expanduser())
        for name in ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', 'chrome'):
            hit = shutil.which(name)
            if hit:
                candidates.append(Path(hit))
        candidates += [Path('/usr/bin/chromium'), Path('/usr/bin/chromium-browser'),
                       Path('/usr/bin/google-chrome'), Path('/snap/bin/chromium')]
        for c in candidates:
            try:
                if c.is_file():
                    return c
            except OSError:
                continue
        return None

    # -----------------------------------------------------------------
    # URL helpers
    # -----------------------------------------------------------------
    @staticmethod
    def _with_query(url: str, payload: str) -> str:
        """Append a raw payload pair to the QUERY (fragment-safe). Payload is
        NOT url-encoded - brackets/dots must survive to the vulnerable parser."""
        from urllib.parse import urlunparse
        parsed = urlparse(url)
        # NOTE: urlunparse inserts the '?' itself - the query component must
        # NOT include a leading separator.
        query = parsed.query + ('&' if parsed.query else '') + payload
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                           query, parsed.fragment))

    # =================================================================
    # Phase B: browser confirmation (definitive for client-side PP)
    # =================================================================
    def _browser_probe(self, url: str, vector: str, full_url: str) -> Optional[Dict]:
        """Load full_url in headless Chromium; return a result row if Object.prototype is polluted."""
        from playwright.sync_api import sync_playwright

        check_js = f"(() => {{ try {{ return ({{}}).{self.marker} ?? null }} catch(e) {{ return null }} }})()"
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    executable_path=str(self.chromium_path),
                    args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'])
                try:
                    page = browser.new_page()
                    page.goto(full_url, timeout=self.page_timeout, wait_until='domcontentloaded')
                    page.wait_for_timeout(700)  # let inline scripts run
                    leaked = page.evaluate(check_js)
                    if leaked == self.value:
                        return {
                            'URL': url,
                            'Vector': vector,
                            'Payload': full_url,
                            'Result': 'CONFIRMED',
                            'Evidence': f"({{}}).{self.marker} === '{leaked}' -> Object.prototype polluted",
                            'Method': 'headless-browser',
                        }
                finally:
                    browser.close()
        except Exception as e:
            logger.debug(f"Browser probe failed for {full_url}: {e}")
            self.last_errors.append(f"browser probe {url}: {str(e)[:150]}")
        return None

    def _validate_url_browser(self, url: str) -> List[Dict]:
        findings = []
        for tpl in QUERY_PAYLOADS:
            payload = tpl.format(m=self.marker, v=self.value)
            hit = self._browser_probe(url, 'query', self._with_query(url, payload))
            if hit:
                findings.append(hit)
                break  # one confirmation per URL/vector is enough
        for tpl in HASH_PAYLOADS:
            payload = tpl.format(m=self.marker, v=self.value)
            hit = self._browser_probe(url, 'hash', f"{url}#{payload}")
            if hit:
                findings.append(hit)
                break
        return findings

    # =================================================================
    # Phase A: JSON-body reflection heuristics (server-side parsers)
    # =================================================================
    async def _probe_json_body(self, client: httpx.AsyncClient, url: str) -> Optional[Dict]:
        body = {"__proto__": {self.marker: self.value}, "deepbug_probe": "1"}
        try:
            resp = await client.post(url, json=body)
            # Canary value reflected back -> a parser accepted our __proto__ merge input
            if self.value in resp.text:
                return {
                    'URL': url,
                    'Vector': 'json-body',
                    'Payload': json.dumps(body),
                    'Result': 'POTENTIAL',
                    'Evidence': f"canary '{self.value}' reflected in {resp.status_code} JSON response",
                    'Method': 'reflection',
                }
        except Exception as e:
            logger.debug(f"JSON body probe failed for {url}: {e}")
        return None

    async def _probe_query_reflection(self, client: httpx.AsyncClient, url: str) -> Optional[Dict]:
        """Query canary reflected inside a <script> block -> PP/XSS-adjacent sink worth a manual look."""
        payload = QUERY_PAYLOADS[0].format(m=self.marker, v=self.value)
        try:
            resp = await client.get(self._with_query(url, payload))
            if self.value in resp.text:
                scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL | re.IGNORECASE)
                in_script = any(self.value in s for s in scripts)
                return {
                    'URL': url,
                    'Vector': 'query',
                    'Payload': payload,
                    'Result': 'POTENTIAL',
                    'Evidence': f"canary reflected in {'<script> context' if in_script else 'response body'}",
                    'Method': 'reflection',
                }
        except Exception as e:
            logger.debug(f"Query reflection probe failed for {url}: {e}")
        return None

    # =================================================================
    # Main entry
    # =================================================================
    async def _validate_all(self, urls: List[str],
                            progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        results: List[Dict] = []
        total = len(urls)

        async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
            for idx, url in enumerate(urls):
                base_prog = idx / total
                if progress_callback:
                    progress_callback(base_prog, f"[{idx + 1}/{total}] {url}")

                # Browser phase: definitive client-side confirmation
                if self.has_playwright:
                    hits = await asyncio.to_thread(self._validate_url_browser, url)
                    results.extend(hits)

                # Reflection heuristics (always - cheap, catches server-side surfaces)
                hit = await self._probe_json_body(client, url)
                if hit:
                    results.append(hit)
                if not any(r['URL'] == url and r['Vector'] == 'query' for r in results):
                    hit = await self._probe_query_reflection(client, url)
                    if hit:
                        results.append(hit)

                if progress_callback:
                    n = len([r for r in results if r['URL'] == url])
                    progress_callback((idx + 1) / total, f"[{idx + 1}/{total}] {url} -> {n} findings")

        if progress_callback:
            confirmed = len([r for r in results if r['Result'] == 'CONFIRMED'])
            progress_callback(1.0, f"Done: {confirmed} confirmed, {len(results) - confirmed} potential")
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