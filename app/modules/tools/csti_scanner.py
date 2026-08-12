# modules/tools/csti_scanner.py
# CSTI/SSTI scanner (Huli's "Beyond XSS" ch.15) - kxss-style confirmation flow.
#
# For each query parameter of each candidate URL: inject arithmetic template
# probes and check whether the server/client stack EVALUATES them:
#   ?x=DBUG{{7*7}}DBUG  -> response contains "DBUG49DBUG"  => CONFIRMED
#   probe reflected raw  => POTENTIAL (injection point, engine unknown)
#
# Engine fingerprinting (SSTI side):
#   {{7*'7'}} -> '7777777' = Jinja2/Twig(python/php string mult) | '49' = others
#   ${7*7}    -> FreeMarker/Velocity (Java)
#   #{7*7}    -> Ruby ERB-ish / Spring
#   <%= 7*7 %>-> ERB/ejs
#
# Config (optional):
#   csti_scanner.max_urls       -> cap (default 30)
#   csti_scanner.max_params     -> params per URL (default 5)

import asyncio
import random
import re
from typing import List, Dict, Optional, Callable
from app.utils.url_utils import urlparse
from urllib.parse import parse_qsl, urlencode, urlunparse

import httpx

from app.utils.logger import get_logger

logger = get_logger()

# probe template -> (payload, evaluated_marker, engine_hint)
PROBES = [
    ("{{7*7}}", "49", "twig/jinja2/angularjs/vue"),
    ("${7*7}", "49", "freemarker/velocity (java)"),
    ("<%= 7*7 %>", "49", "erb/ejs"),
    ("#{7*7}", "49", "ruby/spring"),
    ("{{7*'7'}}", "7777777", "jinja2/twig (string multiplication)"),
]


class CSTIScanner:
    def __init__(self, config: Dict):
        self.config = config
        c_cfg = config.get('csti_scanner', {})
        self.max_urls = int(c_cfg.get('max_urls', 30))
        self.max_params = int(c_cfg.get('max_params', 5))
        self.last_errors: List[str] = []

    def _mutate_url(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
        qs[param] = value
        return urlunparse(parsed._replace(query=urlencode(qs)))

    async def _probe_param(self, client: httpx.AsyncClient, url: str, param: str) -> Optional[Dict]:
        canary = f"DBUG{random.randint(1000, 9999)}"
        reflections = []
        for payload, marker, engine in PROBES:
            probe = f"{canary}{payload}{canary}"
            try:
                resp = await client.get(self._mutate_url(url, param, probe))
            except Exception as e:
                logger.debug(f"CSTI probe failed {url}?{param}: {e}")
                return None

            evaluated = f"{canary}{marker}{canary}"
            reflected = probe in resp.text

            if evaluated in resp.text:
                return {
                    "URL": url,
                    "Parameter": param,
                    "Payload": probe,
                    "Result": "CONFIRMED",
                    "Engine": engine,
                    "Evidence": f"'{probe}' evaluated to '{evaluated}' in {resp.status_code} response",
                }
            if reflected:
                reflections.append(payload)

        if reflections:
            return {
                "URL": url,
                "Parameter": param,
                "Payload": reflections[0],
                "Result": "POTENTIAL",
                "Engine": "unknown (reflected raw)",
                "Evidence": "template syntax reflected without evaluation - try engine-specific payloads in Burp",
            }
        return None

    async def _scan_all(self, urls: List[str],
                        progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        results: List[Dict] = []
        # Only URLs that actually have query params are testable
        testable = []
        for u in urls:
            params = [k for k, _ in parse_qsl(urlparse(u).query, keep_blank_values=True)]
            if params:
                testable.append((u, params[:self.max_params]))

        total = max(len(testable), 1)
        sem = asyncio.Semaphore(8)

        async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
            async def one(idx, url, params):
                async with sem:
                    if progress_callback:
                        progress_callback(idx / total, f"[{idx + 1}/{len(testable)}] {url}")
                    for p in params:
                        hit = await self._probe_param(client, url, p)
                        if hit:
                            results.append(hit)
                            if hit["Result"] == "CONFIRMED":
                                break  # confirmed on this URL - move on

            await asyncio.gather(*[one(i, u, ps) for i, (u, ps) in enumerate(testable)])

        if progress_callback:
            confirmed = len([r for r in results if r["Result"] == "CONFIRMED"])
            progress_callback(1.0, f"Done: {confirmed} confirmed, {len(results) - confirmed} potential")
        return results

    def scan(self, urls: List[str],
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(asyncio.run, self._scan_all(urls, progress_callback)).result()
        return asyncio.run(self._scan_all(urls, progress_callback))