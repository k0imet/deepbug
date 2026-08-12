# modules/tools/supply_chain_auditor.py
# Supply-chain audit (Huli's "Beyond XSS" ch.18).
#
# Crawls live pages and inventories every externally-loaded script/stylesheet:
#   - third-party resource WITHOUT integrity= attribute  -> tamper surface
#   - known-hostile/abandoned CDN (polyfill.io, rawgit...) -> CRITICAL
#   - cleartext http:// resource                          -> downgrade surface
#   - integrity present but weak algo (md5/sha1)          -> downgrade
#
# Companion to the dependency-confusion scanner: that one finds packages that
# could be hijacked at install time; this one finds resources that can be
# hijacked at LOAD time in the user's browser.
#
# Config (optional):
#   supply_chain.max_pages   -> pages to crawl (default 25)
#   supply_chain.extra_watchlist -> dict {cdn_substring: reason}

import asyncio
import re
from html.parser import HTMLParser
from typing import List, Dict, Optional, Callable
from app.utils.url_utils import urlparse

import httpx

from app.utils.logger import get_logger

logger = get_logger()

# Known-hostile / abandoned / high-risk CDN hosts (substring match)
DEFAULT_WATCHLIST = {
    "polyfill.io": "COMPROMISED 2024 - served malware to 100k+ sites, remove immediately",
    "rawgit.com": "abandoned service - domain lapsed, takeover-able",
    "raw.githubusercontent.com": "not a CDN - no caching headers, rate-limited, fragile",
    "gitlab.com/explore": "user-controllable content served as script",
}


class ResourceParser(HTMLParser):
    """Extract script[src] and link[href] with integrity/crossorigin attributes."""

    def __init__(self):
        super().__init__()
        self.resources: List[Dict] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script" and a.get("src"):
            self.resources.append({
                "type": "script", "url": a["src"],
                "integrity": a.get("integrity", ""),
                "crossorigin": a.get("crossorigin", ""),
            })
        elif tag == "link" and a.get("href") and a.get("rel") and \
                any(r in ("stylesheet", "preload", "modulepreload") for r in
                    (a["rel"] if isinstance(a["rel"], list) else [a["rel"]])):
            self.resources.append({
                "type": "stylesheet", "url": a["href"],
                "integrity": a.get("integrity", ""),
                "crossorigin": a.get("crossorigin", ""),
            })


class SupplyChainAuditor:
    def __init__(self, config: Dict):
        self.config = config
        sc_cfg = config.get('supply_chain', {})
        self.max_pages = int(sc_cfg.get('max_pages', 25))
        self.watchlist = dict(DEFAULT_WATCHLIST)
        self.watchlist.update(sc_cfg.get('extra_watchlist', {}))
        self.last_errors: List[str] = []

    # -----------------------------------------------------------------
    # Classification
    # -----------------------------------------------------------------
    @staticmethod
    def _registrable(host: str) -> str:
        parts = host.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else host

    def _assess(self, page_host: str, res: Dict) -> Optional[Dict]:
        url = res["url"]
        if url.startswith("//"):
            url = "https:" + url
        if url.startswith("/") or not url.startswith("http"):
            return None  # relative/same-origin path - not a supply-chain surface

        res_host = urlparse(url).netloc.lower()
        third_party = self._registrable(res_host) != self._registrable(page_host)

        findings = []
        risk = None
        notes = []

        # 1) watchlist CDNs - always critical regardless of integrity
        for sig, reason in self.watchlist.items():
            if sig in res_host:
                risk = "CRITICAL"
                notes.append(f"watchlist CDN '{res_host}': {reason}")
                break

        # 2) cleartext
        if url.startswith("http://"):
            notes.append("cleartext http:// - MITM-downgrade surface")
            risk = risk or "HIGH"

        # 3) integrity analysis (third-party only - first-party SRI is optional)
        if third_party:
            if not res["integrity"]:
                notes.append("third-party resource with NO integrity= - CDN compromise executes JS in your origin")
                risk = risk or "HIGH"
            elif re.match(r'^(md5|sha1)-', res["integrity"]):
                notes.append(f"weak integrity algo: {res['integrity'].split('-')[0]}")
                risk = risk or "MEDIUM"

        if risk is None:
            return None

        return {
            "Page": None,  # filled by caller
            "Resource": url,
            "Type": res["type"],
            "Host": res_host,
            "ThirdParty": third_party,
            "Integrity": res["integrity"] or "(none)",
            "Risk": risk,
            "Notes": "; ".join(notes),
        }

    # -----------------------------------------------------------------
    # Crawl
    # -----------------------------------------------------------------
    async def _audit_page(self, client: httpx.AsyncClient, page_url: str) -> List[Dict]:
        try:
            resp = await client.get(page_url)
            if "text/html" not in resp.headers.get("content-type", ""):
                return []
        except Exception as e:
            logger.debug(f"SRI audit fetch failed {page_url}: {e}")
            return []

        parser = ResourceParser()
        try:
            parser.feed(resp.text)
        except Exception:
            pass

        page_host = urlparse(page_url).netloc
        rows = []
        for res in parser.resources:
            hit = self._assess(page_host, res)
            if hit:
                hit["Page"] = page_url
                rows.append(hit)
        return rows

    async def _audit_all(self, pages: List[str],
                         progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        results: List[Dict] = []
        total = max(len(pages), 1)
        sem = asyncio.Semaphore(10)

        async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
            async def one(idx, page):
                async with sem:
                    if progress_callback:
                        progress_callback(idx / total, f"[{idx + 1}/{len(pages)}] {page}")
                    results.extend(await self._audit_page(client, page))

            await asyncio.gather(*[one(i, p) for i, p in enumerate(pages)])

        if progress_callback:
            crit = len([r for r in results if r["Risk"] == "CRITICAL"])
            progress_callback(1.0, f"Done: {crit} critical, {len(results) - crit} other risks")
        return results

    def scan(self, pages: List[str],
             progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        """Synchronous entry - safe inside Streamlit's running event loop."""
        self.last_errors = []
        if not pages:
            return []
        pages = list(dict.fromkeys(pages))[:self.max_pages]

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(asyncio.run, self._audit_all(pages, progress_callback)).result()
        return asyncio.run(self._audit_all(pages, progress_callback))