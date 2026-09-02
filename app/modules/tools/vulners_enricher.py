# modules/tools/vulners_enricher.py
# Vulners.com enrichment — CVE ID + CPE/tech-version → CVSS/EPSS/exploit/refs
#
# Wraps https://vulners.com/api/v3/search/id  (by CVE) and
# https://vulners.com/api/v3/search/lucene (by Lucene query, e.g. cpe:"nginx 1.18")
#
# Used as:
#   enrich = VulnersEnricher(config)
#   data = await enrich.lookup_id("CVE-2026-3909")  # -> vulners doc
#   results = await enrich.enrich_tech("nginx", "1.18.0")  # -> list of CVEs
#
# Key via config tools.vulners_api_key or env VULNERS_API_KEY (same as Chaos pattern)
# Never logs the key. Cached in data/vulners_cache.sqlite (like dependency_confusion).

import os
import json
import hashlib
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any
import aiohttp
import asyncio

from app.utils.logger import get_logger

logger = get_logger()

VULNERS_ID_URL = "https://vulners.com/api/v3/search/id"
VULNERS_LUCENE_URL = "https://vulners.com/api/v3/search/lucene"
CACHE_DB = Path(__file__).resolve().parent.parent / "data" / "vulners_cache.sqlite"


class VulnersEnricher:
    def __init__(self, config: Dict):
        self.config = config or {}
        self.api_key = (
            self.config.get("tools", {}).get("vulners_api_key")
            or self.config.get("vulners_api_key")
            or os.environ.get("VULNERS_API_KEY")
            or os.environ.get("VULNERS_KEY")
            or ""
        ).strip()
        self.timeout = int(self.config.get("tools", {}).get("vulners_timeout", 12))
        self.enabled = bool(self.api_key)
        if not self.enabled:
            logger.info("VulnersEnricher: no API key (tools.vulners_api_key or VULNERS_API_KEY) — enrichment disabled")
        self._ensure_cache()

    def _ensure_cache(self):
        try:
            CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
            con = sqlite3.connect(str(CACHE_DB))
            con.execute("CREATE TABLE IF NOT EXISTS vulners (key TEXT PRIMARY KEY, value TEXT, ts INTEGER)")
            con.commit()
            con.close()
        except Exception as e:
            logger.debug(f"vulners cache init failed: {e}")

    def _cache_get(self, key: str) -> Optional[Dict]:
        try:
            con = sqlite3.connect(str(CACHE_DB))
            cur = con.execute("SELECT value FROM vulners WHERE key=?", (key,))
            row = cur.fetchone()
            con.close()
            if row:
                return json.loads(row[0])
        except Exception:
            pass
        return None

    def _cache_set(self, key: str, value: Dict):
        try:
            con = sqlite3.connect(str(CACHE_DB))
            con.execute("INSERT OR REPLACE INTO vulners (key, value, ts) VALUES (?, ?, strftime('%s','now'))",
                        (key, json.dumps(value)))
            con.commit()
            con.close()
        except Exception as e:
            logger.debug(f"vulners cache set failed: {e}")

    async def _post(self, session: aiohttp.ClientSession, url: str, payload: Dict) -> Optional[Dict]:
        headers = {"X-Api-Key": self.api_key, "Content-Type": "application/json"}
        try:
            async with session.post(url, json=payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 401:
                    logger.warning("Vulners API: unauthorized — check API key")
                elif resp.status == 429:
                    logger.warning("Vulners API: rate limited (429)")
                else:
                    logger.debug(f"Vulners API {resp.status} for {payload.get('id') or payload.get('query')}")
        except Exception as e:
            logger.debug(f"Vulners POST failed: {e}")
        return None

    async def lookup_id(self, cve_id: str, fields: Optional[List[str]] = None) -> Optional[Dict]:
        """Lookup single CVE by ID, e.g. CVE-2026-3909. Returns vulners document or None."""
        if not self.enabled or not cve_id:
            return None
        cve_id = cve_id.strip().upper()
        cache_key = f"id:{cve_id}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached
        payload = {"id": cve_id, "fields": fields or ["*"]}
        async with aiohttp.ClientSession() as session:
            data = await self._post(session, VULNERS_ID_URL, payload)
            if data and data.get("result") == "OK":
                docs = data.get("data", {}).get("documents", {})
                doc = docs.get(f"CVELIST:{cve_id}") or next(iter(docs.values()), None)
                if doc:
                    self._cache_set(cache_key, doc)
                    return doc
        return None

    async def search_lucene(self, query: str, size: int = 10) -> List[Dict]:
        """Lucene search, e.g. 'cpe:nginx 1.18' or 'nginx'. Returns list of docs."""
        if not self.enabled or not query:
            return []
        cache_key = f"lucene:{hashlib.md5(query.encode()).hexdigest()}:{size}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached.get("docs", [])
        payload = {"query": query, "size": size, "fields": ["*"]}
        async with aiohttp.ClientSession() as session:
            data = await self._post(session, VULNERS_LUCENE_URL, payload)
            if data and data.get("result") == "OK":
                docs = []
                for v in data.get("data", {}).get("search", []):
                    if isinstance(v, dict) and "_source" in v:
                        docs.append(v["_source"])
                    elif isinstance(v, dict):
                        docs.append(v)
                # Fallback: data.documents
                if not docs and isinstance(data.get("data", {}).get("documents"), dict):
                    docs = list(data["data"]["documents"].values())
                self._cache_set(cache_key, {"docs": docs[:size]})
                return docs[:size]
        return []

    async def enrich_tech(self, tech: str, version: str = "", size: int = 5) -> List[Dict]:
        """Tech + version -> CVEs. e.g. enrich_tech('nginx','1.18.0')"""
        if not tech:
            return []
        # Build Lucene query: try cpe first, then plain
        queries = []
        if version:
            queries.append(f'cpe:"{tech} {version}"')
            queries.append(f'{tech} {version}')
        queries.append(tech)
        for q in queries:
            docs = await self.search_lucene(q, size=size)
            if docs:
                return docs
        return []

    async def enrich_cves(self, cve_ids: List[str]) -> Dict[str, Optional[Dict]]:
        """Batch lookup for a list of CVE IDs. Returns {CVE: doc}."""
        if not cve_ids:
            return {}
        results = {}
        # throttle to avoid 429
        for cid in list(dict.fromkeys(cve_ids))[:20]:
            doc = await self.lookup_id(cid)
            results[cid] = doc
            await asyncio.sleep(0.2)
        return results

    # Sync wrappers for Streamlit
    def lookup_id_sync(self, cve_id: str, fields=None) -> Optional[Dict]:
        return _run_coro(self.lookup_id(cve_id, fields))

    def search_lucene_sync(self, query: str, size=10) -> List[Dict]:
        return _run_coro(self.search_lucene(query, size))

    def enrich_tech_sync(self, tech: str, version: str = "", size=5) -> List[Dict]:
        return _run_coro(self.enrich_tech(tech, version, size))

    def enrich_cves_sync(self, cve_ids: List[str]) -> Dict[str, Optional[Dict]]:
        return _run_coro(self.enrich_cves(cve_ids))


def _run_coro(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()
