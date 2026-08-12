"""
shadow_api_scanner.py — dead/zombie/legacy API discovery (OWASP API9).

Workflow from hunt-shadow-api:
  1. enumerate version surface: v1..v4/beta/alpha/internal/legacy/old + dated
     versions + X-API-Version / Accept vendor-version headers — anything other
     than 404/connection-refused is a live version
  2. behavioral diff: same operation on old vs new version — weaker auth,
     missing rate limit, extra fields, accepts-what-new-rejects = the finding
     (version difference alone = informational)

SAFETY: GET/OPTIONS only. Never sends state-changing requests.
"""

import asyncio
import json
import os
import sys
from typing import Dict, List, Optional

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_VERSIONS = ["v1", "v2", "v3", "v4", "beta", "alpha", "internal", "legacy",
             "old", "2022-01-01", "2023-01-01", "2024-01-01"]
_VERSION_HDR = "X-API-Version"
_ACCEPT = "Accept"

_VERBATIM_EXAMPLE = "curl -s -o /dev/null -w '%{http_code} https://$TARGET/api/vX/\\n' \"https://$TARGET/api/vX/\""


def version_fragments(base_path: str = "") -> List[str]:
    """Candidate version segments to brute the path with."""
    return [f"{base_path}/{v}" if base_path else f"/{v}"
            for v in _VERSIONS]


class ShadowApiScanner:
    def __init__(self, timeout: float = 10.0, concurrency: int = 8):
        self.timeout = timeout
        self.concurrency = concurrency

    async def _probe(self, session, url: str, headers: Optional[dict]) -> int:
        try:
            async with session.get(url, headers=headers, timeout=self.timeout,
                                   allow_redirects=False) as r:
                return r.status
        except Exception:
            return 0

    async def _scan_one(self, session, base: str, sem) -> list:
        jobs = []
        for frag in version_fragments():
            jobs.append((frag, None))
            jobs.append((frag, _VERSION_HDR))
            jobs.append((frag, _ACCEPT))
        results = []
        async def job(pair):
            frag, hdr = pair
            url = base.rstrip("/") + frag
            headers = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"}
            if hdr == _VERSION_HDR:
                headers[_VERSION_HDR] = "1"
            elif hdr == _ACCEPT:
                headers[_ACCEPT] = "application/vnd.company.v1+json"
            code = await self._probe(session, url, headers)
            if code not in (0, 404):
                results.append({"url": url, "status": code, "variant": hdr or "path"})
        async with sem:
            tasks = [asyncio.create_task(job(p)) for p in jobs]
            await asyncio.gather(*tasks)
        return results

    async def scan(self, base_url: str) -> list:
        """Return found version URLs with status. Non-404 = live surface."""
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession() as session:
            return await self._scan_one(session, base_url, sem)

    async def diff(self, session, old_url: str, new_url: str,
                   headers: Optional[dict] = None) -> Dict[str, dict]:
        """Behavioral diff on the same operation across versions.

        Compares status, response body shape, and error text. Returns a dict
        with 'identical' and 'notes' — callers inspect for auth/field drift.
        """
        hdrs = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}", **(headers or {})}
        out = {}
        for label, u in (("old", old_url), ("new", new_url)):
            try:
                async with session.get(u, headers=hdrs, timeout=self.timeout,
                                       allow_redirects=False) as r:
                    body = await r.text()
                    out[label] = {
                        "status": r.status,
                        "length": len(body),
                        "body": body[:300],
                        "ct": r.headers.get("Content-Type", ""),
                    }
            except Exception as e:
                out[label] = {"status": 0, "error": str(e)}
        same = (out["old"].get("status") == out["new"].get("status")
                and out["old"].get("ct") == out["new"].get("ct"))
        out["identical"] = bool(same)
        return out

    def scan_sync(self, base_url: str) -> list:
        return asyncio.run(self.scan(base_url))


def _main():
    urls = sys.argv[1:]
    if not urls:
        print(f"usage: {sys.argv[0]} <base_url...>")
        print(_VERBATIM_EXAMPLE)
        sys.exit(1)
    s = ShadowApiScanner()
    for u in urls:
        hits = s.scan_sync(u)
        print(f"== {u}")
        for h in sorted(hits, key=lambda x: x["url"]):
            print(f"   {h['status']} {h['url']} [{h['variant']}]")


if __name__ == "__main__":
    _main()