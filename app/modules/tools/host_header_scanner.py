"""
host_header_scanner.py — Host-header trust reflection probe.

Feeds unique random markers through the single-header alternate-host
variants (X-Forwarded-Host, X-Host, X-Forwarded-Server, Forwarded,
True-Client-IP), the protocol override (X-Forwarded-Proto) and the
path-override headers (X-Original-URL, X-Rewrite-URL), then reports any
reflection of the marker (or http://<marker>/https://<marker>) into the
response body or into the Location header of a 3xx. A reflected root URL /
path here is the primitive behind password-reset poisoning and cache-key
bypasses. Raw-socket dual-Host injection and Host-header override are out of
scope (too invasive for passive recon); per technique_library marker
discipline each marker is baseline-collision-checked first.

SAFETY: passive GET-only probing of in-scope targets; 2-3 requests per
header; unique random alnum markers (8+ chars, never 'test'); never
state-changing.
"""

import asyncio
import os
import random
import re
import string
import sys
from typing import Dict, List, Optional

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_UA = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"}

_TRUST_HEADERS = [
    ("X-Forwarded-Host", "host"),
    ("X-Host", "host"),
    ("X-Forwarded-Server", "host"),
    ("Forwarded", "host"),
    ("True-Client-IP", "host"),
    ("X-Forwarded-Proto", "proto"),
    ("X-Original-URL", "path"),
    ("X-Rewrite-URL", "path"),
]

_CHARS = string.ascii_lowercase + string.digits
_BAD_MARKER = re.compile(r"(test|marker|evil|xss|x4d|zzz)")
_REDIRECTS = (301, 302, 303, 307, 308)


def gen_marker(length: int = 10) -> str:
    while True:
        m = "".join(random.choice(_CHARS) for _ in range(length))
        if not _BAD_MARKER.search(m):
            return m


def marker_variants(kind: str, marker: str) -> List[str]:
    if kind == "proto":
        return [f"http://{marker}", f"https://{marker}"]
    if kind == "path":
        return [marker, f"/{marker}", f"https://{marker}/"]
    return [marker, f"http://{marker}", f"https://{marker}"]


class HostHeaderScanner:
    def __init__(self, timeout: float = 10.0, concurrency: int = 4):
        self.timeout = timeout
        self.concurrency = concurrency

    async def _get(self, session, url: str,
                   headers: Optional[dict] = None) -> tuple:
        try:
            async with session.get(
                    url, headers=headers or _UA,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False) as r:
                body = await r.text(errors="replace")
                return r.status, body, r.headers.get("Location", "")
        except Exception:
            return 0, "", ""

    async def _probe_header(self, session, url: str, name: str, kind: str,
                            base_body: str) -> Optional[dict]:
        marker = gen_marker()
        tries = 0
        while marker in base_body and tries < 4:
            marker = gen_marker()
            tries += 1
        if marker in base_body:
            return None
        for value in marker_variants(kind, marker):
            hdrs = dict(_UA)
            hdrs[name] = value
            status, body, location = await self._get(session, url, hdrs)
            if status in _REDIRECTS and marker in location:
                return {"url": url, "header": name,
                        "reflected_in": "location", "status": status}
            if marker in body:
                return {"url": url, "header": name,
                        "reflected_in": "body", "status": status}
        return None

    async def _scan_one(self, session, url: str, sem) -> list:
        _, base_body, _ = await self._get(session, url)
        out = []

        async def job(name, kind):
            row = await self._probe_header(session, url, name, kind, base_body)
            if row:
                out.append(row)

        async with sem:
            tasks = [asyncio.create_task(job(n, k)) for n, k in _TRUST_HEADERS]
            await asyncio.gather(*tasks)
        return out

    async def scan(self, urls: List[str]) -> List[dict]:
        """Return per-url findings: header reflected in body or Location."""
        sem = asyncio.Semaphore(self.concurrency)
        results = []
        async with aiohttp.ClientSession() as session:
            for u in urls:
                results.extend(await self._scan_one(session, u, sem))
        return results

    def scan_sync(self, urls: List[str]) -> List[dict]:
        return asyncio.run(self.scan(urls))


def _main():
    urls = sys.argv[1:]
    if not urls:
        print(f"usage: {sys.argv[0]} <url...>")
        sys.exit(1)
    s = HostHeaderScanner()
    for row in s.scan_sync(urls):
        print(f"[{row['status']}] {row['header']} -> "
              f"reflected in {row['reflected_in']}: {row['url']}")


if __name__ == "__main__":
    _main()