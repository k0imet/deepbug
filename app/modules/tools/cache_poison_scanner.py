"""
cache_poison_scanner.py — shared-cache poison primitive detection.

Per URL: an untampered baseline plus one request per unkeyed header
(X-Forwarded-Host, X-Host, X-Forwarded-Server, X-Original-URL,
X-Rewrite-URL), each carrying a unique random marker and a random
cache-buster param `?cb=<random>` to avoid colliding with producer cache
objects. A finding fires ONLY when (a) the marker is reflected in the body
AND (b) a cache signal shows a shared-cache hop (X-Cache, CF-Cache-Status !=
DYNAMIC, or Age > 0). Per the methodology rule, Cache-Control: private does
NOT prevent poisoning — it is noted in the output (`cache_control`), but
`poisonable` stays true only when a real cache signal exists.

SAFETY: passive GET-only; one request per header; random cb buster keeps
probes from polluting the observed cache.
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

_UNKEYED_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-Original-URL",
    "X-Rewrite-URL",
]

_CHARS = string.ascii_lowercase + string.digits
_BAD_MARKER = re.compile(r"(test|marker|evil|xss|x4d|zzz)")


def gen_marker(length: int = 10) -> str:
    while True:
        m = "".join(random.choice(_CHARS) for _ in range(length))
        if not _BAD_MARKER.search(m):
            return m


def cache_signal(hdrs: Dict) -> str:
    """First shared-cache signal in header priority order, else ''."""
    xc = hdrs.get("X-Cache", "")
    if xc:
        return f"X-Cache: {xc}"
    cf = hdrs.get("CF-Cache-Status", "")
    if cf and cf.upper() != "DYNAMIC":
        return f"CF-Cache-Status: {cf}"
    try:
        age = int(hdrs.get("Age", "0"))
    except ValueError:
        age = 0
    if age > 0:
        return f"Age: {age}"
    return ""


def _with_buster(url: str, buster: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}cb={buster}"


class CachePoisonScanner:
    def __init__(self, timeout: float = 10.0, concurrency: int = 4):
        self.timeout = timeout
        self.concurrency = concurrency

    async def _probe(self, session, url: str, headers: Optional[dict] = None):
        try:
            async with session.get(
                    url, headers=headers or _UA,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False) as r:
                body = await r.text(errors="replace")
                return {"status": r.status, "body": body,
                        "headers": dict(r.headers), "url": url}
        except Exception:
            return {"status": 0, "body": "", "headers": {}, "url": url}

    async def _scan_one(self, session, url: str, sem) -> list:
        busted = _with_buster(url, gen_marker())
        base = await self._probe(session, busted)
        base_body = base["body"]
        out = []

        async def job(name):
            marker = gen_marker()
            if marker in base_body:
                return
            row = await self._probe(
                session, _with_buster(url, gen_marker()),
                {**_UA, name: f"http://{marker}"})
            signal = cache_signal(row["headers"])
            if marker in row["body"] and signal:
                out.append({
                    "url": row["url"], "header": name, "reflected": True,
                    "cache_signal": signal, "poisonable": True,
                    "cache_control": row["headers"].get("Cache-Control", ""),
                })

        async with sem:
            tasks = [asyncio.create_task(job(n)) for n in _UNKEYED_HEADERS]
            await asyncio.gather(*tasks)
        return out

    async def scan(self, urls: List[str]) -> List[dict]:
        """Return reflection+shared-cache findings only."""
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
    s = CachePoisonScanner()
    for row in s.scan_sync(urls):
        print(f"[{row['cache_signal']}] {row['header']} reflected "
              f"(private={bool(row['cache_control'])}) {row['url']}")


if __name__ == "__main__":
    _main()