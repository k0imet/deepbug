"""
rate_limit_tester.py — bounded presence-check for rate limiting.

Sends N=10 identical requests to a URL, spaced 200ms apart, and reports the
status distribution plus block-keyword matches. Purpose is defense-assessment:
find out whether a rate limit EXISTS — never probe its bypass, never exhaust
it.

SAFETY: GET by default; POST gated behind allow_post=False. Never more than
12 requests total per URL. Stops early once a block signal is seen.
"""

import asyncio
import os
import sys
import time
from collections import Counter
from typing import Dict, List, Optional

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_BLOCK_WORDS = ("not so fast", "rate limit", "too many requests",
                "try again later", "blocked")
_MAX_REQUESTS = 12
_MAX_BODY = 2048


def _body_signal(body: str) -> bool:
    low = body.lower()
    return any(w in low for w in _BLOCK_WORDS)


class RateLimitTester:
    """Detect whether a URL is rate-limited, without attempting bypasses."""

    def __init__(self, allow_post: bool = False, timeout: float = 10.0,
                 n: int = 10, interval: float = 0.2):
        self.allow_post = allow_post
        self.timeout = timeout
        self.n = min(n, _MAX_REQUESTS)
        self.interval = interval

    async def _send(self, session, url: str) -> Dict:
        hdrs = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"}
        try:
            if self.allow_post:
                res = session.post(url, headers=hdrs, data={})
            else:
                res = session.get(url, headers=hdrs)
            async with res as r:
                body = await r.content.read(_MAX_BODY)
                return {"status": r.status,
                        "signal": _body_signal(body.decode("utf-8", "ignore"))}
        except Exception:
            return {"status": 0, "signal": False}

    def _verdict(self, counts: Counter, signals: int) -> Dict:
        if counts[429]:
            kind = "429"
        elif counts[400]:
            kind = "400"
        elif counts[503]:
            kind = "503"
        elif signals:
            kind = "body-word"
        else:
            kind = "none"
        return {"limit_detected": kind != "none", "limit_kind": kind}

    async def scan(self, url: str) -> Dict:
        """Send n identical requests, spaced 200ms, stop on first block."""
        counts = Counter()
        signals = 0
        sent = 0
        blocked = None
        async with aiohttp.ClientSession() as session:
            for i in range(self.n):
                if blocked is not None and i >= 5:
                    break
                res = await self._send(session, url)
                counts[res["status"]] += 1
                signals += 1 if res["signal"] else 0
                sent += 1
                if res["status"] in (429, 503) or res["signal"]:
                    blocked = res["status"] or "word"
                if i < self.n - 1:
                    await asyncio.sleep(self.interval)
        verdict = self._verdict(counts, signals)
        return {"url": url,
                "requests_sent": sent,
                "status_counts": dict(counts),
                "limit_detected": verdict["limit_detected"],
                "limit_kind": verdict["limit_kind"],
                "blocked_signal": bool(blocked)}

    def scan_sync(self, url: str) -> Dict:
        return asyncio.run(self.scan(url))


def _main():
    urls = sys.argv[1:]
    allow_post = "--post" in urls
    urls = [u for u in urls if u != "--post"]
    if not urls:
        print(f"usage: {sys.argv[0]} [--post] <url...>")
        sys.exit(1)
    t = RateLimitTester(allow_post=allow_post)
    for u in urls:
        r = t.scan_sync(u)
        print(f"== {u}")
        print(f"   sent={r['requests_sent']} statuses={r['status_counts']} "
              f"limit={r['limit_kind']} detected={r['limit_detected']}")


if __name__ == "__main__":
    _main()