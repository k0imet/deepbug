"""
race_scanner.py — identical-copies race detection.

Primitive from hunt-race-condition: fire N identical requests in parallel;
if >= 2 return success/final state, a non-atomic limit/uniqness check exists
(double spend, coupon overuse, gift-code reuse, registration dupes).

SAFETY: mutation happens ONLY where the caller explicitly passes a method +
body. Default mode is read-only probe (identical GETs) used to detect
non-atomic cache/limit layers. High-value targets (write endpoints) require
caller opt-in and should run against test accounts on dev/staging.
"""

import asyncio
import statistics
import time
from typing import Dict, List, Optional

import aiohttp

from app.utils.user_agents import PROGRAM_UA_TAG


class RaceScanner:
    def __init__(self, timeout: float = 10.0, burst: int = 10):
        self.timeout = timeout
        self.burst = burst

    async def _burst(self, session, method: str, url: str, payload=None,
                     headers: Optional[dict] = None) -> List[dict]:
        hdrs = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}", **(headers or {})}
        results = []
        barrier = asyncio.Barrier(self.burst)

        async def one(idx: int):
            await barrier.wait()
            t0 = time.monotonic()
            try:
                kw = dict(headers=hdrs, timeout=self.timeout,
                          allow_redirects=False)
                if payload is not None:
                    if isinstance(payload, dict):
                        kw["json"] = payload
                    else:
                        kw["data"] = payload
                async with session.request(method, url, **kw) as r:
                    body = await r.text()
                    results.append({
                        "idx": idx, "status": r.status,
                        "ms": round((time.monotonic() - t0) * 1000, 1),
                        "len": len(body),
                        "sample": body[:160],
                    })
            except Exception as e:
                results.append({"idx": idx, "status": 0, "error": str(e)})

        await asyncio.gather(*[one(i) for i in range(self.burst)])
        return results

    def verdict(self, results: List[dict]) -> Dict:
        codes = [r["status"] for r in results]
        ok = [r for r in results if 200 <= r["status"] < 300]
        by_code = {}
        for r in results:
            by_code.setdefault(r["status"], []).append(r)
        race = len(ok) >= 2 or any(
            len(v) >= 2 and 4 <= k < 500 and k not in (401, 403) and k != 429
            for k, v in by_code.items())
        return {
            "race_signal": bool(race),
            "burst": self.burst,
            "status_counts": {k: len(v) for k, v in by_code.items()},
            "successes": len(ok),
            "note": (">=2 concurrent successes — non-atomic check likely; "
                     "repeat 3/5 from fresh state before reporting"
                     if race else "no race signal in this burst"),
        }

    async def scan(self, method: str, url: str, payload=None,
                   headers: Optional[dict] = None, rounds: int = 1) -> Dict:
        """Run one or more bursts; return verdicts + raw results."""
        outs = []
        async with aiohttp.ClientSession() as session:
            for rnd in range(rounds):
                res = await self._burst(session, method, url, payload, headers)
                outs.append({"round": rnd + 1, "results": res,
                             "verdict": self.verdict(res)})
        return {"url": url, "method": method, "rounds": outs}

    def scan_sync(self, method: str, url: str, payload=None,
                  headers: Optional[dict] = None, rounds: int = 1) -> Dict:
        return asyncio.run(self.scan(method, url, payload, headers, rounds))


def _main():
    import sys
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <method> <url> [json_body] [burst]")
        sys.exit(1)
    method = sys.argv[1].upper()
    url = sys.argv[2]
    payload = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
    burst = int(sys.argv[4]) if len(sys.argv) > 4 else 10
    out = RaceScanner(burst=burst).scan_sync(method, url, payload)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    _main()