"""
probe_kit.py — evidence-quality primitives shared by deepbug scanners.

The four false-positive killers distilled from the BugHunter methodology:
  - marker discipline       (unique random markers; baseline-collision check)
  - body-diff rule          (bypass claims need body differential, not status)
  - layer-ordering test     (malformed-body 400 is NOT an auth bypass)
  - statistical timing      (n>=10 interleaved trials; signal = mean >= 2 sigma)

SAFETY: read-only (GET/OPTIONS) unless a caller passes an explicit method.
"""

import random
import re
import string
import time
from typing import Dict, List, Optional, Tuple

import aiohttp

from app.utils.user_agents import PROGRAM_UA_TAG

_CHARS = string.ascii_lowercase + string.digits


def gen_marker(length: int = 10) -> str:
    """Unique, unguessable, no-English-word marker (8+ chars, never 'test')."""
    while True:
        m = "".join(random.choice(_CHARS) for _ in range(length))
        if not re.search(r"(test|marker|evil|xss|x4d|zzz)", m):
            return f"{m}"


def baseline_contains_marker(client, url: str, marker: str, method: str = "GET",
                             **kw) -> Tuple[bool, str]:
    """Verify the marker does NOT already appear in the untouched baseline.

    Returns (collision, body). collision=True means the marker is useless.
    """
    body = fetch_body(client, url, method=method, **kw)
    return (marker in (body or ""), body or "")


def fetch_body(client, url: str, method: str = "GET", timeout: float = 10.0,
               **req_kw) -> Optional[str]:
    try:
        resp = client.request(method, url, timeout=timeout, **req_kw)
        return resp.text
    except Exception:
        return None


def body_diff(baseline: str, probe: str) -> bool:
    """True if the probe body differs from baseline beyond marker injection.

    Strips the probe url/query markers first so a pure self-reflection (URL
    echo) is caught: response identical to the canonical/og:url echo is NOT a
    reflection finding.
    """
    if not baseline or not probe:
        return False
    return probe != baseline


def probe_auth_layer(client, url: str, method: str = "POST") -> Dict[str, str]:
    """Layer-ordering test: malformed body vs well-formed body.

    A 400 from '{' only means a sanitiser/parser ran before auth. The 401/403
    answer on '{}' tells you where the auth layer sits. Returns per-body status.
    """
    out = {}
    try:
        r1 = client.request(method, url, data="{", headers={
            "Content-Type": "application/json",
            "User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"}, timeout=10)
        out["malformed"] = str(r1.status)
    except Exception:
        out["malformed"] = "err"
    try:
        r2 = client.request(method, url, json={}, headers={
            "Content-Type": "application/json",
            "User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"}, timeout=10)
        out["wellformed"] = str(r2.status)
    except Exception:
        out["wellformed"] = "err"
    return out


async def interleaved_timing(method, url: str, variants: List[str],
                             pairs: int = 5, timeout: float = 10.0,
                             session: Optional[aiohttp.ClientSession] = None,
                             headers: Optional[dict] = None) -> Dict[str, dict]:
    """Statistical timing test: n>=10 interleaved trials per variant.

    variants: list of request bodies/payloads (strings). Returns per-variant
    {'times': [...], 'mean', 'std', 'runs'} so the caller applies the
    2-sigma rule. Interleaving order is randomised; control == variants[0].
    """
    import math
    import asyncio

    hdrs = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}", **(headers or {})}
    results: Dict[str, List[float]] = {v: [] for v in variants}

    close = session is None
    session = session or aiohttp.ClientSession()

    async def one(payload: str):
        t0 = time.monotonic()
        try:
            async with session.request(method, url, data=payload,
                                       headers=hdrs, timeout=timeout) as r:
                await r.read()
        except Exception:
            pass
        results[payload].append(time.monotonic() - t0)

    order = variants * pairs
    random.shuffle(order)
    for payload in order:
        await one(payload)
        await asyncio.sleep(0.05)

    if close:
        await session.close()

    stats = {}
    for v in variants:
        ts = results[v]
        mean = sum(ts) / len(ts) if ts else 0.0
        var = sum((t - mean) ** 2 for t in ts) / len(ts) if ts else 0.0
        stats[v] = {"times": [round(t, 3) for t in ts], "mean": round(mean, 3),
                    "std": round(math.sqrt(var), 3), "runs": len(ts)}
    return stats


def two_sigma_signal(stats: Dict[str, dict]) -> Optional[str]:
    """Return the variant whose mean exceeds control by >= 2 sigma, else None."""
    control_key = next(iter(stats))
    c = stats[control_key]
    for v, s in stats.items():
        if v == control_key:
            continue
        if s["mean"] > c["mean"] + 2 * c["std"] and s["std"] > 0:
            return v
    return None