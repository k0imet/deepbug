"""
sqli_scanner.py — boolean/error-differential SQL injection prober.

Per reflected query parameter:
  1. baseline                        - unique alphanumeric marker
  2. MARKER'                         - odd quote. A 500/4xx status change on
     the quote alone, or a classic database error string in any probe body
     ("SQL syntax", "ORA-", "You have an error in your SQL", "MySQL",
     "PostgreSQL", "SQLSTATE", "syntax error at or near") = error-based lead
  3. MARKER' OR '1'='1 (universally true) vs MARKER' AND '1'='2 (universally
     false): the OR page matches the baseline while the AND page differs and
     loses the marker = boolean lead ("row-set split"). body_diff() is used
     with the OR-1=1 response as the positive baseline.

No time-based or stacked payloads, no sleeps, no writes.

SAFETY: GET-only. Classic SELECT boolean/error differentials, nothing that
        writes, drops, or delays the database.
"""

import asyncio
import os
import sys
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.modules.tools.probe_kit import body_diff, gen_marker
from app.utils.user_agents import PROGRAM_UA_TAG

_UA = f"Mozilla/5.0 {PROGRAM_UA_TAG}"
_DB_ERRORS = ["sql syntax", "ora-", "you have an error in your sql",
              "mysql", "postgresql", "sqlstate", "syntax error at or near"]


def set_param_value(url: str, param: str, value: str) -> str:
    """Replace all occurrences of `param` in the query with `value`."""
    parts = urlsplit(url)
    query = [(k, value if k == param else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if not query:
        query = [(param, value)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query), parts.fragment))


def db_error_hits(body: Optional[str]) -> List[str]:
    """Canonical database error strings present in a response body."""
    if not body:
        return []
    low = body.lower()
    return [m for m in _DB_ERRORS if m in low]


class SQLiScanner:
    def __init__(self, timeout: float = 10.0, concurrency: int = 4):
        self.timeout = timeout
        self.concurrency = concurrency

    async def _get(self, session, url: str) -> Tuple[int, Optional[str]]:
        try:
            async with session.get(url, headers={"User-Agent": _UA},
                                   timeout=self.timeout) as r:
                return r.status, await r.text(errors="replace")
        except Exception:
            return 0, None

    async def _scan_param(self, session, url: str, param: str) -> Dict:
        marker = gen_marker(10)
        entry = {"url": url, "param": param, "lead": "none", "detail": "",
                 "status": 0}
        s0, b0 = await self._get(session, set_param_value(url, param, marker))
        entry["status"] = s0
        if s0 == 0 or not b0:
            entry["detail"] = "request failed or empty body"
            return entry
        if marker not in b0:
            entry["detail"] = "parameter does not reflect marker; skipped"
            return entry

        s_q, b_q = await self._get(
            session, set_param_value(url, param, marker + "'"))
        s_or, b_or = await self._get(
            session, set_param_value(url, param, marker + "' OR '1'='1"))
        s_and, b_and = await self._get(
            session, set_param_value(url, param, marker + "' AND '1'='2"))

        errs = db_error_hits(b_q) or db_error_hits(b_or) or db_error_hits(b_and)
        error_lead = bool(errs) or (s_q >= 500) or (s_q >= 400 and s_q != s0)

        bits = []
        if s_q and s_q != s0:
            bits.append(f"quote probe status {s_q} (baseline {s0})")
        if s_or and s_or != s0:
            bits.append(f"OR-1=1 status {s_or} (baseline {s0})")
        if errs:
            bits.append(f"db error strings: {', '.join(errs)}")

        boolean = False
        if b_or and b_and:
            or_like_base = not body_diff(b_or, b0)
            marker_split = marker in b_or and marker not in b_and
            boolean = bool(or_like_base and marker_split and body_diff(b_or, b_and))
            if boolean:
                bits.append("row-set split: marker in OR-1=1 page, absent in AND-1=2 page")

        if error_lead:
            entry["lead"] = "error-based"
        elif boolean:
            entry["lead"] = "boolean"
        entry["detail"] = "; ".join(bits) or "no signal observed"
        return entry

    async def scan(self, urls: List[str]) -> List[Dict]:
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession() as session:
            async def one(url):
                async with sem:
                    params = list(dict.fromkeys(
                        k for k, _ in parse_qsl(urlsplit(url).query)))
                    out = []
                    for p in params:
                        out.append(await self._scan_param(session, url, p))
                    return out
            results = await asyncio.gather(*(one(u) for u in urls))
        return [e for group in results for e in group]

    def scan_sync(self, urls: List[str]) -> List[Dict]:
        return asyncio.run(self.scan(urls))


def _main():
    urls = sys.argv[1:]
    if not urls:
        print(f"usage: {sys.argv[0]} 'https://host/page?param=1' [...]")
        sys.exit(1)
    for e in SQLiScanner().scan_sync(urls):
        print(f"{e['status']} lead={e['lead']} param={e['param']} "
              f"detail={e['detail']} {e['url']}")


if __name__ == "__main__":
    _main()