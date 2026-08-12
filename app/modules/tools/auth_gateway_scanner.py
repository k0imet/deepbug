"""
auth_gateway_scanner.py — legacy-protocol / bypass-gateway surface probe.

Loads the legacy-protocol matrix from technique_library (legacy_protocol_matrix
-- xmlrpc, _vti_bin, OWA, actuator, jenkins-cli, Tomcat manager, etc.) and
probes every endpoint path on each base URL (origin, or origin + path
prefix). A non-404 answer from a legacy endpoint means an auth gateway can be
bypassed via protocol confusion (SOAP / XML-RPC / JSON-RPC native creds vs
modern SSO). Statuses classify as alive (200/201/405/500 -- server answers
the protocol), gated (401/403) or absent (404). allow_redirects=False so a
3xx never masks the raw endpoint answer; all paths are probed -- it is cheap
and targets are few.

SAFETY: passive GET-only; a single request per endpoint; never issues the
state-changing legacy calls the matrix notes.
"""

import asyncio
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG
from app.modules.tools.technique_library import legacy_protocol_matrix

_UA = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"}

_ALIVE = (200, 201, 405, 500)
_SPLIT = re.compile(r"\s*(?:,|;|\bor\b)\s*")


def expand_endpoints(entry: str) -> List[str]:
    """Expand a matrix endpoint string into concrete probe paths."""
    out = []
    for part in _SPLIT.split(entry or ""):
        p = part.strip()
        if not p:
            continue
        if p == "*":
            continue
        if p.startswith("*"):
            continue
        if p.endswith("/*"):
            p = p[:-2]
        if not p.startswith("/"):
            p = "/" + p
        if p not in out:
            out.append(p)
    return out


class AuthGatewayScanner:
    def __init__(self, timeout: float = 10.0, concurrency: int = 8):
        self.timeout = timeout
        self.concurrency = concurrency
        self._matrix = None

    def matrix_endpoints(self) -> List[Tuple[str, str, str]]:
        if self._matrix is None:
            rows = []
            seen = set()
            for row in legacy_protocol_matrix():
                tech = row.get("tech", "")
                note = row.get("note", "")
                for ep in expand_endpoints(row.get("endpoint", "")):
                    key = (tech, ep)
                    if key in seen:
                        continue
                    seen.add(key)
                    rows.append((tech, ep, note))
            self._matrix = rows
        return self._matrix

    async def _get(self, session, url: str) -> int:
        try:
            async with session.get(
                    url, headers=_UA,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=False) as r:
                return r.status
        except Exception:
            return 0

    async def scan(self, urls: List[str]) -> List[dict]:
        """Return rows for every probed endpoint that answered (status not 0/404)."""
        sem = asyncio.Semaphore(self.concurrency)
        results = []
        async with aiohttp.ClientSession() as session:
            for base in urls:
                base = base.rstrip("/")

                async def job(tech, ep):
                    url = base + ep
                    status = await self._get(session, url)
                    if status in (0, 404):
                        return None
                    return {"url": url, "tech": tech, "status": status,
                            "alive": status in _ALIVE}

                async with sem:
                    tasks = [asyncio.create_task(job(t, e))
                             for t, e, _ in self.matrix_endpoints()]
                    rows = await asyncio.gather(*tasks)
                results.extend(r for r in rows if r)
        return results

    def scan_sync(self, urls: List[str]) -> List[dict]:
        return asyncio.run(self.scan(urls))


def _main():
    urls = sys.argv[1:]
    if not urls:
        print(f"usage: {sys.argv[0]} <base_url...>")
        sys.exit(1)
    s = AuthGatewayScanner()
    for row in s.scan_sync(urls):
        tag = "ALIVE" if row["alive"] else "resp "
        print(f"[{tag}] {row['status']} {row['url']} ({row['tech']})")


if __name__ == "__main__":
    _main()