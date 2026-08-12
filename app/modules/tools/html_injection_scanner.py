"""
html_injection_scanner.py — raw-HTML injection canary tester (no JavaScript).

For every query parameter of the given URLs:
  1. baseline GET with a unique alphanumeric marker value
  2. only if the plain marker reflects, probe <b>MARKER</b> and <u>MARKER</u>
     (max 3 requests per parameter)
  3. judge: marker present in the body AND the tag next to it is UNENCODED
     ("<b>MARKER" present but "&lt;b&gt;MARKER" absent -> the app does NOT
     HTML-escape the input => raw-HTML injection usable for phishing/defacement)

SAFETY: GET-only. Canary markup only - no script, no external fetch.
"""

import asyncio
import os
import sys
from typing import Dict, List
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.modules.tools.probe_kit import gen_marker
from app.utils.user_agents import PROGRAM_UA_TAG

_UA = f"Mozilla/5.0 {PROGRAM_UA_TAG}"
_TAGS = ("b", "u")


def set_param_value(url: str, param: str, value: str) -> str:
    """Replace all occurrences of `param` in the query with `value`."""
    parts = urlsplit(url)
    query = [(k, value if k == param else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if not query:
        query = [(param, value)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query), parts.fragment))


class HtmlInjectionScanner:
    def __init__(self, timeout: float = 10.0, concurrency: int = 8):
        self.timeout = timeout
        self.concurrency = concurrency

    async def _get(self, session, url: str):
        try:
            async with session.get(url, headers={"User-Agent": _UA},
                                   timeout=self.timeout) as r:
                return r.status, await r.text(errors="replace")
        except Exception:
            return 0, None

    @staticmethod
    def _unencoded(body: str, tag: str, marker: str) -> bool:
        raw = f"<{tag}>{marker}"
        enc = f"&lt;{tag}&gt;{marker}"
        return raw in body and enc not in body

    async def _scan_one(self, session, url: str) -> List[Dict]:
        params = list(dict.fromkeys(k for k, _ in parse_qsl(urlsplit(url).query)))
        if not params:
            return [{"url": url, "param": "", "reflected": False,
                     "encoded": False, "status": 0, "note": "no query params"}]
        out = []
        for param in params:
            marker = gen_marker(10)
            status, body = await self._get(session, set_param_value(url, param, marker))
            entry = {"url": url, "param": param, "reflected": False,
                     "encoded": False, "status": status}
            if status == 0 or not body or marker not in body:
                out.append(entry)
                continue
            entry["reflected"] = True
            found_raw = found_enc = False
            for tag in _TAGS:
                bstatus, bbody = await self._get(
                    session, set_param_value(url, param, f"<{tag}>{marker}</{tag}>"))
                if bstatus:
                    entry["status"] = bstatus
                if not bbody:
                    continue
                if f"&lt;{tag}&gt;{marker}" in bbody:
                    found_enc = True
                if self._unencoded(bbody, tag, marker):
                    found_raw = True
            entry["encoded"] = found_enc and not found_raw
            if found_raw:
                entry["note"] = "UNENCODED tag reflection - raw HTML injection"
            out.append(entry)
        return out

    async def scan(self, urls: List[str]) -> List[Dict]:
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession() as session:
            async def one(u):
                async with sem:
                    return await self._scan_one(session, u)
            results = await asyncio.gather(*(one(u) for u in urls))
        return [e for group in results for e in group]

    def scan_sync(self, urls: List[str]) -> List[Dict]:
        return asyncio.run(self.scan(urls))


def _main():
    urls = sys.argv[1:]
    if not urls:
        print(f"usage: {sys.argv[0]} 'https://host/page?param=1' [...]")
        sys.exit(1)
    for e in HtmlInjectionScanner().scan_sync(urls):
        hit = " INJECTABLE" if (e["reflected"] and not e["encoded"]) else ""
        print(f"{e['status']} param={e['param']} reflected={e['reflected']}"
              f" encoded={e['encoded']}{hit} {e['url']}")


if __name__ == "__main__":
    _main()