"""
framework_probes.py — framework-specific quick-win probes.

Triggered by a host-fingerprint tech set: the FIRST framework in precedence
order (nextjs > laravel > spring > aspnet > sharepoint) selects the probe
battery. Next.js: _buildManifest.js via the BUILD_ID extracted from index
HTML (fallback /_next/data/), /manifest.json, and an /_next/image param
check (note only). Laravel: _ignition health-check / execute-solution, .env,
telescope, horizon. ASP.NET: elmah.axd, trace.axd, servicemodel/mex,
WebService/Service asmx?WSDL, .disco. SharePoint: _vti_bin, _layouts/15,
_api/web. Spring: actuator, actuator/env, actuator/heapdump (status only).
detect_framework() sniffs the framework from index HTML via regexes
(_next/static, __NEXT_DATA__, laravel/csrf-token, generator content=Laravel,
_vti, elmah, /actuator links).

SAFETY: passive GET-only; /actuator/heapdump is status + content-type only,
the body is never downloaded.
"""

import asyncio
import os
import re
import sys
from typing import Dict, List, Optional, Set

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_UA = {"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"}

_PRECEDENCE = ["nextjs", "laravel", "spring", "aspnet", "sharepoint"]

_ENV_MARKERS = ["APP_KEY=", "DB_PASSWORD", "AWS_SECRET", "=", "MAIL_PASSWORD"]

_PROBE_TABLE = {
    "nextjs": [
        ("/manifest.json", ("start_url", "display", "background_color")),
        ("/_next/image?url=/favicon.ico&w=64&q=75", (), "image-optimizer"),
    ],
    "laravel": [
        ("/_ignition/health-check", ("health", "can_execute_commands")),
        ("/_ignition/execute-solution", ("solution", "execute")),
        ("/.env", tuple(_ENV_MARKERS)),
        ("/telescope", ("telescope",)),
        ("/horizon", ("horizon",)),
    ],
    "spring": [
        ("/actuator", ("_links", "status")),
        ("/actuator/env", ("propertySources", "activeProfiles")),
        ("/actuator/heapdump", ("application/octet-stream",), "never downloaded"),
    ],
    "aspnet": [
        ("/elmah.axd", ("elmah", "Error Log")),
        ("/trace.axd", ("Application Trace", "__ITEMID__", "tracer")),
        ("/servicemodel/mex", ("wsdl:definitions", "Mex")),
        ("/WebService.asmx?WSDL", ("wsdl:definitions", "WebService")),
        ("/Service.asmx?WSDL", ("wsdl:definitions", "WebService")),
        ("/.disco", ("disco", "discovery.xml")),
    ],
    "sharepoint": [
        ("/_vti_bin/", ("vti_", "FrontPage")),
        ("/_layouts/15/", ("SharePoint", "15.0")),
        ("/_api/web", ("odata.metadata", "Title")),
    ],
}

_BUILD_ID_RE = re.compile(r"/_next/static/([^/\"']+)/_buildManifest\.js")

_NEXT_RE = re.compile(r"(/_next/static/|__NEXT_DATA__)")
_LARAVEL_RE = re.compile(r'(generator[^>\n]{0,40}content=["\']Laravel|csrf-token|'
                         r"laravel_session|window\.laravel)")
_SPRING_RE = re.compile(r'(?:href|src)="[^"]*/actuator')
_ELMAH_RE = re.compile(r"elmah")
_VTI_RE = re.compile(r"_vti")


def detect_framework(sample_html: str) -> str:
    """Regex-sniff the web framework from a sample of index HTML."""
    if _NEXT_RE.search(sample_html):
        return "nextjs"
    if _LARAVEL_RE.search(sample_html):
        return "laravel"
    if _SPRING_RE.search(sample_html):
        return "spring"
    if _ELMAH_RE.search(sample_html):
        return "aspnet"
    if _VTI_RE.search(sample_html):
        return "sharepoint"
    return ""


def _norm_tech(name: str) -> str:
    low = (name or "").strip().lower()
    if low.startswith("next"):
        return "nextjs"
    if "laravel" in low:
        return "laravel"
    if low.startswith("spring"):
        return "spring"
    if low.startswith("asp.net") or low == "aspnet":
        return "aspnet"
    if "sharepoint" in low:
        return "sharepoint"
    return ""


class FrameworkProbes:
    def __init__(self, timeout: float = 10.0, concurrency: int = 4):
        self.timeout = timeout
        self.concurrency = concurrency

    def choose_tech(self, techs: Optional[Set[str]]) -> Optional[str]:
        if not techs:
            return None
        known = {_norm_tech(t) for t in techs}
        for t in _PRECEDENCE:
            if t in known:
                return t
        return None

    async def _fetch_html(self, session, url: str) -> str:
        try:
            async with session.get(url, headers=_UA,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   allow_redirects=False) as r:
                return await r.text(errors="replace")
        except Exception:
            return ""

    async def _probe(self, session, url: str, markers: tuple,
                     note: str = "") -> dict:
        body = ""
        try:
            async with session.get(url, headers=_UA,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   allow_redirects=False) as r:
                ct = r.headers.get("Content-Type", "")
                if note == "never downloaded" or "octet-stream" in ct:
                    async for _ in r.content.iter_chunked(1):
                        break
                    body = ""
                else:
                    body = await r.text(errors="replace")
                status, hay = r.status, ct + "\n" + body
        except Exception:
            return {"url": url, "status": 0, "evidence": "", "note": note}
        evidence = next((m for m in markers if m in hay), "")
        return {"url": url, "path": url, "status": status,
                "evidence": evidence, "note": note}

    async def _scan_one(self, session, base: str, tech: str, sem) -> list:
        probes = list(_PROBE_TABLE.get(tech, []))
        if tech == "nextjs":
            html = await self._fetch_html(session, base)
            bid = _BUILD_ID_RE.search(html)
            if bid:
                probes.insert(0, (f"/_next/static/{bid.group(1)}/_buildManifest.js",
                                  ("buildManifest", "sortedPages")))
            else:
                probes.insert(0, ("/_next/data/", ()))
        out = []

        async def job(path, markers, note):
            url = base.rstrip("/") + path
            row = await self._probe(session, url, markers, note)
            if row["status"] in (0, 404):
                return
            out.append({"url": row["url"], "tech": tech, "path": path,
                        "status": row["status"], "evidence": row["evidence"]}
                       | ({"note": row["note"]} if row["note"] else {}))

        async with sem:
            tasks = [asyncio.create_task(job(p, m, n)) for p, m, *rest in probes
                     for n in (rest[0] if rest else ("",))]
            await asyncio.gather(*tasks)
        return out

    async def scan(self, urls: List[str],
                   techs: Optional[Set[str]] = None) -> List[dict]:
        tech = self.choose_tech(techs)
        if tech is None and urls:
            async with aiohttp.ClientSession() as session:
                tech = detect_framework(await self._fetch_html(session, urls[0]))
        if tech is None or not urls:
            return []
        sem = asyncio.Semaphore(self.concurrency)
        results = []
        async with aiohttp.ClientSession() as session:
            for base in urls:
                results.extend(await self._scan_one(session, base, tech, sem))
        return results

    def scan_sync(self, urls: List[str],
                  techs: Optional[Set[str]] = None) -> List[dict]:
        return asyncio.run(self.scan(urls, techs))


def _main():
    args = sys.argv[1:]
    if len(args) < 1:
        print(f"usage: {sys.argv[0]} <tech,tech...> <url...>")
        sys.exit(1)
    techs = {t for t in args[0].split(",") if t}
    urls = args[1:]
    s = FrameworkProbes()
    for row in s.scan_sync(urls, techs):
        print(f"[{row['status']}] {row['path']} ({row['tech']}) "
              f"evidence={row.get('evidence', '')!r} {row.get('note', '')}")


if __name__ == "__main__":
    _main()