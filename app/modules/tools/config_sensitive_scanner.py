from app.utils.user_agents import PROGRAM_UA_TAG
# modules/tools/config_sensitive_scanner.py
# Probes for misconfigured sensitive-config exposure on in-scope origins:
# Spring Boot Actuator endpoints, Spring Cloud Config Server env leaks
# (mirroring blog.xboy.me "The Spring Of Secrets" / "Access to Odoo"
# writeups), and common sensitive-file paths (.env, application.yml,
# properties, openapi docs, git HEAD).
#
# Posture: passive/light -- plain GET only (no POST, never downloads the
# heapdump), a curated path list, no payloads, no brute-force. A row only
# becomes a *finding* when the response body carries hard evidence markers
# (e.g. `propertySources`, sensitive KEY=value, swagger `openapi`), which
# keeps this false-positive clean on VDP/Intigriti targets.

import asyncio
import concurrent.futures
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

import aiohttp

try:
    from app.utils.logger import get_logger
    logger = get_logger()
except Exception:
    import logging
    logger = logging.getLogger(__name__)


# (path, class) -- class decides the evidence gates below
SENSITIVE_PATHS = [
    ("/actuator/health", "actuator"),
    ("/actuator", "actuator_root"),
    ("/actuator/env", "actuator"),
    ("/actuator/configprops", "actuator"),
    ("/actuator/beans", "actuator"),
    ("/actuator/mappings", "actuator"),
    ("/actuator/loggers", "actuator"),
    ("/actuator/metrics", "actuator"),
    ("/actuator/heapdump", "heap"),
    ("/actuator/threaddump", "text"),
    # legacy spring boot
    ("/env", "actuator"),
    ("/heapdump", "heap"),
    ("/health", "actuator"),
    ("/trace", "text"),
    ("/mappings", "actuator"),
    ("/beans", "actuator"),
    # spring cloud config server
    ("/config-repo/", "config"),
    ("/config-repo/application.properties", "config"),
    ("/config-repo/application.yml", "config"),
    ("/application.properties", "config"),
    ("/application.yml", "config"),
    # sensitive static/config files
    ("/.env", "file"),
    ("/.env.production", "file"),
    ("/.env.local", "file"),
    ("/.git/HEAD", "file"),
    ("/config.json", "file"),
    ("/settings.json", "file"),
    ("/config/production.json", "file"),
    ("/Procfile", "file"),
    ("/docker-compose.yml", "file"),
    # api docs / swagger
    ("/v3/api-docs", "openapi"),
    ("/v2/api-docs", "openapi"),
    ("/openapi.json", "openapi"),
    ("/api-docs", "openapi"),
    ("/swagger-ui.html", "file"),
    ("/swagger-ui/index.html", "file"),
]

# hard evidence substrings per class: a response only counts when its body
# contains at least one of these (status 200 alone is never enough).
_EVIDENCE = {
    "actuator": ['"propertySources"', '"context"', '"sun.boot"', 'spring.',
                 '"UP"', 'management.endpoints', '"mappings"', '"properties"'],
    "actuator_root": ['"_links"', 'heapdump', 'threaddump', 'metrics'],
    "config": ['"password', '"secret', '"token', 'GITHUB_TOKEN', 'AWS_SECRET',
               'DATABASE_URL', '"spring.config', 'apiKey', 'client_secret',
               '"DB_', 'KEY_', 'PASSWORD', 'password=', 'secret=', 'token=',
               'AWS_ACCESS_KEY', 'MYSQL_PASSWORD', 'PGPASSWORD', 'SECRET_KEY='],
    "file": ['AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'DATABASE_URL',
             'SECRET_KEY', 'CLIENT_SECRET', '"clientSecret"', 'apiKey',
             'stripe_sk_', 'sk_live_', 'POSTGRES', 'REDIS_URL', 'AKIA',
             'password=', 'secret=', 'token=', 'AWS_ACCESS_KEY',
             'REACT_APP_', 'NEXT_PUBLIC_'],
    "openapi": ['"openapi"', '"swagger":', '"paths"', '"definitions"'],
    "text": ['ThreadInfo', 'Servlet', '<html>'],
    "heap": ['application/octet-stream'],
}

# KEY=value / "key": "value" shapes required for config/file classes
_KV_RE = re.compile(r'(?:[A-Za-z_][A-Za-z0-9_]*\s*=\s*["\']?[^\s,;]{4,}'
                    r'|"[A-Za-z0-9_.]+"\s*:\s*"[^\"]{4,}"'
                    r'|"[A-Za-z0-9_.]+"\s*:\s*\{)')

_BINARY_CT = ("application/octet-stream", "application/java")


class ConfigSensitiveScanner:
    """
    Probe origins for well-known sensitive endpoints; only evidence-backed
    responses become findings.

    Usage:
        sc = ConfigSensitiveScanner(config)
        res = sc.scan_sync(["https://api.example.com"])
    """

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        if isinstance(config, dict) and "tools" in config:
            cfg = (config.get("tools") or {}).get("config_sensitive_scanner", {})
        else:
            cfg = config.get("config_sensitive_scanner", {}) or {}
        self.timeout = float(cfg.get("timeout", 10))
        self.max_hosts = int(cfg.get("max_hosts", 100))
        self.headers = {"User-Agent": (cfg.get(
            "user_agent", "Mozilla/5.0 (compatible; SecurityProbe/1.0)") or "") + PROGRAM_UA_TAG}
        self.paths = self._build_paths(cfg)

    @staticmethod
    def _build_paths(cfg: Dict) -> List[tuple]:
        over = cfg.get("paths")
        if not over:
            return list(SENSITIVE_PATHS)
        if isinstance(over, dict):
            enabled = {k for k, v in over.items() if v}
            return [(p, c) for p, c in SENSITIVE_PATHS if p in enabled]
        if isinstance(over, list):
            return [(p, c) for p, c in SENSITIVE_PATHS if p in over]
        return list(SENSITIVE_PATHS)

    def _origin(self, url: str) -> str:
        u = urlparse(url)
        if not u.scheme:
            url = "https://" + url
            u = urlparse(url)
        return f"{u.scheme}://{u.netloc}" if u.netloc else ""

    # ------------------------------------------------------------------
    async def _get(self, session, url: str) -> tuple:
        try:
            async with session.get(url, headers=self.headers,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout),
                                   allow_redirects=False) as r:
                ct = r.headers.get("Content-Type", "")
                if any(b in ct for b in _BINARY_CT) or r.status in (301, 302,
                                                                     303, 307, 308):
                    # never download big binary/heapdump payloads; read a
                    # single byte and bail, keep headers for evidence
                    async for _ in r.content.iter_chunked(1):
                        break
                    length = r.headers.get("Content-Length") or 0
                    return r.status, ct, f"::binary::{length}"
                body = await r.text(errors="replace")
                return r.status, ct, body
        except Exception:
            return None, "", ""

    # ------------------------------------------------------------------
    def _evaluate(self, klass: str, status: int, body: str) -> str:
        """Return label: exposed / exposed_binary / clean."""
        if status != 200:
            return "clean"
        if klass == "heap":
            return "exposed_binary" if "::binary::" in body else "clean"
        ev = _EVIDENCE.get(klass, [])
        hits = [e for e in ev if e in body]
        if not hits:
            return "clean"
        if klass in ("config", "file") and not _KV_RE.search(body):
            return "clean"
        return "exposed"

    # ------------------------------------------------------------------
    async def probe(self, session, origin: str, path: str, klass: str) -> Dict:
        url = origin + path
        status, ct, body = await self._get(session, url)
        label = self._evaluate(klass, status, body)
        snippet = ""
        if label.startswith("exposed"):
            snippet = body[:400].replace("\n", " ") if "::binary::" not in body \
                else f"(binary {body.split('::')[2]} bytes)"
        return {
            "url": url, "path": path, "class": klass, "status": status,
            "content_type": ct, "label": label, "snippet": snippet,
        }

    # ------------------------------------------------------------------
    async def scan(self, urls: List[str]) -> Dict[str, Any]:
        rows: List[Dict] = []
        findings: List[Dict] = []
        async with aiohttp.ClientSession() as session:
            for url in urls[: self.max_hosts]:
                origin = self._origin(url)
                if not origin:
                    continue
                for path, klass in self.paths:
                    r = await self.probe(session, origin, path, klass)
                    rows.append(r)
                    if r["label"].startswith("exposed"):
                        findings.append(r)
                        logger.info("config-sens %s -> %s (%s)", r["url"],
                                    r["label"], klass)
        return {"rows": rows, "findings": findings}

    def scan_sync(self, urls: List[str]) -> Dict[str, Any]:
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running and running.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(lambda: asyncio.run(self.scan(urls))).result()
        try:
            return asyncio.run(self.scan(urls))
        except Exception as exc:
            logger.error("config_sensitive scan_sync error: %s", exc)
            return {"rows": [], "findings": []}
