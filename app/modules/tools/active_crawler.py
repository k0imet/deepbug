# modules/tools/active_crawler.py
# Active crawling driver -- katana ( + optional gau dash) wired into the
# recon pipeline. Installed-but-unwired gap item from the 2026 technique
# review, now used by the endpoint engine's input feed.
#
# Strategy (from the "Recon to Master" checklist):
#   1. katana --depth-N crawl over seed targets (SPA-aware, quiet by
#      default, handles JS moved dom).
#   2. optional gau pass over each scope host (passive complement).
#   3. output is scope-filtered + de-polluted via url_cleaner, returned as
#      a plain url list plus host stats.
#
# All heavy tags of the browser-based JS/DOM work stay in their own modules;
# this one only collects observables.

import asyncio
import os
import subprocess
from typing import Dict, List, Optional, Any
from urllib.parse import urlsplit

try:
    from app.utils.logger import get_logger
    logger = get_logger()
except Exception:
    import logging
    logger = logging.getLogger(__name__)


def _run_cmd(cmd: str, env: Optional[Dict[str, str]] = None,
             timeout: int = 120) -> tuple:
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout, env=e)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"


class ActiveCrawler:
    """
    katana-driven active crawling with scope filter + url_cleaner dedup.

    Usage:
        crawler = ActiveCrawler(config)
        out = crawler.scan_sync(
            scope_hosts=['example.com'],
            targets=['https://example.com/'],
            depth=4, threads=10, timeout=120)
    """

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        cfg = config.get("active_crawler", config) if isinstance(config, dict) else {}
        self.cfg = cfg

    # ------------------------------------------------------------------
    @staticmethod
    def _in_scope(url: str, scope_hosts: List[str]) -> bool:
        try:
            h = (urlsplit(url).hostname or "").lower()
        except Exception:
            return False
        for s in scope_hosts:
            s = s.lower().lstrip("*.").rstrip(".")
            if h == s or h.endswith("." + s):
                return True
        return False

    # ------------------------------------------------------------------
    def _bin(self, name: str) -> str:
        path = str(self.cfg.get(name, "~/go/bin/" + name) or "~/go/bin/" + name)
        return os.path.expanduser(path)

    def _katana(self, targets: List[str], depth: int, threads: int,
                timeout: int, scope_hosts: List[str]) -> List[str]:
        binp = self._bin("katana")
        if not os.path.exists(binp):
            logger.warning("katana not found at %s (skip crawl)", binp)
            return []
        tfile = "/tmp/db_crawl_targets.txt"
        with open(tfile, "w") as fh:
            fh.write("\n".join(targets) + "\n")
        cmd = (f"{binp} -list {tfile} -d {int(depth)} -f url "
               f"-c {int(threads)} -timeout {int(timeout)} -silent")
        code, out, err = _run_cmd(cmd, timeout=timeout * depth + 120)
        if code != 0 and not out.strip():
            logger.debug("katana exit=%s stderr=%s", code, err[:200])
        urls = []
        for line in out.splitlines():
            u = line.strip()
            if u:
                urls.append(u)
        if scope_hosts:
            urls = [u for u in urls if self._in_scope(u, scope_hosts)]
        return urls

    def _gau(self, host: str, timeout: int, scope_hosts: List[str]) -> List[str]:
        binp = self._bin("gau")
        if not os.path.exists(binp):
            return []
        cmd = f"{binp} --threads 8 --timeout {int(timeout)} {host} 2>/dev/null"
        # gau queries public archive services and can hang for minutes on slow
        # networks - cap it so a slow archive never stalls the whole crawl.
        code, out, _err = _run_cmd(cmd, timeout=min(timeout + 30, 60))
        urls = [l.strip() for l in out.splitlines() if l.strip()]
        if scope_hosts:
            urls = [u for u in urls if self._in_scope(u, scope_hosts)]
        return urls

    # ------------------------------------------------------------------
    def scan_sync(self, scope_hosts: List[str],
                  targets: Optional[List[str]] = None,
                  depth: int = 4, threads: int = 10, timeout: int = 120,
                  collect_gau: bool = True) -> Dict[str, Any]:
        if not scope_hosts:
            return {"urls": [], "raw_total": 0, "sources": {}, "by_host": {}}
        targets = targets or ["https://%s/" % scope_hosts[0]]

        results: List[str] = []
        sources: Dict[str, int] = {}

        crawl = self._katana(targets, depth, threads, timeout, scope_hosts)
        results += crawl
        sources["katana"] = len(crawl)

        if collect_gau:
            for h in scope_hosts:
                g = self._gau(h, timeout, scope_hosts)
                results += g
                sources["gau/" + h] = len(g)

        try:
            from app.modules.tools.url_cleaner import URLCleaner
            urls = URLCleaner(self.cfg).clean_urls(results)
        except Exception:
            urls = list(dict.fromkeys(results))

        by_host: Dict[str, int] = {}
        for u in urls:
            try:
                h = urlsplit(u).netloc
            except Exception:
                continue
            by_host[h] = by_host.get(h, 0) + 1

        return {"urls": urls, "raw_total": len(results),
                "sources": sources, "by_host": by_host}

    # async wrapper for pipeline compat --------------------------------
    async def scan(self, scope_hosts: List[str], **kw) -> Dict[str, Any]:
        return await asyncio.to_thread(self.scan_sync, scope_hosts, **kw)