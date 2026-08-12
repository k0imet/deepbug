# modules/tools/screenshot_scanner.py
# Screenshot / visual recon -- aquatone-style capture of every live host so
# the operator can eyeball dashboard-y surface (and spot the "single-page
# app that never reflects" traps) without a headless-screenshot toolchain
# installed. Uses Playwright if available; graceful no-op otherwise.
#
# Output is a table (host -> png path -> tiny HTTP status) that the
# reporting page can render as a gallery.

import asyncio
import os
from typing import Dict, List, Any, Optional
from urllib.parse import urlsplit

try:
    from app.utils.logger import get_logger
    logger = get_logger()
except Exception:
    import logging
    logger = logging.getLogger(__name__)


class ScreenshotScanner:
    """
    Screenshot live URLs (one per host by default).

    Usage:
        s = ScreenshotScanner(config)
        res = s.scan_sync(['https://example.com/'], out_dir='/tmp/shots')
    """

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        cfg = config.get("screenshots", config) if isinstance(config, dict) else {}
        self.width = int(cfg.get("width", 1280))
        self.height = int(cfg.get("height", 800))
        self.timeout_ms = int(cfg.get("timeout_ms", 20000))
        self.max_urls = int(cfg.get("max_urls", 200))
        self._has_playwright = None

    # ------------------------------------------------------------------
    def _playwright_available(self) -> bool:
        if self._has_playwright is None:
            try:
                import playwright  # noqa
                self._has_playwright = True
            except Exception:
                self._has_playwright = False
        return self._has_playwright

    # ------------------------------------------------------------------
    def scan_sync(self, urls: List[str],
                  out_dir: str = "/tmp/db_shots") -> Dict[str, Any]:
        if not self._playwright_available():
            return {"shots": [], "skipped": True,
                    "error": "playwright not installed"}
        os.makedirs(out_dir, exist_ok=True)
        from playwright.sync_api import sync_playwright
        shots = []
        urls = [u for u in urls if u.startswith(("http://", "https://"))][:self.max_urls]
        try:
            p = sync_playwright().start()
            browser = p.chromium.launch(headless=True)
        except Exception as exc:
            return {"shots": [], "skipped": True,
                    "error": f"playwright browser not available: {exc}"}
        try:
            for url in urls:
                fname = None
                try:
                    page = browser.new_page(
                        viewport={"width": self.width, "height": self.height})
                    page.set_default_timeout(self.timeout_ms)
                    resp = page.goto(url, wait_until="domcontentloaded")
                    try:
                        page.wait_for_timeout(2500)
                    except Exception:
                        pass
                    status = resp.status if resp else 0
                    host = (urlsplit(url).hostname or "host").replace(".", "_")
                    fname = os.path.join(out_dir, f"{host}.png")
                    page.screenshot(path=fname, full_page=False)
                    shots.append({"url": url, "file": fname, "status": status})
                    page.close()
                except Exception as exc:
                    shots.append({"url": url, "file": fname, "error": str(exc)[:120]})
                    try:
                        page.close()
                    except Exception:
                        pass
        finally:
            try:
                browser.close()
            except Exception:
                pass
            try:
                p.stop()
            except Exception:
                pass
        return {"shots": shots, "skipped": False}