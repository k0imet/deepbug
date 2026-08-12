"""
websocket_scanner.py — CSWSH-style websocket endpoint discovery (recon-only).

Probes a fixed path list under each base URL with an RFC6455 client handshake
(GET Upgrade: websocket). Records 101 upgrades, and 400/403 replies that echo
Sec-WebSocket-* / Upgrade headers. On 101 the socket is closed immediately
after one benign text frame (__ping__) — nothing is read, no message forging.
cookie_auth=True means a session cookie from the aiohttp jar was attached;
origin_required=False + cookie_auth=True = handshake accepted without an
Origin header = missing CSWSH mitigation signal (still recon-only).

Deeper confirmation (per-message auth over the socket, same-user/session
checks) is a manual step — this module never tries to use the socket.

SAFETY: read-only handshakes, WSS only on https hosts, bounded path list,
one benign frame max on 101, no auth/session attempts.
"""

import asyncio
import base64
import os
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_WSPATHS = ["/ws", "/websocket", "/socket", "/sockjs-node", "/api/ws", "/ws/v1"]
_SEC_VERSION = "Sec-WebSocket-Version"
_SEC_ACCEPT = "Sec-WebSocket-Accept"
_UPGRADE = "Upgrade"


def _wss_url(base: str, path: str) -> str:
    u = urlparse(base if "://" in base else "https://" + base)
    netloc = u.netloc or u.hostname
    return f"wss://{netloc}{path}"


def _classify(status: int, headers) -> int:
    if status == 101:
        return 101
    if status in (400, 403):
        echo = headers.get(_SEC_VERSION) or headers.get(_SEC_ACCEPT) or headers.get(_UPGRADE)
        if echo:
            return status
    return 0


class WebSocketScanner:
    """CSWSH-recon probe: which endpoints speak RFC6455, and do they
    require an Origin / send cookies to the handshake endpoint."""

    def __init__(self, timeout: float = 10.0, concurrency: int = 4,
                 prime_session: bool = True):
        self.timeout = timeout
        self.concurrency = concurrency
        self.prime_session = prime_session

    async def _handshake(self, session, url: str) -> Optional[Dict]:
        key = base64.b64encode(os.urandom(16)).decode()
        headers = {
            "User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}",
            "Connection": "Upgrade",
            _UPGRADE: "websocket",
            "Sec-WebSocket-Key": key,
            _SEC_VERSION: "13",
        }
        jar_cookies = session.cookie_jar.filter_cookies(url)
        cookie_auth = len(jar_cookies) > 0
        try:
            async with session.get(url, headers=headers, timeout=self.timeout,
                                   allow_redirects=False) as r:
                status = r.status
                code = _classify(status, r.headers)
                if code == 101:
                    try:
                        conn = r.connection
                        if conn is not None:
                            tr = getattr(conn, "transport", None)
                            if tr is not None:
                                tr.write(b"\x81\x07__ping__")
                    except Exception:
                        pass
                return {
                    "url": url,
                    "handshake": code,
                    "cookie_auth": cookie_auth,
                    "origin_required": False if code == 101 else (True if code in (400, 403) else None),
                }
        except Exception:
            return {"url": url, "handshake": 0, "cookie_auth": cookie_auth,
                    "origin_required": None}

    async def _prime(self, session, base: str):
        if not self.prime_session:
            return
        try:
            async with session.get(base, headers={"User-Agent": f"Mozilla/5.0 {PROGRAM_UA_TAG}"},
                                   timeout=self.timeout, allow_redirects=False):
                pass
        except Exception:
            pass

    async def scan(self, base_url: str) -> List[Dict]:
        """Probe all WSS candidates under base_url. https/wss bases only."""
        u = urlparse(base_url if "://" in base_url else "https://" + base_url)
        if u.scheme not in ("https", "wss"):
            return []
        base = f"{u.scheme}://{u.netloc or u.hostname}"
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession() as session:
            await self._prime(session, base)
            async def one(path: str):
                async with sem:
                    return await self._handshake(session, _wss_url(base, path))
            return await asyncio.gather(*[one(p) for p in _WSPATHS])

    def scan_sync(self, base_url: str) -> List[Dict]:
        return asyncio.run(self.scan(base_url))


def _main():
    urls = sys.argv[1:]
    if not urls:
        print(f"usage: {sys.argv[0]} <https-base-url...>")
        sys.exit(1)
    s = WebSocketScanner()
    for u in urls:
        print(f"== {u}")
        for hit in s.scan_sync(u):
            tag = ("<== WS endpoint" if hit["handshake"] else "")
            print(f"   {hit['handshake']:>3} {hit['url']} "
                  f"[cookie_auth={hit['cookie_auth']} origin_required={hit['origin_required']}] {tag}")


if __name__ == "__main__":
    _main()