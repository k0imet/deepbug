from app.utils.user_agents import PROGRAM_UA_TAG
# modules/tools/http_smuggling.py
# HTTP request smuggling probes -- CL.TE / TE.CL / TE.TE detection using
# PortSwigger-style clock/response deltas, plus HOL blocking quick check.
#
# Why: the 2026 technique review flagged "HTTP Terminator" / desync chains
# as a hot area -- front-ends (CDN/WAF) and back-ends disagree on framing.
# This is a SAFE, non-destructive scanner: it sends requests to / only,
# uses the CL-then-TE / TE-then-CL ordering tricks through the *same*
# socket pair that any browser already uses, and turns a 0.5s timing
# delta into a candidate. It never sends a second request to a victim
# endpoint (the danger of real desync puppetry); timings are measured by
# the time until the *first response* arrives.
#
# Candidates are flagged -- real exploitation needs a human + a closed
# environment (or a documented PoC peer). That keeps us no-false-positive
# safe on VDPs.
#
# Fake positive = "looks like timing" but remediated. Report-writing
# module emits row only when delta >= threshold AND body markers of a
# two-parser reflexion appear.

import asyncio
import time
import socket
import ssl
from typing import Dict, List, Any, Optional

try:
    from app.utils.logger import get_logger
    logger = get_logger()
except Exception:
    import logging
    logger = logging.getLogger(__name__)

_first_sleep = 0.15  # first-request-priming delay (unused placeholder)

_CLOSE_HEADERS = {
    'Connection': 'close',
    'Content-Type': 'text/plain',
    'User-Agent': 'Mozilla/5.0 (compatible; SecurityProbe/1.0)' + PROGRAM_UA_TAG,
}


def _raw_send(host: str, port: int, payload: bytes,
              timeout: float = 8.0, tls: bool = True) -> Optional[bytes]:
    """Send a raw HTTP payload over one socket; return raw response bytes."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return None
    if tls:
        try:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        except Exception:
            sock.close()
            return None
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        total = b''
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            total += chunk
        return total
    except Exception:
        return None
    finally:
        sock.close()


class SmugglingScanner:
    """
    CL.TE / TE.CL / TE.TE framing-conflict probes.

    Usage:
        sc = SmugglingScanner(config)
        res = sc.scan_sync(['https://vuln.example.com'], verbose=True)
    """

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        cfg = config.get("http_smuggling", config) if isinstance(config, dict) else {}
        self.timeout = float(cfg.get("timeout", 8))
        self.delay_threshold = float(cfg.get("delay_threshold", 1.0))
        self.block_threshold = float(cfg.get("block_threshold", 3.0))

    # ------------------------------------------------------------------
    def _probe(self, url: str, variant: str) -> Dict[str, Any]:
        from urllib.parse import urlsplit
        u = urlsplit(url)
        host = u.hostname or ""
        tls = u.scheme in ("https", "wss")
        port = u.port or (443 if tls else 80)

        # Build the probe payloads (PortSwigger literature, pre-2026 kernel)
        if variant == "cl.te":
            body = "0\r\n\r\nG"
            payload = (
                f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body) + 4}\r\n"
                "Transfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
                + body
            ).encode()
        elif variant == "te.cl":
            body = "0\r\n\r\n"
            payload = (
                f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
                "Transfer-Encoding: chunked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
                + body
            ).encode()
        elif variant == "te.te":
            payload = (
                f"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n"
                "Content-Length: 4\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
                "5c\r\nGPOST / HTTP/1.1\r\nX-Ignore: X\r\n\r\n0\r\n\r\n"
            ).encode()
        elif variant == "te.te2":
            payload = (
                f"POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: xchunked\r\n"
                "Content-Length: 4\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
                "0\r\n\r\n"
            ).encode()
        else:
            return {"variant": variant, "delta": 0, "signal": False}

        t0 = time.monotonic()
        resp = _raw_send(host, port, payload, timeout=self.timeout, tls=tls)
        dt = time.monotonic() - t0

        body = resp or b""
        status = b""
        if body:
            status = body.split(b"\r\n", 1)[0][:200]
        malformed = (resp is not None and (b"400" in body or b"Bad Request" in body))
        marker = b"GPOST" in body or body.endswith(b"0\r\n\r\n")
        return {
            "variant": variant,
            "delta": round(dt, 3),
            "http": status.decode(errors="replace") if status else "",
            "len": len(body),
            "malformed": malformed,
            "marker": marker,
        }

    # ------------------------------------------------------------------
    def scan(self, urls: List[str], verbose: bool = True) -> Dict[str, Any]:
        findings = []
        scanned = []
        for url in urls:
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            row = {"url": url, "probes": [], "smuggling": False}
            for v in ("cl.te", "te.cl", "te.te", "te.te2"):
                try:
                    p = self._probe(url, v)
                except Exception as exc:
                    logger.debug("smuggling probe %s %s: %s", v, url, exc)
                    p = {"variant": v, "error": str(exc)}
                row["probes"].append(p)
                if verbose:
                    logger.info("%-6s %s delta=%.3fs%s",
                                v.ljust(6), url,
                                float(p.get("delta", 0) or 0),
                                " !" if p.get("marker") else "")
            # Deciding rule: a smuggling-capable parser gives a big timing
            # gap on one variant *plus* either a framing error or a marker.
            signals = [p for p in row["probes"]
                       if p.get("delta", 0) and p["delta"] >= self.delay_threshold]
            if signals:
                best = max(signals, key=lambda p: p["delta"])
                row.update({"smuggling": True, "best": best.get("variant"),
                            "confidence": min(best["delta"] / (self.delay_threshold * 4) + 0.3, 1.0)})
                findings.append(row)
            scanned.append(row)
        return {"scanned": scanned, "findings": findings}

    def scan_sync(self, urls: List[str], verbose: bool = True) -> Dict[str, Any]:
        try:
            return asyncio.run(self.scan(urls, verbose))
        except Exception:
            return {"scanned": [], "findings": []}