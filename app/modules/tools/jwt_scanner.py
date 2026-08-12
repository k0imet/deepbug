"""
jwt_scanner.py — passive JWT audit, no replay of forged tokens.

  1. find JWTs in supplied texts or by fetching page bodies (eyJ regex)
  2. decode header + payload locally (base64url, missing padding tolerated),
     report alg, exp, iss and role/admin claims
  3. alg == HS256: attempt an offline crack against a small built-in weak-key
     list (hmac/sha256). A cracked key is a real finding - the attacker can
     forge tokens for this service.

Forged or modified tokens are NEVER sent to any endpoint.

SAFETY: GET-only; all token processing happens locally.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import os
import re
import sys
from typing import Dict, List, Optional

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_UA = f"Mozilla/5.0 {PROGRAM_UA_TAG}"
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_WEAK_KEYS = ("password", "secret", "secret_key", "123456", "key", "jwt_secret",
              "changeme", "secret123", "12345678", "admin", "test", "qwerty",
              "abc123", "s3cr3t", "letmein", "iloveyou", "passw0rd", "jwt",
              "secretkey", "supersecret")


def find_jwts(text: str) -> List[str]:
    """All unique JWT-looking tokens in a text, in order of appearance."""
    if not text:
        return []
    return list(dict.fromkeys(_JWT_RE.findall(text)))


def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> Dict:
    """Decode header + payload of a JWT without touching any network."""
    head, pay, _ = token.split(".")
    header = json.loads(_b64url_decode(head))
    payload = json.loads(_b64url_decode(pay))
    return {"header": header, "payload": payload}


def _signature_bytes(token: str) -> bytes:
    sig = token.split(".")[2]
    sig = sig.replace("-", "+").replace("_", "/")
    sig += "=" * (-len(sig) % 4)
    return base64.urlsafe_b64decode(sig)


def crack_jwt(token: str, keys: Optional[List[str]] = None) -> Optional[str]:
    """Return the weak key the token signs with, or None. Offline only."""
    try:
        head, pay, _ = token.split(".")
        sig = _signature_bytes(token)
    except Exception:
        return None
    msg = f"{head}.{pay}".encode()
    for k in keys or _WEAK_KEYS:
        if hmac.compare_digest(hmac.new(k.encode(), msg, hashlib.sha256).digest(), sig):
            return k
    return None


class JWTScanner:
    def __init__(self, timeout: float = 10.0, keys: Optional[List[str]] = None,
                 concurrency: int = 8):
        self.timeout = timeout
        self.keys = keys or _WEAK_KEYS
        self.concurrency = concurrency

    async def _get(self, session, url: str):
        try:
            async with session.get(url, headers={"User-Agent": _UA},
                                   timeout=self.timeout) as r:
                return r.status, await r.text(errors="replace")
        except Exception:
            return 0, None

    def _audit(self, source_url: str, token: str) -> Dict:
        entry = {"source_url": source_url, "jwt": token, "alg": "",
                 "claims": {}, "cracked_key": "", "note": ""}
        try:
            data = decode_jwt(token)
        except Exception:
            entry["note"] = "malformed token (undecodable)"
            return entry
        header, payload = data["header"], data["payload"]
        entry["alg"] = str(header.get("alg", ""))
        entry["claims"] = payload
        alg = entry["alg"].upper()
        if alg == "HS256":
            key = crack_jwt(token, self.keys)
            if key:
                entry["cracked_key"] = key
                entry["note"] = "FORGEABLE: token signs with weak key"
            else:
                entry["note"] = "HS256, built-in weak keys did not match"
        elif alg == "NONE":
            entry["note"] = "alg=none - signature is not enforced"
        else:
            entry["note"] = f"{alg} - offline weak-key crack not applicable"
        return entry

    async def scan(self, urls: List[str]) -> List[Dict]:
        sem = asyncio.Semaphore(self.concurrency)
        out: List[Dict] = []
        async with aiohttp.ClientSession() as session:
            async def one(url):
                async with sem:
                    _, body = await self._get(session, url)
                    return [self._audit(url, t) for t in find_jwts(body or "")]
            results = await asyncio.gather(*(one(u) for u in urls))
        return [e for group in results for e in group]

    def scan_sync(self, urls: List[str]) -> List[Dict]:
        return asyncio.run(self.scan(urls))


def _main():
    args = sys.argv[1:]
    if not args:
        print(f"usage: {sys.argv[0]} <url-with-maybe-a-jwt> [...]")
        print("       or pipe raw text on stdin")
        sys.exit(1)
    if args == ["-"]:
        text = sys.stdin.read()
        for t in find_jwts(text):
            print(json.dumps(JWTScanner()._audit("stdin", t)))
        sys.exit(0)
    for e in JWTScanner().scan_sync(args):
        print(f"alg={e['alg']} cracked={e['cracked_key']!r} note={e['note']} {e['source_url']}")


if __name__ == "__main__":
    _main()