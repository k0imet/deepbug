"""
forgot_password_prober.py — response-differential forgot-password prober.

With allow_post=True:
  GET the reset form, extract the csrf / authenticity_token and the action
  URL, then POST it exactly twice (2s apart):
    - with a known_good_email provided: known-good account vs one random
      syntactically-valid but non-existent mailbox. Differing status / body
      length / redirect between the two responses = enumeration lead.
    - without known_good_email: two random non-existent mailboxes only - the
      result is marked inconclusive (differs = None).
  Any POST response body containing a reset token/link
  ('reset_password_token', '/customers/password/edit?reset_password_token=')
  is a token-in-response finding.

SAFETY: POSTs only when allow_post=True; strictly 2 POSTs max, spaced 2s
        apart, both to the target's own endpoint, with non-existent mailboxes.
"""

import asyncio
import os
import random
import re
import sys
from typing import Dict, List, Optional
from urllib.parse import urljoin

import aiohttp

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

from app.utils.user_agents import PROGRAM_UA_TAG

_UA = f"Mozilla/5.0 {PROGRAM_UA_TAG}"
_FORM_RE = re.compile(r"<form[^>]*>", re.I)
_INPUT_RE = re.compile(r"<input[^>]*>", re.I)
_TOKEN_MARKERS = ("reset_password_token",
                  "/customers/password/edit?reset_password_token=")


def nonexistent_email() -> str:
    return "nope%08x@nonexistent-domain-99.com" % random.getrandbits(32)


def extract_form(body: str, base_url: str) -> Dict:
    """Pull (action, csrf field, email field, hidden fields) from a form."""
    form = {"action": None, "csrf": None, "email_field": "email", "fields": {}}
    fm = _FORM_RE.search(body or "")
    if fm:
        am = re.search(r'action\s*=\s*["\']([^"\']+)["\']', fm.group(0), re.I)
        if am:
            form["action"] = urljoin(base_url, am.group(1))
    for inp in _INPUT_RE.findall(body or ""):
        nm = re.search(r'name\s*=\s*["\']?([^"\'>\s]+)', inp, re.I)
        if not nm:
            continue
        name = nm.group(1)
        tm = re.search(r'type\s*=\s*["\']([^"\']+)["\']', inp, re.I)
        itype = tm.group(1).lower() if tm else "text"
        vm = re.search(r'value\s*=\s*["\']([^"\']*)["\']', inp, re.I)
        form["fields"][name] = vm.group(1) if vm else ""
        if re.search(r"token|csrf", name, re.I) and not form["csrf"]:
            form["csrf"] = name
        if re.search(r"email", name, re.I) or itype == "email":
            form["email_field"] = name
    return form


def _token_in_body(body: Optional[str]) -> bool:
    return bool(body) and any(t in body for t in _TOKEN_MARKERS)


class ForgotPasswordProber:
    def __init__(self, allow_post: bool = False, timeout: float = 10.0,
                 post_delay: float = 2.0):
        self.allow_post = allow_post
        self.timeout = timeout
        self.post_delay = post_delay

    async def _fetch(self, session, method: str, url: str, data=None):
        hdrs = {"User-Agent": _UA}
        try:
            async with session.request(method, url, headers=hdrs, data=data,
                                       timeout=self.timeout) as r:
                body = await r.text(errors="replace")
                return r.status, str(r.url), body
        except Exception:
            return 0, "", None

    async def _scan_one(self, session, url: str, known_good_email: Optional[str],
                        allow_post: bool) -> Dict:
        statuses: Dict[str, int] = {}
        s_get, final_get, b_get = await self._fetch(session, "GET", url)
        statuses["get"] = s_get
        out = {"url": url, "differs": None, "token_in_body": False,
               "statuses": statuses, "note": ""}
        if not allow_post:
            out["token_in_body"] = _token_in_body(b_get)
            out["note"] = "allow_post=False; GET only, no POST sent"
            return out

        form = extract_form(b_get, final_get)
        if not form["fields"] and not form["csrf"]:
            out["note"] = "no reset form found; no POST sent"
            return out
        target = form["action"] or url

        rand1, rand2 = nonexistent_email(), nonexistent_email()
        if known_good_email:
            email1, email2 = known_good_email, rand1
        else:
            email1, email2 = rand1, rand2
            out["note"] = "inconclusive: known_good_email not provided"

        payload = dict(form["fields"])
        payload[form["email_field"]] = email1
        s1, fin1, b1 = await self._fetch(session, "POST", target, payload)
        await asyncio.sleep(self.post_delay)
        payload[form["email_field"]] = email2
        s2, fin2, b2 = await self._fetch(session, "POST", target, payload)
        statuses["post_1"] = s1
        statuses["post_2"] = s2

        if known_good_email and s1 and s2:
            out["differs"] = bool(
                s1 != s2 or len(b1 or "") != len(b2 or "") or fin1 != fin2)
        out["token_in_body"] = _token_in_body(b1) or _token_in_body(b2)
        if out["token_in_body"]:
            out["note"] = "reset token/link present in POST response"
        return out

    async def scan(self, urls: List[str], known_good_email: Optional[str] = None,
                   allow_post: Optional[bool] = None) -> List[Dict]:
        allow_post = self.allow_post if allow_post is None else allow_post
        async with aiohttp.ClientSession() as session:
            results = []
            for u in urls:
                results.append(await self._scan_one(session, u, known_good_email,
                                                    allow_post))
        return results

    def scan_sync(self, urls: List[str], known_good_email: Optional[str] = None,
                  allow_post: Optional[bool] = None) -> List[Dict]:
        return asyncio.run(self.scan(urls, known_good_email=known_good_email,
                                     allow_post=allow_post))


def _main():
    args = sys.argv[1:]
    if not args:
        print(f"usage: {sys.argv[0]} [--post] [--known <email>] <reset-url> [...]")
        sys.exit(1)
    post = "--post" in args
    known = None
    if "--known" in args:
        known = args[args.index("--known") + 1]
    urls = [a for a in args if not a.startswith("--") and a != known]
    for e in ForgotPasswordProber(allow_post=post).scan_sync(urls, known, post):
        print(f"differs={e['differs']} token_in_body={e['token_in_body']} "
              f"statuses={e['statuses']} note={e['note']} {e['url']}")


if __name__ == "__main__":
    _main()