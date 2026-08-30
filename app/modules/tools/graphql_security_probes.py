"""
graphql_security_probes.py — bug-bounty-relevant GraphQL misconfiguration checks.

Run against a confirmed endpoint (e.g. everything in GraphQLScanner results).
Every probe is READ-ONLY: all queries are `{ __typename }` or a deliberately
malformed field name. Nothing mutates state.

What it flags (and why it matters on a report):
  - introspection_enabled     : full schema disclosure
  - field_suggestions_enabled : "Did you mean" leaks field names even when
                                introspection is off -> schema recoverable
                                (this is the basis of clairvoyance-style attacks)
  - batching_enabled          : array payloads -> rate-limit / OTP brute-force
                                bypass, and alias-overloading DoS surface
  - get_method_enabled        : query over GET -> CSRF / cache-poisoning surface;
                                worth checking if mutations are GET-reachable too
  - csrf_form_enabled         : x-www-form-urlencoded accepted -> no preflight,
                                CSRF-able
"""

import re
import json
import asyncio
import aiohttp
from urllib.parse import urlparse
from typing import Dict, Optional


class GraphQLSecurityProbes:
    def __init__(self, timeout: int = 12):
        self.timeout = timeout

    async def run_all(self, session: aiohttp.ClientSession, endpoint: str,
                      introspection_ok: bool = False) -> Dict:
        findings = {
            "endpoint": endpoint,
            "introspection_enabled": bool(introspection_ok),
            "field_suggestions_enabled": False,
            "batching_enabled": False,
            "get_method_enabled": False,
            "csrf_form_enabled": False,
            "suggested_fields": [],
            "notes": [],
            "alias_overload_limit": None,
            "subscription_ws": False,
        }
        await asyncio.gather(
            self._check_suggestions(session, endpoint, findings),
            self._check_batching(session, endpoint, findings),
            self._check_get(session, endpoint, findings),
            self._check_csrf_form(session, endpoint, findings),
            self._check_alias_overload(session, endpoint, findings),
            self._check_subscription_ws(session, endpoint, findings),
            return_exceptions=True,
        )
        self._summarize(findings)
        return findings

    async def _post_json(self, session, endpoint, payload):
        async with session.post(endpoint, json=payload, timeout=self.timeout) as r:
            return r.status, await r.text()

    @staticmethod
    def _typename_resolved(text: str) -> bool:
        try:
            payload = json.loads(text)
            return (isinstance(payload, dict) and
                    isinstance(payload.get('data'), dict) and
                    isinstance(payload['data'].get('__typename'), str))
        except Exception:
            return False

    async def _check_suggestions(self, session, endpoint, f):
        # a misspelled root field; a suggestion-enabled server echoes the real name.
        # NOTE: the raw JSON body escapes quotes as \"name\", so tolerate a
        # leading backslash before the quoted suggestion.
        try:
            _, txt = await self._post_json(session, endpoint,
                                           {"query": "query { __typenamee }"})
            m = re.search(r'did you mean\s+\\?["\']?([a-zA-Z_][a-zA-Z0-9_]*)',
                          txt, re.I)
            if m:
                f["field_suggestions_enabled"] = True
                f["suggested_fields"].append(m.group(1))
        except Exception:
            pass

    async def _check_batching(self, session, endpoint, f):
        try:
            _, txt = await self._post_json(
                session, endpoint,
                [{"query": "{__typename}"}, {"query": "{__typename}"}],
            )
            data = json.loads(txt)
            if isinstance(data, list) and len(data) == 2:
                f["batching_enabled"] = True
        except Exception:
            pass

    async def _check_get(self, session, endpoint, f):
        try:
            async with session.get(endpoint, params={"query": "{__typename}"},
                                   timeout=self.timeout) as r:
                txt = await r.text()
                if r.status == 200 and self._typename_resolved(txt):
                    f["get_method_enabled"] = True
        except Exception:
            pass

    async def _check_csrf_form(self, session, endpoint, f):
        try:
            async with session.post(
                endpoint, data={"query": "{__typename}"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.timeout,
            ) as r:
                txt = await r.text()
                if r.status == 200 and self._typename_resolved(txt):
                    f["csrf_form_enabled"] = True
        except Exception:
            pass

    async def _check_alias_overload(self, session, endpoint, f):
        # Alias-overloading: many aliased copies of the same root field in one
        # request. A compliant server rejects at N; a vulnerable one lets them
        # run (DoS / rate-limit bypass). We use a tiny count (24) to stay
        # non-destructive while still detecting the class.
        try:
            aliases = " ".join(f"a{i}: __typename" for i in range(24))
            query = "{%s}" % aliases
            _, txt = await self._post_json(session, endpoint, {"query": query})
            data = json.loads(txt)
            if isinstance(data, dict) and data.get("data") and \
                    len(data["data"]) >= 20:
                f["alias_overload_limit"] = 24
        except Exception:
            pass

    async def _check_subscription_ws(self, session, endpoint, f):
        # CSWSH (cross-site websocket hijacking) probe: if the endpoint hosts a
        # subscription transport, opening a ws with Origin: null / evil origin
        # and a valid-looking connection_init will reveal whether the server
        # enforces origin-checking. We only *open and negotiate* — never send
        # subscription payloads — so this is inert on the target.
        try:
            u = urlparse(endpoint)
            ws_scheme = "wss" if u.scheme == "https" else "ws"
            ws_url = f"{ws_scheme}://{u.netloc}{u.path}"
            headers = {"Origin": "https://evil.example"}  # spoofed, inert
            conn = await asyncio.wait_for(
                session.ws_connect(ws_url, headers=headers,
                                   protocols=["graphql-ws", "graphql-transport-ws"]),
                timeout=4,
            )
            try:
                await asyncio.wait_for(conn.receive(), timeout=3)
                f["subscription_ws"] = True
            except asyncio.TimeoutError:
                pass
            finally:
                await conn.close()
        except Exception:
            pass

    @staticmethod
    def _summarize(f: Dict):
        n = f["notes"]
        if f["introspection_enabled"]:
            n.append("Introspection enabled — full schema disclosure.")
        if f["field_suggestions_enabled"]:
            n.append("Field suggestions enabled — schema recoverable even with "
                     "introspection disabled (clairvoyance).")
        if f["batching_enabled"]:
            n.append("Query batching enabled — rate-limit/brute-force bypass and "
                     "alias-overloading DoS surface.")
        if f["get_method_enabled"]:
            n.append("GET queries accepted — CSRF/cache-poisoning surface; verify "
                     "whether mutations are also reachable via GET.")
        if f["csrf_form_enabled"]:
            n.append("Form-encoded operations accepted — CSRF-able (no preflight).")
        if f["alias_overload_limit"]:
            n.append(f"Alias-overloading: {f['alias_overload_limit']}+ aliases accepted "
                     "in one request — brute-force/DoS surface (check batching too).")
        if f["subscription_ws"]:
            n.append("WebSocket/subscriptions transport present — check CSWSH "
                     "(origin validation) before using.")
