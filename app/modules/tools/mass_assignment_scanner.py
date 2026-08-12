# modules/tools/mass_assignment_scanner.py
# Active mass-assignment & type-juggling scanner (Sam Curry style).
#
# Mass assignment: POST JSON bodies with privilege/business-logic fields the
# client never sends (admin, role, is_admin, price, verified...) and diff the
# response vs a benign baseline - a backend that silently honors them leaks it
# via status change, body growth, or new privilege keywords.
#
# Type juggling: for endpoints with query params, resend values as the wrong
# type (array, object, bool, null) - verbose 500s / framework errors / type
# confusion in the response are reportable leads.
#
# Config (optional):
#   mass_assignment.max_endpoints   -> cap (default 20)
#   mass_assignment.extra_fields    -> dict of extra fields to inject

import asyncio
import json
import re
from typing import List, Dict, Optional, Callable
from app.utils.url_utils import urlparse
from urllib.parse import parse_qsl, urlencode, urlunparse

import httpx

from app.utils.logger import get_logger

logger = get_logger()

DEFAULT_INJECT_FIELDS = {
    # privilege escalation
    "admin": True, "is_admin": True, "isAdmin": True, "role": "admin",
    "roles": ["admin"], "is_staff": True, "staff": True, "superuser": True,
    "verified": True, "email_verified": True, "active": True,
    # business logic
    "price": 0, "amount": 0, "discount": 100, "balance": 999999,
    "quantity": -1, "plan": "enterprise", "tier": "premium", "subscription": "pro",
    # feature/debug flags
    "debug": True, "test": True, "internal": True, "env": "production",
}

PRIV_KEYWORDS = re.compile(
    r'"(admin|role|is_admin|isAdmin|staff|superuser|verified|plan|tier|balance|discount)"\s*:',
    re.IGNORECASE)

JUGGLE_VARIANTS = [
    ("array", lambda v: [v, v]),
    ("object", lambda v: {"deepbug": v}),
    ("bool", lambda v: True),
    ("null", lambda v: None),
    ("int", lambda v: 0),
]


class MassAssignmentScanner:
    def __init__(self, config: Dict):
        self.config = config
        ma_cfg = config.get('mass_assignment', {})
        self.max_endpoints = int(ma_cfg.get('max_endpoints', 20))
        self.inject_fields = dict(DEFAULT_INJECT_FIELDS)
        self.inject_fields.update(ma_cfg.get('extra_fields', {}))
        self.last_errors: List[str] = []

    # -----------------------------------------------------------------
    # Baseline helpers
    # -----------------------------------------------------------------
    @staticmethod
    async def _safe_json(resp: httpx.Response):
        try:
            return resp.json()
        except Exception:
            return None

    async def _baseline(self, client: httpx.AsyncClient, url: str) -> Optional[Dict]:
        """Baseline: benign POST {} and GET. Records status/length/keys."""
        try:
            r_post = await client.post(url, json={})
            return {
                "post_status": r_post.status_code,
                "post_len": len(r_post.text),
                "post_keys": set((await self._safe_json(r_post) or {}).keys())
                if isinstance(await self._safe_json(r_post), dict) else set(),
                "accepted_post": r_post.status_code not in (404, 405, 501),
            }
        except Exception as e:
            logger.debug(f"Baseline failed for {url}: {e}")
            return None

    # -----------------------------------------------------------------
    # Mass assignment probes (POST JSON)
    # -----------------------------------------------------------------
    async def _probe_mass_assignment(self, client: httpx.AsyncClient, url: str, base: Dict) -> List[Dict]:
        findings = []
        if not base.get("accepted_post"):
            return findings

        # Probe in small groups so one field doesn't mask another
        fields = list(self.inject_fields.items())
        groups = [fields[i:i + 4] for i in range(0, len(fields), 4)]

        for group in groups:
            body = dict(group)
            try:
                resp = await client.post(url, json=body)
            except Exception:
                continue

            signals = []
            if resp.status_code != base["post_status"]:
                signals.append(f"status {base['post_status']}->{resp.status_code}")
            if abs(len(resp.text) - base["post_len"]) > max(200, base["post_len"] * 0.3):
                signals.append(f"body {base['post_len']}->{len(resp.text)} chars")

            data = await self._safe_json(resp)
            if isinstance(data, dict):
                new_keys = set(data.keys()) - base["post_keys"]
                priv_new = [k for k in new_keys if PRIV_KEYWORDS.search(f'"{k}":')]
                if priv_new:
                    signals.append(f"new privilege keys in response: {', '.join(sorted(priv_new))}")
                # reflected acceptance: server echoed our injected value
                for k, v in group:
                    if k in data and data[k] == v:
                        signals.append(f"server accepted '{k}={json.dumps(v)}' verbatim")

            if signals:
                findings.append({
                    "URL": url,
                    "Technique": "mass-assignment",
                    "Injected": json.dumps(body),
                    "Evidence": "; ".join(signals),
                    "Severity": "HIGH" if any("privilege" in s or "accepted" in s for s in signals) else "MEDIUM",
                })
                break  # one strong signal per endpoint is enough
        return findings

    # -----------------------------------------------------------------
    # Type juggling probes (GET query params)
    # -----------------------------------------------------------------
    async def _probe_type_juggling(self, client: httpx.AsyncClient, url: str) -> List[Dict]:
        parsed = urlparse(url)
        qs = dict(parse_qsl(parsed.query))
        if not qs:
            return []

        findings = []
        try:
            base_resp = await client.get(url)
            base_status, base_len = base_resp.status_code, len(base_resp.text)
        except Exception:
            return findings

        for param, orig_val in list(qs.items())[:3]:  # cap params per endpoint
            for variant_name, fn in JUGGLE_VARIANTS:
                try:
                    juggled_qs = {**qs, param: fn(orig_val)}
                    # httpx encodes lists as repeated params; dicts/bools via json-ish string
                    resp = await client.get(url, params=juggled_qs)
                except Exception:
                    continue

                interesting = []
                if resp.status_code >= 500 and base_status < 500:
                    interesting.append(f"500 triggered ({base_status}->{resp.status_code})")
                m = re.search(r'(Traceback|NullPointerException|TypeError|Warning:|stack trace|SQLException|InvalidCastException|System\.InvalidOperation)', resp.text)
                if m:
                    interesting.append(f"framework error leaked: {m.group(1)}")

                if interesting:
                    findings.append({
                        "URL": url,
                        "Technique": "type-juggling",
                        "Injected": f"{param} as {variant_name}",
                        "Evidence": "; ".join(interesting),
                        "Severity": "MEDIUM",
                    })
                    break
            if findings:
                break
        return findings

    # -----------------------------------------------------------------
    # Main entry
    # -----------------------------------------------------------------
    async def _scan_all(self, urls: List[str],
                        progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        results: List[Dict] = []
        total = len(urls)
        sem = asyncio.Semaphore(8)

        async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
            async def one(idx, url):
                async with sem:
                    if progress_callback:
                        progress_callback(idx / total, f"[{idx + 1}/{total}] {url}")
                    base = await self._baseline(client, url)
                    if not base:
                        return
                    results.extend(await self._probe_mass_assignment(client, url, base))
                    results.extend(await self._probe_type_juggling(client, url))

            await asyncio.gather(*[one(i, u) for i, u in enumerate(urls)])

        if progress_callback:
            progress_callback(1.0, f"Done: {len(results)} leads")
        return results

    def scan(self, urls: List[str],
             progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        """Synchronous entry - safe inside Streamlit's running event loop."""
        self.last_errors = []
        if not urls:
            return []
        urls = list(dict.fromkeys(urls))[:self.max_endpoints]

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(asyncio.run, self._scan_all(urls, progress_callback)).result()
        return asyncio.run(self._scan_all(urls, progress_callback))