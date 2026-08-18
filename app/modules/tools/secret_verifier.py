"""secret_verifier.py

v3.6.1: OPT-IN, READ-ONLY live verification of extracted secrets.

Safety posture (do not change):
  - Never runs inside the JS scan pipeline - only when explicitly invoked.
  - Read-only GET / auth.test endpoints only; no writes, no mutations.
  - Keys are sent to their OWN provider over TLS using standard Auth headers.
  - Results are labeled (live/invalid/unknown) - never treated as a finding.
"""
import asyncio
import logging
from typing import Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

_RESPONSE_LIMIT = 2000


class SecretVerifier:
    def __init__(self, config: Optional[Dict] = None, timeout: int = 10):
        cfg = config or {}
        self.timeout = int(cfg.get('secret_verify_timeout', 10))
        self.concurrency = int(cfg.get('secret_verify_concurrency', 8))

    # ------------------------------------------------------------------
    async def _probe(self, session, method: str, url: str, headers: Dict,
                     cred_tail: str, body=None) -> Optional[int]:
        try:
            async with session.request(method, url, headers=headers,
                                       timeout=aiohttp.ClientTimeout(total=self.timeout),
                                       ssl=True, data=body) as r:
                await r.read()
                return r.status
        except Exception:
            return None

    async def verify_one(self, session, service: str, value: str,
                         extra: Optional[Dict] = None) -> Dict:
        v = str(value).strip()
        extra = extra or {}
        result = {'value': v, 'service': service, 'status': 'unknown', 'detail': ''}
        try:
            if service == 'GitHub':
                st = await self._probe(session, 'GET', 'https://api.github.com/user',
                                       {'Authorization': f'token {v}', 'Accept': 'application/vnd.github+json'},
                                       v[-8:])
                result.update({'status': 'live' if st == 200 else ('invalid' if st in (401, 403) else 'unknown'),
                               'detail': f'GET /user -> {st}'})
            elif service == 'Slack':
                st = await self._probe(session, 'POST', 'https://slack.com/api/auth.test',
                                       {'Authorization': f'Bearer {v}',
                                        'Content-Type': 'application/x-www-form-urlencoded'}, v[-8:])
                # auth.test is read-only lookup of the token's identity
                result.update({'status': 'live' if st == 200 else 'unknown',
                               'detail': f'POST auth.test (read-only) -> {st}'})
            elif service == 'Stripe':
                st = await self._probe(session, 'GET', 'https://api.stripe.com/v1/charges?limit=1',
                                       {'Authorization': f'Bearer {v}'}, v[-8:])
                result.update({'status': 'live' if st == 200 else ('invalid' if st == 401 else 'unknown'),
                               'detail': f'GET /v1/charges?limit=1 -> {st}',
                               'mode': 'test' if v.startswith('sk_test') else ('live' if v.startswith('sk_live') else '')})
            elif service == 'SendGrid':
                st = await self._probe(session, 'GET', 'https://api.sendgrid.com/v3/scopes',
                                       {'Authorization': f'Bearer {v}'}, v[-8:])
                result.update({'status': 'live' if st == 200 else ('invalid' if st in (401, 403) else 'unknown'),
                               'detail': f'GET /v3/scopes -> {st}'})
            elif service == 'Mailgun':
                st = await self._probe(session, 'GET', 'https://api.mailgun.net/v3/domains',
                                       {'Authorization': 'Basic ' + __import__('base64').b64encode(
                                           f'api:{v}'.encode()).decode()}, v[-8:])
                result.update({'status': 'live' if st == 200 else 'unknown',
                               'detail': f'GET /v3/domains -> {st}'})
            else:
                result['detail'] = 'no verifier for this service (read-only check unavailable)'
        except Exception as e:
            result['detail'] = f'error: {type(e).__name__}: {str(e)[:80]}'
        return result

    async def _run_all(self, rows: List[Dict]) -> List[Dict]:
        conn = aiohttp.TCPConnector(limit_per_host=4, ssl=False)
        sem = asyncio.Semaphore(self.concurrency)
        async with aiohttp.ClientSession(connector=conn) as session:
            async def one(row):
                async with sem:
                    return await self.verify_one(session, row.get('service', ''),
                                                 row.get('value', ''), row)
            return await asyncio.gather(*[one(r) for r in rows])

    def verify_batch(self, rows: List[Dict]) -> List[Dict]:
        """rows: [{'service':..., 'value':..., ...}]. Synchronous wrapper."""
        if not rows:
            return []
        return asyncio.run(self._run_all(rows))


def run_cli(rows_path: Optional[str] = None, service: Optional[str] = None,
            value: Optional[str] = None) -> int:
    """CLI entry: python3 -m app.modules.tools.secret_verifier [--service X --value Y]"""
    rows = []
    if rows_path:
        import json
        with open(rows_path) as f:
            rows = json.load(f)
    if service and value:
        rows.append({'service': service, 'value': value})
    v = SecretVerifier()
    for r in v.verify_batch(rows):
        print(f"{r['service']:10} {r['value'][:24]:26} {r['status']:8} {r['detail']}")
    return 0


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='Opt-in read-only secret verification')
    ap.add_argument('--json', help='JSON file with [{"service":..., "value":...}, ...]')
    ap.add_argument('--service')
    ap.add_argument('--value')
    args = ap.parse_args()
    raise SystemExit(run_cli(args.json, args.service, args.value))
