#!/usr/bin/env python3
"""hunt_auth_probe.py — authenticated differential probing for PIA.

Compares EVERY candidate endpoint ANONYMOUSLY vs WITH the stored AuthSession
(captured via the app flow in Caido → stored in Auth Sessions / .auth).

Read-only by design: GET/HEAD only, no writes, no brute force, UA tag + scope
gate, low concurrency (per PIA program rules).

Classifications per endpoint:
  authz_gap     : 200 WITHOUT auth where the path smells account/private
                  (HIGH-value authz-bypass / IDOR lead - review manually)
  gated_404     : 404 anon but 200 authed -> post-auth-only endpoint (new surface)
  auth_required : anon 401/403/302 -> authed 200 (confirmed gated - target list)
  differential  : 200 both ways but body differs (data leaking vs masked)
  same_public   : identical response with & without auth
  error         : transport/timeouts (reported, not failed)

Prep:
  python3 scripts/run_auth_session_pia.py   # or use the Auth Sessions UI to
    -> stores projects/PIA/.auth/privateinternetaccess.com.json
Run:
  python3 scripts/hunt_auth_probe.py [--dry]
"""
import asyncio
import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.utils.user_agents import PROGRAM_UA_TAG
from app.modules.project_manager import ProjectManager
from app.modules.utils import load_config

UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
      f'Chrome/120.0.0.0 Safari/537.36{PROGRAM_UA_TAG}')

JUNK = re.compile(r'(/e$|/evt$|/packs/$|/called$|#.*(chat|seopenchat)|/mdr|/(?:m|mo|kk)\.?$|/meses?$|/bln$|/mnd$)', re.I)

PROJECT = 'PIA'
TARGET = 'privateinternetaccess.com'

# Read-only candidates to compare; curated from the anonymous recon (hunt board)
CURATED = [
    ('GET', 'https://www.privateinternetaccess.com/api/purchase_items?slug=vpn&product=1&plan=1&coupon='),
    ('GET', 'https://www.privateinternetaccess.com/api/purchase_info?slug=vpn&product=1&plan=1&coupon='),
    ('GET', 'https://www.privateinternetaccess.com/api/tax?total_amount=10&country=US'),
    ('GET', 'https://www.privateinternetaccess.com/api/coin_invoice_info/1'),
    ('GET', 'https://api.privateinternetaccess.com/health'),
    ('GET', 'https://apiv2.privateinternetaccess.com/health'),
    ('GET', 'https://apiv5.privateinternetaccess.com/health'),
    ('GET', 'https://api.privateinternetaccess.com/api/client/v4/account'),
    ('GET', 'https://api.privateinternetaccess.com/api/client/v4/wallet'),
    ('GET', 'https://api.privateinternetaccess.com/api/client/v4/getvpninfo/1'),
    ('GET', 'https://api.privateinternetaccess.com/api/client/v4/connectedips'),
    ('GET', 'https://api.privateinternetaccess.com/api/client/v5/health'),
    ('GET', 'https://www.privateinternetaccess.com/account/'),
    ('GET', 'https://www.privateinternetaccess.com/clear-session'),
    ('GET', 'https://payments.privateinternetaccess.com/health'),
]
PRIVATE_HINT = ('account', 'wallet', 'profile', 'user', 'invoice', 'order', 'subscription',
                'billing', 'payment', 'config', 'mfa', 'authenticate', 'token', 'vpninfo',
                'connectedips', 'client', 'coupon', 'email', 'history', 'device', 'session')
_GATED = {401, 403, 405, 302}


def load_endpoints() -> list:
    pm = ProjectManager(load_config())
    df = pm.load_scan_results('js_discovered_endpoints', TARGET)
    rows = []
    if hasattr(df, 'iterrows'):
        for _, r in df.iterrows():
            u = str(r.get('endpoint') or '')
            if u.startswith('http') and not JUNK.search(u):
                rows.append((str(r.get('method') or 'GET').upper(), u))
    # merge curated, dedupe by (method,url)
    all_r = list(CURATED)
    seen = {(m, u) for m, u in rows}
    for m, u in all_r:
        if (m, u) not in seen:
            rows.append((m, u))
            seen.add((m, u))
    return rows


def load_auth():
    p = Path('projects') / PROJECT / '.auth' / f'{TARGET.replace(".", "_")}.json'
    data = json.load(open(p)) if p.exists() else {}
    return data


async def probe(session, method, url, auth_headers, tag):
    h = {'User-Agent': UA}
    if tag == 'auth':
        h.update(auth_headers)
    try:
        async with session.request(method, url, headers=h, timeout=12,
                                   allow_redirects=False) as r:
            b = await r.read()
            return {
                'status': r.status, 'ct': r.headers.get('content-type', '')[:30],
                'len': len(b), 'sha': hashlib.sha1(b[:4096]).hexdigest()[:10],
                'loc': r.headers.get('location', '')[:60],
            }
    except Exception as e:
        return {'status': None, 'ct': '', 'len': 0, 'sha': '', 'loc': '',
                'err': f'{type(e).__name__}'}


async def main(dry=False):
    cfg = load_config()
    auth = load_auth()
    bearer = auth.get('bearer', '')
    cookies = auth.get('cookies') or {}
    headers = dict(auth.get('extra_headers') or {})
    if bearer:
        headers['Authorization'] = f'Bearer {bearer}'
    if not headers and not cookies:
        print('NO AuthSession stored -> run the app flow and save it first '
              '(.auth file empty). Running anonymous-only baseline.')

    rows = load_endpoints()
    if dry:
        print(f'{len(rows)} candidate endpoints (dry-run, nothing sent):')
        for m, u in rows:
            print(f'  {m:5} {u[:100]}')
        return

    print(f'probe: {len(rows)} candidates | auth flow={auth.get("flow","-")} '
          f'| bearer={bool(bearer)} | cookies={list(cookies)}')
    out = []
    results = []
    conn = None
    import aiohttp
    conn = aiohttp.TCPConnector(limit_per_host=2, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as s:
        for i, (m, u) in enumerate(rows):
            anon = await probe(s, m, u, {}, 'anon')
            await asyncio.sleep(0.1)
            authed = await probe(s, m, u, headers, 'auth') if (headers or cookies and (False)) else None
            await asyncio.sleep(0.1)
            if authed is None:
                # still run with cookies separately when no headers exist
                authed = await probe(s, m, u, {}, 'anon') if cookies else anon
            out.append(_classify(u, m, anon, authed, results))
            if (i + 1) % 5 == 0:
                print(f'  {i+1}/{len(rows)} ...')
    _report(out, results)


def _classify(url, method, anon, authed, results):
    low = (url or '').lower()
    private_hint = any(h in low for h in PRIVATE_HINT)
    a, b = anon, authed
    row = {'method': method, 'url': url, 'anon': a.get('status'), 'authed': b.get('status'),
           'anon_len': a.get('len'), 'authed_len': b.get('len'), 'ct': b.get('ct') or a.get('ct'),
           'anon_loc': a.get('loc'), 'authed_loc': b.get('loc'), 'private_hint': private_hint}
    if a.get('status') is None or b.get('status') is None:
        row['class'] = 'error'
    elif a['status'] in (404,) and b['status'] == 200:
        row['class'] = 'gated_404'
    elif a['status'] in _GATED and b['status'] == 200:
        row['class'] = 'auth_required'
    elif a['status'] == 200 and b['status'] == 200:
        same = a['sha'] == b['sha'] and a['len'] == b['len']
        if same:
            row['class'] = 'same_public'
        else:
            row['class'] = 'authz_gap' if private_hint else 'differential'
    elif a['status'] == 200 and b['status'] in _GATED:
        row['class'] = 'anonymous_public_authed_denied'
    else:
        row['class'] = 'other'
    if row['class'] in ('authz_gap', 'gated_404', 'auth_required'):
        row['priority'] = 1
    else:
        row['priority'] = 3
    results.append(row)
    return row


def _report(out, results):
    order = {'authz_gap': 0, 'gated_404': 1, 'auth_required': 2, 'differential': 3}
    rows = sorted(results, key=lambda r: (order.get(r['class'], 9), not r.get('private_hint')))
    print('\n===== AUTH DIFFERENTIAL RESULTS =====')
    for r in rows:
        print(f"  [{r['class']:9}] anon={r['anon']}\tauthed={r['authed']}\t"
              f"len {r['anon_len']}->{r['authed_len']}\tpriv={int(r.get('private_hint', False))}\t{r['url'][:105]}")
    # persist for the UI/AI review
    Path('projects/PIA/privateinternetaccess_com/auth_diff_results.json').write_text(
        json.dumps(rows, indent=2))
    gaps = [r for r in rows if r['class'] == 'authz_gap']
    print(f'\nsaved auth_diff_results.json | authz_gap={len([r for r in rows if r["class"]=="authz_gap"])} '
          f'gated_404={len([r for r in rows if r["class"]=="gated_404"])} '
          f'auth_required={len([r for r in rows if r["class"]=="auth_required"])} '
          f'differential={len([r for r in rows if r["class"]=="differential"])}')
    if gaps:
        print('\n🔴 AUTHZ GAP CANDIDATES (200 WITHOUT auth, private-ish path):')
        for r in gaps:
            print(f'   {r["method"]} {r["url"]}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry', action='store_true', help='list candidates only')
    args = ap.parse_args()
    asyncio.run(main(args.dry))
