#!/usr/bin/env python3
"""backtest_bearer_mint.py — backtest the Bearer Mint prober.

Sources:
  A. local controls  - mock /auth/anonymous-mint (KNOWN TP: role injection),
     juice-shop /rest/user/login (KNOWN CLEAN: needs creds),
     vampi /login (KNOWN CLEAN), mock /json_login (KNOWN CLEAN)
  B. real endpoints   - token-ish POST endpoints gathered from every past
     project's js_discovered_endpoints + gf candidates.

Every probe is a single POST (empty/grant/injection bodies) with NO auth.
The prober only replays (GET) after a mint. Output: TP/FP/FN analysis.

Usage:
  python3 scripts/backtest_bearer_mint.py           # all sources
  python3 scripts/backtest_bearer_mint.py --local   # controls only
  python3 scripts/backtest_bearer_mint.py --live    # real endpoints only
"""

import os
import sys
import json
import glob
import pathlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.modules.utils import load_config
from app.modules.tools.bearer_mint_prober import BearerMintProber

CONTROLS = [
    # (label, endpoint, expected)  expected: TP = should mint w/ injection
    ('mock-anonymous-mint', 'http://127.0.0.1:9878/auth/anonymous-mint', 'TP'),
    ('mock-json-login', 'http://127.0.0.1:9878/json_login', 'CLEAN'),
    ('juiceshop-login', 'http://127.0.0.1:3000/rest/user/login', 'CLEAN'),
    ('vampi-login', 'http://127.0.0.1:5000/login', 'CLEAN'),
    ('vampi-token', 'http://127.0.0.1:5000/tokens', 'CLEAN'),
]


def collect_live_endpoints(limit=60):
    """Token-ish POST endpoints from all projects' stored results.

    Tightened: genuinely token-ish paths only (oauth/token, /auth/*, login,
    signin, refresh, jwt, session, mint...), no third-party hosts, no static
    assets, deduped, alive hosts only (2s connect check).
    """
    import socket
    import urllib.parse
    import re
    proj_root = pathlib.Path(__file__).resolve().parent.parent / 'projects'
    hint = re.compile(r'(oauth|/auth/|login|signin|sign-in|refresh|session|jwt|token|mint)', re.I)
    bad = ('googleapis.com', 'gstatic.com', 'facebook.com', 'recaptcha', 'hubstyle',
           'cloudfront', 'akamai', '.css', '.js?', 'schema.org')
    found, seen = [], set()
    for f in glob.glob(str(proj_root / '*' / '*' / 'js_discovered_endpoints_results.json')):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        for r in d:
            ep = (r.get('endpoint') or '').strip()
            m = str(r.get('method') or 'GET').upper()
            if m == 'POST' and ep.startswith('http'):
                found.append(ep)
    for f in glob.glob(str(proj_root / '*' / '*' / 'gf_filtered_urls_results.json')):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        for r in d:
            found.append(str(r.get('URL') or '').strip())
    rows = []
    for u in found:
        if not u.startswith('http'):
            continue
        low = u.lower()
        if not hint.search(u):
            continue
        if any(b in low for b in bad):
            continue
        host = urllib.parse.urlparse(u).netloc.split(':')[0]
        if host in seen:
            continue
        seen.add(host)
        rows.append({'endpoint': u, 'method': 'POST'})
        if len(rows) >= limit:
            break
    # alive-check: only keep hosts that answer a 2s connect
    alive = []
    for r in rows:
        try:
            h = urllib.parse.urlparse(r['endpoint']).netloc.split(':')[0]
            s = socket.create_connection((h, 443), timeout=2)
            s.close()
            alive.append(r)
        except Exception:
            try:
                h = urllib.parse.urlparse(r['endpoint']).netloc.split(':')[0]
                s = socket.create_connection((h, 80), timeout=2)
                s.close()
                alive.append(r)
            except Exception:
                pass
    return alive


def main():
    local = '--local' in sys.argv
    live = '--live' in sys.argv
    cfg = load_config()
    cfg.setdefault('bearer_mint', {})['timeout'] = 4
    prober = BearerMintProber(cfg)
    print('=' * 78)
    print('Bearer Mint Prober backtest')
    print('=' * 78)

    # ---- controls
    controls_findings = {}
    if not live:
        print('\n[CONTROLS]')
        rows = [{'endpoint': ep, 'method': 'POST'} for _, ep, _ in CONTROLS]
        res = prober.scan(rows)
        by_ep = {}
        for f in res:
            by_ep.setdefault(f['endpoint'], []).append(f)
        for label, ep, expected in CONTROLS:
            got = by_ep.get(ep)
            if expected == 'TP':
                ok = bool(got) and any(f['injected_privilege'] for f in got)
            else:
                ok = not got
            verdict = 'PASS' if ok else 'FAIL'
            print(f'  [{verdict}] {label:22} expected={expected:6} '
                  f'minted={len(got) if got else 0}')
            if got:
                for f in got:
                    print(f'          {f["payload"]:18} inj={f["injected_privilege"]!r}')

    # ---- real endpoints
    if not local:
        print('\n[REAL ENDPOINTS]')
        rows = collect_live_endpoints()
        print(f'  collected {len(rows)} token-ish POST endpoints from past projects')
        if rows:
            findings = prober.scan(rows)
            minted = [f for f in findings if f['phase'] == 'unauth_mint']
            print(f'  minted: {len(minted)} / {len(rows)} tested')
            for f in minted:
                sev = f['severity']
                print(f'  🪙 [{sev}] {f["endpoint"][:70]}')
                print(f'        payload={f["payload"]:18} inj={f["injected_privilege"]!r} claims={f["jwt_claims"][:100]}')
            if not minted:
                print('  ✅ no anonymous token minting on any real endpoint (clean backtest)')


if __name__ == '__main__':
    main()
