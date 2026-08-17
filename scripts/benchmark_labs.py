#!/usr/bin/env python3
"""benchmark_labs.py — run every DeepBug validator against the local vuln-lab
benchmark targets and print a PASS/FAIL table.

Targets expected to be running:
  :3000  Juice Shop        (SQLi/NoSQLi/mass assignment/IDOR)
  :5000  VAmPI             (SQLi/IDOR/broken auth API)
  :5013  DVGA              (GraphQL + clairvoyance, hardened mode)
  :8081  crAPI identity    (mass assignment/JWT)
  :9876  DeepBug lab       (PP / DOM XSS / CORS / redirect / SSRF)

Usage:
  python3 scripts/benchmark_labs.py            # all targets
  python3 scripts/benchmark_labs.py lab dvga   # selected targets
Exit code 0 if all expected findings were produced.
"""

import sys
import json
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.modules.utils import load_config
from app.modules.tools.live_rest_validator import LiveRestValidator
from app.modules.tools.cors_validator import CORSValidator
from app.modules.tools.open_redirect_validator import OpenRedirectValidator
from app.modules.tools.ssrf_validator import SSRFValidator
from app.modules.tools.pp_validator import PrototypePollutionValidator
from app.modules.tools.dom_xss_validator import DOMXSSValidator
from app.modules.tools.graphql_scanner import GraphQLScanner

CFG = load_config()
RESULTS = []


def record(name, ok, detail):
    RESULTS.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name:42} {detail}")


def bench_juiceshop():
    rows = [
        {'endpoint': 'http://127.0.0.1:3000/rest/products/search?q=', 'method': 'GET'},
        {'endpoint': 'http://127.0.0.1:3000/rest/user/security-question?email=', 'method': 'GET'},
    ]
    findings = LiveRestValidator(CFG).scan(rows, target_host='127.0.0.1')
    hit = any(f['probe_status'] >= 500 or f['evidence'] for f in findings)
    record('juiceshop REST SQLi (products/search)', hit,
           f"{len(findings)} finding(s): " + '; '.join(f"{f['endpoint'].split('/')[-1]} {f['evidence']}" for f in findings[:3]))


def bench_vampi():
    rows = [
        {'endpoint': 'http://127.0.0.1:5000/books/v1?title=x', 'method': 'GET'},
        {'endpoint': 'http://127.0.0.1:5000/users/v1/1', 'method': 'GET'},
    ]
    findings = LiveRestValidator(CFG).scan(rows, target_host='127.0.0.1')
    hit = any(f['evidence'] for f in findings)
    record('vampi REST SQLi', hit, f"{len(findings)} finding(s): " + '; '.join(f['evidence'] for f in findings[:2]))


_DVGA_DB = os.path.join(os.path.expanduser('~'), '.deepbug_labs', 'dvga', 'dvga.db')


def _dvga_set_hardened(hardened: bool):
    import sqlite3
    try:
        db = sqlite3.connect(_DVGA_DB)
        db.execute('UPDATE servermode SET hardened=?', (1 if hardened else 0,))
        db.commit()
        db.close()
    except Exception as e:
        print(f"   (dvga mode flip skipped: {e})")


def bench_dvga():
    g = GraphQLScanner(CFG)
    _dvga_set_hardened(False)
    res = g.scan(['http://127.0.0.1:5013'])
    ok_find = bool(res['endpoints'])
    record('dvga graphql detect', ok_find, str(res['endpoints']))
    intro = len(res['schemas'])
    record('dvga introspection (ON mode)', intro > 0, f"{intro} schema(s)")
    _dvga_set_hardened(True)
    res2 = g.scan(['http://127.0.0.1:5013'])
    cv = res2['clairvoyance']
    record('dvga clairvoyance (hardened mode)', bool(cv),
           '; '.join(f"{k}: {v.get('note','')[:50]}" for k, v in cv.items()))


def bench_crapi():
    import httpx
    try:
        r = httpx.post('http://127.0.0.1:8081/identity/api/v2/user/register',
                       json={'email': 'b@example.com', 'password': 'Benchmark#2026',
                             'name': 'b', 'number': '+1-555-0102', 'role': 'admin'},
                       timeout=10)
        ok = r.status_code not in (404, 502, 503)
        record('crapi identity reachable', ok, f"HTTP {r.status_code}")
    except Exception as e:
        record('crapi identity reachable', False, type(e).__name__)


def bench_lab():
    rows = [{'endpoint': 'http://127.0.0.1:9876/redirect?url=https://evil.example.com/x', 'method': 'GET'},
            {'endpoint': 'http://127.0.0.1:9876/fetch?url=http://127.0.0.1:9876/internal', 'method': 'GET'}]
    rec = OpenRedirectValidator(CFG).validate_sync([rows[0]['endpoint']])
    record('lab open-redirect', any(r['Result'] == 'CONFIRMED' for r in rec), f"{len(rec)} row(s)")
    ssrf = SSRFValidator(CFG).validate_sync([rows[1]['endpoint']])
    record('lab ssrf', any(r['Result'] == 'PROBABLE' for r in ssrf), f"{len(ssrf)} row(s)")
    cors = CORSValidator(CFG).validate_sync(['http://127.0.0.1:9876/cors'])
    record('lab cors wildcard-creds', any(r['Class'] == 'wildcard-credentials' for r in cors), f"{len(cors)} row(s)")
    pp = PrototypePollutionValidator(CFG).validate_sync(['http://127.0.0.1:9876/pp'])
    record('lab prototype-pollution', any(r['Result'] == 'CONFIRMED' for r in pp), f"{len(pp)} row(s)")
    dx = DOMXSSValidator(CFG).validate_sync(['http://127.0.0.1:9876/domxss'])
    record('lab dom-xss', any(r['Result'] == 'CONFIRMED' for r in dx), f"{len(dx)} row(s)")
    oob = os.environ.get('WEBHOOK_SITE_UUID', '')
    if oob:
        cfg_oob = dict(CFG)
        cfg_oob['ssrf_validator'] = {'oob_uuid': oob}
        cfg_oob['open_redirect_validator'] = {'oob_uuid': oob}
        r2 = SSRFValidator(cfg_oob).validate_sync([rows[1]['endpoint']])
        record('lab ssrf OOB (webhook.site)', any(r['Result'] == 'CONFIRMED' for r in r2), f"{len(r2)} row(s)")
        r3 = OpenRedirectValidator(cfg_oob).validate_sync([rows[0]['endpoint']])
        record('lab open-redirect OOB', any(r['Class'] == 'redirect-offsite' for r in r3), f"{len(r3)} row(s)")
    else:
        print("   (OOB checks skipped - set WEBHOOK_SITE_UUID to enable webhook.site proofs)")


def main():
    targets = sys.argv[1:] or ['juiceshop', 'vampi', 'dvga', 'crapi', 'lab']
    for t in targets:
        {'juiceshop': bench_juiceshop, 'vampi': bench_vampi, 'dvga': bench_dvga,
         'crapi': bench_crapi, 'lab': bench_lab}.get(t, lambda: None)()
    failed = [n for n, ok, _ in RESULTS if not ok]
    print()
    print(f"{'ALL GREEN' if not failed else f'{len(failed)} FAILURES'}: "
          f"{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    if failed:
        print('failed:', ', '.join(failed))
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
