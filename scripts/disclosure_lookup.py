#!/usr/bin/env python3
"""disclosure_lookup.py — query the 11,304-report disclosure catalog.

Usages:
  python3 scripts/disclosure_lookup.py --class SSRF --severity High --n 8
  python3 scripts/disclosure_lookup.py --weakness IDOR --program nasa
  python3 scripts/disclosure_lookup.py --stats
  python3 scripts/disclosure_lookup.py --class 'Access control' --patterns idor,enum,PII
"""

import os
import re
import sys
import json
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

CATALOG = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '..', 'docs', 'skills', '_disclosure_catalog.js')


def load():
    src = open(CATALOG, encoding='utf-8', errors='replace').read()
    blob = src.split('window.DISCLOSURE_REPORTS=', 1)[1].strip().rstrip(';')
    return json.loads(blob)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='cls')
    ap.add_argument('--weakness')
    ap.add_argument('--severity')
    ap.add_argument('--program')
    ap.add_argument('--platform')
    ap.add_argument('--patterns', help='comma-separated substrings to match in title')
    ap.add_argument('--n', type=int, default=8)
    ap.add_argument('--stats', action='store_true')
    args = ap.parse_args()

    reports = load()

    if args.stats:
        from collections import Counter
        print('total:', len(reports))
        for label, key in [('class', 'vulnerabilityClass'), ('weakness', 'weakness'),
                           ('severity', 'severity'), ('platform', 'platform')]:
            c = Counter(r.get(key) for r in reports)
            print(f'{label}: ' + ' · '.join(f'{k}={n}' for k, n in c.most_common(10)))
        return

    hits = reports
    if args.cls:
        hits = [r for r in hits if (r.get('vulnerabilityClass') or '').lower() == args.cls.lower()]
    if args.weakness:
        hits = [r for r in hits if args.weakness.lower() in (r.get('weakness') or '').lower()]
    if args.severity:
        hits = [r for r in hits if (r.get('severity') or '').lower() == args.severity.lower()]
    if args.program:
        hits = [r for r in hits if args.program.lower() in (r.get('program') or '').lower()]
    if args.platform:
        hits = [r for r in hits if (r.get('platform') or '').lower() == args.platform.lower()]
    if args.patterns:
        pats = [p.strip() for p in args.patterns.split(',')]
        hits = [r for r in hits if any(p.lower() in (r.get('title') or '').lower() for p in pats)]

    print(f'{len(hits)} matching report(s)')
    for r in hits[:args.n]:
        sev = r.get('severity') or '?'
        cls = r.get('vulnerabilityClass') or '?'
        print(f"  [{sev:10}] ({cls}) {r.get('title','')[:120]}")
        if r.get('url'):
            print(f"            {r.get('url')}")


if __name__ == '__main__':
    main()
