#!/usr/bin/env python3
"""hunt_capture_auth.py — capture a PIA authenticated context from Caido.

Caido → HTTP History → right-click an authenticated request to a PIA host
(e.g. the /api/client/v5/* or account call you captured after signing in)
→ "Copy as raw" → paste below / or pass --file.

Parses Host + Cookie + Authorization + CSRF-ish headers and stores the
AuthSession under projects/PIA/.auth/privateinternetaccess.com.json
(tokens never touch git - projects/ is ignored).
"""
import argparse
import json
import re
import sys
from pathlib import Path

RAW = r'''
paste-the-raw-request-here
'''


def parse_raw(raw: str) -> dict:
    lines = [ln.rstrip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        raise SystemExit('empty input')
    start = lines[0].split(' ')
    method, target = start[0], start[1]
    headers = {}
    for ln in lines[1:]:
        if ln.startswith('HTTP/'):
            break
        if ':' in ln:
            k, v = ln.split(':', 1)
            headers[k.strip().lower()] = v.strip().lstrip()
    host = headers.get('host', '')
    cookie_hdr = headers.get('cookie', '')
    bears = []
    pm = []
    auth = headers.get('authorization', '')
    if auth.lower().startswith('bearer '):
        bears.append(auth[7:].strip())
    cookie = {}
    for part in cookie_hdr.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            cookie[k.strip()] = v.strip()
    return {'method': method, 'host': host, 'path': target, 'cookie': cookie,
            'authorization': auth.strip(), 'bearers': bears}


def store(cfg: dict):
    out_dir = Path('projects/PIA/.auth')
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / 'privateinternetaccess.com.json'
    data = {
        'target': 'privateinternetaccess.com',
        'base_url': cfg.get('host', 'https://www.privateinternetaccess.com'),
        'cookies': cfg['cookie'],
        'bearer': cfg['bearers'][0] if cfg['bearers'] else '',
        'extra_headers': {},
        'refresh_token': '',
        'token_expires_at': None,
        'flow': 'caido_raw_capture',
    }
    out.write_text(json.dumps(data, indent=2))
    print(f'saved AuthSession -> {out}')
    print(f'  host={cfg["host"]} | cookies={list(data["cookies"])} | bearer={"yes" if data["bearer"] else "no"}')
    # confirm authenticity indicator
    if not data['cookies'] and not data['bearer']:
        print('⚠️  no cookie/bearer found - capture a request that actually carries the session')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', help='path to a raw HTTP request file from Caido')
    args = ap.parse_args()
    raw = open(args.file).read() if args.file else RAW
    if args.file is None and '{paste' in raw:
        raise SystemExit('paste the raw request or pass --file <path>')
    store(parse_raw(raw))
