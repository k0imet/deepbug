#!/usr/bin/env python3
"""test_auth_session.py — AuthSession test matrix (mock server + real targets).

Boots the mock auth server (all login modes + failure paths), runs every flow
against it, then — if Juice Shop is up — proves authenticated IDOR end-to-end.

Usage:
  python3 scripts/test_auth_session.py          # mock matrix only
  python3 scripts/test_auth_session.py --juice  # + real Juice Shop IDOR
Exit code 0 iff all checks pass.
"""

import os
import sys
import json
import shutil
import pathlib
import threading
import http.server

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.modules.integrations.auth_session import AuthSession, AuthError

MOCK = pathlib.Path(__file__).resolve().parent.parent / '.authlab' / 'mock_auth.py'
PORT = 9879

passed, failed = [], []


def t(name, fn):
    try:
        fn()
        passed.append(name)
        print(f'PASS  {name}')
    except Exception as e:
        failed.append(name)
        print(f'FAIL  {name}  -> {type(e).__name__}: {str(e)[:140]}')


def expect_auth_error(fn, contains=''):
    try:
        fn()
        raise AssertionError('expected AuthError')
    except AuthError as e:
        if contains and contains not in str(e):
            raise AssertionError(f'message mismatch: {e}')
    except AssertionError:
        raise
    except Exception as e:
        raise AssertionError(f'wrong exception: {type(e).__name__}: {e}')


def main():
    mock_src = MOCK.read_text()
    ns = {'Handler': None}
    exec(mock_src.replace('if __name__ ==', 'if False and __name__ =='), ns)
    Handler = ns['Handler']
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    B = f'http://127.0.0.1:{PORT}'

    t('json_login happy (nested token+refresh+verify)', lambda: (
        lambda s: (_assert(s.bearer == 'tok_happy'), _assert(s.refresh_token == 'ref_happy'),
                   _assert(s.verify('/authed'))))(
        AuthSession(base_url=B).json_login('/json_login', 'email', 'password',
                                           'user@example.com', 'pass123')))
    t('json_login token in Authorization header', lambda: _assert(
        AuthSession(base_url=B).json_login('/json_login_header_token', 'email', 'password', 'u', 'p').bearer == 'tok_header'))
    t('json_login cookie-only session accepted', lambda: _assert(
        AuthSession(base_url=B).json_login('/json_login_no_token', 'email', 'password', 'u', 'p').cookies.get('session') == 'sess1'))
    t('json_login wrong password -> clean 401', lambda: expect_auth_error(
        lambda: AuthSession(base_url=B).json_login('/json_login', 'email', 'password', 'user@example.com', 'WRONG'), '401'))
    t('json_login non-JSON -> AuthError', lambda: expect_auth_error(
        lambda: AuthSession(base_url=B).json_login('/json_login_plain', 'email', 'password', 'u', 'p')))
    t('json_login 500 -> AuthError', lambda: expect_auth_error(
        lambda: AuthSession(base_url=B).json_login('/json_login_500', 'email', 'password', 'u', 'p')))
    t('form_login CSRF harvest + cookie', lambda: _assert(
        AuthSession(base_url=B).form_login('/form_login', 'username', 'password', 'user', 'pw').cookies.get('session') == 'sess_form'))
    t('form_login no-CSRF page', lambda: _assert(
        AuthSession(base_url=B).form_login('/form_login_nocsrf', 'username', 'password', 'user', 'pw').cookies.get('session') == 'sess_nocsrf'))
    t('form_login bad creds -> AuthError', lambda: expect_auth_error(
        lambda: AuthSession(base_url=B).form_login('/form_login', 'username', 'password', 'user', 'BAD'), '401'))
    t('oauth2 password grant', lambda: (lambda s: (_assert(s.bearer == 'tok_oauth'),
        _assert(s.refresh_token == 'ref_oauth'), _assert(not s.expired)))(
        AuthSession(base_url=B).oauth2_password('/oauth/token', 'cid', 'sec', 'u', 'p')))
    t('oauth2 refresh -> new token + verify', lambda: (lambda s: (
        _assert(s.refresh('/oauth/token')), _assert(s.bearer == 'tok_refreshed'),
        _assert(s.verify('/authed'))))(
        AuthSession(base_url=B).oauth2_password('/oauth/token', 'cid', 'sec', 'u', 'p')))
    t('refresh without refresh_token -> False', lambda: _assert(
        not AuthSession(base_url=B).json_login('/json_login', 'email', 'password',
                                               'user@example.com', 'pass123').refresh('/oauth/token')))
    t('manual bearer + cookie parse', lambda: (lambda s: (
        _assert(s.bearer == 'tok_happy'), _assert(s.cookies == {'a': '1', 'b': '2'})))(
        AuthSession(base_url=B).manual(bearer='Bearer tok_happy', cookie_header='a=1; b=2')))

    def persist_roundtrip():
        p = pathlib.Path('/tmp/deepbug_auth_proj')
        p.mkdir(parents=True, exist_ok=True)
        s = AuthSession(base_url=B).oauth2_password('/oauth/token', 'cid', 'sec', 'u', 'p')
        s.target = 'example.com'
        s.save(p)
        s2 = AuthSession.load(p, 'example.com')
        _assert(s2 and s2.bearer == 'tok_oauth' and s2.refresh_token == 'ref_oauth' and s2.flow == 'oauth2')
        _assert(s2.verify('/authed'))
        shutil.rmtree(p)
    t('save/load roundtrip + loaded session verifies', persist_roundtrip)

    if '--juice' in sys.argv:
        def juice_idor():
            sess = AuthSession(base_url='http://127.0.0.1:3000')
            sess.json_login('/rest/user/login', 'email', 'password', 'e2e-test@deepbug.local', 'DeepBug#Test1$')
            import httpx
            r = httpx.get('http://127.0.0.1:3000/api/Users/1', headers=sess.auth_headers(), timeout=10)
            _assert(r.status_code == 200, 'customer session must read /api/Users/1 (IDOR)')
            nu = httpx.get('http://127.0.0.1:3000/api/Users/1', timeout=10)
            _assert(nu.status_code == 401, 'unauthenticated must stay 401')
        t('juice-shop IDOR via AuthSession (401 -> 200)', juice_idor)

    srv.shutdown()
    print()
    print(f'{len(passed)} passed, {len(failed)} failed')
    if failed:
        print('FAILED:', failed)
    sys.exit(1 if failed else 0)


def _assert(cond, msg='assertion failed'):
    if not cond:
        raise AssertionError(msg)


if __name__ == '__main__':
    main()
