#!/usr/bin/env python3
"""Mock auth server + AuthSession test matrix.

Covers every flow and the failure modes a real login can throw:
  json_login (token in body / nested / header-only / missing / non-JSON / 401)
  form_login (CSRF harvest, no-CSRF, wrong creds, cookie only)
  oauth2_password (happy, missing token, 401)
  refresh (happy, missing refresh_token)
  verify (expect-status variants)
"""
import json
import re
import http.server
import threading

TOKENS = {'access_ok': 'tok_happy', 'refresh_ok': 'tok_refreshed'}
USERS = {'user@example.com': 'pass123'}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None, cookies=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        for k, v in (cookies or {}).items():
            self.send_header('Set-Cookie', f'{k}={v}; Path=/; HttpOnly')
        self.send_header('Content-Type', 'application/json')
        body = body.encode() if isinstance(body, str) else body
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------ JSON login
    def do_POST(self):
        p = self.path.split('?')[0]
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length) if length else b''
        ct = self.headers.get('Content-Type', '')

        if p == '/json_login':
            data = json.loads(raw or b'{}')
            if data.get('email') == 'user@example.com':
                if data.get('password') == 'pass123':
                    self._send(200, json.dumps({'data': {'access_token': 'tok_happy', 'refresh_token': 'ref_happy', 'expires_in': 60}}))
                    return
                self._send(401, json.dumps({'error': 'bad password'}))
                return
            self._send(401, json.dumps({'error': 'no such user'}))
        elif p == '/json_login_header_token':
            # token only in Authorization response header
            self._send(200, json.dumps({'ok': True}), headers={'Authorization': 'Bearer tok_header'})
        elif p == '/json_login_no_token':
            self._send(200, json.dumps({'ok': True, 'status': 'logged-in'}), cookies={'session': 'sess1'})
        elif p == '/json_login_nested':
            self._send(200, json.dumps({'result': {'auth': {'token': 'tok_nested'}}}))
        elif p == '/json_login_plain':
            self._send(200, 'not-json-at-all')
        elif p == '/json_login_500':
            self._send(500, json.dumps({'error': 'boom'}))

        # ---------------------------------------------------------------- form login
        elif p == '/form_login' and ct.startswith('application/x-www-form-urlencoded'):
            form = dict(x.split('=', 1) for x in raw.decode().split('&') if '=' in x)
            if form.get('_token') != 'csrf123':
                self._send(422, b'{"error":"csrf"}')
                return
            if form.get('username') == 'user' and form.get('password') == 'pw':
                self._send(200, json.dumps({'ok': True}), cookies={'session': 'sess_form'})
                return
            self._send(401, b'{"error":"bad creds"}')
        elif p == '/form_login_nocsrf':
            form = dict(x.split('=', 1) for x in raw.decode().split('&') if '=' in x)
            self._send(200, json.dumps({'ok': True}), cookies={'session': 'sess_nocsrf'})

        # ---------------------------------------------------------------- oauth2
        elif p == '/oauth/token':
            form = dict(x.split('=', 1) for x in raw.decode().split('&') if '=' in x)
            if form.get('grant_type') == 'password':
                if form.get('username') == 'u' and form.get('password') == 'p' and form.get('client_id') == 'cid':
                    self._send(200, json.dumps({'access_token': 'tok_oauth', 'refresh_token': 'ref_oauth', 'expires_in': 60}))
                else:
                    self._send(401, json.dumps({'error': 'invalid_grant'}))
            elif form.get('grant_type') == 'refresh_token':
                if form.get('refresh_token') == 'ref_oauth':
                    self._send(200, json.dumps({'access_token': 'tok_refreshed', 'expires_in': 60}))
                else:
                    self._send(400, json.dumps({'error': 'invalid_grant'}))
            else:
                self._send(400, json.dumps({'error': 'unsupported_grant_type'}))
        elif p == '/auth/anonymous-mint':
            # VULNERABLE BY DESIGN: mints a bearer token with NO auth and
            # trusts client-supplied role/scope/identity claims.
            import base64 as _b64, json as _json
            data = json.loads(raw or b'{}')
            role = data.get('role', 'user')
            claims = {'sub': data.get('identity', 'anonymous'),
                      'role': role,
                      'scope': data.get('scope', ''),
                      'user_id': data.get('user_id'),
                      'is_admin': data.get('is_admin', False)}
            header = _b64.urlsafe_b64encode(_json.dumps({'alg': 'none', 'typ': 'JWT'}).encode()).rstrip(b'=')
            payload = _b64.urlsafe_b64encode(_json.dumps(claims).encode()).rstrip(b'=')
            self._send(200, _json.dumps({'access_token': (header + b'.' + payload).decode(),
                                         'token_type': 'Bearer'}))
        elif p == '/auth/admin-panel' and 'Authorization' in str(self.headers):
            # minted tokens (any value) authorize this - vulnerable design
            self._send(200, json.dumps({'admin': 'welcome'}))
        else:
            self._send(404, b'{"error":"nf"}')

    def do_GET(self):
        if self.path == '/form_login':
            page = ('<html><form method="POST">'
                    '<input name="_token" value="csrf123">'
                    '<input name="username"><input name="password">'
                    '</form></html>')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(page)))
            self.end_headers()
            self.wfile.write(page.encode())
        elif self.path == '/form_login_nocsrf':
            page = '<html><form method="POST"><input name="username"></form></html>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(page)))
            self.end_headers()
            self.wfile.write(page.encode())
        elif self.path == '/authed':
            if self.headers.get('Authorization') in ('Bearer tok_happy', 'Bearer tok_oauth'):
                self._send(200, json.dumps({'private': 'data'}))
            elif self.headers.get('Authorization') == 'Bearer tok_refreshed':
                self._send(200, json.dumps({'private': 'data-refreshed'}))
            else:
                self._send(401, b'{"error":"unauthorized"}')
        else:
            self._send(404, b'{}')


def start_server(port=9878):
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == '__main__':
    srv = start_server()
    print(f'mock auth server on 127.0.0.1:9878')
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
