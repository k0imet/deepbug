#!/usr/bin/env python3
"""
Test lab for new DeepBug modules (no auth, no external deps beyond Python stdlib).

Exercises:
  - JWT live decode: alg:none token, HS256 with weak secret, expired token
  - Blind SQLi: time-delay (SLEEP), boolean-diff (1=1 vs 1=2)
  - OOB: SSRF endpoint that calls back to a canary
  - Validator routing: XML endpoint, RCE param, upload form
  - WAF detection: Cloudflare/Akamai-like headers
  - Open redirect: single-letter param `g=`

Start:  python3 scripts/test_lab.py
Port:   9878
"""

import json
import time
import base64
import hmac
import hashlib
import http.server
import threading
import urllib.parse
from io import BytesIO


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _make_jwt(payload: dict, secret: str = 'secret', alg: str = 'HS256') -> str:
    header = _b64url_encode(json.dumps({'alg': alg, 'typ': 'JWT'}).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    msg = f'{header}.{payload_b64}'.encode()
    sig = _b64url_encode(hmac.new(secret.encode(), msg, hashlib.sha256).digest())
    return f'{header}.{payload_b64}.{sig}'


def _make_alg_none(payload: dict) -> str:
    header = _b64url_encode(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())
    payload_b64 = _b64url_encode(json.dumps(payload).encode())
    return f'{header}.{payload_b64}.'


class LabHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None, ct='application/json'):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _read(self):
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length) if length else b''

    def do_GET(self):
        p = self.path.split('?')[0]
        qs = urllib.parse.parse_qs(self.path.split('?')[1] if '?' in self.path else '')

        # --- JWT live decode tests ---
        if p == '/jwt/alg-none':
            token = _make_alg_none({'user': 'admin', 'role': 'admin', 'sub': 'admin@test.com'})
            self._send(200, json.dumps({'access_token': token, 'token_type': 'Bearer'}))
        elif p == '/jwt/weak-secret':
            token = _make_jwt({'user': 'admin', 'is_admin': True, 'sub': 'admin@test.com'}, 'secret')
            self._send(200, json.dumps({'access_token': token, 'token_type': 'Bearer'}))
        elif p == '/jwt/expired':
            token = _make_jwt({'user': 'test', 'exp': int(time.time()) - 86400})
            self._send(200, json.dumps({'access_token': token}))
        elif p == '/jwt/interesting-claims':
            token = _make_jwt({'user': 'admin', 'role': 'superadmin', 'scope': 'admin:read admin:write',
                               'permissions': ['*'], 'is_admin': True, 'org': 'acme-corp',
                               'password': 'hunter2', 'api_key': 'sk_live_abc123'})
            self._send(200, json.dumps({'access_token': token}))
        elif p == '/jwt/kid-injection':
            # kid with path traversal
            header = _b64url_encode(json.dumps({'alg': 'HS256', 'kid': '../../dev/null'}).encode())
            payload = _b64url_encode(json.dumps({'user': 'test'}).encode())
            msg = f'{header}.{payload}'.encode()
            sig = _b64url_encode(hmac.new(b'secret', msg, hashlib.sha256).digest())
            self._send(200, json.dumps({'access_token': f'{header}.{payload}.{sig}'}))

        # --- Blind SQLi tests ---
        elif p == '/sqli/time':
            q = qs.get('id', [''])[0]
            if 'sleep' in q.lower() or 'SLEEP' in q:
                time.sleep(5)
                self._send(200, json.dumps({'result': 'ok'}))
            elif 'WAITFOR' in q.upper():
                time.sleep(5)
                self._send(200, json.dumps({'result': 'ok'}))
            elif 'pg_sleep' in q.lower():
                time.sleep(5)
                self._send(200, json.dumps({'result': 'ok'}))
            elif 'randomblob' in q.lower():
                time.sleep(5)
                self._send(200, json.dumps({'result': 'ok'}))
            elif 'BENCHMARK' in q.upper():
                time.sleep(5)
                self._send(200, json.dumps({'result': 'ok'}))
            else:
                self._send(200, json.dumps({'result': 'ok', 'id': q}))
        elif p == '/sqli/bool':
            q = qs.get('q', [''])[0]
            if '1=1' in q:
                self._send(200, json.dumps({'results': [{'id': 1, 'name': 'admin'}, {'id': 2, 'name': 'user'}]}))
            elif '1=2' in q:
                self._send(200, json.dumps({'results': []}))
            else:
                self._send(200, json.dumps({'results': [{'id': 1, 'name': 'test'}]}))

        # --- SSRF / OOB ---
        elif p == '/oob/ssrf':
            url = qs.get('url', [''])[0]
            if url:
                self._send(200, json.dumps({'fetched': url, 'status': 'called'}))
            else:
                self._send(200, json.dumps({'error': 'no url param'}))
        elif p == '/oob/webhook':
            target = qs.get('target', [''])[0]
            if target:
                self._send(200, json.dumps({'callback': target, 'called': True}))
            else:
                self._send(200, json.dumps({'error': 'no target'}))

        # --- Open redirect with single-letter param ---
        elif p == '/redirect':
            g = qs.get('g', [''])[0]
            if g:
                self.send_response(302)
                self.send_header('Location', g)
                self.end_headers()
            else:
                self._send(200, json.dumps({'error': 'no g param'}))

        # --- RCE params ---
        elif p == '/rce/ping':
            cmd = qs.get('cmd', [''])[0]
            self._send(200, json.dumps({'command': cmd, 'output': 'pong' if cmd == 'ping' else f'ran: {cmd}'}))

        # --- XXE XML endpoint ---
        elif p == '/xxe/parse':
            self._send(200, json.dumps({'parsed': 'ok', 'note': 'accepts XML'}), ct='application/xml')

        # --- LFI params ---
        elif p == '/lfi/view':
            file = qs.get('file', [''])[0]
            self._send(200, json.dumps({'file': file, 'content': 'file contents here'}))

        # --- WAF endpoints ---
        elif p == '/waf/cloudflare':
            self._send(403, 'Blocked', {
                'Server': 'cloudflare',
                'CF-RAY': 'test-ray-123',
                'CF-Cache-Status': 'HIT',
            }, ct='text/html')
        elif p == '/waf/akamai':
            self._send(403, 'Access Denied - Reference #12345.abc', {
                'Server': 'AkamaiGHost',
                'X-Akamai-Request-ID': 'abc123',
            }, ct='text/html')
        elif p == '/waf/aws':
            self._send(403, 'Request blocked by AWS WAF', {
                'Server': 'CloudFront',
                'X-Amz-Cf-Id': 'test-cf-id',
                'X-Amzn-RequestId': 'test-req-id',
            }, ct='text/html')
        elif p == '/waf/rate-limit':
            self._send(429, 'Rate limited', {
                'Retry-After': '60',
                'X-RateLimit-Limit': '100',
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(int(time.time()) + 60),
            }, ct='text/html')

        # --- JS with embedded JWT ---
        elif p == '/app.js':
            token = _make_alg_none({'user': 'admin', 'role': 'admin'})
            js = f"""
            // App configuration
            var API_URL = '/api/v1';
            var AUTH_TOKEN = '{token}';
            var USER_ID = 12345;
            // Angular HTTP samples
            this.http.get('/api/users');
            this.http.post('/api/orders', {{items: []}});
            this.http.put('/api/profile/' + USER_ID);
            var config = {{
                apiKey: 'AIzaSyDummyKeyForTesting123',
                secretKey: 'sk_live_abcdefghijklmnop',
                databaseUrl: 'postgres://user:pass@localhost/db',
                internalApi: 'http://10.0.0.1:8080/admin',
                stagingApi: 'https://staging-api.example.com',
                devApi: 'https://dev-api.example.com',
            }};
            """
            self._send(200, js, ct='application/javascript')

        # --- GraphQL endpoint ---
        elif p == '/graphql':
            self._send(200, json.dumps({'data': {'__typename': 'Query'}}))

        # --- Upload form ---
        elif p == '/upload':
            self._send(200, '<html><form method="POST" enctype="multipart/form-data">'
                       '<input type="file" name="file"><input type="submit"></form></html>',
                       ct='text/html')

        # --- Home ---
        elif p == '/':
            links = [
                '/jwt/alg-none', '/jwt/weak-secret', '/jwt/expired', '/jwt/interesting-claims',
                '/jwt/kid-injection', '/sqli/time?id=1', '/sqli/bool?q=test',
                '/oob/ssrf?url=', '/oob/webhook?target=', '/redirect?g=',
                '/rce/ping?cmd=', '/xxe/parse', '/lfi/view?file=',
                '/waf/cloudflare', '/waf/akamai', '/waf/aws', '/waf/rate-limit',
                '/app.js', '/graphql', '/upload',
            ]
            html = '<h1>DeepBug Test Lab</h1><ul>'
            for link in links:
                html += f'<li><a href="{link}">{link}</a></li>'
            html += '</ul>'
            self._send(200, html, ct='text/html')

        else:
            self._send(404, json.dumps({'error': 'not found'}))

    def do_POST(self):
        raw = self._read()
        p = self.path.split('?')[0]

        if p == '/sqli/time':
            try:
                data = json.loads(raw)
                q = data.get('id', '')
                if 'sleep' in str(q).lower() or 'SLEEP' in str(q):
                    time.sleep(5)
                self._send(200, json.dumps({'result': 'ok'}))
            except Exception:
                self._send(200, json.dumps({'result': 'ok'}))

        elif p == '/xxe/parse':
            body = raw.decode('utf-8', errors='ignore')
            self._send(200, json.dumps({'parsed': 'ok', 'size': len(body)}), ct='application/xml')

        elif p == '/upload':
            self._send(200, json.dumps({'uploaded': True, 'filename': 'test.txt'}))

        else:
            self._send(404, json.dumps({'error': 'not found'}))


def start(port=9878):
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), LabHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f'Test lab running on http://127.0.0.1:{port}')
    return srv


if __name__ == '__main__':
    srv = start()
    print('Endpoints:')
    print('  /jwt/alg-none          — alg:none JWT (signature bypass)')
    print('  /jwt/weak-secret       — HS256 with "secret" key')
    print('  /jwt/expired           — expired JWT')
    print('  /jwt/interesting-claims — admin/role/password in payload')
    print('  /jwt/kid-injection     — kid=../../dev/null')
    print('  /sqli/time?id=1        — time-delay on SLEEP()')
    print('  /sqli/bool?q=test      — boolean-diff on 1=1 vs 1=2')
    print('  /oob/ssrf?url=         — SSRF callback endpoint')
    print('  /redirect?g=           — open redirect (single-letter param)')
    print('  /rce/ping?cmd=         — command execution param')
    print('  /xxe/parse             — XML endpoint')
    print('  /lfi/view?file=        — LFI file param')
    print('  /waf/cloudflare        — Cloudflare WAF headers')
    print('  /waf/akamai            — Akamai WAF headers')
    print('  /waf/aws               — AWS CloudFront/WAF headers')
    print('  /waf/rate-limit        — 429 rate limiting')
    print('  /app.js                — JS with embedded JWT + secrets')
    print('  /graphql               — GraphQL endpoint')
    print('  /upload                — file upload form')
    print()
    print('Press Ctrl+C to stop')
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
        print('Stopped')