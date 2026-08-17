#!/usr/bin/env python3
"""Vuln-lab for DeepBug validators: PP / DOM XSS / CORS / open redirect / SSRF."""
import json
import http.server
import threading
from urllib.parse import urlparse, parse_qs

LAB = """
<!doctype html><html><head><title>Lab</title></head><body>
<h1>Lab</h1>
<div id="msg">safe-mode</div>
<div id="dom"></div>
<script>
  function merge(target, source) {
    for (var key in source) {
      if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
        if (typeof target[key] !== 'object' || target[key] === null) { target[key] = {}; }
        merge(target[key], source[key]);
      } else { target[key] = source[key]; }
    }
    return target;
  }
  function parseQS() {
    var out = {};
    var params = new URLSearchParams(location.search);
    params.forEach(function (value, key) {
      var parts = key.split(/[\\[\\]]+/).filter(Boolean);
      var cur = out;
      for (var i = 0; i < parts.length - 1; i++) {
        if (typeof cur[parts[i]] !== 'object' || cur[parts[i]] === null) { cur[parts[i]] = {}; }
        cur = cur[parts[i]];
      }
      cur[parts[parts.length - 1]] = value;
    });
    return out;
  }
  var config = { safe: true };
  try { merge(config, parseQS()); } catch (e) {}
  if (config.safe === 'false' || config.safe === false) {
    document.getElementById('msg').innerHTML = 'admin-panel=' + config.admin + ':' + config.role;
  } else {
    document.getElementById('msg').innerHTML = 'safe-mode';
  }
  var hash = location.hash.slice(1);
  if (hash) { document.getElementById('dom').innerHTML = '#' + hash; }
</script>
</body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ('/lab', '/pp', '/domxss'):
            self._send(200, LAB.encode(), {"Content-Type": "text/html"})
        elif u.path == '/cors':
            h = {"Content-Type": "application/json",
                 "Access-Control-Allow-Origin": "*",
                 "Access-Control-Allow-Credentials": "true"}
            self._send(200, json.dumps({"secret": "sensitive-data"}).encode(), h)
        elif u.path == '/redirect':
            url = q.get('url', [''])[0]
            if url:
                self.send_response(302)
                self.send_header('Location', url)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            self._send(404, b'no url')
        elif u.path == '/fetch':
            url = q.get('url', [''])[0]
            if not url:
                self._send(400, b'{"error":"url required"}', {"Content-Type": "application/json"})
                return
            import urllib.request
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    body = r.read(2000).decode('utf-8', 'replace')
                    self._send(200, json.dumps({"fetched": url, "body": body[:500]}).encode(),
                               {"Content-Type": "application/json"})
            except Exception as e:
                self._send(502, json.dumps({"fetched": url, "error": str(e)[:100]}).encode(),
                           {"Content-Type": "application/json"})
        elif u.path == '/internal':
            self._send(200, b'{"internal":"admin-zone"}', {"Content-Type": "application/json"})
        else:
            self._send(404, b'not found')


if __name__ == '__main__':
    http.server.ThreadingHTTPServer(('127.0.0.1', 9876), Handler).serve_forever()
