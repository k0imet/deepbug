"""js_protocol.py

v3.6.1: cheap, pattern-based extraction of protocol-level intelligence that
the semantic extractor doesn't reach yet:

  - WebSocket message protocol  (socket.on/emit, ws.send/onmessage, auth-over-ws)
  - Service workers             (fetch-event handlers, offline, push)
  - Push / VAPID public keys
  - SSRF metadata candidates    (cloud metadata hosts, exotic schemes,
                                 proxy/redirect/fetch endpoints)
  - Error-tracking services     (Sentry/LogRocket/Bugsnag/Rollbar/...)
  - Client-side auth guards     (role guards that may not be server-enforced)

All findings are passive patterns on the bundled source -> candidates for
manual review, never auto-severity.
"""

import re
from typing import Dict, List, Optional, Tuple

# ----------------------------------------------------------------------
# WebSocket protocol
# ----------------------------------------------------------------------
_WS_EVENT = re.compile(r"""(?:socket|io|ws|client)\.(?:on|emit|off|once)\s*\(\s*
                         ["']([^"']{1,64})["']""", re.I | re.X)
_WS_SEND = re.compile(r"""(?:socket|io|ws)\.(?:send|sendjson)\s*\(\s*
                        ["']([^"']{1,80})["']""", re.I | re.X)
_WS_AUTH = re.compile(r"""(?:socket|io|ws)\.emit\s*\(\s*
                        ["'](?:auth|login|authenticate|register|token|connect)["']""",
                      re.I | re.X)
_WS_RAW = re.compile(r"""ws\.(?:onmessage|onopen|onclose)\s*=""")

# ----------------------------------------------------------------------
# Service workers / push / offline
# ----------------------------------------------------------------------
_SW_FETCH_HANDLER = re.compile(r"""self\.addEventListener\s*\(\s*["']fetch["']""", re.I)
_SW_PUSH = re.compile(r"""self\.addEventListener\s*\(\s*["']push["']""", re.I)
_SW_NOTIFICATION = re.compile(r"""showNotification\s*\(\s*["']([^"']{1,80})["']""", re.I)
_VAPID = re.compile(r"""vapid(?:PublicKey)?\s*[:=]\s*["']([A-Za-z0-9_-]{40,})["']""", re.I)
_PUSH_SUB = re.compile(r"""[`"'](/[^`"']*(?:push|subscribe|subscription|notification)(?:/\w+)?)[`"']""", re.I)
_SW_REG = re.compile(r"""serviceWorker\.register\s*\(\s*[`"']([^`"']+)[`"']""", re.I)
_SW_MANIFEST = re.compile(r"""<link[^>]*rel=["']manifest["'][^>]*href=["']([^"']+)["']""", re.I)

# ----------------------------------------------------------------------
# SSRF metadata / exotic-scheme candidates
# ----------------------------------------------------------------------
_META_HOST = re.compile(r"""https?://(?:169\.254\.(?:169\.254|170\.2)
                         |metadata\.(?:google\.internal|compute\.)
                         |169\.254\.169\.254)""", re.I | re.X)
_META_CURL = re.compile(r"""curl\s+(?:-s\s+)?['"]?https?://metadata\.google\.internal""", re.I)
_EXOTIC = re.compile(r"""\b(?:file|gopher|dict|sftp|tftp|ldap|ldaps|ftp)://""", re.I)
_PROXY_EP = re.compile(r"""["'`](/[^"'`]*(?:proxy|redirect|fetch|url|link|image|preview|screenshot|render|webhook )[^"'`]*\?)["'`]""", re.I)

# ----------------------------------------------------------------------
# Error-tracking / infra services
# ----------------------------------------------------------------------
_SENTRY_DSN = re.compile(
    r"""https://(?P<hash>[a-f0-9]{32})@(?P<host>[a-z0-9.-]+\.ingest\.sentry\.io|sentry\.io)/?(?P<pid>\d+)?""",
    re.I)
_SENTRY_KEY = re.compile(r"""sentry\.init\s*\(\s*\{[^}]{0,300}?dsn\s*:\s*["']([^"']+)["']""", re.I | re.S)
_ERROR_SVC = [
    ('logrocket', re.compile(r"""logrocket(?:\.io|\.init|\.identify)|__rrweb\.record""", re.I)),
    ('bugsnag', re.compile(r"""bugsnag\.(?:start|notify|init)|@bugsnag""", re.I)),
    ('rollbar', re.compile(r"""rollbar\.(?:init|error|configure)|@rollbar""", re.I)),
    ('raygun', re.compile(r"""raygun\.(?:init|send)""", re.I)),
    ('fullstory', re.compile(r"""fullstory\.com|FS\.(?:init|identify)|fullstory\.identify""", re.I)),
    ('hotjar', re.compile(r"""hotjar\.com|_hjSettings""", re.I)),
    ('posthog', re.compile(r"""posthog\.(?:init|capture)|\.posthog\.com""", re.I)),
    ('datadog', re.compile(r"""datadoghq\.com|[0-9a-f]{32,}@datadoghq""", re.I)),
    ('mixpanel', re.compile(r"""mixpanel\.(?:init|identify|track)""", re.I)),
    ('intercom', re.compile(r"""intercom\.(?:Settings|boot)|@intercom/web""", re.I)),
    ('crisp', re.compile(r"""crisp\.chat|crisp\s*=\s*CRISP""", re.I)),
]

# ----------------------------------------------------------------------
# Client-side auth guards (verify server-side enforcement!)
# ----------------------------------------------------------------------
_AUTH_GUARDS = [
    ('role-identity', re.compile(r"""\b(?:user|auth|session|account)\.\s*\w*\s*===?\s*["'](?:admin|superuser|owner)["']""", re.I)),
    ('has-permission', re.compile(r"""\b(?:has|is)(?:Admin|Superuser|Owner|Role|Permission)\s*\(?""", re.I)),
    ('requires-auth-flag', re.compile(r"""requiresAuth\s*:\s*true""", re.I)),
    ('route-guard', re.compile(r"""beforeEnter\s*\([^)]{0,120}(?:auth|guard|permission|role)""", re.I)),
    ('feature-flag-admin', re.compile(r"""feature[_ -]?flag\w*\s*[=:]\s*["']?admin""", re.I)),
    ('role-param', re.compile(r"""(?:role|roles)\s*[:=]\s*["']?(?:admin|administrator|root|superuser)["']?""", re.I)),
    ('is-admin-check', re.compile(r"""\.isAdmin\s*\(|isAdmin\s*[=:]\s*true""", re.I)),
]

# ----------------------------------------------------------------------
# SSRF-able param endpoints (server-side URL fetch leads)
# ----------------------------------------------------------------------
_SSRF_PARAM_ENDPOINT = re.compile(r"""(?:/[A-Za-z0-9_-]{2,}){1,4}\?.*\b(?:url|uri|href|callback|redirect|webhook|image_url|avatar_url|proxy|target|next|continue|return)=""" , re.I)


def _dedup(rows: List[Dict]) -> List[Dict]:
    seen = set()
    out = []
    for r in rows:
        k = (r.get('type', ''), r.get('value', ''), r.get('line', 0), r.get('source', ''))
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _line(content: str, pos: int) -> int:
    return content[:pos].count('\n') + 1


def _ctx(js: str, pos: int, w: int = 90) -> str:
    return js[max(0, pos - w // 2): pos + w // 2].strip()


def scan_js(content: str, source_url: str) -> Dict[str, List[Dict]]:
    """Run all protocol/pattern extractors over one JS body."""
    out: Dict[str, List[Dict]] = {
        'ws_protocol': [], 'service_workers': [], 'push_keys': [],
        'ssrf_candidates': [], 'error_services': [], 'auth_guards': [],
    }

    # ---- websocket protocol ----
    seen_ev = set()
    for m in _WS_EVENT.finditer(content):
        ev = m.group(1)
        if ev in seen_ev:
            continue
        seen_ev.add(ev)
        kind = 'auth' if ev.lower() in ('auth', 'login', 'authenticate', 'register', 'token') else 'event'
        out['ws_protocol'].append({
            'type': 'ws_' + kind, 'value': ev, 'event': ev,
            'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
            'source': source_url,
            'severity': 'MEDIUM' if kind == 'auth' else 'INFO',
            'confidence': 'high' if kind == 'auth' else 'medium',
        })
    for m in _WS_SEND.finditer(content):
        ev = m.group(1)
        if ev in seen_ev:
            continue
        seen_ev.add(ev)
        out['ws_protocol'].append({
            'type': 'ws_send', 'value': ev, 'event': ev,
            'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
            'source': source_url, 'severity': 'INFO', 'confidence': 'medium'})
    if _WS_RAW.search(content):
        out['ws_protocol'].append({
            'type': 'ws_raw_handlers', 'value': 'ws.onmessage/onopen/onclose assignment',
            'event': '', 'line': 1, 'context': 'raw websocket message handlers present',
            'source': source_url, 'severity': 'INFO', 'confidence': 'low'})

    # ---- service workers ----
    sw = out['service_workers']
    for m in _SW_REG.finditer(content):
        sw.append({'type': 'service_worker', 'value': m.group(1),
                   'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                   'source': source_url, 'severity': 'INFO', 'confidence': 'medium',
                   'note': 'service worker scope - analyze worker JS'})
    if _SW_FETCH_HANDLER.search(content):
        sw.append({'type': 'sw_fetch_handler', 'value': 'fetch event',
                   'line': 1, 'context': 'self.addEventListener("fetch") - offline/request interception',
                   'source': source_url, 'severity': 'MEDIUM', 'confidence': 'medium',
                   'note': 'request interception logic can reveal auth headers to bypass'})
    for m in _SW_NOTIFICATION.finditer(content):
        sw.append({'type': 'sw_notification', 'value': m.group(1),
                   'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                   'source': source_url, 'severity': 'INFO', 'confidence': 'medium'})
    if _SW_PUSH.search(content):
        sw.append({'type': 'sw_push_handler', 'value': 'push event',
                   'line': 1, 'context': 'self.addEventListener("push") - notification payload handling',
                   'source': source_url, 'severity': 'MEDIUM', 'confidence': 'medium'})

    # ---- push / VAPID ----
    for m in _VAPID.finditer(content):
        out['push_keys'].append({'type': 'vapid_public_key', 'value': m.group(1),
                                 'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                                 'source': source_url, 'severity': 'INFO', 'confidence': 'medium'})
    for m in _PUSH_SUB.finditer(content):
        out['push_keys'].append({'type': 'push_subscription_endpoint', 'value': m.group(1),
                                 'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                                 'source': source_url, 'severity': 'INFO', 'confidence': 'medium'})

    # ---- SSRF / metadata candidates ----
    ss = out['ssrf_candidates']
    for m in _META_HOST.finditer(content):
        ss.append({'type': 'cloud_metadata_url', 'value': m.group(0)[:80],
                   'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                   'source': source_url, 'severity': 'HIGH', 'confidence': 'high',
                   'note': 'cloud metadata endpoint referenced in bundle'})
    for m in _EXOTIC.finditer(content):
        ss.append({'type': 'exotic_scheme', 'value': m.group(0)[:40],
                   'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                   'source': source_url, 'severity': 'MEDIUM', 'confidence': 'medium',
                   'note': 'file/gopher/ldap/etc - possible SSRF primitive if server fetches it'})
    for m in _PROXY_EP.finditer(content):
        ss.append({'type': 'url_fetch_endpoint', 'value': m.group(1)[:80],
                   'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                   'source': source_url, 'severity': 'LOW', 'confidence': 'medium',
                   'note': 'server-side URL-fetching endpoint candidate'})

    # ---- error / infra services ----
    es = out['error_services']
    for m in _SENTRY_DSN.finditer(content):
        es.append({'type': 'sentry_dsn', 'service': 'Sentry', 'value': _redact_dsn(m.group(0)),
                   'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                   'source': source_url, 'severity': 'INFO', 'confidence': 'high'})
    for m in _SENTRY_KEY.finditer(content):
        es.append({'type': 'sentry_dsn', 'service': 'Sentry', 'value': _redact_dsn(m.group(1)),
                   'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                   'source': source_url, 'severity': 'INFO', 'confidence': 'high'})
    for name, regex in _ERROR_SVC:
        for m in list(regex.finditer(content))[:3]:
            es.append({'type': 'error_service', 'service': name, 'value': name,
                       'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                       'source': source_url, 'severity': 'INFO', 'confidence': 'medium'})

    # ---- client-side auth guards ----
    ag = out['auth_guards']
    for name, regex in _AUTH_GUARDS:
        for m in list(regex.finditer(content))[:5]:
            ag.append({'type': name, 'value': m.group(0)[:90],
                       'line': _line(content, m.start()), 'context': _ctx(content, m.start()),
                       'source': source_url, 'severity': 'INFO', 'confidence': 'medium',
                       'note': 'client-side authorization check - VERIFY the API enforces it server-side'})

    for k in out:
        out[k] = _dedup(out[k])
    return out


def _redact_dsn(dsn: str) -> str:
    """Sentry DSNs carry an internal key - show shape, not the secret."""
    m = re.match(r'(https://)[^@]+@([a-z0-9.-]+)', dsn, re.I)
    if m:
        return f"{m.group(1)}<key>@{m.group(2)}"
    return dsn[:60] + ('…' if len(dsn) > 60 else '')
