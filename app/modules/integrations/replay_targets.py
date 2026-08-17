# app/modules/integrations/replay_targets.py
"""Replay-target selection for the Caido bridge.

Raw JS-endpoint lists are noise-heavy (XML namespaces, webpack chunks,
SPA routes, static assets). This module scores every endpoint and returns a
curated, deduplicated, capped list worth actually re-sending into Caido
Replay for manual testing.

Priorities (bug-bounty veteran ordering):
  1. Auth-gated / gated-route responses (401/403/405/5xx) - the money
  2. API-ish paths (/api/, /v1/, /graphql, /admin, /actuator, ...)
  3. Endpoints with query parameters or POST/body_schema (mutations to test)
  4. GraphQL / WebSocket endpoints
  5. Validated live 200s only when they carry API hints or params

Excluded outright: static assets, chunk/namespace noise, soft-404s, and
plain SPA page routes (unless explicitly requested).
"""

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

STATIC_EXTS = frozenset((
    '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp', '.avif',
    '.mp4', '.webm', '.pdf', '.zip', '.gz', '.doc', '.docx', '.xls', '.xlsx',
))

NOISE_SUBSTRINGS = (
    'w3.org/', 'xmlns', 'xmlns:', '/_next/static', '/_next/data',
    '/static/', '/assets/', '/img/', '/images/', '/fonts/', '/media/',
    '/favicon', 'manifest.json', 'service-worker', 'sw.js', 'robots.txt',
    'sitemap', 'chunk.', 'vendor.', 'runtime.', '.min.js', '.bundle.',
)

# Hashed bundle fragments: [a-f0-9]{8,} right before an asset extension
_HASHED = re.compile(r'[.-][a-f0-9]{8,}\.(?:js|css|png|jpg|jpeg|svg|woff2?)$')

# Bug-class hints from URL shape (feeds skill-based push-to-Caido workflows)
CLASS_HINTS = {
    'rce': re.compile(r'(cmd|command|exec|run|shell|system|exploit|template|repo|branch|deserialize|yaml|yml|xslt|import|convert|render|download)', re.I),
    'sqli': re.compile(r'(search|q=|query|filter|sort|order=|id=|uid=|name=|email=|label|page=|lang=|category)', re.I),
    'xxe': re.compile(r'(xml|soap|upload|import|parse|convert|pdf|svg|xslt|feed|rss|export)', re.I),
    'ssrf': re.compile(r'(url|uri|image|img|src|fetch|proxy|load|link|webhook|callback|avatar|file|download|render|import|export)', re.I),
    'csrf': re.compile(r'(settings|profile|delete|update|change|disable|enable|transfer|password|email|token|2fa|mfa)', re.I),
    'auth': re.compile(r'(login|logout|signin|signup|register|reset|forgot|verify|token|sso|session|logout|password|otp|mfa|2fa)', re.I),
    'idor': re.compile(r'/(api|rest|v1|v2|users?|orders?|accounts?|profile|item|items|documents?|files?|messages?|stories?|tickets?|payments?|transactions?)/', re.I),
}


def technique_tags(url: str) -> List[str]:
    """Classify an endpoint into bug-class hints for workflow routing."""
    tags = []
    for cls, rx in CLASS_HINTS.items():
        if rx.search(url):
            tags.append(cls)
    return tags

API_HINTS = (
    '/api/', '/v1/', '/v2/', '/v3/', '/rest/', 'graphql', 'gql', '/admin',
    '/internal', '/debug', '/actuator', '/swagger', '/openapi', '/oauth',
    '/auth', '/token', '/login', '/upload', '/webhook', '/callback',
    '/integration', '/import', '/export', '/config', '/env', '/metrics',
    '/health', '/status', '/search', '/users', '/orders', '/payments',
    '/balance', '/transaction', '/kyc', '/withdraw', '/deposit', '/sso',
)

GATED_STATUSES = {'401', '403', '405', '500', '501', '502', '503', '504'}


def _path_only(url: str) -> str:
    try:
        p = urlparse(url)
        return p.scheme, p.netloc, p.path or '/'
    except Exception:
        return '', '', url or '/'


def _static_or_noise(url: str) -> Tuple[bool, str]:
    """Return (is_excluded, reason)."""
    low = url.lower()
    for n in NOISE_SUBSTRINGS:
        if n in low:
            return True, 'noise'
    try:
        path = urlparse(url).path
    except Exception:
        return False, ''
    if path.endswith(tuple(STATIC_EXTS)) or _HASHED.search(path):
        return True, 'static'
    return False, ''


def score_endpoint(row: Dict) -> Tuple[int, str, str]:
    """Score one endpoint row -> (score, category, reason)."""
    url = str(row.get('endpoint') or row.get('url') or '')
    low = url.lower()
    if not url.startswith(('http://', 'https://')):
        return -100, 'noise', 'not-absolute'

    excluded, reason = _static_or_noise(url)
    if excluded:
        return -100, reason or 'excluded', reason

    if str(row.get('soft_404') or '').lower() in ('true', '1', 'yes'):
        return -100, 'soft404', 'soft-404'

    status = str(row.get('live_status') or '')
    method = str(row.get('method') or 'GET').upper()
    has_params = bool(row.get('query_params') and
                      str(row.get('query_params')) not in ('{}', '', 'nan', '[]'))
    has_body = bool(row.get('body_schema') and
                    str(row.get('body_schema')) not in ('{}', '', 'nan', '[]'))
    hints = str(row.get('suspicious_indicators') or '')
    graphql = bool(row.get('graphql_type')) or 'graphql' in low or 'gql' in low
    ws = bool(row.get('websocket')) or low.startswith(('ws://', 'wss://'))

    score = 0
    tags = []

    api_hint = any(h in low for h in API_HINTS)
    if graphql:
        score += 35
        tags.append('graphql')
    elif ws:
        score += 35
        tags.append('websocket')
    elif api_hint:
        score += 30
        tags.append('api')

    if status in GATED_STATUSES:
        score += 25 if status in ('401', '403') else 15
        tags.append(f'gated-{status}')
    elif status == '200':
        score += 8 if (api_hint or graphql or has_params) else 2
        tags.append('live')
    elif status and status.isdigit():
        score += 3
        tags.append(f'http-{status}')

    if has_params:
        score += 10
        tags.append('params')
    if method == 'POST':
        score += 8
        tags.append('post')
    elif method not in ('GET', ''):
        score += 4
        tags.append(method.lower())
    if has_body:
        score += 6
        tags.append('body-schema')
    if hints:
        score += 5
        tags.append('suspicious')

    # plain SPA page route: keep only when it has something to test
    if score <= 2 and not api_hint and not graphql:
        return -50, 'page', 'spa-route'

    category = tags[0] if tags else ('api' if api_hint else 'page')
    return score, category, '+'.join(tags) if tags else 'endpoint'


def build_replay_targets(endpoints_df,
                         max_targets: int = 250,
                         include_pages: bool = False,
                         include_static: bool = False) -> Dict:
    """Curate endpoints for Caido Replay.

    Args:
        endpoints_df: js_discovered_endpoints frame (validated in place is
            preferred - live_status/soft_404/allow_methods enrich the scores).
        max_targets: hard cap on how many endpoints come back.
        include_pages: keep plain SPA page routes (default off - noise).
        include_static: keep static assets (default off).

    Returns:
        {'targets': [{'url','method','score','category','reason','status'}...],
         'skipped': {category: count},
         'total_seen': n}
    """
    import pandas as pd

    targets: List[Dict] = []
    skipped = {}
    total_seen = 0

    if isinstance(endpoints_df, pd.DataFrame) and not endpoints_df.empty:
        rows = endpoints_df.to_dict('records')
    else:
        rows = []

    for row in rows:
        url = str(row.get('endpoint') or row.get('url') or '').strip()
        if not url:
            continue
        total_seen += 1
        score, category, reason = score_endpoint(row)

        if score < 0:
            if include_static and category in ('static', 'noise') and reason == 'static':
                score = 1
                category = 'static'
            elif include_pages and category == 'page':
                score = 1
                category = 'page'
            else:
                skipped[category] = skipped.get(category, 0) + 1
                continue
            reason = 'forced-include'

        targets.append({
            'url': url,
            'method': str(row.get('method') or 'GET').upper(),
            'score': score,
            'category': category,
            'reason': reason,
            'status': str(row.get('live_status') or ''),
        })

    # Dedupe by (scheme, host, path) keeping the highest-scoring variant
    seen = {}
    for t in sorted(targets, key=lambda x: -x['score']):
        key = _path_only(t['url'])
        if key not in seen:
            seen[key] = t
    targets = list(seen.values())

    targets.sort(key=lambda x: (-x['score'], x['url']))
    if len(targets) > max_targets:
        dropped = len(targets) - max_targets
        skipped['cap'] = skipped.get('cap', 0) + dropped
        targets = targets[:max_targets]

    return {
        'targets': targets,
        'skipped': skipped,
        'total_seen': total_seen,
    }
