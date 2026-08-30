"""
validator_router.py — route endpoints by their characteristics to the right
scanners. No auth needed — all probes are unauthenticated.

Given a list of discovered endpoints, classifies each one and routes it to:
  - XML-accepting → XXE scanner
  - cmd=/exec=/action= params → RCE probe kit
  - multipart form → upload probes
  - GraphQL detected → GraphQL security probes
  - JWT in headers/body → JWT live audit
  - JSON endpoints → mass assignment scanner
  - WebSocket endpoints → WebSocket scanner
  - Host header → host header scanner
  - Rate-limit → rate limit tester

Classification is deterministic: Content-Type hints, param names, endpoint
paths, and extraction metadata all feed the routing decision.
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse, parse_qs

from app.utils.logger import get_logger

logger = get_logger()

_XML_CT = {'application/xml', 'text/xml', 'application/soap+xml', 'application/xhtml+xml'}
_MULTIPART_CT = {'multipart/form-data'}
_JSON_CT = {'application/json'}
_GRAPQL_CT = {'application/graphql', 'application/graphql+json'}
_FORM_CT = {'application/x-www-form-urlencoded'}

_RCE_PARAMS = {'cmd', 'command', 'exec', 'execute', 'run', 'action', 'func',
               'function', 'shell', 'bash', 'sh', 'c', 'script', 'code',
               'eval', 'expression', 'expr', 'system', 'popen', 'subprocess',
               'passthru', 'proc_open', 'popen', 'exec_cmd', 'shell_exec',
               'popen', 'backtick'}

_REDIRECT_PARAMS = {'g', 'r', 'l', 'u', 'url', 'to', 'go', 'next', 'ref',
                    'return', 'redirect', 'forward', 'dest', 'destination',
                    'target', 'callback', 'cb', 'goto', 'continue', 'back',
                    'link', 'jump', 'path', 'loc', 'location', 'out', 'view',
                    'redirectUrl', 'redirectTo', 'returnUrl', 'returnTo'}

_FILE_PARAMS = {'file', 'path', 'dir', 'folder', 'directory', 'document',
                'attachment', 'download', 'dl', 'load', 'open', 'read',
                'include', 'require', 'template', 'tpl', 'view', 'page',
                'module', 'component', 'config', 'settings'}


def classify_endpoint(ep: Dict) -> Set[str]:
    """Return a set of scanner classes this endpoint should be routed to."""
    classes: Set[str] = set()

    ct = str(ep.get('content_type', '') or '').lower().split(';')[0].strip()
    url = ep.get('url', '') or ep.get('endpoint', '')
    method = str(ep.get('method', 'GET')).upper()
    body = ep.get('body', {}) or {}
    headers = ep.get('headers', {}) or {}
    params = ep.get('params', []) or []
    path = (urlparse(url).path or '').lower()
    indicators = ep.get('suspicious_indicators', []) or []

    # Content-Type routing
    if ct in _XML_CT:
        classes.add('xxe')
    if ct in _MULTIPART_CT:
        classes.add('upload')
    if ct in _GRAPQL_CT or 'graphql' in path:
        classes.add('graphql')
    if ct in _JSON_CT:
        classes.add('mass_assignment')
    if ep.get('graphql_type'):
        classes.add('graphql')

    # Param-based routing
    if isinstance(params, list):
        param_names = {p.lower() if isinstance(p, str) else '' for p in params}
    elif isinstance(params, dict):
        param_names = {k.lower() for k in params.keys()}
    else:
        try:
            parsed = parse_qs(urlparse(url).query)
            param_names = {k.lower() for k in parsed.keys()}
        except Exception:
            param_names = set()

    if param_names & _RCE_PARAMS:
        classes.add('rce')
    if param_names & _REDIRECT_PARAMS:
        classes.add('open_redirect')
    if param_names & _FILE_PARAMS:
        classes.add('lfi')

    # Body inspection
    if isinstance(body, dict):
        body_keys = {k.lower() for k in body.keys()}
        if body_keys & _RCE_PARAMS:
            classes.add('rce')
        if body_keys & _REDIRECT_PARAMS:
            classes.add('open_redirect')

    # Auth header hints
    auth_header = str(headers.get('Authorization', '') or headers.get('authorization', '')).lower()
    if 'bearer' in auth_header or 'jwt' in auth_header:
        classes.add('jwt')

    # Indicator-based routing
    ind_str = ' '.join(str(i).lower() for i in indicators)
    if 'websocket' in ind_str or ep.get('websocket'):
        classes.add('websocket')
    if 'xml' in ind_str or 'soap' in ind_str:
        classes.add('xxe')
    if 'upload' in ind_str or 'file' in ind_str:
        classes.add('upload')
    if 'host_header' in ind_str:
        classes.add('host_header')
    if 'rate_limit' in ind_str:
        classes.add('rate_limit')

    # Path-based routing
    if 'graphql' in path:
        classes.add('graphql')
    if 'ws' in path or 'websocket' in path:
        classes.add('websocket')
    if 'upload' in path or 'import' in path:
        classes.add('upload')
    if 'token' in path or 'jwt' in path or 'auth' in path:
        classes.add('jwt')

    return classes


def route_endpoints(endpoints: List[Dict]) -> Dict[str, List[Dict]]:
    """Route a list of endpoints to scanner classes.

    Returns dict like {'xxe': [...], 'rce': [...], 'open_redirect': [...], ...}
    """
    routed: Dict[str, List[Dict]] = {}
    for ep in endpoints:
        for cls in classify_endpoint(ep):
            routed.setdefault(cls, []).append(ep)
    return routed


def route_stats(endpoints: List[Dict]) -> Dict[str, int]:
    """Count how many endpoints route to each scanner class."""
    routed = route_endpoints(endpoints)
    return {k: len(v) for k, v in sorted(routed.items(), key=lambda x: -len(x[1]))}


def find_params_for_scanner(scanner_class: str, endpoints: List[Dict]) -> List[str]:
    """Extract the most common parameter names for a given scanner class."""
    from collections import Counter
    routed = route_endpoints(endpoints).get(scanner_class, [])
    params = Counter()
    for ep in routed:
        ep_params = ep.get('params', [])
        if isinstance(ep_params, list):
            for p in ep_params:
                if isinstance(p, str) and p:
                    params[p.lower()] += 1
        elif isinstance(ep_params, dict):
            for k in ep_params:
                params[k.lower()] += 1
    return [p for p, _ in params.most_common(20)]


__all__ = [
    'classify_endpoint', 'route_endpoints', 'route_stats',
    'find_params_for_scanner',
]