"""js_semantic.py

ESTree-based semantic extraction (Phase 1 of the review roadmap).

Turns JS call-expressions into a normalized HTTP request IR:

    JS ── AST ──> CallExpression ──> method + URL expr + options
                                          │
                                          ▼
    RequestIR {
      url, url_template, canonical_path, method, content_type,
      headers{}, auth{type, source}, body{...}, query_params{},
      path_params[], params[..], objects[..], security_signals[],
      websocket, file_upload, source{file, line, function},
      extraction_method: "ast"
    }

Handles: fetch, axios (methods + request + call), jQuery ($.ajax/$.get/$.post),
Angular `this.http.*` / `http.request` / `$http`, XHR `xhr.open`, WebSocket,
Socket.IO (`io` / `io.connect`), plus URL templates (${base}/u/${id}),
binary concat (API + '/u/' + id), `new URL()`, JSON.stringify bodies,
FormData/upload, urlencoded bodies, auth headers + token-source functions.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin as _urljoin, urlsplit

logger = logging.getLogger(__name__)

try:
    import esprima
    HAS_ESPRIMA = True
except Exception:  # pragma: no cover
    esprima = None
    HAS_ESPRIMA = False

# ----------------------------------------------------------------------
# HTTP method verbs on common client objects
# ----------------------------------------------------------------------
_METHOD_VERBS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}
# objects we treat as HTTP clients when they expose a verb method; only
# property-access (not arbitrary globals) to avoid false positives.
_CLIENT_ROOTS = {'http', 'httpclient', 'client', 'api', 'service', 'services',
                 'axios', 'fetch', 'request', 'ajax', '$http', 'rest', 'apiClient'}
_TS_TYPE_GENERIC = re.compile(r'^<.+>$', re.S)

# tracing queries with these params are SSRF / redirect candidates
_SSRF_PARAM = {'url', 'uri', 'href', 'link', 'callback', 'redirect',
               'redirect_uri', 'webhook', 'image_url', 'avatar_url', 'proxy',
               'target', 'destination', 'fetch', 'endpoint', 'host', 'domain',
               'callback_url', 'return_url', 'continue', 'next', 'return'}
_OBJ_IDENTIFIER = ('id', 'userid', 'user_id', 'accountid', 'account_id',
                   'clientid', 'customerid', 'customer_id', 'invoiceid',
                   'invoice_id', 'documentid', 'document_id', 'fileid',
                   'file_id', 'orderid', 'order_id', 'ticketid', 'ticket_id',
                   'recordid', 'record_id', 'profileid', 'profile_id',
                   'deviceid', 'device_id', 'paymentid', 'payment_id',
                   'subscriptionid', 'subscription_id', 'messageid')
_TENANT_IDENTIFIER = ('tenantid', 'tenant_id', 'organizationid', 'organization_id',
                      'workspaceid', 'workspace_id', 'companyid', 'company_id',
                      'merchantid', 'merchant_id', 'teamid', 'team_id', 'orgid',
                      'org_id', 'subdomain', 'namespace', 'tenant', 'organization',
                      'org', 'workspace', 'team', 'company', 'merchant', 'store',
                      'agency', 'branch', 'customer_id', 'client_id')
_AMOUNT_FIELD = ('amount', 'price', 'balance', 'total', 'quantity', 'fee',
                 'charge', 'cost', 'salary', 'limit', 'credit')
_SENSITIVE_FIELD = ('password', 'passwd', 'pwd', 'secret', 'token', 'apikey',
                    'api_key', 'api-key', 'access_token', 'refresh_token',
                    'authorization', 'cookie', 'session', 'ssn', 'ssn_number',
                    'creditcard', 'card_number', 'cvv', 'iban', 'account_number')
_UPLOAD_FIELD = ('file', 'filename', 'attachment', 'document', 'upload',
                 'image', 'avatar', 'photo', 'resume', 'logo', 'thumbnail')
_UPLOAD_PATH = re.compile(r'(upload|attachment|import|import_|files?/|documents?/|media/|avatar)', re.I)
_SSRF_PATH = re.compile(r'(fetch|proxy|redirect|callback|webhook|preview|screenshot|render|download|image)', re.I)


class RequestIR:
    __slots__ = ('method', 'url', 'url_template', 'canonical_path', 'headers',
                 'auth_type', 'auth_source', 'content_type', 'body_fields',
                 'query_params', 'path_params', 'params', 'websocket',
                 'file_upload', 'line', 'function', 'raw')

    def __init__(self, method: str = 'GET', url: str = '', url_template: str = '',
                 canonical_path: str = '', line: int = 0, function: str = ''):
        self.method = method
        self.url = url
        self.url_template = url_template
        self.canonical_path = canonical_path
        self.headers: Dict[str, str] = {}
        self.auth_type: Optional[str] = None
        self.auth_source: Optional[str] = None
        self.content_type: Optional[str] = None
        self.body_fields: Dict[str, str] = {}
        self.query_params: Dict[str, str] = {}
        self.path_params: List[str] = []
        self.params: List[Dict] = []      # name, kind(path/query/body), source, value
        self.websocket: bool = False
        self.file_upload: bool = False
        self.line = line
        self.function = function
        self.raw: str = ''

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'url_template': self.url_template,
            'canonical_path': self.canonical_path,
            'method': self.method,
            'headers': self.headers,
            'auth': {'type': self.auth_type, 'source': self.auth_source},
            'content_type': self.content_type,
            'body': self.body_fields,
            'query_params': self.query_params,
            'path_params': self.path_params,
            'params': self.params,
            'websocket': self.websocket,
            'file_upload': self.file_upload,
            'source': {'line': self.line, 'function': self.function},
        }


# ----------------------------------------------------------------------
# URL expression -> (template_literal, canonical, params)
# ----------------------------------------------------------------------
def _expr_value(node: Dict) -> str:
    """Best-effort string for an AST expression (identifier name etc.)."""
    t = node.get('type')
    if t == 'Identifier':
        return node.get('name') or ''
    if t == 'Literal':
        v = node.get('value')
        return '' if v is None else str(v)
    if t == 'MemberExpression':
        prop = node.get('property', {})
        obj = _expr_value(node.get('object', {}))
        p = _expr_value(prop)
        return f'{obj}.{p}' if obj else p
    if t == 'CallExpression':
        return _call_str(node)
    if t == 'TemplateLiteral':
        return 'template'
    if t == 'BinaryExpression' and node.get('operator') == '+':
        left = _expr_value(node.get('left', {}))
        right = _expr_value(node.get('right', {}))
        return (left or '') + (right or '')
    if t in ('ThisExpression',):
        return 'this'
    if t in ('ObjectExpression', 'ArrayExpression'):
        return ''
    return ''


def _call_str(node: Dict) -> str:
    callee = node.get('callee', {})
    base = _expr_value(callee)
    args = []
    for a in node.get('arguments', [])[:2]:
        args.append(_expr_value(a))
    return f"{base}({', '.join(a for a in args if a)})"


def _is_param_like(name: str) -> bool:
    if not name:
        return False
    low = name.lower()
    if low in ('true', 'false', 'null', 'undefined', 'this', 'location',
               'window', 'document', 'api', 'endpoint', 'env', 'process'):
        return False
    if any(ch in name for ch in (' ', '(', ')', '=', ';', '{', '}')):
        return False
    return True


def _expr_to_param(name: str, kind: str) -> Dict:
    low = name.lower()
    cls = None
    hit = None
    if low in _TENANT_IDENTIFIER or low in _OBJ_IDENTIFIER or low.endswith('id'):
        cls = 'object_identifier' if low in _OBJ_IDENTIFIER or low.endswith('id') else 'tenant_identifier'
        if low in _TENANT_IDENTIFIER:
            cls = 'tenant_identifier'
        hit = True
    if low in _TENANT_IDENTIFIER:
        cls = 'tenant_identifier'
        hit = True
    if low in _SSRF_PARAM:
        cls = 'ssrf_parameter'
        hit = True
    if low in _SENSITIVE_FIELD:
        cls = 'sensitive_field'
        hit = True
    if low in _AMOUNT_FIELD:
        cls = 'amount_field'
        hit = True
    if low in _UPLOAD_FIELD:
        cls = 'upload_field'
        hit = True
    return {'name': name, 'kind': kind, 'source': 'variable' if ' ' not in name else 'literal',
            'class': cls}


def _template_to_parts(node: Dict) -> Tuple[str, str, List[str]]:
    """Resolve a TemplateLiteral node -> (template_str, canonical_str, params[])."""
    quasis = node.get('quasis', [])
    expressions = node.get('expressions', [])
    segs = []
    for i, q in enumerate(quasis):
        segs.append((q.get('value', {}).get('raw', ''), 'static'))
        if i < len(expressions):
            ename = _expr_value(expressions[i])
            if _is_param_like(ename):
                segs.append((f'${{{ename}}}', 'param'))
            else:
                segs.append(('', 'dropped'))
    template = ''.join(s for s, _ in segs)
    canon = re.sub(r'\$\{([^}]+)\}', r'{\1}', template)
    params = []
    for _, kind in segs:
        pass
    return template, canon, params


def _concat_parts(node: Dict) -> Optional[Tuple[str, List[str]]]:
    """Split a + expression into static+variable segments (bounded)."""
    if node.get('type') == 'Literal':
        v = node.get('value')
        return (str(v) if v is not None else '', [])
    if node.get('type') == 'Identifier':
        n = node.get('name', '')
        return (f'${{{n}}}', [n]) if _is_param_like(n) else ('', [])
    if node.get('type') == 'TemplateLiteral':
        t, _c, _p = _template_to_parts(node)
        return (t, [n for n in _p])
    if node.get('type') == 'BinaryExpression' and node.get('operator') == '+':
        left = _concat_parts(node.get('left'))
        right = _concat_parts(node.get('right'))
        if left is None or right is None:
            return None
        ltxt, lparams = left
        rtxt, rparams = right
        params = lparams + rparams
        if ltxt.endswith('$}'):
            joined = ltxt + rtxt
        else:
            joined = ltxt + rtxt
        return joined, params
    if node.get('type') == 'CallExpression':
        # template=var could be from getEnv()/API.base - keep as marker
        return (f'${{{_call_str(node)}}}', [])
    if node.get('type') == 'MemberExpression':
        return (f'${{{_expr_value(node)}}}', [])
    return None


def _build_url(node: Dict, base_url: str) -> Optional[Dict[str, Any]]:
    """Central resolver: node -> {url, template, canonical, path_params, query}."""
    template = ''
    static_parts: List[str] = []
    params: List[str] = []
    has_dynamic = False

    def add(piece: str) -> None:
        nonlocal template, has_dynamic
        m = re.match(r'^\$\{(.+)\}$', piece)
        if m:
            name = m.group(1)
            if _is_param_like(name):
                template += f'${{{name}}}'
                params.append(name)
                has_dynamic = True
            else:
                template += f'${{{name}}}'
        else:
            template += piece

    t = node.get('type')
    if t == 'Literal':
        v = node.get('value')
        if isinstance(v, str):
            template = v
        else:
            return None
    elif t == 'TemplateLiteral':
        template, _canon, _p = _template_to_parts(node)
        m = re.findall(r'\$\{([^}]+)\}', template)
        params = [p for p in m if _is_param_like(p)]
        has_dynamic = bool(params)
    elif t in ('BinaryExpression',):
        if node.get('operator') != '+':
            return None
        parts = _concat_parts(node)
        if parts is None:
            return None
        template, params = parts
        has_dynamic = bool(params)
    elif t == 'CallExpression':
        # new URL('/x', base) or new URL(base + '/x')
        callee = node.get('callee', {})
        if (callee.get('type') == 'NewExpression' or
                (callee.get('type') == 'Identifier' and callee.get('name') == 'URL')):
            args = node.get('arguments', [])
            if args:
                sub = _build_url(args[0], base_url)
                if not sub:
                    return None
                return sub
        return None
    elif t == 'Identifier':
        # bare variable reference (e.g. endpoint passed elsewhere) - keep marker
        n = node.get('name', '')
        template = f'${{{n}}}' if n else ''
        has_dynamic = bool(n)
    elif t == 'MemberExpression':
        template = f'${{{_expr_value(node)}}}'
        has_dynamic = True
    else:
        return None

    if not has_dynamic and not template:
        return None
    if not template:
        return None

    # absolutize + canonicalize
    if template.startswith('${'):
        # root is a runtime variable (${base}/users/{id}) - can't absolutize,
        # but keep the template + canonical path + params for IDOR modeling.
        canon = re.sub(r'\$\{([^}]+)\}', r'{\1}', template)
        path_params = [p for p in re.findall(r'\{([^{}]+)\}', canon) if _is_param_like(p)]
        return {'template': template, 'url': '', 'canonical': canon,
                'path_params': path_params, 'query': {}}
    abs_url = _urljoin(base_url, template)
    split = urlsplit(abs_url)
    query = {}
    if split.query:
        for pair in split.query.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                query[k] = _trim_string(v)
    # canonical: literal path with ${var} -> {var} (keeps only param-ish vars)
    canonical = urljoin_path(split.path)
    canonical = re.sub(r'\$\{([^}]+)\}', r'{\1}', canonical)
    path_params = re.findall(r'\{([^{}]+)\}', canonical)
    if not path_params and params:
        path_params = params
    return {'template': template, 'url': abs_url, 'canonical': canonical,
            'path_params': path_params, 'query': query}


def _trim_string(v: str) -> str:
    return v.strip('"\'`')


def urljoin_path(path: str) -> str:
    """Normalize a path into {param} canonical form; keep /api shape."""
    return re.sub(r'/+', '/', path) if path else ''


# ----------------------------------------------------------------------
# option parsing (headers/body/auth/content-type)
# ----------------------------------------------------------------------
def _parse_headers_obj(node: Dict) -> Dict[str, str]:
    out = {}
    for p in node.get('properties', []):
        k = p.get('key', {})
        kname = ((k.get('name') or k.get('value') or '')
                 if k.get('type') in ('Identifier', 'Literal') else _expr_value(k))
        v = _expr_value(p.get('value', {}))
        if kname and v:
            out[str(kname)] = str(v)
    return out


def _parse_body_node(node: Dict) -> Tuple[Dict[str, str], Optional[str]]:
    """Return (fields, content_type) for a body expression."""
    t = node.get('type')
    if t == 'CallExpression':
        callee = node.get('callee', {})
        # JSON.stringify({...})
        if (callee.get('type') == 'MemberExpression' and
                _expr_value(callee.get('object', {})) == 'JSON' and
                _expr_value(callee.get('property', {})) == 'stringify'):
            args = node.get('arguments', [])
            if args:
                return _parse_body_node(args[0])
        # URLSearchParams / searchParams
        if callee.get('type') == 'Identifier' and callee.get('name') in ('URLSearchParams', 'FormData'):
            ct = 'multipart/form-data' if callee.get('name') == 'FormData' else 'application/x-www-form-urlencoded'
            return ({'__' + callee.get('name'): ''}, ct)
        return ({}, None)
    if t == 'ObjectExpression':
        fields = {}
        for p in node.get('properties', []):
            k = _expr_value(p.get('key', {}))
            vname = _expr_value(p.get('value', {}))
            if k:
                fields[k] = vname if vname else 'null'
        return (fields, 'application/json' if fields else None)
    if t == 'Literal':
        v = node.get('value')
        if isinstance(v, str) and ('=' in v or '&' in v):
            fields = {}
            for pair in v.split('&'):
                if '=' in pair:
                    k, val = pair.split('=', 1)
                    fields[k] = _trim_string(val)
            return (fields, 'application/x-www-form-urlencoded')
        if isinstance(v, str):
            return ({}, 'text/plain')
    if t == 'Identifier':
        return ({node.get('name', ''): 'variable'}, None)
    return ({}, None)


# ----------------------------------------------------------------------
# auth extraction
# ----------------------------------------------------------------------
_AUTH_HEADER_KIND = {
    'authorization': ('bearer', None),      # refined by prefix below
    'x-api-key': ('api_key', 'header'),
    'x-auth-token': ('auth_token', 'header'),
    'x-api-token': ('auth_token', 'header'),
    'api-key': ('api_key', 'header'),
    'x-csrf-token': ('csrf', 'header'),
    'cookie': ('cookie', 'header'),
    'client-secret': ('oauth_client_secret', 'header'),
    'x-client-secret': ('oauth_client_secret', 'header'),
}


def _detect_auth(headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str]]:
    """(auth_type, auth_source) from parsed headers dict."""
    for k, v in headers.items():
        kl = k.lower()
        if kl == 'authorization':
            vv = v.lower()
            if vv.startswith('basic'):
                return ('basic', v)
            if 'bearer' in vv:
                src = v.replace('Bearer', '').strip()
                return ('bearer', src or 'token')
            if 'digest' in vv:
                return ('digest', v)
            return ('bearer', v)
        base = _AUTH_HEADER_KIND.get(kl)
        if base:
            return (base[0], v)
    return (None, None)


# ----------------------------------------------------------------------
# main extractor
# ----------------------------------------------------------------------
class JSSemanticExtractor:
    def __init__(self, config: Optional[Dict] = None):
        cfg = config or {}
        self.client_roots: set = set(_CLIENT_ROOTS)
        self.fetch_opts = cfg.get('js_semantic', {}).get('enabled', True)

    # ----------------------------------------------------------------
    def _callee_method(self, callee: Dict) -> Optional[Tuple[str, str, bool]]:
        """Recognize HTTP client verb calls.
        Returns (method, kind) kind in {'fetch','axios','angular','http','jquery','xhr','socketio'}.
        """
        t = callee.get('type')
        if t == 'Identifier':
            name = callee.get('name', '')
            if name == 'fetch':
                return ('GET', 'fetch')
            if name == 'io':
                return ('WS', 'socketio')
            return None
        if t != 'MemberExpression':
            return None
        prop = callee.get('property', {})
        prop_name = _expr_value(prop) if prop else ''
        obj = callee.get('object', {})
        obj_str = _expr_value(obj) if obj else ''
        low = obj_str.lower()

        # socket.io: io(url) handled as identifier; io.connect(url)
        if low == 'io' and prop_name == 'connect':
            return ('WS', 'socketio')

        # jQuery: $.ajax({...}), $.post/get...
        if low in ('$', 'jquery') and (prop_name in _METHOD_VERBS or prop_name == 'ajax'):
            return (prop_name.upper() if prop_name in _METHOD_VERBS else 'GET', 'jquery')

        if prop_name not in _METHOD_VERBS:
            # xhr.open(method, url)
            if low in ('xhr',) and prop_name == 'open':
                return ('GET', 'xhr')
            # angular http.request('POST', url, options)
            if prop_name == 'request' and (low.endswith('http') or low == '$http'):
                return ('GET', 'http')
            return None

        if low == 'fetch':
            return (prop_name.upper(), 'fetch')
        if low == 'axios':
            return (prop_name.upper(), 'axios')
        if low == 'xhr':
            return (prop_name.upper(), 'xhr')
        if low.endswith('http') or low == '$http':
            return (prop_name.upper(), 'http')
        if low and low in self.client_roots:
            return (prop_name.upper(), 'http')
        return None

    # ----------------------------------------------------------------
    def _build_request(self, node: Dict, source_url: str, func: str) -> Optional[RequestIR]:
        callee = node.get('callee', {})
        args = node.get('arguments', [])
        parsed = self._callee_method(callee)
        if not parsed:
            return None
        method, kind = parsed
        if method == 'WS':
            req = self._build_ws(args, source_url, func, node)
            return req
        req = RequestIR(method=method, line=node.get('loc', {}).get('start', {}).get('line', 0) or 0,
                        function=func)

        url_node = None
        options_node = None

        if kind == 'fetch':
            if args:
                url_node = args[0]
            if len(args) >= 2:
                options_node = args[1]
            if options_node and options_node.get('type') == 'ObjectExpression':
                for p in options_node.get('properties', []):
                    k = _expr_value(p.get('key', {}))
                    kl = k.lower()
                    val = p.get('value', {})
                    if kl == 'method' and val.get('type') == 'Literal':
                        req.method = str(val.get('value') or req.method).upper()
                    elif kl == 'headers':
                        req.headers.update(_parse_headers_obj(val))
                    elif kl == 'credentials' and val.get('type') == 'Literal':
                        if str(val.get('value')) == 'include':
                            req.headers.setdefault('credentials', 'include')
                    elif kl == 'body':
                        fields, ct = _parse_body_node(val)
                        req.body_fields.update(fields)
                        if ct:
                            req.content_type = ct
                    elif kl == 'body' or kl == 'data':
                        fields, ct = _parse_body_node(val)
                        req.body_fields.update(fields)
                        if ct:
                            req.content_type = ct
        elif kind == 'axios':
            # axios.get(url, config)  |  axios.request({url, method, ...})
            if (callee.get('property', {}) or {}).get('type') in ('Identifier', 'Literal') and \
                    _expr_value(callee.get('property', {})) == 'request':
                if args and args[0].get('type') == 'ObjectExpression':
                    for p in args[0].get('properties', []):
                        k = _expr_value(p.get('key', {}))
                        kl = k.lower()
                        val = p.get('value', {})
                        if kl == 'url':
                            url_node = val
                        elif kl == 'method' and val.get('type') == 'Literal':
                            req.method = str(val.get('value') or req.method).upper()
                        elif kl == 'headers':
                            req.headers.update(_parse_headers_obj(val))
                        elif kl in ('data', 'body'):
                            fields, ct = _parse_body_node(val)
                            req.body_fields.update(fields)
                            if ct:
                                req.content_type = ct
            else:
                if args:
                    url_node = args[0]
                if len(args) >= 2 and args[1].get('type') == 'ObjectExpression':
                    self._apply_options(req, args[1])
        elif kind == 'http':
            # Angular: this.http.get(url, options) | http.request('POST', url, options)
            prop = _expr_value(callee.get('property', {}))
            if prop == 'request' and args:
                # request('POST', url, options) or request(url, options)
                if args[0].get('type') == 'Literal':
                    req.method = str(args[0].get('value')).upper()
                    url_node = args[1] if len(args) >= 2 else None
                    options_node = args[2] if len(args) >= 3 else None
                else:
                    url_node = args[0]
                    options_node = args[1] if len(args) >= 2 else None
            else:
                if args:
                    url_node = args[0]
                # Angular post/put/patch: (url, body[, options]); get/delete: (url[, options])
                body = None
                if len(args) >= 3:
                    body = args[1]
                    options_node = args[2] if args[2].get('type') == 'ObjectExpression' else None
                elif len(args) >= 2:
                    a1 = args[1]
                    if method in ('POST', 'PUT', 'PATCH') and a1.get('type') != 'ObjectExpression':
                        body = a1
                    else:
                        options_node = a1 if a1.get('type') == 'ObjectExpression' else None
                if body is not None:
                    fields, ct = _parse_body_node(body)
                    req.body_fields.update(fields)
                    if ct:
                        req.content_type = ct
            if options_node and options_node.get('type') == 'ObjectExpression':
                self._apply_options(req, options_node)
        elif kind == 'jquery':
            if args:
                # $.ajax({url, method}) vs $.get(url)
                if args[0].get('type') == 'ObjectExpression':
                    for p in args[0].get('properties', []):
                        k = _expr_value(p.get('key', {})).lower()
                        val = p.get('value', {})
                        if k == 'url':
                            url_node = val
                        elif k == 'method' and val.get('type') == 'Literal':
                            req.method = str(val.get('value')).upper()
                        elif k == 'headers':
                            req.headers.update(_parse_headers_obj(val))
                        elif k in ('data', 'body'):
                            fields, ct = _parse_body_node(val)
                            req.body_fields.update(fields)
                            if ct:
                                req.content_type = ct
                else:
                    url_node = args[0]
                    if len(args) >= 2:
                        options_node = args[1]
            if options_node and options_node.get('type') == 'ObjectExpression':
                self._apply_options(req, options_node)
        elif kind == 'xhr':
            # xhr.open(method, url)
            if args:
                if args[0].get('type') == 'Literal':
                    req.method = str(args[0].get('value')).upper()
                if len(args) >= 2:
                    url_node = args[1]

        if url_node is None:
            return None
        info = _build_url(url_node, source_url)
        if info is None:
            return None
        req.url_template = info['template']
        req.url = info['url']
        req.canonical_path = info['canonical']
        req.path_params = info['path_params']
        req.query_params.update(info['query'])
        for p, v in info['query'].items():
            req.params.append(_expr_to_param(p, 'query'))
        for p in info['path_params']:
            req.params.append(_expr_to_param(p, 'path'))

        # headers-derived content type
        for k, v in req.headers.items():
            if k.lower() == 'content-type':
                req.content_type = _trim_string(v)

        # auth
        if 'credentials' in req.headers:
            req.auth_type = req.auth_type or 'cookie'
            req.auth_source = req.auth_source or 'credentials:include'
        if 'withcredentials' in {k.lower() for k in req.headers}:
            req.auth_type = req.auth_type or 'cookie'
            req.auth_source = req.auth_source or 'withCredentials'
        at, asrc = _detect_auth(req.headers)
        if at:
            req.auth_type = at
            req.auth_source = asrc
        # oauth-ish fields in body or query = auth architecture
        for f in list(req.body_fields) + list(req.query_params):
            fl = f.lower()
            if fl in ('client_id', 'client_id', 'clientid'):
                req.auth_type = req.auth_type or 'oauth'
            if fl in ('client_secret', 'clientsecret'):
                req.auth_type = req.auth_type or 'oauth_client_secret'
        # file upload body
        if req.content_type == 'multipart/form-data' or any(
                f.lower() in _UPLOAD_FIELD for f in req.body_fields):
            req.file_upload = True
        # default content type guess
        if not req.content_type and req.body_fields:
            req.content_type = 'application/json'

        # raw snippet for context
        req.raw = re.sub(r'\s+', ' ', node_to_string(node))[:200]
        return req

    def _build_ws(self, args: List, source_url: str, func: str, node: Dict) -> Optional[RequestIR]:
        if not args:
            return None
        req = RequestIR(method='WS', line=node.get('loc', {}).get('start', {}).get('line', 0) or 0,
                        function=func)
        req.websocket = True
        info = _build_url(args[0], source_url)
        if info is None:
            return None
        req.url_template = info['template']
        req.url = info['url']
        req.canonical_path = info['canonical']
        if info['url']:
            scheme = urlsplit(info['url']).scheme
            if scheme in ('http', 'https'):
                req.url = req.url.replace('http', 'ws', 1)
        req.raw = re.sub(r'\s+', ' ', node_to_string(node))[:200]
        return req

    def _build_other(self, node: Dict, source_url: str, func: str) -> Optional[RequestIR]:
        """Modern non-verb endpoint forms: dynamic import(), importScripts(),
        serviceWorker.register, EventSource, sendBeacon, new Request,
        window/self.fetch, axios.create({baseURL})."""
        callee = node.get('callee', {})
        args = node.get('arguments', [])
        t = node.get('type')
        line = node.get('loc', {}).get('start', {}).get('line', 0) or 0

        def _mk(method, idx=0, kind=''):
            if not args or idx >= len(args):
                return None
            req = RequestIR(method=method, line=line, function=func)
            info = _build_url(args[idx], source_url)
            if info is None:
                return None
            req.url_template = info['template']
            req.url = info['url']
            req.canonical_path = info['canonical']
            req.path_params = info['path_params']
            req.raw = re.sub(r'\s+', ' ', node_to_string(node))[:200]
            return req

        # dynamic import('chunk.js')  (callee type is 'Import', not Identifier)
        if t == 'CallExpression' and callee.get('type') == 'Import':
            return _mk('GET', 0, 'dynamic_import')
        if t == 'CallExpression' and callee.get('type') == 'Identifier' and callee.get('name') == 'import':
            return _mk('GET', 0, 'dynamic_import')
        if t == 'CallExpression' and callee.get('type') == 'Identifier' and callee.get('name') == 'importScripts':
            return _mk('GET', 0, 'import_scripts')
        if t == 'NewExpression':
            cname = callee.get('name') if callee.get('type') == 'Identifier' else ''
            if cname == 'WebSocket':
                return self._build_ws(args, source_url, func, node)
            if cname == 'EventSource':
                return _mk('GET', 0, 'event_stream')
            if cname == 'Request':
                req = _mk('GET', 0, 'request_init')
                # new Request(url, {method})
                if req and len(args) >= 2 and args[1].get('type') == 'ObjectExpression':
                    for p in args[1].get('properties', []):
                        if _expr_value(p.get('key', {})).lower() == 'method' and \
                                p.get('value', {}).get('type') == 'Literal':
                            req.method = str(p['value'].get('value') or req.method).upper()
                return req
            return None
        if t != 'CallExpression':
            return None
        # serviceWorker.register(url)
        if callee.get('type') == 'MemberExpression':
            prop = _expr_value(callee.get('property', {}))
            obj = _expr_value(callee.get('object', {}))
            if prop == 'register' and 'serviceWorker' in obj:
                return _mk('GET', 0, 'service_worker')
            if prop == 'sendBeacon' and obj == 'navigator':
                return _mk('POST', 0, 'beacon')
            if prop == 'fetch' and obj in ('window', 'self'):
                req = _mk('GET', 0, 'fetch')
                if req and len(args) >= 2 and args[1].get('type') == 'ObjectExpression':
                    self._apply_options(req, args[1])
                return req
            if prop == 'create' and obj == 'axios' and args:
                # axios.create({baseURL}) records the API root
                if args[0].get('type') == 'ObjectExpression':
                    for p in args[0].get('properties', []):
                        if _expr_value(p.get('key', {})).lower() == 'baseurl':
                            base = p.get('value', {})
                            req = RequestIR(method='GET', line=line, function=func)
                            info = _build_url(base, source_url)
                            if info is None:
                                continue
                            req.url_template = info.get('template', '')
                            req.url = info.get('url', '')
                            req.canonical_path = info.get('canonical', '')
                            req.raw = re.sub(r'\s+', ' ', node_to_string(node))[:200]
                            return req
        return None

    def _apply_options(self, req: RequestIR, options_node: Dict) -> None:
        for p in options_node.get('properties', []):
            k = _expr_value(p.get('key', {}))
            kl = k.lower()
            val = p.get('value', {})
            if kl in ('headers',):
                req.headers.update(_parse_headers_obj(val))
            elif kl in ('data', 'body', 'json', 'params'):
                fields, ct = _parse_body_node(val)
                req.body_fields.update(fields)
                if ct:
                    req.content_type = ct
                elif kl == 'json' and val.get('type') in ('ObjectExpression', 'Identifier'):
                    req.content_type = req.content_type or 'application/json'
                elif kl == 'params':
                    if val.get('type') == 'ObjectExpression':
                        for p2 in val.get('properties', []):
                            k2 = _expr_value(p2.get('key', {}))
                            if k2:
                                req.query_params[k2] = _expr_value(p2.get('value', {}))
                                req.params.append(_expr_to_param(k2, 'query'))
            elif kl in ('withcredentials',) and val.get('type') == 'Literal' and val.get('value'):
                req.headers.setdefault('withCredentials', 'true')
            elif kl in ('observe', 'responseType', 'response_type'):
                pass
            elif kl == 'method' and val.get('type') == 'Literal':
                req.method = str(val.get('value') or req.method).upper()

    # ----------------------------------------------------------------
    # FormData / upload detection (file level)
    # ----------------------------------------------------------------
    def _scan_formdata(self, code: str) -> Dict[str, Any]:
        has_formdata = bool(re.search(r'new\s+FormData\s*\(', code))
        upload_fields = re.findall(r'(?:form|fd|upload|data)\s*\.append\s*\(\s*[\'"]([^\'"]+)[\'"]',
                                   code, re.I)
        return {'has_formdata': has_formdata, 'upload_fields': list(dict.fromkeys(upload_fields))}

    # ----------------------------------------------------------------
    def extract(self, code: str, source_url: str) -> Dict[str, Any]:
        """Primary entry: return {'requests': [RequestIR.to_dict...],
                                  'formdata': {...}}"""
        if not HAS_ESPRIMA or not code:
            return {'requests': [], 'formdata': {'has_formdata': False, 'upload_fields': []}}
        try:
            ast = esprima.parseModule(code)
        except Exception:
            try:
                ast = esprima.parseScript(code)
            except Exception:
                return {'requests': [], 'formdata': self._scan_formdata(code)}

        root = ast.toDict()
        requests: List[RequestIR] = []
        func_stack: List[str] = []

        def walk(node):
            if node is None:
                return
            if isinstance(node, list):
                for n in node:
                    walk(n)
                return
            if not isinstance(node, dict):
                return
            t = node.get('type', '')
            if t in ('FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression',
                     'MethodDefinition'):
                name = ''
                if t == 'FunctionDeclaration':
                    name = _expr_value(node.get('id', {})) or '(anonymous)'
                elif t == 'MethodDefinition':
                    name = _expr_value(node.get('key', {})) or '(method)'
                idn = node.get('id', {})
                if name == '' and idn:
                    name = _expr_value(idn)
                func_stack.append(name or '(anonymous)')
                if t == 'MethodDefinition':
                    # esprima stores the function under 'value' (FunctionExpression)
                    value = node.get('value', {})
                    for k in ('params', 'body'):
                        walk(value.get(k))
                else:
                    for k in ('params', 'body'):
                        walk(node.get(k))
                if func_stack:
                    func_stack.pop()
                return
            if t == 'CallExpression':
                func = func_stack[-1] if func_stack else ''
                req = self._build_other(node, source_url, func)
                if req is not None:
                    requests.append(req)
                else:
                    req = self._build_request(node, source_url, func)
                    if req is not None:
                        requests.append(req)
                for a in node.get('arguments', []):
                    walk(a)
                walk(node.get('callee'))
                return
            if t == 'NewExpression':
                # new WebSocket(url) / new EventSource(url) / new Request(url)
                callee = node.get('callee', {})
                if isinstance(callee, dict) and callee.get('type') == 'Identifier':
                    func = func_stack[-1] if func_stack else ''
                    req = self._build_other(node, source_url, func)
                    if req is not None:
                        requests.append(req)
                for v in node.values():
                    walk(v)
                return
            for v in node.values():
                walk(v)

        walk(root)

        # dedupe on (method, url_template)
        seen = set()
        out = []
        for r in requests:
            key = (r.method, r.url_template or r.url, r.line)
            if key in seen:
                continue
            seen.add(key)
            out.append(r.to_dict())
        return {'requests': out, 'formdata': self._scan_formdata(code)}


def node_to_string(node: Dict) -> str:
    """Crude reconstruction for raw snippet context."""
    t = node.get('type')
    if t == 'Literal':
        return repr(node.get('value'))
    if t == 'Identifier':
        return node.get('name', '')
    if t == 'MemberExpression':
        return f"{_expr_value(node.get('object', {}))}.{_expr_value(node.get('property', {}))}"
    if t == 'CallExpression':
        return _call_str(node)
    if t == 'TemplateLiteral':
        quasis = [q.get('value', {}).get('raw', '') for q in node.get('quasis', [])]
        exprs = [node_to_string(e) for e in node.get('expressions', [])]
        pieces = []
        for i, q in enumerate(quasis):
            pieces.append(q)
            if i < len(exprs):
                pieces.append(f'${{{exprs[i]}}}')
        return ''.join(pieces)
    if t == 'ObjectExpression':
        props = []
        for p in node.get('properties', []):
            props.append(f"{_expr_value(p.get('key', {}))}: {node_to_string(p.get('value', {}))}")
        return '{' + ', '.join(props) + '}'
    return f'[{t}]'
