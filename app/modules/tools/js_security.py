"""js_security.py

Aggregate security-intelligence layer (Phases 2-3 of the review roadmap).

Pure functions over the normalized endpoint IR produced by js_semantic:
  - classify_endpoint: object/tenant/sensitive/SSRF/upload classification,
    security_signals + interest_score (evidence, not keyword excitement)
  - oauth_analysis: OAuth flow classification + client_secret exposure
  - jwt_correlation: decode + correlate JWT claims to endpoints/hosts
  - service_graph: host graph + auth relationships
"""

import re
import time
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# ---- object identifier / tenant / sensitive classifiers -------------------
_OBJ_IDENTIFIER = ('id', 'userid', 'user_id', 'accountid', 'account_id',
                   'clientid', 'customerid', 'customer_id', 'invoiceid',
                   'invoice_id', 'documentid', 'document_id', 'fileid',
                   'file_id', 'orderid', 'order_id', 'ticketid', 'ticket_id',
                   'recordid', 'record_id', 'profileid', 'profile_id',
                   'deviceid', 'device_id', 'paymentid', 'payment_id',
                   'subscriptionid', 'subscription_id', 'messageid', 'memberid',
                   'member_id', 'productid', 'product_id', 'transactionid')
_TENANT_IDENTIFIER = ('tenantid', 'tenant_id', 'organizationid', 'organization_id',
                      'workspaceid', 'workspace_id', 'companyid', 'company_id',
                      'merchantid', 'merchant_id', 'teamid', 'team_id', 'orgid',
                      'org_id', 'subdomain', 'namespace', 'agencyid', 'agency_id',
                      'branchid', 'branch_id', 'storeid', 'store_id', 'tenant',
                      'organization', 'org', 'workspace', 'team', 'company',
                      'merchant', 'store', 'agency', 'branch')
_SSRF_PARAM = ('url', 'uri', 'href', 'link', 'callback', 'redirect',
               'redirect_uri', 'webhook', 'image_url', 'avatar_url', 'proxy',
               'target', 'destination', 'fetch', 'endpoint', 'host', 'domain',
               'callback_url', 'return_url', 'continue', 'next', 'return',
               'page_url', 'download_url', 'file_url', 'video_url', 'source',
               'remote', 'server', 'hostname', 'ip')
_SENSITIVE_FIELD = ('password', 'passwd', 'pwd', 'secret', 'token', 'apikey',
                    'api_key', 'api-key', 'access_token', 'refresh_token',
                    'authorization', 'cookie', 'session', 'ssn', 'ssn_number',
                    'creditcard', 'card_number', 'cvv', 'iban', 'account_number',
                    'private_key', 'client_secret', 'clientsecret', 'secret_key',
                    'accesskey', 'secretkey', 'aws_secret', 'aws_access')
_AMOUNT_FIELD = ('amount', 'price', 'balance', 'total', 'quantity', 'fee',
                 'charge', 'cost', 'salary', 'limit', 'credit', 'discount',
                 'tip', 'rate', 'value', 'amountdue')
_REDIRECT_PATH = re.compile(r'(redirect|return|next|continue|callback|back[-_ ]?to)', re.I)
_OAUTH_PATH = re.compile(r'/oauth[/_-]?(token|authorize|revoke|introspect|userinfo|devicecode|auth)?|/oauth2?/', re.I)
_OAUTH_TOKEN_PATH = re.compile(r'(oauth[^/]*/(token|auth|authorize|revoke|introspect)|/token\b|/auth/token|/api/token)', re.I)
_OIDC_PATH = re.compile(r'\.well-known/openid-configuration|\.well-known/oauth-authorization-server', re.I)
_JWKS_PATH = re.compile(r'\.well-known/jwks\.json|/jwks', re.I)
_GRAPHQL = re.compile(r'(/graphql|/v1/graphql|graphql\s*\()', re.I)
_ADMIN_HINT = re.compile(r'(^|/)(admin|internal|manage|management|dashboard|settings|debug|console|superuser)(/|$)', re.I)
_SSRF_PATH = re.compile(
    r'(fetch|proxy|redirect|callback|webhook|preview|screenshot|render|download|image)',
    re.I,
)

_OAUTH_GRANTS = ('authorization_code', 'client_credentials', 'password',
                 'refresh_token', 'device_code', 'implicit', 'urn:ietf:params')

_PRIV_SCOPES = ('admin', 'write', 'delete', 'manage', 'all', 'user_impersonation',
                'account:write', 'admin:all', '*', 'scope_admin')

JWT_ALG_ORDER = ('none', 'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512',
                 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA')


def classify_param(name: str, kind: str) -> Optional[Dict]:
    """Classify a parameter name -> {class, signal} or None."""
    low = name.strip().lower()
    low = re.sub(r'^(params?\.|data\.|form\.|query\.|path\.)', '', low)
    if not low:
        return None
    cls = None
    if low in _TENANT_IDENTIFIER:
        cls = 'tenant_identifier'
    elif low in _OBJ_IDENTIFIER or low.endswith('id') and low.replace('_id', '').replace('id', '') and len(low) >= 3 and low != 'id':
        if low not in ('uuid', 'guid', 'id'):
            cls = 'object_identifier'
    elif low in ('uuid', 'guid', 'token', 'email', 'phone'):
        cls = 'object_identifier' if low in ('uuid', 'guid') else ('sensitive_field' if low == 'token' else 'identifier')
    elif low in _SSRF_PARAM:
        cls = 'ssrf_parameter'
    elif low in _SENSITIVE_FIELD:
        cls = 'sensitive_field'
    elif low in _AMOUNT_FIELD:
        cls = 'amount_field'
    if not cls:
        return None
    return {'name': name, 'kind': kind, 'class': cls}


def _endpoint_identity(e: Dict) -> str:
    u = e.get('url') or ''
    if not u:
        return e.get('canonical_path') or e.get('url_template') or ''
    return u


def classify_endpoint(e: Dict) -> Dict:
    """Returns enriched copy of endpoint with objects, security_signals,
    interest_score. NEVER touches 'severity' (evidence only)."""
    e = dict(e)
    signals: List[str] = []
    objects: List[Dict] = []
    interest = 0

    url = e.get('url') or ''
    cpath = (e.get('canonical_path') or url).lower()
    method = (e.get('method') or 'GET').upper()

    # --- parameters (path + query + body) ---
    params = e.get('params') or []
    for p in params:
        cl = classify_param(p.get('name', ''), p.get('kind', 'query'))
        if not cl:
            continue
        objects.append(cl)
        cls = cl['class']
        if cls == 'object_identifier':
            signals.append('idor_candidate')
            interest += 22
        elif cls == 'tenant_identifier':
            signals.append('multi_tenant_object_reference')
            interest += 18
        elif cls == 'ssrf_parameter':
            signals.append('ssrf_candidate')
            interest += 14
        elif cls == 'sensitive_field':
            signals.append('sensitive_field')
            interest += 8
        elif cls == 'amount_field':
            signals.append('amount_field')
            interest += 6

    # path-param patterns fallback (for regex-extracted endpoints)
    for pm in (e.get('path_params') or []):
        if isinstance(pm, dict):
            pm = pm.get('name', '')
        cl = classify_param(str(pm), 'path')
        if cl and not any(o.get('name') == pm for o in objects):
            objects.append(cl)
            if cl['class'] == 'object_identifier':
                signals.append('idor_candidate')
                interest += 22
            elif cl['class'] == 'tenant_identifier':
                signals.append('multi_tenant_object_reference')
                interest += 18

    # --- file upload ---
    if e.get('file_upload') or e.get('content_type') == 'multipart/form-data' or \
            isinstance(e.get('body'), dict) and any(
                str(k).lower() in ('file', 'filename', 'upload', 'attachment', 'image', 'avatar')
                for k in e.get('body', {})):
        signals.append('file_upload')
        interest += 12

    # --- SSRF endpoint (param on GET to fetch/proxy-ish path) ---
    if method == 'GET' and any(s == 'ssrf_candidate' for s in signals) and _SSRF_PATH.search(cpath):
        signals.append('server_side_url_fetch_candidate')
        interest += 10

    # --- content type ---
    if e.get('content_type') == 'multipart/form-data':
        signals.append('file_upload')
    if e.get('content_type') == 'application/graphql':
        signals.append('graphql')

    # --- auth architecture ---
    auth = e.get('auth') or {}
    atype = auth.get('type')
    if atype:
        signals.append(f'auth:{atype}')
        interest += 6
    if atype == 'bearer':
        signals.append('authenticated_endpoint')
        interest += 4

    # --- path-based evidence ---
    if _OAUTH_TOKEN_PATH.search(cpath):
        signals.append('oauth_token_endpoint')
        interest += 20
    if _OIDC_PATH.search(cpath):
        signals.append('oidc_discovery')
        interest += 15
    if _JWKS_PATH.search(cpath):
        signals.append('jwks_endpoint')
        interest += 10
    if _GRAPHQL.search(cpath):
        signals.append('graphql')
        interest += 8
    if _ADMIN_HINT.search(cpath) and method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        signals.append('admin_action')
        interest += 10
    if 'redirect' in cpath or any(p.get('name', '').lower() in ('redirect', 'redirect_uri', 'return', 'returnurl', 'next', 'continue', 'callback', 'url') for p in (e.get('params') or [])):
        signals.append('open_redirect_candidate')
        interest += 8

    # dedupe signals, keep order
    seen = set()
    signals = [s for s in signals if not (s in seen or seen.add(s))]

    e['objects'] = objects
    e['security_signals'] = signals
    e['interest_score'] = min(100, interest)
    return e


# ======================================================================
# OAUTH analysis
# ======================================================================
_OAUTH_KEYS = ('client_id', 'client_secret', 'audience', 'scope',
               'redirect_uri', 'grant_type', 'response_type',
               'code_challenge', 'code_challenge_method', 'refresh_token',
               'authorization_code', 'code', 'device_code', 'resource')


def oauth_analysis(endpoints: List[Dict]) -> List[Dict]:
    """Identify OAuth endpoints and classify flows + exposed client secrets."""
    clients: List[Dict] = []
    seen = set()
    for e in endpoints:
        url = e.get('url') or ''
        cpath = ((e.get('canonical_path') or e.get('url_template') or url)).lower()
        if not _OAUTH_PATH.search(cpath) and not _OAUTH_TOKEN_PATH.search(cpath):
            continue
        host = urlsplit(url).netloc if url else e.get('host', '')
        fields = {}
        for col in ('body', 'query_params'):
            for k, v in (e.get(col) or {}).items():
                fields[k.lower()] = v
        for p in (e.get('params') or []):
            fields.setdefault(p.get('name', '').lower(), p.get('source', 'variable'))
        payload = {k: fields.get(k) for k in _OAUTH_KEYS if k in fields}
        grant = None
        for key in ('grant_type',):
            gv = fields.get(key, '')
            if gv and gv.lower() in _OAUTH_GRANTS:
                grant = gv.lower()
        if not grant:
            hint = url.lower()
            if 'authorize' in hint:
                grant = 'authorization_code (assumed: authorize endpoint)'
            elif 'token' in hint:
                grant = 'unknown (token endpoint)'
        exposure = None
        if 'client_secret' in fields:
            component = 'body' if 'client_secret' in (e.get('body') or {}) else 'query'
            exposure = {'component': component, 'value': None}
        key = (host, e.get('method', ''), e.get('url') or e.get('url_template', ''))
        if key in seen:
            continue
        seen.add(key)
        clients.append({
            'host': host,
            'endpoint': e.get('url') or e.get('url_template', ''),
            'method': e.get('method', 'POST'),
            'grant_type': grant or 'unknown',
            'client_id': payload.get('client_id'),
            'client_secret_exposed': bool(exposure),
            'secret_component': exposure['component'] if exposure else '',
            'audience': payload.get('audience') or fields.get('aud'),
            'scopes': [s.strip() for s in (payload.get('scope') or '').split() if s.strip()],
            'redirect_uri': payload.get('redirect_uri'),
            'pkce': bool(fields.get('code_challenge')),
            'source': {'file': e.get('source_url', ''), 'line': e.get('line', 0)},
        })
    return clients


# ======================================================================
# JWT correlation
# ======================================================================
def _b64u(s: str) -> bytes:
    import base64
    s = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> Optional[Dict]:
    if token.count('.') != 2:
        return None
    try:
        header, payload, _sig = token.split('.')
        h = json_safe_loads(_b64u(header).decode('utf-8', 'ignore'))
        p = json_safe_loads(_b64u(payload).decode('utf-8', 'ignore'))
    except Exception:
        return None
    if not isinstance(h, dict) or not isinstance(p, dict):
        return None
    return {'header': h, 'payload': p, 'alg': h.get('alg'), 'kid': h.get('kid'),
            'iss': p.get('iss'), 'aud': p.get('aud'), 'sub': p.get('sub'),
            'exp': p.get('exp'), 'scope': p.get('scope'), 'permissions': p.get('permissions'),
            'roles': p.get('roles'), 'azp': p.get('azp'), 'client_id': p.get('client_id'),
            'claims': p}


def json_safe_loads(s) -> Optional[Any]:
    import json
    try:
        return json.loads(s)
    except Exception:
        return None


def _flags_for_jwt(d: Dict, now: float) -> List[str]:
    flags = []
    alg = str(d.get('alg') or '').upper()
    if not alg:
        alg = 'unknown'
    if alg.lower() == 'none':
        flags.append('alg:none')
    if alg in ('HS256', 'HS384', 'HS512'):
        flags.append(f'symmetric_signature:{alg} (offline-crackable if key weak)')
    exp = d.get('exp')
    if isinstance(exp, (int, float)):
        if exp < now:
            flags.append('expired')
        elif exp - now > 86400 * 365:
            flags.append('long_lived_1yr+')
        elif exp - now > 86400:
            flags.append('long_lived_24h+')
    aud = d.get('aud')
    if isinstance(aud, str) and ('*' in aud or aud.lower() == 'any'):
        flags.append('wildcard_audience')
    scope = d.get('scope') or ''
    perms = d.get('permissions') or []
    roles = d.get('roles') or []
    privs = []
    if isinstance(scope, str):
        privs += [s for s in scope.split() if s.lower() in _PRIV_SCOPES]
    if isinstance(perms, list):
        privs += [str(x) for x in perms if str(x).lower() in _PRIV_SCOPES]
    if isinstance(roles, list):
        privs += [str(x) for x in roles if str(x).lower() in ('admin', 'superadmin', 'root', 'owner')]
    if privs:
        flags.append(f'privileged_claim:{",".join(privs)[:80]}')
    if not exp:
        flags.append('no_exp')
    return flags


def jwt_correlation(jwts: List[Dict], endpoints: List[Dict]) -> List[Dict]:
    """Correlate decoded JWT claims to endpoint hosts."""
    now = time.time()
    out = []
    hosts = sorted({urlsplit((e.get('url') or '')).netloc for e in endpoints
                    if (e.get('url') or '').startswith('http')})
    for j in jwts:
        token = j.get('token') or j.get('token_preview') or j.get('value') or ''
        if isinstance(token, str) and token.count('.') == 2 and len(token) > 60:
            d = decode_jwt(token)
        else:
            # _detect_jwts stores full token sometimes; fall back to raw scan
            d = j.get('decoded') or (decode_jwt(token) if token.count('.') == 2 else None)
        if not d:
            continue
        flags = _flags_for_jwt(d, now)
        aud = d.get('aud')
        iss = d.get('iss') or ''
        related = []
        if isinstance(aud, str):
            for h in hosts:
                if (aud in h) or (h in aud) or (aud == f'https://{h}'):
                    related.append(h)
        iss_host = urlsplit(iss).netloc if iss.startswith(('http', 'https')) else ''
        if iss_host and iss_host in hosts and iss_host not in related:
            related.append(iss_host)
        out.append({
            'alg': d.get('alg') or d.get('header', {}).get('alg', 'unknown'),
            'issuer': iss,
            'audience': aud,
            'subject': d.get('sub'),
            'azp': d.get('azp'),
            'scopes': d.get('scope') or '',
            'flags': flags,
            'related_hosts': ','.join(related),
            'source': j.get('source', ''),
            'severity_evidence': flags,
        })
    return out


# ======================================================================
# Service graph
# ======================================================================
def service_graph(endpoints: List[Dict], jwts: List[Dict] = None,
                  oauth_clients: List[Dict] = None) -> Dict:
    """host graph + auth relationships derived from endpoint IR."""
    jwts = jwts or []
    oauth_clients = oauth_clients or []
    hosts: Dict[str, Dict] = {}
    edges = []

    def _host(u: str) -> Optional[str]:
        if not u or not u.startswith('http'):
            return None
        return urlsplit(u).netloc

    for e in endpoints:
        ehost = _host(e.get('url'))
        src_host = _host(e.get('source_url'))
        if not ehost:
            continue
        h = hosts.setdefault(ehost, {'host': ehost, 'endpoints': 0, 'oauth': [], 'accepts': [],
                                     'referenced_by': set()})
        h['endpoints'] += 1
        if (e.get('security_signals') or []):
            for s in (e.get('security_signals') or []):
                if s.startswith('auth:') and s not in h['accepts']:
                    h['accepts'].append(s)
                if s in ('oauth_token_endpoint', 'oidc_discovery') and s not in h['oauth']:
                    h['oauth'].append(s)
        if src_host and src_host != ehost:
            h['referenced_by'].add(src_host)
            edges.append({'from': src_host, 'to': ehost, 'kind': 'references'})

    for o in oauth_clients:
        h = hosts.setdefault(o.get('host', ''), {'host': o.get('host', ''), 'endpoints': 0,
                                                 'oauth': [], 'accepts': [], 'referenced_by': set()})
        g = o.get('grant_type', '')
        if g and g not in h['oauth']:
            h['oauth'].append(f'{o.get("method","POST")} {o.get("endpoint","")} [{g}]')
        if o.get('client_secret_exposed'):
            h['_client_secret_exposed'] = True

    # auth relationships: oauth-issuing hosts feed bearer-accepting hosts
    auth_rels = []
    for e in endpoints:
        src = _host(e.get('source_url'))
        ehost = _host(e.get('url'))
        auth = (e.get('auth') or {})
        if src and ehost and src != ehost:
            auth_rels.append({'from': src, 'to': ehost, 'via': e.get('method', 'GET'),
                              'auth': (auth.get('type') or '') +
                              (f':{auth.get("source")}' if auth.get('source') else '')})
        if (e.get('security_signals') or '') and isinstance(e.get('security_signals'), list):
            pass

    return {
        'hosts': sorted(hosts.values(), key=lambda h: -h['endpoints']),
        'edges': edges,
        'auth_relationships': auth_rels,
    }
