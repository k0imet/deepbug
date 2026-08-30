"""
oauth_oidc_auditor.py — OAuth/OIDC discovery-doc auditor.

Fetches /.well-known/openid-configuration (plus RFC 8414 and common fallbacks)
for each host and flags risky or interesting configurations:

  * password grant (ROPG) enabled            -> credential-stuffing surface
  * implicit response types (token/id_token) -> token-in-browser history
  * dynamic client registration_endpoint     -> open client enrollment
  * issuer/host mismatch                     -> multi-tenant / legacy infra intel
  * high-value scopes (admin, sso, offline, write)
  * IdP fingerprint (Okta, Auth0, Keycloak, Ping, Azure AD, custom)

Read-only: discovery documents are public by design. No token requests.

Config keys (under `oauth_audit.*`):
  timeout: per-request timeout (default 8)
  max_hosts: cap on hosts audited (default 200)
"""

import asyncio
import json
from typing import Dict, List, Any
from urllib.parse import urlparse

import aiohttp

from app.utils.logger import get_logger

logger = get_logger()

DISCOVERY_PATHS = [
    '/.well-known/openid-configuration',
    '/.well-known/oauth-authorization-server',
    '/oauth/.well-known/openid-configuration',
    '/oauth2/default/.well-known/openid-configuration',
]

IDP_FINGERPRINTS = [
    ('Okta', ['okta_post_message', '/oauth2/v1/', 'okta.com']),
    ('Auth0', ['auth0.com', 'auth0Client', 'mfa-otp']),
    ('Keycloak', ['keycloak', 'realm']),
    ('Ping', ['pingidentity', 'pf.wsfed']),
    ('Azure AD', ['login.microsoftonline.com', 'sts.windows.net']),
    ('Gigya/SAP CDC', ['gigya', 'webSdkBootstrap']),
]

HIGH_VALUE_SCOPES = {'admin', 'sso', 'offline_access', 'offline', 'write',
                     'root', 'internal', 'test', 'sensitive', 'impersonate'}

RISKY_GRANTS = {'password': 'ROPG enabled — credential stuffing surface',
                'urn:ietf:params:oauth:grant-type:device_code':
                    'Device code flow — phishing/CFP abuse surface',
                'client_credentials': 'Client credentials grant advertised'}


class OAuthOIDCAuditor:
    """Audit OIDC/OAuth discovery documents for risky configuration."""

    def __init__(self, config: Dict):
        cfg = (config or {}).get('oauth_audit', {})
        self.timeout = int(cfg.get('timeout', 8))
        self.max_hosts = int(cfg.get('max_hosts', 200))

    async def _fetch_doc(self, session, sem, url) -> Dict:
        try:
            async with sem:
                async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True) as r:
                    if r.status != 200:
                        return {}
                    ct = r.headers.get('Content-Type', '')
                    if 'json' not in ct and 'javascript' not in ct:
                        return {}
                    return json.loads(await r.text(errors='ignore'))
        except Exception:
            return {}

    def _analyze(self, doc: Dict, host: str, url: str) -> List[Dict]:
        findings = []
        if not isinstance(doc, dict) or 'issuer' not in doc:
            return findings

        grants = doc.get('grant_types_supported') or []
        rtypes = doc.get('response_types_supported') or []
        scopes = doc.get('scopes_supported') or []
        issuer = doc.get('issuer', '')

        idp = next((name for name, sigs in IDP_FINGERPRINTS
                    if any(s in json.dumps(doc)[:4000] for s in sigs)),
                   'custom')

        for g in grants:
            if g in RISKY_GRANTS:
                findings.append({
                    'host': host, 'url': url, 'kind': 'risky_grant',
                    'detail': f'{g}: {RISKY_GRANTS[g]}', 'idp': idp,
                    'issuer': issuer,
                })
        for rt in rtypes:
            if 'token' == rt or rt.endswith(' token'):
                findings.append({
                    'host': host, 'url': url, 'kind': 'implicit_flow',
                    'detail': f'implicit response type "{rt}" enabled',
                    'idp': idp, 'issuer': issuer,
                })
                break
        if doc.get('registration_endpoint'):
            findings.append({
                'host': host, 'url': url, 'kind': 'dynamic_registration',
                'detail': f"registration_endpoint exposed: "
                          f"{doc['registration_endpoint']}",
                'idp': idp, 'issuer': issuer,
            })
        try:
            iss_host = urlparse(issuer).netloc
        except Exception:
            iss_host = ''
        if iss_host and iss_host != host:
            findings.append({
                'host': host, 'url': url, 'kind': 'issuer_mismatch',
                'detail': f'issuer "{issuer}" does not match audited host '
                          f'(multi-brand/legacy infra)',
                'idp': idp, 'issuer': issuer,
            })
        hot = sorted(s for s in scopes
                     if any(k in s.lower() for k in HIGH_VALUE_SCOPES))
        if hot:
            findings.append({
                'host': host, 'url': url, 'kind': 'high_value_scopes',
                'detail': f'scopes of interest: {", ".join(hot[:10])}',
                'idp': idp, 'issuer': issuer,
            })
        if not findings:
            findings.append({
                'host': host, 'url': url, 'kind': 'info',
                'detail': f'{idp} discovery doc (no risky defaults found)',
                'idp': idp, 'issuer': issuer,
            })
        return findings

    async def audit_host(self, session, sem, host: str,
                         out: List[Dict]) -> None:
        base = f'https://{host}'
        for path in DISCOVERY_PATHS:
            doc = await self._fetch_doc(session, sem, base + path)
            if doc:
                out.extend(self._analyze(doc, host, base + path))
                return

    async def scan(self, hosts: List[str]) -> Dict[str, Any]:
        hosts = [h.split('/')[0] for h in hosts][:self.max_hosts]
        results: List[Dict] = []
        sem = asyncio.Semaphore(20)
        conn = aiohttp.TCPConnector(limit=30, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            await asyncio.gather(
                *(self.audit_host(session, sem, h, results) for h in hosts))
        summary = {}
        for f in results:
            summary[f['kind']] = summary.get(f['kind'], 0) + 1
        return {'findings': results, 'summary': summary,
                'hosts_audited': len(hosts)}
