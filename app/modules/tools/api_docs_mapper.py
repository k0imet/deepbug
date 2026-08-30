"""
api_docs_mapper.py — API documentation / schema exposure mapper.

Probes hosts for publicly reachable API definition artifacts and live docs UIs:

  /openapi.json /swagger.json /api-docs /v2/swagger.json /v3/api-docs
  /swagger/v1/swagger.json /api/openapi.json /doc/openapi.json
  GraphQL endpoints (/graphql — bare-GET liveness check), Swagger UI, Redoc

When an OpenAPI/Swagger document is found it is parsed and the endpoint
inventory (method + path + security requirements) is returned so the results
can feed the Vulnerability Scanner URL sources and shadow-API triage.

Read-only: GET requests only.

Config keys (under `api_docs.*`):
  timeout: per-request timeout (default 8)
  max_hosts: cap on hosts probed (default 200)
  max_paths_per_doc: endpoint rows extracted per doc (default 200)
"""

import asyncio
import json
from typing import Dict, List, Any

import aiohttp

from app.utils.logger import get_logger

logger = get_logger()

DOC_PATHS = [
    '/openapi.json', '/swagger.json', '/api-docs', '/v2/swagger.json',
    '/v3/api-docs', '/swagger/v1/swagger.json', '/api/openapi.json',
    '/doc/openapi.json', '/api/v1/openapi.json',
]
UI_PATHS = ['/swagger/', '/swagger-ui/', '/swagger-ui.html', '/redoc/',
            '/api-docs/ui']
# Canonical GraphQL HTTP endpoint. A bare GET typically answers
# "Must provide query string" (400) — a safe, distinctive liveness marker.
GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql']
GRAPHQL_MARKERS = ('must provide query', 'graphql', '"errors"',
                   'operationname', 'querystring')

INTERESTING_PATH_RE = ('admin', 'internal', 'debug', 'user', 'account',
                       'token', 'password', 'secret', 'key', 'export',
                       'report', 'invoice', 'payment')


class APIDocsMapper:
    """Discover exposed API docs and extract endpoint inventories."""

    def __init__(self, config: Dict):
        cfg = (config or {}).get('api_docs', {})
        self.timeout = int(cfg.get('timeout', 8))
        self.max_hosts = int(cfg.get('max_hosts', 200))
        self.max_paths = int(cfg.get('max_paths_per_doc', 200))
        self.concurrency = int(cfg.get('concurrency', 60))

    async def _get(self, session, sem, url) -> tuple:
        try:
            async with sem:
                async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False) as r:
                    if r.status != 200:
                        return r.status, '', ''
                    body = await r.text(errors='ignore')
                    return r.status, r.headers.get('Content-Type', ''), body
        except Exception:
            return -1, '', ''

    def _parse_openapi(self, doc: Dict, url: str, host: str) -> Dict:
        paths = doc.get('paths') or {}
        endpoints = []
        for p, ops in list(paths.items())[:self.max_paths]:
            for method, op in ops.items():
                if method.lower() not in ('get', 'post', 'put', 'patch',
                                          'delete'):
                    continue
                if not isinstance(op, dict):
                    continue
                sec = op.get('security') is not None or bool(doc.get('security'))
                hot = any(k in p.lower() for k in INTERESTING_PATH_RE)
                endpoints.append({
                    'method': method.upper(), 'path': p,
                    'operation_id': op.get('operationId', ''),
                    'requires_auth': sec, 'interesting': hot,
                })
        servers = doc.get('servers') or []
        base = servers[0].get('url', '') if servers else ''
        return {
            'host': host, 'kind': 'openapi_doc', 'url': url,
            'title': doc.get('info', {}).get('title', ''),
            'version': doc.get('info', {}).get('version', ''),
            'base_url': base,
            'endpoint_count': len(paths),
            'endpoints': endpoints,
            'interesting_count': sum(1 for e in endpoints if e['interesting']),
            'unauth_count': sum(1 for e in endpoints if not e['requires_auth']),
        }

    async def probe_host(self, session, sem, host: str,
                         out: List[Dict]) -> None:
        for scheme in ('https',):
            base = f'{scheme}://{host}'
            for path in DOC_PATHS:
                status, ct, body = await self._get(session, sem, base + path)
                if status != 200:
                    continue
                if body.lstrip()[:1] != '{':
                    continue
                try:
                    doc = json.loads(body)
                except Exception:
                    continue
                if isinstance(doc.get('paths'), dict):
                    out.append(self._parse_openapi(doc, base + path, host))
                    break
            for path in UI_PATHS:
                status, ct, body = await self._get(session, sem, base + path)
                low = body[:4000].lower()
                marker = ('swagger ui' if 'swagger' in path else 'redoc')
                # require real docs-UI markers in the body — SPA fallbacks
                # return 200 + HTML for every path and must not count
                sig = ('swagger-ui' in low or 'swaggeruibundle' in low
                       or ('redoc' in path and 'redoc' in low))
                if status == 200 and sig:
                    out.append({'host': host, 'kind': 'docs_ui', 'url': base + path,
                                'detail': f'{marker.title()} reachable'})
                    break
            for path in GRAPHQL_PATHS:
                status, ct, body = await self._get(session, sem, base + path)
                low = body[:500].lower()
                if status in (200, 400, 405) and any(m in low for m in GRAPHQL_MARKERS):
                    out.append({'host': host, 'kind': 'graphql_endpoint',
                                'url': base + path,
                                'detail': f'live GraphQL endpoint '
                                          f'(HTTP {status} on bare GET)'})
                    break

    async def scan(self, hosts: List[str]) -> Dict[str, Any]:
        hosts = [h.split('/')[0] for h in hosts][:self.max_hosts]
        results: List[Dict] = []
        sem = asyncio.Semaphore(self.concurrency)
        conn = aiohttp.TCPConnector(limit=self.concurrency * 2, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as session:
            await asyncio.gather(
                *(self.probe_host(session, sem, h, results) for h in hosts))
        docs = [r for r in results if r['kind'] == 'openapi_doc']
        uis = [r for r in results if r['kind'] == 'docs_ui']
        return {
            'findings': results,
            'summary': {
                'hosts_probed': len(hosts),
                'openapi_docs': len(docs),
                'docs_uis': len(uis),
                'total_endpoints': sum(d['endpoint_count'] for d in docs),
            },
        }
