from app.utils.user_agents import PROGRAM_UA_TAG
"""
GraphQLScanner — hardened detection + misconfiguration probes + clairvoyance.

File: app/modules/tools/graphql_scanner.py

CHANGES vs. original:
  - Detection no longer trusts a bare {errors:[...]} body (that false-positives on
    plain REST APIs). Confirmed only if `{__typename}` resolves in `data`, an error
    message carries GraphQL-specific phrasing, or a GraphiQL/Playground IDE is exposed.
  - Adds a GET probe (?query={__typename}) so GET-only endpoints and exposed IDEs
    are caught.
  - Introspection query now requests inputFields + enumValues (valid sample mutations).
  - Runs GraphQLSecurityProbes per confirmed endpoint (batching, field suggestions,
    GET/CSRF), folded into results['security'] and results['analysis'][ep]['security'].
  - Runs GraphQLClairvoyance on endpoints where introspection is DISABLED, storing
    the reconstructed partial schema in results['clairvoyance'][ep].
"""

import re
import aiohttp
import asyncio
import json
from typing import List, Dict, Any, Optional, Callable
from app.utils.url_utils import urljoin

from app.utils.logger import get_logger
from .graphql_analyzer import GraphQLAnalyzer
from .graphql_security_probes import GraphQLSecurityProbes
from .graphql_clairvoyance import GraphQLClairvoyance

logger = get_logger()


# error phrasing that only a GraphQL server produces
_GQL_ERROR_SIGNS = re.compile(
    r"(cannot query field|must be a valid graphql|graphql syntax|"
    r"unknown argument|did you mean|no such type|expected type|"
    r"must provide query string|query is required|syntax error|"
    r"field ['\"][^'\"]+['\"] of type)",
    re.IGNORECASE,
)

# markers of a REAL exposed in-browser IDE (GraphiQL app assets / playground
# react bundle). Plain prose mentioning "graphiql" on a docs page is NOT enough.
_GQL_IDE_SIGNS = re.compile(
    r"(graphiql(?:\.min)?\.(?:js|css)|__GRAPHIQL__|"
    r"graphql-playground-react|graphql-playground\.(?:js|css)|"
    r"<div[^>]+id=[\"']graphiql|graphiql\.react)",
    re.IGNORECASE,
)


class GraphQLScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.timeout = 10
        self.max_concurrent = 50
        self.headers = {
            'User-Agent': 'DeepBug-GraphQL/2.0' + PROGRAM_UA_TAG,
            'Content-Type': 'application/json'
        }
        self.common_paths = [
            '/graphql', '/v1/graphql', '/v2/graphql', '/api/graphql',
            '/gql', '/graphiql', '/graphql/console', '/graphql/explorer',
            '/api/v1/graphql', '/api/v2/graphql'
        ]

        # Minimal payload just to trigger a GraphQL validation error or success
        self.verify_payload = {"query": "{ __typename }"}

        # Robust Introspection: nested `ofType` for Lists/Non-Nulls, PLUS inputFields
        # and enumValues so the analyzer can build valid sample mutations.
        self.introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              name kind description
              fields(includeDeprecated: true) {
                name
                type { ...TypeRef }
                args { name type { ...TypeRef } }
              }
              inputFields { name type { ...TypeRef } }
              enumValues(includeDeprecated: true) { name }
            }
          }
        }
        fragment TypeRef on __Type {
          name kind
          ofType { name kind ofType { name kind ofType { name kind ofType { name kind } } } }
        }
        """

    # -----------------------------------------------------------------
    # DETECTION (hardened)
    # -----------------------------------------------------------------

    @staticmethod
    def _confirm_graphql(text: str) -> Optional[str]:
        """
        Decide whether a response body proves a GraphQL endpoint.
        Returns a short reason string if confirmed, else None.
        A plain {"errors":[...]} REST response is NOT enough — the error must be
        GraphQL-shaped, or __typename must have resolved. S3/XML error pages
        (NoSuchKey, MethodNotAllowed, AccessDenied) are explicitly excluded.
        """
        if not text:
            return None
        if '<Error>' in text or '<Code>NoSuchKey</Code>' in text or \
           'MethodNotAllowed' in text or '<Code>AccessDenied' in text:
            return None
        try:
            data = json.loads(text)
        except Exception:
            data = None

        if isinstance(data, dict):
            d = data.get('data')
            if isinstance(d, dict) and '__typename' in d:
                return 'typename_resolved'
            errs = data.get('errors')
            if isinstance(errs, list) and errs:
                joined = ' '.join(
                    str(e.get('message', '')) if isinstance(e, dict) else str(e)
                    for e in errs
                )
                if _GQL_ERROR_SIGNS.search(joined):
                    return 'graphql_error'

        # exposed IDE (GraphiQL / Playground) served as HTML
        if text and _GQL_IDE_SIGNS.search(text):
            return 'graphql_ide'

        # auth-gated GraphQL: 401/403 JSON with an "errors" array + errorType
        # (AWS AppSync style). Not confirmable via validation, but it IS a
        # GraphQL API - surface it so it can be tested with valid tokens.
        try:
            d = json.loads(text)
            if isinstance(d, dict) and isinstance(d.get('errors'), list) and d['errors']:
                joined = ' '.join(str(e.get('message', '')) if isinstance(e, dict) else str(e)
                                  for e in d['errors'])
                if joined and ('authorization' in joined.lower() or
                               'authenticated' in joined.lower() or
                               'unauthorized' in joined.lower() or
                               'token' in joined.lower() or
                               'forbidden' in joined.lower()):
                    return 'gated_auth'
        except Exception:
            pass
        return None

    async def _detect_endpoint_async(self, session: aiohttp.ClientSession, base_url: str,
                                     path: str, semaphore: asyncio.Semaphore) -> Optional[str]:
        """Probe a single path (POST then GET) and confirm GraphQL presence."""
        url = urljoin(base_url, path)
        async with semaphore:
            # 1. POST { __typename }
            try:
                async with session.post(url, json=self.verify_payload,
                                        timeout=self.timeout) as resp:
                    if resp.status in (200, 400, 405, 422, 401, 403):
                        reason = self._confirm_graphql(await resp.text())
                        if reason:
                            logger.info(f"GraphQL endpoint [{reason}]: {url}")
                            return url
            except Exception:
                pass

            # 2. GET ?query={__typename} — catches GET-only servers and exposed IDEs
            try:
                async with session.get(url, params={'query': '{__typename}'},
                                       timeout=self.timeout) as resp:
                    if resp.status in (200, 400, 405, 422, 401, 403):
                        reason = self._confirm_graphql(await resp.text())
                        if reason:
                            logger.info(f"GraphQL endpoint via GET [{reason}]: {url}")
                            return url
            except Exception:
                pass
        return None

    # -----------------------------------------------------------------
    # INTROSPECTION
    # -----------------------------------------------------------------

    async def _run_introspection_async(self, session: aiohttp.ClientSession,
                                       endpoint: str) -> Optional[Dict]:
        """Dump the schema using the robust introspection query."""
        try:
            async with session.post(endpoint, json={"query": self.introspection_query},
                                    timeout=15) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, dict) and 'data' in data \
                            and data['data'] and '__schema' in data['data']:
                        logger.info(f"Introspection successful on {endpoint}")
                        return data
        except Exception as e:
            logger.debug(f"Introspection failed on {endpoint} (may be disabled): {e}")
        return None

    # -----------------------------------------------------------------
    # ORCHESTRATION
    # -----------------------------------------------------------------

    async def scan_async(self, urls: List[str],
                         progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """High-concurrency GraphQL discovery, introspection, analysis, probes, clairvoyance."""
        results: Dict[str, Any] = {
            'endpoints': [], 'schemas': {}, 'analysis': {},
            'security': {}, 'clairvoyance': {}
        }
        if not urls:
            return results

        semaphore = asyncio.Semaphore(self.max_concurrent)

        async with aiohttp.ClientSession(headers=self.headers) as session:
            # 1. Spray all paths concurrently across all base URLs
            probe_tasks = [
                self._detect_endpoint_async(session, base, path, semaphore)
                for base in urls for path in self.common_paths
            ]
            if progress_callback:
                progress_callback(0.1, f"Probing {len(probe_tasks)} potential GraphQL paths...")

            discovered = await asyncio.gather(*probe_tasks)
            valid_endpoints = sorted(set(ep for ep in discovered if ep))
            results['endpoints'] = valid_endpoints

            if not valid_endpoints:
                if progress_callback:
                    progress_callback(1.0, "GraphQL Scan Complete (no endpoints)")
                return results

            # 2. Introspection concurrently on found endpoints
            if progress_callback:
                progress_callback(0.4, f"Running Introspection on {len(valid_endpoints)} endpoints...")
            intro_tasks = [self._run_introspection_async(session, ep) for ep in valid_endpoints]
            schemas = await asyncio.gather(*intro_tasks)

            # 3. Analyze any schemas we got
            for ep, schema in zip(valid_endpoints, schemas):
                if schema:
                    results['schemas'][ep] = schema
                    try:
                        analyzer = GraphQLAnalyzer(schema)
                        summary = analyzer.summarize()
                        summary['raw_schema'] = schema
                        results['analysis'][ep] = summary
                    except Exception as e:
                        logger.warning(f"Schema analysis failed for {ep}: {e}")

            # 4. Security misconfiguration probes (read-only) on every endpoint,
            #    schema or not — introspection-disabled targets still get flagged.
            if progress_callback:
                progress_callback(0.7, f"Running security probes on {len(valid_endpoints)} endpoints...")
            probes = GraphQLSecurityProbes(timeout=self.timeout)
            sec_tasks = [
                probes.run_all(session, ep, introspection_ok=(ep in results['schemas']))
                for ep in valid_endpoints
            ]
            sec_results = await asyncio.gather(*sec_tasks, return_exceptions=True)

            for ep, sec in zip(valid_endpoints, sec_results):
                if isinstance(sec, dict):
                    results['security'][ep] = sec
                    # fold into analysis so the UI shows it even with no schema
                    results['analysis'].setdefault(ep, {})['security'] = sec
                else:
                    logger.debug(f"Security probe error on {ep}: {sec}")

            # 5. Clairvoyance — reconstruct schema where introspection is disabled
            disabled = [ep for ep in valid_endpoints if ep not in results['schemas']]
            if disabled:
                if progress_callback:
                    progress_callback(0.9, f"Reconstructing {len(disabled)} schema(s) via clairvoyance...")
                for ep in disabled:
                    try:
                        cv = GraphQLClairvoyance(
                            ep, session,
                            max_depth=self.config.get('gql_clair_depth', 3),
                            max_requests=self.config.get('gql_clair_budget', 2500),
                        )
                        recon = await cv.reconstruct()
                        if recon.get('viable') and recon.get('types'):
                            results['clairvoyance'][ep] = recon
                    except Exception as e:
                        logger.debug(f"Clairvoyance failed on {ep}: {e}")

            if progress_callback:
                progress_callback(1.0, "GraphQL Scan Complete")

        return results

    def scan(self, urls: List[str],
             progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Synchronous wrapper for legacy compatibility."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(self.scan_async(urls, progress_callback))