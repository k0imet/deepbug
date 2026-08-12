# modules/tools/github_subdomains.py
# GitHub *subdomain* enumeration (github-subdomains vibes) as a config
# driven module. Queries the GitHub search API for the apex and normalizes
# any host strings bubbled up from repo / commit / code search metadata.
#
# Token optional:
#   * repo search  - no auth  (repos referencing the apex)
#   * commit search - no auth (messages that mention the apex or its hosts)
#   * code search  - requires GITHUB_TOKEN (GitHub API restriction)
#
# Output is scoped (dropped unless it matches the apex suffix), deduped,
# and ready to feed the dnsx resolution stage in the recon pipeline.

import asyncio
import os
import re
from typing import Dict, List, Optional, Any
import aiohttp

try:
    from app.utils.logger import get_logger
    logger = get_logger()
except Exception:
    import logging
    logger = logging.getLogger(__name__)

_GITHUB_API = 'https://api.github.com'
_HOST_RE = re.compile(r"([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+)")

_SNIPPED = set()


class GitHubSubdomains:
    """
    Enumerate subdomains of a root domain from GitHub metadata.

    Usage:
        gh = GitHubSubdomains(config)
        res = gh.scan_sync('example.com', ['example.com'])
        print(res['subdomains'])
    """

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        cfg = config.get("github_subdomains", config) if isinstance(config, dict) else {}
        self.token_env = cfg.get('token_env', 'GITHUB_TOKEN')
        self.timeout = int(cfg.get('timeout', 20))
        self.token = os.environ.get(self.token_env, '') or \
            os.environ.get('GITHUB_TOKEN', '')

    # ------------------------------------------------------------------
    async def _search(self, session, path: str, params: Dict) -> Optional[Dict]:
        headers = {'Accept': 'application/vnd.github+json'}
        if self.token:
            headers['Authorization'] = f'token {self.token}'
        url = _GITHUB_API + path
        try:
            async with session.get(url, params=params, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=self.timeout)) as s:
                if s.status in (403, 429, 422):
                    logger.debug("github_subdomains %s on %s", s.status, path)
                    return None
                if s.status != 200:
                    return None
                return await s.json()
        except Exception:
            return None

    # ------------------------------------------------------------------
    def _collect(self, items, apex: str) -> set:
        hosts = set()
        parts_re = re.compile(r'(?:https?://)?'
                              r'([a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+)', re.I)
        for it in items:
            if isinstance(it, dict):
                blobs = [str(v) for v in it.values()]
            else:
                blobs = [str(it)]
            for b in blobs:
                if not b:
                    continue
                for m in parts_re.finditer(b):
                    cand = m.group(1).lower()
                    if cand == apex or cand.endswith('.' + apex):
                        hosts.add(cand)
        return hosts

    # ------------------------------------------------------------------
    async def scan(self, apex: str,
                   scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        scope_hosts = scope_hosts or [apex]
        apex = apex.strip().lower().lstrip('*.')
        result: Dict[str, Any] = {'subdomains': [],
                                  'sources': [], 'token_used': bool(self.token)}
        found: set = set()

        async with aiohttp.ClientSession() as session:
            # repo search (no auth): repos that reference the apex
            data = await self._search(session, '/search/repositories',
                                      {'q': apex, 'per_page': '100'})
            if data and data.get('items'):
                found |= self._collect(data['items'], apex)
                result['sources'].append('repos')
            else:
                result['sources'].append('repos(skip)')

            # commit search (no auth)
            data = await self._search(session, '/search/commits',
                                      {'q': apex, 'per_page': '100'})
            if data and data.get('items'):
                found |= self._collect(data['items'], apex)
                result['sources'].append('commits')
            else:
                result['sources'].append('commits(skip)')

            # code search (token-gated)
            if self.token:
                data = await self._search(session, '/search/code',
                                          {'q': f'"{apex}"', 'per_page': '100'})
                if data and data.get('items'):
                    found |= self._collect(data['items'], apex)
                    result['sources'].append('code')
                else:
                    result['sources'].append('code(skip)')
            else:
                result['sources'].append('code(no-token)')

        out = []
        for h in sorted(found):
            if any(h == s.lstrip('*.') or h.endswith('.' + s.lstrip('*.'))
                   for s in scope_hosts):
                out.append(h)
        result['subdomains'] = out
        return result

    def scan_sync(self, apex: str,
                  scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        try:
            return asyncio.run(self.scan(apex, scope_hosts))
        except Exception:
            return {'subdomains': [], 'sources': [], 'token_used': bool(self.token)}