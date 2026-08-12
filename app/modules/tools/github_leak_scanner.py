from app.utils.user_agents import PROGRAM_UA_TAG
# modules/tools/github_leak_scanner.py
# GitHub secret-mining for bug bounty (the "GitHub dorking" trick from
# infosecwriteups): orgs commit secrets into code, PRs, issues and commit
# history that never gets scrubbed.
#
#   * Code search   - requires GITHUB_TOKEN (GitHub API restriction), highest value
#   * Issue search  - org issues/PRs often paste creds (works without token)
#   * Commit search - patch-level secret scanning in git history (no token)
#
# Rate-limit aware (10 search req/min unauthenticated) and scope-safe: findings
# are data, not exploits. Output:
#   {'findings': [{source, repo, path, html_url, snippet, secrets}],
#    'secrets_summary': {...}, 'errors': [...], 'totals': {...}}

import re
import os
import time
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any

from app.utils.logger import get_logger

logger = get_logger()

_GITHUB_API = 'https://api.github.com'

# Keywords combined with '"<domain>"' to form search queries.
_DORK_QUERIES = [
    'password', 'api_key', 'apikey', 'api-key', 'token', 'secret',
    'aws_access_key_id', 'AWS_SECRET_ACCESS_KEY', 'client_secret',
    'DB_PASSWORD', 'private_key', 'authorization', 'Bearer',
]

# Secret sniffing on fetched content/snippets.
_SECRET_PATTERNS: Dict[str, str] = {
    'AWS_AccessKey': r'\bAKIA[0-9A-Z]{16}\b',
    'GitHub_token': r'\bgh[pousr]_[0-9A-Za-z]{36,}\b',
    'Slack_token': r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b',
    'Google_API_key': r'\bAIza[0-9A-Za-z_\-]{35}\b',
    'Stripe_key': r'\b(?:sk|pk)_(?:test|live)_[0-9A-Za-z]{20,}\b',
    'Twilio': r'\bSK[0-9a-fA-F]{32}\b',
    'Bearer_token': r'\bBearer\s+[0-9A-Za-z\-_\.]{20,}',
    'RSAPrivateKey': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    'Env_secret_var': r'\b(?:DB|APP|API|AWS|SECRET|TOKEN)[A-Z_]*_(?:PASSWORD|KEY|SECRET|PASS)\s*[=:]\s*\S+',
    'Mongo_uri': r'mongodb(\+srv)?://[^\s"\']+',
    'Service_account': r'"type"\s*:\s*"service_account"',
}

_ACCEPT_HEADERS = {
    'code': 'application/vnd.github+json',
    'issues': 'application/vnd.github+json',
    'commits': 'application/vnd.github.cloak-preview+json',
}


class GitHubLeakScanner:
    """
    GitHub dorking / secret mining with rate-limit awareness.

    Usage:
        scanner = GitHubLeakScanner(config)
        results = scanner.scan_sync('example.com', progress_callback=...)
    """

    def __init__(self, config: Dict):
        cfg = config.get('github', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 20))
        self.max_queries = int(cfg.get('max_queries', 12))
        self.per_query = int(cfg.get('per_query', 10))
        self.token_env = cfg.get('token_env', 'GITHUB_TOKEN')
        self.token = os.environ.get(self.token_env, '') or os.environ.get('GITHUB_TOKEN', '')
        sources = cfg.get('sources', ['code', 'issues', 'commits'])
        self.sources = [s for s in sources if s in ('code', 'issues', 'commits')] or ['issues']
        self.auth_ok = bool(self.token)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, domain: str,
                   queries: Optional[List[str]] = None,
                   progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        domain = (domain or '').strip().lower().rstrip('.')
        if not domain:
            return self._empty_result()
        result = self._empty_result()
        result['target'] = domain
        result['token_used'] = self.auth_ok

        queries = (queries or self.default_queries())[:self.max_queries]
        errors: List[str] = []
        backoff_until = 0.0

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for qi, q in enumerate(queries):
                query = q.format(domain=domain)
                for source in self.sources:
                    if source == 'code' and not self.auth_ok:
                        errors.append('code search skipped: GITHUB_TOKEN not set')
                        continue
                    if time.monotonic() < backoff_until:
                        continue
                    try:
                        findings, err = await self._collect(session, source, query)
                    except Exception as e:
                        errors.append(f'{source}: {type(e).__name__}: {e}')
                        findings, err = [], str(e)
                    if err:
                        if 'rate' in err.lower():
                            backoff_until = time.monotonic() + 61.0
                        errors.append(f'{source}: {err}')
                        continue
                    for f in findings:
                        result['findings'].append(f)
                        for s in f.get('secrets', []):
                            result['secrets_summary'][s] = result['secrets_summary'].get(s, 0) + 1
                    if progress_callback:
                        progress_callback(min((qi + 1) / len(queries), 0.98),
                                          f'[{source}] {len(findings)} hits for {query[:50]}')
                # GitHub search API is strict: back off between queries
                await asyncio.sleep(3.0 if not self.auth_ok else 1.2)

        result['errors'] = sorted(set(errors))[:10]
        result['totals'] = {
            'findings': len(result['findings']),
            'secrets': sum(result['secrets_summary'].values()),
            'queries': len(queries),
            'sources_used': len(self.sources),
            'errors': len(result['errors']),
        }
        logger.info(f'GitHub dorking done: {result["totals"]["findings"]} findings, '
                    f'{result["totals"]["secrets"]} secrets')
        return result

    def scan_sync(self, domain: str, queries: Optional[List[str]] = None,
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(domain, queries, progress_callback))

    @staticmethod
    def default_queries() -> List[str]:
        return [f'"{{domain}}" {kw}' for kw in _DORK_QUERIES]

    # ------------------------------------------------------------------
    # GitHub internals
    # ------------------------------------------------------------------
    async def _api_get(self, session: aiohttp.ClientSession, url: str,
                       params: Dict, accept: Optional[str] = None) -> Any:
        headers = {'Accept': accept or 'application/vnd.github+json',
                   'User-Agent': 'deepbug-recon' + PROGRAM_UA_TAG}
        if self.auth_ok:
            headers['Authorization'] = f'token {self.token}'
        async with session.get(url, params=params, headers=headers) as resp:
            if resp.status in (403, 429):
                raise RuntimeError(f'rate-limited HTTP {resp.status}')
            if resp.status == 401:
                raise RuntimeError('bad/expired GITHUB_TOKEN')
            if resp.status != 200:
                return None
            try:
                return await resp.json(content_type=None)
            except Exception:
                return None

    async def _fetch_raw(self, session: aiohttp.ClientSession, repo: str, path: str) -> str:
        if not repo or not path:
            return ''
        url = f'https://raw.githubusercontent.com/{repo}/HEAD/{path}'
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return (await resp.text(errors='ignore'))[:5000]
        except Exception:
            pass
        return ''

    async def _collect(self, session: aiohttp.ClientSession, source: str,
                       query: str) -> tuple:
        """Returns (findings, error)."""
        url = f'{_GITHUB_API}/search/{source}'
        data = await self._api_get(session, url, {'q': query, 'per_page': self.per_query},
                                   accept=_ACCEPT_HEADERS[source])
        if data is None:
            return [], 'no response'
        items = data.get('items', []) if isinstance(data, dict) else []
        findings = []
        for it in items[:self.per_query]:
            if source == 'code':
                repo = (it.get('repository') or {}).get('full_name', '')
                path = it.get('path', '')
                snippet = await self._fetch_raw(session, repo, path)
                if not snippet:
                    snippet = ''.join(m.get('fragment', '')
                                      for m in (it.get('text_matches') or []))
                findings.append(self._finding('code', it.get('html_url', ''),
                                              repo, path, snippet))
            elif source == 'issues':
                body = it.get('body') or ''
                snippet = (it.get('title') or '') + '\n' + body[:3000]
                repo = (it.get('repository_url') or '').rstrip('/').rsplit('/', 1)[-1]
                findings.append(self._finding('issues', it.get('html_url', ''),
                                              repo, it.get('title', ''), snippet))
            else:  # commits
                snippet = (it.get('commit') or {}).get('message', '')[:2000]
                repo = (it.get('repository') or {}).get('full_name', '') \
                    if isinstance(it.get('repository'), dict) else ''
                sha = it.get('sha', '')
                findings.append(self._finding('commits', it.get('html_url', ''),
                                              repo, sha[:12], snippet))
        return [f for f in findings if f], ''

    @staticmethod
    def _finding(source: str, html_url: str, repo: str,
                 path: str, snippet: str) -> Optional[Dict]:
        snippet = (snippet or '').strip()[:1000]
        if not snippet and not path:
            return None
        return {
            'source': source,
            'repo': repo,
            'path': path,
            'html_url': html_url,
            'snippet': snippet,
            'secrets': _sniff_secrets(snippet),
        }

    def _empty_result(self) -> Dict[str, Any]:
        return {'findings': [], 'secrets_summary': {}, 'errors': [],
                'totals': {'findings': 0, 'secrets': 0, 'queries': 0,
                           'sources_used': 0, 'errors': 0},
                'target': '', 'token_used': False}


def _sniff_secrets(text: str) -> List[str]:
    found = []
    for name, pattern in _SECRET_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            found.append(name)
    return found


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()
