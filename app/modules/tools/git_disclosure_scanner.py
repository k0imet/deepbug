# modules/tools/git_disclosure_scanner.py
# Exposed .git directory hunting (the "git folder leaks" trick from
# infosecwriteups). A reachable /.git/HEAD = full source-code disclosure.
#
#   * Probe /.git/HEAD + refs (case variants included)
#   * Parse the branch ref -> commit -> tree -> blob chain
#   * Pull high-value source files (.env, credentials, config, source) and
#     sniff snippets for secrets - a limited, low-noise git-dumper-lite.
#
# Respects config caps (max_files/depth); never writes to the target.
#   {'results': [{base, head_ref, branch, commit, exposed, files: [...]}],
#    'totals': {...}}

import re
import zlib
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any

from app.utils.logger import get_logger

logger = get_logger()

_GIT_PATHS = ('.git/HEAD', '.git/config', '.git/refs/heads/master', '.git/refs/heads/main')
_CASE_VARIANTS = ('.git', '.Git', '.GIT', '.gIt')

# file types we bother pulling from the object store
_INTERESTING_SUFFIXES = (
    '.env', '.py', '.js', '.ts', '.json', '.yml', '.yaml', '.conf', '.config',
    '.ini', '.php', '.sql', '.rb', '.go', '.java', '.sh', '.xml', '.pem',
    '.key', '.p12', '.pfx', 'credentials', 'id_rsa', 'docker-compose',
    'makefile', 'config.php', 'config.js', 'settings.py', 'secret', 'token',
)
_INTERESTING_RE = re.compile(
    r'(\.(?:env|py|js|ts|json|ya?ml|conf|ini|php|sql|rb|go|java|sh|xml|pem|key|p12|pfx)$'
    r'|credentials|id_rsa|docker-compose|secret|token|makefile)', re.IGNORECASE)

_SECRET_PATTERNS = {
    'AWS_AccessKey': r'\bAKIA[0-9A-Z]{16}\b',
    'GitHub_token': r'\bgh[pousr]_[0-9A-Za-z]{36,}\b',
    'Slack_token': r'\bxox[baprs]-[0-9A-Za-z-]{10,}\b',
    'Google_API_key': r'\bAIza[0-9A-Za-z_\-]{35}\b',
    'RSAPrivateKey': r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
    'Env_secret_var': r'\b(?:DB|APP|API|AWS|SECRET|TOKEN)[A-Z_]*_(?:PASSWORD|KEY|SECRET|PASS)\s*[=:]\s*\S+',
    'Mongo_uri': r'mongodb(\+srv)?://[^\s"\']+',
}


def _sniff_secrets(text: str) -> List[str]:
    found = []
    for name, pattern in _SECRET_PATTERNS.items():
        if re.search(pattern, text, re.IGNORECASE):
            found.append(name)
    return found


class GitDisclosureScanner:
    """
    Exposed .git detection + limited blob dump.

    Usage:
        scanner = GitDisclosureScanner(config)
        results = scanner.scan_sync(['https://example.com/app'], progress_callback=...)
    """

    def __init__(self, config: Dict):
        cfg = config.get('git_disclosure', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 15))
        self.max_files = int(cfg.get('max_files', 25))
        self.depth = int(cfg.get('depth', 2))
        self.max_snippet = int(cfg.get('max_snippet', 500))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, urls: List[str],
                   progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        results = []
        seen_bases = set()
        total = len(urls)
        for i, raw in enumerate(urls):
            base = _base_url(raw)
            if not base or base in seen_bases:
                continue
            seen_bases.add(base)
            try:
                res = await self._check_base(base)
            except Exception as e:
                res = {'base': base, 'error': str(e), 'exposed': False, 'files': []}
            results.append(res)
            if progress_callback:
                progress_callback((i + 1) / max(total, 1),
                                  f'git check {base}: {"EXPOSED" if res.get("exposed") else "ok"}')

        totals = {
            'targets': len(results),
            'exposed': sum(1 for r in results if r.get('exposed')),
            'files': sum(len(r.get('files', [])) for r in results),
        }
        logger.info(f'git disclosure done: {totals}')
        return {'results': results, 'totals': totals}

    def scan_sync(self, urls: List[str],
                  progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(urls, progress_callback))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _get(self, session: aiohttp.ClientSession, url: str) -> bytes:
        async with session.get(url, allow_redirects=True,
                               timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
            if resp.status == 200:
                return await resp.read()
        return b''

    async def _check_base(self, base: str) -> Dict[str, Any]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            head_ref = ''
            for path in _GIT_PATHS:
                if head_ref:
                    break
                for variant in _CASE_VARIANTS:
                    body = await self._get(session, f'{base}/{variant}/{path.split("/", 1)[1]}')
                    if body.startswith(b'ref: '):
                        head_ref = body.decode('utf-8', 'ignore').strip()
                        break
            if not head_ref:
                return {'base': base, 'head_ref': '', 'branch': '', 'commit': '',
                        'exposed': False, 'files': [], 'note': 'no .git/HEAD reachable'}
            branch = head_ref.replace('ref: refs/heads/', '').strip()
            git_root = base.rstrip('/') + '/.git'
            # resolve branch tip
            commit = (await self._get(session, f'{git_root}/refs/heads/{branch}')).decode('utf-8', 'ignore').strip()
            if not re.fullmatch(r'[0-9a-fA-F]{40}', commit):
                # packed refs: fall back to the HEAD content we already have
                commit = ''

            files: List[Dict] = []
            walked = set()
            queue = []  # (type, sha, path, depth)
            if commit:
                queue.append(('commit', commit, '', 0))
            visited = set()
            while queue and len(files) < self.max_files:
                otype, osha, path, depth = queue.pop(0)
                if (otype, osha) in visited:
                    continue
                visited.add((otype, osha))
                raw = await self._get(session, f'{git_root}/objects/{osha[:2]}/{osha[2:]}')
                if not raw:
                    continue  # packed object - not fetchable
                obj = _decompress_object(raw)
                if otype == 'commit':
                    tree_sha = ''
                    for line in obj.splitlines():
                        if line.startswith(b'tree '):
                            tree_sha = line.split()[1].decode('utf-8', 'ignore')
                            break
                    if tree_sha and depth < self.depth + 1:
                        queue.append(('tree', tree_sha, path, depth))
                elif otype == 'tree':
                    for mode, ttype, sha, name in _parse_tree(obj):
                        child_path = f'{path}/{name}'.strip('/') if path else name
                        if ttype == 'tree':
                            if depth < self.depth:
                                queue.append(('tree', sha, child_path, depth + 1))
                        elif ttype == 'blob' and (depth <= 1 or _INTERESTING_RE.search(child_path)):
                            queue.append(('blob', sha, child_path, depth + 1))
                elif otype == 'blob':
                    snippet = obj.decode('utf-8', 'ignore').strip()[:self.max_snippet]
                    if _INTERESTING_RE.search(path) or _sniff_secrets(snippet):
                        files.append({
                            'path': path,
                            'sha': osha,
                            'url': f'{git_root}/objects/{osha[:2]}/{osha[2:]}',
                            'snippet': snippet,
                            'secrets': _sniff_secrets(snippet),
                        })
            files = files[:self.max_files]
            return {
                'base': base,
                'head_ref': head_ref,
                'branch': branch,
                'commit': commit,
                'exposed': True,
                'files': files,
                'note': f'{len(files)} interesting files pulled',
            }

    def _empty_result(self) -> Dict[str, Any]:
        return {'results': [], 'totals': {'targets': 0, 'exposed': 0, 'files': 0}}


def _base_url(raw: str) -> str:
    raw = (raw or '').strip()
    if not raw:
        return ''
    if not raw.startswith(('http://', 'https://')):
        raw = 'https://' + raw
    from urllib.parse import urlparse
    p = urlparse(raw)
    if not p.hostname:
        return ''
    return f'{p.scheme}://{p.netloc}'


def _decompress_object(raw: bytes) -> bytes:
    try:
        out = zlib.decompress(raw)
    except Exception:
        return b''
    nul = out.find(b'\x00')
    if nul == -1:
        return b''
    return out[nul + 1:]


def _parse_tree(data: bytes) -> List[tuple]:
    entries = []
    i = 0
    while i < len(data):
        sp = data.find(b' ', i)
        if sp == -1:
            break
        mode = data[i:sp].decode('utf-8', 'ignore')
        sp2 = data.find(b'\x00', sp)
        if sp2 == -1:
            break
        name = data[sp + 1:sp2].decode('utf-8', 'ignore')
        sha = data[sp2 + 1:sp2 + 21].hex()
        i = sp2 + 21
        if mode.startswith('4'):
            ttype = 'tree'
        elif mode.startswith(('10', '12')):
            ttype = 'blob'
        else:
            ttype = 'other'
        entries.append((mode, ttype, sha, name))
    return entries


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()