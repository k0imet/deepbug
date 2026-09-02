from app.utils.user_agents import PROGRAM_UA_TAG
# modules/tools/vhost_fuzzer.py
# Virtual-host discovery (the "finds subdomains with no DNS records" trick):
# an app reachable at the same IP under many Host: headers is invisible to
# DNS brute force - only Host-header probing finds it.
#
#   * Resolve known subdomains -> unique IPs
#   * Per IP: baseline (Host: apex) + junk (Host: invalid zone)
#   * Try candidate labels as Host: <label>.<domain>; a response that differs
#     from BOTH baselines (status / length / title) is a virtual host hit.
#
# Scope-filtered (only <label>.<zone> hosts are reported). Passive GETs only.
#   {'subdomains': [...], 'hits': [{host, ip, status, length, title}],
#    'totals': {...}}

import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Callable, Any

from app.utils.logger import get_logger

logger = get_logger()

_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)

_VHOST_WORDS = [
    'admin', 'admin2', 'dev', 'development', 'staging', 'stage', 'test', 'testing',
    'qa', 'uat', 'preprod', 'pre-production', 'sandbox', 'demo', 'beta', 'alpha',
    'api', 'api2', 'v2', 'v3', 'graphql', 'www', 'ww1', 'mail', 'webmail', 'smtp',
    'portal', 'intranet', 'internal', 'corp', 'corporate', 'vpn', 'remote', 'access',
    'git', 'gitlab', 'github', 'jenkins', 'ci', 'cd', 'build', 'travis', 'sonar',
    'sonarqube', 'grafana', 'kibana', 'elastic', 'elk', 'metrics', 'monitor',
    'prometheus', 'sentry', 'logging', 'jira', 'confluence', 'wiki', 'help',
    'support', 'docs', 'documentation', 'blog', 'status', 'statuspage', 'download',
    'downloads', 'files', 'assets', 'cdn', 'img', 'media', 'static', 'app', 'apps',
    'web', 'm', 'mobile', 'secure', 'login', 'sso', 'auth', 'oauth', 'oauth2',
    'console', 'panel', 'dashboard', 'phpmyadmin', 'adminer', 'redis', 'cache',
    'db', 'database', 'mysql', 'postgres', 'mongo', 'mongodb', 'rabbitmq',
    'elasticsearch', 'k8s', 'kubernetes', 'docker', 'registry', 'backup',
    'backups', 'archive', 'old', 'new', 'dev2', 'test2', 'staging2', 'lab', 'labs',
    # 2024 modern naming
    'internal-prd', 'internal-staging', 'platform', 'platform-admin', 'backoffice',
    'admin-internal', 'api-internal', 'private', 'prd', 'prod', 'stg', 'devops',
]

# words derived from already-known subdomains (e.g. api-admin, xyz-dev)
_LABEL_RE = re.compile(r'^[a-z0-9\-]+$')


class VhostFuzzer:
    """
    Virtual-host discovery via Host-header fuzzing.

    Usage:
        fuzzer = VhostFuzzer(config)
        results = fuzzer.scan_sync(domain, subdomains=['www.example.com'],
                                   scope_hosts=['example.com'])
    """

    def __init__(self, config: Dict):
        cfg = config.get('vhost', {}) if isinstance(config, dict) else {}
        self.timeout = int(cfg.get('timeout', 12))
        self.max_ips = int(cfg.get('max_ips', 5))
        self.max_candidates = int(cfg.get('max_candidates', cfg.get('max_vhosts', 400)))
        self.min_diff = int(cfg.get('min_diff', cfg.get('min_length_diff', 15)))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, domain: str,
                   subdomains: Optional[List[str]] = None,
                   progress_callback: Optional[Callable[[float, str], None]] = None,
                   scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        domain = (domain or '').strip().lower().rstrip('.')
        if not domain:
            return self._empty_result()
        scope_hosts = [h.lower().rstrip('.') for h in (scope_hosts or [domain]) if h and h != '*']

        def _in_zone(host: str) -> bool:
            host = host.lower().rstrip('.')
            return any(host == s or host.endswith('.' + s) for s in scope_hosts)

        # unique IPs from known subdomains
        hosts_to_resolve = sorted(set([domain] + [s.lower() for s in (subdomains or [])]))
        ip_map: Dict[str, List[str]] = {}
        for h in hosts_to_resolve[:40]:
            ips = await self._resolve(h)
            ip_map[h] = ips
        unique_ips = []
        seen_ips = set()
        for ips in ip_map.values():
            for ip in ips:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    unique_ips.append(ip)
        unique_ips = unique_ips[:self.max_ips]
        if not unique_ips:
            return {**self._empty_result(), 'errors': ['no resolvable IPs']}

        # candidate labels
        labels = set(_VHOST_WORDS)
        for h in hosts_to_resolve:
            base = h.replace('.' + domain, '').strip('.')
            for part in base.split('.'):
                if _LABEL_RE.match(part) and len(part) <= 32:
                    labels.add(part)
                    labels.add(f'{part}-dev')
                    labels.add(f'{part}2')
        candidates = sorted(labels)[:self.max_candidates]

        hits: List[Dict] = []
        total = len(unique_ips)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
            for i, ip in enumerate(unique_ips):
                base_status, base_len, base_title, base_hash = await self._probe_vhost(session, ip, domain)
                junk_status, junk_len, _, junk_hash = await self._probe_vhost(session, ip, f'nx.{domain}')
                for cand in candidates:
                    host = f'{cand}.{domain}'
                    if not _in_zone(host):
                        continue
                    status, length, title, h = await self._probe_vhost(session, ip, host)
                    if _is_distinct(status, length, h, base_status, base_len, base_hash,
                                    junk_len, junk_hash, self.min_diff):
                        hits.append({'host': host, 'ip': ip, 'status': status,
                                     'length': length, 'title': title})
                if progress_callback:
                    progress_callback((i + 1) / max(total, 1),
                                      f'vhosts on {ip}: {len(hits)} hits so far')

        seen_hosts = set()
        for h in hits:
            if h['host'] not in seen_hosts:
                seen_hosts.add(h['host'])
        result = {
            'subdomains': sorted(seen_hosts),
            'hits': hits,
            'ips': unique_ips,
            'errors': [],
            'totals': {'ips': len(unique_ips), 'candidates': len(candidates),
                       'hits': len(hits), 'subdomains': len(seen_hosts)},
            'scope_zone': sorted(scope_hosts),
        }
        logger.info(f'vhost fuzz done: {result["totals"]}')
        return result

    def scan_sync(self, domain: str, subdomains: Optional[List[str]] = None,
                  progress_callback: Optional[Callable[[float, str], None]] = None,
                  scope_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        return _run_coro(self.scan(domain, subdomains, progress_callback, scope_hosts))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    async def _resolve(self, host: str) -> List[str]:
        try:
            import socket
            infos = socket.getaddrinfo(host, None)
            return list({i[4][0] for i in infos})
        except Exception:
            return []

    @staticmethod
    def _body_hash(body: str) -> str:
        """Normalized hash that ignores dynamic tokens (CSRF, request-id, dates)."""
        import hashlib
        # Strip dynamic fragments that cause false diffs
        norm = re.sub(r'[a-f0-9]{16,}', '', body)  # tokens / hashes
        norm = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^<]{0,20}', '', norm)  # dates
        norm = re.sub(r'\s+', ' ', norm).strip()[:8000]
        return hashlib.md5(norm.encode(errors='ignore')).hexdigest()

    async def _probe_vhost(self, session: aiohttp.ClientSession, ip: str,
                           host: str) -> tuple:
        # Try HTTPS first (SNI), fall back to HTTP — TLS-only vhosts are invisible otherwise
        for scheme in ('https', 'http'):
            try:
                url = f'{scheme}://{ip}/'
                # aiohttp uses the Host header for vhost, but TLS SNI needs connector-level server_hostname
                # We rely on Host header + ssl=False (no cert verify) — covers 90% of cases behind ALB/CloudFront
                connector = session.connector
                # For HTTPS, try with SNI via TCPConnector(acquired via session)
                async with session.get(url,
                                       headers={'Host': host, 'User-Agent': 'deepbug-vhost' + PROGRAM_UA_TAG},
                                       timeout=aiohttp.ClientTimeout(total=self.timeout),
                                       ssl=False) as resp:
                    body = await resp.text(errors='ignore')
                    title = _TITLE_RE.search(body)
                    h = self._body_hash(body)
                    return resp.status, len(body), (title.group(1).strip()[:80] if title else ''), h
            except Exception:
                continue
        return 0, 0, '', ''

    def _empty_result(self) -> Dict[str, Any]:
        return {'subdomains': [], 'hits': [], 'ips': [], 'errors': [],
                'totals': {'ips': 0, 'candidates': 0, 'hits': 0, 'subdomains': 0},
                'scope_zone': []}


def _is_distinct(status: int, length: int, h: str, base_status: int, base_len: int, base_hash: str,
                 junk_len: int, junk_hash: str, min_diff: int) -> bool:
    if status in (0, 404, 502, 503, 504):
        return False
    if status != base_status and status != 404:
        return True
    # Same status as baseline — require a clearly different body from BOTH baselines.
    # Prefer hash (ignores CSRF/timestamps), fall back to length.
    if h and base_hash and junk_hash:
        if h != base_hash and h != junk_hash:
            return True
    if abs(length - base_len) >= max(min_diff, 80) and abs(length - junk_len) >= max(min_diff, 80):
        return True
    return False


def _run_coro(coro):
    """Run a coroutine from sync code, tolerating an already-running loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()