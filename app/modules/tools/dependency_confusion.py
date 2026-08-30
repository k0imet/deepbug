import json
import re
import sqlite3
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Optional, Callable
import pandas as pd
from urllib.parse import quote

from app.utils.logger import get_logger
from app.utils.user_agents import get_user_agent

logger = get_logger()

class DependencyConfusionScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': get_user_agent()})
        self.session.mount('https://', requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=50))
        self.npm_registry = "https://registry.npmjs.org/"
        self.pypi_registry = "https://pypi.org/pypi/"
        self.cache_db = Path(config.get(
            'dependency_cache_db', Path(__file__).parent / 'registry_cache.db'))
        self._init_cache()

    def _init_cache(self):
        conn = sqlite3.connect(str(self.cache_db))
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS cache
                      (package TEXT PRIMARY KEY, package_exists INTEGER, latest_version TEXT, scope_blocked INTEGER)''')
        conn.commit()
        conn.close()

    def _get_cached(self, package: str) -> Optional[Dict]:
        conn = sqlite3.connect(str(self.cache_db))
        c = conn.cursor()
        c.execute("SELECT package_exists, latest_version, scope_blocked FROM cache WHERE package=?", (package,))
        row = c.fetchone()
        conn.close()
        if row:
            exists, latest, blocked = bool(row[0]), row[1], bool(row[2])
            return {
                'exists': exists,
                'latest_version': latest,
                'scope_blocked': blocked,
                'status': 'blocked' if blocked else ('exists' if exists else 'not_found'),
            }
        return None

    def _set_cached(self, package: str, exists: bool, latest_version: str = None, scope_blocked: bool = False):
        conn = sqlite3.connect(str(self.cache_db))
        c = conn.cursor()
        c.execute("REPLACE INTO cache (package, package_exists, latest_version, scope_blocked) VALUES (?, ?, ?, ?)",
                  (package, 1 if exists else 0, latest_version, 1 if scope_blocked else 0))
        conn.commit()
        conn.close()

    def _check_npm_package(self, package: str) -> Dict:
        cached = self._get_cached(package)
        if cached:
            return cached
        result = {'exists': False, 'latest_version': None, 'scope_blocked': False,
                  'status': 'unknown'}
        try:
            resp = self.session.get(self.npm_registry + quote(package, safe=''), timeout=(3, 10))
            if resp.status_code == 200:
                data = resp.json()
                versions = data.get('versions', {})
                if versions:
                    result['exists'] = True
                    result['latest_version'] = (data.get('dist-tags') or {}).get('latest')
                result['status'] = 'exists'
            elif resp.status_code == 404:
                result['status'] = 'not_found'
            elif resp.status_code == 403:
                result['scope_blocked'] = True
                result['status'] = 'blocked'
            else:
                result['status'] = f'http_{resp.status_code}'
        except Exception as e:
            logger.debug(f"Error checking npm package {package}: {e}")
            result['error'] = type(e).__name__
        # Never turn a timeout, rate limit, or registry error into a cached
        # "package available" finding. Only definitive registry answers cache.
        if result['status'] in ('exists', 'not_found', 'blocked'):
            self._set_cached(package, result['exists'], result['latest_version'], result['scope_blocked'])
        return result

    def _check_npm_scope(self, scope: str) -> bool:
        cached = self._get_cached(scope)
        if cached: return cached['scope_blocked']
        try:
            resp = self.session.get(self.npm_registry + scope, timeout=(3, 10))
            if resp.status_code == 403:
                self._set_cached(scope, False, None, True)
                return True
            else:
                self._set_cached(scope, False, None, False)
                return False
        except: return False

    @staticmethod
    def _extract_npm_names(content: str) -> List[str]:
        """Extract package names evidenced in a JS bundle without executing it."""
        names = set()
        patterns = (
            r'node_modules[/\\](?P<name>@[a-z0-9._-]+[/\\][a-z0-9._-]+|[a-z0-9._-]+)',
            r'(?:require|import)\s*\(\s*["\x27](?P<name>@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9._-]+)["\x27]\s*\)',
            r'\bfrom\s*["\x27](?P<name>@[a-z0-9._-]+/[a-z0-9._-]+|[a-z0-9._-]+)["\x27]',
        )
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.I):
                name = match.group('name').replace('\\', '/').lower()
                if name and not name.startswith(('.', '/')):
                    names.add(name)
        return sorted(names)

    def _download_candidate(self, url: str) -> Optional[str]:
        try:
            response = self.session.get(url, timeout=(3, 15), allow_redirects=False)
            if response.status_code != 200:
                return None
            body = response.content[:int(self.config.get('dependency_max_js_bytes', 2_000_000))]
            return body.decode('utf-8', errors='ignore')
        except Exception as exc:
            logger.debug("Dependency source fetch failed %s: %s", url, exc)
            return None

    def scan(self, urls: List[str], progress_callback: Optional[Callable] = None) -> pd.DataFrame:
        evidence = {}
        unique_urls = list(dict.fromkeys(u for u in urls if str(u).startswith(('http://', 'https://'))))
        for idx, url in enumerate(unique_urls):
            if progress_callback:
                progress_callback(idx / max(len(unique_urls), 1), f"Inspecting bundle {idx + 1}/{len(unique_urls)}")
            content = self._download_candidate(url)
            if not content:
                continue
            for package in self._extract_npm_names(content):
                evidence.setdefault(package, url)

        findings = []
        packages = sorted(evidence)
        with ThreadPoolExecutor(max_workers=min(12, max(len(packages), 1))) as pool:
            futures = {pool.submit(self._check_npm_package, package): package for package in packages}
            for done, future in enumerate(as_completed(futures), 1):
                package = futures[future]
                result = future.result()
                if result.get('status') == 'not_found':
                    scoped = package.startswith('@')
                    findings.append({
                        'package': package,
                        'ecosystem': 'npm',
                        'registry_status': 'not_found',
                        'severity': 'LOW' if scoped else 'MEDIUM',
                        'confidence': 'candidate',
                        'source_url': evidence[package],
                        'note': ('Referenced package is absent from public npm. Confirm it is private and '
                                 'review registry/proxy configuration; absence alone is not a vulnerability.'),
                    })
                if progress_callback:
                    progress_callback(done / max(len(packages), 1),
                                      f"Checked package {done}/{len(packages)}")
        return pd.DataFrame(findings, columns=[
            'package', 'ecosystem', 'registry_status', 'severity',
            'confidence', 'source_url', 'note'])
