import json
import re
import sqlite3
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Optional, Callable
import pandas as pd

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
        self.cache_db = Path(__file__).parent / 'registry_cache.db'
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
            return {'exists': bool(row[0]), 'latest_version': row[1], 'scope_blocked': bool(row[2])}
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
        result = {'exists': False, 'latest_version': None, 'scope_blocked': False}
        try:
            resp = self.session.get(self.npm_registry + package, timeout=(3, 10))
            if resp.status_code == 200:
                data = resp.json()
                versions = data.get('versions', {})
                if versions:
                    result['exists'] = True
                    latest = max(versions.keys(), key=lambda v: [int(x) for x in v.split('.') if x.isdigit()])
                    result['latest_version'] = latest
            elif resp.status_code == 403:
                result['scope_blocked'] = True
        except Exception as e:
            logger.debug(f"Error checking npm package {package}: {e}")
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

    def scan(self, urls: List[str], progress_callback: Optional[Callable] = None) -> pd.DataFrame:
        all_deps = []
        for idx, url in enumerate(urls):
            # ... (keep your existing parsing logic here) ...
            pass
        # Batch check logic here...
        return pd.DataFrame() # Return your processed findings