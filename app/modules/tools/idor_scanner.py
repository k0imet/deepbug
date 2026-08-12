# modules/tools/idor_scanner.py

import re
import requests
import json
import pandas as pd
from typing import List, Dict, Optional, Callable, Any
from urllib.parse import urlparse, parse_qs
import concurrent.futures

from app.utils.logger import get_logger
logger = get_logger()


class IDORScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.session_a = None
        self.session_b = None

    def set_sessions(self, session_a: requests.Session, session_b: requests.Session):
        """Set the two authenticated sessions."""
        self.session_a = session_a
        self.session_b = session_b

    def _extract_ids_from_url(self, url: str) -> List[Dict]:
        """Extract potential ID parameters from a URL (path and query)."""
        findings = []
        # Pattern: numeric IDs in path or query
        patterns = [
            (r'/user/(\d+)', 'numeric', 'path'),
            (r'/users/(\d+)', 'numeric', 'path'),
            (r'/profile/(\d+)', 'numeric', 'path'),
            (r'/order/([a-f0-9-]{36})', 'uuid', 'path'),
            (r'/order/(\d+)', 'numeric', 'path'),
            (r'/api/v\d+/(\d+)', 'numeric', 'path'),
            (r'[?&]id=(\d+)', 'numeric', 'query'),
            (r'[?&]user_id=(\d+)', 'numeric', 'query'),
            (r'[?&]uid=([a-f0-9-]+)', 'uuid', 'query'),
        ]
        for pattern, id_type, position in patterns:
            for match in re.finditer(pattern, url):
                id_value = match.group(1)
                findings.append({
                    'url': url,
                    'id_value': id_value,
                    'id_type': id_type,
                    'position': position
                })
        return findings

    def _replace_id_in_url(self, url: str, old_id: str, new_id: str) -> str:
        """Replace the first occurrence of old_id in the URL with new_id."""
        return url.replace(old_id, new_id, 1)

    def _compare_json_responses(self, resp_a: dict, resp_b: dict) -> bool:
        """
        Recursively compare two JSON responses to see if they have the same structure.
        Returns True if they are structurally identical (ignoring specific values).
        """
        def compare_structure(obj1, obj2):
            if type(obj1) != type(obj2):
                return False
            if isinstance(obj1, dict):
                if set(obj1.keys()) != set(obj2.keys()):
                    return False
                for key in obj1:
                    if not compare_structure(obj1[key], obj2[key]):
                        return False
                return True
            elif isinstance(obj1, list):
                if len(obj1) != len(obj2):
                    return False
                for item1, item2 in zip(obj1, obj2):
                    if not compare_structure(item1, item2):
                        return False
                return True
            else:
                # Primitives: we don't care about the value, just the type
                return type(obj1) == type(obj2)
        try:
            return compare_structure(resp_a, resp_b)
        except:
            return False

    def test_idor(self, base_url: str, original_id: str, method: str = "GET", data: Optional[Dict] = None) -> List[Dict]:
        if not self.session_a or not self.session_b:
            return []

        # Get baseline response from User A (the owner)
        try:
            resp_a = self.session_a.request(method, base_url, json=data, timeout=5)
            resp_a.raise_for_status()
        except:
            return []

        # Test other IDs (we'll try a few variations)
        results = []
        test_ids = [str(int(original_id) + offset) for offset in [1, 2, 3, -1, -2, -3, 10, 100]]
        for new_id in test_ids:
            new_url = self._replace_id_in_url(base_url, original_id, new_id)
            try:
                # Request with User A's session (should see different resource)
                resp_a_test = self.session_a.request(method, new_url, json=data, timeout=5)
                # Request with User B's session (should see the same if vulnerable)
                resp_b_test = self.session_b.request(method, new_url, json=data, timeout=5)
                if resp_a_test.status_code == 200 and resp_b_test.status_code == 200:
                    # Compare JSON structures
                    try:
                        json_a = resp_a_test.json()
                        json_b = resp_b_test.json()
                        if self._compare_json_responses(json_a, json_b):
                            results.append({
                                'original_url': base_url,
                                'tested_url': new_url,
                                'original_id': original_id,
                                'tested_id': new_id,
                                'status_a': resp_a_test.status_code,
                                'status_b': resp_b_test.status_code,
                                'potential_idor': True,
                                'evidence': 'Identical JSON structure returned for different user sessions'
                            })
                    except:
                        pass
            except:
                continue
        return results

    def scan(self, urls: List[str], progress_callback: Optional[Callable] = None) -> pd.DataFrame:
        import pandas as pd
        all_findings = []
        total = len(urls)

        for idx, url in enumerate(urls):
            if progress_callback:
                progress_callback(idx / total, f"Testing {url} for IDOR...")
            id_infos = self._extract_ids_from_url(url)
            for info in id_infos:
                if info['id_type'] == 'numeric':
                    findings = self.test_idor(
                        info['url'],
                        info['id_value'],
                        method="GET"
                    )
                    all_findings.extend(findings)

        if all_findings:
            df = pd.DataFrame(all_findings)
            return df.drop_duplicates(subset=['original_url', 'tested_id'])
        else:
            return pd.DataFrame(columns=['original_url', 'tested_url', 'original_id', 'tested_id', 'status_a', 'status_b', 'potential_idor', 'evidence'])