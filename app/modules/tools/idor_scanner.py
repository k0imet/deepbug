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
        """Extract potential ID parameters from a URL (path and query).

        Generalised: any numeric/uuid path segment (excluding `/v<N>/` version
        prefixes) plus a wide query-param name set - catches IDs that the old
        hardcoded-path list missed (e.g. `/api/Users/1`)."""
        findings = []
        # numeric path segments, skipping version prefixes (/v1/, /v2/ ...)
        for match in re.finditer(r'/(?!v\d+/)(\d{1,12})(?:/|$)', url):
            findings.append({'url': url, 'id_value': match.group(1),
                             'id_type': 'numeric', 'position': 'path'})
        # uuid path segments
        for match in re.finditer(
                r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)',
                url, re.IGNORECASE):
            findings.append({'url': url, 'id_value': match.group(1),
                             'id_type': 'uuid', 'position': 'path'})
        # query params (wide name set)
        for match in re.finditer(
                r'[?&](?:id|user_id|uid|order_id|account_id|profile_id|booking_id|'
                r'item_id|product_id|pid|oid|uuid|key|ref|token|user|owner|'
                r'customer|client|resource_id)=([a-zA-Z0-9-]+)', url, re.IGNORECASE):
            findings.append({'url': url, 'id_value': match.group(1),
                             'id_type': 'query', 'position': 'query'})
        # dedupe by (position, value)
        seen = set()
        out = []
        for f in findings:
            k = (f['position'], f['id_value'])
            if k not in seen:
                seen.add(k)
                out.append(f)
        return out

    def _replace_id_in_url(self, url: str, old_id: str, new_id: str,
                           position: str = 'path') -> str:
        """Replace the ID in the PATH only (never the host/port - old code
        corrupted 127.0.0.1 -> 227.0.0.1 by replacing the first '1')."""
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        parts = urlsplit(url)
        path = parts.path
        query = parts.query
        if position == 'query':
            pairs = [(k, new_id if v == old_id else v)
                     for k, v in parse_qsl(parts.query, keep_blank_values=True)]
            query = urlencode(pairs, doseq=True)
        else:
            path = re.sub(rf'(?<=/){re.escape(old_id)}(?=/|$)', new_id, parts.path)
        return urlunsplit((parts.scheme, parts.netloc, path,
                           query, parts.fragment))

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

    def test_idor(self, base_url: str, original_id: str, method: str = "GET",
                  data: Optional[Dict] = None, position: str = 'path') -> List[Dict]:
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
            new_url = self._replace_id_in_url(base_url, original_id, new_id, position)
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
                if info['id_type'] == 'numeric' or (
                        info['position'] == 'query' and info['id_value'].isdigit()):
                    findings = self.test_idor(
                        info['url'],
                        info['id_value'],
                        method="GET",
                        position=info['position'],
                    )
                    all_findings.extend(findings)

        if all_findings:
            df = pd.DataFrame(all_findings)
            return df.drop_duplicates(subset=['original_url', 'tested_id'])
        else:
            return pd.DataFrame(columns=['original_url', 'tested_url', 'original_id', 'tested_id', 'status_a', 'status_b', 'potential_idor', 'evidence'])
