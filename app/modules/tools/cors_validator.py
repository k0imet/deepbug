# modules/tools/cors_validator.py
# CORS misconfiguration VALIDATION - live confirmation of permissive
# cross-origin policies, grounded in the standard abuse model:
#
#   CONFIRMED  - server echoes OUR arbitrary Origin in Access-Control-Allow-Origin
#                AND sends Access-Control-Allow-Credentials: true. An attacker page
#                can read authenticated cross-origin responses (read arbitrary data).
#   POTENTIAL  - arbitrary Origin echoed, but no credentials header: still usable
#                to read PUBLIC responses / CSRF-with-ability-to-read (low impact).
#   INFO       - Access-Control-Allow-Origin: * together with credentials: true -
#                browsers refuse to apply the credentials flag with a wildcard, so
#                this is NOT exploitable (classic tool false positive).
#
# Probes are read-only: GET + OPTIONS preflight with a hostile Origin header.
# Sources: freecodecamp CORS guide, invicti misconfigured-ACAO article, offensive360
# wildcard-credentials breakdown (see corpus).
#
# Config (all optional):
#   cors_validator.max_urls       -> cap URLs checked (default 250)
#   cors_validator.timeout        -> per-request budget (default 8)
#   cors_validator.origins        -> hostile Origin values tested (defaults below)

import asyncio
import re
from typing import Dict, List, Optional, Callable

import aiohttp

from app.utils.logger import get_logger

logger = get_logger()

_DEFAULT_ORIGINS = [
    "https://deepbug-evil.example",
    "https://deepbug-evil.example.evil.com",
    "null",
    "https://deepbug-evil.example:8443",
]

_MAX_ACAO = re.compile(r'^https?://[^\s,]+$')


class CORSValidator:
    def __init__(self, config: Dict):
        cfg = config.get('cors_validator', {}) if isinstance(config, dict) else {}
        self.max_urls = int(cfg.get('max_urls', 250))
        self.timeout = float(cfg.get('timeout', 8))
        self.origins: List[str] = [str(o) for o in cfg.get('origins') or _DEFAULT_ORIGINS]
        self.last_errors: List[str] = []

    @staticmethod
    def _classify(origin: str, acao: str, acac: str, allow_methods: str) -> Optional[Dict]:
        acao = (acao or '').strip()
        acac = (acac or '').strip().lower() == 'true'
        if not acao:
            return None  # no CORS policy at all
        if acao == '*':
            if acac:
                return {'Result': 'INFO', 'Class': 'wildcard-credentials',
                        'Sink': f'AC-Allow-Origin: * + AC-Credentials: true (ignored by browsers)',
                        'Method': 'header-probe'}
            return None  # open API with wildcard - by design, not a finding
        # explicit echo of our origin (or a close suffix variant)?
        echoed = acao == origin
        if not echoed and _MAX_ACAO.match(acao):
            # server echoes some other concrete origin - nothing we control
            if not (origin.replace('https://', '').endswith('.' + acao.replace('https://', ''))):
                return None
        if echoed or origin.lower() in (acao or '').lower():
            if acac:
                return {'Result': 'CONFIRMED', 'Class': 'cors-credentials',
                        'Sink': f'ACAO echoes {origin[:40]} + AC-Credentials: true',
                        'Method': 'header-probe'}
            return {'Result': 'POTENTIAL', 'Class': 'cors-reflection',
                    'Sink': f'ACAO echoes {origin[:40]} (no credentials)',
                    'Method': 'header-probe'}
        return None

    async def _probe_origin(self, session: aiohttp.ClientSession, url: str,
                            origin: str) -> Optional[Dict]:
        hdr = {'Origin': origin,
               'Access-Control-Request-Method': 'GET'}
        try:
            async with session.get(url, headers=hdr, timeout=self.timeout,
                                   allow_redirects=False) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                methods = resp.headers.get('Access-Control-Allow-Methods', '')
                row = self._classify(origin, acao, acac, methods)
                if not row:
                    return None
                row['URL'] = url
                row['Origin'] = origin
                row['ACAO'] = acao[:80]
                row['ACAC'] = acac
                row['Evidence'] = (f"GET {url} with Origin: {origin} -> "
                                   f"ACAO: {acao[:60]} ACAC: {acac or '-'} AMethods: {methods[:40] or '-'}")
                return row
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logger.debug(f"CORS probe failed {url}: {e}")
            return None

    async def _probe_preflight(self, session: aiohttp.ClientSession, url: str,
                               origin: str) -> Optional[Dict]:
        """OPTIONS preflight: media/JSON APIs only answer preflight with headers."""
        hdr = {'Origin': origin,
               'Access-Control-Request-Method': 'POST',
               'Access-Control-Request-Headers': 'content-type'}
        try:
            async with session.options(url, headers=hdr, timeout=self.timeout,
                                       allow_redirects=False) as resp:
                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                methods = resp.headers.get('Access-Control-Allow-Methods', '')
                row = self._classify(origin, acao, acac, methods)
                if not row:
                    return None
                row['URL'] = url
                row['Origin'] = origin
                row['ACAO'] = acao[:80]
                row['ACAC'] = acac
                row['Evidence'] = (f"OPTIONS {url} (preflight) Origin: {origin} -> "
                                   f"ACAO: {acao[:60]} ACAC: {acac or '-'} AMethods: {methods[:40] or '-'}")
                return row
        except asyncio.TimeoutError:
            return None
        except Exception as e:
            logger.debug(f"CORS preflight probe failed {url}: {e}")
            return None

    async def _validate_all(self, urls: List[str],
                            progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        results: List[Dict] = []
        seen: set = set()
        total = len(urls)
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout * 4)) as session:
            for idx, url in enumerate(urls):
                if progress_callback:
                    progress_callback(idx / total, f"[{idx + 1}/{total}] {url}")
                for origin in self.origins:
                    for probe in (self._probe_origin, self._probe_preflight):
                        row = await probe(session, url, origin)
                        if not row:
                            continue
                        key = (url, origin, row['Class'])
                        if key in seen:
                            continue
                        seen.add(key)
                        results.append(row)
                if progress_callback:
                    progress_callback((idx + 1) / total,
                                      f"[{idx + 1}/{total}] {url} -> {len([r for r in results if r['URL'] == url])} hit(s)")
        if progress_callback:
            confirmed = len([r for r in results if r['Result'] == 'CONFIRMED'])
            progress_callback(1.0, f"Done: {confirmed} confirmed, "
                                   f"{len([r for r in results if r['Result'] == 'POTENTIAL'])} potential")
        return results

    def validate_sync(self, urls: List[str],
                      progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict]:
        """Synchronous entry - safe inside Streamlit's running event loop."""
        self.last_errors = []
        if not urls:
            return []
        urls = list(dict.fromkeys(urls))[:self.max_urls]
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(asyncio.run, self._validate_all(urls, progress_callback))
                return future.result()
        return asyncio.run(self._validate_all(urls, progress_callback))