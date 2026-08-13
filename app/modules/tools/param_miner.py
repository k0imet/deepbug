# modules/tools/param_miner.py
# Rewritten: correct tool detection (PATH-aware), verified CLI flags for
# x8 / Arjun / ParamSpider, correct output parsers, per-param isolation in
# the built-in fuzzer, and run diagnostics exposed to the UI.
#
# Config keys honored (all optional):
#   tools.paths.x8 / tools.paths.arjun / tools.paths.paramspider
#   tools.wordlists.params            -> extra wordlist file merged into built-in list
#   param_miner.max_urls              -> safety cap (default 50)
#   param_miner.timeout               -> per-tool timeout seconds (default 240)
#   param_miner.x8_concurrency        -> x8 -c value (default 25)
#   param_miner.arjun_threads         -> arjun -t value (default 10)
#   param_miner.osint                 -> run ParamSpider phase (default True)
#
# ParamSpider runs are deduped on the registrable root domain:
#   - legacy builds (expose a --subs flag) scan `*.root/*` for a single
#     `-d root`, covering www + all subdomains in one invocation;
#   - modern builds scan `root/*` (CDX matchType=prefix, host-only), so each
#     deep subdomain still gets its own invocation while the apex runs once.

import asyncio
import glob
import json
import os
import random
import re
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Callable, Set, Tuple, Iterable

from app.utils.url_utils import urlparse
from urllib.parse import parse_qs

import httpx

from app.utils.logger import get_logger

logger = get_logger()


# ---------------------------------------------------------------------
# Async subprocess runner
# ---------------------------------------------------------------------
async def run_command_async(cmd: List[str], timeout: int = 120) -> tuple:
    """Run a command asynchronously, return (stdout, stderr, returncode)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return '', f'Binary not found: {cmd[0]}', 127
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode('utf-8', errors='ignore'), stderr.decode('utf-8', errors='ignore'), proc.returncode
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return '', f'Timeout after {timeout}s', -1


class ParamMiner:
    def __init__(self, config: Dict):
        self.config = config
        pm_cfg = config.get('param_miner', {})

        self.timeout = int(pm_cfg.get('timeout', 240))
        self.x8_concurrency = int(pm_cfg.get('x8_concurrency', 15))
        self.x8_processes = int(pm_cfg.get('x8_processes', 4))
        self.arjun_threads = int(pm_cfg.get('arjun_threads', 10))
        self.max_urls = int(pm_cfg.get('max_urls', 50))
        self.enable_osint = bool(pm_cfg.get('osint', True))

        paths = config.get('tools', {}).get('paths', {})
        self.x8_path = self._resolve_tool('x8', paths.get('x8'))
        self.arjun_path = self._resolve_tool('arjun', paths.get('arjun'))
        self.paramspider_path = self._resolve_tool('paramspider', paths.get('paramspider'))

        self.has_x8 = self.x8_path is not None
        self.has_arjun = self.arjun_path is not None
        self.has_paramspider = self.paramspider_path is not None

        # Cached probe of installed ParamSpider flavor (see _paramspider_includes_subs)
        self._paramspider_subs_cache: Optional[bool] = None

        self.wordlist_dir = Path(__file__).parent / 'data'
        self.wordlist_dir.mkdir(exist_ok=True)
        self.wordlist_path = self._ensure_wordlist()

        # Run diagnostics, surfaced by the UI after each run
        self.last_errors: List[str] = []
        self.last_stats: Dict = {}
        self.big_wordlist: Optional[str] = None

        if self.has_x8:
            logger.info(f"ParamMiner: x8 detected at {self.x8_path} (primary fuzzer)")
        elif self.has_arjun:
            logger.info(f"ParamMiner: Arjun detected at {self.arjun_path} (primary fuzzer)")
        else:
            logger.warning("ParamMiner: no external fuzzer found - using built-in async fuzzer only.")

    # -----------------------------------------------------------------
    # Tool resolution: config path -> PATH -> common install locations
    # -----------------------------------------------------------------
    @staticmethod
    def _resolve_tool(name: str, configured: Optional[str]) -> Optional[Path]:
        candidates = []
        if configured:
            candidates.append(Path(configured).expanduser())
        which = shutil.which(name)
        if which:
            candidates.append(Path(which))
        home = Path.home()
        candidates += [
            home / '.cargo' / 'bin' / name,
            home / '.local' / 'bin' / name,
            home / 'go' / 'bin' / name,
            Path('/usr/local/bin') / name,
            Path('/usr/bin') / name,
        ]
        for c in candidates:
            try:
                if c.is_file() and os.access(c, os.X_OK):
                    return c
            except OSError:
                continue
        return None

    # -----------------------------------------------------------------
    # Built-in high-impact wordlist
    # -----------------------------------------------------------------
    def _ensure_wordlist(self) -> Path:
        path = self.wordlist_dir / 'params.txt'
        if not path.exists() or path.stat().st_size < 500:
            logger.info("Initializing high-impact parameter wordlist...")
            params = [
                # SSRF / Open Redirect
                "url", "uri", "redirect", "redirect_uri", "redirect_url", "return", "return_to", "returnTo",
                "next", "callback", "redir", "goto", "target", "dest", "destination", "out", "view", "dir",
                "continue", "forward", "link", "site", "host", "domain", "feed", "load", "fetch",
                # LFI / Path Traversal / File ops
                "file", "path", "filename", "filepath", "upload", "download", "template", "include",
                "page", "doc", "document", "folder", "root", "pg", "style", "pdf", "read", "load_file",
                # IDOR / Access Control
                "id", "user_id", "uid", "userid", "username", "user", "account", "account_id", "profile",
                "role", "group", "admin", "access", "permission", "auth", "key", "doc_id", "order_id",
                # Injection-prone
                "search", "query", "q", "s", "term", "keywords", "keyword", "comment", "message",
                "content", "body", "text", "title", "name", "input", "value", "data", "cmd", "exec",
                "command", "ping", "ip", "domain_lookup",
                # Debug / Config / Feature flags
                "debug", "test", "testing", "dev", "env", "mode", "config", "setting", "settings",
                "verbose", "log", "trace", "internal", "beta", "feature", "preview", "hidden",
                # Cache poisoning / misc
                "cb", "cachebuster", "cache", "sort", "order", "filter", "lang", "locale", "theme",
                "api_key", "apikey", "format", "type", "action", "method", "output", "callback_url",
                # GraphQL / API
                "mutation", "variables", "operationName", "operation", "fields", "endpoint",
                # OAuth / Auth flow
                "client_id", "client_secret", "grant_type", "scope", "state", "code", "token",
                "access_token", "refresh_token", "response_type", "nonce", "assertion",
                # Mass assignment / business logic
                "price", "amount", "quantity", "discount", "currency", "is_admin", "isAdmin",
                "verified", "status", "active", "enabled", "balance",
            ]
            with open(path, 'w') as f:
                f.write("\n".join(dict.fromkeys(params)))
        return path

    @staticmethod
    def _find_big_wordlist() -> Optional[Path]:
        """
        Auto-borrow Arjun's bundled large.txt (~25,890 params) - a 237-word
        list barely scratches real targets. Searches pip/pipx install locations.
        """
        home = Path.home()
        patterns = [
            str(home / '.local/pipx/venvs/arjun/lib/python*/site-packages/arjun/db/large.txt'),
            str(home / '.local/lib/python*/site-packages/arjun/db/large.txt'),
            '/usr/lib/python*/site-packages/arjun/db/large.txt',
            '/usr/local/lib/python*/site-packages/arjun/db/large.txt',
            '/usr/share/arjun/db/large.txt',
        ]
        for pat in patterns:
            for hit in glob.glob(pat):
                if Path(hit).is_file():
                    return Path(hit)
        return None

    def _load_master_wordlist(self, historical_params: Set[str]) -> List[str]:
        # Curated high-impact list FIRST (builtin fuzzer slices from the front)
        with open(self.wordlist_path, 'r') as f:
            curated = [line.strip() for line in f if line.strip()]
        seen = set(curated)
        words = list(curated)

        def _add(items):
            for w in items:
                if w and w not in seen:
                    seen.add(w)
                    words.append(w)

        extra = self.config.get('tools', {}).get('wordlists', {}).get('params')
        if extra and Path(extra).is_file():
            with open(extra, 'r') as f:
                _add(line.strip() for line in f)

        # Auto-merge a big list (arjun's large.txt) if present on the system
        if not extra:  # explicit user wordlist wins; don't double-load
            big = self._find_big_wordlist()
            if big:
                try:
                    with open(big, 'r') as f:
                        _add(line.strip() for line in f)
                    logger.info(f"ParamMiner: merged big wordlist {big}")
                    self.big_wordlist = str(big)
                except Exception as e:
                    logger.debug(f"Big wordlist load failed: {e}")

        _add(historical_params)
        return words

    # =================================================================
    # ParamSpider target selection (root-domain dedup)
    # =================================================================
    @staticmethod
    def _apex_root(host: str) -> str:
        """Reduce a host to its registrable apex for Wayback domain matching."""
        labels = host.strip().lower().split('.')
        if len(labels) <= 2 or re.match(r'^\d+\.\d+\.\d+\.\d+$', host.strip()):
            return host.strip().lower()
        return ".".join(labels[-2:])

    async def _paramspider_includes_subs(self) -> bool:
        """
        True when a single root-domain invocation covers subdomains.

        Legacy builds (devanshbatham lineage, incl. the 0xKayala fork that
        popularized the "--subs False" README) query `url=*.example.com/*`
        (CDX matchType=domain) by default, so `-d root` returns apex, www and
        all subdomains in one shot. Modern builds (current devanshbatham
        master) query `url=example.com/*` (CDX matchType=prefix - host only).
        Probed once from `-h` output and cached; unknown -> assume modern.
        """
        if self._paramspider_subs_cache is not None:
            return self._paramspider_subs_cache
        legacy = False
        if self.has_paramspider:
            try:
                stdout, _, _ = await run_command_async([str(self.paramspider_path), '-h'], timeout=15)
                legacy = 'subs' in stdout.lower()
            except Exception:
                pass
        self._paramspider_subs_cache = legacy
        return legacy

    @staticmethod
    def _select_paramspider_targets(hosts: Iterable[str], subs_by_root: bool) -> List[str]:
        """Decide which hosts to hand to ParamSpider.

        Legacy build (root covers www + subdomains): one run per distinct root.
        Modern build (host-only prefix): apex runs once per root; each deep
        subdomain still runs, except ``www.*`` which the Wayback SURT index
        aliases to the apex and would duplicate the apex results.
        """
        host_list = sorted({h for h in hosts if h})
        roots = sorted({ParamMiner._apex_root(h) for h in host_list})
        if subs_by_root:
            return roots
        deep = sorted(h for h in host_list if h not in roots and not h.lower().startswith('www.'))
        return roots + deep

    # =================================================================
    # OSINT Phase: ParamSpider (historical URLs from Wayback)
    # =================================================================
    async def _run_paramspider_osint(self, targets: List[str]) -> Tuple[Set[str], List[str]]:
        """
        Returns (historical_param_names, archived_urls_with_params).
        Both are exposed to the UI - on WAF-fronted targets the historical
        data is often the ONLY yield, so it must never be swallowed silently.
        `targets` are pre-deduped root domains (+ deep subdomains for modern
        ParamSpider builds) by `_select_paramspider_targets`.
        """
        if not self.has_paramspider or not self.enable_osint:
            return set(), []

        historical_params: Set[str] = set()
        historical_urls: Set[str] = set()
        for domain in sorted(targets):
            logger.info(f"ParamSpider OSINT on: {domain}")
            # -s streams URLs to stdout; banner lines never start with http
            cmd = [str(self.paramspider_path), '-d', domain, '-s']
            stdout, stderr, ret = await run_command_async(cmd, timeout=180)

            found = 0
            for line in stdout.splitlines():
                line = line.strip()
                if line.startswith('http') and '?' in line:
                    try:
                        historical_params.update(parse_qs(urlparse(line).query).keys())
                        historical_urls.add(line)
                        found += 1
                    except Exception:
                        continue

            # Legacy fallback: output file in ./results/<domain>.txt
            legacy = Path(f"results/{domain}.txt")
            if found == 0 and legacy.exists():
                try:
                    for line in legacy.read_text(errors='ignore').splitlines():
                        line = line.strip()
                        if line.startswith('http') and '?' in line:
                            historical_params.update(parse_qs(urlparse(line).query).keys())
                            historical_urls.add(line)
                    legacy.unlink()
                except Exception as e:
                    logger.debug(f"Legacy ParamSpider output error: {e}")

            if ret != 0 and found == 0:
                msg = f"ParamSpider failed on {domain}: {stderr.strip()[:200] or 'no output (wayback unreachable?)'}"
                logger.warning(msg)
                self.last_errors.append(msg)

        logger.info(f"ParamSpider OSINT: {len(historical_params)} params from {len(historical_urls)} archived URLs.")
        # Cap URL list - the UI and downstream scanners don't need 50k wayback links
        return historical_params, sorted(historical_urls)[:1000]

    # =================================================================
    # Active Fuzzing: x8 (primary - Rust, fast, accurate)
    # =================================================================
    @staticmethod
    def _parse_x8_baseline(stdout: str) -> Optional[str]:
        """Extract baseline status from x8 console: 'GET <url> (<status>) [<size>]'."""
        m = re.search(r'^(?:GET|POST|PUT)\s+\S+\s+\((\d{3})\)', stdout, re.MULTILINE)
        return m.group(1) if m else None

    async def _run_x8(self, url: str, wordlist_path: str, semaphore: asyncio.Semaphore) -> List[Dict]:
        async with semaphore:
            out_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False).name
            try:
                cmd = [
                    str(self.x8_path),
                    '-u', url,
                    '-w', wordlist_path,
                    '-X', 'GET',
                    '-c', str(self.x8_concurrency),
                    '--timeout', '15',
                    '--mimic-browser',  # browser-like headers: gets past some WAF fingerprints
                    '--disable-progress-bar',
                    '--disable-colors',
                    '-v', '0',
                    '-o', out_file,
                    '-O', 'json',
                ]
                stdout, stderr, ret = await run_command_async(cmd, timeout=self.timeout)

                # Known x8 failure mode: trustdns resolution issues -> retry without it
                if (ret != 0 or not os.path.exists(out_file) or os.path.getsize(out_file) == 0) \
                        and 'dns' in (stderr + stdout).lower():
                    cmd.insert(-4, '--disable-trustdns')
                    stdout, stderr, ret = await run_command_async(cmd, timeout=self.timeout)

                baseline = self._parse_x8_baseline(stdout)
                if baseline:
                    self._x8_baselines[url] = baseline

                # Keep a bounded tail of x8's own console output for the UI
                # diagnostics ("did x8 actually run? what did it say?").
                stdout_tail = (stdout or '').strip()[-400:]
                if stdout_tail:
                    self._x8_stdout = getattr(self, '_x8_stdout', {})
                    if len(self._x8_stdout) > 40:
                        self._x8_stdout.clear()
                    self._x8_stdout[url] = stdout_tail

                if not os.path.exists(out_file) or os.path.getsize(out_file) == 0:
                    if ret != 0:
                        self.last_errors.append(f"x8 failed on {url}: {stderr.strip()[:200]}")
                    return []

                with open(out_file, 'r') as f:
                    data = json.load(f)

                results = []
                # x8 json: [{method, url, status, size, found_params:[{name, value, diffs, status, size, reason_kind}], injection_place}]
                for entry in data if isinstance(data, list) else []:
                    for p in entry.get('found_params', []):
                        results.append({
                            'parameter': p.get('name', ''),
                            'value': p.get('value'),
                            'status': p.get('status', ''),
                            'reason': p.get('reason_kind', ''),
                            'diffs': p.get('diffs', ''),
                            'injection_place': entry.get('injection_place', 'Path'),
                            'method': entry.get('method', 'GET'),
                            'tool': 'x8',
                            'source_url': entry.get('url', url),
                        })
                return [r for r in results if r['parameter']]
            except json.JSONDecodeError as e:
                self.last_errors.append(f"x8 output parse error on {url}: {e}")
                return []
            except Exception as e:
                logger.warning(f"x8 error on {url}: {e}")
                self.last_errors.append(f"x8 error on {url}: {e}")
                return []
            finally:
                if os.path.exists(out_file):
                    os.unlink(out_file)

    # -----------------------------------------------------------------
    # x8 self-test: prove the binary + flags + output parse all work.
    # Returns raw diagnostics the UI can render verbatim.
    # -----------------------------------------------------------------
    def x8_self_test(self, url: str) -> Dict:
        if not self.has_x8:
            return {'ok': False, 'error': 'x8 binary not found (tools.paths.x8 / PATH)'}
        out_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False).name
        try:
            cmd = [
                str(self.x8_path),
                '-u', url,
                '-w', str(self.wordlist_path),
                '-X', 'GET',
                '-c', '5',
                '--timeout', '10',
                '--mimic-browser',
                '--disable-progress-bar',
                '--disable-colors',
                '-v', '0',
                '-o', out_file,
                '-O', 'json',
            ]
            import asyncio as _ai
            stdout, stderr, ret = _ai.run(run_command_async(cmd, timeout=120))
            parsed = []
            if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
                try:
                    with open(out_file, 'r') as f:
                        data = json.load(f)
                    parsed = [
                        {'url': e.get('url', url),
                         'found_params': [p.get('name') for p in e.get('found_params', []) if p.get('name')]}
                        for e in data if isinstance(e, dict)
                    ]
                except json.JSONDecodeError as e:
                    parsed = [{'error': f'JSON parse failed: {e}'}]
            return {
                'ok': ret == 0,
                'url': url,
                'exit_code': ret,
                'stdout': (stdout or '').strip()[-1500:],
                'stderr': (stderr or '').strip()[-800:],
                'json_output': parsed,
            }
        except Exception as e:
            return {'ok': False, 'url': url, 'error': f'{type(e).__name__}: {e}'}
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    # =================================================================
    # Active Fuzzing: Arjun (fallback)
    # =================================================================
    async def _run_arjun(self, url: str, wordlist_path: str, semaphore: asyncio.Semaphore) -> List[Dict]:
        async with semaphore:
            out_file = tempfile.NamedTemporaryFile(suffix='.json', delete=False).name
            try:
                cmd = [
                    str(self.arjun_path),
                    '-u', url,
                    '-w', wordlist_path,
                    '-m', 'GET',
                    '-t', str(self.arjun_threads),
                    '-T', '15',
                    '-q',
                    '-oJ', out_file,
                ]
                stdout, stderr, ret = await run_command_async(cmd, timeout=self.timeout)

                if not os.path.exists(out_file) or os.path.getsize(out_file) == 0:
                    if ret != 0:
                        self.last_errors.append(f"Arjun failed on {url}: {stderr.strip()[:200]}")
                    return []

                with open(out_file, 'r') as f:
                    data = json.load(f)

                results = []
                for target, payload in data.items():
                    # Arjun 2.x: {"url": {"method": ..., "params": [...]}}
                    # legacy:    {"url": ["p1", "p2"]}
                    if isinstance(payload, dict):
                        names = payload.get('params', [])
                    elif isinstance(payload, list):
                        names = payload
                    else:
                        names = []
                    for name in names:
                        results.append({
                            'parameter': name,
                            'value': None,
                            'status': '',
                            'reason': 'anomaly',
                            'tool': 'arjun',
                            'source_url': target,
                        })
                return results
            except json.JSONDecodeError as e:
                self.last_errors.append(f"Arjun output parse error on {url}: {e}")
                return []
            except Exception as e:
                logger.warning(f"Arjun error on {url}: {e}")
                self.last_errors.append(f"Arjun error on {url}: {e}")
                return []
            finally:
                if os.path.exists(out_file):
                    os.unlink(out_file)

    # =================================================================
    # Built-in async fuzzer (no external tools required)
    # Two-phase: chunked probes -> binary isolation of anomalous chunks
    # =================================================================
    async def _baseline_request(self, client: httpx.AsyncClient, url: str) -> Optional[Dict]:
        try:
            canary = f"deepbug_{random.randint(10000, 99999)}"
            resp = await client.get(url, params={canary: canary})
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "canary": canary,
            }
        except Exception:
            return None

    async def _probe_params(self, client: httpx.AsyncClient, url: str, params: List[str]) -> Optional[Dict]:
        """Send params with unique reflected canaries; classify anomaly vs baseline."""
        try:
            values = {p: f"DBUG{p}{random.randint(100, 999)}" for p in params}
            resp = await client.get(url, params=values)
            reflected = [p for p, v in values.items() if v in resp.text]
            return {
                "status": resp.status_code,
                "length": len(resp.text),
                "reflected": reflected,
            }
        except Exception:
            return None

    async def _isolate_chunk(self, client: httpx.AsyncClient, url: str, chunk: List[str], base: Dict) -> List[Dict]:
        """Binary-split an anomalous chunk down to the individual parameter(s)."""
        found = []
        if len(chunk) == 1:
            probe = await self._probe_params(client, url, chunk)
            if probe is None:
                return found
            reason = []
            if probe["status"] != base["status"]:
                reason.append(f"status {base['status']}->{probe['status']}")
            if abs(probe["length"] - base["length"]) > 50:
                reason.append(f"length {base['length']}->{probe['length']}")
            if chunk[0] in probe["reflected"]:
                reason.append("reflected")
            if reason:
                found.append({
                    'parameter': chunk[0],
                    'value': None,
                    'status': probe["status"],
                    'reason': ", ".join(reason),
                    'tool': 'builtin_fuzzer',
                    'source_url': url,
                })
            return found

        mid = len(chunk) // 2
        for half in (chunk[:mid], chunk[mid:]):
            probe = await self._probe_params(client, url, half)
            if probe is None:
                continue
            anomalous = (probe["status"] != base["status"]
                         or abs(probe["length"] - base["length"]) > 50
                         or probe["reflected"])
            if anomalous:
                # reflections identify their param directly
                for p in probe["reflected"]:
                    found.append({
                        'parameter': p,
                        'value': None,
                        'status': probe["status"],
                        'reason': 'reflected',
                        'tool': 'builtin_fuzzer',
                        'source_url': url,
                    })
                remaining = [p for p in half if p not in probe["reflected"]]
                if remaining and (probe["status"] != base["status"]
                                  or abs(probe["length"] - base["length"]) > 50):
                    found.extend(await self._isolate_chunk(client, url, remaining, base))
        return found

    async def _fallback_async_fuzzer(self, client: httpx.AsyncClient, url: str,
                                     params_to_test: List[str], semaphore: asyncio.Semaphore) -> List[Dict]:
        results: List[Dict] = []
        async with semaphore:
            base = await self._baseline_request(client, url)
            if not base:
                self.last_errors.append(f"builtin fuzzer: no baseline for {url} (unreachable?)")
                return results

            chunk_size = 25
            chunks = [params_to_test[i:i + chunk_size] for i in range(0, len(params_to_test), chunk_size)]

            for chunk in chunks:
                probe = await self._probe_params(client, url, chunk)
                if probe is None:
                    continue
                anomalous = (probe["status"] != base["status"]
                             or abs(probe["length"] - base["length"]) > 50
                             or probe["reflected"])
                if anomalous:
                    results.extend(await self._isolate_chunk(client, url, chunk, base))
                await asyncio.sleep(random.uniform(0.05, 0.15))

            # dedupe within this url
            seen = set()
            unique = []
            for r in results:
                if r['parameter'] not in seen:
                    seen.add(r['parameter'])
                    unique.append(r)
            return unique

    # =================================================================
    # Main async entry
    # =================================================================
    async def mine_parameters(self, urls: List[str],
                              progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, List[Dict]]:
        self.last_errors = []
        self.last_stats = {}
        self._x8_baselines: Dict[str, str] = {}
        self.last_historical_params: List[str] = []
        self.last_historical_urls: List[str] = []
        if not urls:
            return {}

        # Safety cap: active fuzzing is noisy; keep it focused
        if len(urls) > self.max_urls:
            logger.warning(f"ParamMiner: {len(urls)} URLs supplied, capped to {self.max_urls} (param_miner.max_urls)")
            urls = urls[:self.max_urls]

        # 1. OSINT phase - ParamSpider only on deduped root domains, not on
        # every pool host (apex + www + subdomains collapse into one run).
        hosts = sorted({urlparse(u).netloc.split(':')[0] for u in urls if urlparse(u).netloc})
        ps_targets = self._select_paramspider_targets(
            hosts, await self._paramspider_includes_subs())
        if progress_callback:
            progress_callback(0.05, f"Gathering historical parameters (ParamSpider OSINT on {len(ps_targets)} target(s))...")
        if self.enable_osint and ps_targets:
            historical_params, self.last_historical_urls = await self._run_paramspider_osint(ps_targets)
            self.last_historical_params = sorted(historical_params)
        else:
            historical_params = set()

        # 2. Master wordlist -> temp file for external tools
        master_wordlist = self._load_master_wordlist(historical_params)
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as tmp:
            tmp.write("\n".join(master_wordlist))
            custom_wordlist_path = tmp.name

        engine = 'x8' if self.has_x8 else ('arjun' if self.has_arjun else 'builtin')
        self.last_stats = {
            'engine': engine,
            'urls_tested': len(urls),
            'wordlist_size': len(master_wordlist),
            'historical_params': len(historical_params),
            'historical_urls': len(self.last_historical_urls),
            'big_wordlist': self.big_wordlist,
        }
        logger.info(f"ParamMiner: engine={engine}, {len(urls)} URLs, wordlist={len(master_wordlist)}")

        # 3. Active fuzzing with real per-URL progress
        semaphore = asyncio.Semaphore(self.x8_processes)
        results: Dict[str, List[Dict]] = {}
        done_count = 0
        total = len(urls)

        async def run_one(client: httpx.AsyncClient, url: str) -> List[Dict]:
            nonlocal done_count
            if self.has_x8:
                res = await self._run_x8(url, custom_wordlist_path, semaphore)
            elif self.has_arjun:
                res = await self._run_arjun(url, custom_wordlist_path, semaphore)
            else:
                # builtin is request-heavy per param: cap at the best 2000 (curated list comes first)
                res = await self._fallback_async_fuzzer(client, url, master_wordlist[:2000], semaphore)
            done_count += 1
            if progress_callback:
                progress_callback(0.1 + 0.85 * (done_count / total),
                                  f"[{done_count}/{total}] {url} -> {len(res)} params")
            return res

        # follow_redirects=False: 3xx deltas (e.g. ?next= open redirects) stay visible to the fuzzer
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=False) as client:
            tasks = [run_one(client, u) for u in urls]
            all_scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, scan_result in zip(urls, all_scan_results):
            if isinstance(scan_result, Exception):
                logger.error(f"Mining failed on {url}: {scan_result}")
                self.last_errors.append(f"{url}: {scan_result}")
                continue
            if scan_result:
                unique = {r['parameter']: r for r in scan_result}.values()
                results[url] = list(unique)
                logger.info(f"{url}: {len(unique)} hidden parameters")

        self.last_stats['urls_with_findings'] = len(results)
        self.last_stats['total_params'] = sum(len(v) for v in results.values())

        # Baseline analysis: explains WHY a run found nothing
        if self._x8_baselines:
            from collections import Counter
            self.last_stats['x8_baselines'] = dict(Counter(self._x8_baselines.values()))
            blocked = sum(1 for s in self._x8_baselines.values() if s in ('401', '403', '406', '429'))
            if results:
                self.last_stats['hint'] = None
            elif blocked >= len(self._x8_baselines) * 0.6:
                self.last_stats['hint'] = (
                    f"{blocked}/{len(self._x8_baselines)} URLs returned {sorted(set(self._x8_baselines.values()))} "
                    "baseline - a WAF/auth wall is flattening every response, so no parameter can stand out. "
                    "Re-run with session cookies (authenticated context) or probe these URLs manually in Burp."
                )
            else:
                self.last_stats['hint'] = (
                    "Targets responded normally but no parameter changed any response. "
                    "Try: authenticated requests, POST method mining, or a bigger/custom wordlist."
                )

        if os.path.exists(custom_wordlist_path):
            os.unlink(custom_wordlist_path)

        if progress_callback:
            progress_callback(1.0, f"Done: {self.last_stats['total_params']} parameters on {len(results)} URLs")

        return results

    # =================================================================
    # Synchronous wrapper for Streamlit
    # =================================================================
    def mine_parameters_sync(self, urls: List[str],
                             progress_callback: Optional[Callable[[float, str], None]] = None) -> Dict[str, List[Dict]]:
        """Sync entry point - safe inside Streamlit's running event loop."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(asyncio.run, self.mine_parameters(urls, progress_callback))
                return future.result()
        return asyncio.run(self.mine_parameters(urls, progress_callback))