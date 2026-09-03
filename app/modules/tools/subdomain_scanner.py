# modules/tools/subdomain_scanner.py
# Hardened version with input sanitization, wildcard detection, scope enforcement,
# permutation scanning, CT log integration, and improved error handling.

import os
import re
import json
import tempfile
import asyncio
import aiohttp
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Union, Set
import pandas as pd

from app.utils.logger import get_logger
from app.utils.subprocess_runner import run_command
# Dual import keeps both `modules.X` (streamlit pages) and `app.modules.X`
# (headless tests) working.
try:
    from app.modules.utils import parse_nuclei_output, load_config
except ImportError:  # pragma: no cover - streamlit pages import as `modules.utils`
    from modules.utils import parse_nuclei_output, load_config

logger = get_logger()

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
WILDCARD_CHECK_COUNT = 5       # Number of random subdomains to test for wildcard
WILDCARD_THRESHOLD = 0.8       # If >= 80% resolve to same IP, consider it wildcard
MAX_DOMAIN_LEN = 253           # RFC 1035 max domain length
VALID_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)
RAND_SUBDOMAIN_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'


class ScopeValidator:
    """
    Enforces bug bounty scope rules.
    Supports: exact match, wildcard subdomain (*.example.com), and exclusion lists.
    """

    def __init__(self, scope_rules: Optional[List[str]] = None):
        self.in_scope: Set[str] = set()
        self.wildcard_scope: Set[str] = set()
        self.exclusions: Set[str] = set()

        if scope_rules:
            for rule in scope_rules:
                rule = rule.strip().lower()
                if rule.startswith('!'):
                    self.exclusions.add(rule[1:])
                elif rule.startswith('*.'):
                    self.wildcard_scope.add(rule[2:])
                else:
                    self.in_scope.add(rule)

    def is_in_scope(self, subdomain: str) -> bool:
        subdomain = subdomain.lower().strip()

        # Check exclusions first
        if subdomain in self.exclusions:
            return False
        for ex in self.exclusions:
            if subdomain.endswith('.' + ex) or subdomain == ex:
                return False

        # No scope rules = everything in scope (default behavior)
        if not self.in_scope and not self.wildcard_scope:
            return True

        # Exact match
        if subdomain in self.in_scope:
            return True

        # Wildcard match
        for wild in self.wildcard_scope:
            if subdomain == wild or subdomain.endswith('.' + wild):
                return True

        return False

    def filter_subdomains(self, subdomains: List[str]) -> List[str]:
        return [s for s in subdomains if self.is_in_scope(s)]


class SubdomainScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.subfinder_path = Path(self.config['tools']['paths'].get('subfinder', 'subfinder'))
        self.dnsx_path = Path(self.config['tools']['paths'].get('dnsx', 'dnsx'))
        self.httpx_path = Path(self.config['tools']['paths'].get('httpx', 'httpx'))
        self.amass_path = Path(self.config['tools']['paths'].get('amass', 'amass'))
        self.nuclei_path = Path(self.config['tools']['paths'].get('nuclei', 'nuclei'))
        self.nuclei_templates_path = Path(self.config['tools']['paths'].get('nuclei_templates', ''))

        # Optional tools for enhanced recon
        self.dnsgen_path = Path(self.config['tools']['paths'].get('dnsgen', 'dnsgen'))
        self.massdns_path = Path(self.config['tools']['paths'].get('massdns', 'massdns'))
        self.altdns_path = Path(self.config['tools']['paths'].get('altdns', 'altdns'))

        # Scope rules from config
        scope_rules = config.get('scope', {}).get('subdomains', [])
        self.scope_validator = ScopeValidator(scope_rules)

        # Chaos dataset (ProjectDiscovery) — optional, keyed via config or env
        self.chaos_api_key = (
            config.get('tools', {}).get('chaos_api_key')
            or config.get('chaos_api_key')
            or os.environ.get('CHAOS_API_KEY')
            or os.environ.get('PDCP_API_KEY')
            or ""
        ).strip()

        # Wildcard detection cache
        self._wildcard_ips: Dict[str, str] = {}

        self._check_tool_paths()

    def _check_tool_paths(self):
        required_tools = {
            "subfinder": self.subfinder_path,
            "dnsx": self.dnsx_path,
            "httpx": self.httpx_path,
            "amass": self.amass_path,
            "nuclei": self.nuclei_path,
        }
        for tool_name, path_obj in required_tools.items():
            if not path_obj.exists():
                logger.warning(f"SubdomainScanner: {tool_name} not found at {path_obj}. Related features disabled.")

        if not self.nuclei_templates_path.is_dir():
            logger.warning(f"Nuclei templates directory not found at {self.nuclei_templates_path}. Takeover scan may fail.")

    # ------------------------------------------------------------------
    # Input Sanitization
    # ------------------------------------------------------------------
    @staticmethod
    def _sanitize_domain(domain: str) -> str:
        """
        Sanitize and validate domain input.
        Prevents command injection and ensures RFC-compliant domain names.

        Raises:
            ValueError: If domain is invalid or contains dangerous characters.
        """
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")

        domain = domain.strip().lower()

        # Block shell metacharacters and path traversal
        dangerous_chars = set(';|&`$(){}[]<>\\!#*?')
        if any(c in dangerous_chars for c in domain):
            raise ValueError(f"Domain contains invalid characters: {domain}")

        # Length check
        if len(domain) > MAX_DOMAIN_LEN:
            raise ValueError(f"Domain exceeds maximum length of {MAX_DOMAIN_LEN}")

        # Validate format
        if not VALID_DOMAIN_RE.match(domain):
            raise ValueError(f"Invalid domain format: {domain}")

        # Prevent IP addresses being passed as domains
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', domain):
            raise ValueError(f"IP addresses are not valid domains: {domain}")

        return domain

    @staticmethod
    def _sanitize_subdomain_list(subdomains: List[str]) -> List[str]:
        """Sanitize a list of subdomains, dropping invalid entries."""
        valid = []
        for s in subdomains:
            try:
                clean = SubdomainScanner._sanitize_domain(s)
                valid.append(clean)
            except ValueError as e:
                logger.debug(f"Dropping invalid subdomain: {e}")
        return valid

    # ------------------------------------------------------------------
    # Wildcard Detection
    # ------------------------------------------------------------------
    def _detect_wildcard(self, domain: str) -> Optional[str]:
        """
        Detect if a domain uses wildcard DNS (*.domain.com -> IP).
        Returns the wildcard IP if detected, None otherwise.
        """
        if domain in self._wildcard_ips:
            return self._wildcard_ips[domain]

        if not self.dnsx_path.is_file():
            return None

        import random
        import string

        # Generate random subdomains
        random_subs = [
            ''.join(random.choices(RAND_SUBDOMAIN_CHARS, k=10)) + '.' + domain
            for _ in range(WILDCARD_CHECK_COUNT)
        ]

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(random_subs))

            cmd = [str(self.dnsx_path), '-l', temp_file, '-a', '-silent']
            stdout, stderr, ret = run_command(cmd, timeout=60)

            if ret != 0:
                return None

            # Count resolutions per IP
            ip_counts: Dict[str, int] = {}
            total_resolved = 0
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # dnsx -a output format: subdomain [ip1,ip2]
                if '[' in line and ']' in line:
                    ip_part = line[line.find('[')+1:line.find(']')]
                    ips = [ip.strip() for ip in ip_part.split(',') if ip.strip()]
                    for ip in ips:
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
                    total_resolved += 1

            if total_resolved == 0:
                return None

            # Check if any IP resolves >= threshold
            for ip, count in ip_counts.items():
                if count / WILDCARD_CHECK_COUNT >= WILDCARD_THRESHOLD:
                    self._wildcard_ips[domain] = ip
                    logger.info(f"Wildcard detected for {domain} -> {ip} ({count}/{WILDCARD_CHECK_COUNT})")
                    return ip

            self._wildcard_ips[domain] = None
            return None

        except Exception as e:
            logger.warning(f"Wildcard detection failed for {domain}: {e}")
            return None
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    def _filter_wildcard_from_dnsx(self, dns_results: List[Dict[str, str]], domain: str) -> List[Dict[str, str]]:
        """
        Wildcard-filter an EXISTING dnsx result set - avoids a second full
        resolution pass (the old flow resolved every subdomain twice).
        """
        wildcard_ip = self._detect_wildcard(domain)
        if not wildcard_ip or not dns_results:
            return dns_results

        filtered = []
        dropped = 0
        for r in dns_results:
            ips = [i.strip() for i in str(r.get('ip', '')).split(',') if i.strip()]
            if wildcard_ip in ips:
                dropped += 1
                logger.debug(f"Filtering wildcard subdomain: {r.get('hostname')} -> {wildcard_ip}")
            else:
                filtered.append(r)
        if dropped:
            logger.info(f"Wildcard filtering: dropped {dropped}/{len(dns_results)} resolved hosts")
        return filtered

    def _filter_wildcard_subdomains(self, subdomains: List[str], domain: str) -> List[str]:
        """Remove subdomains that resolve to the wildcard IP."""
        wildcard_ip = self._detect_wildcard(domain)
        if not wildcard_ip:
            return subdomains

        if not self.dnsx_path.is_file():
            return subdomains

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(subdomains) + '\n')

            cmd = [str(self.dnsx_path), '-l', temp_file, '-a', '-silent']
            stdout, stderr, ret = run_command(cmd, timeout=300)

            if ret != 0:
                return subdomains

            # Build subdomain -> IP mapping
            sub_to_ip: Dict[str, List[str]] = {}
            for line in stdout.splitlines():
                line = line.strip()
                if '[' in line and ']' in line:
                    sub = line[:line.find('[')].strip()
                    ip_part = line[line.find('[')+1:line.find(']')]
                    ips = [ip.strip() for ip in ip_part.split(',') if ip.strip()]
                    sub_to_ip[sub] = ips

            filtered = []
            for sub in subdomains:
                ips = sub_to_ip.get(sub, [])
                if wildcard_ip not in ips:
                    filtered.append(sub)
                else:
                    logger.debug(f"Filtering wildcard subdomain: {sub} -> {wildcard_ip}")

            logger.info(f"Wildcard filtering: {len(subdomains)} -> {len(filtered)} subdomains")
            return filtered

        except Exception as e:
            logger.warning(f"Wildcard filtering failed: {e}")
            return subdomains
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    # ------------------------------------------------------------------
    # Chaos Dataset (ProjectDiscovery) — https://chaos.projectdiscovery.io
    # ------------------------------------------------------------------
    async def _fetch_chaos(self, domain: str) -> List[str]:
        """
        Fetch subdomains from ProjectDiscovery Chaos dataset.
        Requires API key via config tools.chaos_api_key or env CHAOS_API_KEY / PDCP_API_KEY.
        Endpoint: https://dns.projectdiscovery.io/dns/<domain>/subdomains
        """
        if not self.chaos_api_key:
            logger.debug("Chaos API key not configured — skipping.")
            return []
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {"Authorization": self.chaos_api_key}
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        subs = data.get("subdomains") or data.get("data") or []
                        if isinstance(subs, dict):
                            subs = subs.get("subdomains", [])
                        results: List[str] = []
                        for sub in subs:
                            sub = str(sub).strip().lower().rstrip(".")
                            if not sub:
                                continue
                            # Chaos may return bare labels or FQDNs
                            if not sub.endswith(domain):
                                # bare label like "admin" -> "admin.example.com"
                                if "." not in sub:
                                    sub = f"{sub}.{domain}"
                                else:
                                    # already FQDN for another domain, skip if not suffix
                                    if not sub.endswith("." + domain):
                                        continue
                            results.append(sub)
                        logger.info(f"Chaos found {len(results)} subdomains for {domain}")
                        return results
                    elif resp.status == 401:
                        logger.warning("Chaos API: unauthorized — check your API key.")
                    elif resp.status == 429:
                        logger.warning("Chaos API: rate limited (429).")
                    else:
                        logger.debug(f"Chaos API failed for {domain}: {resp.status} {await resp.text()}")
        except Exception as e:
            logger.debug(f"Chaos fetch failed for {domain}: {e}")
        return []

    # ------------------------------------------------------------------
    # Certificate Transparency (CT) Log Enumeration
    # ------------------------------------------------------------------
    async def _fetch_ct_logs(self, domain: str) -> List[str]:
        """
        Fetch subdomains from Certificate Transparency logs via crt.sh.
        Async HTTP call for non-blocking operation.
        """
        subdomains = set()

        # crt.sh API
        urls = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://crt.sh/?q=%25.{domain}&output=json",
        ]

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
            for url in urls:
                try:
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for entry in data:
                                name = entry.get('name_value', '').strip().lower()
                                # crt.sh returns multi-line entries
                                for sub in name.split('\n'):
                                    sub = sub.strip()
                                    if sub and sub.endswith(domain) and '*' not in sub:
                                        subdomains.add(sub)
                except Exception as e:
                    logger.debug(f"CT log fetch failed for {url}: {e}")

        return list(subdomains)

    # ------------------------------------------------------------------
    # Permutation / Alteration Scanning
    # ------------------------------------------------------------------
    def _run_permutation_scan(self, domain: str, known_subdomains: List[str],
                              max_permutations: int = 3000) -> List[str]:
        """
        Generate subdomain permutations using dnsgen or altdns.
        Requires known subdomains as input for context-aware generation.
        Capped at max_permutations to keep downstream resolution/probing fast.
        """
        if not known_subdomains:
            return []

        permutations = set()

        # Try dnsgen first (better quality)
        if self.dnsgen_path.is_file():
            temp_input = temp_output = None
            try:
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                    temp_input = f.name
                    f.write('\n'.join(known_subdomains))
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                    temp_output = f.name

                cmd = [str(self.dnsgen_path), temp_input, '-f']
                stdout, stderr, ret = run_command(cmd, timeout=120)

                if ret == 0:
                    for line in stdout.splitlines():
                        sub = line.strip()
                        if sub and sub.endswith(domain):
                            permutations.add(sub)
            except Exception as e:
                logger.warning(f"dnsgen failed: {e}")
            finally:
                for f in [temp_input, temp_output]:
                    if f and Path(f).exists():
                        Path(f).unlink()

        # Fallback to altdns
        if not permutations and self.altdns_path.is_file():
            temp_input = temp_output = None
            try:
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                    temp_input = f.name
                    f.write('\n'.join(known_subdomains))
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                    temp_output = f.name

                cmd = [
                    'python3', str(self.altdns_path),
                    '-i', temp_input,
                    '-o', temp_output,
                    '-w', 'words.txt'  # Default wordlist
                ]
                stdout, stderr, ret = run_command(cmd, timeout=180)

                if ret == 0 and Path(temp_output).exists():
                    with open(temp_output, 'r') as f:
                        for line in f:
                            sub = line.strip()
                            if sub and sub.endswith(domain):
                                permutations.add(sub)
            except Exception as e:
                logger.warning(f"altdns failed: {e}")
            finally:
                for f in [temp_input, temp_output]:
                    if f and Path(f).exists():
                        Path(f).unlink()

        # Built-in permutation if no tools available
        if not permutations:
            permutations = self._builtin_permutations(domain, known_subdomains)

        if len(permutations) > max_permutations:
            logger.info(f"Permutations capped: {len(permutations)} -> {max_permutations}")
            permutations = set(sorted(permutations)[:max_permutations])

        return list(permutations)

    def _builtin_permutations(self, domain: str, known_subdomains: List[str]) -> Set[str]:
        """Built-in permutation logic when external tools are unavailable."""
        permutations = set()
        prefixes = ['dev', 'staging', 'prod', 'test', 'api', 'admin', 'portal',
                    'internal', 'beta', 'alpha', 'demo', 'uat', 'qa', 'sandbox',
                    'secure', 'vpn', 'mail', 'ftp', 'ssh', 'db', 'backup',
                    'old', 'new', 'v1', 'v2', 'v3', 'app', 'mobile', 'cdn',
                    'static', 'assets', 'media', 'images', 'docs', 'support',
                    'help', 'status', 'monitor', 'grafana', 'kibana', 'jenkins',
                    'git', 'gitlab', 'github', 'confluence', 'jira', 'wiki']

        suffixes = ['-api', '-app', '-admin', '-dev', '-staging', '-prod',
                    '-test', '-internal', '-external', '-public', '-private',
                    '-new', '-old', '-backup', '-dr', '-primary', '-secondary']

        # Extract base names from known subdomains (capped - combinatorial guard)
        base_names = set()
        for sub in known_subdomains[:200]:
            parts = sub.replace('.' + domain, '').split('.')
            for part in parts:
                if part and part not in prefixes:
                    base_names.add(part)
        base_names = set(sorted(base_names)[:40])

        # Generate permutations
        for prefix in prefixes:
            permutations.add(f"{prefix}.{domain}")
            for base in base_names:
                permutations.add(f"{prefix}-{base}.{domain}")
                permutations.add(f"{prefix}.{base}.{domain}")

        for suffix in suffixes:
            for base in base_names:
                permutations.add(f"{base}{suffix}.{domain}")

        return permutations

    # ------------------------------------------------------------------
    # Command Execution Wrapper
    # ------------------------------------------------------------------
    def _run_command(self, cmd: Union[str, List[str]], tool_name: str, timeout: int = 300,
                     progress_callback: Optional[Callable[[float, str], None]] = None,
                     stdin_data: Optional[str] = None) -> str:
        cmd_list = cmd if isinstance(cmd, list) else cmd.split()
        logger.info(f"Running: {' '.join(cmd_list)}")
        if progress_callback:
            progress_callback(0, f"Starting {tool_name}...")

        stdout, stderr, ret = run_command(cmd_list, timeout=timeout)
        if ret != 0:
            error_msg = f"{tool_name} failed with exit code {ret}: {stderr.strip()}"
            logger.error(error_msg)
            if progress_callback:
                progress_callback(0, f"Error: {error_msg}")
            raise RuntimeError(error_msg)

        if progress_callback:
            progress_callback(1, f"{tool_name} completed.")
        return stdout

    # ------------------------------------------------------------------
    # Subdomain Discovery (Enhanced)
    # ------------------------------------------------------------------
    def _run_subfinder(self, domain: str, progress_callback: Optional[Callable[[float, str], None]] = None,
                       max_time_minutes: int = 3) -> List[str]:
        if not self.subfinder_path.is_file():
            logger.warning("Subfinder not found, skipping.")
            return []
        # -max-time caps total runtime (minutes); without it subfinder runs to its own 10min default
        cmd = [str(self.subfinder_path), '-d', domain, '-silent', '-max-time', str(max_time_minutes)]
        try:
            output = self._run_command(cmd, 'Subfinder', timeout=max_time_minutes * 60 + 60,
                                       progress_callback=lambda p, s: progress_callback(p * 0.15, s) if progress_callback else None)
            subs = [line.strip() for line in output.splitlines() if line.strip()]
            return self._sanitize_subdomain_list(subs)
        except Exception as e:
            logger.error(f"Subfinder failed: {e}")
            return []

    def _run_amass(self, domain: str, progress_callback: Optional[Callable[[float, str], None]] = None,
                   timeout_minutes: int = 5) -> List[str]:
        if not self.amass_path.is_file():
            logger.warning("Amass not found, skipping.")
            return []
        # -timeout caps amass (minutes); without it passive enum can run 15+ minutes
        cmd = [str(self.amass_path), 'enum', '-d', domain, '-passive', '-silent', '-timeout', str(timeout_minutes)]
        try:
            output = self._run_command(cmd, 'Amass', timeout=timeout_minutes * 60 + 60,
                                       progress_callback=lambda p, s: progress_callback(0.15 + p * 0.25, s) if progress_callback else None)
            subs = [line.strip() for line in output.splitlines() if line.strip()]
            return self._sanitize_subdomain_list(subs)
        except Exception as e:
            logger.error(f"Amass failed: {e}")
            return []

    def _run_dnsx(self, subdomains: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, str]]:
        if not self.dnsx_path.is_file() or not subdomains:
            return []
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(subdomains) + '\n')
            cmd = [str(self.dnsx_path), '-l', temp_file, '-a', '-cname', '-json', '-silent']
            output = self._run_command(cmd, 'Dnsx', timeout=300,
                                       progress_callback=lambda p, s: progress_callback(0.4 + p * 0.3, s) if progress_callback else None)
            results = []
            for line in output.splitlines():
                try:
                    data = json.loads(line)
                    results.append({
                        'hostname': data.get('host', ''),
                        'ip': ', '.join(data.get('a', [])),
                        'cname': ', '.join(data.get('cname', []))
                    })
                except Exception as e:
                    logger.warning(f"Error parsing dnsx output: {e}")
            return results
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    def _httpx_cmd(self, temp_input: str, temp_output: str, port_list: List[str],
                   threads: int = 100, rate: int = 500) -> List[str]:
        """Build the httpx command line (shared by single-run and chunked probing)."""
        cmd = [
            str(self.httpx_path), '-l', temp_input, '-json', '-o', temp_output,
            '-silent', '-follow-redirects', '-title', '-tech-detect',
            '-status-code', '-content-length', '-web-server',
            '-t', str(threads),
            '-timeout', '8',
            '-rl', str(rate),
            '-ports', ','.join(port_list),
        ]
        return cmd

    @staticmethod
    def _parse_httpx_output(output_file: str) -> List[Dict[str, Any]]:
        """Parse httpx JSONL output into result dicts (deduped by URL)."""
        results = []
        seen = set()
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        if not url or url in seen:
                            continue
                        seen.add(url)
                        results.append({
                            'URL': url,
                            'Input': data.get('input', ''),
                            'StatusCode': data.get('status-code', ''),
                            'Title': data.get('title', ''),
                            'WebServer': data.get('webserver', ''),
                            'ContentLength': data.get('content-length', ''),
                            'Technologies': ', '.join(data.get('tech', []))
                        })
                    except Exception as e:
                        logger.warning(f"Error parsing httpx output: {e}")
        except OSError as e:
            logger.warning(f"Could not read httpx output {output_file}: {e}")
        return results

    def probe_live_hosts_chunked(self, subdomains: List[str],
                                 extra_ports: Optional[List[str]] = None,
                                 chunk_size: int = 150, concurrency: int = 25,
                                 rate_limit: int = 150,
                                 progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, Any]]:
        """
        Probe many subdomains without crashing httpx: split the input into
        manageable chunks, run httpx per chunk with modest threads/rate, then
        merge + dedupe the results. Returns the combined live-host list.

        This replaces the single giant httpx invocation which can blow up on
        large subdomain sets (thousands of hosts, -t 100, -rl 500).
        """
        if not self.httpx_path.is_file() or not subdomains:
            return []

        default_ports = ['443']  # 443-only by default; extra ports only when explicitly requested
        if extra_ports:
            port_list = list(dict.fromkeys(default_ports + extra_ports))
        else:
            port_list = default_ports

        hosts = list(dict.fromkeys(h for h in subdomains if h))
        chunks = [hosts[i:i + chunk_size] for i in range(0, len(hosts), chunk_size)]
        logger.info(f"probe_live_hosts_chunked: {len(hosts)} hosts in {len(chunks)} chunks "
                    f"(chunk={chunk_size}, threads={concurrency}, rate={rate_limit})")

        all_results = []
        seen = set()
        for idx, chunk in enumerate(chunks):
            if progress_callback:
                progress_callback(idx / max(len(chunks), 1),
                                  f"Probing hosts {idx * chunk_size + 1}-{idx * chunk_size + len(chunk)} "
                                  f"of {len(hosts)} (chunk {idx + 1}/{len(chunks)})...")
            temp_input = temp_output = None
            try:
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_in:
                    temp_input = f_in.name
                    f_in.write('\n'.join(chunk) + '\n')
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_out:
                    temp_output = f_out.name
                cmd = self._httpx_cmd(temp_input, temp_output, port_list,
                                      threads=concurrency, rate=rate_limit)
                self._run_command(cmd, 'Httpx', timeout=300)
                for row in self._parse_httpx_output(temp_output):
                    if row['URL'] not in seen:
                        seen.add(row['URL'])
                        all_results.append(row)
            except Exception as e:
                logger.warning(f"httpx chunk {idx + 1} failed: {e}")
            finally:
                for f in [temp_input, temp_output]:
                    if f and Path(f).exists():
                        Path(f).unlink()

        if progress_callback:
            progress_callback(1.0, f"Probing done: {len(all_results)} live hosts from {len(hosts)} inputs.")
        logger.info(f"probe_live_hosts_chunked: {len(all_results)} live hosts")
        return all_results

    def _run_httpx(self, subdomains: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, Any]]:
        if not self.httpx_path.is_file() or not subdomains:
            return []
        temp_input = temp_output = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_in:
                temp_input = f_in.name
                f_in.write('\n'.join(subdomains) + '\n')
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_out:
                temp_output = f_out.name
            # 443-only by default - httpx otherwise probes [80,443] on every host
            cmd = self._httpx_cmd(temp_input, temp_output, ['443'], threads=100, rate=500)
            self._run_command(cmd, 'Httpx', timeout=600,
                              progress_callback=lambda p, s: progress_callback(0.7 + p * 0.3, s) if progress_callback else None)
            return self._parse_httpx_output(temp_output)
        finally:
            for f in [temp_input, temp_output]:
                if f and Path(f).exists():
                    Path(f).unlink()

    # ------------------------------------------------------------------
    # Subdomain takeover – Nuclei only
    # ------------------------------------------------------------------
    def _run_httpx_with_ports(self, subdomains: List[str], extra_ports: List[str] = None,
                               progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, Any]]:
        """
        Run httpx with custom port support.
        If extra_ports provided, appends them to the default port list.
        """
        if not self.httpx_path.is_file() or not subdomains:
            return []

        # Build port list. NOTE: we always pass '-ports' explicitly - httpx's own
        # default list is [80, 443] which probes EVERY host on BOTH ports (one
        # 80 + one 443 row per host), duplicating live results ~2x. By forcing
        # the flag we probe each host exactly once per requested port.
        default_ports = ['443']
        if extra_ports:
            port_list = list(dict.fromkeys(default_ports + extra_ports))  # dedupe, keep order
        else:
            port_list = default_ports

        temp_input = temp_output = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_in:
                temp_input = f_in.name
                f_in.write('\n'.join(subdomains) + '\n')
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f_out:
                temp_output = f_out.name

            cmd = [
                str(self.httpx_path), '-l', temp_input, '-json', '-o', temp_output,
                '-silent', '-follow-redirects', '-title', '-tech-detect',
                '-status-code', '-content-length', '-web-server',
                    '-t', '100',      # threads
                '-timeout', '8',  # per-request timeout (s) - dead hosts fail fast
                '-rl', '500'      # rate limit (req/s)
            ]

            # Explicit port list - always pass it (see note above about httpx
            # defaulting to [80, 443] and double-probing every host)
            cmd.extend(['-ports', ','.join(port_list)])

            self._run_command(cmd, 'Httpx', timeout=600,
                              progress_callback=lambda p, s: progress_callback(0.7 + p * 0.3, s) if progress_callback else None)

            results = self._parse_httpx_output(temp_output)
            return results
        finally:
            for f in [temp_input, temp_output]:
                if f and Path(f).exists():
                    Path(f).unlink()


    def _run_nuclei_takeover(self, subdomains: List[str], progress_callback: Optional[Callable[[float, str], None]] = None) -> List[Dict[str, str]]:
        if not self.nuclei_path.is_file():
            logger.warning("Nuclei not found, cannot run takeover scan.")
            return []

        if not subdomains:
            return []

        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as f:
                temp_file = f.name
                f.write('\n'.join(subdomains) + '\n')

            cmd = [str(self.nuclei_path), '-l', temp_file, '-jsonl', '-silent', '-tags', 'takeover']
            if self.nuclei_templates_path.is_dir():
                cmd.extend(['-templates', str(self.nuclei_templates_path)])
            cmd.extend(['-rl', '150', '-timeout', '10'])

            try:
                output = self._run_command(cmd, 'Nuclei (takeover)', timeout=600,
                                           progress_callback=progress_callback)
            except RuntimeError as e:
                logger.info(f"Nuclei takeover scan finished with no findings: {e}")
                return []

            findings = parse_nuclei_output(output)
            takeover_results = []
            for f in findings:
                takeover_results.append({
                    'Domain': f.get('matched_at', '').split('/')[0] if f.get('matched_at') else '',
                    'Service': f.get('name', ''),
                    'Status': f.get('severity', 'unknown'),
                    'Evidence': f.get('extracted_results', [])
                })
            return takeover_results

        except Exception as e:
            logger.warning(f"Unexpected error in Nuclei takeover scan: {e}")
            return []
        finally:
            if temp_file and Path(temp_file).exists():
                Path(temp_file).unlink()

    # ------------------------------------------------------------------
    # Public method for takeover scan (Nuclei only)
    # ------------------------------------------------------------------
    def run_subdomain_takeover_scan(self, subdomains_df: pd.DataFrame,
                                    progress_callback: Optional[Callable[[float, str], None]] = None) -> pd.DataFrame:
        if 'hostname' in subdomains_df.columns:
            subdomains = subdomains_df['hostname'].tolist()
        elif 'Subdomain' in subdomains_df.columns:
            subdomains = subdomains_df['Subdomain'].tolist()
        else:
            subdomains = subdomains_df.iloc[:, 0].tolist()

        if not subdomains:
            return pd.DataFrame(columns=['Domain', 'Service', 'Status', 'Evidence'])

        if not self.nuclei_path.is_file():
            raise RuntimeError("Nuclei not found. Please install Nuclei and set the correct path in config.json.")

        if progress_callback:
            progress_callback(0.1, "Running Nuclei takeover scan...")

        findings = self._run_nuclei_takeover(subdomains, progress_callback)

        if not findings:
            return pd.DataFrame(columns=['Domain', 'Service', 'Status', 'Evidence'])

        df = pd.DataFrame(findings)
        for col in ['Domain', 'Service', 'Status', 'Evidence']:
            if col not in df.columns:
                df[col] = ''

        df = df.drop_duplicates(subset=['Domain', 'Service'], keep='first')
        return df[['Domain', 'Service', 'Status', 'Evidence']]

    # ------------------------------------------------------------------
    # Full subdomain scan (ENHANCED)
    # ------------------------------------------------------------------
    async def perform_subdomain_scan_async(self, domain: str, 
                                            progress_callback: Optional[Callable[[float, str], None]] = None,
                                            enable_ct: bool = True,
                                            enable_chaos: bool = True,
                                            enable_permutation: bool = True,
                                            enable_wildcard_filter: bool = True) -> Dict[str, pd.DataFrame]:
        """
        Enhanced async subdomain scan with CT logs, permutations, wildcard filtering, and scope enforcement.
        """
        # Sanitize input
        try:
            domain = self._sanitize_domain(domain)
        except ValueError as e:
            logger.error(f"Invalid domain: {e}")
            raise

        results = {
            "subfinder_subdomains": pd.DataFrame(columns=['Subdomain']),
            "amass_subdomains": pd.DataFrame(columns=['Subdomain']),
            "ct_logs_subdomains": pd.DataFrame(columns=['Subdomain']),
            "chaos_subdomains": pd.DataFrame(columns=['Subdomain']),
            "permutation_subdomains": pd.DataFrame(columns=['Subdomain']),
            "resolved_subdomains": pd.DataFrame(columns=['hostname', 'ip', 'cname']),
            "live_hosts": pd.DataFrame(columns=['URL', 'Input', 'StatusCode', 'Title', 'WebServer', 'ContentLength', 'Technologies']),
            "takeover_findings": pd.DataFrame(columns=['Domain', 'Service', 'Status', 'Evidence'])
        }

        all_subdomains: Set[str] = set()

        # Phase 1: Passive enumeration (parallel where possible)
        if progress_callback:
            progress_callback(0.05, "Running passive subdomain enumeration...")

        subfinder_results = self._run_subfinder(domain, progress_callback)
        if subfinder_results:
            results["subfinder_subdomains"] = pd.DataFrame([{'Subdomain': s} for s in subfinder_results])
            all_subdomains.update(subfinder_results)

        amass_results = self._run_amass(domain, progress_callback)
        if amass_results:
            results["amass_subdomains"] = pd.DataFrame([{'Subdomain': s} for s in amass_results])
            all_subdomains.update(amass_results)

        # Phase 2: Certificate Transparency logs
        if enable_ct:
            if progress_callback:
                progress_callback(0.30, "Fetching Certificate Transparency logs...")
            try:
                ct_results = await self._fetch_ct_logs(domain)
                if ct_results:
                    ct_results = self._sanitize_subdomain_list(ct_results)
                    ct_results = self.scope_validator.filter_subdomains(ct_results)
                    results["ct_logs_subdomains"] = pd.DataFrame([{'Subdomain': s} for s in ct_results])
                    all_subdomains.update(ct_results)
                    logger.info(f"CT logs found {len(ct_results)} subdomains")
            except Exception as e:
                logger.warning(f"CT log enumeration failed: {e}")

        # Phase 2b: Chaos dataset (ProjectDiscovery)
        if enable_chaos:
            if progress_callback:
                progress_callback(0.33, "Fetching Chaos dataset...")
            try:
                chaos_results = await self._fetch_chaos(domain)
                if chaos_results:
                    chaos_results = self._sanitize_subdomain_list(chaos_results)
                    chaos_results = self.scope_validator.filter_subdomains(chaos_results)
                    results["chaos_subdomains"] = pd.DataFrame([{'Subdomain': s} for s in chaos_results])
                    all_subdomains.update(chaos_results)
                    logger.info(f"Chaos found {len(chaos_results)} subdomains")
            except Exception as e:
                logger.warning(f"Chaos enumeration failed: {e}")

        # Phase 3: Apply scope filtering
        all_subdomains = set(self.scope_validator.filter_subdomains(list(all_subdomains)))

        if not all_subdomains:
            logger.warning("No subdomains found after scope filtering")
            return results

        # Phase 4: Permutation scanning
        if enable_permutation and len(all_subdomains) > 0:
            if progress_callback:
                progress_callback(0.40, "Generating subdomain permutations...")
            try:
                perm_results = self._run_permutation_scan(domain, list(all_subdomains))
                if perm_results:
                    perm_results = self._sanitize_subdomain_list(perm_results)
                    perm_results = self.scope_validator.filter_subdomains(perm_results)
                    results["permutation_subdomains"] = pd.DataFrame([{'Subdomain': s} for s in perm_results])
                    all_subdomains.update(perm_results)
                    logger.info(f"Permutations generated {len(perm_results)} new subdomains")
            except Exception as e:
                logger.warning(f"Permutation scanning failed: {e}")

        # Phase 5: Wildcard filtering
        if enable_wildcard_filter:
            if progress_callback:
                progress_callback(0.55, "Detecting and filtering wildcard DNS...")
            filtered = self._filter_wildcard_subdomains(list(all_subdomains), domain)
            if len(filtered) < len(all_subdomains):
                logger.info(f"Filtered {len(all_subdomains) - len(filtered)} wildcard subdomains")
            all_subdomains = set(filtered)

        # Phase 6: DNS resolution
        if progress_callback:
            progress_callback(0.60, "Resolving DNS records...")
        dns_results = self._run_dnsx(list(all_subdomains), progress_callback)
        if dns_results:
            results["resolved_subdomains"] = pd.DataFrame(dns_results)

        # Phase 7: HTTP probing
        if progress_callback:
            progress_callback(0.75, "Probing HTTP services...")
        http_results = self._run_httpx(list(all_subdomains), progress_callback)
        if http_results:
            results["live_hosts"] = pd.DataFrame(http_results)

        # Phase 8: Takeover scan
        if progress_callback:
            progress_callback(0.95, "Checking for subdomain takeovers...")
        try:
            takeover_df = self.run_subdomain_takeover_scan(
                pd.DataFrame({'hostname': list(all_subdomains)}),
                progress_callback=progress_callback
            )
            if not takeover_df.empty:
                results["takeover_findings"] = takeover_df
        except Exception as e:
            logger.warning(f"Takeover scan failed: {e}")

        if progress_callback:
            progress_callback(1.0, f"Scan completed. Found {len(all_subdomains)} unique subdomains.")

        logger.info(f"Subdomain scan complete: {len(all_subdomains)} unique subdomains for {domain}")
        return results

    def perform_subdomain_scan(self, domain: str, 
                                progress_callback: Optional[Callable[[float, str], None]] = None,
                                enable_ct: bool = True,
                                enable_chaos: bool = True,
                                enable_permutation: bool = True,
                                enable_wildcard_filter: bool = True) -> Dict[str, pd.DataFrame]:
        """Synchronous wrapper for the async scan."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(
            self.perform_subdomain_scan_async(
                domain, progress_callback, enable_ct, enable_chaos, enable_permutation, enable_wildcard_filter
            )
        )