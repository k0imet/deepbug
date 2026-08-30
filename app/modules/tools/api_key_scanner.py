"""
ApiKeyScanner - precise API key detection for JavaScript
=========================================================
Uses the curated api_keys.json corpus (streaak/keyhacks services paired with
gitleaks-grade regexes) to detect REAL API keys in JS content. Unlike the
generic GF/entropy secret scanner, every finding here matches a known key
format for a named service, so false positives are rare and each hit maps
directly to a verification command.

Anti-FP measures
----------------
1. Placeholder rejection - word-boundary + substring checks against known
   doc/example markers (never matches the value prefixes of real keys, e.g.
   `sk_live_`, `ghp_`, `AIza...`).
2. Entropy gating - optional, config-tunable per service (default: jwt /
   private keys / ssh), skipped for prefix-anchored formats (AKIA, ghp_, ...).
3. Repeated/sequential character checks ("aaaa...", "0123...").
4. Multi-line extraction - PEM private-key blocks and GCP service-account
   JSON are captured across newlines.
5. Confidence scoring - high/medium/low from known prefixes + entropy;
   only obviously-low matches are dropped.

Corpus path is overridable via config key `tools.paths.api_key_corpus`
(default: app/modules/tools/data/api_keys.json).

Usage
-----
    scanner = ApiKeyScanner(config)
    findings = scanner.scan_js_content(js_content, source_url)
    findings = scanner.scan_urls(urls, progress_callback=...)
"""

import json
import math
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Callable, Tuple, Set

logger = logging.getLogger(__name__)

DEFAULT_CORPUS = Path(__file__).resolve().parent / 'data' / 'api_keys.json'

# gitleaks patterns close with a boundary that excludes ',' - fine for git
# diffs, wrong for JS object literals. Relax it to accept , ; " ' ` and space.
# Anchored to the exact gitleaks suffix so nothing mid-pattern is touched.
_TRAILING_BOUNDARY = re.compile(r"\(\?:\[\\x60'\"\s;\]\|\\\[nr\]\|\$\)\s*$")

def _relax_boundary(rx_text: str) -> str:
    return _TRAILING_BOUNDARY.sub(
        lambda m: '(?:[,;\'"`\\s]|$)', rx_text)

# Multi-line captures (corpus regexes are line-oriented). Minified bundles
# store newlines as escaped `\n` text, so both real and escaped forms count.
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 -]+-----(?:[\r\n]|\\[rn])[A-Za-z0-9+/=\s]{40,}?(?:[\r\n]|\\[rn])-----END [A-Z0-9 -]+-----",
    re.MULTILINE)
_SA_JSON = re.compile(
    r'\{\s*"type"\s*:\s*"service_account"[^{}]{80,}\}', re.DOTALL)

SEVERITY_MAP: List[Tuple[str, str]] = [
    ("stripe", "CRITICAL"), ("square", "CRITICAL"), ("paypal", "CRITICAL"),
    ("razorpay", "CRITICAL"), ("aws", "CRITICAL"), ("cloudflare", "CRITICAL"),
    ("github", "CRITICAL"), ("gitlab", "CRITICAL"), ("openai", "CRITICAL"),
    ("anthropic", "CRITICAL"), ("deepseek", "CRITICAL"), ("groq", "CRITICAL"),
    ("replicate", "CRITICAL"), ("huggingface", "CRITICAL"), ("gcp", "CRITICAL"),
    ("google", "HIGH"), ("firebase", "HIGH"), ("slack", "CRITICAL"),
    ("twilio", "CRITICAL"), ("twitch", "CRITICAL"), ("discord", "CRITICAL"),
    ("sendgrid", "HIGH"), ("mailgun", "HIGH"), ("mailchimp", "HIGH"),
    ("heroku", "HIGH"), ("npm", "HIGH"), ("pypi", "HIGH"),
    ("telegram", "HIGH"), ("azure", "HIGH"), ("sentry", "HIGH"),
    ("datadog", "HIGH"), ("new relic", "HIGH"), ("dropbox", "HIGH"),
    ("vault", "CRITICAL"), ("private key", "CRITICAL"), ("jwt", "HIGH"),
    ("ssh", "CRITICAL"), ("service account", "CRITICAL"), ("pagerduty", "HIGH"),
    ("circleci", "HIGH"), ("travis", "HIGH"), ("buildkite", "HIGH"),
    ("opsgenie", "HIGH"), ("sonarcloud", "HIGH"), ("mapbox", "HIGH"),
    ("algolia", "HIGH"), ("asana", "HIGH"), ("zendesk", "HIGH"),
    ("hubspot", "HIGH"), ("salesforce", "HIGH"), ("grafana", "HIGH"),
    ("shodan", "HIGH"), ("twitter", "HIGH"), ("facebook", "HIGH"),
    ("instagram", "HIGH"), ("linkedin", "HIGH"), ("youtube", "HIGH"),
    ("spotify", "HIGH"), ("amplitude", "HIGH"), ("iterable", "HIGH"),
    ("branch", "HIGH"), ("contentful", "HIGH"), ("cypress", "HIGH"),
    ("wpengine", "HIGH"), ("weglot", "HIGH"), ("abtasty", "MEDIUM"),
    ("loqate", "MEDIUM"), ("ipstack", "MEDIUM"), ("keen", "MEDIUM"),
    ("calendly", "MEDIUM"), ("delighted", "MEDIUM"), ("bazaarvoice", "MEDIUM"),
    ("visual studio app center", "MEDIUM"), ("pivotaltracker", "MEDIUM"),
    ("wakatime", "MEDIUM"), ("buttercms", "MEDIUM"), ("deviantart", "MEDIUM"),
    ("pendo", "MEDIUM"), ("lokalise", "MEDIUM"), ("freshdesk", "MEDIUM"),
    ("jumpcloud", "MEDIUM"), ("browserstack", "MEDIUM"), ("saucelabs", "MEDIUM"),
    ("bitly", "MEDIUM"), ("bing maps", "MEDIUM"), ("google maps", "MEDIUM"),
    ("google recaptcha", "MEDIUM"), ("infura", "MEDIUM"), ("zapier", "MEDIUM"),
]

# Known value prefixes that make a match authoritative regardless of entropy.
# NOTE: must not include substrings of each other (`sk-` before `sk-proj-` is
# fine since we match the raw value prefix).
KNOWN_PREFIXES = [
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "glpat-", "glsa_", "glrt-", "GR1348941", "xoxb-", "xoxp-", "xoxa-",
    "xoxr-", "xapp-", "sk_live_", "sk_test_", "pk_live_", "pk_test_",
    "rk_live_", "rk_test_", "sq0atp-", "sq0csp-", "rzp_live_", "rzp_test_",
    "AIza", "AAAA", "SG.", "npm_", "NRAK-", "NRII-", "pdy_", "wg_",
    "BQ", "IGQVJ", "key_live_", "secret_live_", "A3T", "AKIA", "ASIA",
    "ABIA", "ACCA", "EAACEdEose0cBA", "EAAA", "SK", "eyJ", "p8e-",
]


class ApiKeyScanner:
    """Precise API-key scanner backed by the keyhacks corpus."""

    def __init__(self, config: Dict):
        paths_cfg = config.get('tools', {}).get('paths', {})
        path = paths_cfg.get('api_key_corpus', '')
        self.corpus_path = Path(path).expanduser() if path else DEFAULT_CORPUS

        scanner_cfg = config.get('js_secret_scanner', {})
        self.max_line_context = int(scanner_cfg.get('max_line_context', 120))
        self.max_matches = int(config.get('js_max_matches', 30))
        self.min_entropy = float(scanner_cfg.get('min_entropy', 3.5))
        self.entropy_services = set(
            scanner_cfg.get('entropy_services', ['jwt', 'private key', 'ssh', 'generic']))

        self.entries: List[Dict] = []
        self._placeholder_re = self._build_placeholder_re()
        self._load()

    # ------------------------------------------------------------------
    # Placeholder detection - conservative: never matches real key prefixes
    # ------------------------------------------------------------------
    @staticmethod
    def _build_placeholder_re() -> re.Pattern:
        """Compile a fast regex for obvious placeholder tokens.

        Deliberately excludes value-prefix substrings that appear in real keys
        (`sk_live_`, `dev`, `token`, `key`, `secret`, `live_`, `prod_`, ...):
        a placeholder check must never outvote a precise key-format match.
        """
        tokens = [
            r"your_", r"my_", r"xxxx", r"test_key", r"dummy", r"placeholder",
            r"changeme", r"process\.env\.", r"import\.meta\.env\.", r"\$\{",
            r"undefined", r"null", r"00000000", r"token_here", r"key_here",
            r"secret_here", r"insert_your", r"replace_me", r"fill_me_in",
            r"sk_xxxxxxxx", r"pk_xxxxxxxx", r"ghp_xxxxxxxx", r"glpat-xxxxxxxx",
            r"AIzaSyxxxxxxxx",
        ]
        pattern = r"(?i)(" + "|".join(re.escape(t) for t in tokens) + r")"
        return re.compile(pattern)

    def _is_placeholder(self, value: str) -> bool:
        """True when the value is clearly a doc example / placeholder.

        Only consulted for values NOT anchored by a known key prefix (those
        are format-authoritative); the repeated/sequential heuristics here are
        too blunt to outvote e.g. `AIza...` or `sk_live_...` matches.
        """
        if not value or len(value) < 4:
            return True
        if self._placeholder_re.search(value):
            return True
        # word-boundary example/sample markers (docs keys), not substrings
        if re.search(r'(?i)\b(example|sample|demo)\b', value):
            return True
        # hex colour codes (common in minified CSS-in-JS)
        if re.fullmatch(r'[0-9a-fA-F]{3,8}', value):
            return True
        # all-same-character runs ("aaaa", "0000", "zzzzzzzz")
        if len(set(value)) == 1:
            return True
        # sequential runs ("0123456789", "abcdefgh")
        if re.search(r'(?i)\b(?:0?123456789|abcdefgh?|qwerty|asdf|zxcv|test)\b', value):
            return True
        # >60% a single repeated character - very unlikely for a real key
        max_count = max(value.lower().count(c) for c in set(value.lower()))
        if len(value) > 8 and max_count / len(value) > 0.6:
            return True
        return False

    # ------------------------------------------------------------------
    # Multi-line extraction - PEM blocks & service-account JSON
    # ------------------------------------------------------------------
    def _scan_multiline(self, js_content: str, source_url: str) -> List[Dict]:
        findings = []
        for m in _PEM_BLOCK.finditer(js_content):
            value = m.group(0)
            if not value or self._is_placeholder(value):
                continue
            if len(value) < 30:
                continue
            line, context = self._line_context(js_content, m.start(), m.end())
            findings.append({
                'type': 'API Key', 'service': 'Private Key (PEM)',
                'key_name': 'private-key', 'value': value[:200],
                'severity': 'CRITICAL', 'line': line, 'context': context,
                'source': source_url, 'confidence': 'high',
                'entropy': self._shannon_entropy(value[:200]),
                'verification': '', 'link': '',
            })
        for m in _SA_JSON.finditer(js_content):
            value = m.group(0)
            if len(value) < 80:
                continue
            line, context = self._line_context(js_content, m.start(), m.end())
            findings.append({
                'type': 'API Key', 'service': 'Google Cloud Service Account',
                'key_name': 'gcp-service-account', 'value': value[:200],
                'severity': 'CRITICAL', 'line': line, 'context': context,
                'source': source_url, 'confidence': 'high',
                'entropy': self._shannon_entropy(value),
                'verification': '', 'link': '',
            })
        return findings

    # ------------------------------------------------------------------
    # Corpus loading
    # ------------------------------------------------------------------
    def _load(self) -> None:
        if not self.corpus_path.exists():
            logger.warning(f"API key corpus not found at {self.corpus_path}; scanner disabled.")
            return
        try:
            data = json.loads(self.corpus_path.read_text())
            for entry in data.get('entries', []):
                for key in entry.get('keys', []):
                    rx_text = key.get('regex', '')
                    if not rx_text:
                        continue
                    try:
                        self.entries.append({
                            'service': entry.get('service', 'Unknown'),
                            'key_name': key.get('name', ''),
                            'regex': re.compile(_relax_boundary(rx_text)),
                            'verification': entry.get('verification', ''),
                            'link': entry.get('link', ''),
                        })
                    except re.error as e:
                        logger.warning(f"Invalid regex for {entry.get('service')}: {e}")
            logger.info(f"API key corpus loaded: {len(self.entries)} patterns from {self.corpus_path.name}")
        except Exception as e:
            logger.error(f"Failed to load API key corpus: {e}")

    # ------------------------------------------------------------------
    # Severity lookup
    # ------------------------------------------------------------------
    @staticmethod
    def _severity_for(service: str) -> str:
        s = service.lower()
        for token, sev in SEVERITY_MAP:
            if token in s:
                return sev
        return 'HIGH'

    # ------------------------------------------------------------------
    # Shannon entropy
    # ------------------------------------------------------------------
    @staticmethod
    def _shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    # ------------------------------------------------------------------
    # Confidence scoring - prefix-anchored values are authoritative
    # ------------------------------------------------------------------
    def _confidence(self, service: str, value: str, entropy: float) -> str:
        if any(value.startswith(p) for p in KNOWN_PREFIXES):
            return 'high'
        if entropy >= 4.5:
            return 'high'
        if entropy >= self.min_entropy:
            return 'medium'
        return 'low'

    def _line_context(self, content: str, start: int, end: int) -> Tuple[int, str]:
        line_num = content[:start].count('\n') + 1
        line_start = content.rfind('\n', 0, start) + 1
        line_end = content.find('\n', end)
        if line_end == -1:
            line_end = len(content)
        line_content = content[line_start:line_end].strip()
        if len(line_content) > self.max_line_context:
            mid = start - line_start
            s = max(0, mid - self.max_line_context // 2)
            line_content = line_content[s:s + self.max_line_context]
        return line_num, line_content

    # ------------------------------------------------------------------
    # Main scanning
    # ------------------------------------------------------------------
    def scan_js_content(self, js_content: str, source_url: str = '') -> List[Dict]:
        findings = []
        if not js_content or len(js_content) < 10:
            return findings

        for pat in self.entries:
            count = 0
            for match in pat['regex'].finditer(js_content):
                if count >= self.max_matches:
                    break
                value = (match.group(1) if match.lastindex and match.lastindex >= 1
                         else match.group(0))
                if not value or len(value) < 4:
                    continue
                prefix_authoritative = any(value.startswith(p) for p in KNOWN_PREFIXES)
                if not prefix_authoritative and self._is_placeholder(value):
                    continue

                service_lower = pat['service'].lower()
                needs_entropy = any(s in service_lower for s in self.entropy_services)
                entropy = self._shannon_entropy(value)
                if needs_entropy and entropy < self.min_entropy:
                    continue

                confidence = self._confidence(pat['service'], value, entropy)
                if confidence == 'low':
                    continue

                count += 1

                line, context = self._line_context(js_content, match.start(), match.end())
                findings.append({
                    'type': 'API Key',
                    'service': pat['service'],
                    'key_name': pat['key_name'],
                    'value': value,
                    'severity': self._severity_for(pat['service']),
                    'line': line,
                    'context': context,
                    'source': source_url,
                    'confidence': confidence,
                    'entropy': round(entropy, 3),
                    'verification': pat['verification'],
                    'link': pat['link'],
                })

        findings.extend(self._scan_multiline(js_content, source_url))

        # Dedup by raw value, highest severity first
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: (sev_order.get(x['severity'], 4), -len(x['value'])))
        seen = set()
        unique = []
        for f in findings:
            if f['value'] not in seen:
                seen.add(f['value'])
                unique.append(f)
        return unique

    # ------------------------------------------------------------------
    # URL scanning
    # ------------------------------------------------------------------
    def scan_urls(self, urls: List[str],
                  progress_callback: Optional[Callable] = None) -> Dict:
        """Fetch each URL and scan its body. Returns {'scanned': [...], 'errors': [...]}."""
        import httpx
        findings, errors = [], []
        total = len(urls)
        for idx, url in enumerate(urls):
            try:
                resp = httpx.get(url, timeout=15, follow_redirects=True,
                                 verify=False,
                                 headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                                        'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'})
                if resp.status_code == 200 and resp.text:
                    findings.extend(self.scan_js_content(resp.text, url))
                elif resp.status_code != 200:
                    errors.append(f"{url}: HTTP {resp.status_code}")
            except Exception as e:
                errors.append(f"{url}: {type(e).__name__}")
            if progress_callback:
                progress_callback((idx + 1) / total, f"Scanned {idx + 1}/{total} URLs")
        return {'scanned': findings, 'errors': errors}

    def get_pattern_stats(self) -> Dict:
        stats = {}
        for pat in self.entries:
            stats[pat['service']] = stats.get(pat['service'], 0) + 1
        return stats
