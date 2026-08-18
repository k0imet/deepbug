"""
JSGFSecretScanner - GF Pattern-Based Secret Detection for JavaScript
=====================================================================
Leverages mrofisr/gf-patterns for comprehensive secret detection in JS files.

This module loads GF pattern JSON files and applies them to JS content,
giving us 36+ secret patterns (AI tokens, API keys, OAuth, JWT, etc.) beyond
the basic hardcoded regexes in the original secret_validator.

PLUS: Built-in patterns for React/Vue/Angular/Gatsby env vars that leak in
production bundles (REACT_APP_*, NEXT_PUBLIC_*, etc.)

Usage:
    scanner = JSGFSecretScanner(config)
    findings = scanner.scan_js_content(js_content, source_url)
"""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Built-in patterns for frontend framework env vars (not in mrofisr/gf-patterns)
# Using re.compile with separate strings to avoid quote escaping issues
BUILTIN_PATTERNS = {
    "react_env_vars": re.compile(
        r"REACT_APP_[A-Z_]+\s*:\s*['\"]([A-Za-z0-9_\-\.\/\+=]{8,})['\"]",
        re.IGNORECASE
    ),
    "framework_secrets": re.compile(
        r"(?:REACT_APP|NEXT_PUBLIC|VUE_APP|ANGULAR_ENV|GATSBY_)[A-Z_]*(?:API_KEY|SECRET|PASSWORD|TOKEN|KEY|IV|AUTH)\s*:\s*['\"]([^'\"]{8,})['\"]",
        re.IGNORECASE
    ),
    "webpack_define_plugin": re.compile(
        r"['\"]([A-Z_]*(?:API_KEY|SECRET|PASSWORD|TOKEN|KEY|IV|AUTH)[A-Z_]*)['\"]\s*:\s*['\"]([^'\"]{8,})['\"]",
        re.IGNORECASE
    ),
    "auth0-client-secret": re.compile(
        r"auth0[^\"'\n]{0,40}client\s*_?secret\s*['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_-]{10,})['\"]",
        re.IGNORECASE
    ),
    "auth0-domain": re.compile(
        r"['\"]([a-z0-9_-]+\.auth0\.com)['\"]",
        re.IGNORECASE
    ),
}

# Mapping of GF pattern names to their secret categories and severity
SECRET_PATTERN_METADATA = {
    # AI & Modern Services
    "ai-services": {"category": "AI Token", "severity": "CRITICAL", "provider": "Multi-AI"},
    "anthropic": {"category": "AI Token", "severity": "CRITICAL", "provider": "Anthropic"},
    "cohere": {"category": "AI Token", "severity": "CRITICAL", "provider": "Cohere"},
    "groq": {"category": "AI Token", "severity": "CRITICAL", "provider": "Groq"},

    # Cloud & Infrastructure
    "aws-keys": {"category": "Cloud Credential", "severity": "CRITICAL", "provider": "AWS"},
    "firebase_secrets": {"category": "Cloud Credential", "severity": "HIGH", "provider": "Firebase"},
    "s3-buckets": {"category": "Cloud Resource", "severity": "MEDIUM", "provider": "AWS S3"},
    "cloud-resources": {"category": "Cloud Resource", "severity": "MEDIUM", "provider": "Multi-Cloud"},

    # Version Control & CI/CD
    "github_secrets": {"category": "VCS Token", "severity": "CRITICAL", "provider": "GitHub"},
    "npm-tokens": {"category": "Package Registry", "severity": "HIGH", "provider": "NPM"},
    "pypi-tokens": {"category": "Package Registry", "severity": "HIGH", "provider": "PyPI"},

    # Payment & Financial
    "stripe-keys_secrets": {"category": "Payment Token", "severity": "CRITICAL", "provider": "Stripe"},
    "square-keys_secrets": {"category": "Payment Token", "severity": "CRITICAL", "provider": "Square"},
    "paypal-token_secrets": {"category": "Payment Token", "severity": "CRITICAL", "provider": "PayPal"},

    # Communication
    "discord-webhooks": {"category": "Webhook", "severity": "HIGH", "provider": "Discord"},
    "slack-token_secrets": {"category": "Chat Token", "severity": "CRITICAL", "provider": "Slack"},
    "slack-webhook_secrets": {"category": "Webhook", "severity": "HIGH", "provider": "Slack"},
    "twilio-keys_secrets": {"category": "SMS Token", "severity": "CRITICAL", "provider": "Twilio"},
    "mailgun-keys_secrets": {"category": "Email Token", "severity": "HIGH", "provider": "Mailgun"},
    "mailchimp-keys_secrets": {"category": "Email Token", "severity": "HIGH", "provider": "Mailchimp"},

    # Social & OAuth
    "facebook-oauth_secrets": {"category": "OAuth", "severity": "CRITICAL", "provider": "Facebook"},
    "facebook-token_secrets": {"category": "Social Token", "severity": "HIGH", "provider": "Facebook"},
    "twitter-oauth_secrets": {"category": "OAuth", "severity": "CRITICAL", "provider": "Twitter/X"},
    "twitter-token_secrets": {"category": "Social Token", "severity": "HIGH", "provider": "Twitter/X"},
    "google-oauth_secrets": {"category": "OAuth", "severity": "CRITICAL", "provider": "Google"},
    "google-token_secrets": {"category": "OAuth Token", "severity": "HIGH", "provider": "Google"},
    "google-keys_secrets": {"category": "API Key", "severity": "CRITICAL", "provider": "Google"},
    "google-service-account_secrets": {"category": "Service Account", "severity": "CRITICAL", "provider": "Google"},

    # Authentication
    "jwt": {"category": "Auth Token", "severity": "HIGH", "provider": "JWT"},
    "oauth-config": {"category": "OAuth Config", "severity": "HIGH", "provider": "Generic"},
    "auth0-client-secret": {"category": "Auth0 Client Secret", "severity": "CRITICAL", "provider": "Auth0"},
    "auth0-domain": {"category": "Auth0 Config", "severity": "LOW", "provider": "Auth0"},
    "http-auth": {"category": "Auth Credential", "severity": "HIGH", "provider": "HTTP"},
    "auth": {"category": "Auth Pattern", "severity": "MEDIUM", "provider": "Generic"},

    # Cryptographic
    "asymmetric-keys_secrets": {"category": "Private Key", "severity": "CRITICAL", "provider": "Crypto"},
    "crypto": {"category": "Crypto Material", "severity": "HIGH", "provider": "Generic"},
    "base64": {"category": "Encoded Secret", "severity": "LOW", "provider": "Generic"},

    # Generic / Catch-all
    "secrets": {"category": "Generic Secret", "severity": "MEDIUM", "provider": "Unknown"},
    "sec": {"category": "Security Pattern", "severity": "LOW", "provider": "Unknown"},
    "json-sec": {"category": "JSON Secret", "severity": "MEDIUM", "provider": "Unknown"},
    "heroku-keys_secrets": {"category": "Platform Token", "severity": "HIGH", "provider": "Heroku"},
    "picatic-keys_secrets": {"category": "Payment Token", "severity": "HIGH", "provider": "Picatic"},

    # BUILT-IN: Frontend Framework Env Vars
    "react_env_vars": {"category": "React Secret", "severity": "CRITICAL", "provider": "React"},
    "framework_secrets": {"category": "Framework Secret", "severity": "CRITICAL", "provider": "Frontend"},
    "webpack_define_plugin": {"category": "Build Secret", "severity": "CRITICAL", "provider": "Webpack"},
}

# Patterns that should be skipped in JS (not relevant or too noisy)
JS_SKIP_PATTERNS = {
    "xss", "sqli", "ssrf", "lfi", "rce", "ssti", "idor",
    "redirect", "cors", "takeovers", "debug-pages", "debug_logic",
    "php-curl", "php-errors", "php-serialized", "php-sinks", "php-sources",
    "execs", "ccode", "parsers", "serial", "strings", "swearwords",
    "typos", "jsvar", "interestingEXT", "interestingsubs", "modern-frameworks",
    "meg-headers", "servers", "ip", "fw", "img-traversal", "xml",
    "openapi", "api-endpoints", "urls", "interestingparams", "upload-fields",
    "go-functions", "badwords"
}


class JSGFSecretScanner:
    """
    GF-pattern-powered secret scanner for JavaScript content.

    Loads regex patterns from ~/.gf/*.json AND built-in patterns for frontend
    framework env vars (React, Vue, Angular, Gatsby, Next.js).

    Covers: 36+ GF patterns + 3 built-in frontend patterns = 39+ total.
    """

    def __init__(self, config: Dict):
        self.config = config
        gf_dir_path = config.get('tools', {}).get('paths', {}).get('gf_patterns', '~/.gf')
        self.gf_dir = Path(gf_dir_path).expanduser()
        self.patterns = self._load_secret_patterns()

        # Entropy threshold for filtering low-entropy false positives
        self.min_entropy = config.get('js_secret_scanner', {}).get('min_entropy', 3.5)
        self.max_line_context = config.get('js_secret_scanner', {}).get('max_line_context', 120)

        if not self.patterns:
            logger.warning(f"No GF secret patterns loaded from {self.gf_dir}")
        else:
            builtin_count = len(BUILTIN_PATTERNS)
            gf_count = len(self.patterns) - builtin_count
            logger.info(f"Loaded {len(self.patterns)} secret patterns ({gf_count} GF + {builtin_count} built-in)")

    def _load_secret_patterns(self) -> Dict[str, re.Pattern]:
        """Load secret-relevant patterns from GF directory + built-ins."""
        patterns = {}

        # 1. Load from GF directory
        if self.gf_dir.exists():
            for json_file in self.gf_dir.glob('*.json'):
                pattern_name = json_file.stem

                if pattern_name in JS_SKIP_PATTERNS:
                    continue

                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)

                    if 'pattern' not in data:
                        continue

                    flags = re.IGNORECASE
                    if data.get('flags', '').lower() == 'i':
                        flags = re.IGNORECASE

                    try:
                        compiled = re.compile(data['pattern'], flags)
                        patterns[pattern_name] = compiled
                    except re.error as e:
                        logger.warning(f"Invalid regex in {json_file.name}: {e}")

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in {json_file.name}: {e}")
                except Exception as e:
                    logger.error(f"Failed to load pattern {json_file.name}: {e}")
        else:
            logger.warning(f"GF patterns directory not found: {self.gf_dir}")

        # 2. Add built-in patterns (frontend framework env vars)
        for name, compiled in BUILTIN_PATTERNS.items():
            if name not in patterns:
                patterns[name] = compiled
                logger.debug(f"Added built-in pattern: {name}")

        return patterns

    def _shannon_entropy(self, data: str) -> float:
        """Calculate Shannon entropy to filter low-entropy false positives."""
        if not data:
            return 0.0
        import math
        entropy = 0.0
        for x in set(data):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def _is_placeholder(self, value: str) -> bool:
        """Check if a matched value is a placeholder or example."""
        placeholders = [
            'your_', 'my_', 'example', 'sample', 'test', 'demo', 'dummy',
            'placeholder', 'xxxx', 'aaaa', 'bbbb', 'cccc', 'dddd', 'eeee',
            '1234567890', 'abcdef', '000000', '111111', '999999',
            'insert_', 'replace_', 'change_', 'edit_',
            'YOUR_', 'MY_', 'EXAMPLE', 'SAMPLE', 'TEST', 'DEMO',
            'process.env.', 'import.meta.env.', 'window.__ENV__',
            '${', '{', '}', 'undefined', 'null', 'true', 'false',
        ]
        lower_val = value.lower()
        return any(ph in lower_val for ph in placeholders)

    def _get_line_context(self, content: str, match_start: int, match_end: int) -> Tuple[int, str]:
        """Get line number and surrounding context for a match."""
        lines_before = content[:match_start].count('\n')
        line_num = lines_before + 1

        line_start = content.rfind('\n', 0, match_start) + 1
        line_end = content.find('\n', match_end)
        if line_end == -1:
            line_end = len(content)

        line_content = content[line_start:line_end].strip()
        if len(line_content) > self.max_line_context:
            match_in_line = match_start - line_start
            start = max(0, match_in_line - self.max_line_context // 2)
            end = min(len(line_content), start + self.max_line_context)
            line_content = line_content[start:end]

        return line_num, line_content

    def _extract_match_value(self, match: re.Match, pattern_name: str) -> Optional[str]:
        """Extract the actual secret value from a regex match."""
        # Try numbered groups first (most common)
        if match.lastindex and match.lastindex >= 1:
            return match.group(1)

        # Try common group names
        for group_name in ['secret', 'key', 'token', 'value', 'password', 'api_key']:
            try:
                val = match.group(group_name)
                if val:
                    return val
            except IndexError:
                continue

        # Fallback to full match
        return match.group(0)

    def scan_js_content(self, js_content: str, source_url: str = '') -> List[Dict]:
        """
        Scan JavaScript content for secrets using loaded GF + built-in patterns.

        Args:
            js_content: The JavaScript source code to scan
            source_url: URL where the JS was found (for attribution)

        Returns:
            List of finding dicts with type, value, severity, context, etc.
        """
        findings = []

        if not self.patterns:
            logger.warning("No patterns loaded. Skipping GF secret scan.")
            return findings

        if not js_content or len(js_content) < 10:
            return findings

        for pattern_name, regex in self.patterns.items():
            metadata = SECRET_PATTERN_METADATA.get(pattern_name, {
                "category": "Unknown",
                "severity": "MEDIUM",
                "provider": "Unknown"
            })

            for match in regex.finditer(js_content):
                try:
                    matched_value = self._extract_match_value(match, pattern_name)
                    if not matched_value or len(matched_value) < 4:
                        continue

                    if self._is_placeholder(matched_value):
                        continue

                    # Entropy check for token-like values
                    if len(matched_value) >= 16:
                        entropy = self._shannon_entropy(matched_value)
                        if entropy < self.min_entropy:
                            continue

                    line_num, line_context = self._get_line_context(
                        js_content, match.start(), match.end()
                    )

                    finding = {
                        'type': metadata['category'],
                        'provider': metadata['provider'],
                        'pattern_name': pattern_name,
                        'value': matched_value,
                        'severity': metadata['severity'],
                        'line': line_num,
                        'context': line_context,
                        'source': source_url,
                        'confidence': 'high' if len(matched_value) > 20 else 'medium',
                        'entropy': self._shannon_entropy(matched_value) if len(matched_value) >= 8 else 0,
                        'match_start': match.start(),
                        'match_end': match.end(),
                    }

                    findings.append(finding)

                except Exception as e:
                    logger.debug(f"Error processing match for {pattern_name}: {e}")
                    continue

        # Deduplicate by value
        seen = set()
        unique_findings = []
        for f in findings:
            key = (f['pattern_name'], f['value'])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        unique_findings.sort(key=lambda x: severity_order.get(x['severity'], 5))

        logger.info(f"GF secret scan found {len(unique_findings)} unique secrets in {source_url}")
        return unique_findings

    def get_pattern_stats(self) -> Dict[str, int]:
        """Return stats about loaded patterns by category."""
        stats = {}
        for name in self.patterns.keys():
            meta = SECRET_PATTERN_METADATA.get(name, {"category": "Unknown"})
            cat = meta['category']
            stats[cat] = stats.get(cat, 0) + 1
        return stats