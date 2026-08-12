# modules/tools/gf_scanner.py
# GF-style URL pattern scanner with a BUILT-IN pattern library.
# Works out of the box; merges ~/.gf/*.json (tomnomnom/mrofisr formats) when present.
#
# Config (optional):
#   tools.paths.gf_patterns -> directory with extra .json patterns (default ~/.gf)

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Optional, Callable, Any
from app.utils.url_utils import urlparse
import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# Built-in pattern library (no external dependency)
# ---------------------------------------------------------------------
BUILTIN_PATTERNS: Dict[str, str] = {
    "xss": r"(?i)(\?|&)(q|s|search|query|keyword|keywords|term|name|value|input|comment|message|text|title|content|view|item|cat|category|err|error|callback|jsonp|qry)=",
    "sqli": r"(?i)(\?|&)(id|uid|user|userid|user_id|item|cat|category|product|prod|order|order_id|num|number|article|post|postid|page_id|doc|document_id|news|thread|topic)=(\d+|'|\")",
    "ssrf": r"(?i)(\?|&)(url|uri|link|src|source|dest|destination|target|redirect|redirect_uri|redirect_url|return|return_to|returnto|next|goto|callback|callback_url|continue|forward|feed|load|fetch|proxy|host|site|domain|image|img|file_url|endpoint|api_url|webhook)=",
    "lfi": r"(?i)(\?|&)(file|path|filepath|filename|dir|directory|folder|page|pg|doc|document|include|template|view|content|layout|load|read|download|root|style|module|lang|locale)=",
    "rce": r"(?i)(\?|&)(cmd|command|exec|execute|run|ping|ip|host|shell|system|code|eval|daemon|dir|action|module|option|patch|process|job|task)=",
    "ssti": r"(?i)(\?|&)(template|name|user|username|email|title|content|message|comment|preview|render|theme|greeting|nickname)=",
    "idor": r"(?i)(\?|&)(id|uid|user|user_id|userid|account|account_id|profile|doc_id|document|order|order_id|invoice|ticket|record|file_id|report|ref|no|num)=\d+",
    "secrets": r"(?i)(api[_-]?key|apikey|access[_-]?key|secret|token|auth[_-]?token|password|passwd|pwd|session|sessionid|jwt|bearer|private[_-]?key|client[_-]?secret)=",
    "debug": r"(?i)((\?|&)(debug|test|dev|stage|staging|verbose|trace|internal|admin|config|log|show|env)=|\.(log|bak|old|swp|env|ini|conf)(\?|$))",
    "sensitive_files": r"(?i)\.(env|git|svn|hg|bak|backup|old|sql|db|sqlite|sqlite3|log|ini|conf|config|yml|yaml|pem|key|crt|zip|tar|gz|tgz|7z|rar|swp|ds_store)(\?|/|$)",
    "api": r"(?i)(/api/|/api$|/v[0-9]+/|/graphql|/swagger|/openapi|/rest/|/wp-json/|/gateway/|/svc/)",
    "cors": r"(?i)(\?|&)(origin|callback|jsonp|cb|domain|allowed)=",
    "takeover": r"(?i)(s3\.amazonaws\.com|\.cloudfront\.net|\.azurewebsites\.net|\.herokuapp\.com|\.github\.io|\.firebaseapp\.com|\.netlify\.app|\.vercel\.app|\.zendesk\.com|\.freshdesk\.com)",
}

# Pattern categories from mrofisr/gf-patterns (external ~/.gf names)
PATTERN_CATEGORIES = {
    "xss": ["xss", "xss-params", "reflected-params"],
    "sqli": ["sqli", "sql-injection", "sql-errors"],
    "ssrf": ["ssrf", "redirect", "open-redirect", "url-params"],
    "lfi": ["lfi", "path-traversal", "file-params"],
    "rce": ["rce", "command-injection", "exec-params"],
    "ssti": ["ssti", "template-injection"],
    "idor": ["idor", "id-params", "numeric-id"],
    "secrets": [
        "aws-keys", "github_secrets", "google-keys_secrets", "heroku-keys_secrets",
        "stripe-keys_secrets", "npm-tokens", "pypi-tokens", "firebase_secrets",
        "jwt", "asymmetric-keys_secrets", "facebook-token_secrets", "twitter-token_secrets",
        "ai-services", "anthropic", "cohere", "groq", "discord-webhooks", "slack-webhook_secrets",
        "secrets",
    ],
    "cloud": ["cloud-resources", "s3-buckets", "servers", "ip", "fw"],
    "api": ["api-endpoints", "openapi", "graphql", "swagger", "api"],
    "sensitive_files": ["sensitive-files", "modern-frameworks", "interestingEXT", "sensitive_files"],
    "debug": ["debug-pages", "interestingparams", "badwords", "debug"],
    "takeover": ["takeovers", "takeover"],
    "cors": ["cors"],
}

# Reverse mapping: pattern_name -> category
PATTERN_TO_CATEGORY = {}
for cat, patterns in PATTERN_CATEGORIES.items():
    for p in patterns:
        PATTERN_TO_CATEGORY[p] = cat
# Built-ins map directly by their own name
for name in BUILTIN_PATTERNS:
    PATTERN_TO_CATEGORY.setdefault(name, name)


class GFScanner:
    def __init__(self, config: Dict):
        self.config = config
        self.patterns: Dict[str, re.Pattern] = {}

        # 1) Built-in library - always available
        for name, rx in BUILTIN_PATTERNS.items():
            try:
                self.patterns[name] = re.compile(rx)
            except re.error as e:
                logger.error(f"Built-in GF pattern '{name}' failed to compile: {e}")

        builtin_count = len(self.patterns)

        # 2) External ~/.gf patterns merge on top (same-name overrides builtin)
        gf_dir_path = self.config.get('tools', {}).get('paths', {}).get('gf_patterns', '~/.gf')
        self.gf_dir = Path(gf_dir_path).expanduser()
        external = self._load_external_patterns()
        self.patterns.update(external)

        loaded_cats = {PATTERN_TO_CATEGORY.get(p, "uncategorized") for p in self.patterns}
        logger.info(f"GFScanner: {builtin_count} built-in + {len(external)} external patterns "
                    f"({len(self.patterns)} total), categories: {sorted(loaded_cats)}")

    def _load_external_patterns(self) -> Dict[str, re.Pattern]:
        """Load .json patterns from the GF directory (tomnomnom + mrofisr formats)."""
        patterns = {}
        if not self.gf_dir.exists():
            logger.info(f"GFScanner: {self.gf_dir} not found - using built-in pattern library only.")
            return patterns

        for json_file in self.gf_dir.glob('*.json'):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if 'pattern' in data:
                    flags = re.IGNORECASE  # gf semantics are case-insensitive by convention
                    try:
                        patterns[json_file.stem] = re.compile(data['pattern'], flags)
                    except re.error as e:
                        logger.warning(f"Invalid regex in {json_file.name}: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in GF pattern {json_file.name}: {e}")
            except Exception as e:
                logger.error(f"Failed to load GF pattern {json_file.name}: {e}")
        return patterns

    # -----------------------------------------------------------------
    # Domain helpers
    # -----------------------------------------------------------------
    def _extract_domain_without_protocol(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc.split(':')[0] if parsed.netloc else url.split('/')[0]

    def _get_root_domains(self, urls: List[str]) -> List[str]:
        root_domains = set()
        for url in urls:
            domain = self._extract_domain_without_protocol(url)
            parts = domain.split('.')
            root_domains.add(".".join(parts[-2:]) if len(parts) >= 2 else domain)
        return list(root_domains)

    def _is_subdomain_of_any(self, domain: str, root_domains: List[str]) -> bool:
        for root in root_domains:
            if domain == root or domain.endswith(f".{root}"):
                return True
        return False

    # -----------------------------------------------------------------
    # Pattern access
    # -----------------------------------------------------------------
    def get_patterns_by_category(self, category: str) -> Dict[str, re.Pattern]:
        target_names = set(PATTERN_CATEGORIES.get(category, [])) | {category}
        return {k: v for k, v in self.patterns.items()
                if k in target_names or PATTERN_TO_CATEGORY.get(k) == category}

    def list_available_categories(self) -> List[str]:
        available = {PATTERN_TO_CATEGORY.get(p, "uncategorized") for p in self.patterns}
        return sorted(available)

    # -----------------------------------------------------------------
    # Scanning
    # -----------------------------------------------------------------
    def scan_in_memory(self, urls: List[str], selected_patterns: Optional[List[str]] = None,
                       selected_categories: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """Filter URLs with pre-compiled patterns; dedupes per (URL, Category)."""
        # Determine which patterns to use
        if selected_categories:
            target_patterns = {}
            for cat in selected_categories:
                target_patterns.update(self.get_patterns_by_category(cat))
        elif selected_patterns:
            target_patterns = {k: v for k, v in self.patterns.items() if k in selected_patterns}
        else:
            target_patterns = self.patterns

        if not target_patterns:
            logger.warning("No patterns selected for scanning.")
            return []

        # url -> category -> set of matched pattern names (dedupe)
        hits: Dict[str, Dict[str, set]] = {}
        for url in urls:
            for pattern_name, regex in target_patterns.items():
                if regex.search(url):
                    category = PATTERN_TO_CATEGORY.get(pattern_name, "uncategorized")
                    hits.setdefault(url, {}).setdefault(category, set()).add(pattern_name)

        findings = []
        for url, cats in hits.items():
            for category, names in cats.items():
                findings.append({
                    "URL": url,
                    "Matched_Pattern": ", ".join(sorted(names)),
                    "Category": category,
                })
        return findings

    def perform_scan(self, target_urls: List[str],
                     progress_callback: Optional[Callable[[float, str], None]] = None,
                     selected_categories: Optional[List[str]] = None) -> Dict[str, pd.DataFrame]:
        """Orchestrates the filtering scan; returns categorized DataFrames."""
        all_scan_results = {
            "gf_filtered_urls": pd.DataFrame(),
            "gf_xss_candidates": pd.DataFrame(),
            "gf_sqli_candidates": pd.DataFrame(),
            "gf_ssrf_candidates": pd.DataFrame(),
            "gf_lfi_candidates": pd.DataFrame(),
            "gf_rce_candidates": pd.DataFrame(),
            "gf_ssti_candidates": pd.DataFrame(),
            "gf_secrets_candidates": pd.DataFrame(),
            "gf_idor_candidates": pd.DataFrame(),
            "gf_api_candidates": pd.DataFrame(),
            "gf_debug_candidates": pd.DataFrame(),
            "gf_sensitive_files_candidates": pd.DataFrame(),
        }

        if not target_urls:
            return all_scan_results

        if progress_callback:
            progress_callback(0.2, f"Filtering {len(target_urls)} URLs with {len(self.patterns)} patterns...")

        findings = self.scan_in_memory(target_urls, selected_categories=selected_categories)

        if findings:
            df = pd.DataFrame(findings)
            all_scan_results["gf_filtered_urls"] = df

            category_map = {
                "xss": "gf_xss_candidates",
                "sqli": "gf_sqli_candidates",
                "ssrf": "gf_ssrf_candidates",
                "lfi": "gf_lfi_candidates",
                "rce": "gf_rce_candidates",
                "ssti": "gf_ssti_candidates",
                "secrets": "gf_secrets_candidates",
                "idor": "gf_idor_candidates",
                "api": "gf_api_candidates",
                "debug": "gf_debug_candidates",
                "sensitive_files": "gf_sensitive_files_candidates",
            }
            for cat, result_key in category_map.items():
                cat_df = df[df['Category'] == cat]
                if not cat_df.empty:
                    all_scan_results[result_key] = cat_df

            logger.info(f"GF found {len(findings)} matches across {df['Category'].nunique()} categories.")
        else:
            logger.info("GF did not find any URLs matching patterns.")

        if progress_callback:
            progress_callback(1.0, "Scan completed.")

        return all_scan_results