"""
secret_validator.py — false-positive suppression for JS secret findings.

Drop-in for deepbug's JSAnalyzer:
  1. Replace the body of _load_secret_patterns() with HARDENED_SECRET_PATTERNS.
  2. Replace _extract_secrets() with a call to extract_secrets() below, OR
     pass your existing raw findings through SecretValidator.filter_findings().

The three big FP sources in the original pattern set were:
  - "AWS Secret Key"  r"[A-Za-z0-9/+=]{40}"      -> matched every hash / b64 blob
  - "Heroku API Key"  <bare UUID>                -> matched every UUID in the app
  - "Generic API Key" keyword 'token'|'secret'   -> matched csrfToken, cancelToken...
All three are handled below via structural gates + entropy + placeholder checks.
"""

import re
import math
import json
import base64
from typing import Dict, List, Optional


# --- hardened pattern set -------------------------------------------------
# meta keys:
#   min_entropy : Shannon entropy floor (bits/char) on the captured secret. 0 = skip.
#   group       : which regex group holds the secret (default 0 = whole match).
#   gate        : extra validation applied in SecretValidator.filter_findings():
#                   None          -> entropy + placeholder only
#                   'jwt'         -> must decode as a real JWT header with 'alg'
#                   'aws_secret'  -> only kept if an AKIA id is present in the file
#                   'heroku_uuid' -> only kept if 'heroku' is in the local context
HARDENED_SECRET_PATTERNS: List[Dict] = [
    {"name": "AWS Access Key ID",
     "regex": r"\bAKIA[0-9A-Z]{16}\b", "min_entropy": 2.5},
    {"name": "AWS Secret Access Key",
     "regex": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
     "min_entropy": 4.2, "gate": "aws_secret"},
    {"name": "Google API Key",
     "regex": r"\bAIza[0-9A-Za-z_\-]{35}\b", "min_entropy": 3.0},
    {"name": "GitHub Token",
     "regex": r"\bgh[pousr]_[0-9A-Za-z]{36,251}\b", "min_entropy": 3.5},
    {"name": "GitHub Fine-Grained PAT",
     "regex": r"\bgithub_pat_[0-9A-Za-z_]{22,255}\b", "min_entropy": 3.5},
    {"name": "Slack Token",
     "regex": r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "min_entropy": 3.0},
    {"name": "Stripe Secret Key",
     "regex": r"\bsk_live_[0-9a-zA-Z]{24,}\b", "min_entropy": 3.0},
    {"name": "Stripe Restricted Key",
     "regex": r"\brk_live_[0-9a-zA-Z]{24,}\b", "min_entropy": 3.0},
    {"name": "JWT",
     "regex": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b",
     "min_entropy": 3.5, "gate": "jwt"},
    {"name": "Private Key Block",
     "regex": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
     "min_entropy": 0.0},
    {"name": "Twilio API Key",
     "regex": r"\bSK[0-9a-f]{32}\b", "min_entropy": 3.0},
    {"name": "Mailgun API Key",
     "regex": r"\bkey-[0-9a-zA-Z]{32}\b", "min_entropy": 3.0},
    {"name": "Discord Webhook",
     "regex": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
     "min_entropy": 0.0},
    {"name": "Firebase URL",
     "regex": r"https://[a-zA-Z0-9_-]+\.firebaseio\.com", "min_entropy": 0.0},
    {"name": "Heroku API Key (UUID)",
     "regex": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
     "min_entropy": 3.0, "gate": "heroku_uuid"},
    {"name": "Generic Secret Assignment",
     # compound keywords only — 'token'/'secret' alone were the FP engine
     "regex": r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
              r"client[_-]?secret|secret[_-]?key|private[_-]?key)"
              r"\s*[:=]\s*['\"]([0-9a-zA-Z\-_.=+/]{20,})['\"]",
     "min_entropy": 3.6, "group": 1},
]


_PLACEHOLDER_TOKENS = (
    "example", "sample", "test", "dummy", "placeholder", "changeme", "your_",
    "xxxx", "redacted", "fake", "mock", "demo", "replaceme", "lorem",
    "0000000000", "1234567890", "abcdefghij", "deadbeef", "secretsecret",
)

# match sits inside a sourcemap / data-uri / SRI hash / asset blob -> not a secret
_CONTEXT_NOISE = re.compile(
    r"(sourcemappingurl|integrity\s*=|sha(?:256|384|512)-|\.map(?:['\"]|$)|"
    r"data:[a-z]+/|;base64,|/fonts?/|/images?/|\.woff2?|\.chunk\.|webpack_require)",
    re.IGNORECASE,
)


class SecretValidator:
    def __init__(self, default_min_entropy: float = 3.0):
        self.default_min_entropy = default_min_entropy
        self._meta = {p["name"]: p for p in HARDENED_SECRET_PATTERNS}

    @staticmethod
    def entropy(s: str) -> float:
        if not s:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in s:
            counts[ch] = counts.get(ch, 0) + 1
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @staticmethod
    def is_placeholder(value: str) -> bool:
        v = value.lower()
        if any(tok in v for tok in _PLACEHOLDER_TOKENS):
            return True
        # low character diversity: "aaaaaaaa", "00000000..."
        if len(set(value)) <= max(3, len(value) // 10):
            return True
        # keyboard / monotonic runs
        if re.search(r"(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwerty|asdf)", v):
            return True
        return False

    @staticmethod
    def valid_jwt(token: str) -> bool:
        try:
            head = token.split(".")[0]
            head += "=" * (-len(head) % 4)
            data = json.loads(base64.urlsafe_b64decode(head.encode()))
            return isinstance(data, dict) and "alg" in data
        except Exception:
            return False

    def filter_findings(self, findings: List[Dict], js_content: str) -> List[Dict]:
        has_akia = bool(re.search(r"\bAKIA[0-9A-Z]{16}\b", js_content))
        cleaned: List[Dict] = []
        seen = set()

        for f in findings:
            value = f.get("value", "") or ""
            name = f.get("type", "")
            context = (f.get("context") or "").lower()
            meta = self._meta.get(name, {})
            gate = meta.get("gate")
            min_e = meta.get("min_entropy", self.default_min_entropy)

            if _CONTEXT_NOISE.search(context):
                continue

            # structural / co-occurrence gates
            if gate == "jwt" and not self.valid_jwt(value):
                continue
            if gate == "aws_secret" and not has_akia:
                continue
            if gate == "heroku_uuid" and "heroku" not in context:
                continue

            # entropy + placeholder (skip for structural finds like PEM blocks / URLs)
            if min_e > 0:
                if self.is_placeholder(value):
                    continue
                if self.entropy(value) < min_e:
                    continue

            key = (name, value)
            if key in seen:
                continue
            seen.add(key)

            f["entropy"] = round(self.entropy(value), 2)
            f["confidence"] = self._confidence(name, gate, has_akia)
            cleaned.append(f)

        return cleaned

    @staticmethod
    def _confidence(name: str, gate: Optional[str], has_akia: bool) -> str:
        strong = {
            "AWS Access Key ID", "Google API Key", "GitHub Token",
            "GitHub Fine-Grained PAT", "Slack Token", "Stripe Secret Key",
            "Stripe Restricted Key", "Private Key Block", "Discord Webhook",
        }
        if name in strong:
            return "high"
        if name == "AWS Secret Access Key" and has_akia:
            return "high"
        return "medium"


def extract_secrets(js_content: str, source_url: str,
                    validator: Optional[SecretValidator] = None) -> List[Dict]:
    """Drop-in replacement for JSAnalyzer._extract_secrets()."""
    validator = validator or SecretValidator()
    findings: List[Dict] = []
    for p in HARDENED_SECRET_PATTERNS:
        rx = re.compile(p["regex"])
        grp = p.get("group", 0)
        for match in rx.finditer(js_content):
            # use the numbered group if it participated, else the whole match
            if grp and match.lastindex and grp <= match.lastindex:
                value = match.group(grp)
            else:
                value = match.group(0)
            if not value:
                continue
            start = max(0, match.start() - 60)
            end = min(len(js_content), match.end() + 60)
            findings.append({
                "type": p["name"],
                "value": value,
                "context": js_content[start:end].replace("\n", " ").strip(),
                "line": js_content[:match.start()].count("\n") + 1,
                "source": source_url,
            })
    return validator.filter_findings(findings, js_content)