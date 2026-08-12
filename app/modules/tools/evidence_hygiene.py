"""
evidence_hygiene.py — redaction of credential-shaped values in evidence.

Pure stdlib, offline, unit-testable. Redacts cookie header values, auth
headers, and KEY=VALUE / "key": "value" / key:value pairs whose names look
like credentials. HAR files get the same treatment across request headers,
cookies, query strings and post params, and are rewritten in place at a new
path.

SAFETY: no network. Masking keeps the last <keep_tail> chars of a value for
correlation; values shorter than keep_tail are fully masked.
"""

import json
import os
import re
import sys
from typing import Any, Dict
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SENSITIVE_NAME_FRAGMENTS = ("cookie", "token", "password", "passwd", "key",
                             "secret", "auth", "session")

# regex catalogue (value is always the last capture group)
_COOKIE_HEADER_RE = re.compile(r"(?i)((?:set-)?cookie)\s*:\s*([^\r\n]*)")
_SESSIONY_PAIR = re.compile(r"(?i)(session|sid|token|auth|csrf|xsrf|access)")
_COOKIE_PAIR_RE = re.compile(r"(?i)([^=;\s,]+)=([^;,\s]+)")
_AUTH_HDR_RE = re.compile(r"(?i)(authorization|proxy-authorization)\s*:\s*"
                          r"(?:[a-z]+\s+)?([^\s,;\"}]+)")
_KV_RE = re.compile(r"(?i)((?<![\w-])(?:api[_-]?key|access_token|client_secret|"
                    r"session[a-z_0-9]*|password|passwd|pwd|secret|token))\b"
                    r"\s*[=:]\s*[\"']*([^&\"';\s,}]+)")
_COOKIE_EQ_RE = re.compile(r"(?i)(?<![\w-])cookie\s*=\s*(\S[^;&\s,;\"'}]*?)"
                           r"(?=\s|;|&|,|\"|'|$)")
_QUERY_PAIR_RE = re.compile(r"(?i)([a-z0-9_.\-[\]]+)=([^&]*)")

_BEAKER = "<redacted>"


def _mask(value: str, keep_tail: int) -> str:
    value = value.strip().rstrip(";,").strip("'\"")
    if keep_tail > 0 and len(value) > keep_tail:
        return f"{_BEAKER}…{value[-keep_tail:]}"
    return _BEAKER


def _hdr_value(match, keep_tail: int) -> str:
    hdr = match.group(1)
    payload = match.group(2)
    def pair(m):
        if _SESSIONY_PAIR.search(m.group(1)):
            return f"{m.group(1)}={_mask(m.group(2), keep_tail)}"
        return m.group(0)
    cleaned = _COOKIE_PAIR_RE.sub(pair, payload)
    return f"{hdr}: {cleaned}"


def redact(text: str, keep_tail: int = 4) -> str:
    """Mask credential-like values in text. Values keep last keep_tail chars."""
    text = _COOKIE_HEADER_RE.sub(lambda m: _hdr_value(m, keep_tail), text)
    text = _AUTH_HDR_RE.sub(
        lambda m: f"{m.group(1)}: {_mask(m.group(2), keep_tail)}", text)
    text = _KV_RE.sub(
        lambda m: f"{m.group(1)}={_mask(m.group(2), keep_tail)}", text)
    text = _COOKIE_EQ_RE.sub(
        lambda m: f"cookie={_mask(m.group(1), keep_tail)}", text)
    return text


def _redact_url(url: str, keep_tail: int) -> str:
    parts = urlsplit(url)
    if not parts.query:
        return url
    redacted = [
        (name, _mask(val, keep_tail) if _is_sensitive(name) else val)
        for name, val in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(redacted), parts.fragment))


def _is_sensitive(name: str) -> bool:
    low = name.lower()
    return any(f in low for f in _SENSITIVE_NAME_FRAGMENTS)


def _redact_node(node: Any, keep_tail: int) -> Any:
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "value" and isinstance(v, str) and _is_sensitive(str(node.get("name", ""))):
                out[k] = _mask(v, keep_tail)
            elif k == "text" and isinstance(v, str):
                out[k] = redact(v, keep_tail)
            elif k == "url" and isinstance(v, str):
                out[k] = redact(_redact_url(v, keep_tail), keep_tail)
            else:
                out[k] = _redact_node(v, keep_tail)
        return out
    if isinstance(node, list):
        return [_redact_node(i, keep_tail) for i in node]
    return node


def redact_har(har_path: str, out_path: str, keep_tail: int = 4) -> None:
    """Parse a HAR file, redact request/response credential fields, write it."""
    with open(har_path, encoding="utf-8") as fh:
        har = json.load(fh)
    sanitized = _redact_node(har, keep_tail)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(sanitized, fh, indent=2)
    print(f"redacted {har_path} -> {out_path}")


def redact_file(in_path: str, out_path: str = "", keep_tail: int = 4) -> str:
    """Redact a generic text file (curl output, dumps). Returns out path."""
    with open(in_path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    cleaned = redact(text, keep_tail)
    target = out_path or (in_path + ".redacted")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(cleaned)
    print(f"redacted {in_path} -> {target}")
    return target


def _main():
    args = sys.argv[1:]
    if len(args) < 2:
        print(f"usage: {sys.argv[0]} <file|har> <file|har> [keep_tail]")
        sys.exit(1)
    tail = int(args[2]) if len(args) > 2 else 4
    src, dst = args[0], args[1]
    if dst.endswith(".har") or (src.endswith(".har") and not dst):
        redact_har(src, dst if dst.endswith(".har") else src + ".redacted", tail)
    else:
        redact_file(src, dst, tail)


if __name__ == "__main__":
    _main()