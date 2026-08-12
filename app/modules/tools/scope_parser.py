"""
scope_parser.py — include/exclude scope matching for recon targets.

Parses program scope text (markdown sections, JSON scope files, plain line
lists) into include/exclude patterns with BugHunter Scope semantics:
  - *.example.com  -> any depth of labels UNDER example.com, not bare it
  - example.com    -> the host AND any subdomain depth
  - re:<regex>     -> compiled as-is (tested against host and raw input)
Suffix confusion is guarded: example.com.evil.com never matches example.com.

SAFETY: offline parsing only, no network.
"""

import json
import os
import re
import sys
from typing import List, Optional, Tuple
from urllib.parse import urlparse

_INCLUDE_JSON_KEYS = ("in_scope", "domains", "assets", "targets", "urls")
_EXCLUDE_JSON_KEYS = ("out_scope", "out_of_scope")
_INCLUDE_SECTION = ("in scope", "in-scope", "in_scope")
_EXCLUDE_SECTION = ("out of scope", "out-of-scope", "out_scope", "exclusion")


class _Pattern:
    __slots__ = ("source", "rx", "wild")

    def __init__(self, source: str):
        self.source = source
        text = source.strip().strip("`").strip()
        text = re.sub(r"^(?:https?|wss?|ftp)://", "", text, flags=re.I)
        text = text.rstrip("/")
        if text.startswith("re:"):
            self.rx = re.compile(text[3:], re.I)
            self.wild = False
        elif text.startswith("*."):
            self.rx = re.compile(rf"^.+\.{re.escape(text[2:].lstrip('.'))}$", re.I)
            self.wild = True
        else:
            if text.endswith(":80") or text.endswith(":443"):
                text = text.rsplit(":", 1)[0]
            if text.startswith("."):
                text = text.lstrip(".")
                self.wild = True
            else:
                self.wild = False
            self.rx = re.compile(rf"^(?:.+\.)?{re.escape(text.rstrip('.'))}$", re.I)

    def match(self, host: str, raw: str) -> bool:
        if self.rx.match(host):
            return True
        return self.rx.match(raw) if raw != host else False


def _candidates(lines: List[str]) -> Tuple[List[str], List[str]]:
    inside, outside = [], []
    section = "in"
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            low = stripped.lstrip("#").strip().lower()
            for s in _INCLUDE_SECTION:
                if s in low:
                    section = "in"
                    break
            else:
                for s in _EXCLUDE_SECTION:
                    if s in low:
                        section = "out"
                        break
            continue
        if "(placeholder)" in stripped.lower():
            continue
        item = re.sub(r"^\s*[-*+>]|\s*(?:\[[ x]\])\s*", "", stripped).strip()
        if not item or item == "-":
            continue
        (outside if section == "out" else inside).append(item)
    return inside, outside


def _from_json(obj, out: List[str], inside: List[str]):
    if isinstance(obj, dict):
        for k, v in obj.items():
            low = k.lower().replace("-", "_")
            if low in ("in_scope",) or low in ("domains", "assets", "targets", "urls"):
                _collect(v, inside)
            elif low in ("out_scope", "out_of_scope"):
                _collect(v, out)
            else:
                _from_json(v, out, inside)
    elif isinstance(obj, list):
        for i in obj:
            _from_json(i, out, inside)


def _collect(node, dest: List[str]):
    if isinstance(node, str):
        dest.append(node)
    elif isinstance(node, list):
        for i in node:
            _collect(i, dest)
    elif isinstance(node, dict):
        for v in node.values():
            _collect(v, dest)


class ScopeParser:
    def __init__(self, text: str):
        inside, outside = [], []
        try:
            obj = json.loads(text)
            if isinstance(obj, (dict, list)):
                _from_json(obj, outside, inside)
            else:
                inside, outside = _candidates(text.splitlines())
        except (json.JSONDecodeError, TypeError):
            inside, outside = _candidates(text.splitlines())
        self._in: List[_Pattern] = [_Pattern(p) for p in inside]
        self._out: List[_Pattern] = [_Pattern(p) for p in outside]
        self.patterns = {"in_scope": inside, "out_of_scope": outside}

    @staticmethod
    def domain_from_url(value: str) -> str:
        """Hostname from a URL or bare host string (lowercased, port stripped)."""
        value = value.strip()
        if "://" in value:
            host = urlparse(value).hostname or ""
        else:
            host = value.split("/", 1)[0]
            if host.startswith("["):
                host = host.strip("[]").split("]")[0]
        host = host.rstrip(".").lower()
        if ":" in host and host.rsplit(":", 1)[1].isdigit():
            host = host.rsplit(":", 1)[0]
        return host

    def _host(self, host_or_url: str) -> Tuple[str, str]:
        host = self.domain_from_url(host_or_url)
        return host, host_or_url.strip().lower()

    def out_of_scope(self, host_or_url: str) -> bool:
        host, raw = self._host(host_or_url)
        return any(p.match(host, raw) for p in self._out)

    def in_scope(self, host_or_url: str) -> bool:
        if self.out_of_scope(host_or_url):
            return False
        host, raw = self._host(host_or_url)
        return any(p.match(host, raw) for p in self._in)

    def matches(self, host_or_url: str) -> Optional[str]:
        host, raw = self._host(host_or_url)
        for p in self._out:
            if p.match(host, raw):
                return f"out_of_scope:{p.source}"
        for p in self._in:
            if p.match(host, raw):
                return f"in_scope:{p.source}"
        return None


def _main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <scope.txt|scope.json> [host...]")
        sys.exit(1)
    with open(sys.argv[1], encoding="utf-8") as fh:
        parser = ScopeParser(fh.read())
    hosts = sys.argv[2:] or ["example.com", "a.example.com", "x.test.example.com",
                             "example.com.evil.com"]
    print(f"in patterns: {parser.patterns['in_scope']}")
    print(f"out patterns: {parser.patterns['out_of_scope']}")
    for h in hosts:
        print(f"   {h:35s} in={str(parser.in_scope(h)):5s} "
              f"out={str(parser.out_of_scope(h)):5s} match={parser.matches(h)}")


if __name__ == "__main__":
    _main()