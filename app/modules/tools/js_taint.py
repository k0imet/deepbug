"""js_taint.py

v3.6.1: lightweight source-to-sink correlation for DOM XSS primitives.

This is NOT full dataflow: it correlates a user-controllable SOURCE with a
dangerous SINK within the same function/statement scope and labels the result
a CANDIDATE for manual review (confidence low/medium). Real exploitability is
never asserted.

Sources: location.hash/search/href/pathname, document.URL, document.referrer,
URLSearchParams, document.cookie, window.name, postMessage event.data.
Sinks:   innerHTML/outerHTML, document.write, insertAdjacentHTML, eval,
setTimeout/setInterval with string, Function(), script src, iframe srcdoc,
javascript: URI, location= / location.assign with attacker data.
"""

import re
from typing import Dict, List, Optional, Tuple

try:
    import esprima
    HAS_ESPRIMA = True
except Exception:  # pragma: no cover
    esprima = None
    HAS_ESPRIMA = False

_SOURCES = [
    ('location.hash', r'location(?:\.hash|\[["\']hash["\']\])'),
    ('location.search', r'location(?:\.search|\[["\']search["\']\])'),
    ('location.href', r'location(?:\.href|\[["\']href["\']\])'),
    ('location.pathname', r'location(?:\.pathname|\[["\']pathname["\']\])'),
    ('document.URL', r'document\s*\.\s*URL'),
    ('document.referrer', r'document\s*\.\s*referrer'),
    ('URLSearchParams', r'(?:new\s+)?URLSearchParams\s*\('),
    ('document.cookie', r'document\s*\.\s*cookie'),
    ('window.name', r'window\s*\.\s*name'),
    ('postMessage', r'postMessage\s*\('),
]
_SOURCE_RE = [(n, re.compile(p, re.I)) for n, p in _SOURCES]

_SINKS = [
    ('innerHTML', r'\.\s*innerHTML\s*='),
    ('outerHTML', r'\.\s*outerHTML\s*='),
    ('document.write', r'document\s*\.\s*(?:write|writeln)\s*\('),
    ('insertAdjacentHTML', r'\.\s*insertAdjacentHTML\s*\('),
    ('eval', r'(?<![\w$.])eval\s*\('),
    ('setTimeout-str', r'setTimeout\s*\(\s*["\']'),
    ('setInterval-str', r'setInterval\s*\(\s*["\']'),
    ('Function()', r'new\s+Function\s*\('),
    ('script-src', r'\.\s*src\s*=\s*(?:[^;]{0,40}?)?\b`'),
    ('iframe-srcdoc', r'\.\s*srcdoc\s*='),
    ('javascript-uri', r'["\']\s*javascript\s*:'),
    ('location-assign', r'location\s*\.\s*(?:assign|replace)\s*\('),
]
_SINK_RE = [(n, re.compile(p, re.I)) for n, p in _SINKS]


def _line(content: str, pos: int) -> int:
    return content[:pos].count('\n') + 1


def _ctx(js: str, pos: int, w: int = 90) -> str:
    return js[max(0, pos - w // 2): pos + w // 2].strip()


def _source_hits(text: str) -> List[str]:
    return [name for name, rx in _SOURCE_RE if rx.search(text)]


def _ast_function_ranges(root: Dict) -> List[Tuple[int, int, str]]:
    """Return [(start, end, fn_name)] for function-like scopes in an ESTree."""
    out: List[Tuple[int, int, str]] = []
    stack = [root]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        t = node.get('type', '')
        if t in ('FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'):
            rng = node.get('range')
            name = ''
            if t == 'FunctionDeclaration':
                name = (node.get('id') or {}).get('name', '') or '(anonymous)'
            elif t == 'MethodDefinition':
                name = node.get('key', {}).get('name', '(method)')
            if rng:
                out.append((rng[0], rng[1], name))
        if t == 'MethodDefinition':
            val = node.get('value')
            if isinstance(val, dict):
                stack.append(val)
            continue
        for v in node.values():
            if isinstance(v, dict):
                stack.append(v)
            elif isinstance(v, list):
                stack.extend(v)
    return out


def scan_taint(content: str, source_url: str, window: int = 400) -> List[Dict]:
    """Correlate sources with sinks -> taint CANDIDATES (not confirmations)."""
    findings: List[Dict] = []
    seen = set()

    keys = []
    ast = None
    if HAS_ESPRIMA:
        try:
            ast = esprima.parseModule(content).toDict()
        except Exception:
            try:
                ast = esprima.parseScript(content).toDict()
            except Exception:
                ast = None

    for sink_name, srx in _SINK_RE:
        for m in list(srx.finditer(content))[:12]:
            pos = m.start()

            # candidate dataflow: what does this sink consume?
            cons_text = content[pos: pos + 160].split(';')[0]

            # 1) AST-scoped: source present inside the same function body
            fn_name = ''
            fn_flag = False
            for (st, en, name) in (ast and _ast_function_ranges(ast) or []):
                if st <= pos <= en:
                    fn_name = name or ''
                    if _source_hits(content[st:en]):
                        fn_flag = True
                    break

            # 2) proximity fallback (no AST or same-statement)
            lo = max(0, pos - window)
            neigh = content[lo: pos + window]
            srcs = _source_hits(neigh) if not fn_flag else []
            same_stmt = _source_hits(cons_text)

            combined = list(dict.fromkeys(srcs + same_stmt))
            if fn_flag and not combined:
                # source present somewhere in the function -> name it loosely
                combined = _source_hits(content[st:en]) if 'st' in dir() else combined
            if not fn_flag and not combined:
                continue

            conf = 'medium' if (same_stmt or fn_flag) else 'low'
            key = (sink_name, pos)
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                'type': 'dom_xss_taint',
                'sink': sink_name,
                'source': ','.join(combined),
                'function': fn_name,
                'line': _line(content, pos),
                'context': _ctx(content, pos),
                'source_url': source_url,
                'severity': 'MEDIUM',          # evidence signal, not exploitability
                'confidence': conf,
                'note': ('same-function source+sink co-occurrence'
                         if fn_flag else 'proximity ({} chars) - manual review'.format(window)),
            })
    return findings
