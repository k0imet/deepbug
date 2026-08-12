"""
technique_library.py — knowledge base loader for the deepbug framework.

Bundles the Claude-BugHunter hunt-* methodology (681 disclosed-report patterns)
into queryable data: URL/param -> vulnerability-class routing, class weights for
surface ranking, the legacy-protocol bypass matrix, never-submit rules, chain
tables, and payload snippets.

Consumers: classifier.py (surface -> classes + rank), reporting.py (triage
gates), and any scanner that needs target-routed payloads.
"""

import json
import os
import re

_DATA = None


def _load():
    global _DATA
    if _DATA is None:
        path = os.path.join(os.path.dirname(__file__), "..", "data", "technique_library.json")
        with open(path, encoding="utf-8") as fh:
            _DATA = json.load(fh)
    return _DATA


def class_weights():
    return _load()["class_weights"]


def param_noise():
    return _load()["param_noise"]


def param_to_classes(name):
    """Classify a single parameter name by its semantics (case-insensitive)."""
    low = name.lower()
    pre = _load()["param_to_classes"]["predefined"]
    for cls, names in pre.items():
        if low in names:
            return [cls]
    for rule in _load()["param_to_classes"]["name_rules"]:
        pat = rule["match"]
        if pat == "default":
            continue
        if re.search(pat, low):
            return rule["classes"]
    return ["sqli", "xss", "idor"]


def url_to_classes(url):
    """Classify a URL by path/query patterns. Returns ordered class list."""
    hits = []
    for row in _load()["url_pattern_to_classes"]:
        try:
            if re.search(row["pattern"], url, re.I):
                for c in row["classes"]:
                    if c not in hits:
                        hits.append(c)
        except re.error:
            continue
    return hits


def rank_surface(items):
    """Score surface items: weight(class) + 5*has_param + 55*is_secret -> priority.

    items: list of dicts with 'url', optional 'param', optional 'classes',
    optional 'source' == 'secret'.
    Returns items sorted by descending priority with 'priority' set.
    """
    weights = class_weights()
    for it in items:
        classes = it.get("classes") or url_to_classes(it.get("url", ""))
        base = max((weights.get(c, 20) for c in classes), default=20)
        prio = base
        if it.get("param"):
            prio += 5
        if it.get("source") == "secret":
            prio += 55
        it["priority"] = prio
        if not it.get("classes"):
            it["classes"] = classes
    return sorted(items, key=lambda x: -x["priority"])


def rank_host(host):
    """Subdomain keyword triage: p1 / p2 / kill (mirrors cbh _rank_host)."""
    low = host.lower()
    for hint in _load()["priority_rank_hints"]["kill"]:
        if low.startswith(hint):
            return "KILL"
    for hint in _load()["priority_rank_hints"]["p1"]:
        if hint in low:
            return "P1"
    return "P2"


def legacy_protocol_matrix():
    return _load()["legacy_protocol_matrix"]


def payloads(cls):
    return _load()["payloads"].get(cls)


def chain_table():
    return _load()["chain_table"]


def never_submit():
    return _load()["never_submit"]


def is_never_submit(text):
    """Keyword sniff of a finding description against the never-submit list."""
    t = text.lower()
    for rule in never_submit():
        if rule.lower() in t:
            return rule
    return None


def quick_wins():
    return _load()["payloads"]["source_leak_quick"]