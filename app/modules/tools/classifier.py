"""
classifier.py — surface classification + ranking for deepbug.

Feeds the endpoint/param inventory through the technique_library routing tables
(URL patterns, parameter semantics) and scores every item, mirroring the
recon->map handoff of the BugHunter methodology: every (url,param) becomes a
ranked attack-surface line with its likely vulnerability classes, so focused
testing (and reporting) start at the highest-value lines.

Inputs (any of):
  - list of endpoint dicts from endpoint_engine (url/method fields)
  - list of endpoint dicts from EndpointValidator.validate (url/method/status)
  - plain list of URL strings

Output: same dicts with 'classes' (max 3) and 'priority' added, sorted desc.
"""

import re
import sys
import json
from typing import List, Dict, Any

from app.modules.tools.technique_library import (
    param_to_classes,
    url_to_classes,
    rank_surface,
    param_noise,
)

_MAX_CLASSES = 3
_AUTH_STATUS_SIGNAL = {401, 403}


def _is_noise_param(name: str) -> bool:
    low = name.lower()
    return any(low == p or low.startswith(p) for p in param_noise())


def _param_names(url: str) -> List[str]:
    q = url.split("?", 1)[1] if "?" in url else ""
    names = []
    for part in q.split("&"):
        if "=" not in part:
            continue
        name = part.split("=")[0].strip()
        if name and not _is_noise_param(name):
            names.append(name)
    return names


def _merge_classes(url: str, params: List[str]) -> List[str]:
    # param-derived classes win (param signals beat path hints), then URL rules
    classes = []
    for p in params:
        for c in param_to_classes(p):
            if c not in classes:
                classes.append(c)
    for c in url_to_classes(url):
        if c not in classes:
            classes.append(c)
    return classes[: _MAX_CLASSES]


def classify_ep(ep: Dict[str, Any]) -> Dict[str, Any]:
    url = ep.get("url", "")
    params = ep.get("params") or _param_names(url)
    ep["classes"] = _merge_classes(url, params)
    ep["param"] = ep.get("param")
    # auth-relevant surfaces get pushed up
    if ep.get("method", "GET") not in ("GET", "OPTIONS"):
        ep["priority_bump"] = 5
    return ep


def classify_and_rank(endpoints: List[Any]) -> List[Dict[str, Any]]:
    """Accept endpoint dicts (or bare strings), classify, rank, return sorted."""
    normalized = []
    for ep in endpoints:
        if isinstance(ep, str):
            ep = {"url": ep, "method": "GET"}
        normalized.append(classify_ep(dict(ep)))
    return rank_surface(normalized)


def top_worklist(endpoints: List[Any], limit: int = 20) -> List[Dict[str, Any]]:
    ranked = classify_and_rank(endpoints)
    return ranked[:limit]


def run(endpoints_json: str, out_json: str, limit: int = 50):
    """CLI: read endpoints JSON array (dicts or strings), write ranked list."""
    with open(endpoints_json, encoding="utf-8") as fh:
        eps = json.load(fh)
    ranked = classify_and_rank(eps)[:limit]
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(ranked, fh, indent=2)
    print(f"ranked {len(ranked)} items -> {out_json}")
    for ep in ranked[:10]:
        print(f"  [prio {ep.get('priority', 0):>3}] {ep.get('method','GET')} "
              f"{ep.get('url')} <- {ep.get('classes')}")


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 50)