"""
hunter.py — orchestrator: ranked worklist -> per-vuln-class scanners.

Consumes classifier() worklist items ({url, classes, param}) and dispatches
each class to its scanner module. Scanners are imported lazily so a missing
module degrades to a SKIP instead of crashing the run. Classes that need
opt-in state (sessions, canary hosts, POST-only) are printed as
"SKIP (needs opt-in)" and recorded in the report.

SAFETY: honors each scanner's own GET-only default; never enables POST or
sessioned scanners without an explicit opt-in.
"""

import asyncio
import importlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))

# vuln class -> (module name, class name)
_REGISTRY = {
    "sqli": ("sqli_scanner", "SQLiScanner"),
    "xss": ("html_injection_scanner", "HtmlInjectionScanner"),
    "html-injection": ("html_injection_scanner", "HtmlInjectionScanner"),
    "ssrf": ("ssrf_scanner", "SSRFScanner"),
    "idor": ("idor_scanner", "IDORScanner"),
    "host-header": ("host_header_scanner", "HostHeaderScanner"),
    "cache-poison": ("cache_poison_scanner", "CachePoisonScanner"),
    "info-leak": ("auth_gateway_scanner", "AuthGatewayScanner"),
    "auth-bypass": ("auth_gateway_scanner", "AuthGatewayScanner"),
    "open-redirect": ("open_redirect_validator", "OpenRedirectValidator"),
    "lfi": ("xxe_scanner", "XXEScanner"),
    "xxe": ("xxe_scanner", "XXEScanner"),
    "jwt": ("jwt_scanner", "JWTScanner"),
}

_OPTIN_REASON = {
    "idor": "needs opt-in: requires authenticated sessions",
    "open-redirect": "needs opt-in: requires a canary host",
}


def _load_scanner(class_name: str):
    module_name, cls_name = _REGISTRY[class_name]
    return getattr(importlib.import_module(f"app.modules.tools.{module_name}"), cls_name)


def _findings_of(raw: Any) -> List[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return [raw]


async def _invoke(scanner, url: str) -> Optional[List[Any]]:
    """Try the common scan entry points in order; return findings or None."""
    url_list = [url]
    for name in ("validate_sync", "scan_sync", "scan"):
        fn = getattr(scanner, name, None)
        if fn is None:
            continue
        try:
            if asyncio.iscoroutinefunction(fn):
                res = await fn(url_list)
            else:
                res = await asyncio.to_thread(fn, url_list)
            return _findings_of(res)
        except TypeError:
            try:
                if asyncio.iscoroutinefunction(fn):
                    res = await fn()
                else:
                    res = await asyncio.to_thread(fn)
                return _findings_of(res)
            except TypeError:
                continue
        except Exception:
            continue
    return None


async def _run_class(class_name: str, item: Dict) -> Dict:
    url = item.get("url", "")
    scanner_name = f"{_REGISTRY[class_name][1]}" if class_name in _REGISTRY else class_name
    if class_name in _OPTIN_REASON:
        print(f"SKIP (needs opt-in) {class_name}: {url}")
        return {"class": class_name, "scanner": scanner_name,
                "findings": [], "skipped": True, "reason": _OPTIN_REASON[class_name]}
    try:
        cls = _load_scanner(class_name)
    except (ImportError, AttributeError) as e:
        print(f"SKIP (scanner unavailable) {class_name} [{scanner_name}]: {url}")
        return {"class": class_name, "scanner": scanner_name,
                "findings": [], "skipped": True, "reason": f"module unavailable: {e}"}
    try:
        scanner = cls()
    except TypeError:
        scanner = cls({"url": url, "param": item.get("param"),
                       "classes": item.get("classes", [])})
    try:
        findings = await _invoke(scanner, url)
    except Exception as e:
        print(f"SKIP (scan error) {class_name}: {url} ({e})")
        return {"class": class_name, "scanner": scanner_name,
                "findings": [], "skipped": True, "reason": f"scan error: {e}"}
    if findings is None:
        print(f"SKIP (no usable scan method) {class_name}: {url}")
        return {"class": class_name, "scanner": scanner_name,
                "findings": [], "skipped": True, "reason": "no scan entry point"}
    return {"class": class_name, "scanner": scanner_name,
            "findings": findings, "skipped": False, "reason": None}


async def run(worklist: List[Dict], max_items: int = 20,
              concurrency: int = 3) -> Dict:
    """Dispatch worklist items to per-class scanners. Returns report dict."""
    sem = asyncio.Semaphore(concurrency)
    results: List[Dict] = []
    total_findings = 0
    total_skips = 0
    total_scans = 0

    async def one(item):
        async with sem:
            classes = item.get("classes") or []
            return [await _run_class(c, item) for c in classes]

    items = worklist[:max_items]
    for item in items:
        url = item.get("url", "")
        print(f"== {url} [{item.get('classes') or []}] param={item.get('param')}")
        scans = await one(item)
        for s in scans:
            if s["skipped"]:
                total_skips += 1
            else:
                total_scans += 1
                total_findings += len(s["findings"])
        results.append({"item": url, "param": item.get("param"),
                        "classes": item.get("classes", []), "scans": scans})
    return {"summary": {"items": len(items), "scans": total_scans,
                        "skipped": total_skips, "findings": total_findings},
            "results": results}


def run_sync(worklist: List[Dict], max_items: int = 20,
             concurrency: int = 3) -> Dict:
    return asyncio.run(run(worklist, max_items=max_items, concurrency=concurrency))


def _main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <worklist.json> [out.json]")
        sys.exit(1)
    with open(sys.argv[1], encoding="utf-8") as fh:
        worklist = json.load(fh)
    report = run_sync(worklist)
    print(json.dumps(report["summary"]))
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"report -> {sys.argv[2]}")


if __name__ == "__main__":
    _main()