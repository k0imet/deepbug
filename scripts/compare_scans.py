#!/usr/bin/env python3
"""compare_scans.py — change detection between two JS scans of the same target.

Diff-based intel the tool previously couldn't answer:
  - NEW endpoints (released since last scan)
  - REMOVED endpoints (dead-endpoint cleanup / feature removal)
  - NEW/rotated secrets (credential rotation or new exposure)
  - CHANGED JS files (content_hash differs -> re-analyze for new findings)
  - NEW vulnerable libraries introduced

Usage:
  python3 scripts/compare_scans.py projects/<proj>/<target>_scanA projects/<proj>/<target>_scanB
  (each dir is a snapshot copy of the target's *_results.json files)
"""
import json
import os
import sys
from pathlib import Path

FRAMES = {
    'endpoints': 'js_discovered_endpoints_results.json',
    'secrets': 'js_sensitive_data_findings_results.json',
    'libraries': 'js_libraries_results.json',
    'vulnerable_libs': 'js_vulnerable_libs_results.json',
    'files': 'js_files_results.json',
    'api_keys': 'js_api_keys_results.json',
    'oauth': 'js_oauth_clients_results.json',
}


def _load_dir(d: Path) -> dict:
    out = {}
    for key, fname in FRAMES.items():
        p = d / fname
        rows = []
        if p.exists():
            try:
                data = json.load(open(p))
                rows = data if isinstance(data, list) else []
            except Exception as e:
                print(f"  (warn) {fname}: {e}")
        out[key] = rows
    return out


def _ep_key(r):
    return (str(r.get('method', 'GET')).upper(), r.get('endpoint') or r.get('url') or '')


def _sec_key(r):
    return str(r.get('value', ''))


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 1
    old_dir, new_dir = Path(sys.argv[1]), Path(sys.argv[2])
    if not old_dir.is_dir() or not new_dir.is_dir():
        print(f"error: both arguments must be directories.\n  old={old_dir} (exists={old_dir.is_dir()})\n  new={new_dir} (exists={new_dir.is_dir()})")
        return 1

    old, new = _load_dir(old_dir), _load_dir(new_dir)

    def section(title, rows):
        print(f"\n### {title} ({len(rows)})")
        for r in rows[:60]:
            print(f"  - {r}")
        if len(rows) > 60:
            print(f"  ... and {len(rows)-60} more")

    # endpoints
    o_eps, n_eps = {_ep_key(r) for r in old['endpoints']}, {_ep_key(r) for r in new['endpoints']}
    added = sorted(n_eps - o_eps)
    removed = sorted(o_eps - n_eps)
    # secrets
    o_sec, n_sec = {_sec_key(r) for r in old['secrets']}, {_sec_key(r) for r in new['secrets']}
    sec_added = sorted(n_sec - o_sec)
    sec_gone = sorted(o_sec - n_sec)
    # libraries
    o_lib = {f"{r.get('library')}@{r.get('version')}" for r in old['libraries']}
    n_lib = {f"{r.get('library')}@{r.get('version')}" for r in new['libraries']}
    # files changed by content_hash
    o_files = {r.get('url'): r.get('content_hash') for r in old['files']}
    n_files = {r.get('url'): r.get('content_hash') for r in new['files']}
    changed = sorted(u for u in n_files if o_files.get(u) and n_files.get(u) != o_files.get(u))
    new_files = sorted(set(n_files) - set(o_files))
    # vulnerable libs
    o_vuln = {f"{r.get('library')}@{r.get('version')}:{r.get('cve')}" for r in old['vulnerable_libs']}
    n_vuln = {f"{r.get('library')}@{r.get('version')}:{r.get('cve')}" for r in new['vulnerable_libs']}
    # oauth
    o_oa = {f"{r.get('host')}|{r.get('endpoint')}" for r in old['oauth'] if r.get('client_secret_exposed')}
    n_oa = {f"{r.get('host')}|{r.get('endpoint')}" for r in new['oauth'] if r.get('client_secret_exposed')}

    print(f"Comparing {old_dir}  ->  {new_dir}")
    section("🆕 NEW endpoints", [f"{m} {u}" for m, u in added])
    section("🗑️ REMOVED endpoints", [f"{m} {u}" for m, u in removed])
    section("🔑 NEW secrets", [s[:60] for s in sec_added])
    section("💤 secrets no longer present", [s[:60] for s in sec_gone])
    section("📦 NEW libraries", sorted(n_lib - o_lib))
    section("⚠️ CHANGED JS files (re-analyze)", changed)
    section("🆕 NEW JS files", new_files)
    section("🚨 NEW vulnerable libs", sorted(n_vuln - o_vuln))
    section("🔄 NEW exposed oauth clients", sorted(n_oa - o_oa))

    print(f"\nSummary: +{len(added)} endpoints, -{len(removed)} removed, "
          f"+{len(sec_added)} secrets, {len(changed)} changed files, "
          f"+{len(n_vuln - o_vuln)} vulnerable libs")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
