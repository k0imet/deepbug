#!/usr/bin/env python3
"""Headless re-run of the JS Analysis (v3.0 engine) for a project target,
saving all result frames exactly like 1_Recon.py does.

Usage:
  python3 scripts/rerun_js_analysis.py [target_domain]
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd
from app.modules.utils import load_config
from app.modules.project_manager import ProjectManager
from app.modules.tools.js_analyzer import JSAnalyzer

CONFIG = load_config()
pm = ProjectManager(CONFIG)
target = sys.argv[1] if len(sys.argv) > 1 else '2go.com'

if not pm.get_current_project_name():
    print('no current project set')
    sys.exit(1)

analyzer = JSAnalyzer(CONFIG)
scope_mgr = pm.get_scope_manager()
analyzer.scope_hosts = (set(scope_mgr.get_scope_hosts())
                        if scope_mgr and (scope_mgr.in_scope or scope_mgr.wildcard_scope)
                        else {target})

live = pm.load_scan_results('live_hosts', target)
urls = []
if isinstance(live, pd.DataFrame) and 'URL' in live.columns:
    urls = [u for u in live['URL'].tolist() if u.startswith('http')]
if not urls:
    urls = [f'https://{target}', f'http://{target}']

print(f'project={pm.get_current_project_name()} target={target} '
      f'seed_urls={len(urls)} scope_hosts={len(analyzer.scope_hosts)}')

results = analyzer.analyze_js_for_project(urls, validate=False)

saved = 0
for key, df in results.items():
    if isinstance(df, pd.DataFrame) and not df.empty:
        pm.save_scan_results(key, target, df)
        print(f'  saved {key}: {len(df)} rows')
        saved += 1
print(f'done. saved {saved} result frames')
