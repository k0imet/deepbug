#!/usr/bin/env python3
"""hunt_pia_recon.py — PIA bug bounty: passive subdomain discovery + live probe.

Low-traffic by design (per PIA program rules):
  - subfinder (passive, 3m cap) + certificate-transparency logs only
  - live probing = httpx on 443 only, threads=25, rate=150
  - everything scope-filtered BEFORE any host is probed
  - the staging exclusion host is dropped before probing
"""
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pandas as pd

from app.modules.utils import load_config
from app.modules.project_manager import ProjectManager
from app.modules.tools.subdomain_scanner import SubdomainScanner

CONFIG = load_config()
pm = ProjectManager(CONFIG)
scanner = SubdomainScanner(CONFIG)
sm = pm.get_scope_manager()

PARENTS = ['privateinternetaccess.com', 'piaservers.com', 'piaservers.net']


def _save(key, target, rows, cols):
    if not rows:
        print(f'  (empty) {key} for {target}')
        return
    df = pd.DataFrame(rows, columns=cols)
    pm.save_scan_results(key, target, df)
    print(f'  saved {key}: {len(df)} rows')


def main(mode='enum'):
    print(f'current project: {pm.get_current_project_name()}')
    for parent in PARENTS:
        pm.add_target_to_current_project(parent)
    print('targets:', list(pm.get_all_targets_for_current_project().keys()))

    all_subs = {}
    for parent in PARENTS:
        print(f'\n=== {parent} ===')
        subfinder = scanner._run_subfinder(parent, max_time_minutes=3)
        print(f'  subfinder: {len(subfinder)}')
        _save('subfinder_subdomains', parent, [{'Host': h} for h in subfinder], ['Host'])

        try:
            ct = asyncio.run(scanner._fetch_ct_logs(parent))
        except Exception as e:
            print(f'  ct failed: {e}')
            ct = []
        print(f'  ct_logs: {len(ct)}')
        _save('ct_logs_subdomains', parent, [{'Host': h} for h in ct], ['Host'])

        merged = list(dict.fromkeys(subfinder + ct))
        in_scope = [h for h in merged if sm.is_in_scope(h)]
        dropped = len(merged) - len(in_scope)
        if dropped:
            print(f'  scope: dropped {dropped} out-of-scope')
        all_subs[parent] = in_scope
        _save('all_subdomains', parent, [{'Host': h} for h in in_scope], ['Host'])
        print(f'  in-scope subdomains: {len(in_scope)}')

    print('\n=== live probing (443 only, threads=25, rate=150) ===')
    for parent in PARENTS:
        hosts = all_subs.get(parent, [])
        if not hosts:
            print(f'  {parent}: no in-scope hosts to probe')
            continue
        # hard exclusion: never probe the staging host
        hosts = [h for h in hosts if 'staging-5-77b8e3a311bcb6ec5e96' not in h]
        print(f'  probing {len(hosts)} hosts on {parent} ...')
        try:
            live = scanner.probe_live_hosts_chunked(
                hosts, extra_ports=None, chunk_size=150,
                concurrency=25, rate_limit=150,
                progress_callback=lambda p, m: print(f'    [{p*100:.0f}%] {m}'))
        except Exception as e:
            print(f'  probe failed for {parent}: {e}')
            continue
        print(f'  live: {len(live)}')
        if live:
            _save('live_hosts', parent, live, list(live[0].keys()) if isinstance(live[0], dict) else ['URL'])
        pd.DataFrame({'Host': hosts}).to_csv(
            Path('projects/PIA') / parent.replace('.', '_') / 'probe_input.txt',
            index=False, header=False)

    print('\nDONE')


if __name__ == '__main__':
    main()
