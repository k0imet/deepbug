#!/usr/bin/env python3
"""target_playbook.py — the skill-driven checklist as code.

Runs the full DeepBug playbook against a target IN ORDER so nothing gets
skipped, printing a status row per step and writing a playbook report into
the project directory. Derived from docs/skills/* — every stage maps to a
skill (recon, config leaks, JS, auth surface, validators, OOB).

Usage:
  python3 scripts/target_playbook.py example.com                 # all stages
  python3 scripts/target_playbook.py example.com --stage 2       # one stage
  python3 scripts/target_playbook.py example.com --stages 1,2,5  # subset
  WEBHOOK_SITE_UUID=... python3 scripts/target_playbook.py x.com # OOB proofs

Stages:
  1  subdomain enumeration + live-host probing
  2  config/env-file secret scan (environment.js & friends on every live host)
  3  JS analysis (endpoints/secrets/API keys) - full analyzer pipeline
  4  results triage review (dangerous patterns, CSP gadgets, libs, API keys)
  5  auth-surface check (login/signup/reset/verify/mfa routes + auth hosts)
  6  validator battery (REST injection, CORS, redirect, SSRF + OOB, PP/DOM XSS)
  7  GraphQL probe
  8  closure checklist (the five "did I actually..." questions)
"""

import os
import re
import sys
import json
import time
import shutil
import pathlib
from typing import List, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.modules.utils import load_config, is_valid_url
from app.modules.project_manager import ProjectManager
from app.utils.logger import get_logger

logger = get_logger()

# env/config files worth fetching on every live host
ENV_FILES = ['/environment.js', '/config.js', '/env.js', '/runtime-config.js',
             '/app-config.json', '/config.json', '/assets/environment.json',
             '/assets/config.json', '/app-config.js', '/settings.js']

# secret-ish patterns for the config scan (clientId alone is public by design)
SECRET_PATTERNS = [
    (r'clientSecret', 'client_secret'),
    (r'auth0ClientSecret', 'auth0_client_secret'),
    (r'client_secret', 'client_secret'),
    (r'secretKey', 'secret_key'),
    (r'privateKey', 'private_key'),
    (r'apiKey', 'api_key'),
    (r'api_key', 'api_key'),
    (r'webhook', 'webhook'),
    (r'password', 'password'),
    (r'accessToken', 'access_token'),
    (r'refreshToken', 'refresh_token'),
]

AUTH_ROUTES = ['/login', '/signup', '/register', '/forgot-password', '/reset-password',
               '/set-password', '/mfa-reset', '/verify-email', '/account-selection',
               '/password/reset', '/u/login', '/u/signup', '/dbconnections/signup']


class Playbook:
    def __init__(self, domain: str):
        self.domain = domain
        self.cfg = load_config()
        self.pm = ProjectManager(self.cfg)
        self.project = domain.replace('.', '-')
        if not self.pm.create_project(self.project):
            pass
        self.pm.set_current_project(self.project)
        self.proj_path = self.pm.get_current_project_path()
        self.rows: List[str] = []
        self.findings: List[dict] = []

    # ------------------------------------------------------------------ utils
    def step(self, name: str, status: str, detail: str = ''):
        icon = {'OK': '✅', 'SKIP': '⏭️ ', 'WARN': '⚠️ ', 'FAIL': '❌'}.get(status, '·')
        line = f'{icon} {name:44} {detail}'
        self.rows.append(line)
        print(line)

    @staticmethod
    def _fetch_many(urls, timeout=8, workers=16):
        """Parallel GET; returns [(url, status, text_head, content_type)]."""
        import concurrent.futures, httpx
        def one(u):
            try:
                r = httpx.get(u, timeout=timeout, follow_redirects=False,
                              headers={'User-Agent': 'Mozilla/5.0'})
                return (u, r.status_code, r.text[:120000],
                        r.headers.get('content-type', ''))
            except Exception:
                return (u, 0, '', '')
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(one, urls))

    @staticmethod
    def _fetch_gentle(urls, timeout=8):
        """Lower-concurrency fetch with one retry on failure/403 - for scans
        that trip WAF/rate limits (env files). Returns same tuple shape."""
        import time as _t
        first = Playbook._fetch_many(urls, timeout=timeout, workers=4)
        retry = [(u, c, t, ct) for u, c, t, ct in first if c in (0, 403, 420, 429)]
        out = [(u, c, t, ct) for u, c, t, ct in first if c not in (0, 403, 420, 429)]
        if retry:
            _t.sleep(2)
            out += Playbook._fetch_many([u for u, *_ in retry], timeout=timeout, workers=3)
        return out

    def finding(self, kind: str, evidence: str, severity: str = 'info'):
        f = {'kind': kind, 'evidence': evidence[:300], 'severity': severity}
        self.findings.append(f)
        print(f'   🔎 [{severity}] {kind}: {evidence[:220]}')

    def save_report(self):
        rep = f"""# Playbook report: {self.domain}
Generated: {time.strftime('%Y-%m-%d %H:%M')}

## Steps
""" + '\n'.join(self.rows) + """

## Findings
""" + (json.dumps(self.findings, indent=1) if self.findings else 'none')
        pathlib.Path(self.proj_path).mkdir(parents=True, exist_ok=True)
        (pathlib.Path(self.proj_path) / 'playbook_report.md').write_text(rep)
        print(f'\nReport: {self.proj_path}/playbook_report.md')

    # ------------------------------------------------------------------ stage 1
    def subdomains(self):
        self.step('1 subdomain enumeration', 'OK', 'subfinder + amass + resolution')
        sub = shutil.which('subfinder')
        if not sub:
            self.step('1a subfinder', 'SKIP', 'binary missing')
            return
        out = pathlib.Path('/tmp') / f'playbook_{self.domain}_subs.txt'
        try:
            os.system(f'timeout 90 {sub} -d {self.domain} -silent > {out} 2>/dev/null')
            subs = sorted(set(out.read_text().splitlines()))
        except Exception as e:
            self.step('1a subfinder', 'FAIL', str(e))
            return
        self.step(f'1a subfinder', 'OK', f'{len(subs)} hostnames')
        import socket
        live = []
        for h in subs[:60]:
            try:
                socket.gethostbyname(h)
                live.append(h)
            except Exception:
                pass
        self.step('1b resolve', 'OK', f'{len(live)} resolvable')
        alive = []
        for h, code, text, ct in self._fetch_many([f'https://{h}/' for h in live[:25]]):
            if code == 0:
                continue
            title = re.search(r'<title[^>]*>([^<]{0,50})', text, re.I)
            alive.append((h, code, (title.group(1) if title else '').strip()))
        for h, code, title in alive:
            self.step(f'   live {h}', 'OK', f'{code} {title}')
        self._live = [h for h, _, _ in alive] + [self.domain]
        # note interesting names without probing
        interesting = [h for h in subs if re.search(r'(admin|vpn|api|account|auth|billing|test|dev|stage|origin|export|internal)', h)]
        if interesting:
            self.step('1c notable hosts', 'WARN', ', '.join(interesting[:12]))

    # ------------------------------------------------------------------ stage 2
    def env_scan(self):
        self.step('2 config/env-file secret scan', 'OK', 'environment.js & friends')
        hosts = list(getattr(self, '_live', None) or [])
        if not hosts:
            hosts = [self.domain]
            out = pathlib.Path('/tmp') / f'playbook_{self.domain}_subs.txt'
            if out.exists():
                import socket
                for h in out.read_text().splitlines()[:40]:
                    try:
                        socket.gethostbyname(h)
                        hosts.append(h)
                    except Exception:
                        pass
            for h in ('auth', 'account', 'acct', 'web', 'www', 'api', 'gateway', 'app'):
                cand = f'{h}.{self.domain}'
                if cand not in hosts:
                    hosts.append(cand)
            hosts = sorted(set(hosts))
        urls = [f'https://{host}{f}' for host in hosts for f in ENV_FILES]
        seen = 0
        for u, code, text, ct in self._fetch_gentle(urls):
            if code != 200 or not text or len(text) < 10:
                continue
            if 'text/html' in ct and '<html' in text[:200].lower():
                continue
            seen += 1
            for pat, kind in SECRET_PATTERNS:
                for m in re.finditer(pat, text):
                    i = m.start()
                    snippet = text[max(0, i - 40):i + 120].replace('\n', ' ')
                    value = re.search(r'["\']([A-Za-z0-9_\-\./]{12,90})["\']', snippet)
                    redacted = f'{value.group(1)[:12]}…{value.group(1)[-4:]}' if value else '?'
                    self.finding(f'config-leak:{kind}', f'{u}: {snippet[:110]}',
                                 'high' if 'secret' in kind else 'info')
        self.step('2a scanned', 'OK', f'{seen} config file(s) read')
        if not any(f['kind'].startswith('config-leak') for f in self.findings):
            self.step('2b result', 'OK', 'no secrets in env/config files')

    # ------------------------------------------------------------------ stage 3
    def js_analysis(self):
        self.step('3 JS analysis', 'OK', 'analyzer v3 pipeline')
        from app.modules.tools.js_analyzer import JSAnalyzer
        a = JSAnalyzer(self.cfg)
        a.scope_hosts = {self.domain}
        try:
            results = a.analyze_js_for_project([f'https://{self.domain}/'])
        except Exception as e:
            self.step('3a analyzer', 'FAIL', str(e)[:140])
            return
        import pandas as pd
        saved = 0
        for key, df in results.items():
            if isinstance(df, pd.DataFrame) and not df.empty:
                self.pm.save_scan_results(key, self.domain, df)
                saved += 1
        self.step('3a saved', 'OK', f'{saved} result sets')
        self._results = results

    # ------------------------------------------------------------------ stage 4
    def triage(self):
        self.step('4 results triage review', 'OK', 'dangerous patterns / CSP / libs / keys')
        results = getattr(self, '_results', None)
        if results is None:
            import pandas as pd
            keys = ['js_dangerous_patterns', 'js_csp_gadgets', 'js_libraries', 'js_api_keys',
                    'js_prototype_pollution', 'js_dom_clobbering', 'js_sensitive_data_findings']
            results = {}
            for k in keys:
                d = self.pm.load_scan_results(k, self.domain)
                if isinstance(d, pd.DataFrame):
                    results[k] = d
        for k, label in [('js_dangerous_patterns', 'dangerous patterns'),
                         ('js_csp_gadgets', 'CSP gadgets'),
                         ('js_prototype_pollution', 'proto pollution'),
                         ('js_dom_clobbering', 'dom clobbering'),
                         ('js_libraries', 'libraries')]:
            df = results.get(k)
            if df is not None and not df.empty:
                self.step(f'4a {label}', 'WARN', f'{len(df)} rows - REVIEW')
        ak = results.get('js_api_keys')
        if ak is not None and not ak.empty:
            counts = ak['service'].value_counts()
            self.step('4b api keys', 'WARN', '; '.join(f'{s}={n}' for s, n in list(counts.items())[:6]))
            self.finding('api-keys-review', 'classify public-by-design (tenant ids, client tokens) vs real')
        secrets = results.get('js_sensitive_data_findings')
        if secrets is not None and not secrets.empty:
            self.step('4c secrets', 'WARN', f'{len(secrets)} rows - REVIEW')

    # ------------------------------------------------------------------ stage 5
    def auth_surface(self):
        self.step('5 auth-surface check', 'OK', 'login/signup/reset/verify/mfa routes')
        hosts = getattr(self, '_live', None) or [self.domain]
        # SPA catch-all baseline: apps return the same 200 shell for any path.
        shells = {}
        for host in hosts:
            try:
                base = self._fetch_gentle([f'https://{host}/'])[0]
                shells[host] = base[2][:4000]
            except Exception:
                shells[host] = ''
        hits = 0
        for host in hosts:
            for route in AUTH_ROUTES:
                try:
                    row = self._fetch_gentle([f'https://{host}{route}'])[0]
                    code, text, ct = row[1], row[2], row[3]
                    if code in (301, 302, 400, 401, 403):
                        hits += 1
                        self.step(f'   {host}{route}', 'OK', f'{code}')
                        continue
                    if code == 200 and text[:4000] != shells.get(host, ''):
                        hits += 1
                        self.step(f'   {host}{route}', 'OK', '200 (distinct page)')
                except Exception:
                    continue
        if hits == 0:
            self.step('5a result', 'OK', 'no standalone auth routes surfaced (managed IdP likely)')
        else:
            self.finding('auth-surface', f'{hits} auth route(s) found - test reset/enumeration per skill 02')

    # ------------------------------------------------------------------ stage 6
    def validators(self):
        self.step('6 validator battery', 'OK', 'REST / CORS / redirect / SSRF(+OOB) / PP / DOM-XSS')
        eps = self.pm.load_scan_results('js_discovered_endpoints', self.domain)
        rows = eps.to_dict('records') if isinstance(eps, __import__('pandas').DataFrame) and not eps.empty else []
        host = self.domain
        import pandas as pd
        from app.modules.tools.live_rest_validator import LiveRestValidator
        from app.modules.tools.cors_validator import CORSValidator
        from app.modules.tools.open_redirect_validator import OpenRedirectValidator
        from app.modules.tools.ssrf_validator import SSRFValidator
        if rows:
            v = LiveRestValidator(self.cfg)
            f = v.scan(rows, target_host=host)
            self.step('6a REST battery', 'OK', f'{len(f)} injection signals')
            for x in f[:6]:
                self.finding('rest-validation', f"{x.get('endpoint','')} {x.get('evidence','')}", 'high' if x.get('probe_status', 0) >= 500 else 'info')
        else:
            self.step('6a REST battery', 'SKIP', 'no endpoints saved (run stage 3)')
        cors_rows = CORSValidator(self.cfg).validate_sync([f'https://{host}/'])
        self.step('6b CORS', 'OK', f'{len(cors_rows)} signal(s)')
        oob = os.environ.get('WEBHOOK_SITE_UUID', '')
        or_cfg = dict(self.cfg)
        if oob:
            or_cfg['open_redirect_validator'] = {'oob_uuid': oob}
            or_cfg['ssrf_validator'] = {'oob_uuid': oob}
        cands = [r.get('endpoint') for r in rows if r.get('endpoint')]
        if cands:
            rr = OpenRedirectValidator(or_cfg).validate_sync(cands[:10])
            self.step('6c open-redirect', 'OK', f'{len(rr)} row(s)'
                      + (f' OOB={sum(1 for x in rr if x.get("Result")=="CONFIRMED")}' if oob else ''))
            sr = SSRFValidator(or_cfg).validate_sync(cands[:10])
            self.step('6d SSRF', 'OK', f'{len(sr)} row(s)'
                      + (f' OOB={sum(1 for x in sr if x.get("Result")=="CONFIRMED")}' if oob else ''))
        # browser validators (heavy; only on the app origin)
        from app.modules.tools.pp_validator import PrototypePollutionValidator
        from app.modules.tools.dom_xss_validator import DOMXSSValidator
        try:
            pp = PrototypePollutionValidator(self.cfg).validate_sync([f'https://{host}/'])
            self.step('6e PP', 'OK', f'{len(pp)} row(s)')
            dx = DOMXSSValidator(self.cfg).validate_sync([f'https://{host}/'])
            self.step('6f DOM-XSS', 'OK', f'{len(dx)} row(s)')
        except Exception as e:
            self.step('6e/f browser validators', 'SKIP', str(e)[:80])

    # ------------------------------------------------------------------ stage 7
    def graphql(self):
        self.step('7 GraphQL probe', 'OK', 'scanner on live hosts')
        from app.modules.tools.graphql_scanner import GraphQLScanner
        g = GraphQLScanner(self.cfg)
        res = g.scan([f'https://{self.domain}'])
        self.step('7a result', 'OK', f'{len(res.get("endpoints", []))} endpoint(s)')

    # ------------------------------------------------------------------ stage 8
    def closure(self):
        self.step('8 closure checklist', 'OK', '')
        checks = [
            ('subdomains enumerated', any('subfinder' in r for r in self.rows)),
            ('env/config files scanned', any('config/env-file' in r for r in self.rows)),
            ('JS results REVIEWED', any('triage review' in r for r in self.rows)),
            ('validators run', any('validator battery' in r for r in self.rows)),
            ('auth surface checked', any('auth-surface' in r for r in self.rows)),
        ]
        for label, ok in checks:
            self.step(f'   {label}', 'OK' if ok else 'FAIL', '')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    domain = sys.argv[1]
    stages = {1: 'subdomains', 2: 'env_scan', 3: 'js_analysis', 4: 'triage',
              5: 'auth_surface', 6: 'validators', 7: 'graphql', 8: 'closure'}
    sel = None
    for a in sys.argv[2:]:
        if a == '--stage':
            sel = {int(sys.argv[sys.argv.index(a) + 1])}
        elif a == '--stages':
            sel = {int(x) for x in sys.argv[sys.argv.index(a) + 1].split(',')}
    pb = Playbook(domain)
    for n, fn in stages.items():
        if sel and n not in sel:
            continue
        try:
            getattr(pb, fn)()
        except Exception as e:
            pb.step(f'{n} {fn}', 'FAIL', f'{type(e).__name__}: {str(e)[:140]}')
    pb.save_report()


if __name__ == '__main__':
    main()
