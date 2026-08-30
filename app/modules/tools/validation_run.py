"""
validation_run.py — Full validation orchestration chain.

After JS analysis discovers endpoints, this runs the FULL pipeline:
  1. Scope-filter endpoints
  2. classify → route to applicable scanners
  3. Nuclei on high-severity templates (targeting discovered live hosts)
  4. REST battery (live_rest_validator) on discovered endpoints
  5. OOB tests (SSRF validator, open redirect validator)
  6. Blind SQLi on parameterized endpoints
  7. JWT audit on any found tokens
  8. Save all results

Every step is optional and budgeted. No auth required — all probes are
unauthenticated. Results are returned as a dict of DataFrames, ready to
save via ProjectManager.

Config keys (under `validation.*`):
  max_endpoints: max endpoints to validate (default 300)
  budget_seconds: total validation budget (default 300)
  per_request_timeout: per-request timeout (default 8)
  concurrency: global concurrency (default 25)
  enable_nuclei: run nuclei scan (default True)
  enable_rest_battery: run REST validator (default True)
  enable_oob: run OOB probes (default True)
  enable_sqli_blind: run blind SQLi (default True)
  enable_jwt_audit: audit JWTs (default True)
  enable_validator_routing: route to XXE/RCE/upload (default True)
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path

import pandas as pd

from app.utils.logger import get_logger

logger = get_logger()


class ValidationRunner:
    """Orchestrates the full validation pipeline."""

    def __init__(self, config: Dict, project_manager=None):
        self.config = config
        self.project_manager = project_manager
        cfg = config.get('validation', {}) if isinstance(config, dict) else {}
        self.max_endpoints = int(cfg.get('max_endpoints', 300))
        self.budget_seconds = int(cfg.get('budget_seconds', 300))
        self.per_request_timeout = int(cfg.get('per_request_timeout', 8))
        self.concurrency = int(cfg.get('concurrency', 25))
        self.enable_nuclei = bool(cfg.get('enable_nuclei', True))
        self.enable_rest_battery = bool(cfg.get('enable_rest_battery', True))
        self.enable_oob = bool(cfg.get('enable_oob', True))
        self.enable_sqli_blind = bool(cfg.get('enable_sqli_blind', True))
        self.enable_jwt_audit = bool(cfg.get('enable_jwt_audit', True))
        self.enable_validator_routing = bool(cfg.get('enable_validator_routing', True))

    def run(self, endpoints: List[Dict], live_hosts: Optional[List[str]] = None,
            target: str = '', scope_manager=None,
            progress_callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Run the full validation pipeline.

        Args:
            endpoints: discovered endpoints from JS analysis
            live_hosts: live HTTP hosts (for nuclei targeting)
            target: target domain name
            scope_manager: optional ScopeManager for filtering
            progress_callback: optional progress callback (frac, msg)

        Returns:
            Dict of results, each value a DataFrame or list of findings.
        """
        results: Dict[str, Any] = {}
        deadline = time.time() + self.budget_seconds
        recorder = None
        if self.project_manager is not None and target:
            try:
                from app.modules.run_metadata import ScanRunRecorder
                recorder = ScanRunRecorder.from_project_manager(
                    self.project_manager, target, 'full_validation',
                    config=self.config, seed_count=len(endpoints))
            except Exception as exc:
                logger.warning(f"Run metadata unavailable: {exc}")

        def _record(name: str, status: str, count=None, error: str = ''):
            if recorder:
                recorder.step(name, status, count=count, error=error)

        def _out_of_budget(name: str) -> bool:
            if time.time() <= deadline:
                return False
            _record(name, 'timed_out', error='global validation budget exhausted')
            if recorder:
                results['run_metadata'] = recorder.finish('timed_out')
            return True

        def _emit(frac: float, msg: str):
            if progress_callback:
                try:
                    progress_callback(frac, msg)
                except Exception:
                    pass
            logger.info(f"Validation: {msg}")

        if not endpoints:
            _emit(1.0, "No endpoints to validate")
            _record('input', 'completed', count=0)
            if recorder:
                results['run_metadata'] = recorder.finish('completed')
            return results

        _emit(0.0, f"Validation pipeline starting: {len(endpoints)} endpoints")

        if scope_manager:
            endpoints = [
                ep for ep in endpoints
                if scope_manager.is_in_scope(ep.get('url', '') or ep.get('endpoint', ''))
            ]
            _emit(0.02, f"Scope-filtered: {len(endpoints)} endpoints remain")

        if len(endpoints) > self.max_endpoints:
            endpoints = endpoints[:self.max_endpoints]
            _emit(0.03, f"Capped at {self.max_endpoints} endpoints")

        steps = sum([
            self.enable_nuclei, self.enable_rest_battery,
            self.enable_oob, self.enable_sqli_blind,
            self.enable_jwt_audit, self.enable_validator_routing,
        ])
        step = 0
        slice_size = 0.90 / max(steps, 1)

        # Step 1: Nuclei scan on live hosts
        if self.enable_nuclei and live_hosts:
            if _out_of_budget('nuclei'):
                return results
            step += 1
            _emit(0.03 + slice_size * (step - 0.5), f"Nuclei: {len(live_hosts)} hosts...")
            try:
                from app.modules.scanner import VulnerabilityScanner
                scanner = VulnerabilityScanner(self.config)
                nuclei_df = scanner.run_nuclei_scan(
                    live_hosts,
                    options={
                        'severity': 'critical,high,medium',
                        'rate': 50,
                        'timeout': 10,
                    }
                )
                if not nuclei_df.empty:
                    results['nuclei_findings'] = nuclei_df
                    _emit(0.03 + slice_size * step, f"Nuclei: {len(nuclei_df)} findings")
                else:
                    _emit(0.03 + slice_size * step, "Nuclei: no findings")
                _record('nuclei', 'completed', count=len(nuclei_df))
            except Exception as e:
                logger.warning(f"Nuclei step failed: {e}")
                _emit(0.03 + slice_size * step, f"Nuclei: failed ({e})")
                _record('nuclei', 'failed', error=str(e))

        # Step 2: REST battery on discovered endpoints
        if self.enable_rest_battery:
            if _out_of_budget('rest_battery'):
                return results
            step += 1
            _emit(0.03 + slice_size * (step - 0.5), f"REST battery: {len(endpoints)} endpoints...")
            try:
                from app.modules.tools.live_rest_validator import LiveRestValidator
                validator = LiveRestValidator(self.config)
                rest_rows = [
                    {'endpoint': ep.get('url', '') or ep.get('endpoint', ''),
                     'method': ep.get('method', 'GET')}
                    for ep in endpoints[:200]
                ]
                rest_findings = validator.scan_sync(rest_rows, target_host=target)
                if rest_findings:
                    results['rest_findings'] = pd.DataFrame(rest_findings)
                    _emit(0.03 + slice_size * step, f"REST battery: {len(rest_findings)} findings")
                else:
                    _emit(0.03 + slice_size * step, "REST battery: no findings")
                _record('rest_battery', 'completed', count=len(rest_findings or []))
            except Exception as e:
                logger.warning(f"REST battery step failed: {e}")
                _emit(0.03 + slice_size * step, f"REST battery: failed ({e})")
                _record('rest_battery', 'failed', error=str(e))

        # Step 3: OOB probes (SSRF + open redirect)
        if self.enable_oob:
            if _out_of_budget('oob'):
                return results
            step += 1
            _emit(0.03 + slice_size * (step - 0.5), "OOB: SSRF + redirect probes...")
            try:
                from app.modules.tools.oob import OOBManager
                from app.modules.tools.ssrf_validator import SSRFValidator
                from app.modules.tools.open_redirect_validator import OpenRedirectValidator

                oob_mgr = OOBManager(self.config)
                canary = asyncio.run(oob_mgr.create_webhook_token())
                oob_findings = []

                if canary:
                    canary_url = canary.callback_url

                    ssrf_eps = [
                        ep for ep in endpoints[:100]
                        if any(p in str(ep.get('url', '')).lower()
                               for p in ('url', 'proxy', 'api', 'webhook', 'fetch', 'import'))
                    ]
                    if ssrf_eps:
                        try:
                            ssrf_validator = SSRFValidator(self.config)
                            ssrf_cfg = dict(self.config.get('ssrf', {}))
                            ssrf_cfg['canary_host'] = canary_url
                            ssrf_results = ssrf_validator.scan(ssrf_eps)
                            oob_findings.extend(ssrf_results or [])
                        except Exception as e:
                            logger.warning(f"SSRF validator failed: {e}")

                    redirect_eps = [
                        ep for ep in endpoints[:100]
                        if any(p in str(ep.get('url', '')).lower()
                               for p in ('redirect', 'return', 'next', 'goto', 'callback', 'url'))
                    ]
                    if redirect_eps:
                        try:
                            redirect_validator = OpenRedirectValidator(self.config)
                            redirect_cfg = dict(self.config.get('open_redirect', {}))
                            redirect_cfg['canary_host'] = canary_url
                            redirect_results = redirect_validator.scan(redirect_eps)
                            oob_findings.extend(redirect_results or [])
                        except Exception as e:
                            logger.warning(f"Redirect validator failed: {e}")

                    asyncio.run(oob_mgr.poll_all(timeout=15))
                    summary = oob_mgr.summary()
                    oob_findings.append({'type': 'oob_summary', 'summary': summary})

                if oob_findings:
                    results['oob_findings'] = pd.DataFrame(oob_findings)
                    _emit(0.03 + slice_size * step, f"OOB: {len(oob_findings)} findings")
                else:
                    _emit(0.03 + slice_size * step, "OOB: no findings")
                _record('oob', 'completed', count=len(oob_findings))
            except Exception as e:
                logger.warning(f"OOB step failed: {e}")
                _emit(0.03 + slice_size * step, f"OOB: failed ({e})")
                _record('oob', 'failed', error=str(e))

        # Step 4: Blind SQLi on parameterized endpoints
        if self.enable_sqli_blind:
            if _out_of_budget('sqli_blind'):
                return results
            step += 1
            _emit(0.03 + slice_size * (step - 0.5), "Blind SQLi: probing parameterized endpoints...")
            try:
                from app.modules.tools.sqli_blind import BlindSQLiScanner
                sqli_scanner = BlindSQLiScanner(self.config)
                sqli_results = sqli_scanner.scan_sync(endpoints[:50])
                all_sqli = sqli_results.get('time_findings', []) + sqli_results.get('bool_findings', [])
                if all_sqli:
                    results['sqli_blind'] = pd.DataFrame(all_sqli)
                    _emit(0.03 + slice_size * step, f"Blind SQLi: {len(all_sqli)} findings")
                else:
                    _emit(0.03 + slice_size * step, "Blind SQLi: no findings")
                _record('sqli_blind', 'completed', count=len(all_sqli))
            except Exception as e:
                logger.warning(f"Blind SQLi step failed: {e}")
                _emit(0.03 + slice_size * step, f"Blind SQLi: failed ({e})")
                _record('sqli_blind', 'failed', error=str(e))

        # Step 5: JWT audit on found tokens
        if self.enable_jwt_audit:
            if _out_of_budget('jwt_audit'):
                return results
            step += 1
            _emit(0.03 + slice_size * (step - 0.5), "JWT audit: scanning endpoints for tokens...")
            try:
                from app.modules.tools.jwt_live import audit_from_text
                jwt_findings = []
                for ep in endpoints[:30]:
                    text = str(ep.get('url', '')) + ' ' + str(ep.get('body', ''))
                    audit = audit_from_text(text, source=ep.get('url', ''))
                    jwt_findings.extend(audit)
                if jwt_findings:
                    results['jwt_audit'] = pd.DataFrame(jwt_findings)
                    critical = sum(1 for f in jwt_findings if f.get('critical_count', 0) > 0)
                    _emit(0.03 + slice_size * step, f"JWT: {len(jwt_findings)} tokens, {critical} critical")
                else:
                    _emit(0.03 + slice_size * step, "JWT: no tokens found")
                _record('jwt_audit', 'completed', count=len(jwt_findings))
            except Exception as e:
                logger.warning(f"JWT audit step failed: {e}")
                _emit(0.03 + slice_size * step, f"JWT: failed ({e})")
                _record('jwt_audit', 'failed', error=str(e))

        # Step 6: Validator routing (XXE, RCE, upload)
        if self.enable_validator_routing:
            if _out_of_budget('validator_routing'):
                return results
            step += 1
            _emit(0.03 + slice_size * (step - 0.5), "Validator routing: classifying endpoints...")
            try:
                from app.modules.tools.validator_router import route_endpoints, route_stats
                routed = route_endpoints(endpoints)
                stats = route_stats(endpoints)
                results['validator_routing'] = {
                    'routed': {k: len(v) for k, v in routed.items()},
                    'stats': stats,
                }
                _emit(0.03 + slice_size * step, f"Validator routing: {stats}")
                _record('validator_routing', 'completed', count=sum(len(v) for v in routed.values()))
            except Exception as e:
                logger.warning(f"Validator routing step failed: {e}")
                _emit(0.03 + slice_size * step, f"Validator routing: failed ({e})")
                _record('validator_routing', 'failed', error=str(e))

        _emit(1.0, f"Validation complete: {len(results)} result sets")
        if recorder:
            results['run_metadata'] = recorder.finish()
        return results

    def run_sync(self, *args, **kwargs) -> Dict[str, Any]:
        return self.run(*args, **kwargs)


__all__ = ['ValidationRunner']
