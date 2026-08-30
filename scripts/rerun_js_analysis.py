#!/usr/bin/env python3
"""Headless re-run of the JS Analysis engine for a project target, saving all
result frames exactly like 1_Recon.py does, with a full scan-run ledger.

Scope safety (fail closed):
  * requires an explicit --project AND --target, or an already-active project
    used ONLY when --target is explicitly provided;
  * never creates a project and never switches projects silently;
  * refuses to run when no project exists, when the project has no scope
    rules, when the target is out of scope, or when an explicitly supplied
    seed resolves outside scope;
  * without --seed, saved live_hosts URLs are used (scope-filtered) and only
    fall back to https://<target> after the scope gate passed.

Ledger (ScanRunRecorder, run_type=js_analysis):
  records project/target/seed_count, per-step statuses, result counts for
  every frame, material coverage failures, and a final status of completed /
  partial / timed_out / failed. Only a config HASH is persisted - never
  config values or secrets. A run with zero findings but successful coverage
  is `completed`. Ordinary guessed-map 404s are recorded as coverage notes,
  not failures. Unhandled exceptions finish the ledger as `failed`.

Exit codes:
  0  completed (including zero-finding runs)
  1  failed or timed_out
  2  usage error or fail-closed scope gate (nothing was scanned)
  3  partial - coverage was materially affected. Documented choice: PARTIAL
     IS NONZERO so automation cannot mistake degraded evidence for a clean
     rerun; all fetched results are still persisted before exiting.
"""
import argparse
import os
import sys
import traceback

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pandas as pd  # noqa: E402

from app.modules.utils import load_config  # noqa: E402
from app.modules.project_manager import ProjectManager, ScopeManager  # noqa: E402
from app.modules.run_metadata import ScanRunRecorder  # noqa: E402
from app.modules.tools.js_analyzer import JSAnalyzer  # noqa: E402

EXIT_COMPLETED = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3

# Outcomes that are routine negative probes rather than coverage damage:
# guessed {bundle}.map requests that simply arent served.
_BENIGN_MAP_OUTCOMES = {'http_404', 'http_410'}
_MATERIAL_KINDS = {'seed', 'frame_seed', 'js', 'chunk', 'source_map',
                   'nextjs_manifest', 'vite_manifest',
                   'nextjs_manifest_candidate'}


class ScopeGateError(RuntimeError):
    """Raised when the fail-closed scope gate refuses to start a run."""


def check_arg_rules(args) -> str:
    """Usage-rule violations that must fail before any project access."""
    if args.project and not args.target:
        return '--project requires an explicit --target (never guess)'
    if not args.project and not args.target:
        return ('give --project <name> --target <host>, or rely on the '
                'already-active project WITH an explicit --target')
    return ''


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='rerun_js_analysis',
        description='Headless JS analysis rerun with run-ledger bookkeeping.')
    parser.add_argument('--project', help='existing project name to activate '
                        '(explicit switch; never created)')
    parser.add_argument('--target', help='target domain/host to analyze')
    parser.add_argument('--seed', action='append', default=[], dest='seeds',
                        metavar='URL',
                        help='explicit seed URL (repeatable; beats live_hosts)')
    parser.add_argument('--validate', action='store_true',
                        help='also probe discovered endpoints live')
    return parser


def _has_scope_rules(scope_mgr: ScopeManager) -> bool:
    return bool(scope_mgr.in_scope or scope_mgr.wildcard_scope)


def gate_scope(pm: ProjectManager, target: str) -> ScopeManager:
    """Fail closed unless an active project, scope rules, and an in-scope
    target all exist."""
    if not pm.get_current_project_name():
        raise ScopeGateError('no active project; pass --project <name> and '
                             '--target <host>')
    scope_mgr = pm.get_scope_manager()
    if scope_mgr is None:
        raise ScopeGateError('no ScopeManager available for the active project')
    if not _has_scope_rules(scope_mgr):
        raise ScopeGateError('project has no scope rules; refusing to scan '
                             '(define scope first)')
    if not target:
        raise ScopeGateError('no target given; pass --target <host>')
    if not scope_mgr.is_in_scope(target):
        raise ScopeGateError(f'target {target!r} is NOT in project scope')
    return scope_mgr


def resolve_seeds(explicit_seeds, live_hosts, target: str,
                  scope_mgr: ScopeManager):
    """Seed selection order: explicit --seed > saved live_hosts > https://target.

    Explicit seeds are validated strictly: one out-of-scope entry aborts the
    run. live_hosts-derived URLs are silently filtered to scope. Returns
    (seeds, source_note)."""
    if explicit_seeds:
        bad = [u for u in explicit_seeds
               if not scope_mgr.is_in_scope(u)]
        if bad:
            raise ScopeGateError(
                'explicit seed(s) outside scope, refusing to scan: '
                + ', '.join(bad[:10]))
        return list(explicit_seeds), 'explicit'

    urls = []
    if isinstance(live_hosts, pd.DataFrame) and 'URL' in live_hosts.columns:
        urls = [u for u in live_hosts['URL'].tolist()
                if isinstance(u, str) and u.startswith('http')]
    urls = [u for u in urls if scope_mgr.is_in_scope(u)]
    if urls:
        return urls, 'live_hosts'
    # Target already passed the scope gate above.
    return [f'https://{target}'], 'https_fallback'


def material_coverage_failures(coverage_rows) -> list:
    """Coverage outcomes that materially affect coverage confidence.

    Guessed-map 404/410s ({bundle}.map probes that are simply not served) are
    ordinary negatives: they stay visible in js_coverage but never fail a run.
    """
    failures = []
    for row in coverage_rows:
        url = str(row.get('url', '')) if hasattr(row, 'get') else ''
        kind = str(row.get('kind', '')) if hasattr(row, 'get') else ''
        outcome = str(row.get('outcome', '')) if hasattr(row, 'get') else ''
        if not outcome or outcome in ('ok', 'inline', 'html_ok'):
            continue
        if outcome.startswith('html_ok'):
            continue
        if kind == 'source_map' and outcome in _BENIGN_MAP_OUTCOMES:
            continue
        if kind not in _MATERIAL_KINDS and outcome.startswith('http_4'):
            continue
        item = f'{kind or "fetch"}:{outcome}:{url}'
        if item not in failures:
            failures.append(item)
    return failures


def compute_final_status(seed_count: int, seeds_alive: int,
                         download_ok: int, download_attempts: int,
                         analyzed_count: int, timed_out_count: int,
                         persist_failed: bool, crashed: bool) -> str:
    """completed | partial | timed_out | failed.

    * crash -> failed
    * every seed dead -> partial (nothing was covered)
    * fetches attempted but none succeeded -> partial (material)
    * timeouts that wiped out all analysis -> timed_out
    * persistence broke -> partial
    * otherwise completed - INCLUDING runs with zero findings and runs where
      the target simply exposed no JavaScript: coverage was healthy.
    """
    if crashed:
        return 'failed'
    if seed_count and not seeds_alive:
        return 'partial'
    if timed_out_count and not analyzed_count:
        return 'timed_out'
    if download_attempts and not download_ok:
        return 'partial'
    if persist_failed:
        return 'partial'
    return 'completed'


def _frame_counts(results) -> dict:
    return {key: (len(df) if isinstance(df, pd.DataFrame) else 0)
            for key, df in (results or {}).items()}


def persist_frames(pm: ProjectManager, results, target: str,
                   recorder: ScanRunRecorder) -> int:
    """Persist EVERY result frame - empty frames included - so stale rows
    from earlier runs are cleared by this rerun. Records one ledger step per
    frame with its row count. Returns the number of saved frames."""
    saved = 0
    for key, df in sorted((results or {}).items()):
        if not isinstance(df, pd.DataFrame):
            continue
        try:
            pm.save_scan_results(key, target, df, persist_empty=True)
            recorder.step(f'persist:{key}', 'completed', count=len(df))
            saved += 1
        except Exception as exc:
            recorder.step(f'persist:{key}', 'failed', error=str(exc))
            raise
    return saved


def summarize(run_data: dict, frame_counts: dict, max_failures: int = 6) -> None:
    print(f"run_id={run_data['run_id']} status={run_data['status']}")
    failures = run_data.get('coverage_failures') or []
    print(f"coverage_failures={len(failures)}")
    for item in failures[:max_failures]:
        print(f"  ! {item}")
    print('result_frames=' + json_compact(frame_counts))


def json_compact(counts: dict) -> str:
    return '{' + ', '.join(f'{k}: {v}' for k, v in sorted(counts.items())) + '}'


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    rule_error = check_arg_rules(args)
    if rule_error:
        print(f'ERROR: {rule_error}', file=sys.stderr)
        return EXIT_USAGE

    config = load_config()
    pm = ProjectManager(config)

    try:
        if args.project:
            if not pm.set_current_project(args.project):
                print(f'ERROR: project {args.project!r} does not exist '
                      '(projects are never created here)', file=sys.stderr)
                return EXIT_USAGE

        target = args.target
        try:
            scope_mgr = gate_scope(pm, target)
        except ScopeGateError as exc:
            print(f'SCOPE GATE: {exc}', file=sys.stderr)
            return EXIT_USAGE
        project_name = pm.get_current_project_name()

        live_hosts = pm.load_scan_results('live_hosts', target)
        try:
            seeds, seed_source = resolve_seeds(args.seeds, live_hosts, target,
                                               scope_mgr)
        except ScopeGateError as exc:
            print(f'SCOPE GATE: {exc}', file=sys.stderr)
            return EXIT_USAGE
    except Exception as exc:
        print(f'ERROR during startup gates: {exc}', file=sys.stderr)
        return EXIT_USAGE

    analyzer = JSAnalyzer(config)
    analyzer.scope_hosts = set(scope_mgr.get_scope_hosts())

    recorder = ScanRunRecorder.from_project_manager(
        pm, target, 'js_analysis', config=config, seed_count=len(seeds),
        tool_version=f'js-analyzer-v3.7')
    print(f'project={project_name} target={target} seeds={len(seeds)} '
          f'({seed_source}) scope_hosts={len(analyzer.scope_hosts)}')

    seeds_alive = 0
    analyzed_count = 0
    download_ok = 0
    timed_out_count = 0
    persist_failed = False
    crashed = False
    results = {}
    frame_counts = {}

    try:
        recorder.step('seed_discovery', 'completed', count=len(seeds))

        results = analyzer.analyze_js_for_project(
            seeds, validate=args.validate)
        coverage = results.get('js_coverage')
        coverage_rows = coverage.to_dict('records') if isinstance(coverage, pd.DataFrame) \
            and not coverage.empty else []

        seed_rows = [r for r in coverage_rows
                     if r.get('kind') in ('seed', 'frame_seed')]
        seeds_alive = sum(1 for r in seed_rows
                          if str(r.get('outcome', '')).startswith('html_ok')
                          or str(r.get('outcome', '')) == 'js_seed')

        download_ok = sum(1 for r in coverage_rows
                          if r.get('kind') in ('js', 'chunk', 'source_map',
                                               'nextjs_manifest', 'vite_manifest')
                          and str(r.get('outcome')) in ('ok', 'inline', 'truncated'))
        recorder.step('download', 'completed' if download_ok else 'failed',
                      count=download_ok,
                      message=f'{download_ok} fetches ok, '
                              f'{len(coverage_rows)} attempts')

        js_files = results.get('js_files')
        analyzed_count = len(js_files) if isinstance(js_files, pd.DataFrame) else 0
        timed_out_count = len([r for r in coverage_rows
                               if r.get('outcome') == 'timeout'])
        recorder.step('analyze', 'completed' if analyzed_count else 'failed',
                      count=analyzed_count)
        for item in material_coverage_failures(coverage_rows)[:50]:
            recorder.coverage_failure(item)

        # Persist EVERY result frame, including empty ones, so stale data
        # from earlier runs is cleared by this rerun.
        try:
            saved_frames = persist_frames(pm, results, target, recorder)
        except Exception:
            persist_failed = True
            saved_frames = 0
        recorder.step('persist', 'completed' if not persist_failed else 'partial',
                      count=saved_frames)
    except Exception as exc:
        crashed = True
        recorder.step('scan', 'failed', error=f'{type(exc).__name__}: {exc}')
        traceback.print_exc()

    frame_counts = _frame_counts(results)
    step_timeouts = sum(1 for s in recorder.data['steps']
                        if s.get('status') == 'timed_out')
    download_attempts = 0
    cov = results.get('js_coverage')
    if isinstance(cov, pd.DataFrame) and not cov.empty:
        download_attempts = len(cov)
    status = compute_final_status(
        seed_count=len(seeds), seeds_alive=seeds_alive,
        download_ok=download_ok, download_attempts=download_attempts,
        analyzed_count=analyzed_count,
        timed_out_count=timed_out_count + step_timeouts,
        persist_failed=persist_failed, crashed=crashed)
    final_error = ''
    if status == 'failed':
        final_error = 'unhandled exception during js analysis rerun'
    run_data = recorder.finish(status, error=final_error)

    summarize(run_data, frame_counts)
    if status in ('failed', 'timed_out'):
        return EXIT_FAILED
    if status == 'partial':
        return EXIT_PARTIAL
    return EXIT_COMPLETED


if __name__ == '__main__':
    sys.exit(main())
