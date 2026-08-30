"""Tests for the repaired headless rerun script (argparse + ledger + gates).

These tests never launch a live scan: they exercise the script's pure
helpers, its scope gate, and persistence bookkeeping with fake objects.
"""
import importlib.util
import sys
from pathlib import Path

import pandas as pd
import pytest

from app.modules.project_manager import ScopeManager
from app.modules.run_metadata import ScanRunRecorder

spec = importlib.util.spec_from_file_location(
    'rerun_js_analysis',
    Path(__file__).resolve().parent.parent / 'scripts' / 'rerun_js_analysis.py')
rr = importlib.util.module_from_spec(spec)
sys.modules.setdefault('rerun_js_analysis', rr)
spec.loader.exec_module(rr)


class FakePM:
    """Minimal ProjectManager stand-in: no project creation, no network."""

    def __init__(self, active='proj-a'):
        self.active = active
        self.saved = []

    def get_current_project_name(self):
        return self.active

    def set_current_project(self, name):
        if name == 'missing':
            return False
        self.active = name
        return True


def make_scope(tmp_path, rules):
    mgr = ScopeManager(tmp_path)
    for rule in rules:
        mgr.add_in_scope(rule)
    return mgr


# ---------------------------------------------------------------- argparse

def test_project_requires_target():
    args = rr.build_parser().parse_args(['--project', 'p'])
    assert rr.check_arg_rules(args)


def test_nothing_given_is_a_usage_error():
    args = rr.build_parser().parse_args([])
    assert rr.check_arg_rules(args)


def test_explicit_project_and_target_is_valid():
    args = rr.build_parser().parse_args(['--project', 'p', '--target', 't'])
    assert rr.check_arg_rules(args) == ''


def test_seed_flag_is_repeatable():
    args = rr.build_parser().parse_args(
        ['--target', 't', '--seed', 'https://a/x', '--seed', 'https://b/y'])
    assert args.seeds == ['https://a/x', 'https://b/y']


# ------------------------------------------------------------- scope gates

def test_gate_fails_closed_without_scope_rules(tmp_path):
    pm = FakePM()
    scope = make_scope(tmp_path, [])          # no rules at all
    with pytest.raises(rr.ScopeGateError):
        rr.gate_scope(pm_with_scope(pm, scope), 'example.com')


def test_gate_fails_when_target_out_of_scope(tmp_path):
    pm = FakePM()
    scope = make_scope(tmp_path, ['allowed.example'])
    with pytest.raises(rr.ScopeGateError) as err:
        rr.gate_scope(pm_with_scope(pm, scope), 'evil.example')
    assert 'NOT in project scope' in str(err.value)


def test_gate_passes_in_scope_target(tmp_path):
    pm = FakePM()
    scope = make_scope(tmp_path, ['*.good.example'])
    got = rr.gate_scope(pm_with_scope(pm, scope), 'sub.good.example')
    assert got is scope


def pm_with_scope(pm, scope):
    pm.get_scope_manager = lambda: scope
    return pm


# ------------------------------------------------------------ seed choice

def test_explicit_seed_outside_scope_aborts(tmp_path):
    scope = make_scope(tmp_path, ['good.example'])
    with pytest.raises(rr.ScopeGateError):
        rr.resolve_seeds(['https://evil.example/x'], None, 'good.example',
                         scope)


def test_seed_priority_explicit_beats_live_hosts_beats_https(tmp_path):
    scope = make_scope(tmp_path, ['good.example'])
    live = pd.DataFrame({'URL': ['https://good.example/one',
                                 'http://good.example/two']})
    seeds, source = rr.resolve_seeds([], live, 'good.example', scope)
    assert source == 'live_hosts' and len(seeds) == 2

    seeds2, source2 = rr.resolve_seeds(
        ['https://good.example/explicit'], live, 'good.example', scope)
    assert source2 == 'explicit' and seeds2 == ['https://good.example/explicit']

    seeds3, source3 = rr.resolve_seeds([], None, 'good.example', scope)
    assert source3 == 'https_fallback' and seeds3 == ['https://good.example']


def test_live_host_seeds_filtered_to_scope(tmp_path):
    scope = make_scope(tmp_path, ['good.example'])
    live = pd.DataFrame({'URL': ['https://good.example/a',
                                 'https://offscope.example/b']})
    seeds, _ = rr.resolve_seeds([], live, 'good.example', scope)
    assert seeds == ['https://good.example/a']


# ------------------------------------------------------- status semantics

def test_zero_findings_with_healthy_coverage_is_completed():
    assert rr.compute_final_status(1, 1, 4, 6, 0, 0, False, False) == 'completed'
    # target simply had no JS at all
    assert rr.compute_final_status(1, 1, 0, 0, 0, 0, False, False) == 'completed'


def test_all_downloads_dead_is_partial_but_guessed_map_404_is_not():
    assert rr.compute_final_status(1, 1, 0, 9, 0, 0, False, False) == 'partial'


def test_crash_is_failed_and_total_timeout_is_timed_out():
    assert rr.compute_final_status(1, 1, 1, 2, 1, 0, False, True) == 'failed'
    # fetches succeeded but every analysis attempt hit the watchdog
    assert rr.compute_final_status(1, 1, 3, 4, 0, 5, False, False) == 'timed_out'


def test_dead_seed_is_partial():
    assert rr.compute_final_status(2, 0, 0, 0, 0, 0, False, False) == 'partial'


def test_material_failures_ignore_guessed_map_404s():
    rows = [
        {'url': 'https://x/main.js.map', 'kind': 'source_map',
         'outcome': 'http_404'},
        {'url': 'https://x/main.js', 'kind': 'js', 'outcome': 'ok'},
        {'url': 'https://x/chunk.js', 'kind': 'chunk', 'outcome': 'timeout'},
    ]
    failures = rr.material_coverage_failures(rows)
    assert failures == ['chunk:timeout:https://x/chunk.js']


# ------------------------------------------------------------- persistence

def test_persist_frames_always_uses_persist_empty(tmp_path):
    recorder = ScanRunRecorder(tmp_path, 'example.test', 'js_analysis',
                               seed_count=1)

    class RecordingPM:
        def __init__(self):
            self.calls = []

        def save_scan_results(self, scan_type, target, results,
                              persist_empty=False):
            self.calls.append((scan_type, persist_empty))

    fake_pm = RecordingPM()
    empty_frame = pd.DataFrame(columns=['a', 'b'])
    saved = rr.persist_frames(fake_pm, {'js_files': empty_frame}, 'example.test',
                              recorder)
    assert saved == 1
    # the whole point: stale data must be cleared even when nothing was found
    assert fake_pm.calls[0][1] is True
    counts = {s['name']: s.get('count') for s in recorder.data['steps']}
    assert counts['persist:js_files'] == 0


def test_persist_frames_failure_marks_ledger(tmp_path):
    recorder = ScanRunRecorder(tmp_path, 'example.test', 'js_analysis')

    class ExplodingPM:
        def save_scan_results(self, *args, **kwargs):
            raise OSError('disk full')

    with pytest.raises(OSError):
        rr.persist_frames(ExplodingPM(), {'js_files': pd.DataFrame()}, 't',
                          recorder)
    step = [s for s in recorder.data['steps']
            if s['name'] == 'persist:js_files'][0]
    assert step['status'] == 'failed'


# ----------------------------------------------------------------- ledger

def test_recorder_records_config_hash_not_values(tmp_path):
    run = ScanRunRecorder(tmp_path, 'example.test', 'js_analysis',
                          config={'api_key': 'super-secret-value'})
    text = run.path.read_text()
    assert 'super-secret-value' not in text
    assert run.data['run_type'] == 'js_analysis'
    assert run.data['config_hash']
