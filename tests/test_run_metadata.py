import json

from app.modules.run_metadata import ScanRunRecorder


def test_run_ledger_distinguishes_clean_from_partial(tmp_path):
    run = ScanRunRecorder(tmp_path, 'example.test', 'validation',
                          config={'api_key': 'secret'}, seed_count=3)
    run.step('js', 'completed', count=0)
    run.step('nuclei', 'failed', error='binary missing')
    final = run.finish()

    saved = json.loads(run.path.read_text())
    assert final['status'] == saved['status'] == 'partial'
    assert saved['finding_counts']['js'] == 0
    assert saved['config_hash']
    assert 'secret' not in run.path.read_text()


def test_timed_out_step_controls_final_status(tmp_path):
    run = ScanRunRecorder(tmp_path, 'example.test', 'js', seed_count=1)
    run.step('download', 'timed_out')

    assert run.finish()['status'] == 'timed_out'
