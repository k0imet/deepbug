import json

import pandas as pd

from app.modules.project_manager import ProjectManager


def test_persist_empty_replaces_stale_scan_results(tmp_path):
    manager = ProjectManager({
        'project_settings': {'base_projects_dir': str(tmp_path)},
    })
    manager.create_project('audit')
    manager.set_current_project('audit')
    manager.save_scan_results(
        'js_discovered_endpoints', 'example.test',
        pd.DataFrame([{'endpoint': 'https://example.test/old'}]))

    manager.save_scan_results(
        'js_discovered_endpoints', 'example.test', pd.DataFrame(),
        persist_empty=True)

    result_path = tmp_path / 'audit' / 'example_test' / 'js_discovered_endpoints_results.json'
    assert json.loads(result_path.read_text()) == []
