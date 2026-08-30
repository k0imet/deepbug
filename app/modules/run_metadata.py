"""Atomic, append-only scan-run metadata for trustworthy campaign history."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.modules.utils import sanitize_target


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _config_hash(config: dict) -> str:
    """Fingerprint configuration without persisting credentials or values."""
    raw = json.dumps(config or {}, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


class ScanRunRecorder:
    """Persist run and step status separately from scanner findings."""

    VALID_FINAL = {'completed', 'partial', 'timed_out', 'failed', 'cancelled'}

    def __init__(self, project_path: Path, target: str, run_type: str,
                 config: Optional[dict] = None, seed_count: int = 0,
                 tool_version: str = ''):
        target_name = sanitize_target(target)
        if not target_name:
            raise ValueError('target is required for scan metadata')
        self.run_id = (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') +
                       '-' + uuid.uuid4().hex[:8])
        self.run_dir = Path(project_path) / target_name / '.runs'
        self.path = self.run_dir / f'{self.run_id}.json'
        self.data: dict[str, Any] = {
            'schema_version': 1,
            'run_id': self.run_id,
            'run_type': run_type,
            'target': target,
            'status': 'running',
            'started_at': _utc_now(),
            'finished_at': None,
            'seed_count': int(seed_count),
            'config_hash': _config_hash(config or {}),
            'tool_version': tool_version or 'working-tree',
            'steps': [],
            'finding_counts': {},
            'coverage_failures': [],
            'error': '',
        }
        self._write()

    @classmethod
    def from_project_manager(cls, project_manager, target: str, run_type: str,
                             **kwargs):
        project_path = project_manager.get_current_project_path()
        if not project_path:
            raise ValueError('no active project for scan metadata')
        return cls(project_path, target, run_type, **kwargs)

    def _write(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True))
        os.replace(tmp, self.path)

    def step(self, name: str, status: str, *, count: Optional[int] = None,
             message: str = '', error: str = '') -> None:
        row = {'name': name, 'status': status, 'at': _utc_now()}
        if count is not None:
            row['count'] = int(count)
            self.data['finding_counts'][name] = int(count)
        if message:
            row['message'] = message[:500]
        if error:
            row['error'] = error[:500]
        self.data['steps'].append(row)
        self._write()

    def coverage_failure(self, item: str) -> None:
        if item and item not in self.data['coverage_failures']:
            self.data['coverage_failures'].append(item[:500])
            self._write()

    def finish(self, status: Optional[str] = None, *, error: str = '') -> dict:
        if status is None:
            step_states = {s.get('status') for s in self.data['steps']}
            if 'timed_out' in step_states:
                status = 'timed_out'
            elif step_states & {'failed', 'unavailable'}:
                status = 'partial'
            else:
                status = 'completed'
        if status not in self.VALID_FINAL:
            raise ValueError(f'invalid final scan status: {status}')
        self.data['status'] = status
        self.data['finished_at'] = _utc_now()
        self.data['error'] = error[:1000]
        self._write()
        return dict(self.data)


__all__ = ['ScanRunRecorder']
