# modules/project_manager.py

import os
import json
import shutil
import pandas as pd
from pathlib import Path
from typing import Dict, Any, Union, Optional, List, Set

# Use new logger
from app.utils.logger import get_logger
logger = get_logger()


from app.utils.url_utils import urlparse

# Canonical home for sanitize/desanitize is modules/utils.py; this dual import
# keeps both `modules.X` and `app.modules.X` import styles working (pages add
# both the repo root and app/modules to sys.path; headless tests only add root).
try:
    from app.modules.utils import sanitize_target, desanitize_target
except ImportError:  # pragma: no cover - streamlit pages import as `modules.utils`
    from modules.utils import sanitize_target, desanitize_target


class ScopeManager:
    """
    Manages bug bounty scope rules per project.
    Supports: exact match, wildcard subdomain (*.example.com), and exclusion lists.
    Scope is persisted per-project and loaded automatically.
    """

    def __init__(self, project_path: Path):
        self.project_path = project_path
        self.scope_file = project_path / ".scope.json"
        self.in_scope: Set[str] = set()
        self.wildcard_scope: Set[str] = set()
        self.exclusions: Set[str] = set()
        self._load()

    @staticmethod
    def _norm(rule: str) -> str:
        """Lowercase, strip whitespace/trailing dots and leading '*.'."""
        rule = (rule or '').strip().lower().rstrip('.')
        if rule.startswith('*.'):
            rule = rule[2:]
        return rule

    def _load(self):
        """Load scope rules from project's .scope.json file."""
        if self.scope_file.exists():
            try:
                with open(self.scope_file, 'r') as f:
                    data = json.load(f)
                self.in_scope = {self._norm(r) for r in data.get('in_scope', []) if self._norm(r)}
                self.wildcard_scope = {self._norm(r) for r in data.get('wildcard_scope', []) if self._norm(r)}
                self.exclusions = {self._norm(r) for r in data.get('exclusions', []) if self._norm(r)}
                logger.info(f"Loaded scope for project: {len(self.in_scope)} exact, "
                           f"{len(self.wildcard_scope)} wildcard, {len(self.exclusions)} exclusions")
            except Exception as e:
                logger.error(f"Error loading scope file: {e}")
                self.in_scope = set()
                self.wildcard_scope = set()
                self.exclusions = set()

    def _save(self):
        """Persist scope rules to project's .scope.json file."""
        try:
            data = {
                'in_scope': sorted(list(self.in_scope)),
                'wildcard_scope': sorted(list(self.wildcard_scope)),
                'exclusions': sorted(list(self.exclusions)),
            }
            with open(self.scope_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving scope file: {e}")

    def add_in_scope(self, rule: str):
        """Add an in-scope rule. Supports exact domains or wildcards (*.example.com)."""
        raw = (rule or '').strip().lower()
        if not raw:
            return
        if raw.startswith('!'):
            self.add_exclusion(raw[1:])
            return
        if raw.startswith('*.'):
            self.wildcard_scope.add(self._norm(raw))
        else:
            self.in_scope.add(self._norm(raw))
        self._save()

    def add_exclusion(self, rule: str):
        """Add an exclusion rule (leading '*.' and '!' tolerated and normalized)."""
        rule = self._norm(rule)
        if rule.startswith('!'):
            rule = rule[1:]
        if not rule:
            return
        self.exclusions.add(rule)
        self._save()

    def remove_rule(self, rule: str):
        """Remove a scope rule."""
        rule = self._norm(rule)
        if not rule:
            return
        self.in_scope.discard(rule)
        self.wildcard_scope.discard(rule)
        self.exclusions.discard(rule)
        self._save()

    def clear(self):
        """Clear all scope rules."""
        self.in_scope = set()
        self.wildcard_scope = set()
        self.exclusions = set()
        self._save()

    @staticmethod
    def _as_host(target: str) -> str:
        """
        Normalize any domain / subdomain / URL / IP into a bare lowercase
        hostname. URL-parse based, so credentials (`user:pass@`) can NEVER
        smuggle a host: 'http://example.com:8080@evil.com/x' -> 'evil.com'.
        """
        t = (target or '').strip().lower().rstrip('.')
        if not t:
            return ''
        if t.startswith(('http://', 'https://', 'ws://', 'wss://', 'ftp://', '//')):
            try:
                host = urlparse(t).hostname or ''
                return host.rstrip('.').lower()
            except Exception:
                return ''
        if '@' in t:
            # bare 'user@host' (no scheme) is not a valid hostname - reject it
            return ''
        if t.count(':') > 1:
            # raw IPv6 literal (no scheme) - compare as-is
            return t.split('/')[0].rstrip('.').lower()
        # bare host[:port][/path]
        return t.split(':')[0].split('/')[0].rstrip('.').lower()

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a target (domain, subdomain, or URL) is in scope.

        Args:
            target: Domain, subdomain, or URL to check

        Returns:
            True if in scope, False otherwise
        """
        host = self._as_host(target)
        if not host:
            return False

        # Check exclusions first
        if host in self.exclusions:
            return False
        for ex in self.exclusions:
            if host.endswith('.' + ex):
                return False

        # No scope rules = everything in scope (default behavior)
        if not self.in_scope and not self.wildcard_scope:
            return True

        # Exact match
        if host in self.in_scope:
            return True

        # Wildcard match
        for wild in self.wildcard_scope:
            if host == wild or host.endswith('.' + wild):
                return True

        return False

    def filter_targets(self, targets: List[str]) -> List[str]:
        """Filter a list of targets, keeping only in-scope ones."""
        return [t for t in targets if self.is_in_scope(t)]

    def get_rules(self) -> Dict[str, List[str]]:
        """Get all scope rules as a dict."""
        return {
            'in_scope': sorted(list(self.in_scope)),
            'wildcard_scope': sorted(list(self.wildcard_scope)),
            'exclusions': sorted(list(self.exclusions)),
        }

    def get_scope_hosts(self) -> List[str]:
        """All hosts that are part of the scope zone (for host-suffix matching in tools)."""
        return sorted(set(self.in_scope) | set(self.wildcard_scope))

    def get_bug_bounty_header(self) -> Dict[str, str]:
        """Per-project X-Bug-Bounty header (e.g. {'X-Bug-Bounty': 'k0imet'})."""
        hdr_file = self.project_path / ".bug_bounty"
        if hdr_file.is_file():
            try:
                val = hdr_file.read_text().strip()
                if val:
                    # Handle both "k0imet" and "X-Bug-Bounty: k0imet" formats
                    if ":" in val:
                        name, value = val.split(":", 1)
                        return {name.strip(): value.strip()}
                    # auto sha256 if non-alphanumeric per program rules
                    return {"X-Bug-Bounty": val}
            except Exception:
                pass
        return {}

    def set_bug_bounty_header(self, value: str, header_name: str = "X-Bug-Bounty") -> None:
        hdr_file = self.project_path / ".bug_bounty"
        try:
            if not value or not value.strip():
                if hdr_file.exists():
                    hdr_file.unlink()
            else:
                hdr_file.write_text(f"{header_name}: {value.strip()}")
        except Exception as e:
            logger.error(f"Failed to save bug bounty header: {e}")

    def __repr__(self):
        return (f"ScopeManager(in_scope={len(self.in_scope)}, "
                f"wildcard={len(self.wildcard_scope)}, exclusions={len(self.exclusions)})")


class ProjectManager:
    # DataFrame columns inspected for scope enforcement at save time.
    # Any row whose host in one of these columns is out-of-scope is dropped
    # BEFORE hitting disk - so out-of-scope data never reaches later scans.
    # 'Matched_At'/'Target' cover nuclei output (scanner.py), 'Endpoint' the
    # GraphQL endpoint saves. Columns that name the TARGET itself vs columns
    # that merely record where a row was FOUND (provenance).
    SCOPE_TARGET_COLUMNS = ['URL', 'url', 'endpoint', 'Endpoint', 'host',
                            'hostname', 'Subdomain', 'subdomain', 'Domain',
                            'Target', 'Matched_At', 'matched_at', 'Base']
    SCOPE_PROVENANCE_COLUMNS = ['source_url', 'source', 'Input']

    def __init__(self, config: Dict):
        self.config = config
        self.base_projects_dir = Path(self.config['project_settings']['base_projects_dir']).expanduser()
        self.base_projects_dir.mkdir(parents=True, exist_ok=True)
        self.current_project_file = self.base_projects_dir / ".current_project_name.txt"
        self._current_project_name = self._load_current_project_name_from_file()
        self._scope_manager: Optional[ScopeManager] = None
        logger.info(f"ProjectManager initialized. Projects directory: {self.base_projects_dir}")
        if self._current_project_name:
            logger.info(f"Loaded active project: {self._current_project_name}")
            self._load_scope_for_current_project()
        else:
            logger.info("No active project loaded initially.")

    def _load_current_project_name_from_file(self) -> Optional[str]:
        if self.current_project_file.exists():
            try:
                name = self.current_project_file.read_text().strip()
                if name and (self.base_projects_dir / name).is_dir():
                    return name
                else:
                    self.current_project_file.unlink(missing_ok=True)
                    return None
            except Exception as e:
                logger.error(f"Error loading current project name from file: {e}")
                return None
        return None

    def _save_current_project_name_to_file(self, project_name: str):
        try:
            self.current_project_file.write_text(project_name)
        except Exception as e:
            logger.error(f"Error saving current project name to file: {e}")

    def _load_scope_for_current_project(self):
        """Load scope manager for the current project."""
        project_path = self.get_current_project_path()
        if project_path:
            self._scope_manager = ScopeManager(project_path)
        else:
            self._scope_manager = None

    def get_scope_manager(self) -> Optional[ScopeManager]:
        """Get the scope manager for the current project."""
        return self._scope_manager

    def get_current_project_name(self) -> Optional[str]:
        return self._current_project_name

    def set_current_project(self, project_name: str) -> bool:
        project_path = self.base_projects_dir / project_name
        if project_path.is_dir():
            self._current_project_name = project_name
            self._save_current_project_name_to_file(project_name)
            self._load_scope_for_current_project()
            logger.info(f"Current project set to: {project_name}")
            return True
        logger.warning(f"Project '{project_name}' not found at {project_path}.")
        return False

    def create_project(self, project_name: str) -> bool:
        project_path = self.base_projects_dir / project_name
        if project_path.exists():
            logger.warning(f"Project '{project_name}' already exists.")
            return False
        try:
            project_path.mkdir(parents=True, exist_ok=True)
            self._current_project_name = project_name
            self._save_current_project_name_to_file(project_name)
            self._load_scope_for_current_project()
            logger.info(f"Project '{project_name}' created at {project_path} and set as active.")
            return True
        except Exception as e:
            logger.error(f"Failed to create project '{project_name}': {e}")
            return False

    def get_all_projects(self) -> List[str]:
        return sorted([d.name for d in self.base_projects_dir.iterdir() if d.is_dir() and not d.name.startswith('.')])

    def get_current_project_path(self) -> Optional[Path]:
        if self._current_project_name:
            return self.base_projects_dir / self._current_project_name
        return None

    def get_all_targets_for_current_project(self) -> Dict[str, Any]:
        project_path = self.get_current_project_path()
        if not project_path:
            logger.warning("No current project set. Cannot retrieve targets.")
            return {}
        targets_dict = {}
        try:
            with os.scandir(project_path) as it:
                for item in it:
                    if item.is_dir() and not item.name.startswith('.') and item.name != 'custom_templates':
                        original_target_name = desanitize_target(item.name)
                        targets_dict[original_target_name] = {}
        except Exception as e:
            logger.error(f"Error listing targets for current project: {e}")
            return {}
        return targets_dict

    def add_target_to_current_project(self, target: str) -> bool:
        project_path = self.get_current_project_path()
        if not project_path:
            logger.error("No current project set. Cannot add target.")
            return False
        sanitized_target = sanitize_target(target)
        if not sanitized_target:
            logger.error(f"Cannot add target with empty name: '{target}'")
            return False
        target_dir = project_path / sanitized_target
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Ensured target directory exists for '{target}' in project '{self._current_project_name}'.")
            return True
        except Exception as e:
            logger.error(f"Failed to create directory for target '{target}': {e}")
            return False

    # ------------------------------------------------------------------
    # Scope enforcement (central chokepoint)
    # ------------------------------------------------------------------
    def _filter_df_by_scope(self, df: pd.DataFrame) -> tuple:
        """
        Drop rows whose TARGET host is out of scope. Returns (filtered_df, dropped_count).
        No scope rules configured -> is_in_scope() is True for everything -> no-op.

        Target columns (URL/endpoint/host/Domain/Target/Matched_At/Base...) are
        authoritative: a row is dropped when ALL of its target columns are
        out-of-scope. Provenance columns (source_url/source/Input - where the
        row was FOUND) never veto a row.
        """
        if self._scope_manager is None or df is None or df.empty:
            return df, 0
        target_cols = [c for c in self.SCOPE_TARGET_COLUMNS if c in df.columns]
        check_cols = target_cols or [c for c in self.SCOPE_PROVENANCE_COLUMNS if c in df.columns]
        if not check_cols:
            return df, 0
        try:
            combined = pd.Series(False, index=df.index)
            for col in check_cols:
                combined |= df[col].astype(str).apply(self._scope_manager.is_in_scope)
            dropped = int((~combined).sum())
            return df[combined].reset_index(drop=True), dropped
        except Exception as e:
            logger.error(f"Scope filtering failed: {e}")
            return df, 0

    def filter_targets_by_scope(self, targets: List[str]) -> List[str]:
        """Public helper for in-pipeline filtering (before results exist to save)."""
        if self._scope_manager is None:
            return targets
        return self._scope_manager.filter_targets(targets)

    def save_scan_results(self, scan_type: str, target: str,
                          results: Union[pd.DataFrame, Dict[str, pd.DataFrame]],
                          persist_empty: bool = False):
        project_path = self.get_current_project_path()
        if not project_path:
            logger.error("Cannot save results: No project selected.")
            return
        sanitized_target = sanitize_target(target)
        if not sanitized_target:
            logger.error(f"Cannot save results: empty target '{target}'")
            return
        target_dir = project_path / sanitized_target
        file_name = f"{scan_type}_results.json"
        file_path = target_dir / file_name
        try:
            if isinstance(results, pd.DataFrame):
                if results.empty and not persist_empty:
                    logger.info(f"Nothing to save for '{scan_type}' of '{target}': empty DataFrame.")
                    return
                results, dropped = self._filter_df_by_scope(results)
                if dropped:
                    logger.info(f"Scope: dropped {dropped} out-of-scope rows from '{scan_type}'")
                if results.empty and not persist_empty:
                    logger.info(f"Nothing to save for '{scan_type}' of '{target}': all rows out of scope.")
                    return
                target_dir.mkdir(parents=True, exist_ok=True)
                tmp_path = file_path.with_suffix('.tmp')
                results.to_json(tmp_path, orient='records', indent=4)
                os.replace(tmp_path, file_path)
            elif isinstance(results, dict) and all(isinstance(v, pd.DataFrame) for v in results.values()):
                if not results:
                    logger.info(f"Nothing to save for '{scan_type}' of '{target}': empty results dict.")
                    return
                if all(v.empty for v in results.values()) and not persist_empty:
                    logger.info(f"Nothing to save for '{scan_type}' of '{target}': all DataFrames empty.")
                    return
                nested_data = {}
                total_dropped = 0
                for k, v in results.items():
                    v, dropped = self._filter_df_by_scope(v)
                    total_dropped += dropped
                    nested_data[k] = v.to_dict(orient='records')
                if total_dropped:
                    logger.info(f"Scope: dropped {total_dropped} out-of-scope rows from '{scan_type}'")
                target_dir.mkdir(parents=True, exist_ok=True)
                tmp_path = file_path.with_suffix('.tmp')
                with open(tmp_path, 'w') as f:
                    json.dump(nested_data, f, indent=4)
                os.replace(tmp_path, file_path)
            else:
                logger.error(f"Unsupported results type for saving: {type(results)}")
                return
            logger.info(f"Results for '{scan_type}' of '{target}' saved to {file_path}")
        except Exception as e:
            logger.error(f"Error saving results for '{scan_type}' of '{target}': {e}")

    def load_scan_results(self, scan_type: str, target: str) -> Union[pd.DataFrame, Dict[str, pd.DataFrame], None]:
        project_path = self.get_current_project_path()
        if not project_path:
            return pd.DataFrame()
        sanitized_target = sanitize_target(target)
        if not sanitized_target:
            logger.warning(f"Cannot load results: empty target '{target}'")
            return pd.DataFrame()
        target_dir = project_path / sanitized_target
        file_name = f"{scan_type}_results.json"
        file_path = target_dir / file_name
        if not file_path.exists():
            if scan_type in ['js_analysis']:
                return {}
            return pd.DataFrame()
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            if isinstance(data, list):
                # Tolerant parse: list of records -> single DataFrame.
                # A list of dicts with no usable rows still builds an empty DF.
                try:
                    return pd.DataFrame(data)
                except Exception:
                    logger.warning(f"Could not build DataFrame from {file_path}")
                    return pd.DataFrame() if scan_type not in ['js_analysis'] else {}
            elif isinstance(data, dict):
                # Tolerant parse: nested dict of record-lists -> {key: DataFrame}.
                # Non-list values (metadata, etc.) are ignored, never fatal.
                nested = {}
                for k, v in data.items():
                    if isinstance(v, list):
                        try:
                            nested[k] = pd.DataFrame(v)
                        except Exception:
                            logger.warning(f"Could not build DataFrame for '{k}' in {file_path}")
                            nested[k] = pd.DataFrame()
                if nested:
                    return nested
                # dict present but nothing list-shaped in it
                return {} if scan_type in ['js_analysis'] else pd.DataFrame()
            else:
                logger.warning(f"Unexpected data format in {file_path}")
                if scan_type in ['js_analysis']:
                    return {}
                return pd.DataFrame()
        except Exception as e:
            logger.error(f"Error loading results for '{scan_type}' of '{target}': {e}")
            if scan_type in ['js_analysis']:
                return {}
            return pd.DataFrame()

    def get_all_results_for_current_project(self) -> Dict[str, Dict[str, Union[pd.DataFrame, Dict[str, pd.DataFrame]]]]:
        project_path = self.get_current_project_path()
        if not project_path:
            return {}
        all_results = {}
        try:
            with os.scandir(project_path) as target_iter:
                for target_entry in target_iter:
                    if not target_entry.is_dir() or target_entry.name.startswith('.'):
                        continue
                    original_target_name = desanitize_target(target_entry.name)
                    with os.scandir(target_entry.path) as scan_iter:
                        for scan_file in scan_iter:
                            if not scan_file.name.endswith("_results.json"):
                                continue
                            scan_type = scan_file.name[: -len("_results.json")]
                            results = self.load_scan_results(scan_type, original_target_name)
                            is_empty = False
                            if isinstance(results, pd.DataFrame):
                                is_empty = results.empty
                            elif isinstance(results, dict):
                                is_empty = all(df.empty for df in results.values() if isinstance(df, pd.DataFrame))
                            if not is_empty:
                                if scan_type not in all_results:
                                    all_results[scan_type] = {}
                                all_results[scan_type][original_target_name] = results
        except Exception as e:
            logger.error(f"Error iterating project results: {e}")
            return {}
        return all_results

    @staticmethod
    def _count_json_records(path: str) -> int:
        """Row count of a saved results JSON (list length or sum of nested list lengths). 0 on any error."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            if isinstance(data, list):
                return len(data)
            if isinstance(data, dict):
                return sum(len(v) for v in data.values() if isinstance(v, list))
            return 0
        except Exception:
            return 0

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Most recently modified scans of the current project.

        Returns a list of dicts {'scan_type', 'target', 'file', 'records',
        'mtime'} ordered by mtime descending (newest first), capped at
        `limit`. records is the row count of the saved JSON (0 when empty
        or unparseable).
        """
        project_path = self.get_current_project_path()
        if not project_path:
            return []
        scans: List[Dict[str, Any]] = []
        try:
            with os.scandir(project_path) as target_iter:
                for target_entry in target_iter:
                    if not target_entry.is_dir() or target_entry.name.startswith('.'):
                        continue
                    target = desanitize_target(target_entry.name)
                    with os.scandir(target_entry.path) as scan_iter:
                        for scan_file in scan_iter:
                            if not scan_file.name.endswith("_results.json"):
                                continue
                            scan_type = scan_file.name[: -len("_results.json")]
                            try:
                                mtime = scan_file.stat().st_mtime
                            except OSError:
                                mtime = 0.0
                            scans.append({
                                'scan_type': scan_type,
                                'target': target,
                                'file': scan_file.path,
                                'records': self._count_json_records(scan_file.path),
                                'mtime': mtime,
                            })
        except Exception as e:
            logger.error(f"get_recent_scans failed: {e}")
            return []
        scans.sort(key=lambda s: s['mtime'], reverse=True)
        return scans[: max(0, limit)]

    def delete_project(self, project_name: str) -> bool:
        if not project_name or not isinstance(project_name, str):
            logger.error(f"Invalid project name: {project_name}")
            return False
        project_path = self.base_projects_dir / project_name
        if not project_path.exists():
            logger.warning(f"Project '{project_name}' does not exist at {project_path}.")
            return False
        try:
            shutil.rmtree(project_path)
            logger.info(f"Deleted project '{project_name}' and its files at {project_path}")
            if self._current_project_name == project_name:
                self._current_project_name = None
                self._save_current_project_name_to_file("")
                self._scope_manager = None
                logger.info(f"Cleared current project as '{project_name}' was deleted.")
            return True
        except Exception as e:
            logger.error(f"Failed to delete project '{project_name}': {e}")
            return False
