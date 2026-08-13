import sys
import time
import queue
import threading
from pathlib import Path

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.modules.utils import load_config, is_valid_url
from app.modules.project_manager import ProjectManager
from app.modules.scanner import VulnerabilityScanner
from app.utils.theme import inject_theme, app_header

try:
    from app.modules.integrations import evidence
except ImportError:  # evidence module unavailable: skip evidence capture gracefully
    evidence = None

try:
    from app.utils.logger import get_logger as _get_logger
    _scan_logger = _get_logger()
except Exception:
    import logging
    _scan_logger = logging.getLogger("deepbug.scanner")

CONFIG = load_config()

inject_theme()
app_header("🛡️", "Vulnerability Scanner", "Run Nuclei scans against live hosts from the active project.")

if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance

if 'scanner_tool' not in st.session_state:
    st.session_state.scanner_tool = VulnerabilityScanner(CONFIG)

if 'scan_status' not in st.session_state:
    st.session_state.update({
        'scan_status': 'idle',
        'scan_progress': 0.0,
        'scan_message': '',
        'scan_results': None,
        'scan_error': '',
        'scan_queue': queue.Queue()
    })


def run_nuclei_task(targets, template, queue):
    """Background task to avoid blocking the Main Thread."""
    try:
        def progress_callback(p, msg):
            queue.put(('progress', p, msg))

        df = st.session_state.scanner_tool.run_nuclei_scan(
            targets, template_path=template, progress_callback=progress_callback
        )
        queue.put(('result', df))
    except Exception as e:
        queue.put(('error', str(e)))


def _attach_target_column(df, urls):
    if not isinstance(df, pd.DataFrame) or df.empty or 'Target' in df.columns or not urls:
        return df
    df = df.copy()
    if 'Matched_At' in df.columns:
        def _find_target(matched):
            for u in urls:
                if str(matched).startswith(str(u).rstrip('/')):
                    return u
            return urls[0]
        df['Target'] = df['Matched_At'].apply(_find_target)
    else:
        df['Target'] = urls[0]
    return df


def _reset_scan_state():
    for key in ('scan_status', 'scan_progress', 'scan_message', 'scan_results', 'scan_error'):
        st.session_state.pop(key, None)
    st.rerun()


current_project = project_manager.get_current_project_name()
if not current_project:
    st.warning("No project selected. Open the Projects page to create or load one.")
    st.stop()

all_targets = list(project_manager.get_all_targets_for_current_project().keys())
selected_target = st.selectbox("Select target:", [''] + all_targets, key="scanner_selected_target")

# --- Previously saved results (persisted on disk) ---
if selected_target:
    saved = project_manager.load_scan_results('vulnerabilities', selected_target)
    if isinstance(saved, pd.DataFrame) and not saved.empty:
        mtime_note = ''
        try:
            sanitized = selected_target.replace('.', '_').replace('/', '_')
            saved_file = project_manager.get_current_project_path() / sanitized / 'vulnerabilities_results.json'
            if saved_file.exists():
                mtime_note = f" – file last written {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(saved_file.stat().st_mtime))}"
        except OSError:
            pass
        st.subheader("Previously saved results (loaded from disk)")
        st.markdown(f"**{len(saved)}** saved findings for `{selected_target}`{mtime_note}.")
        st.dataframe(saved, width='stretch')

# --- Targeting & Config ---
col1, col2 = st.columns(2)
with col1:
    selected_urls = []
    if selected_target:
        live = project_manager.load_scan_results('live_hosts', selected_target)
        if isinstance(live, pd.DataFrame) and 'URL' in live.columns and not live.empty:
            url_options = live['URL'].dropna().astype(str).tolist()
            selected_urls = st.multiselect("Select URLs to scan:", url_options, default=url_options, key="scanner_urls")

with col2:
    manual_urls = st.text_area("Or enter URLs manually (one per line):", key="scanner_manual_urls")
    custom_path = st.text_input("Custom template path:", key="scanner_template_path")
    start_scan = st.button("Start Scan", disabled=(st.session_state.scan_status == 'running'))

scan_targets = list(selected_urls)
for line in (manual_urls or '').splitlines():
    url = is_valid_url(line.strip())
    if url and url not in scan_targets:
        scan_targets.append(url)

if start_scan:
    if not scan_targets:
        st.error("No scan targets. Select URLs from the project target or enter some manually.")
    elif st.session_state.scan_status == 'running':
        st.info("A scan is already running.")
    else:
        st.session_state.scan_status = 'running'
        st.session_state.scan_progress = 0.0
        st.session_state.scan_message = 'Starting scan...'
        threading.Thread(target=run_nuclei_task, args=(scan_targets, custom_path, st.session_state.scan_queue), daemon=True).start()
        st.rerun()

# --- Queue Processor ---
if not st.session_state.scan_queue.empty():
    try:
        item = st.session_state.scan_queue.get_nowait()
        if isinstance(item, (tuple, list)) and len(item) >= 2:
            msg_type, *payload = item
            if msg_type == 'progress':
                try:
                    st.session_state.scan_progress = float(payload[0])
                except (TypeError, ValueError):
                    pass
                st.session_state.scan_message = str(payload[1])
            elif msg_type == 'result':
                st.session_state.scan_results = payload[0]
                st.session_state.scan_status = 'completed'
            elif msg_type == 'error':
                st.session_state.scan_error = str(payload[0])
                st.session_state.scan_status = 'failed'
            else:
                st.session_state.scan_error = f"Unknown queue message: {msg_type!r}"
                st.session_state.scan_status = 'failed'
        else:
            st.session_state.scan_error = f"Unexpected queue payload: {item!r}"
            st.session_state.scan_status = 'failed'
    except queue.Empty:
        pass

# --- Live UI Updates ---
if st.session_state.scan_status == 'running':
    st.progress(st.session_state.scan_progress, text=st.session_state.scan_message or 'Running...')
    time.sleep(0.5)
    st.rerun()

elif st.session_state.scan_status == 'completed':
    result_df = st.session_state.scan_results
    if isinstance(result_df, pd.DataFrame) and not result_df.empty:
        result_df = _attach_target_column(result_df, scan_targets)
        save_target = selected_target or 'manual_scan'
        project_manager.save_scan_results('vulnerabilities', save_target, result_df)
        st.success(f"Scan finished: {len(result_df)} vulnerabilities saved to disk.")
        try:
            if evidence is not None and project_manager.get_current_project_path() is not None:
                project_path = project_manager.get_current_project_path()
                for _, row in result_df.head(min(25, len(result_df))).iterrows():
                    try:
                        evidence.capture_finding(project_path, save_target, 'vulnerabilities', row.to_dict())
                    except Exception as _evid_err:
                        _scan_logger.error("Evidence capture failed: %s", _evid_err)
        except Exception as _evid_err:
            _scan_logger.error("Evidence capture failed: %s", _evid_err)
        if evidence is not None:
            st.caption("📥 Evidence captured for up to 25 findings (see Integrations → Evidence capture to export).")
        if save_target == 'manual_scan':
            st.caption("Saved under target `manual_scan` because no project target was selected.")
        st.dataframe(result_df, width='stretch')
    elif isinstance(result_df, pd.DataFrame):
        st.info("Scan finished with no findings.")
    else:
        st.warning("Scan finished but produced no result data.")
    if st.button("Reset", key="reset_scan_completed"):
        _reset_scan_state()

elif st.session_state.scan_status == 'failed':
    st.error(f"Scan failed: {st.session_state.scan_error or 'Unknown error'}")
    if st.button("Reset", key="reset_scan_failed"):
        _reset_scan_state()