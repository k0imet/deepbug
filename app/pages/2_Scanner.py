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


def run_nuclei_task(targets, template, queue, options=None):
    """Background task to avoid blocking the Main Thread."""
    try:
        def progress_callback(p, msg):
            queue.put(('progress', p, msg))

        df = st.session_state.scanner_tool.run_nuclei_scan(
            targets, template_path=template, progress_callback=progress_callback,
            options=options
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

# --- URL source aggregation: pull from every tool in the pipeline ---
def _source_urls(scan_type, url_cols, target):
    """Load URLs for one source type, tolerating any column naming."""
    urls = []
    frame = project_manager.load_scan_results(scan_type, target)
    if isinstance(frame, pd.DataFrame) and not frame.empty:
        for col in url_cols:
            if col in frame.columns:
                urls.extend(frame[col].dropna().astype(str).tolist())
                break
    # Nested js_analysis dict fallback
    if scan_type == 'js_discovered_endpoints' and isinstance(frame, dict):
        for sub in ('js_discovered_endpoints', 'js_priority_endpoints'):
            sub_df = frame.get(sub)
            if isinstance(sub_df, pd.DataFrame) and not sub_df.empty:
                for col in url_cols:
                    if col in sub_df.columns:
                        urls.extend(sub_df[col].dropna().astype(str).tolist())
                        break
    return [u for u in urls if is_valid_url(u)]


def _load_gf_urls(target):
    """Collect URLs from every saved gf_*_candidates frame (Vulnerability Detection output)."""
    urls = []
    project_path = project_manager.get_current_project_path()
    if project_path and target:
        target_dir = project_path / target.replace('.', '_').replace('/', '_')
        if target_dir.is_dir():
            for f in sorted(target_dir.glob('gf_*_results.json')):
                try:
                    df = pd.read_json(f)
                    for col in ('URL', 'url'):
                        if col in df.columns:
                            urls.extend(df[col].dropna().astype(str).tolist())
                            break
                except Exception:
                    continue
    return [u for u in urls if is_valid_url(u)]


st.subheader("🎯 Targets")
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

sources = {
    'live_hosts': ('🌐 Live hosts', ['URL']),
    'js_discovered_endpoints': ('📜 JS endpoints', ['endpoint', 'URL']),
    'param_miner': ('🔑 Param-mined URLs', ['URL', 'url']),
    'param_miner_historical': ('🕰️ Historical param URLs', ['URL', 'url']),
    'collected_urls': ('🗃️ Collected URLs', ['URL', 'url']),
    'caido_history': ('🕸️ Caido history', ['url', 'URL']),
    'burp_history': ('🔗 Burp history', ['url', 'URL']),
}
source_counts = {}
if selected_target:
    for key, (label, cols) in sources.items():
        source_counts[key] = len(_source_urls(key, cols, selected_target))
    source_counts['gf_candidates'] = len(_load_gf_urls(selected_target))
else:
    for key in sources:
        source_counts[key] = 0
    source_counts['gf_candidates'] = 0

col1, col2 = st.columns(2)
with col1:
    st.markdown("**Scan sources** (merged + deduped):")
    enabled = {}
    for key, (label, _) in sources.items():
        enabled[key] = st.checkbox(f"{label} ({source_counts[key]})", value=bool(source_counts[key]),
                                   key=f"scn_src_{key}",
                                   disabled=(source_counts[key] == 0))
    enabled['gf_candidates'] = st.checkbox(f"🎯 GF candidates ({source_counts['gf_candidates']})",
                                           value=bool(source_counts['gf_candidates']),
                                           key="scn_src_gf",
                                           disabled=(source_counts['gf_candidates'] == 0))

with col2:
    manual_urls = st.text_area("Or enter URLs manually (one per line):", key="scanner_manual_urls")
    st.markdown("**Nuclei options**")
    custom_path = st.text_input("Template path (file/dir, comma-separated ok, empty = default templates):",
                                key="scanner_template_path",
                                help="Absolute path or relative to the configured nuclei templates dir. "
                                     "Leave empty to use the configured templates directory.")
    t1, t2 = st.columns(2)
    with t1:
        scan_tags = st.text_input("Tags (-tags)", key="scn_tags", placeholder="cve,oast,exposure")
    with t2:
        scan_severity = st.multiselect("Severity (-severity)", ["info", "low", "medium", "high", "critical"],
                                       key="scn_severity", default=None)
    t3, t4, t5 = st.columns(3)
    with t3:
        scan_rate = st.number_input("Rate (req/s)", 1, 2000, 150, key="scn_rate")
    with t4:
        scan_conc = st.number_input("Concurrency (-c)", 1, 500, 25, key="scn_conc")
    with t5:
        scan_workflow = st.checkbox("Workflow (-w)", key="scn_wf",
                                    help="Treat the template path as a nuclei workflow file.")

# Project-level custom templates (persisted in the project dir, reusable)
project_templates = {}
project_path = project_manager.get_current_project_path()
if project_path:
    tpl_dir = project_path / 'custom_templates'
    if tpl_dir.is_dir():
        project_templates = {f.name: f for f in sorted(tpl_dir.glob('*.yaml'))}
    with st.expander("🗂️ Project templates (custom_templates/)"):
        if project_templates:
            chosen = st.selectbox("Use a project template:", [''] + list(project_templates.keys()),
                                  key="scn_proj_tpl")
            if chosen:
                custom_path = str(project_templates[chosen])
                st.caption(f"Using project template: `{chosen}`")
        else:
            st.caption("No templates yet — upload .yaml files to store them per project.")
        up = st.file_uploader("Upload custom template(s)", type=["yaml", "yml"], accept_multiple_files=True,
                              key="scn_tpl_upload")
        if up:
            tpl_dir.mkdir(exist_ok=True)
            for f in up:
                (tpl_dir / f.name).write_bytes(f.getbuffer())
            st.success(f"Saved {len(up)} template(s) to `{tpl_dir}` — they appear above next run.")
            st.rerun()

scan_targets = []
if selected_target:
    for key, (label, _) in sources.items():
        if enabled.get(key):
            scan_targets.extend(_source_urls(key, sources[key][1], selected_target))
    if enabled.get('gf_candidates'):
        scan_targets.extend(_load_gf_urls(selected_target))
for line in (manual_urls or '').splitlines():
    url = is_valid_url(line.strip())
    if url:
        scan_targets.append(url)
scan_targets = list(dict.fromkeys(scan_targets))

# ---- scope gate: nothing out-of-scope reaches nuclei ----
_before_scope = len(scan_targets)
scan_targets = project_manager.filter_targets_by_scope(scan_targets)
_dropped_scope = _before_scope - len(scan_targets)
if _dropped_scope:
    st.warning(f"🚫 Removed {_dropped_scope} out-of-scope URL(s) before scanning.")

source_total = sum(source_counts.values())
st.caption(f"🎯 **{len(scan_targets)} unique URLs** ready to scan (from {source_total} collected across "
           f"{len([k for k, v in enabled.items() if v])} source(s)).")
if scan_targets:
    with st.expander(f"Preview ({min(50, len(scan_targets))} of {len(scan_targets)}):"):
        st.dataframe(pd.DataFrame({'URL': scan_targets[:50]}), width='stretch')

scan_options = {
    'tags': scan_tags.strip() if scan_tags.strip() else None,
    'severity': scan_severity or None,
    'rate': int(scan_rate),
    'concurrency': int(scan_conc),
    'is_workflow': bool(scan_workflow),
}
start_scan = st.button("🚀 Start Scan", type="primary", disabled=(st.session_state.scan_status == 'running'))

if start_scan:
    if not scan_targets:
        st.error("No scan targets. Enable a source with URLs, or enter URLs manually.")
    elif st.session_state.scan_status == 'running':
        st.info("A scan is already running.")
    else:
        st.session_state.scan_status = 'running'
        st.session_state.scan_progress = 0.0
        st.session_state.scan_message = 'Starting scan...'
        threading.Thread(target=run_nuclei_task,
                         args=(scan_targets, custom_path, st.session_state.scan_queue),
                         kwargs={'options': scan_options},
                         daemon=True).start()
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
    if st.session_state.get('scan_saved') and st.session_state.scan_results is not None:
        st.success(f"Scan finished: {len(st.session_state.scan_results)} vulnerabilities saved to disk.")
        st.dataframe(st.session_state.scan_results, width='stretch')
        if st.button("Reset", key="reset_scan_completed_2"):
            _reset_scan_state()
            st.rerun()
        st.stop()
    st.session_state.scan_saved = True
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