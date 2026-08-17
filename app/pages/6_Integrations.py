# pages/6_Integrations.py
# Integrations: Burp Suite (scan + proxy history import), Caido (Replay + history
# via GraphQL) and evidence capture/export. The backend clients live in
# app/modules/integrations/{burp,caido}.py and app/modules/integrations/evidence.py —
# they are imported lazily so this page keeps working if they are not built yet.

import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.modules.utils import load_config
from app.modules.project_manager import ProjectManager
from app.modules.integrations.replay_targets import build_replay_targets
from app.utils.theme import inject_theme, app_header, get_palette

CONFIG = load_config()

inject_theme()
app_header("🔌", "Integrations",
           "Bridge DeepBug with the tools you already use.")
st.caption("Connect Burp Suite and Caido to close the manual-validation loop; "
           "capture request/response evidence for findings.")

if 'project_manager_instance' not in st.session_state:
    st.session_state.project_manager_instance = ProjectManager(CONFIG)
project_manager = st.session_state.project_manager_instance

current_project = project_manager.get_current_project_name()
if not current_project:
    st.warning("No project selected yet.")
    st.info("Create or open a project in **📂 Projects** first — integrations save "
            "scan findings and evidence per project target, so an active project "
            "is required before anything can be exported.")
    st.stop()

project_path = project_manager.get_current_project_path()
_palette = get_palette()


# ---------------------------------------------------------------------
# Lazy backend-client loading (built by other agents)
# ---------------------------------------------------------------------
def _load_burp():
    try:
        from app.modules.integrations.burp import BurpClient
        return BurpClient, None
    except ImportError as e:
        return None, f"Burp client module not available yet: {e}"


def _load_caido():
    try:
        from app.modules.integrations.caido import CaidoClient
        return CaidoClient, None
    except ImportError as e:
        return None, f"Caido client module not available yet: {e}"


def _load_evidence():
    try:
        from app.modules.integrations import evidence
        return evidence, None
    except ImportError as e:
        return None, f"Evidence module not available yet: {e}"


def _first(items):
    return next((i for i in items if i), None)


def _burp_client(base_url: str, api_key: str):
    """Cached per (url, key) so the connection survives reruns."""
    cache = st.session_state.get('burp_client')
    if cache is not None and st.session_state.get('burp_client_key') == (base_url, api_key):
        return cache, None
    BurpClient, err = _load_burp()
    if BurpClient is None:
        return None, err
    try:
        client = BurpClient(base_url=base_url, api_key=api_key)
        st.session_state['burp_client'] = client
        st.session_state['burp_client_key'] = (base_url, api_key)
        return client, None
    except Exception as e:
        return None, f"Could not initialize BurpClient: {type(e).__name__}: {e}"


def _caido_client(base_url: str, pat: str):
    cache = st.session_state.get('caido_client')
    if cache is not None and st.session_state.get('caido_client_key') == (base_url, pat):
        return cache, None
    CaidoClient, err = _load_caido()
    if CaidoClient is None:
        return None, err
    try:
        client = CaidoClient(base_url=base_url, pat=pat)
        st.session_state['caido_client'] = client
        st.session_state['caido_client_key'] = (base_url, pat)
        return client, None
    except Exception as e:
        return None, f"Could not initialize CaidoClient: {type(e).__name__}: {e}"


def _health_result(res):
    if isinstance(res, tuple):
        return bool(res[0]), (str(res[1]) if len(res) > 1 and res[1] else "")
    return bool(res), ""


def _scan_succeeded(status) -> bool:
    if isinstance(status, dict):
        status = status.get('status', status.get('state', ''))
    if not isinstance(status, str):
        status = str(status)
    return status.lower() in ('succeeded', 'success', 'complete', 'completed', 'done', 'finished')


def _to_df(res):
    if isinstance(res, pd.DataFrame):
        return res
    if isinstance(res, dict):
        for k in ('results', 'items', 'data', 'findings'):
            v = res.get(k)
            if isinstance(v, list) and v:
                return pd.DataFrame(v)
        return pd.DataFrame()
    if isinstance(res, list) and res:
        try:
            return pd.DataFrame(res)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()


def _dedupe_urls(urls):
    seen, out = set(), []
    for u in urls:
        u = str(u).strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


# ---------------------------------------------------------------------
# 🔗 Burp Suite
# ---------------------------------------------------------------------
st.subheader("🔗 Burp Suite")
st.caption("Drive Burp's scanner from DeepBug and pull proxy history back in. "
           "Enable the REST API in Burp (Settings → Suite → REST API) and use the key "
           "shown there once.")

with st.expander("Connection", expanded=True):
    c1, c2 = st.columns([3, 2])
    with c1:
        burp_url = st.text_input("Base URL", value="http://127.0.0.1:1337",
                                 key="intg_burp_url",
                                 placeholder="http://127.0.0.1:1337")
    with c2:
        burp_key = st.text_input("API Key", type="password", key="intg_burp_key",
                                 help="Shown once in Burp when enabling the REST API. "
                                      "Falls back to the BURP_API_KEY environment "
                                      "variable if left empty.")
    if st.button("Test connection", key="intg_burp_test"):
        client, err = _burp_client(burp_url, burp_key or CONFIG.get('burp_api_key') or "")
        if client is None:
            st.warning(err)
        else:
            with st.spinner("Contacting Burp REST API..."):
                try:
                    ok, msg = _health_result(client.health())
                except Exception as e:
                    ok, msg = False, f"{type(e).__name__}: {e}"
            if ok:
                st.success(f"Connected to Burp at {burp_url}. {msg}".strip())
            else:
                st.error(f"Connection failed: {msg or 'unreachable'}")

st.markdown("#### 🎯 Send live hosts to Burp scan")

targets = project_manager.get_all_targets_for_current_project()
target_list = list(targets.keys()) if targets else []

if not target_list:
    st.info("No targets in this project yet — add one in **📂 Projects** or "
            "**🔍 Reconnaissance** first.")
else:
    c1, c2 = st.columns([2, 1])
    with c1:
        burp_target = st.selectbox("Target", target_list, key="intg_burp_target")
    with c2:
        st.caption("Scans the project target's live hosts (from Reconnaissance).")

    if st.button("Send live hosts to Burp scan", key="intg_burp_scan"):
        live = project_manager.load_scan_results('live_hosts', burp_target)
        urls = (live['URL'].dropna().astype(str).tolist()
                if isinstance(live, pd.DataFrame) and 'URL' in live.columns and not live.empty
                else [])
        if not urls:
            st.warning("No live hosts saved for this target yet. Run "
                       "Reconnaissance → Live Hosts first.")
        else:
            client, err = _burp_client(burp_url, burp_key or CONFIG.get('burp_api_key') or "")
            if client is None:
                st.warning(err)
            else:
                with st.spinner(f"Sending {len(urls)} URLs to Burp scanner..."):
                    try:
                        task = client.start_scan(urls)
                        task_id = task.get('task_id') if isinstance(task, dict) else str(task)
                        st.session_state['burp_task_id'] = task_id
                        st.info(f"Burp scan started — task id: `{task_id}`. Use "
                                "**Check scan status** below to poll.")
                    except Exception as e:
                        st.error(f"Failed to start Burp scan: {type(e).__name__}: {e}")

    burp_task_id = st.session_state.get('burp_task_id')
    if burp_task_id:
        st.caption(f"Active Burp task: `{burp_task_id}`")
        if st.button("Check scan status", key="intg_burp_poll"):
            client, err = _burp_client(burp_url, burp_key or CONFIG.get('burp_api_key') or "")
            if client is None:
                st.warning(err)
            else:
                with st.spinner("Polling Burp..."):
                    try:
                        status = client.scan_status(burp_task_id)
                        status_val = status.get('status', status.get('state', '')) if isinstance(status, dict) else status
                        st.caption(f"Status: `{status_val}`")
                        if _scan_succeeded(status):
                            results = client.scan_results(burp_task_id)
                            df = _to_df(results)
                            if df.empty:
                                st.info("Scan succeeded but no findings were returned.")
                            else:
                                project_manager.save_scan_results('burp_findings', burp_target, df)
                                st.success(f"Scan succeeded — {len(df)} findings saved as "
                                           f"`burp_findings` for `{burp_target}`.")
                                st.dataframe(df, use_container_width=True)
                        elif status_val in ('running', 'queued', 'pending', 'starting'):
                            st.info("Scan still running — check again in a bit.")
                        else:
                            st.info(f"Scan not finished yet (status: `{status_val}`).")
                    except Exception as e:
                        st.error(f"Error polling Burp: {type(e).__name__}: {e}")

st.markdown("#### 📥 Import Burp proxy history")

c1, c2 = st.columns([2, 1])
with c1:
    burp_upload = st.file_uploader(
        "Burp export file (.json / .xml / .burp)", type=['json', 'xml', 'burp'],
        key="intg_burp_upload",
        help="Export from Burp via `Burp → Proxy → HTTP history → Export items` "
             "as JSON or XML (a .burp file is XML).")
with c2:
    burp_history_target = st.selectbox("Target to save to", target_list or ["—"],
                                       key="intg_burp_hist_target",
                                       disabled=not target_list)

if burp_upload is not None and target_list:
    if st.button("Import Burp proxy history", key="intg_burp_import"):
        fmt = burp_upload.name.rsplit('.', 1)[-1].lower()
        client, err = _burp_client(burp_url, burp_key or CONFIG.get('burp_api_key') or "")
        if client is None:
            st.warning(err)
        else:
            try:
                text = burp_upload.getvalue().decode('utf-8', errors='replace')
                with st.spinner(f"Parsing {fmt} export..."):
                    parsed = client.parse_burp_export(text, fmt)
                if isinstance(parsed, pd.DataFrame):
                    rows = parsed.to_dict(orient='records')
                else:
                    rows = list(parsed) if parsed else []
                df = pd.DataFrame(rows)
                if df.empty:
                    st.warning("No request/response items found in the export.")
                else:
                    if not {'url', 'method', 'status'}.issubset(df.columns):
                        col_map = {}
                        src = _first([c for c in ('Url', 'URL', 'host', 'Host', 'path') if c in df.columns])
                        if src and 'url' not in df.columns:
                            col_map[src] = 'url'
                        src = _first([c for c in ('Method', 'm_method') if c in df.columns])
                        if src and 'method' not in df.columns:
                            col_map[src] = 'method'
                        src = _first([c for c in ('Status', 'status_code', 'm_status') if c in df.columns])
                        if src and 'status' not in df.columns:
                            col_map[src] = 'status'
                        if col_map:
                            df = df.rename(columns=col_map)
                    project_manager.save_scan_results('burp_history', burp_history_target, df)
                    st.success(f"Saved **{len(df)}** history items as `burp_history` "
                               f"for `{burp_history_target}`.")
                    st.dataframe(df.head(50), use_container_width=True)
                    st.caption(f"{len(df)} items in total — showing the first 50. "
                               "URLs are available on the Dashboard; use them with "
                               "Scanner or the Caido Replay bridge below.")
            except Exception as e:
                st.error(f"Import failed: {type(e).__name__}: {e}")

st.markdown("---")

# ---------------------------------------------------------------------
# 🕸️ Caido
# ---------------------------------------------------------------------
st.subheader("🕸️ Caido")
st.caption("Push endpoints into Caido Replay sessions and pull proxy history "
           "back via the GraphQL API.")

with st.expander("Connection", expanded=True):
    c1, c2 = st.columns([3, 2])
    with c1:
        caido_url = st.text_input("Base URL", value="http://127.0.0.1:8080",
                                  key="intg_caido_url",
                                  placeholder="http://127.0.0.1:8080")
    with c2:
        caido_pat = st.text_input("Personal Access Token", type="password",
                                  key="intg_caido_pat",
                                  help="Dashboard → Developer → Personal Access Token. "
                                       "Falls back to the CAIDO_PAT environment "
                                       "variable if left empty.")
    if st.button("Test connection", key="intg_caido_test"):
        client, err = _caido_client(caido_url, caido_pat or CONFIG.get('caido_pat') or "")
        if client is None:
            st.warning(err)
        else:
            with st.spinner("Contacting Caido GraphQL..."):
                try:
                    ok, msg = _health_result(client.health())
                except Exception as e:
                    ok, msg = False, f"{type(e).__name__}: {e}"
            if ok:
                st.success(f"Connected to Caido at {caido_url}. {msg}".strip())
            else:
                st.error(f"Connection failed: {msg or 'unreachable'}")

st.markdown("#### 🚀 Send endpoints to Caido Replay")

if not target_list:
    st.info("No targets in this project yet — add one in **📂 Projects** first.")
else:
    c1, c2, c3 = st.columns([2, 1, 1])
    with c1:
        caido_target = st.selectbox("Target", target_list, key="intg_caido_target")
    with c2:
        caido_max = st.number_input("Max endpoints", 10, 2000, 250,
                                    key="intg_caido_max")
    with c3:
        st.caption("Selects high-value JS-discovered endpoints: API-ish paths, "
                   "gated (401/403/405/5xx), GraphQL, param'd & POST. "
                   "Static assets, chunk/namespace noise and plain SPA routes "
                   "are filtered out and deduplicated by path.")
        include_pages = st.checkbox("Include plain page routes", value=False,
                                    key="intg_caido_pages")
        include_static = st.checkbox("Include static assets", value=False,
                                     key="intg_caido_static")

    # ---- live preview of what would be sent ----
    endpoints = project_manager.load_scan_results('js_discovered_endpoints', caido_target)
    selection = {}
    if isinstance(endpoints, pd.DataFrame) and not endpoints.empty:
        # scope gate first: never forward out-of-scope endpoints to Caido
        endpoints, dropped_scope = project_manager._filter_df_by_scope(endpoints)
        selection = build_replay_targets(
            endpoints, max_targets=int(caido_max),
            include_pages=include_pages, include_static=include_static)
        selection['dropped_scope'] = dropped_scope
    if selection.get('targets'):
        note = ''
        if selection.get('dropped_scope'):
            note = f" 🚫 {selection['dropped_scope']} out-of-scope endpoint(s) removed."
        st.caption(f"From {selection['total_seen']} endpoints → "
                   f"**{len(selection['targets'])}** selected.{note} "
                   f"Skipped: {selection['skipped']}")
        with st.expander(f"Preview ({len(selection['targets'])})"):
            prev = pd.DataFrame([{'score': t['score'], 'status': t['status'],
                                  'category': t['category'], 'method': t['method'],
                                  'url': t['url']} for t in selection['targets']])
            st.dataframe(prev, use_container_width=True)

    if st.button("Send endpoints to Caido Replay", key="intg_caido_send",
                 disabled=not bool(selection.get('targets'))):
        if not selection.get('targets'):
            st.warning("No endpoints to send — run JS Analysis (and ideally "
                       "**Validate Endpoints**) for this target first.")
        else:
            client, err = _caido_client(caido_url, caido_pat or CONFIG.get('caido_pat') or "")
            if client is None:
                st.warning(err)
            else:
                urls = [t['url'] for t in selection['targets']]
                with st.spinner(f"Importing {len(urls)} endpoints into Caido Replay..."):
                    try:
                        res = client.import_replay_sessions(urls)
                        if isinstance(res, dict):
                            ids = res.get('session_ids', res.get('ids', res.get('sessions', [])))
                        else:
                            ids = res
                        if isinstance(ids, list):
                            session_label = f"{len(ids)} session(s): " + ", ".join(str(i) for i in ids[:5])
                            if len(ids) > 5:
                                session_label += f" … (+{len(ids) - 5} more)"
                        else:
                            session_label = f"ids: {ids}"
                        st.success(f"Sent **{len(urls)}** endpoints to Caido Replay — {session_label}")
                    except Exception as e:
                        st.error(f"Caido Replay import failed: {type(e).__name__}: {e}")

        # ---- push AUTHENTICATED candidates (stored AuthSession -> Caido) ----
        from app.modules.integrations.auth_session import AuthSession as _AuthSession
        _auth = _AuthSession.load(project_manager.get_current_project_path(), caido_target)
        if _auth is not None and _auth.authenticated:
            st.caption(f"🔐 Stored AuthSession found (`{_auth.flow}`) — candidates below are "
                       f"pushed **with its cookies/bearer** into the raw Replay requests.")
            if st.button("🚀 Push authenticated candidates to Caido", key="intg_caido_auth_send"):
                client, err = _caido_client(caido_url, caido_pat or CONFIG.get('caido_pat') or "")
                if client is None:
                    st.warning(err)
                else:
                    urls = [t['url'] for t in selection['targets']]
                    auth_hdrs = dict(_auth.auth_headers())
                    cookie = "; ".join(f"{k}={v}" for k, v in _auth.cookies.items())
                    if cookie:
                        auth_hdrs['Cookie'] = cookie
                    with st.spinner(f"Importing {len(urls)} endpoints (authenticated)...",
                                    ):
                        try:
                            res = client.import_replay_sessions(urls, headers=auth_hdrs)
                            if isinstance(res, dict):
                                ids = res.get('session_ids', res.get('ids', res.get('sessions', [])))
                            else:
                                ids = res if isinstance(res, list) else []
                            st.success(f"Sent **{len(urls)}** authenticated endpoint(s) — "
                                       f"{len(ids)} session(s). Verify in Caido Replay.")
                        except Exception as e:
                            st.error(f"Authenticated import failed: {type(e).__name__}: {e}")
        else:
            st.caption("No stored AuthSession for this target — create one in **🔐 Auth Sessions** "
                       "above to push authenticated candidates.")

st.markdown("#### 📥 Import Caido proxy history")

if target_list:
    c1, c2 = st.columns([2, 1])
    with c1:
        caido_limit = st.number_input("Limit (items to pull)", min_value=10,
                                      max_value=1000, value=200, step=10,
                                      key="intg_caido_limit")
    with c2:
        caido_hist_target = st.selectbox("Target to save to", target_list,
                                         key="intg_caido_hist_target")
    st.caption("Pulled via Caido's GraphQL API — the free tier allows 2 projects "
               "/ 7 workflows, which is plenty for history import.")
    if st.button("Import Caido proxy history", key="intg_caido_pull"):
        client, err = _caido_client(caido_url, caido_pat or CONFIG.get('caido_pat') or "")
        if client is None:
            st.warning(err)
        else:
            with st.spinner(f"Pulling up to {caido_limit} history items..."):
                try:
                    res = client.fetch_history(int(caido_limit))
                    df = _to_df(res)
                    if df.empty:
                        st.warning("No history items returned.")
                    else:
                        project_manager.save_scan_results('caido_history', caido_hist_target, df)
                        st.success(f"Saved **{len(df)}** history items as `caido_history` "
                                   f"for `{caido_hist_target}`.")
                        st.dataframe(df.head(50), use_container_width=True)
                        st.caption(f"{len(df)} items in total — showing the first 50.")
                except Exception as e:
                    st.error(f"Caido history import failed: {type(e).__name__}: {e}")

st.markdown("---")

# ---------------------------------------------------------------------
# 🧾 Evidence capture
# ---------------------------------------------------------------------
st.subheader("🧾 Evidence capture")
st.caption("Saved scan findings can carry evidence (curl commands, matched "
           "responses). Export them as a bundle.")

evidence, ev_err = _load_evidence()
if evidence is None:
    st.warning("Evidence module not yet available — it is being built. "
               "Check back shortly.")

if evidence is not None:
    if st.button("Export evidence bundle", key="intg_evid_export"):
        try:
            result = evidence.export_evidence_bundle(project_path)
            if isinstance(result, tuple) and len(result) >= 2:
                count, zip_bytes = result[0], result[1]
            else:
                zip_bytes, count = result, None
            if zip_bytes:
                st.success(f"Evidence bundle ready — {count or '?'} evidence entries.")
                st.download_button(
                    "⬇️ Download evidence bundle", zip_bytes,
                    file_name=f"evidence_{current_project}_{datetime.now():%Y%m%d}.zip",
                    mime="application/zip", key="intg_evid_download")
            else:
                st.info("No evidence entries captured yet — findings can carry "
                        "evidence; add one below or re-run the evidence capture.")
        except Exception as e:
            st.error(f"Evidence export failed: {type(e).__name__}: {e}")

with st.form(key="intg_evid_note_form"):
    note_target = st.selectbox("Target", target_list or ["—"], key="intg_evid_note_target",
                               disabled=not target_list)
    note_text = st.text_input("Manual note (what you observed / request details):",
                              key="intg_evid_note")
    submitted = st.form_submit_button("Capture manual note", key="intg_evid_note_btn")
if submitted:
    if not note_text.strip():
        st.warning("Note is empty — nothing captured.")
    elif evidence is None:
        st.warning("Evidence module not yet available — it is being built. "
                   "Check back shortly.")
    elif not target_list:
        st.warning("No targets in this project yet.")
    else:
        try:
            evidence.capture_note(project_path, note_target, note_text.strip())
            st.success(f"Manual note captured for `{note_target}`.")
        except Exception as e:
            st.error(f"Failed to capture note: {type(e).__name__}: {e}")

st.markdown("---")
st.caption("Licensing: Burp Suite Professional EULA prohibits running Pro in "
           "CI/CD pipelines — use these connectors from your workstation. "
           "Caido free tier supports all of this.")

# =====================================================================
# 🔐 Auth Sessions - one authenticated context per target, injected into
# every validator (REST battery, IDOR, GraphQL).
# =====================================================================
st.markdown("---")
st.subheader("🔐 Auth Sessions")
st.caption("Capture ONE login per target (JSON / form / OAuth2 / manual paste) "
           "and every validator replays it: authenticated REST probing, IDOR "
           "with real sessions, gated GraphQL. Sessions are stored under "
           "`projects/<project>/.auth/` (gitignored).")
with st.expander("Manage sessions", expanded=False):
    from app.modules.integrations.auth_session import AuthSession, AuthError as _AuthError
    if not target_list:
        st.info("Add a target in Projects first.")
    else:
        as_target = st.selectbox("Target:", target_list, key="authsess_target")
        as_flow = st.selectbox("Flow:",
                               ["json_login", "form_login", "oauth2", "manual"],
                               key="authsess_flow",
                               help="json_login: POST JSON, token from body/header. "
                                    "form_login: GET page, harvest CSRF, POST form. "
                                    "oauth2: grant_type=password. manual: paste.")
        c1, c2, c3 = st.columns(3)
        with c1:
            as_user = st.text_input("Username/email:", key="authsess_user")
            as_user_field = st.text_input("User field name:", "email", key="authsess_userf")
        with c2:
            as_pass = st.text_input("Password:", type="password", key="authsess_pass")
            as_pass_field = st.text_input("Pass field name:", "password", key="authsess_passf")
        with c3:
            as_base = st.text_input("Base URL:", value=f"https://{as_target}", key="authsess_base")
            as_endpoint = st.text_input("Login path (or OAuth token path):", "/rest/user/login",
                                        key="authsess_path")
        as_extra = st.text_input("Extra fields (JSON, optional):", key="authsess_extra")
        as_client = st.text_input("OAuth client_id (oauth2 only):", key="authsess_cid")
        as_secret = st.text_input("OAuth client_secret (oauth2 only):", type="password",
                                  key="authsess_csec")
        as_bearer = st.text_input("Manual bearer token:", type="password", key="authsess_bearer")
        as_cookie = st.text_input("Manual Cookie header:", key="authsess_cookie")

        if st.button("🔑 Establish session", key="authsess_run"):
            try:
                sess = AuthSession(target=as_target, base_url=as_base.rstrip('/'))
                if as_flow == 'json_login':
                    extra = json.loads(as_extra) if as_extra.strip() else None
                    sess.json_login(as_endpoint, as_user_field, as_pass_field,
                                    as_user, as_pass, extra_fields=extra)
                elif as_flow == 'form_login':
                    sess.form_login(as_endpoint, as_user_field, as_pass_field,
                                    as_user, as_pass)
                elif as_flow == 'oauth2':
                    sess.oauth2_password(as_endpoint, as_client, as_secret, as_user, as_pass)
                elif as_flow == 'manual':
                    sess.manual(bearer=as_bearer, cookie_header=as_cookie)
                sess.save(project_manager.get_current_project_path())
                ok = sess.verify()
                st.success(f"Session established ({sess.flow})"
                           + (f" · verify probe OK" if ok else " · verify probe failed"))
            except _AuthError as e:
                st.error(f"Auth failed: {e}")
            except Exception as e:
                st.error(f"Session error: {type(e).__name__}: {e}")

        stored = AuthSession.load(project_manager.get_current_project_path(), as_target)
        if stored is not None and stored.authenticated:
            st.markdown(f"**Stored session** (`{stored.flow}`) — "
                        f"bearer: {'yes' if stored.bearer else 'no'} · "
                        f"cookies: {list(stored.cookies.keys())} · "
                        f"refresh: {'yes' if stored.refresh_token else 'no'}")
            vc1, vc2 = st.columns(2)
            if vc1.button("✅ Verify stored", key="authsess_verify"):
                st.success("Session valid." if stored.verify() else "Session INVALID.")
            if vc2.button("🗑️ Delete stored", key="authsess_del"):
                (project_manager.get_current_project_path() / '.auth' /
                 f"{as_target.replace('.', '_').replace('/', '_')}.json").unlink(missing_ok=True)
                st.rerun()
        else:
            st.caption("No stored session for this target yet.")
