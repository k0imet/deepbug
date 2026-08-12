# DeepBug Architecture

## Tech stack

- **Python 3.13+** runtime
- **Streamlit** (>= 1.40) — the entire UI, rendered from 6 page files
- **pandas** (>= 2.0) — results are DataFrames end-to-end
- **plotly** (>= 5.18) — charts on the Dashboard
- **aiohttp** (>= 3.9) — AI chat completions (streaming SSE) and result analysis; no vendor SDK
- **httpx** / **requests** — HTTP helpers in tools
- Optional: **Go** binaries (nuclei, subfinder, etc.) for most recon features

## Entrypoint & navigation

`deepbug_app.py` (repo root) is the only entrypoint. It:

1. Inserts `deepbug/`, `deepbug/app`, and `deepbug/app/modules` into `sys.path`.
2. Loads config via `load_config()` and caches it plus the `ProjectManager` in `st.session_state`.
3. Sets page config, theme, and the sidebar brand + active-project badge.
4. Builds navigation with `st.navigation()` — explicit page order:

```python
st.navigation([
    st.Page('app/pages/0_Projects.py',  title='Projects',            icon='📂', url_path='projects'),
    st.Page('app/pages/1_Recon.py',     title='Reconnaissance',      icon='🔍', url_path='recon'),
    st.Page('app/pages/2_Scanner.py',   title='Vulnerability Scanner', icon='🛡️', url_path='scanner'),
    st.Page('app/pages/3_Dashboard.py', title='Dashboard',           icon='📊', url_path='dashboard'),
    st.Page('app/pages/4_Reporting.py', title='Reporting',           icon='📄', url_path='reporting'),
    st.Page('app/pages/5_AI.py',        title='AI Assistant',        icon='🤖', url_path='ai'),
], position='sidebar')
```

> ⚠️ Do not run `streamlit run app/app.py` or `streamlit run app/pages/...` —
> the app is designed around this single entrypoint (see TROUBLESHOOTING.md).

## App package layout

```
deepbug/
├── deepbug_app.py              # entrypoint (path setup, config, nav)
├── requirements.txt
├── app/
│   ├── install.sh              # optional: installs Go recon tools
│   ├── pages/                  # 6 Streamlit pages (one per nav item)
│   ├── modules/                # core logic
│   │   ├── config.json         # runtime config (see CONFIGURATION.md)
│   │   ├── project_manager.py  # ProjectManager + ScopeManager
│   │   ├── scanner.py          # VulnerabilityScanner (Nuclei)
│   │   ├── recon.py            # Reconnaissance (full-recon pipeline)
│   │   ├── utils.py            # load_config defaults, parsers, sanitize
│   │   └── tools/              # 69 Python modules — one scanner per concern
│   └── utils/                  # theme, logger, cache, subprocess_runner, ui_helpers, ...
└── .streamlit/config.toml      # Streamlit theme / server settings
```

`app/modules/tools/` contains ~69 modules (e.g. `subdomain_scanner.py`,
`js_analyzer.py`, `gf_scanner.py`, `ai_analyzer.py`, `secret_chainer.py`,
`shodan_recon.py`, …) plus a `data/` directory with pattern corpora.

## 6-page flow

```
+------------+     +----------------+     +---------------------+
| 0_Projects | --> | 1_Recon        | --> | 2_Scanner           |
| project mgr|     | 8 recon tabs   |     | Nuclei on live hosts|
+------------+     +----------------+     +----------+----------+
                                                     |
                                                     v
+----------------+     +--------------+     +---------------------+
| 4_Reporting    | <-- | 3_Dashboard  | <-- | saved *_results.json|
| HTML report    |     | metrics/charts|     | (per project/target)|
+----------------+     +--------------+     +---------------------+
                                                       |
                                                       v
                                              +----------------+
                                              | 5_AI           |
                                              | chat + analysis|
                                              +----------------+
```

Every page reads the same on-disk JSON store, so results flow forward through
the workflow regardless of which page wrote them.

## Persistence model

All data lives under the configured base projects directory
(`project_settings.base_projects_dir`, default `/home/user/deepbug/projects`):

```
projects/
├── .current_project_name.txt     # active project name (persisted across restarts)
├── <project>/
│   ├── .scope.json               # scope rules for that project
│   ├── .ai_chat.json             # AI Assistant conversation history
│   └── <sanitized_target>/       # e.g. example_com  ('.' → '_' via sanitize_target)
│       └── <scan_type>_results.json
```

- **`<scan_type>_results.json`** — either a JSON list of records (one DataFrame)
  or a nested dict `{sub_type: [records, ...]}` (e.g. JS analysis). Written by
  `ProjectManager.save_scan_results()`.
- **Atomic writes** — results are first written to a `.tmp` file, then moved
  into place with `os.replace()`, so a crash never leaves a half-written JSON.
- **Scope filtering at save** — rows whose host is out of scope are dropped
  *before* the file is written (central chokepoint in `save_scan_results`).
- **`.current_project_name.txt`** — stores the active project; the manager
  validates it still exists and auto-clears it otherwise.
- **`.scope.json`** — `{in_scope, wildcard_scope, exclusions}` lists, loaded
  automatically when a project becomes active.
- **`.ai_chat.json`** — chat history, persisted per project so it survives page
  switches and restarts.

## ProjectManager — single source of truth

`ProjectManager` (app/modules/project_manager.py) is the only component that
writes or reads the projects directory:

- `create_project` / `set_current_project` / `delete_project` / `get_all_projects`
- `add_target_to_current_project` / `get_all_targets_for_current_project`
- `save_scan_results(scan_type, target, results)` — scope filter + atomic write
- `load_scan_results(scan_type, target)` — tolerant loader (see below)
- `get_all_results_for_current_project()` — used by Dashboard, Reporting, AI
- `get_recent_scans(limit=10)` — newest-first scan list with record counts
- `filter_targets_by_scope(targets)` — in-pipeline filtering before results exist

Loads are **tolerant**: a missing file returns an empty DataFrame (or `{}` for
`js_analysis`), and a corrupted/unparseable file is logged and treated as empty
rather than crashing the page.

## ScopeManager

Per-project scope enforcement (`ScopeManager` in project_manager.py):

- **Exact match** — `example.com` matches that host only.
- **Wildcard** — `*.example.com` matches the zone + any subdomain.
- **Exclusions** — `!foo.example.com` (or a bare exclusion) removes hosts;
  exclusions are checked first and win over everything.
- **Normalization** — rules are lowercased, trailing dots stripped, `*.` and
  leading `!` tolerated; URLs are parsed so `user:pass@` can't smuggle a host.
- **Defaults** — no rules configured = everything is in scope.
- **Enforcement points** — `filter_targets_by_scope()` in scan pipelines and
  `_filter_df_by_scope()` at save time; the Recon tab shows live IN/OUT status.

## Scanner output schema

`VulnerabilityScanner` (app/modules/scanner.py) defines a stable Nuclei output
schema — every saved `vulnerabilities` result matches it:

| Column | Source (nuclei JSONL) |
|--------|------------------------|
| `Template_ID` | `template-id` |
| `Name` | `info.name` |
| `Severity` | `info.severity` (uppercased, sorted CRITICAL→INFO) |
| `Matched_At` | `matched-at` |
| `Target` | `host`, falling back to the host part of `Matched_At` |
| `Extracted_Results` | `extracted-results` |
| `Curl_Command` | `curl-command` |

Nuclei output is parsed line-by-line from JSONL; malformed/truncated lines are
skipped, never fatal.
