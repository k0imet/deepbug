# DeepBug Troubleshooting

Common issues and their fixes.

## `No module named 'app.modules'`

**Cause**: the app was launched with the wrong entrypoint, e.g.
`streamlit run app/app.py` or `streamlit run app/pages/1_Recon.py`. The import
paths are set up by `deepbug_app.py` only.

**Fix**: always start from the repository root:

```bash
cd /home/user/deepbug
streamlit run deepbug_app.py
```

## Scan results not showing on other pages

- Pages read results for the **active project only** — create/load the same
  project on the **Projects** page first.
- The Scanner page (`2_Scanner.py`) saves Nuclei results **under the selected
  project target**; if you scan manually without selecting a target, findings
  are saved under a target called `manual_scan`.
- The Dashboard caches nothing — it re-reads disk on every rerun, but if the
  file changed while the page was open, hit **🔄 Refresh** (Projects and
  Dashboard both have one).

## `Nuclei executable not found`

The Scanner fails hard when the nuclei binary is missing:

```
RuntimeError: Nuclei executable not found at '...'
```

**Fix**: set the correct path in `app/modules/config.json` under
`tools.paths.nuclei` (the loader also expands `$HOME`, e.g.
`"$HOME/go/bin/nuclei"`), or ensure `nuclei` is on `PATH` — the scanner falls
back to a `shutil.which('nuclei')` lookup. Install it via `bash app/install.sh`
or `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`.
A missing **templates directory** is only a warning, not fatal.

## Empty Dashboard

The Dashboard aggregates saved `*_results.json` files only. Run scans first:
Reconnaissance → (optional) Vulnerability Scanner. Empty pages show "No scan
results yet." / "No scans saved yet." — expected on a fresh project.

## AI chat / analysis errors

- **404 on `/chat/completions`** → the base URL must be an OpenAI-compatible
  endpoint ending in `/v1` (e.g. `https://api.groq.com/openai/v1`, not
  `https://api.groq.com`).
- **401/auth errors** → set a valid key in the AI Assistant page, in
  `ai.api_key` in config, or export `OPENAI_API_KEY`. Local models (Ollama,
  LM Studio) need no key — leave it empty.
- **Timeouts** → raise `ai.timeout` (default 60) in the `ai` config block, or
  check that the local model server is running and reachable.
- Analysis **falling back to "Local heuristic analysis"** → that's the
  built-in fallback when AI isn't enabled or the call failed; connect a valid
  endpoint to get LLM output.

See AI-GUIDE.md for provider examples.

## Duplicate widget key errors

Older versions collided on widget keys across projects; the pages now use
**project-scoped keys** (e.g. `recon_target_<project>`), so switching projects
no longer clashes. If you still see `There are multiple elements with the same
key` after an upgrade, **restart Streamlit** — stale widget state from a
previous session is the usual culprit (Ctrl+C, then re-run).

## Port 8501 already in use

```bash
streamlit run deepbug_app.py --server.port 8502
```

## Projects directory missing / not created

`ProjectManager.__init__` creates `project_settings.base_projects_dir`
(`mkdir(parents=True, exist_ok=True)`), so this is rare. If it fails
(permissions), check the path in `app/modules/config.json` and that the parent
directory is writable by the user running Streamlit.

## Corrupted `*_results.json`

Result loading is **tolerant by design**: unreadable JSON, unexpected shapes,
and non-list values inside nested dicts are logged and treated as empty
(empty DataFrame, or `{}` for `js_analysis`) rather than crashing the page.
Fix the file by re-running the scan that produced it.
