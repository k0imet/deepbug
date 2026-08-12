# DeepBug Configuration

The runtime configuration lives in **`app/modules/config.json`** and is loaded
by `load_config()` in `app/modules/utils.py`. Two important behaviors:

- **Defaults + deep merge** — the loader defines a full default config in code
  and deep-merges `config.json` over it, so every key always exists. Sections
  you omit (e.g. the whole `ai` block) still get sensible defaults.
- **Environment-variable expansion** — string values containing `$VAR` or
  `${VAR}` are expanded at load time, so `"$HOME/go/bin/nuclei"` works as-is.

## `project_settings`

| Key | Default | Purpose |
|-----|---------|---------|
| `base_projects_dir` | `./projects` | Where projects/targets/`*_results.json` live. The shipped `config.json` sets `/home/user/deepbug/projects`. |

## `tools.paths`

Absolute paths to every external binary (config.json values shown; the code
defaults are empty strings and `$VAR` is expanded):

`subfinder`, `dnsx`, `nuclei`, `nuclei_templates`, `nmap`, `masscan`, `subjs`,
`webanalyze`, `httpx`, `getjs`, `gf`, `kxss`, `linkfinder`, `fakjs`,
`paramspider`, `amass`, `ffuf`, `arjun`, `x8`, `gf_patterns`, `katana`, `gau`,
`uro`, `playwright`

Plus a special non-path key:

- `gitb_subdomains_token_env` — env var name holding the GitHub token for the
  GitHub subdomain scanner (default `GITHUB_TOKEN`).

> Nuclei resolution is lenient: the configured path is used if it exists,
> otherwise `nuclei` is looked up on `PATH`, otherwise the configured value is
> kept so the error message stays clear. The Scanner only fails hard when the
> binary is missing entirely.

## `tools.rate_limits`

| Key | Default | Purpose |
|-----|---------|---------|
| `masscan` | `1000` | Ports/second rate for masscan scans. |

## `tools.sqltimer`

Time-based SQLi timing defaults: `sleep_time` (5s), `threads` (10),
`timeout_multiplier` (6), `timeout_buffer` (10s).

## `tools.http_smuggling`

`timeout` (8s), `delay_threshold` (1.0), `block_threshold` (3.0) — CL.TE/TE.CL
detection timing.

## `tools.url_clean`

- `drop_blog_slugs` (true) — remove blog-like path segments
- `keep_values` (false) — strip or keep query values when deduplicating URLs

## `tools.active_crawler`

`depth` (4), `threads` (10), `timeout` (120s) — katana-based active crawl.

## `tools.screenshots`

`width` (1280), `height` (800), `timeout_ms` (20000), `max_urls` (100) —
headless screenshot scanner limits.

## `tools.secret_chainer`

`timeout` (12s), `max_checks` (30), `delay` (0.3s), and the enabled `chains`
(boolean per secret → service validation chain):

`cognito_pool`, `oauth_client_credentials`, `aws_keys`, `github_token`,
`github_finegrained`, `stripe_live`, `stripe_restricted`, `slack`, `discord`,
`google_api`, `twilio_token`, `mailgun_key`, `appkey_header`

## `tools.config_sensitive_scanner`

`timeout` (10s), `max_hosts` (100), `user_agent` (a SecurityProbe UA) — probes
for exposed config files across hosts.

## `experimental`

| Key | Default | Purpose |
|-----|---------|---------|
| `enable_async` | false | Async scan paths |
| `enable_ai` | false | AI features (the shipped config sets it true) |
| `enable_db` | false | DB-backed storage experiments (shipped config: true) |
| `enable_resume` | false | Resume/cache Nuclei results (`load_cache`/`save_cache`, TTL 7200s) |
| `log_level` | INFO | Logging level |
| `log_file` | `logs/deepbug.log` | Log destination |
| `SHODAN_API_KEY` | — | Shodan key used by the Shodan/ASN OSINT tool (prefer the env var) |
| `subprocess_timeout` | 600 | Default timeout for external commands |

## Other top-level sections

- `logging` — `level` (INFO) and `file` (`bugbountybot.log`).
- `recon_output_dir` — `./recon_tmp_output`, temporary recon scratch space.
- `output_formats` — `default: "csv"` for downloads.
- `dom_xss` — `max_urls` (40), `browser` (true), `page_timeout_ms` (8000),
  `max_variants` (6) for the DOM XSS validator.

## The `ai` section

The `ai` block is **not present in the shipped `config.json`** — it is provided
entirely by the code defaults in `load_config()`. To customize it, add an `ai`
block to `config.json` (it overrides the defaults key-by-key):

```json
{
  "ai": {
    "enable": true,
    "api_base": "https://api.openai.com/v1",
    "api_key": "",
    "model": "gpt-4o-mini",
    "chat_base": "https://api.tokenrouter.com/v1",
    "chat_model": "moonshotai/kimi-k3-free",
    "chat_temperature": 0.3,
    "chat_max_history": 20,
    "chat_max_chars": 6000,
    "timeout": 60,
    "max_context": 6000
  }
}
```

| Key | Default | Used by |
|-----|---------|---------|
| `enable` | false | Result analysis via AIAnalyzer (analysis only; the chat page has its own key logic) |
| `api_base` | `https://api.openai.com/v1` | Analysis endpoint base URL |
| `api_key` | `""` | Analysis key; falls back to `OPENAI_API_KEY` env var |
| `model` | `gpt-4o-mini` | Analysis model |
| `chat_base` | `https://api.tokenrouter.com/v1` | AI Assistant chat base URL (prefilled in the UI) |
| `chat_model` | `moonshotai/kimi-k3-free` | Chat model (prefilled in the UI) |
| `chat_temperature` | 0.3 | Chat temperature |
| `chat_max_history` | 20 | Most recent messages sent per turn |
| `chat_max_chars` | 6000 | Per-message / pinned-context character cap |
| `timeout` | 60 | HTTP timeout for both chat and analysis |
| `max_context` | 6000 | Characters of results compacted into an analysis prompt |

See AI-GUIDE.md for provider examples and page-level overrides.

## Environment variables

| Variable | Used by |
|----------|---------|
| `OPENAI_API_KEY` | Fallback for `ai.api_key` in AIAnalyzer when the config key is empty |
| `SHODAN_API_KEY` | Shodan OSINT (default `token_env` in the `shodan` section) |
| `GITHUB_TOKEN` | GitHub subdomain / leak scanners (default `token_env` in the `github` section and `tools.paths.gitb_subdomains_token_env`) |
