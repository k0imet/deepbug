# Changelog

All notable changes to **DeepBug** are documented here.  
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) + [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

We use this to **encourage collaboration**: every PR should add a line under `## [Unreleased]`, reviewers check `CHANGELOG` before `git log`.

---

## [Unreleased]

### Added
- `vulners_enricher` — tech+version → Vulners CVE enrich (CVSS/EPSS/KEV/exploits), auto-triggered on `webanalyze` + `js_libraries` versions, cached.
- `js_analyzer` — `interesting_comments` (TODO|FIXME|SECURITY|HACK|BUG) + `emails` harvester (zack0x01 borrow, strict flag).
- `js_analyzer` — `raw-*` auth header rules (Bearer/Basic/AWS Sig) + `\\u00XX`/`%XX`/HTML-entity decode layer (JSRecon-Buddy borrow).
- `js_analyzer` — source-map `.map` guessing probe + NPM scoped package regex (`@scope/pkg`).

### Changed
- `js_analyzer` 3.7 → 3.8 — header `__version__ = "3.8.0"` + `js_vulners_auto`/`js_detect_comments`/`js_detect_emails` flags.
- `README` — added `Chaos` + `Vulners` to recon stack.

---

## [3.8.0] - 2026-09-02
### Added
- **Vulners.com** API (`/api/v3/search/id` + `/search/lucene`) via `VulnersEnricher` — `X-Api-Key`, SQLite cache, 429 handling; UI in `Recon → Advanced → 🔍 Vulners Enrichment` (per-project key input, CVE lookup + tech enrich). Closes 2026 gap: AI libs + tech-version → CVE.
- **Best-of-breed JS borrow** (no flaws copied):
  - `zack0x01/JS-Analyser`: strict flag model, `is_strict` for vendor keys, comment/email categories, `test.js` fixture.
  - `TheArqsz/JSRecon-Buddy`: `raw-bearer-token`/`raw-basic-auth`/`raw-aws-auth-header`, `decodeText` layer, `.map` guessing, 32-param list, scoped NPM regex.
  - `m4ll0k/SecretFinder`: `amazon_aws_url2` (5 S3 styles), `firebase` FCM, `google_captcha`, `SSH_privKey` multiline, `possible_Creds`.
  - `vavkamil/js-snitch`: TruffleHog `Verified` badge concept, `r/generic.secrets` optional engine.
  - `semgrep/semgrep`: taint skeletons (`mode:taint` sources→sinks) + constant-propagation mental model for future YAML rules.

### Changed
- `js_analyzer` 3.7 → 3.8.0 — see `app/modules/tools/js_analyzer.py:1` header.

---

## [3.7.0] - 2026-09-02
### Added
- **Vite/Rollup** manifest discovery (`__vite__mapDeps`, `manifest.json` capped 6) — from gap analysis.
- **Next.js** buildId tolerant regex + 4 manifests (`_buildManifest` balanced brackets, `_routesManifest`, `_ssgManifest`, `_middlewareManifest`) + `ViteManifest` recursion.
- **Chaos** dataset as 4th passive subdomain source (`dns.projectdiscovery.io`, `CHAOS_API_KEY`), parallel, scope-gated.
- **SubdomainScanner** `enable_chaos` flag, `chaos_subdomains` results.

### Changed
- Tabs: `Parameter Mining` now **before** `Vulnerability Detection` so `x8` `?param=deepbug_test` URLs auto-feed GF.
- `param_miner` → `gf_scanner` feeder: builds full URLs from `Parameter` column.

---

## [3.6.0] - 2026-09-02
### Added
- **Cookie Bomb Lab** (`cookie_bomb_scanner.py`) — passive analytics + `document.cookie` sink + single-request `?gclid=AAAA*4000` probe → `400/431` check. 9th tab in Recon.

### Fixed
- `vhost_fuzzer` — HTTPS/SNI first, body hash (not `len 15`) + CDN-aware, modern wordlist (`internal-prd/platform/backoffice`).

---

## [3.5.0] - 2026-09-01
### Added
- `api_docs_mapper` wired into `Recon → Advanced` — probes OpenAPI/Swagger/Redoc + GraphQL, feeds endpoints to Scanner.

### Removed
- `shadow_api_scanner`, `sqli_scanner` (dup of `live_rest_validator`), `scope_parser` (dup of `ScopeManager`).

---

## [3.4.0] - 2026-08-31
### Fixed
- Arrow-compat DataFrames (`_arrow_safe`) for `auth` dict / `status` mixed types — fixes `pyarrow.lib.ArrowInvalid`.
- `use_container_width` → `width='stretch'` (Streamlit 2025-12-31 deprecation).

### Changed
- `X-Bug-Bounty` header dynamic per-project in `Recon → 🏷️ Bug Bounty Header` (was hardcoded `k0imet` in `config.json`). `ScopeManager.get/set_bug_bounty_header()` → `projects/<proj>/.bug_bounty`.

---

## [3.3.0] - 2026-08-28
### Added
- Aylo / MyDirtyHobby project `aylo-mydirtyhobby` (5 exact hosts, `assets.mydirtyhobby.com`, `users.mydirtyhobby.com` for JS), agegate `AGEGATEPASSED=1` bypass, authed JS sweep (26 files/232 endpoints past-gate).

### Fixed
- `js_analyzer` `X-Bug-Bounty` via `get_bug_bounty_headers()`, throttled 5 rps for 7/sec program.

---

## [3.2.0] - 2026-08-28
### Added
- Danalock / Salto project `danalock` (Tier1 `staging.api.danalock.com`, creds `shs-intigriti@saltosystems.com`).

---

## [3.1.0] - 2026-08-31 — Steroids Edition (performance-hardened)
- `js_max_matches 30`, `bisect` line index, `ast_max_bytes 250KB`, `minified_line_len 2000`, `file_timeout 90s`, `max_files 500`, truncated not dropped, `allow_redirects=False` + `100.64.0.0/10` SSRF block, `HTMLParser` crawl + `subjs/getJS` + Wayback.

---

## Contributing

1. **Bump `VERSION`** and add an `## [Unreleased]` entry — reviewers check this first.
2. **One feature per PR**, with `Added / Changed / Fixed / Removed` sections.
3. Link the `HowToHunt` or `GAP_ANALYSIS_2026` item it closes.

```
# Example
## [Unreleased]
### Added
- `my_feature` — closes #123, borrow from https://github.com/.../...

## [3.8.0] - 2026-09-02
...
```

See `CONTRIBUTING.md` for branch/PR flow.
