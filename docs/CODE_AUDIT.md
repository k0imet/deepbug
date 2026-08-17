# DeepBug Code Audit — 2026-08-17

Full-repo review (pages + tool modules + cross-module contract checks).
Two review passes completed; integrations/core pass pending.

## CRITICAL (fix immediately)

| # | Location | Class | Issue | Status |
|---|---|---|---|---|
| C1 | `5_AI.py:147` | logic gap | Chat draft sent on ANY rerun (`if (prompt or submitted) and prompt:`) → duplicate API calls + rerun loop | FIXED |
| C2 | `1_Recon.py:204` | contract | `recon_runner._last_subdomain_results` doesn't exist → Full Recon silently discards ALL results with a misleading error | FIXED |
| C3 | `6_Integrations.py:416-446` | logic gap | AuthSession push block nested inside `if st.button(...)` → authenticated Caido push unreachable | FIXED |

## HIGH

| # | Location | Class | Issue | Status |
|---|---|---|---|---|
| H1 | `2_Scanner.py:208` | silent failure | Workflow checkbox (`-w`) never passed to scanner → nuclei workflows run as templates | FIXED |
| H2 | `6_Integrations.py:170...` | contract | Burp/Caido credential fallbacks read wrong config keys; env fallback missing | FIXED |
| H3 | `6_Integrations.py:233` | wrong key | Burp scan-status poll reads `status`/`state` but client returns `scan_status` → success never recognized | FIXED |
| H4 | download buttons in click blocks | logic gap | `st.download_button` inside `if st.button()` never renders on its own rerun (4_Reporting, 5_AI, 6_Integrations, 1_Recon ×9) | FIXED (5_AI + 6_Integrations + 4_Reporting; 1_Recon deferred) |
| H5 | `2_Scanner.py:319` | duplication | Completed-scan branch re-saves + re-captures evidence every rerun | FIXED |
| H6 | `2_Scanner.py:230` | targets | `custom_templates/` dir shows as bogus target `custom.templates` | FIXED |
| H7 | `endpoint_engine.py:488` | scope | `netloc` (with port) vs scope host compare → ported-host endpoints silently dropped | FIXED |
| H8 | `js_api_explorer.py:1287` | corruption | `_normalize_url` turns bare-relative `users/123` into `://users/123` → dropped | FIXED |
| H9 | `js_api_explorer.py:1349` | contract | `_score_endpoint` clobbers `suspicious_indicators` → `source_map_available` never seen → js_source_maps always empty | FIXED |
| H10 | `subdomain_scanner.py:375` | flags | dnsgen invoked as `-w <domains-file>` (wordlist) → 0 permutations always | FIXED |
| H11 | `subdomain_scanner.py:749` | swallow | nuclei non-zero exit logged as "no findings" → false negatives | OPEN (log-level fix pending) |
| H12 | `port_scanner.py:45-51` | RCE | `shell=True` with unsanitized target → command injection from the UI field | FIXED |
| H13 | `js_gf_secret_scanner.py:38` | contract | `webpack_define_plugin` reports the var NAME not the secret value | OPEN |
| H14 | `github_subdomains.py:136` | async | `asyncio.run` inside running loop → always-empty results silently | OPEN |
| H15 | `config_sensitive_scanner.py:210` | async | same `asyncio.run` pattern | OPEN |
| H16 | `run_2go_battery.py:16` | script | argv indexed before arg guard → IndexError instead of usage | FIXED |

## MEDIUM (documented, deferred)

- M1 scope allow-all defaults (subdomain_scanner, js_analyzer, endpoint_engine) → fail-closed proposal
- M2 SPA route regexes miss `routerLink:"/x"` forms + `${}` interpolations
- M3 `active_crawler.py` shared `/tmp/db_crawl_targets.txt` → cross-target race
- M4 katana/gau/subjs/getJS/waybackurls stderr discarded → silent 0-result crawls
- M5 altdns `-w words.txt` depends on CWD → permutation pass never runs
- M6 `subdomain_scanner` sync wrapper `get_event_loop` breaks inside running loop
- M7 `secret_validator` O(n·m) line counting + no per-pattern cap → minified-bundle blowup
- M8 `js_gf_secret_scanner` unbounded finditer (no max_matches)
- M9 `api_key_scanner` cap consumed by discarded low-confidence matches
- M10 ParamSpider `-s` flag fork incompatibility (value-taking build)
- M11 AST regex-fallback skipped when AST finds ≥3 requests
- M12 dead branch: `window.WebSocket`/`global.WebSocket` undetectable
- M13 `dorking_scanner` `.format()` crash on braces kills whole scan
- M14 nmap parser drops product/version (keeps protocol only)
- M15 js_analyzer thread pool leaked on exception before shutdown
- M16 js_api_explorer parse cache unbounded across targets
- M17 `2_Scanner` dict fallback reads keys that can't exist (nested under js_analysis)
- M18 project-template selectbox overwrites manual path silently
- M19 `st.session_state.scanner_tool` accessed from background thread
- M20 port_scanner import path `modules.utils` breaks standalone page runs
- M21 dead `st.session_state[_pkey]` write in Recon target persist
- M22 reset doesn't drain scan queue (stale progress messages)
- M23 inconsistent traceback swallowing across Recon handlers
- M24 evidence bundle count always `?` (returns bytes, not tuple)
- M25 AuthSession delete misses `:` sanitization
- M26 AI chat env-var-only users blocked despite help text
- M27 Dashboard legacy scan-name dedupe branches dead
- M28 `width='stretch'` breaks streamlit<1.42 (pin requirement)
- M29 `0_Projects` private `_scope_manager` stale on external edits
- M30 `st.stop()` after no-result scans hides page remainder
- M31 dead imports (WebanalyzeScanner etc.) in 1_Recon
- M32 `6_Integrations` dict-shaped endpoints silently disable Caido bridge
- M33 XSS in generated HTML report (target name/rows unescaped)
- M34 gf sqli pattern misses string-valued params
- M35 `subdomain_scanner._wildcard_ips` typed `Dict[str,str]` stores None

## Pending review pass

Integrations + validators + core/utils audit ran but returned no output — rerun:
cors/pp/dom_xss/open_redirect/ssrf/live_rest/idor/graphql family/ai_analyzer,
burp/caido/auth_session/preview_corpus/evidence/replay_targets,
project_manager/recon/scanner/utils + scripts.
