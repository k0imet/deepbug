# DeepBug Modules — Reconnaissance Tabs & Result Keys

The Reconnaissance page (`app/pages/1_Recon.py`) is a "Full Recon" pipeline
plus **8 consolidated tabs**. Every scan saves results to disk via
`project_manager.save_scan_results(...)`; tabs re-load and display stored
results on every run, so re-running a tab updates the stored JSON.

## One-click pipeline

**🚀 Full Recon** (`Reconnaissance.full_recon_scan` in `app/modules/recon.py`)
chains: subdomain enumeration (subfinder + amass + CT logs + permutations) →
subdomain takeover check → web technology scan (webanalyze) → JS analysis →
nmap port scan on the main domain. Scope-aware: the domain must be in scope or
it aborts. Saved keys: `subfinder_subdomains`, `amass_subdomains`,
`ct_logs_subdomains`, `resolved_subdomains`, `live_hosts`,
`subdomain_takeovers`, `web_technologies`, `ports`, plus the `js_*` keys below.

## The 8 tabs

### 1. 🌐 Subdomain & Takeover
- **Subdomain scan**: passive enumeration run **in parallel** — Subfinder,
  Amass (time-capped, default 5 min) and CT logs; optional permutations
  (capped at 3000) and wildcard filtering.
- One DNS resolution pass (`dnsx`) reused for wildcard filtering; only
  **resolved** hosts get HTTP probed (`httpx`, extra ports configurable,
  default `8080,8443`).
- **Scope gate**: out-of-scope subdomains are dropped before any resolution
  or probing.
- **🔁 Subdomain Takeover** check runs against the resolved-subdomains results.

### 2. 🔌 Port & Service Scan
- `PortScanner` with tool choice **nmap / masscan / naabu**, custom port range
  (e.g. `1-1000`, `80,443,8080`; masscan is rate-limited via config), saved as
  `ports`.

### 3. 📜 JavaScript Analysis (v3.0)
`JSAnalyzer` runs framework detection, prototype pollution, DOM clobbering,
postMessage analysis, dangerous patterns, JSONP, dynamic rendering and CSP
gadget detection over live hosts (or `https://` + `http://` of the domain as
fallback). "Validate Endpoints" probes discovered endpoints for live status,
allowed methods and soft-404s. Results are split into **9 sub-tabs**:

| Sub-tab | Content |
|---------|---------|
| 📊 Overview | Frameworks, prototype pollution, dangerous patterns, secrets, priority endpoints |
| 🔑 Secrets & Patterns | Secrets (masked), dangerous patterns, JSONP, dynamic rendering, CSP gadgets |
| ⚠️ Client-Side Vectors | Prototype pollution vectors, DOM clobbering, postMessage issues |
| 📂 Endpoints | Discovered endpoints (soft-404/interesting filters), GraphQL, WebSocket, source maps |
| 🧪 PP Validation | Active `__proto__` canary injection (`pp_validator`) |
| 🖥️ DOM XSS | DOM XSS validation (`dom_xss_validator`) |
| 🌐 CORS | CORS validation (`cors_validator`) |
| ↩️ Open Redirect | Open redirect validation (`open_redirect_validator`) |
| 📡 SSRF | SSRF validation (`ssrf_validator`) |

Validators confirm static candidates with headless-browser proof where
available (pip-installed `playwright`); results show CONFIRMED / PROBABLE /
POTENTIAL.

### 4. 🔍 Vulnerability Detection
- **GF scan**: `gf_scanner` runs built-in pattern categories (xss, sqli, ssrf,
  lfi, rce, ssti, secrets, idor, api, debug, sensitive files — plus any custom
  patterns in `~/.gf`).
- **🎯 XSS Confirmation (kxss)**: probes GF XSS candidates (or pasted URLs)
  for confirmed reflections; severity CRITICAL/HIGH.
- **🧩 Template Injection (CSTI/SSTI)**: injects `{{7*7}}`-style probes into
  query params; evaluated `49` = confirmed, with engine fingerprinting.

### 5. ☁️ Cloud & Infra
- `cloud_enum`-based **Cloud Enumeration** for AWS, Azure and GCP buckets;
  publicly listable buckets are flagged as reportable.

### 6. 🔑 Parameter Mining
- **🗃️ URL Collection**: archives (gau, waybackurls) and optional active crawl
  (katana), then cleaned/deduplicated (`url_cleaner`).
- **Parameter mining**: x8 (primary when installed), else Arjun, else the
  built-in async fuzzer; optional **Historical OSINT** via ParamSpider
  (Wayback) — historical URLs feed back into the Vulnerability Detection tab.

### 7. 🛡️ Security Headers
- `CORSHeadersScanner`: per-URL status, CORS misconfiguration + severity, ACAO,
  and missing security headers (CSP, HSTS, X-Frame-Options, …).

### 8. 🧬 Advanced Scans
- **GraphQL Scanner**: endpoint discovery + schema analysis (types, queries,
  mutations, dangerous fields, misconfig notes).
- **IDOR / BOLA Scanner**: requires two authenticated sessions (Session A =
  resource owner, Session B = attacker cookies) and cross-checks access.
- **Dependency Confusion**: checks JS-file URLs for dependency-confusion risks.
- **Supply Chain Audit (SRI)**: flags third-party scripts/stylesheets without
  `integrity=` (compromised-CDN risk), known-hostile CDNs (polyfill.io,
  rawgit) and cleartext resources.
- **Mass Assignment & Type Juggling**: injects privilege/business-logic fields
  (admin, role, price…) and type-confuses query params; response diffs expose
  honoring backends.

> Note: `app/modules/tools/` also ships modules not currently wired into the
> Recon page tabs (e.g. `github_subdomains`, `http_smuggling`,
> `secret_chainer`, `config_sensitive_scanner`, `screenshot_scanner`,
> `shodan_recon`, `git_disclosure_scanner`, `bypass_403`, `vhost_fuzzer`,
> `graphql_analyzer`, `graphql_clairvoyance`, `dorking_scanner`, `jwt_scanner`,
> `race_scanner`, `xxe_scanner`, …). They exist for programmatic/headless use;
> the UI exposes the 8 tabs above.

## Result save keys (verified from `save_scan_results` calls)

| Tab | Save keys |
|-----|-----------|
| 1 — Subdomain & Takeover | `subfinder_subdomains`, `amass_subdomains`, `ct_logs_subdomains`, `resolved_subdomains`, `live_hosts`, `subdomain_takeovers` |
| 2 — Port & Service Scan | `ports` |
| 3 — JS Analysis | `js_frameworks`, `js_prototype_pollution`, `js_dangerous_patterns`, `js_sensitive_data_findings`, `js_priority_endpoints`, `js_dom_clobbering`, `js_postmessage_issues`, `js_jsonp_endpoints`, `js_dynamic_rendering`, `js_csp_gadgets`, `js_discovered_endpoints`, `js_graphql_endpoints`, `js_websocket_endpoints`, `js_source_maps`, `js_files`, `pp_validation`, `dom_xss_validation`, `cors_validation`, `open_redirect_validation`, `ssrf_validation` |
| 4 — Vulnerability Detection | `gf_xss_candidates`, `gf_sqli_candidates`, `gf_ssrf_candidates`, `gf_lfi_candidates`, `gf_rce_candidates`, `gf_ssti_candidates`, `gf_secrets_candidates`, `gf_idor_candidates`, `gf_api_candidates`, `gf_debug_candidates`, `gf_sensitive_files_candidates`, `gf_filtered_urls`, `kxss_confirmed_xss`, `csti_findings` |
| 5 — Cloud & Infra | `cloud_aws`, `cloud_azure`, `cloud_gcp` |
| 6 — Parameter Mining | `collected_urls`, `param_miner`, `param_miner_historical` |
| 7 — Security Headers | `cors_headers` |
| 8 — Advanced Scans | `graphql_endpoints`, `idor_findings`, `dependency_confusion`, `supply_chain`, `mass_assignment` |
| Scanner page | `vulnerabilities` (Nuclei schema — see ARCHITECTURE.md) |

Full Recon additionally saves `web_technologies`. The Dashboard counts
`live_hosts` → Subdomains, `ports` → Open Ports, `js_files` → JS Files,
`vulnerabilities`/`gf_vuln_urls` → Vulnerabilities, `subdomain_takeovers` →
Takeovers.
