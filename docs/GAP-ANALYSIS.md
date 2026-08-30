# DeepBug — Veteran Bug-Bounty Gap Analysis

_Companion to README.md · Generated 2026-08-13 · Benchmarked against the modern
12-stage hunting workflow (reconFTW / ProjectDiscovery / bbot class tooling) and
the Burp Suite + Caido integration surfaces._

> **Status update (2026-08-13):** P0 shipped — Burp + Caido connectors and the
> HAR/evidence store are live (see `docs/INTEGRATIONS.md`). Stage 9 is now
> 🟡 B− (proxy loop connected; OOB collaborator still pending).

---

## 1. Quantified inventory — what DeepBug has today

| Asset | Count |
|---|---|
| Scanner/tool modules (`app/modules/tools/`) | **62** |
| UI pages (Projects → Recon → Scanner → Dashboard → Reporting → AI) | 6 |
| Recon tabs (Subdomain/Takeover, Ports, JS, Vuln Detection, Cloud, Params, Headers, Advanced) | 8 |
| JS-analysis sub-tabs (incl. 5 live validators: PP, DOM XSS, CORS, Open Redirect, SSRF) | 9 |
| Result types persisted per project/target (`<scan_type>_results.json`) | **70+ keys** |
| External engines integrated (subfinder, amass, dnsx, httpx, nmap, masscan, naabu, katana, gau, wayback/CDX/CC/OTX, webanalyze, nuclei, x8, arjun, kxss, gf, playwright) | ~17 |
| Proxy integrations (Burp / Caido / ZAP) | **0** |
| OOB/Collaborator support (interactsh-class) | 0 |
| HAR / raw request-response evidence store | 0 |
| Scheduling / monitoring / notifications | partial (resume flag only) |

---

## 2. Stage-by-stage grade (canonical 12-stage workflow)

| # | Stage | DeepBug coverage | Grade |
|---|---|---|---|
| 1 | **Scope parsing** | Per-project ScopeManager (exact/wildcard/exclusions), enforced at save time | 🟢 A− |
| 2 | **Asset/subdomain discovery** | subfinder+amass+CT+permutations, GitHub subdomains, ASN/DNS OSINT, dorking, vhost fuzzer, cloud enum | 🟢 A |
| 3 | **DNS resolution & alive filtering** | dnsx resolve + httpx alive, wildcard filter | 🟢 B+ |
| 4 | **Port & service discovery** | nmap/masscan/naabu + webanalyze fingerprinting | 🟢 B+ |
| 5 | **Crawling & URL harvest** | katana crawl, CDX/CommonCrawl/OTX archives, URL cleaner, shadow API, websocket discovery | 🟢 A− |
| 6 | **JS analysis & endpoint extraction** | JSAnalyzer v3.7 (endpoints, secrets, source maps with unpack evidence, PP, DOM clobbering, postMessage, JSONP, CSP gadgets, frameworks; v3.7 adds proactive Next.js build-manifest discovery + App Router flight/server-action inventory and Vite/Rollup manifest/dynamic-import chunk coverage) + GF secret scanner + validators | 🟢 A+ |
| 7 | **Parameter discovery** | x8 / arjun / paramspider + built-in fuzzer + historical params | 🟢 A− |
| 8 | **Vulnerability scanning (DAST)** | nuclei + 20+ focused scanners (GF families, kxss, CSTI/SSTI, SQLi, XXE, SSRF+validator, IDOR/BOLA, JWT, 403-bypass, mass assignment, GraphQL suite, open redirect, config exposure, git disclosure, cache… ) | 🟢 A |
| 9 | **Manual validation & exploitation** | **Proxy integration: none** · no Repeater/Replay · no OOB collaborator · no request crafting UI | 🔴 F |
| 10 | **FP triage & evidence** | Evidence redaction (Reporting), screenshots module, dashboard dedup | 🟡 C+ |
| 11 | **Reporting & submission** | HTML report from saved sections, redaction, AI assistance; missing CVSS calc, screenshots-in-report, per-program templates, markdown/HAR bundles | 🟡 C+ |
| 12 | **Cross-cutting ops** | one-click Full Recon pipeline; scope guardrails; atomic persistence; missing: asset store/dedup across runs, scheduling + diffing, notifications, secrets vault, team collaboration | 🟡 C |

**Overall: ~70% of the end-to-end loop.** The tool is already **top-tier in recon/scan
breadth** (stages 1–8) — ahead of most DIY setups. The **fatal gap is stage 9** (proxy /
manual validation loop) and the **evidence/HAR layer** that reports depend on.

---

## 3. Burp Suite integration — what's possible (researched)

| Capability | Feasible | Mechanism | Notes |
|---|---|---|---|
| **Send targets/hosts to Burp** | ✅ Easy | Burp **REST API** (Pro *and* Community ship the service; `Settings → Suite → REST API`, default `127.0.0.1:1337`) — auth is the **API key in the URL path**: `http://127.0.0.1:1337/<KEY>/v0.1/scan` | Scanner endpoints are **Pro-only** |
| **Retrieve Burp scan findings** | ✅ | `GET /v0.1/scan/{id}` → `issue_events[]` (name/path/**severity**) → import into a project as `burp_findings` | Poll until `scan_status: succeeded` |
| **Import Burp proxy history** (items → our URL pool / param mining / JS analysis) | ✅ | (a) manual: Burp **"Save items"** XML/JSON → import page; (b) **Doyensec `burp-rest-api` extension** → `GET /burp/proxy/history` (JSON, `API-KEY:` header) | Extension on GitHub (`vmware/burp-rest-api`) |
| **Live traffic feed** | ✅ | **Montoya API** custom extension (Java): `proxy().history()`, `http().registerHttpHandler()`, embedded HTTP server → push requests to DeepBug ingest endpoint | Official API, EULA-permitted interop |
| **DeepBug checks → Burp** | 🟡 | **BChecks** DSL (plain-text `.bcheck`, runs inside Burp Scanner/DAST — no standalone CLI); Sprocket-style conversion of nuclei/our templates | Pro/DAST only; good for *distribution* of our technique knowledge |
| **Headless Burp in CI** | ⛔ **Licensing wall** | Pro EULA **2.3(e)(iii) prohibits Pro in CI/CD pipelines**; sanctioned path = Burp Suite **DAST** (Docker, JUnit/XML) | Document this constraint in the UI |
| Python SDK | — | No official one; community: `burpa`, Patrowl engine; our connector would be plain HTTP | ✅ |

**Recommended integration shape (P1):**
1. **Burp connector page** (`/settings` or `7_Burp.py`): host:port + API key → "Send live hosts to Burp scan", "Import Burp findings" (`burp_findings` → Dashboard/Reporting), and "Import proxy history" (via extension or file upload).
2. Respect the EULA: run scans through the user's own GUI-attached Burp, not a CI farm; show a one-time license notice.

---

## 4. Caido integration — what's possible (researched)

| Capability | Feasible | Mechanism | Notes |
|---|---|---|---|
| **Import requests into Caido** (our endpoints → Replay) | ✅ | **GraphQL** `createReplaySession` (host/port/TLS/SNI + base64 raw request) + `startReplayTask` | Community **Python SDK `caido-sdk-client`** (PyPI, MIT) — full integration is free |
| **Pull Caido proxy history** (their traffic → our scanners) | ✅ | GraphQL `request.list` / `request.get` (HTTPQL filters, raw bytes) | Free tier OK |
| **Auth** | ✅ | **Personal Access Token** (`caido_…`, Dashboard → Developer) → `Authorization: Bearer`; ~7-day access + refresh | Device flow alternative |
| **Caido → DeepBug (workflows calling our tools)** | 🟡 | Workflow **Shell nodes** run arbitrary commands (stdin base64 JSON) → could call a future DeepBug CLI | Needs a headless CLI mode |
| **AI assistant driving Caido** | 🟡 | Community **`caido-mcp-server`** → our AI page could gain an MCP client | Nice-to-have |
| **Licensing** | ✅ | **Basic tier free forever**: 2 projects, 7 workflows, 3 plugins — sufficient for the connector | "Export current rows" is paid; GraphQL export is free |

**Recommended integration shape (P1):** `caido_connector.py` (Python SDK, configurable base URL + PAT):
- "Send N collected endpoints → Caido Replay sessions"
- "Import Caido history → param mining / JS analysis / URL pool"
- Optional: "Run Caido workflow" via `startReplayTask` preprocessor.

---

## 5. The quantified gap list (priority-ordered)

### P0 — without these the tool is not end-to-end
1. **Proxy/evidence loop (Burp + Caido connectors)** — see sections 3–4. Also a generic **request/response store**: capture HAR/curl/request pairs during scans (nuclei already emits `Curl_Command`; validators have evidence) → save as evidence artifacts per finding.
2. **OOB / Collaborator support** — interactsh-class integration (self-hosted `interactsh-client` or `oast.me`/`interactsh.com`): blind SSRF / blind XSS / blind XXE confirmation + automated canary detection in `ssrf_scanner`, `xxe_scanner`, `open_redirect` (they currently rely on in-band signals).

### P1 — what veterans expect
3. **One-command full run + asset store** — unify "Full Recon" into a pipeline with a persistent per-project **asset store** (dedup across runs, `assets.jsonl`-style), resume-on-failure, and **diff/incremental mode**.
4. **Monitoring & notifications** — scheduled re-scan (config interval) + `notify`-style push (Slack/Discord/Telegram webhooks) for new hosts/findings.
5. **Reporting upgrade** — CVSS 3.1 calculator (quick reference exists in docs), screenshots embedded in reports, HAR evidence bundling, per-program markdown templates, duplicates-check linkouts.
6. **ffuf-style fuzzing UI** (config has `ffuf` path; not wired) — wordlist-based fuzzing of discovered endpoints.

### P2 — beginner & expert polish
7. **Beginner guardrails**: rate-limit defaults per tool, scope confirm dialogs, "what is this scan?" tooltips per tab, safe-harbor/program-policy reminders, curated demo target (already have `acme` seed project) + lab guidance.
8. **Expert ergonomics**: raw request editor (curl/HTTP → send), response viewer, follow-up AI triage on findings with one-click "ask AI", per-program notes & disclosure deadlines.
9. **Program scope sync**: import scopes from `bounty-targets-data` / HackerOne / Intigriti / YesWeHack feeds (Caido's `h1caido`/`yeswecaido` plugins are a model).
10. **Secrets management UI** (API keys per program) — currently only `config.json`.

---

## 6. Bottom line

- **Do we have enough to get there? Yes.** The scanner layer (62 modules, stages 1–8)
  is the hard part and it's done. The remaining work is **~4–6 weeks of focused feature
  work**, dominated by the proxy connectors (P0-1), the evidence/HAR store (P0-2/P1-5),
  and the ops layer (P1-3/4).
- **Burp**: real integration is possible and license-safe if done user-driven
  (REST API + Doyensec extension for history; **no CI/CD Pro**).
- **Caido**: the cleanest path — free-tier GraphQL + Python SDK, two-way.
- **Beginner/expert**: the beginner path needs guardrails + guided flows (P2-7);
  experts will adopt it once the proxy loop closes.

_Next suggested sprint: P0-1 proxy connectors + HAR evidence store → P1-5 reporting
upgrade → P1-3/4 pipeline & monitoring._
