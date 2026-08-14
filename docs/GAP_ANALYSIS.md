# DeepBug — Brutal Gap Analysis (2026-08-14)

Every gap observed during real-lab and live-target validation, with the fix.
Severity = what it costs us in the field. Effort = rough implementation size.

---

## 1. DISCOVERY (the eyes) — misses mean we never see the bug

| # | Gap | Evidence (how we got burned) | Fix | Sev / Effort |
|---|---|---|---|---|
| 1.1 | **Single-letter / short params not covered** in redirect, SSRF, IDOR, GF param lists | freevisit.ru `/redirect/?g=` → 302 verbatim; scanner + validator found 0 until `g` was added | Unified param registry (`app/modules/tools/param_registry.py`) shared by every scanner; seed with g,r,l,to,go,next,ref,u,url2,return… | HIGH / S |
| 1.2 | **String-concatenation / builder-API URLs** still missed | `host + "/api/" + id` builds: only `${}` templates are handled | Concatenation-aware extraction (chase `"a"+"b"` chains; record `fmt.Sprintf`/`sprintf`/`format` patterns) | MED / M |
| 1.3 | **Call-site methods lost**: Angular `this.http.get/post` not captured (only fetch/axios/jquery/xhr) | Juice Shop `this.http.get(\`…\`)` came out method=GET, template — no POST/auth hints | Add `http.(get|post|put|delete)` regex; merge method+auth hints into the template pass | MED / S |
| 1.4 | **Served-but-unreferenced `.map` files** not probed | Juice Shop `main.js.map` 200 but bundle had no `sourceMappingURL` | Probe `{bundle}.map` for every found JS file (cheap, big win) | MED / S |
| 1.5 | **Query params dropped from extracted endpoints** | `search?q=${…}` now kept, but ordinary `?a=1&b=2` URLs from HTML/markup still stripped in places | Normalize: keep query strings for API-ish paths; mark params for validators | MED / M |
| 1.6 | **GF only scans URL strings**, not bodies/responses | Body-based SQLi/SSRF/reflection detection absent (kxss is the only body-aware tool) | Add a `body_scanner` pass: fetch candidate URLs once, run pattern sets over responses (bounded) | MED / M |
| 1.7 | **Source-map content never unpacked into endpoints/secrets** | `unpack_sourcemap` exists; results only flagged, content unused | Feed unpacked sources through the full endpoint+secret pipeline | LOW / M |
| 1.8 | **Single-page-app route catalog incomplete** for frameworks beyond React/Angular | Vue/Svelte/Ember route syntaxes unverified | Add Vue router + SvelteKit patterns; unit-test against framework bundles | LOW / S |

## 2. VALIDATION (the hands) — we find surface but can't prove

| # | Gap | Evidence | Fix | Sev / Effort |
|---|---|---|---|---|
| 2.1 | **No session/cookie/token management — THE big one** | Juice Shop IDOR/2FA, DVGA mutations, WebGoat GraphQL, crAPI flows: all blocked on auth | `AuthSession` manager: login once (form/JSON/OAuth), persist cookies+Bearer, inject into every validator; "authenticated run" mode | **CRITICAL** / L |
| 2.2 | **No multi-step business flows** | register→login→authorized-call chains untestable; mass assignment only provable manually | Flow engine: `steps:[{req},…]` templates with variable extraction (token from login) | HIGH / M |
| 2.3 | **JWT live testing absent** | Juice Shop token contained the password hash + alg=none forgeable; `jwt_scanner` only audits JS-embedded tokens | `jwt_live`: given a token → decode, check alg/header confusion, weak-HMAC crack, expiry/scope tests | HIGH / S |
| 2.4 | **Blind SQLi unsupported** (only error-based + status diff) | Lab/signature-only evidence; time/boolean oracle detection missing | Add time-delay (`SLEEP`/`pg_sleep`) + boolean-diff probes, rate-limit-safe | MED / M |
| 2.5 | **OOB works but is config-only** | webhook.site works (CONFIRMED oob-callback) yet needs manual UUID + env var | `oob.py` helper: create token on demand, manage per-run canaries, surface in UI; keep API-key per user | MED / S |
| 2.6 | **XXE / deserialization / command-injection / upload validators not wired** | Modules exist (`xxe_scanner`, `race_scanner`…) but nothing auto-runs them on the right endpoints | Route by endpoint class: XML-accepting → XXE; `?cmd=`/`exec` → cmd-inj; multipart → upload probes | MED / M |
| 2.7 | **IDOR scanner = manual two-session paste** | No account lifecycle automation | Pair with 2.1/2.2: register 2 accounts, drive both sessions automatically | MED / M |
| 2.8 | **Auth-gated GraphQL detected but never tested** | `gated_auth` class exists; nothing consumes it | With 2.1: attach session, retry introspection + clairvoyance + mutations | MED / M |
| 2.9 | **Rate-limit / brute-force checks manual** | `rate_limit_tester` exists, unintegrated | Add to "Full validation" run for auth + reset endpoints | LOW / S |

## 3. PIPELINE (the flow) — results never chain

| # | Gap | Evidence | Fix | Sev / Effort |
|---|---|---|---|---|
| 3.1 | **No "Full validation" orchestration** | After JS analysis, nothing auto-runs nuclei + validators + JWT + GF on the new surface | `validation_run.py`: analysis → scope-filter → nuclei(high-sev templates) → REST battery → OOB SSRF/redirect → JWT live → save+render | **HIGH** / M |
| 3.2 | **Nuclei never re-filtered at scan time until today** | FIXED (2_Scanner gate) — but not auto-chained | Covered by 3.1 | — |
| 3.3 | **Evidence export ignores scope** | Old evidence exported unfiltered | Re-filter bundles at export time | LOW / S |
| 3.4 | **Validators don't re-run on new endpoints automatically** | New endpoints discovered → nobody validates until manual click | 3.1 + "validate new" delta tracker (hash endpoint sets, validate only new) | MED / M |
| 3.5 | **WAF/Cloudflare awareness absent** | BitOasis: everything 403 behind CF; no backoff/UA-rotation/detection | WAF detection module: on 403/challenge, mark host, slow down, rotate UA/fingerprint, report | MED / M |

## 4. INFRA & ENGINEERING (the friction)

| # | Gap | Evidence | Fix | Sev / Effort |
|---|---|---|---|---|
| 4.1 | **Labs not orchestrated; processes die** | Lab server died 3× (stale aiohttp responses); DVGA needed hand-toggling; crAPI/WebGoat auth fights | `scripts/lab_up.sh` (podman/docker + venv), health checks, `benchmark_labs.py --up` | MED / S |
| 4.2 | **No CI for the benchmark** | 13/13 is manual | GitHub Action: boot minimal lab set, run `benchmark_labs.py`, gate PRs | LOW / S |
| 4.3 | **Config sprawl** | Each validator owns a config namespace; no central `validation:` block | Central `validation:` config + UI page for validator tuning | LOW / M |
| 4.4 | **PortSwigger/WebGoat blocked on account auth** | Auth0 email-code + Spring CSRF friction | Documented manual bring-up (needs one human action); then sessions (2.1) unlock them | MED / S |
| 4.5 | **Playwright path resolution fragile** | Works on this box; breaks on fresh installs | `install_browser` helper + cache-bust | LOW / S |
| 4.6 | **No exploit-chain/evidence per finding** | Verdicts exist; no "how to verify manually" for non-confirmed items | Attach manual-verification curl/step to every finding row (corpus-assisted) | LOW / S |

## 5. REALISM (the freevisit lesson)

| # | Gap | Evidence | Fix | Sev / Effort |
|---|---|---|---|---|
| 5.1 | **Param-name coverage is the #1 live miss** | `g` cost us the freevisit find until manually added | 1.1 (param registry) + corpus-assisted param lists | HIGH / S |
| 5.2 | **Scheme-less canaries useless on strict targets** | freevisit ignores `g=canary.invalid` | Always emit `https://canary` variants FIRST (done in redirect validator; audit SSRF/others) | MED / S |
| 5.3 | **Real OOB is a hard requirement** | Blind SSRF unprovable without it | webhook.site integration (2.5) | HIGH / S |
| 5.4 | **Vendors block automation silently** | LiteSpeed/Akamai/CF variants behave differently per path | Per-host response profiling (redirect vs 200 vs challenge) before judging | MED / M |

---

## Priority roadmap (what I'd build next)

1. **AuthSession manager** (2.1) — unlocks IDOR/JWT/DVGA/WebGoat/crAPI; the single biggest lever.
2. **Full validation orchestration** (3.1) — turns findings into proven findings automatically.
3. **OOB first-class** (2.5) — one-click webhook.site token, in-UI canaries.
4. **Param registry + concat-extraction** (1.1/1.2) — closes the exact class of miss freevisit exposed.
5. **JWT live testing** (2.3) — cheap, high report value.
6. **Lab orchestration + CI** (4.1/4.2) — keeps the 13/13 suite honest.

## What is genuinely good (credit where due)
- Save-time scope chokepoint + run-time gates (this session)
- API-key corpus scanner, REST validation battery with baseline-diff
- GraphQL clairvoyance proven against DVGA hardened mode
- OOB webhook.site proofs (SSRF CONFIRMED class)
- Template-literal + SPA-route extraction fixes
- Benchmark suite: 13/13 ALL GREEN
