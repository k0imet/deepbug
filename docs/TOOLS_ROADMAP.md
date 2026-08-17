# DeepBug — Tools & Modules Roadmap

Derived from docs/skills/* gap analysis + the live-target lessons (freevisit,
Juice Shop, BitOasis, Redbull). Each row: module → why → effort.

## Tier 1 — highest value (close the "can't prove" gap)

| Module | Skill | Why | Effort |
|---|---|---|---|
| **Session-aware scans** (extend AuthSession into IDOR, GraphQL, REST battery, wayback) | 01, 02, 09 | Authenticated surface is where ~all High/Crit disclosures live | M |
| **Auth bypass oracle** (`auth_bypass_prober.py`: login with path-normalization, alternate endpoints, default creds spot-checks — POST only, bounded) | 02 | "Authentication Bypass via Path Normalization (Double Slash)", "Admin Takeover with Any Password", "SAML bypass" | M |
| **RCE probe kit** (`rce_prober.py`: safe sleep/echo probes on `cmd/exec/param` params + template markers) | 05 | RCE = highest bounty density (227/395 high+crit) | M |
| **Desync/smuggling engine** (`smuggle_probe.py`: TE:CL / CL:TE differential via two-request timing) | 12 | "Mass Session Hijacking" via desync | L |
| **XXE battery** (`xxe_probe.py`: XML-accepting endpoints, ENTITY payload, OOB to webhook.site) | 14 | 19/22 XXE were high/critical | S |
| **File-upload checklist** (`upload_probe.py`: extension/type bypass, content sniffing, path traversal in filename, image-magick/zip-slip) | 11 | "Uploaded XLF files result in External Entity Execution" | M |
| **Business-logic flow engine** (multi-step: register→login→action → detect balance/price/count manipulation) | 08 | Logic flaws are program-favorites and hugely under-covered | L |

## Tier 2 — broaden the net

| Module | Skill | Why | Effort |
|---|---|---|---|
| **CSRF prober** (`csrf_prober.py`: JSON/form endpoints, no CSRF token/samesite, form-encoded accepted → flagged) | 07 | 309 disclosures; cheap to check at validation time | S |
| **Info-disclosure sweeps** (directory listing, verbose errors, debug endpoints, source map probing `{bundle}.map`) | 04 | "Directory Listing", "Error Message" exposures are easy P4-P3 | S |
| **Subdomain takeover full matrix** (CDN/ELB/AppService/DO/Netlify/ghost/resend claimability) | 13 | 52 reports; the Redbull review showed real dangling CNAMEs | S |
| **GraphQL charge** (with AuthSession: introspection retry, clairvoyance on gated, mutation spraying, batching abuse) | 02, 09 | gated GraphQL = live API revealed | M |
| **WAF-aware engine** (on 403/challenge: backoff, UA/fingerprint rotation, mark host) | cross | BitOasis: full 403 wall with no tooling | M |

## Tier 3 — polish

| Module | Why | Effort |
|---|---|---|
| **Corpus-trained payload sets** (feed payloads from the disclosure titles + preview.is corpus into probe modules) | keeps payloads current | S |
| **Per-finding manual-verification snippet** (attach curl/step to every finding row) | triage speed | S |
| **CI for benchmark + auth_session + smuggling test suites** | regression safety | S |

## How to run the build

1. `01` — extend `scripts/test_auth_session.py` → two-session IDOR driving `idor_scanner`.
2. `02` — `auth_bypass_prober.py` (reuses AuthSession).
3. `05/12/14/11` — standalone probe kits sharing the baseline-diff pattern from `live_rest_validator`.
4. Cross-cutting: every module writes `*_results.json`, scope-filtered at save, evidence + verification snippet.
