# Caido ↔ DeepBug — End-to-End Workflow (replication guide)

This guide documents the complete, reproducible Caido integration flow used in
the DeepBug validation run. It is written so anyone can replicate it against
their own Caido instance and target.

```
┌─────────────┐  1. PAT     ┌──────────────┐
│   Caido     │◀────────────│   DeepBug    │
│ (GraphQL)   │             │ (Integrations│
│             │────────────▶│  page / CLI) │
│  Replay     │  2. push    └──────────────┘
│  sessions   │    3. run
│  + history  │────────────▶  4. pull history ──▶ caido_history results
└─────────────┘
```

---

## 0. Verified environment (the run this doc replicates)

| Component | Value |
|---|---|
| Caido | `caido-cli`, instance at `http://127.0.0.1:8080` (GraphQL at `/graphql`) |
| Caido schema | 2026 build — `createReplaySession` uses `requestSource.raw.connectionInfo` + `kind: "HTTP"`; `startReplayTask(sessionId: ID!)` (direct arg, no `input` wrapper); history via `requests(first: N)` with `filter` as an **HTTPQLInput object** (omit when unused) |
| DeepBug | `/home/user/deepbug`, client `app/modules/integrations/caido.py` (schema-matched v2, guest auto-auth) |
| Demo target | local test server `http://127.0.0.1:8765` (fully controlled, legal, reproducible) |
| Python | 3.13, httpx |
| **Live run result** | 4 replay sessions pushed (ids 6–13 across runs), 50 history rows pulled and saved as `caido_history` in project `caido-demo` |

---

## 1. Caido-side setup (one-time, ~1 minute)

1. **Start Caido** — instance must be reachable; verify:
   ```bash
   curl -s -X POST http://127.0.0.1:8080/graphql \
     -H "Content-Type: application/json" \
     -d '{"query":"{ __schema { queryType { name } } }"}'
   # → {"data":{"__schema":{"queryType":{"name":"QueryRoot"}}}}
   ```
2. **Create a Personal Access Token (PAT)** — in the Caido web UI:
   **Dashboard → Developer → Personal Access Token → Create**.
   Copy it (starts with `caido_`). DeepBug sends it as `Authorization: Bearer <PAT>`.
   > Mutations (`createReplaySession`, `startReplayTask`) and the history query
   > (`requests`) require a valid token — guest mode alone is NOT enough.
   >
   > **Guest auto-auth (recommended):** if no PAT is configured, DeepBug's client
   > automatically calls the public `loginAsGuest` mutation and uses the returned
   > access token — on instances with guest mode enabled the integration works
   > with **zero configuration**. (Verified live: push + history pull both worked
   > with the guest token; a manually-created PAT was rejected as `INVALID_TOKEN`
   > on this instance — if that happens to you, the guest path is the fallback.)
3. **(Optional) Manual-validation loop** — set your browser's proxy to the Caido
   instance port and browse the target so real traffic lands in Caido history;
   DeepBug can then pull it (`caido_history`) and feed it to scans.

## 2. DeepBug-side configuration

```bash
# Option A — env var (recommended for CLI/automation)
export CAIDO_PAT="caido_..."
# Option B — app/modules/config.json → integrations.caido.pat
# Option C — Integrations page UI (session-only)
```
Base URL default `http://127.0.0.1:8080` (config `integrations.caido.base_url`).

## 3. The flow DeepBug executes (what to replicate)

### 3.1 Push: endpoints → Caido Replay
Input: collected URLs (live hosts, JS-discovered endpoints, archives).
For each URL the client:
1. builds a raw request:
   `GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n`
2. `createReplaySession(input: { kind: "HTTP", requestSource: { raw: { connectionInfo: { host, port, isTLS, SNI }, raw: <base64> } } })`
   → returns `session.id`
3. `startReplayTask(input: { sessionId })` → runs the request through Caido.

CLI equivalent (reproduce):
```bash
cd /home/user/deepbug && python3 - <<'PY'
import sys; sys.path.insert(0, '/home/user/deepbug')
from app.modules.integrations.caido import CaidoClient
cc = CaidoClient("http://127.0.0.1:8080", pat="caido_...")
ids = cc.import_replay_sessions([
    "http://127.0.0.1:8765/",
    "http://127.0.0.1:8765/api/search?q=test",
    "http://127.0.0.1:8765/admin",
])
print("created sessions:", ids)
PY
```

### 3.2 Pull: Caido history → DeepBug project
`requests(first: N) { nodes { id host method path query isTls port } }`
→ normalized rows `{url, method, status, id}` (URL rebuilt from host/port/path/query)
→ saved as `<project>/<target>/caido_history_results.json` (shows on
Dashboard/Reporting and feeds the Vulnerability Detection tab).

### 3.3 Verify
- Caido UI → **Replay** shows the sessions (name "DeepBug import N").
- DeepBug → Integrations → Caido → *Import Caido proxy history* → table of
  pulled requests; then Recon → GF scan uses them.

---

## 4. Running it from the UI (manual replication)

1. DeepBug → **Integrations** → Caido: base URL + PAT → *Test connection* (green).
2. Pick the project target → **Send endpoints to Caido Replay** (dedupes live
   hosts + JS endpoints; status line shows session count).
3. **Import Caido proxy history** (limit e.g. 200) → saved as `caido_history`.
4. Open **Recon → Vulnerability Detection** — the pulled URLs are now part of
   the scan pool.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `health()` false but Caido is up | old client schema — this doc's v2 client uses introspection; update the file |
| `Operation error` / INVALID_TOKEN with a PAT | PAT rejected on this instance — the client falls back to guest auto-login; or create a fresh PAT in Caido |
| `Field "error" ... must have a selection of subfields` | schema drift — `error { __typename }` in mutations (already in v2 client) |
| `Expected input type "HTTPQLInput"` on history | `filter` is an object, not a string — v2 client omits it when empty |
| `Unknown argument "input"` on startReplayTask | schema uses `startReplayTask(sessionId: ID!)` direct arg (v2 client matches) |
| history empty | history reads are authed (PAT/guest token); also check you sent requests first (Replay or proxy browsing) |
| port/SNI wrong on imported sessions | client derives them from the URL (tls = https, sni = host, port default 80/443) |

---

## 6. Demo target

The replicated run used the local test server (127.0.0.1:8765) — endpoints `/`,
`/api/search?q=test`, `/admin` (403), `/api/items?id=1`, `/xml`, `/redirect?url=…`.
The same flow works unchanged for any in-scope program target: swap the URL list.
