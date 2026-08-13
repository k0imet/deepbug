# DeepBug Integrations — Burp Suite, Caido & Evidence

The **Integrations** page (`/integrations`) closes the manual-validation loop: it
bridges DeepBug's automation with your interactive proxy and bundles request/
response evidence for reports.

```
DeepBug ──(send live hosts / endpoints)──▶ Burp REST API / Caido Replay
DeepBug ◀─(findings / proxy history)────── Burp / Caido
DeepBug ──(evidence.jsonl + HAR zip)─────▶ Reports
```

---

## 🔗 Burp Suite

### Setup (once)

1. Burp Suite (Pro or Community) → **Settings → Suite → REST API** → tick
   **Service running** (default `127.0.0.1:1337`).
2. Add an API key (copy it immediately — it's shown **once**).
   DeepBug calls the key-in-URL style: `http://127.0.0.1:1337/<KEY>/v0.1/scan`.
3. In DeepBug → **Integrations → Burp Suite**:
   - Base URL `http://127.0.0.1:1337` · API key (or `BURP_API_KEY` env).
   - *Test connection* → should show a green health check.

### What you can do

| Action | How | Saved as |
|---|---|---|
| Send project live hosts to a Burp scan | pick target → *Send live hosts to Burp scan* → poll status | `burp_findings` (per target) |
| Import Burp findings (name/path/severity) | *Check scan status* when `succeeded` | `burp_findings` |
| Import proxy history | upload a Burp **"Save items"** export (`.json`/`.xml`/`.burp`) | `burp_history` |
| Pull history via the Doyensec `burp-rest-api` extension | `BurpClient.fetch_proxy_history()` (extension at `github.com/vmware/burp-rest-api`, `API-KEY:` header) | `burp_history` |

> **Licensing**: Burp Suite Pro's EULA (clause 2.3(e)(iii)) prohibits using Pro in
> CI/CD pipelines. Use these connectors from your workstation (GUI-attached Burp).
> The scanning REST API endpoints are **Pro-only**; Community can still serve the
> API but has no scanner.

### BChecks

Your DeepBug technique knowledge can also live inside Burp: community + official
checks at `github.com/PortSwigger/BChecks` run inside Burp Scanner / DAST.
(Nuclei templates — incl. DeepBug's — are routinely converted to `.bcheck`.)

---

## 🕸️ Caido

### Setup (once)

1. Caido (free tier works for all of this) → **Dashboard → Developer** → create a
   **Personal Access Token** (`caido_…`).
2. In DeepBug → **Integrations → Caido**:
   - Base URL `http://127.0.0.1:8080` (or your instance) · PAT (or `CAIDO_PAT` env).
   - *Test connection* → green health check.

### What you can do

| Action | How | Saved as |
|---|---|---|
| Push collected endpoints into Caido Replay | pick target → *Send endpoints to Caido Replay* (live hosts + JS-discovered endpoints, deduped) | session ids in UI |
| Import Caido proxy history | *Import Caido proxy history* (limit 10–1000) → normalized URL/method/status | `caido_history` |

Free-tier limits: 2 projects, 7 workflows, 3 plugins — the GraphQL API + PAT work
unlimited. Caido workflows can also run your tools via **Shell nodes** (see
`docs/CAIDO` upstream) and the community `caido-mcp-server` exposes Caido to AI
assistants.

---

## 🧾 Evidence capture

- Scans persist **evidence** per finding to `<project>/<target>/evidence/evidence.jsonl`
  (request/response snippets, curl commands, extracted results, manual notes).
- The **Scanner** page captures up to 25 nuclei findings automatically.
- The **Reporting** page can attach an *Evidence* section to generated HTML
  reports (`🧾 Attach evidence bundle` checkbox).
- **Integrations → Evidence capture** exports a ZIP with `deepbug.har` (HAR 1.2),
  `manifest.json`, and per-target JSONL files.

### Manual notes

The Integrations page has a *Capture manual note* form — ideal for recording what
you validated by hand in Burp/Caido before it ends up in a report.

---

## Configuration (`app/modules/config.json` → `integrations`)

```json
"integrations": {
  "burp":  { "base_url": "http://127.0.0.1:1337", "api_key": "", "timeout": 30 },
  "caido": { "base_url": "http://127.0.0.1:8080",  "pat": "",     "timeout": 30 }
}
```
Environment overrides: `BURP_API_KEY`, `CAIDO_PAT`. Keys are never written to disk
by the UI (session-only).
