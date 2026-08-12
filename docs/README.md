# DeepBug Wiki

DeepBug is a Streamlit-based automated reconnaissance & bug-hunting platform. It
runs a 6-page workflow — Projects → Reconnaissance → Vulnerability Scanner →
Dashboard → Reporting → AI Assistant — and persists every scan result to disk as
JSON, with optional per-project bug-bounty scope enforcement.

## What this wiki covers

| Page | What it answers |
|------|-----------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Tech stack, app layout, 6-page flow, persistence model, scope manager, scanner output schema |
| [INSTALLATION.md](INSTALLATION.md) | Prerequisites, setup steps, optional tool installer, first-run checks |
| [CONFIGURATION.md](CONFIGURATION.md) | Every relevant section of `app/modules/config.json`, defaults, env vars |
| [AI-GUIDE.md](AI-GUIDE.md) | Bring-your-own-AI: OpenAI-compatible endpoints, providers, config examples, troubleshooting |
| [MODULES.md](MODULES.md) | The 8 Recon tabs, what runs under each, and the result save keys |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Common issues and fixes |

## Running DeepBug

From the repository root (`/home/user/deepbug`):

```bash
streamlit run deepbug_app.py
```

The main `deepbug_app.py` file is the single entrypoint: it sets up the Python
path, loads config, and builds the sidebar navigation (see ARCHITECTURE.md).

## Workflow order

1. **📂 Projects** — create/load/delete projects and review the scan overview.
2. **🔍 Reconnaissance** — subdomains, ports, JS analysis, vulnerability detection, cloud, params, headers, advanced scans (8 tabs).
3. **🛡️ Vulnerability Scanner** — run Nuclei against live hosts; results saved as `vulnerabilities`.
4. **📊 Dashboard** — key metrics, severity pie chart, per-target overview, recent activity.
5. **📄 Reporting** — select saved results and download a single HTML report.
6. **🤖 AI Assistant** — chat with any OpenAI-compatible endpoint and analyze saved results.

## Other docs

For install, usage and feature overview beyond this wiki, see the project's main
[`README.md`](../README.md) at the repository root.
