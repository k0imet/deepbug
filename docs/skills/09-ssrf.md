# 09 · SSRF (207 reports · 75 High+Crit)

## What it is
Server-side request where the URL/route is attacker-chosen → reach internal
services, cloud metadata (169.254.169.254), other tenants, or run limited proxies.

## Attack surface
- URL params: `url, uri, image, img, src, fetch, proxy, load, link, webhook, callback, avatar, file, download, render`
- File uploads by URL, PDF/image rendering, webhooks, import/export, GraphQL resolvers
- Proxy/converter services, "unfurl" previews, DNS exfil for blind

## Real-world technique language
- "SSRF … access to metadata server on AWS" (169.254.169.254)
- "Internal Docker API without Auth", "internal Solr Query Injection enabling LFI"
- "XXE → SSRF, service enumeration, blind file reads"
- "TURN server allows TCP/UDP proxying to internal network … metadata services"
- "CSRF → HTTP SSRF any private ip:port"

## Severity drivers
- Access to metadata/container internals → Critical (credential theft)
- Internal service reach (Redis/ES/Docker API) → High
- Blind SSRF with no impact shown → Medium (still worth OOB-proofing)

## DeepBug coverage
- `ssrf_validator` with **webhook.site OOB → CONFIRMED (oob-callback)** (proven)
- `ssrf_scanner` heuristics; GF ssrf category; 169.254.169.254 refs flagged in JS

## Gaps → modules
- Protocol/redirect chain awareness (HTTP→HTTP, `@`/`#`/`%0d` bypass corpus)
- DNS-rebind-safe OOB batch (multiple canaries in one run)
- GraphQL-arg SSRF probing (entrypoint args that fetch URLs)
- Auto-map internal service reach (JS→internal host → SSRF payload on that host)
