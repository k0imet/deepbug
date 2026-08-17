# 12 · HTTP Request Smuggling / Desync (54 reports · 21 High+Crit)

## What it is
Front-end and back-end disagree on request boundaries (CL/TE or TE/TE). Smuggled
requests bypass front-end auth/WAF → poison caches, hijack sessions, desync
other users' requests.

## Attack surface
- Any CL→TE discrepancy beyond the proxy — most commonly products with
  different parser quirks (Apache, nginx, Tornado, Go, Node, Cloudflare-fronted)
- Use "smuggling beats WAF/auth" to turn otherwise closed endpoints into open ones
- Cache poisoning via a smuggled request fragment

## Real-world technique language
- "HTTP Desync Attack — Mass Session Hijacking"
- "Request smuggling … using malformed Transfer-Encoding header"
- "HTTP Desync attack … web cache poisoning"
- CL.0 / TE.CL / TE.TE variants (the field day: 2023-2025)

## Severity drivers
- Mass session hijacking / cache poisoning → Critical
- WAF bypass to a normally-gated endpoint → High

## DeepBug coverage
- None active (no desync engine). `http` fingerprinting exists in recon.

## Gaps → modules
- `smuggle_probe`: differential CL/TE timing probes per host+path (canary timing),
  then a two-request CL.TE demo; report parser fingerprint + PoC request pair
- Add parser fingerprinting (server banner → known-desync CVE map)
- Hook into scope-aware "cache poisoning" follow-ups when a cache layer is detected
