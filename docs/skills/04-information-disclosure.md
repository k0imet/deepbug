# 04 · Information Disclosure (1,119 reports · 177 High+Crit)

## What it is
Sensitive data exposed to users who shouldn't see it — usually the POLITE version
of a much worse bug (leaked tokens/keys/headers/PII let you chain to RCE/ATO).

## Attack surface
- Error messages/stack traces, debug endpoints (`/actuator`, `/debug`, `/verbose`)
- Directory listing, backup/old files (`.bak`, `.sql`, `.env`, `.git`)
- API responses returning over-scoped fields (roles, tokens, hashes, internal IPs)
- Public buckets/CDNs, open Firebase/RTDB, exposed S3/GCS/Azure
- CORS misconfig leaking + cookies; verbose GraphQL errors (`Did you mean` — clairvoyance!)
- Source maps, `X-Powered-By`/debug headers, Swagger/OpenAPI, kubeconfig/cloud metadata

## Real-world technique language
- "Information exposure through directory listing / error message / debug information / sent data"
- "Missing encryption of sensitive data in transit/at rest"
- Leaked `Authorization`/`Set-Cookie` in bodies, tokens in referer, passwords in JWT payloads
  (Juice Shop literally put the MD5 password inside the admin JWT)

## Severity drivers
- Credentials/tokens/keys exposed → High/Critical (chain to ATO/RCE)
- PII exposure without auth → Medium-High
- Directory listing / banners → Low/Informational

## DeepBug coverage
- API-key corpus scanner (106 patterns, prefix-aware, keyhacks)
- $.env/, /actuator, git-disclosure, config-sensitive probes exist
- GraphQL error-leak → clairvoyance schema reconstruction
- JS secrets sanitized + FP-corpus

## Gaps → modules
- `banner_sweep`: security-header + stack-trace + verbose-error probes across live hosts
- Source-map probing (`{bundle}.map` — the Juice Shop miss)
- Bucket/keychain checks wired per project (RTDB/Firestore/GCS read-only)
- "Tokens in body/header/referer" scan over every collected response
