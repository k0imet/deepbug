# 01 · Access Control / IDOR (1,359 reports · 407 High+Crit)

## What it is
The app enforces auth (you're logged in) but not authorization (WHO may touch WHAT).
The single most-reported serious class in the dataset — and one of the easiest to cash.

## Attack surface
- Object reads/writes keyed by attacker-controlled id/uid/uuid/key/order/param
- Mass endpoints (`/api/Users`, `/users/export`, `/download?id=`)
- Multi-tenant boundaries (A's tenant vs B's) — often only one tenant is tested
- Hidden params / BOLA beyond numeric ids (UUIDs, emails, bank accounts, filenames)
- Property-level: BOPLA — you can't read the object, but you can WRITE a field (`isActive`, `role`)

## Subtypes (real distribution)
- Improper Access Control (generic): 559
- Privilege Escalation: 315
- Insecure Direct Object Reference (IDOR): 238
- Improper Authorization: 37 · Improper Authentication: 20 · Info Disclosure: 16

## PoC patterns (real report titles → what to reproduce)
- "Unauthenticated Mass Data Extraction and Arbitrary Item Deletion"
- "IDOR … disclosing Username, Email, PIN, LastName, Address, PhoneNumbers" — enumerate sequential ids
- "HTTP Verb Tampering Leads to Authorization Bypass" — same path, different method (GET→POST→PUT→PATCH)
- "Access Control Bypass + LFI exposes /etc/passwd"
- "Broken Object Property Level Authorization" — write `isActive=true` on someone else's object
- "I can leak password of students … add myself as parent to any student" — horizontal + vertical in one
- "Privilege Escalation to any User Group / Account Status"

## Severity drivers
- PII/financial/protected data readable → High
- Write/delete on other users' objects, or full tenant break → Critical
- Object id guessable without kill-chain → still Medium/High depending on data

## DeepBug coverage
- `idor_scanner` exists but needs two pasted sessions — being replaced by AuthSession-driven two-account IDOR
- `replay_targets` surfaces /api/Users-style endpoints; GF flags `api` + `idor` categories

## Gaps → modules
- Two-session IDOR over all numeric/uuid params (AuthSession × 2)
- BOPLA write-probe: PUT/PATCH with an extra `role`/`isActive` field on foreign ids
- Verb-tampering pass (GET→PATCH) on authorization-gated paths
- Tenant-boundary scan: same request against tenant A + tenant B
