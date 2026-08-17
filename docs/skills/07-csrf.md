# 07 · CSRF (309 reports)

## What it is
State-changing requests that don't require proof of intent (no token, no SameSite,
form-encoded JSON accepted from cross-origin). Weapon: a victim's browser sends the
request with their session.

## Attack surface
- Password/email change, 2FA disable, transfer/webhook, admin actions
- JSON endpoints that ALSO accept form-encoded (`Content-Type: application/x-www-form-urlencoded`)
  → classic CSRF vector (like the GraphQL form-encoded probe we already run)
- `SameSite=None` + missing token; GET-based mutations

## Real-world technique language
- "CSRF to change password leads to full account take over"
- "CSRF Bypass — /plugins/servlet/oauth/consumer-info" (CVE classes)
- OAuth callback CSRF (state missing) → token binding

## Severity drivers
- CSRF on privileged actions (password/email/transfer) → High
- CSRF on settings/profile → Medium

## DeepBug coverage
- GraphQL scanner flags form-encoded operations (CSRF-able) on GraphQL only
- No general CSRF prober yet

## Gaps → modules
- `csrf_prober`: for each POST/PUT/PATCH endpoint — no CSRF token in body/header,
  `SameSite` absent/None, form-encoded accepted → candidate; store with a
  PoC HTML snippet per finding
