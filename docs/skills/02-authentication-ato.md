# 02 · Authentication / Account Takeover (1,149 reports · 234 High+Crit)

## What it is
Anything that lets an attacker become (or take over) another user's session/account:
broken auth flows, credential handling, session bugs, password reset abuse, OAuth/SAML misconfig.

## Attack surface
- Login/register/reset/verify flows (email, SMS, OTP), session cookies/JWTs
- Password reset: host-header poisoning, token in URL/leakable, no rate limit, user-enumeration
- OAuth/SAML/SSO: CSRF on callback, token in referer, state/Nonce missing, issuer confusion
- Session: fixation, no revocation, non-httponly cookie, JWT alg confusion, weak HMAC secret
- "Default password" / default admin creds left live
- Email change without re-verification → permanent ATO chain

## Subtypes (real distribution)
- Improper Authentication (generic): 522
- Violation of Secure Design Principles: 74
- Improper Restriction of Authentication Attempts (no rate limit): 63
- CSRF (on password change etc.): 45 · Info Disclosure: 44

## PoC patterns (real report titles → what to reproduce)
- "Authentication Bypass via Path Normalization (Double Slash)" — request the same route, different casing/slash
- "Session Created for Admin Account with Any Password" — authorize by username only, ignore password
- "SAML Authentication Bypass Leading To Unauthenticated Admin Takeover"
- "Full Account Takeover" via email change / password reset poisoning / OAuth token leak
- "CSRF to change password leads to full account take over"
- "Leak OAuth token" — callback receives token, referenced in an active request
- "Malicious reinstallation of widget app … extracting private oauth tokens"
- "Unauthorised Admin Access Due to default Password"

## Severity drivers
- ATO of ANY account (esp. admin/internal) → Critical by default
- Password reset with host-header poisoning → High/Critical
- No rate limit on reset/verify + user enumeration → Medium-High (chainable)

## DeepBug coverage
- AuthSession (login flows) + `rest_validator` login-probe (SQLi/NoSQLi injection into email/password)
- `forgot_password_prober.py` exists — not yet wired/run in the benchmark
- JWT audit tab decodes/weak-cracks tokens found in JS

## Gaps → modules
- `auth_bypass_prober`: path-normalization variants on login/logout, login-as-any-user (username-only), default-creds spot checks
- Reset-flow prober: host header swap, token-in-body vs header, response-diff user enumeration
- OAuth/SAML: callback CSRF + state/Nonce absence, token-in-referer check
- Session cookie flags audit per host (`HttpOnly`, `Secure`, `SameSite`) + fixation test
