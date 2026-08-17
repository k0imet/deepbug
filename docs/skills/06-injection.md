# 06 · Injection (General: CRLF, header, resource, template) (365 reports · 58 High+Crit)

## What it is
The catch-all for payloads that shape server behavior — HTTP header/CRLF injection,
response splitting, template/resource injection, email header injection, log injection.

## Attack surface
- Redirect/`next` params, `Host`/`Referer` in password resets (header injection → cache poisoning / ATO)
- Response-splitting via CRLF (`%0d%0a`) in params echoed into headers
- Email injection (`To:`/`Bcc:`/`Subject:` in contact forms)
- Template engines, LDAP/XPath/XQuery, command substitution in filenames
- Open redirects (11 within this class) — the freevisit `/redirect/?g=` case

## Real-world technique language
- "CRLF Injection", "HTTP Response Splitting", "Header Injection"
- "HTML injection" in rendered content
- "Host header injection" (password-reset poisoning)
- "Open Redirect" (query on display)

## Severity drivers
- CRLF → cache poisoning/session fix → Medium-High
- Header injection in password reset → High (ATO)
- Open redirect alone → Low/Medium (useful as a chain link)

## DeepBug coverage
- `open_redirect_validator` + scanner (now with `g`,`r`,`l`,`to` params + OOB)
- REST battery covers SQLi/NoSQLi; CRLF/header not yet probed

## Gaps → modules
- `header_inject_prober`: inject `%0d%0aX-Test: canary` into echo-y params; confirm in response headers
- `host_header_prober` (exists as module — wire into reset-flow tests)
- Email-injection probe on contact/support forms
