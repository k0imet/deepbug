# 03 · Cross-Site Scripting (1,737 reports · largest single class)

## What it is
Attacker-controlled input rendered as script. Reflected, stored, DOM — plus the
client-side sink chain (DOM clobbering → XSS, prototype pollution → XSS).

## Attack surface
- Search/error/redirect reflections (reflected)
- Comments/profiles/snippets/files (stored, incl. upload filename/meta)
- `location.hash/search`, `postMessage`, `innerHTML/document.write` chains (DOM)
- JSONP, JS bundling (template literals), CSP bypass via gadgets (angular, trusted-types)

## Real-world technique language (recognize in reports)
- DOM clobbering → XSS ("Clobbering a global variable", config objects, `window.config.apiUrl`)
- Prototype pollution → XSS (merge sinks + innerHTML)
- CSP bypass: `strict-dynamic` with a loaded script, `unsafe-inline` via a gadget
- MIME sniffing / non-`nosniff` reflected content
- Stored XSS in admin-facing fields (agent consoles, dashboards) — higher impact

## Severity drivers
- Stored XSS in an admin/agent context → High/Critical
- Reflected without auth bypass → Medium
- DOM XSS in a first-party bundle with a sink — often accepted at Medium/High depending on impact

## DeepBug coverage
- `dom_xss_validator` — CONFIRMED innerHTML sink via hash (proven in lab)
- `pp_validator` — prototype pollution → browser proof
- GF xss candidates + `kxss_scanner` for reflected
- postMessage("*") detection + DOM clobbering statics from JS analysis

## Gaps → modules
- DOM XSS validation via **postMessage** delivery (validator supports it; exercise it)
- Stored-XSS trier: submit benign reflection probes into inputs, re-fetch, detect canary
- CSP bypass gadget checks (angular/vue/`trusted-types` absence)
- `nosniff`/MIME-sniff header audit folded into security-headers tab
