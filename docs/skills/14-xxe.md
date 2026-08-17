# 14 · XXE (22 reports · 19 High+Crit)

## What it is
XML parser resolves external entities → file read, SSRF, internal service
enumeration, blind exfil via OOB.

## Attack surface
- Any XML-accepting endpoint: SOAP, GraphQL (XML transport), file upload (.xml, .xlf),
  fonts (SVG), document converters, RSS/Atom imports, database exports
- `Content-Type: application/xml` switch on JSON endpoints is a classic
  (parser accepts both → weak validation)

## Real-world technique language
- "XXE in upload file feature" · "Uploaded XLF files result in External Entity Execution"
- "XXE on …" (duckduckgo, starbucks case-insens: parse errors disclose internals)
- "Blind XXE on …" (OOB exfil)
- "Xml External Entity Injection … info dump"

## Severity drivers
- File read (any readable file) → High
- + SSRF/OOB to metadata → Critical
- Blind with OOB proof → Medium-High

## DeepBug coverage
- `xxe_scanner` module EXISTS — never wired into the active pipeline/benchmark

## Gaps → modules
- `xxe_probe`: for XML-accepting endpoints — `<!DOCTYPE x [<!ENTITY f SYSTEM "file:///etc/passwd">]>`
  (bounded: single probe), content-type switch on JSON endpoints, OOB to webhook.site
- Detect XML acceptance first (send `application/xml` + a probe doc, observe parser errors)
- Wire `xxe_scanner` heuristics into endpoint classification (upload/soap/graphql-xml)
