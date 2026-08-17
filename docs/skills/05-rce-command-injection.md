# 05 · Remote Code Execution / Command Injection (395 reports · 227 High+Crit)

## What it is
Attacker-controlled input reaches a shell/expression/language runtime. The most
lucrative class in the dataset by High+Crit density — and the hardest to find
blind (most need auth or a specific param/format).

## Attack surface
- `cmd`, `exec`, `command`, `param`, `filename`, `path`, `dns`,
  `template`, `repo`, `branch`, `xml` (XSLT), `yaml`, `sql` (SSRF-adjacent)
- CSV/spreadsheet formula evaluation ("CSV expression evaluation → RCE")
- Deserialization surfaces (Java/Clojure/Python pickle/YAML — `!` tags)
- OGNL/Spring expression in headers/params (Confluence/Tesla cases)
- Template injection (SSTI): `{{7*7}}` → test in server-rendered templates
- Image/video/PDF processing (ImageMagick, ffmpeg, LibreOffice)
- Cron/at, port scans collapsing to internal RCE via SSRF

## Real-world technique language
- "CSV expression evaluation leads to backend RCE + Kubernetes serviceaccount token disclosure"
- "Command Injection via Unsanitized Filename"
- "RCE via Insecure Deserialization" (Java/Clojure YAML)
- "RCE via OGNL Injection" · "RCE … via HazelcastPort" (unauthenticated JGroups/Hazelcast)
- "Local File Inclusion … Possible RCE in Xamin Server"

## Severity drivers
- Anything named RCE → Critical (or High when authenticated/limited)
- Chain with token disclosure → Critical without auth

## DeepBug coverage
- GF `rce`/`ssti` candidate categories (URL-pattern only)
- `race_scanner`, `ssrf_validator` (SSRF→RCE chains partially covered)

## Gaps → modules
- `rce_prober`: bounded, safe probes (sleep/echo) on exec-y params —
  never `cat /etc/passwd` on unknown targets; report only state-changing evidence
- `ssti_prober`: `{{7*7}}` / `${7*7}`/`#{7*7}` matcher + template-context fingerprinting
- Deserialization hint scanner: walk JS/pages for YAML/Java deser gadgets (CVE tags)
- Upload→RCE check in file-security skill (11)
