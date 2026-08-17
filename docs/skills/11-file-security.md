# 11 · File Security / Uploads (173 reports)

## What it is
Upload/download/parse of files as an attack channel: content-type/extension bypass,
path traversal in filenames, zip-slip, polyglots, SVG/XML parsers, image libs,
CSV formula injection, and XSS via file content.

## Attack surface
- Upload endpoints (avatar, import, attach, editor assets)
- Filename reflected into headers/paths (`../../`, `..%2f`, null bytes)
- `.html`/`.svg` upload → stored XSS; `.xml` → XXE; image → lib exploit
- ZIP/TAR extraction (zip-slip), XLF/CSV imports (entity/formula execution)
- Download endpoints with filename param → traversal

## Real-world technique language
- "Uploaded XLF files result in External Entity Execution" (XML)
- "XXE in upload file feature" · "XXE via JUnit Preview"
- "CSV expression evaluation → RCE" (formula injection)
- ImageMagick/polyglot gadget cases

## Severity drivers
- Stored XSS via upload, or upload→RCE/XXE → High/Critical
- Traversal read → High; write (webshell) → Critical (if reachable)

## DeepBug coverage
- Upload endpoints surface via JS/endpoint extraction; no active upload tester

## Gaps → modules
- `upload_probe`: minimal benign files as `image/png`, `.html`, `.svg`, `.xml`,
  `.txt` → check served content-type, stored-XSS reflection, XXE OOB
- `filename_traversal`: upload `..%2f..%2f<canary>`, download `?file=../../etc`
- `zip_slip`: upload archive with `../` entry, check extraction path
- CSV formula injection: upload `=HYPERLINK` / `=cmd` cell, check export
