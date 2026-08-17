# DeepBug — Bug-Hunting Skills Library

Mined from **11,304 real bug-bounty disclosures** (`docs/skills/_disclosure_catalog.js` —
Disclosure Index / Open Security Research Archive). Each skill doc answers:
what it is, the attack surface, the real-world subtypes, PoC patterns taken from
actual reports, severity drivers, DeepBug coverage, and the gaps to close.

Source dataset profile: HackerOne 9,991 · Bugcrowd 804 · Code4rena 410 ·
Immunefi 92 · severity: Medium 3,035 / Low 2,003 / High 1,569 / Critical 806.

## Skill index

| Skill | Reports | High+Crit | DeepBug coverage today |
|---|---|---|---|
| [01-access-control-idor](01-access-control-idor.md) | 1,359 | 407 | PARTIAL — session-aware IDOR pending |
| [02-authentication-ato](02-authentication-ato.md) | 1,149 | 234 | GAP — AuthSession landed, live tests next |
| [03-xss](03-xss.md) | 1,737 | ~25% | GOOD — DOM XSS validator + kxss |
| [04-information-disclosure](04-information-disclosure.md) | 1,119 | 177 | PARTIAL — JS secrets + corpus |
| [05-rce-command-injection](05-rce-command-injection.md) | 395 | 227 | GAP — no active RCE probes |
| [06-injection](06-injection.md) | 365 | 58 | PARTIAL — SQLi/NoSQLi battery |
| [07-csrf](07-csrf.md) | 309 | — | PARTIAL — form-encoded GraphQL check only |
| [08-business-logic](08-business-logic.md) | 300 | 49 | GAP — logic flaws need flows |
| [09-ssrf](09-ssrf.md) | 207 | 75 | GOOD — OOB webhook.site CONFIRMED |
| [10-sql-injection](10-sql-injection.md) | 171 | 101 | GOOD — REST battery |
| [11-file-security](11-file-security.md) | 173 | — | GAP — uploads untested |
| [12-request-smuggling](12-request-smuggling.md) | 54 | 21 | GAP — no desync engine |
| [13-subdomain-takeover](13-subdomain-takeover.md) | 52 | — | GOOD — dangling-CNAME checks |
| [14-xxe](14-xxe.md) | 22 | 19 | GAP — XXE scanner exists, not wired |
| [15-smart-contracts](15-smart-contracts.md) | 419 | — | OUT OF SCOPE (Code4rena) |

## Reading a skill doc

Every doc follows the same skeleton so they stay usable in the field:

```
1. What it is / where it lives        (attack surface)
2. Subtypes (real distribution)       (from the disclosure dataset)
3. PoC patterns (real titles)         (language to recognize when triaging)
4. Severity drivers                   (what turns P4 into P1)
5. DeepBug coverage                   (what already finds it)
6. Gaps → modules to build            (feeds docs/TOOLS_ROADMAP.md)
```

## Tooling

- `_disclosure_catalog.js` — the raw 11,304-report dataset (window.DISCLOSURE_REPORTS).
  Query it directly for program/class/weakness/severity research.
- See `docs/TOOLS_ROADMAP.md` for the module-by-module build plan derived from the gaps.
