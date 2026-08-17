# 13 · Subdomain Takeover (52 reports)

## What it is
A domain's CNAME points at a cloud resource that no longer exists (or was never
provisioned) → an attacker re-registers it and controls the host. Classic:
Azure App Service name reuse, Heroku, Netlify, GitHub Pages, S3 buckets, ghost.io,
DigitalOcean, and stale CNAMEs to decommissioned load balancers.

## Attack surface
- Dangling CNAMEs from JS scans / CT logs (collect + resolve target)
- Claimability differs by provider:
  - Azuresites / herokuapp / netlify.app / ondigitalocean.app / ghost.io → **claimable**
  - ELB/ALB (`*.elb.amazonaws.com`) → **NOT claimable** (generated names) — don't report
  - Taskcluster/readthedocs/statuspage → provider-dependent
- Look for: unclaimed brand-hosted subdomains, expired registration pages on 2xx

## Real-world technique language
- "Subdomain takeover" at brand hosts (stripe, facebook-adjacent CTF cases)
- Verify with: `Host` resolves but target NXDOMAIN + provider takeover doc
- Proof: register the name on the provider and show control (if authorized)

## Severity drivers
- Full subdomain control (phishing, cookie theft on parent, TLS) → Medium-High
- No cookies on parent / no auth on sub → still Medium (internal tooling case)
- These are the "leave-no-stone-un" finds triage loves — low effort, easy dup-escaping angle

## DeepBug coverage
- `subdomain_takeovers_results` — dangling CNAME detection (Redbull run: 16 candidates)
- Claimability classifier built into the review workflow (ELB vs Azuresites)

## Gaps → modules
- Provider-claimability matrix (per CNAME suffix) rendered in the takeover table
- NXDOMAIN target re-check + "claimable" badge per row
- Watch list: auto re-check on a schedule (takeovers appear when infra is torn down)
