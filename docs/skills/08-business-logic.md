# 08 · Business Logic (300 reports · 49 High+Crit)

## What it is
Flaws in rules that "shouldn't happen" if math/state were enforced: race conditions,
double-spending, negative/float quantities, price manipulation, quantity controls,
signup/email-confirm bypasses, coupon TOCTOU.

## Attack surface
- Payments (double payout, negative qty, price override), points/balance
- Coupon/promo/voucher redeem (validate→create races = TOCTOU)
- Email/phone confirmation bypass → take over any account/store
- Cart/order state machines, multipliers, loyalty, referral abuse
- Rarely detectable by pattern — needs the FLOW to be understood (multi-step, two accounts)

## Real-world technique language
- "Race condition leads to memory disclosure", "Ethereum account balance manipulation"
- "Double Payout via PayPal", "Items bought for free due to lacks of quantity controls"
- "OLO Total price manipulation using negative quantities"
- "Bypassing partner email confirmation to take over any store"
- "SDX orderbook invalid state … trade at arbitrary price"

## Severity drivers
- Any monetary impact (free items, double payout, price override) → High/Critical
- Confirmation bypass → High

## DeepBug coverage
- `race_scanner` module exists (burst re-send) — not wired into any targeted flow
- `live_rest_validator` baseline-diff helps spot price/count changes but is not logic-aware

## Gaps → modules
- **Flow engine**: scripted multi-step templates with variable extraction and
  two-account differentials (A creates, B consumes) — the highest-leverage build for this class
- `balance_oracle`: re-run flow N times, detect non-idempotent state (double-spend,
  unlimited coupon)
- Signup/confirm-bypass checklist (enumerate email/phone confirm steps)
