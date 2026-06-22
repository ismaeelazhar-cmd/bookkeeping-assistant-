# HMRC Making Tax Digital (MTD) — build vs. buy

This app already calculates VAT correctly in-app (per-transaction rate/direction, a VAT Control
Account, and a VAT Return report with Boxes 1/4/5/6/7 for any date range — see `VAT Return` in the
ledger UI). What it does **not** do is submit that return to HMRC directly. This doc evaluates
whether to build that, and recommends not doing it yet.

## What direct submission actually requires

Submitting a VAT return (or, from the ITSA side, quarterly income/expense updates) straight to
HMRC isn't just an API call — it's a formal vendor relationship:

1. **Register as a "recognised" MTD software vendor** via HMRC's Developer Hub. This means going
   through their application process, agreeing to their Terms of Use, and passing review of how
   the software handles VAT/ITSA data.
2. **OAuth 2.0 integration** against HMRC's Making Tax Digital API (VAT: `/organisations/vat/{vrn}/returns`;
   ITSA equivalents under the Income Tax API set), including building and maintaining the
   token refresh/consent flow per end user (each user authorises *your* application against
   *their* HMRC business tax account).
3. **Fraud prevention headers** — HMRC requires a specific set of HTTP headers on every API call
   (device ID, user agent, originating IP, etc., per their "Fraud Prevention Headers" spec) used
   to detect abuse. Missing or malformed headers get applications rejected or throttled.
4. **A sandbox-to-production promotion process** — build and test against HMRC's sandbox, request
   production credentials, and pass their pre-production checklist before going live for real
   filings.
5. **Ongoing compliance obligations** — MTD rules, header specs, and ITSA rollout phases change on
   HMRC's schedule, not yours; a recognised vendor has to track and respond to those.

None of this is a sprint task. It's closer to a multi-week project with an external approval gate
you don't control (HMRC's review timeline), and it creates an ongoing maintenance obligation that
outlives any single feature release.

## The pragmatic middle step (recommended now)

Ship what's already built — correct in-app VAT and Self Assessment estimate calculation — and let
the user file it themselves through:

- **HMRC's own online portal** (manual entry of the Box 1–9 figures this app already produces), or
- **Bridging software** (e.g. a simple CSV/spreadsheet bridge product) that takes calculated
  figures and submits them on the user's behalf — several free/cheap bridging tools exist
  specifically for software that doesn't have its own HMRC connection.

This is exactly the model many smaller accounting tools use before (or instead of) building full
MTD integration themselves.

## When to revisit

Worth building direct submission once there's evidence it's the actual blocker for users — i.e.
people are asking "why do I have to copy these numbers into HMRC's site/a bridge" often enough that
the multi-week build-plus-approval cost is clearly worth it. Until then, the in-app calculation is
the valuable 90%; the submission API is the expensive last 10%.
