# Bookkeeping Assistant

A multi-tenant double-entry bookkeeping web app: log in, create one or more companies, invite collaborators with scoped permissions, and post transactions that flow straight into live T-accounts, a trial balance, and generated financial statements — with VAT, invoicing, bank reconciliation, and an AI layer that reads your actual ledger rather than guessing at it.

## Core ledger

- Email/password login (PBKDF2-hashed, session-based) with optional **TOTP 2FA** (RFC 6238, works with any standard authenticator app), plus single-use, hashed **backup codes** issued on enabling 2FA so losing the authenticator device doesn't mean losing the account.
- Multi-company per user, fully isolated data per company. Invite collaborators by email with **view / comment / post** permission, enforced server-side on every mutating endpoint — not just hidden in the UI.
- A real **chart of accounts**: every account name is resolved through a case-insensitive-unique table, so "Cash" and "cash" can never silently fork into two accounts. Renaming an account cascades everywhere it's used; deleting one in use is blocked.
- Money is stored as **integer pence** internally — no floating-point drift on amounts. The JSON API still speaks pounds, so nothing about that is visible from outside.
- Soft-delete: "deleting" a transaction sets `voided_at`/`voided_by` rather than removing the row. Excluded from normal views, recoverable via `?includeVoided=1`, and every create/void is recorded in an **audit log**.
- **Period locking**: lock the books up to a date (e.g. after filing a VAT return) and nothing on or before that date can be added, edited, or deleted by anyone.
- **Opening balances** as a real table (not disguised transactions), feeding the trial balance, Statement of Financial Position, and a genuine brought-forward cash figure on the Cash Flow Statement.
- **Compound/split journals**: one payment or receipt split across several accounts, posted as linked entries sharing a `journal_id`.

## Movements & reconciliation

- **Live bank feed (Plaid)**: link a real bank account or card. This is the "buy don't build" Open Banking piece — actual connections go through Plaid's regulated infrastructure (the same approach Xero/FreeAgent use), not custom bank scraping. Transactions sync via cursor-based incremental sync straight into the same `bank_lines` the Bank Reconciliation screen already uses. A webhook gives real-time push updates once deployed somewhere reachable — every incoming webhook's signature is verified against Plaid's published key before it's trusted, not just accepted on POST — with a manual "Sync now" button covering local/sandbox use where Plaid's servers can't reach `localhost`. The access token is encrypted at rest with the same key used for the AI API key, and is never returned to the browser.
- **Movements Inbox**: drop a bank statement PDF or freeform text; keyword rules (or an AI pass) propose the debit/credit pair for review before posting. Every entry carries a `confidence` flag, surfaced as an "unreviewed" warning on any financial statement line built from it.
- **Bank Reconciliation**: import or paste a statement, match each line to a posted transaction or post a new one directly, with a running ledger-vs-statement balance check.
- **Receipt OCR**: attach a receipt/invoice (PDF/PNG/JPEG/HEIC/WEBP) to any transaction; Claude or Ollama (see AI integration below) reads the date/description/amount off it. The pre-transaction "scan a receipt" flow in Quick Entry auto-posts the transaction directly (and attaches the file) when a categorization rule or learned preset confidently identifies the accounts, instead of only ever pre-filling the form.
- **Categorization rules** ("Amazon always → Office Supplies") apply automatically across every entry point — bank feed sync, CSV import, and receipt scans — not just a settings list with no effect.

## Tax & compliance

- **VAT engine**: per-transaction rate and direction, automatic splitting into Net + VAT Control Account + Gross postings, and a VAT Return report (Boxes 1/4/5/6/7) for any date range.
- **Making Tax Digital (HMRC) submission**: OAuth connection, obligations check, and direct VAT-return submission via HMRC's API, with a **filing history** of what was actually submitted and HMRC's response. Submission itself is unverified against a real HMRC account — it needs the user's own application registered on HMRC's Developer Hub.
- **Mileage log**: logs a business trip and posts the HMRC-approved mileage claim (45p/25p taper at 10,000 miles, flat rates for motorcycle/bicycle) straight to the ledger.
- **CIS (Construction Industry Scheme)**: split-leg postings for CIS suffered/deducted at payment time, plus a per-subcontractor **Payment and Deduction Statement** view with a printable document.
- **Fixed asset register**: register an asset, run straight-line or reducing-balance depreciation per month as a normal ledger posting (flows into the P&L and reduces net book value automatically).

## Sales & purchases

- **Contacts** (customers/suppliers) and real **Invoices/Bills** with a draft → sent → paid lifecycle. Sending posts to Trade Receivables/Payables (with VAT if set); paying settles it. Deleting one voids its linked ledger postings rather than leaving orphans.
- **Invoice PDFs**: a real PDF (logo, business address, payment terms, bank details — all from Settings → Branding) generated with `fpdf2` (pure-Python, no system libraries), downloadable per invoice/bill and emailable as an attachment. Three template designs (classic/modern/minimal), picked per company.
- **Invoice status timeline**: drafted/sent/opened/paid timestamps per document — "opened" is stamped on the customer portal's first real visit, not just inferred.
- **Auto-chase cadence**: 3 days before due, due today, 7 days after, 14 days after — each stage fires once, with wording that matches what's actually happening (not a flat "overdue" message before the due date has even passed).
- **Customer payment portal**: every sent invoice gets an unguessable `/portal/<token>` link — a public, read-only page showing the invoice, with a "Pay now" button once Stripe keys are configured (falls back to read-only if not). Paying through Stripe Checkout auto-posts the payment and marks the invoice paid via a signature-verified webhook.
- **Aging report** bucketing outstanding invoices/bills by days overdue.

## Reporting & analysis

- Statement of Profit or Loss, Statement of Financial Position, and a Cash Flow Statement (IAS 7 direct method) — all generated from the ledger, not entered separately.
- **Ask Your Ledger**: ask a plain-English question ("how much did I spend on travel last quarter?") and get an answer computed from your actual transaction data, not a guess.
- **Anomaly flagging**: first-time account use and statistically unusual transaction amounts (z-score against that account's history), computed live, no AI required.
- **Click-to-explain drill-down**: every account in the trial balance and every line in the P&L/SOFP is clickable, showing the exact transactions behind the figure.
- Dashboard summary (cash position, outstanding receivables/payables, net profit) and a contextual help layer that explains *why* each Movements Inbox suggestion or bank-rec match happened, wired to real state rather than generic tooltips.

## Fund accounting & consolidation (opt-in)

- **Fund accounting**: off by default per company — turning it on changes nothing else about how that company works. When on: tag transactions with a fund (restricted/designated/unrestricted) and get a **Statement of Financial Activities** segmenting incoming resources and resources expended by fund type. Funds don't auto-create like accounts do; they need a deliberate type, so referencing an unknown fund is a hard error, not a guess.
- **Multi-entity consolidation**: group companies you own (e.g. a charity plus its trading subsidiary) and view a combined P&L/SOFP summary, aggregated across entities by matching account name. Balances in accounts named "Intercompany..."/"Due from/to..." are automatically eliminated between members (netted up to the matched amount, with any unmatched residual flagged) so a loan or trade balance between group members isn't double-counted — still no minority-interest handling, so it's not a substitute for a real consolidation engine on complex group structures.

## AI integration

Two providers, picked per company in Settings → AI Features:

- **Claude (Anthropic)**: the API key is **write-only** — once set, it's never serialized back to the browser in any API response, and the actual API call happens server-side (`server.py`'s `call_claude`), not from client-side JavaScript. Most accurate; paid per use.
- **Ollama (local, free)**: points at a self-hosted Ollama server (default `http://localhost:11434`), no API key or cost at all. Lower OCR/categorization accuracy than Claude, and **no PDF support** — only image receipts (photos/screenshots), since Ollama has no native document understanding the way Claude does; that limitation surfaces as a clear error rather than mis-reading a PDF as garbage.

Both go through one dispatcher (`call_ai`) so every AI feature works under either provider: Movements Inbox categorization, receipt OCR (including a pre-transaction "scan a receipt" flow in Quick Entry that auto-posts the transaction directly when a categorization rule/preset confidently matches), Ask Your Ledger (now a real multi-turn conversation, persisted per company in the browser), and an AI-generated month-end narrative (period-over-period deltas computed server-side; the model only writes them up, never computes the figures itself).

## Business health & automation

- **Business Health Score**: a single 0-100 dashboard number from four independent signals — cash runway (months), 90-day profit margin, % of receivables overdue, and days since the last closed bank reconciliation.
- **Missing-receipt detection**: flags expense/COGS postings over £20 with no attached receipt, in the same Anomalies panel as the existing duplicate-transaction and unusual-balance checks; extended to also catch duplicate bills/invoices (same contact + amount within 7 days).
- **Onboarding wizard**: business-type chart-of-accounts templates (retail/service/construction) and opening balances posted as real ledger entries, instead of a blank chart on day one.
- **Demo mode**: one click from the login screen, no signup — spins up a throwaway account and a pre-seeded "Riverside Plumbing & Heating" company with 6 months of sample transactions.
- **Quick entry mode**: a stripped-down transaction form (date/description/amount/category) for the common case, hiding VAT/FX/fund/department fields behind a toggle; posts against the company's default credit account automatically.
- **Cash flow what-if scenarios**: overlay a hypothetical amount/date on the existing Cash Flow Forecast without touching the real ledger.
- **Accountant collaboration**: a "comment" permission tier (between view and post) that can leave transaction comments and lock periods, but can't post or delete a transaction — for an invited accountant who needs more than view-only without full write access.

## Running locally

```bash
pip3 install --user -r requirements.txt
python3 server.py
```

Then open http://127.0.0.1:5050. Set `FLASK_DEBUG=0` to turn off Flask's debug mode (on by default for local dev).

## Running the tests

```bash
pip3 install --user -r requirements-dev.txt
python3 -m pytest
```

81 tests covering auth, the account-dedup fix, pence precision, period locking, soft-delete, the invoice/bill lifecycle, compound journals, permission enforcement, the full 2FA cycle (including backup-code recovery and regeneration), bank reconciliation, fixed assets, attachments, preset learning, fund accounting/SOFA math, multi-entity consolidation, the scheduled backup job, and the Plaid integration — including one test that makes a real network call to Plaid's sandbox with fake credentials (to prove the request is shaped correctly rather than just unit-testing in isolation) and tests that exercise genuinely-signed and tampered webhook payloads against a real EC key pair, not mocked verification logic. Each test run gets an isolated SQLite file — nothing touches your real `data.sqlite`.

## Deploying for real

This app is safe to run for personal/local use as-is. Putting it somewhere reachable from the internet needs three more things, none of which are optional:

**1. A production WSGI server, not Flask's dev server.**

```bash
pip3 install --user -r requirements-prod.txt
gunicorn -c gunicorn.conf.py server:app
```

`gunicorn.conf.py` binds to `127.0.0.1:5050` only (not `0.0.0.0`) — it's meant to sit behind a reverse proxy, not face the internet directly. Worker count is deliberately small; SQLite's single-writer lock is the real concurrency ceiling here, not Python's, so throwing more workers at it doesn't help past a point.

**2. A reverse proxy terminating HTTPS.** Nginx or Caddy in front, forwarding to `127.0.0.1:5050`, with a real TLS certificate (Let's Encrypt via certbot, or Caddy's automatic HTTPS). Without this, every password, session cookie, and AI API key on this app travels in plaintext over the network. This is the single most important thing missing for real-world use and it's infrastructure, not code — there's no way to fix it from inside `server.py`.

**3. Back up two files outside of normal application backups**: `.secret_key` and `.encryption_key`. Losing `.secret_key` just logs everyone out (regenerate and move on). Losing `.encryption_key` means every stored AI API key becomes permanently unreadable — `decrypt_secret()` will silently treat them as unset, and each company's owner will need to re-enter theirs. Neither file is ever committed (both gitignored) and neither is included in the JSON export (deliberately — an export is exactly the kind of file that ends up emailed or dropped in a shared folder).

Set the `SECRET_KEY` env var to hand the session secret to the app via your deploy platform's config instead of relying on the on-disk `.secret_key` file — it takes priority when set. `FLASK_HTTPS=1` is for *local* dev convenience only (a throwaway self-signed cert via Werkzeug's `ssl_context="adhoc"`, for testing anything that needs a secure context); it is not a substitute for #2 above and should never be set in production.

**4. Notifications run themselves — no cron job needed.** A daemon thread (`start_background_scheduler` in `server.py`) ticks every hour and runs the same digest/AR-chase check for every company, whether or not anyone opens the dashboard that day. The on-demand `POST /api/companies/<id>/run-notifications-check` (still triggered by the dashboard, and still useful for testing) and the scheduler share one function and the same dedupe table, with the dedupe row claimed *before* sending — so this stays correct even if you run more than one worker process. The one case this doesn't cover: if the whole app is down for an hour-plus stretch (host rebooting, etc.), the next tick after it comes back up catches up automatically since the dedupe is per-day, not per-tick.

**5. (Optional) A Stripe webhook, if using the customer payment portal.** In Settings → Get Paid Online → "Show advanced", there's a ready-to-copy webhook URL for your deployment's address. Add it as an endpoint in the Stripe Dashboard listening for `checkout.session.completed`, then paste the resulting signing secret back into that same section. Without this, a customer can still pay via the portal, but the invoice won't auto-mark-paid on this end — it'll need reconciling manually.

## Status

Hardened so far: persistent session secret, basic rate limiting on auth endpoints, CSRF protection (Origin/Referer validation on state-changing requests), AI API key encrypted at rest (separate key file from the session secret), server-side-only AI key handling (the key is write-only — never serialized back to the browser in any response), and **verified Plaid webhook signatures** (ES256 JWT per Plaid's documented scheme, checked against a cached JWK and a 5-minute replay window before any webhook payload is trusted). **2FA backup/recovery codes**: losing your authenticator device no longer means losing account access — 10 single-use, hashed-at-rest codes are issued when 2FA is enabled (shown once), consumed one at a time at login, and can be regenerated (invalidating the old set) from Account Security with a live TOTP code. **Automated backups**: the hourly background scheduler now writes one full JSON export per company per day to `data/backups/<company_id>/<date>.json`, pruning anything older than 30 days — no cron job or manual export needed.

**Deliberately not built**: minority-interest handling in multi-entity consolidation (intercompany balances ARE now eliminated — see above — but a partly-owned subsidiary isn't modelled); fund-level opening balances and cumulative funds-carried-forward across periods for the SOFA report; a background job scheduler/event bus/data warehouse or any other heavy platform infrastructure — this is a single Flask+SQLite app, and that scale of architecture would be scaffolding with nothing real behind it, not a feature.

**Unverified against real third-party accounts** (the code path is real and tested with fake/local data, but needs the user's own credentials to confirm end-to-end): Making Tax Digital submission needs a real HMRC Developer Hub application; the Stripe customer-payment portal needs a real Stripe account and API keys; SMTP-based emails/notifications need real mail server credentials. Stripe Checkout session creation, the PDF generator, and the public portal page are all verified working with placeholder/no credentials — only the actual money-moving and email-sending steps are unverified.
