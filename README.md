# Bookkeeping Assistant

A multi-tenant double-entry bookkeeping web app: log in, create one or more companies, invite collaborators with scoped permissions, and post transactions that flow straight into live T-accounts, a trial balance, and generated financial statements — with VAT, invoicing, bank reconciliation, and an AI layer that reads your actual ledger rather than guessing at it.

## Core ledger

- Email/password login (PBKDF2-hashed, session-based) with optional **TOTP 2FA** (RFC 6238, works with any standard authenticator app).
- Multi-company per user, fully isolated data per company. Invite collaborators by email with **view / comment / post** permission, enforced server-side on every mutating endpoint — not just hidden in the UI.
- A real **chart of accounts**: every account name is resolved through a case-insensitive-unique table, so "Cash" and "cash" can never silently fork into two accounts. Renaming an account cascades everywhere it's used; deleting one in use is blocked.
- Money is stored as **integer pence** internally — no floating-point drift on amounts. The JSON API still speaks pounds, so nothing about that is visible from outside.
- Soft-delete: "deleting" a transaction sets `voided_at`/`voided_by` rather than removing the row. Excluded from normal views, recoverable via `?includeVoided=1`, and every create/void is recorded in an **audit log**.
- **Period locking**: lock the books up to a date (e.g. after filing a VAT return) and nothing on or before that date can be added, edited, or deleted by anyone.
- **Opening balances** as a real table (not disguised transactions), feeding the trial balance, Statement of Financial Position, and a genuine brought-forward cash figure on the Cash Flow Statement.
- **Compound/split journals**: one payment or receipt split across several accounts, posted as linked entries sharing a `journal_id`.

## Movements & reconciliation

- **Live bank feed (Plaid)**: link a real bank account or card. This is the "buy don't build" Open Banking piece — actual connections go through Plaid's regulated infrastructure (the same approach Xero/FreeAgent use), not custom bank scraping. Transactions sync via cursor-based incremental sync straight into the same `bank_lines` the Bank Reconciliation screen already uses. A webhook gives real-time push updates once deployed somewhere reachable; a manual "Sync now" button covers local/sandbox use where Plaid's servers can't reach `localhost`. The access token is encrypted at rest with the same key used for the AI API key, and is never returned to the browser.
- **Movements Inbox**: drop a bank statement PDF or freeform text; keyword rules (or an AI pass) propose the debit/credit pair for review before posting. Every entry carries a `confidence` flag, surfaced as an "unreviewed" warning on any financial statement line built from it.
- **Bank Reconciliation**: import or paste a statement, match each line to a posted transaction or post a new one directly, with a running ledger-vs-statement balance check.
- **Receipt OCR**: attach a receipt/invoice (PDF/PNG/JPEG/HEIC/WEBP) to any transaction; Claude reads the date/description/amount off it.

## Tax & compliance

- **VAT engine**: per-transaction rate and direction, automatic splitting into Net + VAT Control Account + Gross postings, and a VAT Return report (Boxes 1/4/5/6/7) for any date range. See `docs/MTD-evaluation.md` for why direct HMRC submission isn't built (yet) and what the pragmatic interim is.
- **Fixed asset register**: register an asset, run straight-line or reducing-balance depreciation per month as a normal ledger posting (flows into the P&L and reduces net book value automatically).

## Sales & purchases

- **Contacts** (customers/suppliers) and real **Invoices/Bills** with a draft → sent → paid lifecycle. Sending posts to Trade Receivables/Payables (with VAT if set); paying settles it. Deleting one voids its linked ledger postings rather than leaving orphans.
- **Aging report** bucketing outstanding invoices/bills by days overdue.

## Reporting & analysis

- Statement of Profit or Loss, Statement of Financial Position, and a Cash Flow Statement (IAS 7 direct method) — all generated from the ledger, not entered separately.
- **Ask Your Ledger**: ask a plain-English question ("how much did I spend on travel last quarter?") and get an answer computed from your actual transaction data, not a guess.
- **Anomaly flagging**: first-time account use and statistically unusual transaction amounts (z-score against that account's history), computed live, no AI required.
- **Click-to-explain drill-down**: every account in the trial balance and every line in the P&L/SOFP is clickable, showing the exact transactions behind the figure.
- Dashboard summary (cash position, outstanding receivables/payables, net profit) and a contextual help layer that explains *why* each Movements Inbox suggestion or bank-rec match happened, wired to real state rather than generic tooltips.

## Fund accounting & consolidation (opt-in)

- **Fund accounting**: off by default per company — turning it on changes nothing else about how that company works. When on: tag transactions with a fund (restricted/designated/unrestricted) and get a **Statement of Financial Activities** segmenting incoming resources and resources expended by fund type. Funds don't auto-create like accounts do; they need a deliberate type, so referencing an unknown fund is a hard error, not a guess.
- **Multi-entity consolidation**: group companies you own (e.g. a charity plus its trading subsidiary) and view a combined P&L/SOFP summary. This is a plain aggregation across entities by matching account name — there's no intercompany elimination, so it's not true consolidation accounting if the grouped companies trade with each other.

## AI integration

The Claude API key is **write-only** — once set, it's never serialized back to the browser in any API response, and the actual Anthropic API call happens server-side (`server.py`'s `call_claude`), not from client-side JavaScript. Used for: Movements Inbox categorization, receipt OCR, and Ask Your Ledger.

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

73 tests covering auth, the account-dedup fix, pence precision, period locking, soft-delete, the invoice/bill lifecycle, compound journals, permission enforcement, the full 2FA cycle, bank reconciliation, fixed assets, attachments, preset learning, fund accounting/SOFA math, multi-entity consolidation, and the Plaid integration (including one test that makes a real network call to Plaid's sandbox with fake credentials, to prove the request is shaped correctly rather than just unit-testing in isolation). Each test run gets an isolated SQLite file — nothing touches your real `data.sqlite`.

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

## Status

Hardened so far: persistent session secret, basic rate limiting on auth endpoints, CSRF protection (Origin/Referer validation on state-changing requests), AI API key encrypted at rest (separate key file from the session secret), a full JSON backup endpoint, and server-side-only AI key handling (the key is write-only — never serialized back to the browser in any response). **Still not built**: 2FA backup/recovery codes (losing your authenticator device currently means losing account access — there's no recovery flow), and a built-in automated backup schedule (the export endpoint exists; nothing calls it on a timer).

**Deliberately not built**: real consolidation accounting (intercompany eliminations, minority interest) — the multi-entity consolidation feature is a plain aggregation, documented as such; fund-level opening balances and cumulative funds-carried-forward across periods for the SOFA report.
