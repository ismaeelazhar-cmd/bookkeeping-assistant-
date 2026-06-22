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

## AI integration

The Claude API key is **write-only** — once set, it's never serialized back to the browser in any API response, and the actual Anthropic API call happens server-side (`server.py`'s `call_claude`), not from client-side JavaScript. Used for: Movements Inbox categorization, receipt OCR, and Ask Your Ledger.

## Running locally

```bash
pip3 install --user flask werkzeug
python3 server.py
```

Then open http://127.0.0.1:5050.

## Running the tests

```bash
pip3 install --user pytest
python3 -m pytest
```

38 tests covering auth, the account-dedup fix, pence precision, period locking, soft-delete, the invoice/bill lifecycle, compound journals, permission enforcement, and the full 2FA cycle. Each test run gets an isolated SQLite file — nothing touches your real `data.sqlite`.

## Status

Dev-mode Flask app (SQLite, Flask's built-in server) — fine for local/personal use. Hardened so far: persistent session secret (survives restarts), basic rate limiting on auth endpoints, a full JSON backup endpoint, and server-side-only AI key handling. **Not yet**: HTTPS (needs a real deployment target), encryption at rest for the AI key in the SQLite file itself, and a production WSGI server in place of Flask's dev server.

**Deliberately not built**: restricted/unrestricted fund accounting, a Statement of Financial Activities, and multi-entity consolidation — these are charity/nonprofit-specific and weren't confirmed as relevant to this app's actual use case. Worth building if that changes.
