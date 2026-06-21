# Bookkeeping Assistant

A small double-entry bookkeeping web app: log in, create one or more companies, and post transactions that go straight into live T-accounts, a trial balance, and generated Statement of Profit or Loss / Statement of Financial Position / Statement of Cash Flows.

## Features

- Email/password login (hashed, session-based), multi-company per user, fully isolated data per company.
- Post transactions manually, or drop a bank statement PDF / freeform text into the **Movements Inbox** — rule-based keyword matching or an optional Claude API call proposes the debit/credit pair for review before posting.
- Live T-accounts, journal, trial balance ("Compilation of T-Accounts"), CSV import/export.
- Account classification (Revenue/Expense/Asset/Liability/Equity) drives auto-generated financial statements, including a Statement of Cash Flows reconciled directly from ledger cash movements (IAS 7 direct method).

## Running locally

```bash
pip3 install --user flask werkzeug
python3 server.py
```

Then open http://127.0.0.1:5050.

## Status

This is a dev-mode Flask app (SQLite, Flask's built-in server) — fine for local/personal use, **not yet production-hardened** (no HTTPS, in-memory session secret regenerates on restart, no rate limiting). See open issues for the accounting feature gaps being worked through (VAT, bank reconciliation, audit trail, opening balances, fixed asset depreciation, etc).
