# Handover — Bookkeeping Assistant

Paste this whole file into a new chat to resume work with full context.

## What this is

A Flask + SQLite multi-tenant double-entry bookkeeping web app.

- Repo: `bookkeeping-assistant-`, local path `/Users/ismaeelazhar/Claude/bookkeeping-app`, branch `main`
- GitHub: `git@github.com:ismaeelazhar-cmd/bookkeeping-assistant-.git`
- Single backend file: `server.py` (~7000+ lines)
- Single frontend file: `templates/index.html` (client-side hash-routing SPA — there are no separate server routes per "page")
- Tests: `tests/` (pytest), 81 passing as of the last commit
- `README.md` has a maintained feature list and a "Status" section that's kept accurate — treat it as ground truth for what's built vs. not.

## Standing rules (read before doing anything)

- Never skip a requested item silently. If something needs a real external account, or is a pricing/business decision, say so explicitly rather than faking it.
- Always run `python3 -m pytest -q` (full suite) and verify changes live via the preview tool before committing.
- **Never run `rm -f data.sqlite*` while the server is running** — caused a real data-loss incident earlier in this project. Just don't delete that file casually at all.
- Commit messages explain WHY, not WHAT, and must end with:
  `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`
- No comments in code unless documenting a non-obvious reason (a workaround, a hidden constraint).
- Never add a new pip dependency without clear need — check what's already imported first (e.g. Plaid webhook verification was hand-rolled with the already-present `cryptography` package instead of adding PyJWT).
- After finishing a verified unit of work: `git add` the specific files, commit, `git fetch && git log --oneline main..origin/main` (check divergence), then `git push`.

## What's been built (high-value summary — see README.md for the full list)

Core ledger, multi-company permissions, chart of accounts, pence-precision money, soft-delete + audit log, period locking, opening balances, compound journals, Plaid live bank feed with **verified webhook signatures** (ES256 JWT per Plaid's documented scheme — see `verify_plaid_webhook()` in server.py), Movements Inbox, bank reconciliation, receipt OCR (Claude or Ollama), categorization rules, VAT engine, HMRC MTD submission, mileage log, CIS, fixed assets (depreciation logic now consolidated into one function, `calculate_monthly_depreciation_charge()`), invoices/bills with PDF generation (3 templates), customer payment portal (Stripe), aging report, full financial statements, Ask Your Ledger (multi-turn AI chat), anomaly flagging, fund accounting, multi-entity consolidation (with intercompany elimination), dual AI providers (Claude paid / Ollama free local), Business Health Score, demo mode, quick entry mode, recurring journals UI, **2FA with backup/recovery codes** (10 single-use hashed codes, shown once, regenerable), **automated daily backups** (wired into the hourly background scheduler, writes JSON exports to `data/backups/<company_id>/<date>.json`, 30-day retention), PAYE/NI payroll calculator (in-app, editable rates — not a real HMRC RTI submission), mobile camera-direct receipt capture.

## What's explicitly NOT built (by design, not oversight — see README "Deliberately not built")

Minority-interest handling in consolidation, fund-level opening balances/carry-forward across periods, any heavy platform infrastructure (job scheduler/event bus/data warehouse) beyond what a single Flask+SQLite app needs.

## What's unverified against real third-party accounts

MTD submission (needs a real HMRC Developer Hub app), Stripe customer portal (needs real Stripe keys), SMTP email (needs real mail credentials). The code paths are real and tested with fake/local data — just not confirmed end-to-end with live credentials.

## Pending / open items

- **#17 Kill AI API key requirement for end users** — pending in the task list. Ollama (free, local, no API key) already exists as an alternative to Claude; the open question is whether/how to make that the seamless default rather than something the user has to discover in Settings → AI Features.
- **#37 Push notifications** — pending. Not started.
- **Permanent deployment to Fly.io** — in progress as of this handover. `fly.toml` already exists in the repo (app name `bookkeeping-assistant-ismaeel`, region `lhr`, persistent volume mounted at `/data` for `data.sqlite`). `flyctl` was just installed locally. The user needs to complete `flyctl auth login` (their own account/billing) before a `flyctl deploy` can run. Once deployed, the permanent URL will be `https://bookkeeping-assistant-ismaeel.fly.dev` (or whatever `flyctl deploy` reports — confirm before sharing as final).
- A previous Cloudflare Tunnel URL was used for **temporary** access only — it is NOT stable across reconnects and should be considered dead/irrelevant now that permanent Fly.io deployment is in progress.

## Known sharp edges (already fixed, but worth knowing the history)

- `rm -f data.sqlite*` while the server holds the file open silently creates a fresh empty DB (data-loss incident, see "standing rules" above).
- SQLite `ALTER TABLE ... ADD COLUMN DEFAULT` cannot take a `?` placeholder (DDL) — any new migration needing a non-trivial default must inline it via an f-string if the value is a fixed app-controlled constant.
- `date.toISOString().slice(0,7)` style date math in the frontend silently shifts across UTC day boundaries — use the existing `localMonthKey`/`localDateStr` helpers in `index.html` instead of going through `toISOString()`.

## How to verify changes

1. `python3 -m pytest -q` from the repo root.
2. Use the preview tool (`preview_start` with config name `bookkeeping-app` from `.claude/launch.json`, port 5050) to exercise the actual UI/API before considering something done — don't just trust the diff.
3. Test login: `test@myaccountingpal.com` (or sign up a fresh throwaway account via `/api/signup` for anything destructive/stateful, like 2FA flows).
