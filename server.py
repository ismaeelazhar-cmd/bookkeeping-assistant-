import os
import sqlite3
import secrets
import json
import logging
import datetime
from pathlib import Path
from urllib.parse import urlparse
from functools import wraps

import uuid
import re
import base64
import time
import hmac
import struct
import hashlib
import urllib.request
import urllib.error
import mimetypes

from flask import Flask, request, jsonify, session, send_from_directory, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet, InvalidToken

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

BASE_DIR = Path(__file__).parent
# DATA_DIR is everything that must survive a redeploy/restart — the database, uploaded
# attachments, and the two key files below. Defaults to BASE_DIR (no behavior change for local
# dev); set to a mounted persistent volume's path (e.g. /data on Fly.io) in production, since the
# container filesystem itself is ephemeral.
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "data.sqlite"
UPLOADS_DIR = DATA_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # 10MB

def load_or_create_secret_key():
    """Stage 7: persist the session secret to disk so a server restart doesn't log
    everyone out. The file is gitignored, same treatment as data.sqlite.
    A SECRET_KEY env var (set by the host platform / deploy config) takes priority over the
    file, so production deployments aren't forced to rely on a key written to local disk."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    secret_path = DATA_DIR / ".secret_key"
    if secret_path.exists():
        return secret_path.read_text().strip()
    key = secrets.token_hex(32)
    secret_path.write_text(key)
    secret_path.chmod(0o600)
    return key


def load_or_create_encryption_key():
    """Separate key file from the session secret on purpose: a leak of the SQLite file alone
    (e.g. a careless backup) isn't enough to recover stored AI API keys — you'd also need this
    file, which lives only on the server, never in source control, never in an export."""
    key_path = DATA_DIR / ".encryption_key"
    if key_path.exists():
        return key_path.read_bytes()
    key = Fernet.generate_key()
    key_path.write_bytes(key)
    key_path.chmod(0o600)
    return key


def encrypt_secret(plaintext):
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext):
    if not ciphertext:
        return ""
    try:
        return _fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""  # pre-encryption plaintext key, or corrupted — treat as unset, user re-enters it


_fernet = Fernet(load_or_create_encryption_key())

app = Flask(__name__, static_folder=str(BASE_DIR / "static"))
app.secret_key = load_or_create_secret_key()
app.config["MAX_CONTENT_LENGTH"] = MAX_ATTACHMENT_BYTES


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.before_request
def check_csrf_origin():
    """Lightweight CSRF mitigation: every JSON endpoint already resists CSRF because a plain
    cross-origin HTML form can't trigger a application/json request without a CORS preflight
    we don't allow. The one real gap was the multipart attachment upload (a plain <form
    enctype="multipart/form-data"> CAN cross origins). This closes that gap: if a browser sends
    Origin or Referer on a state-changing request, it must match our own host. Non-browser
    clients (curl, the test suite) send neither and are unaffected — they can't exploit CSRF in
    the first place since they don't carry the victim's session cookie."""
    if request.method not in ("POST", "PUT", "DELETE"):
        return
    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if not origin:
        return
    if urlparse(origin).netloc != urlparse(request.host_url).netloc:
        return jsonify({"error": "Cross-origin request blocked."}), 403


SCHEMA_VERSION = 4  # bumped for #18: invoices_bills.cis_deduction_pence/cis_rate


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")

    existing_version = 0
    try:
        row = db.execute("SELECT version FROM schema_meta").fetchone()
        existing_version = row[0] if row else 0
    except sqlite3.OperationalError:
        existing_version = 0

    if existing_version < SCHEMA_VERSION:
        # Stage 1 changed column types (REAL -> INTEGER pence) and table shapes in ways SQLite
        # can't ALTER in place. There is no real customer data behind this yet (local dev only,
        # data.sqlite is gitignored) so we rebuild clean rather than write a brittle migration.
        db.executescript(
            """
            DROP TABLE IF EXISTS schema_meta;
            DROP TABLE IF EXISTS invoices_bills;
            DROP TABLE IF EXISTS contacts;
            DROP TABLE IF EXISTS opening_balances;
            DROP TABLE IF EXISTS accounts;
            DROP TABLE IF EXISTS bank_lines;
            DROP TABLE IF EXISTS fixed_assets;
            DROP TABLE IF EXISTS presets;
            DROP TABLE IF EXISTS account_types;
            DROP TABLE IF EXISTS audit_log;
            DROP TABLE IF EXISTS transactions;
            DROP TABLE IF EXISTS companies;
            DROP TABLE IF EXISTS users;
            """
        )

    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT DEFAULT NULL,
            totp_pending_secret TEXT DEFAULT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS companies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            default_credit_account TEXT DEFAULT '',
            ai_api_key TEXT DEFAULT '',
            locked_until TEXT DEFAULT '',
            period_start_date TEXT DEFAULT '',
            currency TEXT NOT NULL DEFAULT 'GBP',
            confidence_threshold REAL NOT NULL DEFAULT 0.7,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- Chart of accounts: the single source of truth for account names. Transactions still
        -- store the account NAME (not yet a hard foreign key — that's a bigger relational
        -- change left for a later stage), but every write path resolves through
        -- resolve_account() below, which is case-insensitive-unique and auto-creates rather
        -- than silently forking "Cash" vs "cash".
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            code TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, name COLLATE NOCASE)
        );

        CREATE TABLE IF NOT EXISTS opening_balances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            amount_pence INTEGER NOT NULL,
            side TEXT NOT NULL,
            as_of_date TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, account_id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            desc TEXT NOT NULL,
            amount_pence INTEGER NOT NULL,
            debit TEXT NOT NULL,
            credit TEXT NOT NULL,
            tax_year TEXT DEFAULT '',
            vat_rate REAL DEFAULT 0,
            vat_direction TEXT DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'high',
            journal_id TEXT DEFAULT NULL,
            voided_at TEXT DEFAULT NULL,
            voided_by TEXT DEFAULT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS presets (
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            desc_key TEXT NOT NULL,
            debit TEXT NOT NULL,
            credit TEXT NOT NULL,
            PRIMARY KEY (company_id, desc_key)
        );

        CREATE TABLE IF NOT EXISTS bank_lines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            cash_account TEXT NOT NULL,
            date TEXT NOT NULL,
            desc TEXT NOT NULL,
            amount_pence INTEGER NOT NULL,
            matched_transaction_id INTEGER REFERENCES transactions(id) ON DELETE SET NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- A linked bank account/card via Plaid. access_token is the live credential that reads
        -- the user's real bank transactions — encrypted at rest with the same Fernet key used
        -- for the AI API key, never returned to the browser in any response.
        CREATE TABLE IF NOT EXISTS bank_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            item_id TEXT NOT NULL UNIQUE,
            access_token TEXT NOT NULL,
            institution_name TEXT DEFAULT '',
            cash_account TEXT NOT NULL DEFAULT 'Cash',
            sync_cursor TEXT DEFAULT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            user_email TEXT NOT NULL,
            action TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id INTEGER,
            before_json TEXT DEFAULT '',
            after_json TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS fixed_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            asset_account TEXT NOT NULL,
            cost_pence INTEGER NOT NULL,
            purchase_date TEXT NOT NULL,
            useful_life_years REAL NOT NULL,
            residual_value_pence INTEGER DEFAULT 0,
            method TEXT DEFAULT 'straight_line',
            depreciation_account TEXT DEFAULT 'Depreciation Expense',
            accum_account TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'customer',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            address_line1 TEXT DEFAULT '',
            address_city TEXT DEFAULT '',
            address_postcode TEXT DEFAULT '',
            address_country TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- Invoices (kind='invoice', sales to a customer) and Bills (kind='bill', purchases from a
        -- supplier) share a shape, so they share a table. "account" is the P&L/asset side of the
        -- entry (Sales for an invoice; whatever expense/asset account for a bill). transaction_id
        -- is set once it's sent (posted to the ledger); payment_transaction_id once it's paid.
        CREATE TABLE IF NOT EXISTS invoices_bills (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            due_date TEXT NOT NULL,
            desc TEXT NOT NULL,
            amount_pence INTEGER NOT NULL,
            account TEXT NOT NULL,
            vat_rate REAL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'draft',
            transaction_id INTEGER REFERENCES transactions(id) ON DELETE SET NULL,
            payment_transaction_id INTEGER REFERENCES transactions(id) ON DELETE SET NULL,
            linked_doc_id INTEGER REFERENCES invoices_bills(id),
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            transaction_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            stored_path TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- #8: a record of what was actually submitted to HMRC and when — the MTD submit
        -- endpoint itself was already built, but without this there was no way to see past
        -- filings, only file new ones blind.
        CREATE TABLE IF NOT EXISTS vat_filings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            period_key TEXT NOT NULL,
            net_vat_due_pence INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            hmrc_response_json TEXT NOT NULL,
            submitted_by TEXT NOT NULL,
            submitted_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- #17: mileage log for sole traders/directors using their own vehicle for business
        -- trips — HMRC's Approved Mileage Allowance Payments (AMAP) scheme, claimed instead of
        -- tracking actual fuel/running costs.
        CREATE TABLE IF NOT EXISTS mileage_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            tax_year TEXT NOT NULL,
            from_location TEXT NOT NULL,
            to_location TEXT NOT NULL,
            miles REAL NOT NULL,
            purpose TEXT NOT NULL,
            vehicle_type TEXT NOT NULL DEFAULT 'car',
            amount_pence INTEGER NOT NULL,
            transaction_id INTEGER REFERENCES transactions(id) ON DELETE SET NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- #14: free-text notes on a transaction ("Asked John about this — waiting for receipt"),
        -- separate from the audit log since these are conversational, not a record of what
        -- changed in the ledger.
        CREATE TABLE IF NOT EXISTS transaction_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            transaction_id INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- Stage 7: collaboration. The company's owner (companies.user_id) always has full
        -- access; this table adds others on top with a capped permission level. "comment" is
        -- accepted as a value now for forward-compatibility but currently behaves like "view"
        -- — there's no commenting feature yet to gate.
        CREATE TABLE IF NOT EXISTS company_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            permission TEXT NOT NULL DEFAULT 'view',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, user_id)
        );

        -- Stage 6, opt-in: only matters when companies.fund_accounting_enabled is set. A fund
        -- is a tag a transaction can optionally carry — restricted/designated/unrestricted —
        -- so a Statement of Financial Activities can be built from the same ledger without
        -- touching anything else.
        CREATE TABLE IF NOT EXISTS funds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'unrestricted',
            description TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, name COLLATE NOCASE)
        );

        -- Cost centres / departments, opt-in (companies.cost_centres_enabled): tag a transaction
        -- with a department to get a P&L broken down by department. Same mechanism as funds
        -- (deliberate creation, not auto-create — a typo in a department name shouldn't silently
        -- spawn a new one) but for trading companies rather than nonprofits.
        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, name COLLATE NOCASE)
        );

        -- Stock/inventory for product-based businesses, costed FIFO. quantity_on_hand is
        -- derived from stock_layers (sum of remaining_quantity), never stored directly, so it
        -- can't drift out of sync with the layers that actually back the cost calculation.
        CREATE TABLE IF NOT EXISTS stock_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            stock_account TEXT NOT NULL,
            cogs_account TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, name COLLATE NOCASE)
        );

        -- One row per purchase ("layer") — a sale consumes the oldest layers first (FIFO) until
        -- the sold quantity is covered, which is what makes the COGS figure FIFO rather than a
        -- simple average cost.
        CREATE TABLE IF NOT EXISTS stock_layers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            stock_item_id INTEGER NOT NULL REFERENCES stock_items(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            quantity_purchased REAL NOT NULL,
            quantity_remaining REAL NOT NULL,
            unit_cost_pence INTEGER NOT NULL,
            transaction_id INTEGER REFERENCES transactions(id) ON DELETE SET NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- A record of each sale's FIFO consumption — kept separately from stock_layers (which
        -- only tracks what's left) so a sale's actual cost breakdown stays inspectable later.
        CREATE TABLE IF NOT EXISTS stock_sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            stock_item_id INTEGER NOT NULL REFERENCES stock_items(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            quantity REAL NOT NULL,
            cogs_pence INTEGER NOT NULL,
            sale_amount_pence INTEGER NOT NULL,
            revenue_transaction_id INTEGER REFERENCES transactions(id) ON DELETE SET NULL,
            cogs_transaction_id INTEGER REFERENCES transactions(id) ON DELETE SET NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- Multi-entity consolidation: a simple named grouping of companies the same user owns.
        -- The consolidated report sums matching account lines across members — it's a plain
        -- aggregation, not true consolidation accounting (no intercompany eliminations).
        CREATE TABLE IF NOT EXISTS consolidation_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS consolidation_group_members (
            group_id INTEGER NOT NULL REFERENCES consolidation_groups(id) ON DELETE CASCADE,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            PRIMARY KEY (group_id, company_id)
        );

        -- A formal reconciliation "session" against one cash account for one statement date —
        -- separate from bank_lines (the individual imported statement rows), which already
        -- existed. This adds the higher-level open/close workflow: a rec is open while lines are
        -- being matched, then closed once the cleared balance ties to the statement.
        CREATE TABLE IF NOT EXISTS bank_reconciliations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            account TEXT NOT NULL,
            statement_date TEXT NOT NULL,
            statement_closing_balance_pence INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- A template for a journal that repeats on a fixed cadence (rent, loan interest,
        -- subscriptions). period-close posts every due one as a normal transaction and advances
        -- next_due — it doesn't run automatically on a schedule, only when period-close is called.
        CREATE TABLE IF NOT EXISTS recurring_journals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            label TEXT NOT NULL,
            frequency TEXT NOT NULL DEFAULT 'monthly',
            next_due TEXT NOT NULL,
            debit TEXT NOT NULL,
            credit TEXT NOT NULL,
            amount_pence INTEGER NOT NULL,
            end_date TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- Anything the system ingested but couldn't confidently categorise (AI suggestion below
        -- the company's confidence_threshold today; bank feed / PDF / CSV ingestion are documented
        -- trigger points for later, not yet wired) lands here instead of being silently posted or
        -- guessed. raw_line_json preserves exactly what came in, so the clarification UI can show
        -- the user the original line, not just the (possibly wrong) suggestion.
        -- A pre-invoice document: approved before goods/services are received, becomes a bill
        -- once they are. No ledger effect of its own — converting to a bill creates a normal
        -- draft invoices_bills row, which only posts when that bill is sent, same as any other.
        CREATE TABLE IF NOT EXISTS purchase_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            desc TEXT NOT NULL,
            amount_pence INTEGER NOT NULL,
            account TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'draft',
            bill_id INTEGER REFERENCES invoices_bills(id) ON DELETE SET NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        -- One budgeted amount per account per month ('YYYY-MM'). Variance against actual is
        -- computed on read (sum of that month's transactions for the account), not stored.
        CREATE TABLE IF NOT EXISTS budgets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
            period TEXT NOT NULL,
            amount_pence INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (company_id, account_id, period)
        );

        CREATE TABLE IF NOT EXISTS clarification_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            raw_line_json TEXT NOT NULL,
            suggested_debit TEXT DEFAULT '',
            suggested_credit TEXT DEFAULT '',
            suggested_amount_pence INTEGER DEFAULT 0,
            confidence REAL DEFAULT 0,
            reason TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT DEFAULT NULL,
            resolved_by TEXT DEFAULT NULL
        );
        """
    )
    # additive column for compound journals — safe to ALTER in place, no need to wipe data for this one
    tx_cols = {row[1] for row in db.execute("PRAGMA table_info(transactions)").fetchall()}
    if "journal_id" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN journal_id TEXT DEFAULT NULL")
    if "reviewed_by" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN reviewed_by TEXT DEFAULT NULL")
        db.execute("ALTER TABLE transactions ADD COLUMN reviewed_at TEXT DEFAULT NULL")
    user_cols = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "totp_secret" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL")
        db.execute("ALTER TABLE users ADD COLUMN totp_pending_secret TEXT DEFAULT NULL")
    company_cols = {row[1] for row in db.execute("PRAGMA table_info(companies)").fetchall()}
    if "fund_accounting_enabled" not in company_cols:
        db.execute("ALTER TABLE companies ADD COLUMN fund_accounting_enabled INTEGER DEFAULT 0")
    if "plaid_client_id" not in company_cols:
        db.execute("ALTER TABLE companies ADD COLUMN plaid_client_id TEXT DEFAULT ''")
        db.execute("ALTER TABLE companies ADD COLUMN plaid_secret TEXT DEFAULT ''")  # encrypted at rest, like ai_api_key
        db.execute("ALTER TABLE companies ADD COLUMN plaid_env TEXT DEFAULT 'sandbox'")
    bank_line_cols = {row[1] for row in db.execute("PRAGMA table_info(bank_lines)").fetchall()}
    if "external_id" not in bank_line_cols:
        db.execute("ALTER TABLE bank_lines ADD COLUMN external_id TEXT DEFAULT NULL")
    # partial index (not a full UNIQUE constraint) so manually-pasted lines, which never set
    # external_id, don't collide with each other — only Plaid-synced lines need de-duplication
    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_bank_lines_external "
        "ON bank_lines(company_id, external_id) WHERE external_id IS NOT NULL"
    )
    if "fund_id" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN fund_id INTEGER DEFAULT NULL REFERENCES funds(id)")
    if "department_id" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN department_id INTEGER DEFAULT NULL REFERENCES departments(id)")
    if "currency" not in tx_cols:
        # amount_pence is always the GBP (or company base-currency) equivalent — every other
        # report/balance in this app assumes one currency and stays correct unmodified. A
        # foreign-currency posting additionally stores the original amount and the rate used, for
        # display and as the basis for FX revaluation later.
        db.execute("ALTER TABLE transactions ADD COLUMN currency TEXT DEFAULT NULL")
        db.execute("ALTER TABLE transactions ADD COLUMN foreign_amount_pence INTEGER DEFAULT NULL")
        db.execute("ALTER TABLE transactions ADD COLUMN exchange_rate REAL DEFAULT NULL")
    if "cost_centres_enabled" not in company_cols:
        db.execute("ALTER TABLE companies ADD COLUMN cost_centres_enabled INTEGER DEFAULT 0")
    if "currency" not in company_cols:
        db.execute("ALTER TABLE companies ADD COLUMN currency TEXT NOT NULL DEFAULT 'GBP'")
    if "confidence_threshold" not in company_cols:
        db.execute("ALTER TABLE companies ADD COLUMN confidence_threshold REAL NOT NULL DEFAULT 0.7")
    if "hmrc_client_id" not in company_cols:
        # Making Tax Digital (VAT) OAuth credentials, same write-only/encrypted-at-rest treatment
        # as the Plaid fields above. hmrc_vrn is the VAT registration number HMRC's API is keyed
        # on; hmrc_access_token/refresh_token are populated after the OAuth consent flow
        # completes, not entered directly.
        db.execute("ALTER TABLE companies ADD COLUMN hmrc_client_id TEXT DEFAULT ''")
        db.execute("ALTER TABLE companies ADD COLUMN hmrc_client_secret TEXT DEFAULT ''")
        db.execute("ALTER TABLE companies ADD COLUMN hmrc_env TEXT DEFAULT 'sandbox'")
        db.execute("ALTER TABLE companies ADD COLUMN hmrc_vrn TEXT DEFAULT ''")
        db.execute("ALTER TABLE companies ADD COLUMN hmrc_access_token TEXT DEFAULT ''")
        db.execute("ALTER TABLE companies ADD COLUMN hmrc_refresh_token TEXT DEFAULT ''")
        db.execute("ALTER TABLE companies ADD COLUMN hmrc_token_expires_at TEXT DEFAULT ''")
    contact_cols = {row[1] for row in db.execute("PRAGMA table_info(contacts)").fetchall()}
    if "address_line1" not in contact_cols:
        db.execute("ALTER TABLE contacts ADD COLUMN address_line1 TEXT DEFAULT ''")
        db.execute("ALTER TABLE contacts ADD COLUMN address_city TEXT DEFAULT ''")
        db.execute("ALTER TABLE contacts ADD COLUMN address_postcode TEXT DEFAULT ''")
        db.execute("ALTER TABLE contacts ADD COLUMN address_country TEXT DEFAULT ''")
    ib_cols = {row[1] for row in db.execute("PRAGMA table_info(invoices_bills)").fetchall()}
    if "linked_doc_id" not in ib_cols:
        db.execute("ALTER TABLE invoices_bills ADD COLUMN linked_doc_id INTEGER DEFAULT NULL REFERENCES invoices_bills(id)")
    if "cis_deduction_pence" not in ib_cols:
        # #18: recorded at payment time so the CIS contractor view can list every deduction
        # made/suffered without re-deriving it from transaction descriptions.
        db.execute("ALTER TABLE invoices_bills ADD COLUMN cis_deduction_pence INTEGER DEFAULT 0")
        db.execute("ALTER TABLE invoices_bills ADD COLUMN cis_rate REAL DEFAULT NULL")
    db.execute("DELETE FROM schema_meta")
    db.execute("INSERT INTO schema_meta (version) VALUES (?)", (SCHEMA_VERSION,))
    db.commit()
    db.close()


# ---------- money helpers (Stage 1: integer pence storage, float-pounds JSON contract) ----------

def to_pence(amount):
    return int(round(float(amount) * 100))


def from_pence(pence):
    return round((pence or 0) / 100.0, 2)


# ---------- chart of accounts ----------

CODE_BASE_BY_TYPE = {
    "cash": 1000, "current_asset": 1100, "noncurrent_asset": 1500,
    "current_liability": 2000, "noncurrent_liability": 2500,
    "equity": 3000, "revenue": 4000, "cogs": 5000, "expense": 6000, "drawings": 3500,
}

DEFAULT_CHART = [
    ("Cash", "cash"),
    ("Sales", "revenue"),
    ("Opening Balance Equity", "equity"),
    ("VAT Control Account", "current_liability"),
    ("Depreciation Expense", "expense"),
]

# Onboarding chart-of-accounts templates, keyed by business type. Each extends DEFAULT_CHART
# with a handful of accounts a business of that type will need on day one — not exhaustive,
# just enough that the chart doesn't start completely blank for the most common shapes of
# small business. "general" is DEFAULT_CHART itself (no extra accounts).
CHART_TEMPLATES = {
    "general": [],
    "retail": [
        ("Stock / Inventory", "current_asset"),
        ("Cost of Goods Sold", "cogs"),
        ("Shop Rent", "expense"),
        ("Card Processing Fees", "expense"),
        ("Stock Suppliers", "current_liability"),
    ],
    "service": [
        ("Trade Receivables", "current_asset"),
        ("Subcontractor Costs", "cogs"),
        ("Software & Subscriptions", "expense"),
        ("Professional Fees", "expense"),
        ("Trade Payables", "current_liability"),
    ],
    "construction": [
        ("Materials", "cogs"),
        ("Subcontractor Costs", "cogs"),
        ("CIS Suffered", "current_asset"),
        ("Plant & Equipment Hire", "expense"),
        ("Trade Payables", "current_liability"),
        ("Retentions Held", "current_liability"),
    ],
}


def guess_account_type(name):
    n = name.lower()
    if n == "cash" or "bank" in n or "petty cash" in n:
        return "cash"
    if "accumulated depreciation" in n:
        return "noncurrent_asset"
    if "depreciation" in n:
        return "expense"
    if "drawing" in n:
        return "drawings"
    if n == "capital" or "capital introduced" in n or "share capital" in n or "share premium" in n or "opening balance equity" in n:
        return "equity"
    if "director" in n and "loan" in n:
        # Director's Loan Account: can sit on either side (the company owes the director, or the
        # director owes the company) — current_asset is the default since an overdrawn DLA (the
        # director owes money) is the case with tax consequences (S455) worth surfacing; the user
        # can reclassify it in Chart of Accounts if their DLA is consistently the other way.
        return "current_asset"
    if "loan" in n:
        return "noncurrent_liability"
    if "vat" in n or "payable" in n:
        return "current_liability"
    if "receivable" in n or "recievable" in n:
        return "current_asset"
    if "current portion" in n:
        return "current_liability"
    if "sale" in n or "revenue" in n or "income" in n:
        return "revenue"
    if "cost of sale" in n or "purchase" in n:
        return "cogs"
    if "equipment" in n or "vehicle" in n or "property" in n or "premises" in n or "fixtures" in n:
        return "noncurrent_asset"
    return "expense"


def next_account_code(db, company_id, account_type):
    base = CODE_BASE_BY_TYPE.get(account_type, 6000)
    row = db.execute(
        "SELECT COUNT(*) as n FROM accounts WHERE company_id = ? AND type = ?",
        (company_id, account_type),
    ).fetchone()
    return str(base + (row["n"] or 0))


def get_account_by_name(db, company_id, name):
    return db.execute(
        "SELECT * FROM accounts WHERE company_id = ? AND name = ? COLLATE NOCASE",
        (company_id, name),
    ).fetchone()


def resolve_account(db, company_id, raw_name, guessed_type=None):
    """Case-insensitive lookup-or-create against the chart of accounts.
    Returns the canonical (as-stored) name. This is what kills the "Cash" vs
    "cash" duplicate-account bug: a second spelling never creates a second row,
    it snaps to whatever's already there."""
    raw_name = (raw_name or "").strip()
    if not raw_name:
        return raw_name
    existing = get_account_by_name(db, company_id, raw_name)
    if existing:
        return existing["name"]
    account_type = guessed_type or guess_account_type(raw_name)
    code = next_account_code(db, company_id, account_type)
    db.execute(
        "INSERT INTO accounts (company_id, code, name, type) VALUES (?,?,?,?)",
        (company_id, code, raw_name, account_type),
    )
    return raw_name


def resolve_fund_id(db, company_id, fund_name):
    """Unlike accounts, funds don't auto-create — they need a type (restricted/designated/
    unrestricted) decided deliberately, so a transaction referencing an unknown fund is an error
    rather than a silent guess."""
    if not fund_name:
        return None
    row = db.execute(
        "SELECT id FROM funds WHERE company_id = ? AND name = ? COLLATE NOCASE", (company_id, fund_name)
    ).fetchone()
    if row is None:
        raise LedgerError(f'No fund named "{fund_name}" — create it first under Funds.')
    return row["id"]


def resolve_department_id(db, company_id, department_name):
    if not department_name:
        return None
    row = db.execute(
        "SELECT id FROM departments WHERE company_id = ? AND name = ? COLLATE NOCASE", (company_id, department_name)
    ).fetchone()
    if row is None:
        raise LedgerError(f'No department named "{department_name}" — create it first under Departments.')
    return row["id"]


def seed_default_chart(db, company_id, business_type=None):
    for name, account_type in DEFAULT_CHART:
        resolve_account(db, company_id, name, account_type)
    for name, account_type in CHART_TEMPLATES.get(business_type or "general", []):
        resolve_account(db, company_id, name, account_type)


def log_audit(db, company_id, action, entity_type, entity_id, before=None, after=None):
    db.execute(
        "INSERT INTO audit_log (company_id, user_email, action, entity_type, entity_id, before_json, after_json) "
        "VALUES (?,?,?,?,?,?,?)",
        (
            company_id, session.get("email", "unknown"), action, entity_type, entity_id,
            json.dumps(before) if before is not None else "",
            json.dumps(after) if after is not None else "",
        ),
    )


def compute_tax_year(date_str, period_start_date):
    """Derive the tax year label server-side from the transaction date and the company's fiscal
    year anchor (companies.period_start_date), rather than trusting a client-supplied string —
    a client can't be allowed to pick its own tax year. If no anchor is set, falls back to the
    calendar year. Anchor month/day define the fiscal year start; the anchor's own year is
    irrelevant, just its month/day."""
    tx_date = datetime.date.fromisoformat(date_str)
    if not period_start_date:
        return str(tx_date.year)
    anchor = datetime.date.fromisoformat(period_start_date)
    fy_start_this_year = datetime.date(tx_date.year, anchor.month, anchor.day)
    start_year = tx_date.year if tx_date >= fy_start_this_year else tx_date.year - 1
    if anchor.month == 1 and anchor.day == 1:
        return str(start_year)
    return f"{start_year}-{start_year + 1}"


def is_locked(company_row, date_str):
    locked_until = company_row["locked_until"] if company_row else ""
    return bool(locked_until) and date_str <= locked_until


# ---------- TOTP 2FA (RFC 6238) — pure stdlib, no new dependency ----------

def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(10)).decode("ascii")  # 16-char base32, compatible with any TOTP app


def totp_code(secret, for_time, step=30, digits=6):
    counter = int(for_time // step)
    key = base64.b32decode(secret.upper())
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code_int).zfill(digits)


def verify_totp(secret, code, window=1, step=30):
    if not secret or not code:
        return False
    now = time.time()
    return any(totp_code(secret, now + i * step, step) == code.strip() for i in range(-window, window + 1))


def totp_uri(secret, email):
    return f"otpauth://totp/Bookkeeping%20App:{email}?secret={secret}&issuer=Bookkeeping%20App&digits=6&period=30"


# ---------- auth helpers ----------

# ---------- basic rate limiting (Stage 7) ----------
# In-memory and per-process — fine for a single dev/small-deployment instance, won't survive
# a restart or work across multiple workers. A real deployment behind a load balancer would
# want this in Redis or similar, but that's a new dependency this app doesn't otherwise need.

_rate_limit_buckets = {}


def rate_limit(max_attempts=10, window_seconds=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = (fn.__name__, request.remote_addr)
            now = time.time()
            attempts = [t for t in _rate_limit_buckets.get(key, []) if now - t < window_seconds]
            if len(attempts) >= max_attempts:
                return jsonify({"error": "Too many attempts — wait a few minutes and try again."}), 429
            attempts.append(now)
            _rate_limit_buckets[key] = attempts
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Not logged in"}), 401
        return fn(*args, **kwargs)
    return wrapper


def company_required(fn):
    """Grants access if the caller owns the company OR is an invited member. Sets
    g.company_permission to 'owner', or to the member's permission level ('view'/'comment'/'post')."""
    @wraps(fn)
    def wrapper(company_id, *args, **kwargs):
        db = get_db()
        row = db.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
        if row is None:
            return jsonify({"error": "Company not found"}), 404
        if row["user_id"] == session["user_id"]:
            permission = "owner"
        else:
            member = db.execute(
                "SELECT permission FROM company_members WHERE company_id = ? AND user_id = ?",
                (company_id, session["user_id"]),
            ).fetchone()
            if member is None:
                return jsonify({"error": "Company not found"}), 404
            permission = member["permission"]
        g.company = row
        g.company_permission = permission
        return fn(company_id, *args, **kwargs)
    return wrapper


def write_required(fn):
    """Stage 7: gate mutations to owner or 'post'-permission members. Apply AFTER
    @company_required in the decorator stack (so g.company_permission is already set)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.company_permission not in ("owner", "post"):
            return jsonify({"error": "You have view-only access to this company."}), 403
        return fn(*args, **kwargs)
    return wrapper


def comment_required(fn):
    """#16: a step below write_required — 'comment'-permission members (the accountant-
    collaboration tier: can leave notes and lock periods, but can't post or delete
    transactions) pass this gate too. Apply AFTER @company_required."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.company_permission not in ("owner", "post", "comment"):
            return jsonify({"error": "You have view-only access to this company."}), 403
        return fn(*args, **kwargs)
    return wrapper


def owner_required(fn):
    """For company deletion and member management — stricter than write_required, only the actual owner."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.company_permission != "owner":
            return jsonify({"error": "Only the company owner can do this."}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------- static / pages ----------

@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR / "templates"), "index.html")


# ---------- auth endpoints ----------

@app.route("/api/signup", methods=["POST"])
@rate_limit(max_attempts=10, window_seconds=300)
def signup():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or "@" not in email or len(password) < 8:
        return jsonify({"error": "Enter a valid email and a password of at least 8 characters."}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        return jsonify({"error": "An account with that email already exists."}), 409

    password_hash = generate_password_hash(password, method="pbkdf2:sha256")
    cur = db.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, password_hash)
    )
    db.commit()
    session["user_id"] = cur.lastrowid
    session["email"] = email
    return jsonify({"id": cur.lastrowid, "email": email})


@app.route("/api/login", methods=["POST"])
@rate_limit(max_attempts=15, window_seconds=300)
def login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect email or password."}), 401

    if user["totp_secret"]:
        session.pop("user_id", None)
        session["pending_2fa_user_id"] = user["id"]
        return jsonify({"requires2fa": True})

    session["user_id"] = user["id"]
    session["email"] = user["email"]
    return jsonify({"id": user["id"], "email": user["email"]})


DEMO_TRANSACTIONS = [
    # (days ago, desc, amount, debit, credit) — a fictional plumbing business's typical month:
    # a few invoiced jobs, materials, van/fuel, insurance, phone, and a monthly rent/wage run.
    # Repeated once per month for 6 months below, with the day offset varied per iteration.
    (2, "Boiler service — Hartley residence", 280.00, "Cash", "Sales"),
    (5, "Bathroom refit — Thompson Ltd", 1850.00, "Trade Receivables", "Sales"),
    (6, "Materials — Plumbing World", 340.00, "Materials & Supplies", "Cash"),
    (9, "Emergency callout — Davis", 150.00, "Cash", "Sales"),
    (11, "Van fuel", 95.00, "Vehicle & Fuel", "Cash"),
    (14, "Pipe fitting job — Clark Properties", 620.00, "Cash", "Sales"),
    (16, "Public liability insurance", 65.00, "Insurance", "Cash"),
    (18, "Materials — City Plumb Supplies", 210.00, "Materials & Supplies", "Cash"),
    (20, "Mobile phone bill", 38.00, "Phone & Internet", "Cash"),
    (22, "Kitchen plumbing — White Contractors", 940.00, "Trade Receivables", "Sales"),
    (25, "Van service & MOT", 180.00, "Vehicle & Fuel", "Cash"),
    (27, "Office rent", 450.00, "Rent", "Cash"),
    (28, "Owner drawings", 1200.00, "Drawings", "Cash"),
]


def seed_demo_data(db, company_id):
    """Backfills ~6 months of realistic plumbing-business transactions for demo mode — varied
    enough (invoiced jobs, materials, van costs, rent, drawings) to make the dashboard, reports,
    and reconciliation pages all show something rather than being empty on first look."""
    today = datetime.date.today()
    opening_date = today - datetime.timedelta(days=6 * 30)
    try:
        post_ledger_transaction(db, company_id, opening_date.isoformat(), "Capital introduced", 8000.00, "Cash", "Capital Introduced")
    except LedgerError:
        pass
    for month_offset in range(6, 0, -1):
        for days_ago, desc, amount, debit, credit in DEMO_TRANSACTIONS:
            date = today - datetime.timedelta(days=month_offset * 30 - days_ago)
            try:
                post_ledger_transaction(db, company_id, date.isoformat(), desc, amount, debit, credit)
            except LedgerError:
                continue


@app.route("/api/demo", methods=["POST"])
@rate_limit(max_attempts=20, window_seconds=3600)
def start_demo():
    """One-click demo: spins up a throwaway account + a 'Riverside Plumbing & Heating' company
    pre-loaded with 6 months of sample transactions, and logs the browser straight into it — no
    signup form. The account is a real row (so the session/permission model needs nothing
    special) but uses a randomly generated, never-displayed email+password so it can't collide
    with or be guessed into a real user's account."""
    db = get_db()
    demo_email = f"demo-{uuid.uuid4().hex}@demo.local"
    password_hash = generate_password_hash(secrets.token_urlsafe(24), method="pbkdf2:sha256")
    cur = db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (demo_email, password_hash))
    user_id = cur.lastrowid

    company_cur = db.execute(
        "INSERT INTO companies (user_id, name) VALUES (?, ?)", (user_id, "Riverside Plumbing & Heating (Demo)")
    )
    company_id = company_cur.lastrowid
    seed_default_chart(db, company_id, "service")
    g.company = db.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
    seed_demo_data(db, company_id)
    db.commit()

    session["user_id"] = user_id
    session["email"] = demo_email
    return jsonify({"id": company_id, "email": demo_email})


@app.route("/api/login/2fa", methods=["POST"])
@rate_limit(max_attempts=10, window_seconds=300)
def login_2fa():
    data = request.get_json(force=True) or {}
    code = (data.get("code") or "").strip()
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return jsonify({"error": "No pending 2FA login — log in with your password first."}), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (pending_id,)).fetchone()
    if user is None or not verify_totp(user["totp_secret"], code):
        return jsonify({"error": "Invalid code."}), 401
    session.pop("pending_2fa_user_id", None)
    session["user_id"] = user["id"]
    session["email"] = user["email"]
    return jsonify({"id": user["id"], "email": user["email"]})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def me():
    if "user_id" not in session:
        return jsonify({"user": None})
    return jsonify({"user": {"id": session["user_id"], "email": session["email"]}})


# ---------- 2FA management (requires an active session, separate from the login flow above) ----------

@app.route("/api/2fa/status", methods=["GET"])
@login_required
def twofa_status():
    db = get_db()
    user = db.execute("SELECT totp_secret FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    return jsonify({"enabled": bool(user["totp_secret"])})


@app.route("/api/2fa/setup", methods=["POST"])
@login_required
def twofa_setup():
    secret = generate_totp_secret()
    db = get_db()
    db.execute("UPDATE users SET totp_pending_secret = ? WHERE id = ?", (secret, session["user_id"]))
    db.commit()
    return jsonify({"secret": secret, "otpauthUri": totp_uri(secret, session["email"])})


@app.route("/api/2fa/confirm", methods=["POST"])
@login_required
def twofa_confirm():
    data = request.get_json(force=True) or {}
    code = (data.get("code") or "").strip()
    db = get_db()
    user = db.execute("SELECT totp_pending_secret FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user["totp_pending_secret"]:
        return jsonify({"error": "Start setup first."}), 400
    if not verify_totp(user["totp_pending_secret"], code):
        return jsonify({"error": "Invalid code — check your authenticator app and try again."}), 400
    db.execute(
        "UPDATE users SET totp_secret = totp_pending_secret, totp_pending_secret = NULL WHERE id = ?",
        (session["user_id"],),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/2fa/disable", methods=["POST"])
@login_required
def twofa_disable():
    data = request.get_json(force=True) or {}
    code = (data.get("code") or "").strip()
    db = get_db()
    user = db.execute("SELECT totp_secret FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if not user["totp_secret"]:
        return jsonify({"error": "2FA isn't enabled."}), 400
    if not verify_totp(user["totp_secret"], code):
        return jsonify({"error": "Invalid code."}), 400
    db.execute("UPDATE users SET totp_secret = NULL, totp_pending_secret = NULL WHERE id = ?", (session["user_id"],))
    db.commit()
    return jsonify({"ok": True})


# ---------- companies ----------

@app.route("/api/companies", methods=["GET"])
@login_required
def list_companies():
    db = get_db()
    rows = db.execute(
        "SELECT id, name, default_credit_account, ai_api_key, locked_until, period_start_date, "
        "fund_accounting_enabled, plaid_client_id, plaid_secret, plaid_env, confidence_threshold, cost_centres_enabled, "
        "hmrc_client_id, hmrc_client_secret, hmrc_env, hmrc_vrn, hmrc_access_token, "
        "'owner' as permission "
        "FROM companies WHERE user_id = ? "
        "UNION ALL "
        "SELECT c.id, c.name, c.default_credit_account, c.ai_api_key, c.locked_until, c.period_start_date, "
        "c.fund_accounting_enabled, c.plaid_client_id, c.plaid_secret, c.plaid_env, c.confidence_threshold, c.cost_centres_enabled, "
        "c.hmrc_client_id, c.hmrc_client_secret, c.hmrc_env, c.hmrc_vrn, c.hmrc_access_token, "
        "cm.permission "
        "FROM companies c JOIN company_members cm ON cm.company_id = c.id "
        "WHERE cm.user_id = ? "
        "ORDER BY name",
        (session["user_id"], session["user_id"]),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["ai_api_key_set"] = bool(d.pop("ai_api_key"))  # Stage 5: the raw key never leaves the server
        d["plaid_secret_set"] = bool(d.pop("plaid_secret"))  # same write-only treatment
        d["hmrc_client_secret_set"] = bool(d.pop("hmrc_client_secret"))
        d["hmrc_connected"] = bool(d.pop("hmrc_access_token"))
        result.append(d)
    return jsonify(result)


@app.route("/api/companies", methods=["POST"])
@login_required
def create_company():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Company name is required."}), 400
    business_type = data.get("businessType") or "general"
    if business_type not in CHART_TEMPLATES:
        business_type = "general"
    db = get_db()
    cur = db.execute(
        "INSERT INTO companies (user_id, name) VALUES (?, ?)", (session["user_id"], name)
    )
    company_id = cur.lastrowid
    seed_default_chart(db, company_id, business_type)

    # Onboarding opening balances: each {account, amount} debits the named account (it's where
    # the value already sits — a bank balance, stock on hand, etc.) against Opening Balance
    # Equity, the same plug account a manual catch-up entry would use. Best-effort: a bad row
    # (unknown amount, zero) is just skipped rather than failing the whole company creation.
    opening_balances = data.get("openingBalances") or []
    g.company = db.execute("SELECT * FROM companies WHERE id = ?", (company_id,)).fetchone()
    for row in opening_balances:
        account = (row.get("account") or "").strip()
        try:
            amount = float(row.get("amount") or 0)
        except (TypeError, ValueError):
            continue
        if not account or amount <= 0:
            continue
        try:
            post_ledger_transaction(
                db, company_id, data.get("openingBalancesDate") or datetime.date.today().isoformat(),
                f"Opening balance — {account}", amount, account, "Opening Balance Equity",
            )
        except LedgerError:
            continue

    db.commit()
    return jsonify({
        "id": company_id, "name": name, "default_credit_account": "", "ai_api_key_set": False,
        "locked_until": "", "period_start_date": "", "fund_accounting_enabled": 0,
        "plaid_client_id": "", "plaid_secret_set": False, "plaid_env": "sandbox", "permission": "owner",
        "confidence_threshold": 0.7, "cost_centres_enabled": 0,
    })


@app.route("/api/chart-templates", methods=["GET"])
@login_required
def chart_templates():
    """Lists the onboarding business-type templates so the signup wizard can show what extra
    accounts each one adds, without hardcoding the list twice (once server-side, once in JS)."""
    return jsonify([
        {
            "id": key,
            "label": {"general": "General / other", "retail": "Retail", "service": "Service business",
                       "construction": "Construction & trades"}.get(key, key.title()),
            "extraAccounts": [name for name, _ in accounts],
        }
        for key, accounts in CHART_TEMPLATES.items()
    ])


@app.route("/api/companies/<int:company_id>", methods=["DELETE"])
@login_required
@company_required
@owner_required
def delete_company(company_id):
    db = get_db()
    db.execute("DELETE FROM companies WHERE id = ?", (company_id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/settings", methods=["PUT"])
@login_required
@company_required
@write_required
def update_settings(company_id):
    data = request.get_json(force=True) or {}
    db = get_db()
    confidence_threshold = float(data.get("confidenceThreshold", 0.7) or 0.7)
    confidence_threshold = min(1.0, max(0.0, confidence_threshold))
    db.execute(
        "UPDATE companies SET default_credit_account = ?, locked_until = ?, period_start_date = ?, "
        "fund_accounting_enabled = ?, plaid_client_id = ?, plaid_env = ?, confidence_threshold = ?, "
        "cost_centres_enabled = ?, hmrc_client_id = ?, hmrc_env = ?, hmrc_vrn = ? WHERE id = ?",
        (
            data.get("defaultCreditAccount", ""), data.get("lockedUntil", ""), data.get("periodStartDate", ""),
            1 if data.get("fundAccountingEnabled") else 0,
            data.get("plaidClientId", ""), data.get("plaidEnv") or "sandbox", confidence_threshold,
            1 if data.get("costCentresEnabled") else 0,
            data.get("hmrcClientId", ""), data.get("hmrcEnv") or "sandbox", data.get("hmrcVrn", ""), company_id,
        ),
    )
    # The AI key and Plaid secret are write-only from the client's perspective: a blank field
    # never overwrites whatever's already stored (the browser can't see the real value to
    # "leave it unchanged" any other way), and clearing either requires an explicit flag.
    if data.get("aiApiKey"):
        db.execute("UPDATE companies SET ai_api_key = ? WHERE id = ?", (encrypt_secret(data["aiApiKey"]), company_id))
    elif data.get("clearAiApiKey"):
        db.execute("UPDATE companies SET ai_api_key = '' WHERE id = ?", (company_id,))
    if data.get("plaidSecret"):
        db.execute("UPDATE companies SET plaid_secret = ? WHERE id = ?", (encrypt_secret(data["plaidSecret"]), company_id))
    elif data.get("clearPlaidSecret"):
        db.execute("UPDATE companies SET plaid_secret = '' WHERE id = ?", (company_id,))
    if data.get("hmrcClientSecret"):
        db.execute("UPDATE companies SET hmrc_client_secret = ? WHERE id = ?", (encrypt_secret(data["hmrcClientSecret"]), company_id))
    elif data.get("clearHmrcClientSecret"):
        db.execute("UPDATE companies SET hmrc_client_secret = '', hmrc_access_token = '', hmrc_refresh_token = '' WHERE id = ?", (company_id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/period-lock", methods=["PUT"])
@login_required
@company_required
@comment_required
def update_period_lock(company_id):
    """#16: locking a period (after a VAT return or month-end close) is the one settings change
    an invited accountant needs to make routinely, separate from the full settings form which
    also touches integrations/AI keys — comment-permission is enough to lock dates, but still
    can't post or delete a single transaction."""
    locked_until = (request.get_json(force=True) or {}).get("lockedUntil", "")
    db = get_db()
    db.execute("UPDATE companies SET locked_until = ? WHERE id = ?", (locked_until, company_id))
    db.commit()
    log_audit(db, company_id, "lock_period", "company", company_id, after={"lockedUntil": locked_until})
    db.commit()
    return jsonify({"ok": True, "lockedUntil": locked_until})


VALID_PERMISSIONS = ("view", "comment", "post")


@app.route("/api/companies/<int:company_id>/members", methods=["GET"])
@login_required
@company_required
def list_members(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT cm.id, u.email, cm.permission FROM company_members cm "
        "JOIN users u ON u.id = cm.user_id WHERE cm.company_id = ? ORDER BY u.email",
        (company_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/members", methods=["POST"])
@login_required
@company_required
@owner_required
def invite_member(company_id):
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    permission = data.get("permission") or "view"
    if permission not in VALID_PERMISSIONS:
        return jsonify({"error": "Invalid permission level."}), 400
    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if user is None:
        return jsonify({"error": f'No account exists for "{email}" yet — they need to sign up first, then you can invite them.'}), 404
    if user["id"] == session["user_id"]:
        return jsonify({"error": "You already own this company."}), 400
    db.execute(
        "INSERT INTO company_members (company_id, user_id, permission) VALUES (?,?,?) "
        "ON CONFLICT(company_id, user_id) DO UPDATE SET permission = excluded.permission",
        (company_id, user["id"], permission),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/members/<int:member_id>", methods=["DELETE"])
@login_required
@company_required
@owner_required
def remove_member(company_id, member_id):
    db = get_db()
    db.execute("DELETE FROM company_members WHERE id = ? AND company_id = ?", (member_id, company_id))
    db.commit()
    return jsonify({"ok": True})


# ---------- multi-entity consolidation (Stage 6) ----------
#
# A simple named grouping of companies the user owns. The report sums matching account lines
# across members by (name, type) — a plain aggregation, explicitly NOT true consolidation
# accounting: there's no intercompany elimination (a loan from Company A to Company B would
# double-count as an asset in A and a liability in B rather than netting to zero), and no
# minority-interest handling. Good enough for "what does this group look like combined";
# not a substitute for a real consolidation engine if intercompany transactions exist.

@app.route("/api/consolidation-groups", methods=["GET"])
@login_required
def list_consolidation_groups():
    db = get_db()
    groups = db.execute(
        "SELECT id, name FROM consolidation_groups WHERE user_id = ? ORDER BY name", (session["user_id"],)
    ).fetchall()
    result = []
    for g_row in groups:
        members = db.execute(
            "SELECT c.id, c.name FROM consolidation_group_members cgm "
            "JOIN companies c ON c.id = cgm.company_id WHERE cgm.group_id = ?",
            (g_row["id"],),
        ).fetchall()
        result.append({"id": g_row["id"], "name": g_row["name"], "members": [dict(m) for m in members]})
    return jsonify(result)


@app.route("/api/consolidation-groups", methods=["POST"])
@login_required
def create_consolidation_group():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    company_ids = data.get("companyIds") or []
    if not name or len(company_ids) < 2:
        return jsonify({"error": "A name and at least 2 companies are required."}), 400

    db = get_db()
    owned = db.execute(
        f"SELECT id FROM companies WHERE user_id = ? AND id IN ({','.join('?' * len(company_ids))})",
        (session["user_id"], *company_ids),
    ).fetchall()
    if len(owned) != len(set(company_ids)):
        return jsonify({"error": "You can only consolidate companies you own."}), 403

    cur = db.execute("INSERT INTO consolidation_groups (user_id, name) VALUES (?, ?)", (session["user_id"], name))
    group_id = cur.lastrowid
    for cid in set(company_ids):
        db.execute("INSERT INTO consolidation_group_members (group_id, company_id) VALUES (?, ?)", (group_id, cid))
    db.commit()
    return jsonify({"id": group_id})


@app.route("/api/consolidation-groups/<int:group_id>", methods=["DELETE"])
@login_required
def delete_consolidation_group(group_id):
    db = get_db()
    db.execute("DELETE FROM consolidation_groups WHERE id = ? AND user_id = ?", (group_id, session["user_id"]))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/consolidation-groups/<int:group_id>/report", methods=["GET"])
@login_required
def consolidation_report(group_id):
    db = get_db()
    group = db.execute(
        "SELECT id FROM consolidation_groups WHERE id = ? AND user_id = ?", (group_id, session["user_id"])
    ).fetchone()
    if group is None:
        return jsonify({"error": "Not found."}), 404

    member_ids = [r["company_id"] for r in db.execute(
        "SELECT company_id FROM consolidation_group_members WHERE group_id = ?", (group_id,)
    ).fetchall()]

    combined = {}  # name -> {type, debit, credit}
    for cid in member_ids:
        types_by_name = {r["name"]: r["type"] for r in db.execute(
            "SELECT name, type FROM accounts WHERE company_id = ?", (cid,)
        ).fetchall()}
        for tx in db.execute(
            "SELECT amount_pence, debit, credit FROM transactions WHERE company_id = ? AND voided_at IS NULL", (cid,)
        ).fetchall():
            amount = from_pence(tx["amount_pence"])
            for account, side in ((tx["debit"], "debit"), (tx["credit"], "credit")):
                entry = combined.setdefault(account, {"type": types_by_name.get(account, "expense"), "debit": 0, "credit": 0})
                entry[side] += amount
        # opening balances feed account totals too — without this, a consolidated balance sheet
        # would silently exclude every balance brought forward from before the ledger started
        for ob in db.execute(
            "SELECT ob.amount_pence, ob.side, a.name as account FROM opening_balances ob "
            "JOIN accounts a ON a.id = ob.account_id WHERE ob.company_id = ?", (cid,)
        ).fetchall():
            amount = from_pence(ob["amount_pence"])
            entry = combined.setdefault(ob["account"], {"type": types_by_name.get(ob["account"], "expense"), "debit": 0, "credit": 0})
            entry[ob["side"]] += amount

    debit_normal_types = {"cash", "cogs", "expense", "current_asset", "noncurrent_asset", "drawings"}
    totals = {"revenue": 0, "cogs": 0, "expense": 0, "current_asset": 0, "noncurrent_asset": 0,
              "current_liability": 0, "noncurrent_liability": 0, "equity": 0, "drawings": 0, "cash": 0}
    accounts_out = []
    for name, entry in combined.items():
        t = entry["type"]
        balance = (entry["debit"] - entry["credit"]) if t in debit_normal_types else (entry["credit"] - entry["debit"])
        totals[t] = totals.get(t, 0) + balance
        accounts_out.append({"name": name, "type": t, "balance": balance})

    net_profit = totals["revenue"] - totals["cogs"] - totals["expense"]
    total_assets = totals["cash"] + totals["current_asset"] + totals["noncurrent_asset"]
    total_liabilities = totals["current_liability"] + totals["noncurrent_liability"]
    total_equity = totals["equity"] + net_profit - totals["drawings"]

    # This consolidation is a plain aggregation (documented elsewhere in this app) — it does not
    # eliminate intercompany balances. At minimum, flag accounts that look like they record a
    # balance between related entities (the things that genuinely need eliminating before this
    # report can be called real consolidated accounts) so the user knows to look at them.
    intercompany_accounts = [
        a for a in accounts_out
        if re.search(r"intercompany|inter-company|due (from|to)", a["name"], re.IGNORECASE)
    ]

    return jsonify({
        "memberCount": len(member_ids),
        "accounts": sorted(accounts_out, key=lambda a: a["name"]),
        "summary": {
            "revenue": totals["revenue"], "cogs": totals["cogs"], "expenses": totals["expense"],
            "netProfit": net_profit, "totalAssets": total_assets, "totalLiabilities": total_liabilities,
            "totalEquity": total_equity,
        },
        "intercompanyWarning": {
            "accounts": [{"name": a["name"], "balance": a["balance"]} for a in intercompany_accounts],
            "note": "These look like balances between related entities. This report is a plain "
                    "aggregation, not true consolidation accounting — these have NOT been eliminated "
                    "and may overstate combined assets/liabilities if the member companies trade with "
                    "each other.",
        } if intercompany_accounts else None,
    })


# ---------- chart of accounts ----------

@app.route("/api/companies/<int:company_id>/accounts", methods=["GET"])
@login_required
@company_required
def list_accounts(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, code, name, type FROM accounts WHERE company_id = ? ORDER BY code",
        (company_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/accounts", methods=["POST"])
@login_required
@company_required
@write_required
def create_account(company_id):
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    account_type = data.get("type") or "expense"
    if not name:
        return jsonify({"error": "Account name is required."}), 400
    db = get_db()
    if get_account_by_name(db, company_id, name):
        return jsonify({"error": f'An account named "{name}" already exists (account names are case-insensitive-unique).'}), 409
    code = data.get("code") or next_account_code(db, company_id, account_type)
    cur = db.execute(
        "INSERT INTO accounts (company_id, code, name, type) VALUES (?,?,?,?)",
        (company_id, code, name, account_type),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "code": code, "name": name, "type": account_type})


@app.route("/api/companies/<int:company_id>/accounts/<int:account_id>", methods=["PUT"])
@login_required
@company_required
@write_required
def update_account(company_id, account_id):
    data = request.get_json(force=True) or {}
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE id = ? AND company_id = ?", (account_id, company_id)
    ).fetchone()
    if account is None:
        return jsonify({"error": "Account not found."}), 404

    new_name = (data.get("name") or account["name"]).strip()
    new_type = data.get("type") or account["type"]
    old_name = account["name"]

    if new_name.lower() != old_name.lower():
        clash = get_account_by_name(db, company_id, new_name)
        if clash and clash["id"] != account_id:
            return jsonify({"error": f'An account named "{new_name}" already exists.'}), 409

    db.execute("UPDATE accounts SET name = ?, type = ? WHERE id = ?", (new_name, new_type, account_id))

    if new_name != old_name:
        # cascade the rename everywhere the old name string was used
        for table, cols in (
            ("transactions", ["debit", "credit"]),
            ("bank_lines", ["cash_account"]),
            ("fixed_assets", ["asset_account", "depreciation_account", "accum_account"]),
            ("presets", ["debit", "credit"]),
        ):
            for col in cols:
                db.execute(
                    f"UPDATE {table} SET {col} = ? WHERE company_id = ? AND {col} = ?",
                    (new_name, company_id, old_name),
                )
        db.execute(
            "UPDATE companies SET default_credit_account = ? WHERE id = ? AND default_credit_account = ?",
            (new_name, company_id, old_name),
        )

    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/accounts/<int:account_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_account(company_id, account_id):
    db = get_db()
    account = db.execute(
        "SELECT * FROM accounts WHERE id = ? AND company_id = ?", (account_id, company_id)
    ).fetchone()
    if account is None:
        return jsonify({"ok": True})
    in_use = db.execute(
        "SELECT COUNT(*) as n FROM transactions WHERE company_id = ? AND (debit = ? OR credit = ?) AND voided_at IS NULL",
        (company_id, account["name"], account["name"]),
    ).fetchone()["n"]
    if in_use:
        return jsonify({"error": f'"{account["name"]}" is used by {in_use} transaction(s) and can\'t be deleted.'}), 409
    db.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    db.commit()
    return jsonify({"ok": True})


# ---------- funds (Stage 6, opt-in) ----------

VALID_FUND_TYPES = ("unrestricted", "restricted", "designated")


@app.route("/api/companies/<int:company_id>/funds", methods=["GET"])
@login_required
@company_required
def list_funds(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, name, type, description FROM funds WHERE company_id = ? ORDER BY name", (company_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/funds", methods=["POST"])
@login_required
@company_required
@write_required
def create_fund(company_id):
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    fund_type = data.get("type") or "unrestricted"
    if not name:
        return jsonify({"error": "Fund name is required."}), 400
    if fund_type not in VALID_FUND_TYPES:
        return jsonify({"error": "Invalid fund type."}), 400
    db = get_db()
    existing = db.execute(
        "SELECT id FROM funds WHERE company_id = ? AND name = ? COLLATE NOCASE", (company_id, name)
    ).fetchone()
    if existing:
        return jsonify({"error": f'A fund named "{name}" already exists.'}), 409
    cur = db.execute(
        "INSERT INTO funds (company_id, name, type, description) VALUES (?,?,?,?)",
        (company_id, name, fund_type, data.get("description", "")),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/funds/<int:fund_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_fund(company_id, fund_id):
    db = get_db()
    in_use = db.execute(
        "SELECT COUNT(*) as n FROM transactions WHERE company_id = ? AND fund_id = ? AND voided_at IS NULL",
        (company_id, fund_id),
    ).fetchone()["n"]
    if in_use:
        return jsonify({"error": f"This fund is used by {in_use} transaction(s) and can't be deleted."}), 409
    db.execute("DELETE FROM funds WHERE id = ? AND company_id = ?", (fund_id, company_id))
    db.commit()
    return jsonify({"ok": True})


# ---------- departments / cost centres, opt-in ----------

@app.route("/api/companies/<int:company_id>/departments", methods=["GET"])
@login_required
@company_required
def list_departments(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, name FROM departments WHERE company_id = ? ORDER BY name", (company_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/departments", methods=["POST"])
@login_required
@company_required
@write_required
def create_department(company_id):
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Department name is required."}), 400
    db = get_db()
    existing = db.execute(
        "SELECT id FROM departments WHERE company_id = ? AND name = ? COLLATE NOCASE", (company_id, name)
    ).fetchone()
    if existing:
        return jsonify({"error": f'A department named "{name}" already exists.'}), 409
    cur = db.execute("INSERT INTO departments (company_id, name) VALUES (?,?)", (company_id, name))
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/departments/<int:department_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_department(company_id, department_id):
    db = get_db()
    in_use = db.execute(
        "SELECT COUNT(*) as n FROM transactions WHERE company_id = ? AND department_id = ? AND voided_at IS NULL",
        (company_id, department_id),
    ).fetchone()["n"]
    if in_use:
        return jsonify({"error": f"This department is used by {in_use} transaction(s) and can't be deleted."}), 409
    db.execute("DELETE FROM departments WHERE id = ? AND company_id = ?", (department_id, company_id))
    db.commit()
    return jsonify({"ok": True})


# ---------- stock / inventory (FIFO) ----------

def _stock_item_summary(db, company_id, item):
    layers = db.execute(
        "SELECT quantity_remaining, unit_cost_pence FROM stock_layers "
        "WHERE company_id = ? AND stock_item_id = ? AND quantity_remaining > 0 ORDER BY date, id",
        (company_id, item["id"]),
    ).fetchall()
    quantity_on_hand = sum(l["quantity_remaining"] for l in layers)
    value_pence = sum(l["quantity_remaining"] * l["unit_cost_pence"] for l in layers)
    return {
        "id": item["id"], "name": item["name"], "stockAccount": item["stock_account"], "cogsAccount": item["cogs_account"],
        "quantityOnHand": quantity_on_hand,
        "valueOnHand": from_pence(value_pence),
        "averageUnitCost": from_pence(value_pence / quantity_on_hand) if quantity_on_hand > 0 else 0,
    }


@app.route("/api/companies/<int:company_id>/stock-items", methods=["GET"])
@login_required
@company_required
def list_stock_items(company_id):
    db = get_db()
    items = db.execute("SELECT * FROM stock_items WHERE company_id = ? ORDER BY name", (company_id,)).fetchall()
    return jsonify([_stock_item_summary(db, company_id, i) for i in items])


@app.route("/api/companies/<int:company_id>/stock-items", methods=["POST"])
@login_required
@company_required
@write_required
def create_stock_item(company_id):
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Stock item name is required."}), 400
    db = get_db()
    stock_account = resolve_account(db, company_id, data.get("stockAccount") or "Stock", "current_asset")
    cogs_account = resolve_account(db, company_id, data.get("cogsAccount") or "Cost of Sales", "cogs")
    try:
        cur = db.execute(
            "INSERT INTO stock_items (company_id, name, stock_account, cogs_account) VALUES (?,?,?,?)",
            (company_id, name, stock_account, cogs_account),
        )
    except sqlite3.IntegrityError:
        return jsonify({"error": f'A stock item named "{name}" already exists.'}), 409
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/stock-items/<int:item_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_stock_item(company_id, item_id):
    db = get_db()
    db.execute("DELETE FROM stock_items WHERE id = ? AND company_id = ?", (item_id, company_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/stock-items/<int:item_id>/purchase", methods=["POST"])
@login_required
@company_required
@write_required
def purchase_stock(company_id, item_id):
    data = request.get_json(force=True) or {}
    date = data.get("date")
    quantity = float(data.get("quantity") or 0)
    unit_cost = float(data.get("unitCost") or 0)
    payment_account = data.get("paymentAccount") or "Cash"
    if not date or quantity <= 0 or unit_cost <= 0:
        return jsonify({"error": "Date, a positive quantity, and a positive unit cost are required."}), 400

    db = get_db()
    item = db.execute("SELECT * FROM stock_items WHERE id = ? AND company_id = ?", (item_id, company_id)).fetchone()
    if item is None:
        return jsonify({"error": "Stock item not found."}), 404

    unit_cost_pence = to_pence(unit_cost)
    total_cost = from_pence(round(quantity * unit_cost_pence))
    try:
        tx_id = post_ledger_transaction(
            db, company_id, date, f"Stock purchase — {item['name']}", total_cost, item["stock_account"], payment_account
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status

    db.execute(
        "INSERT INTO stock_layers (company_id, stock_item_id, date, quantity_purchased, quantity_remaining, unit_cost_pence, transaction_id) "
        "VALUES (?,?,?,?,?,?,?)",
        (company_id, item_id, date, quantity, quantity, unit_cost_pence, tx_id),
    )
    db.commit()
    return jsonify({"transactionId": tx_id, "totalCost": total_cost})


@app.route("/api/companies/<int:company_id>/stock-items/<int:item_id>/sale", methods=["POST"])
@login_required
@company_required
@write_required
def sell_stock(company_id, item_id):
    data = request.get_json(force=True) or {}
    date = data.get("date")
    quantity = float(data.get("quantity") or 0)
    sale_amount = float(data.get("saleAmount") or 0)
    revenue_account = data.get("revenueAccount") or "Sales"
    payment_account = data.get("paymentAccount") or "Cash"
    if not date or quantity <= 0 or sale_amount <= 0:
        return jsonify({"error": "Date, a positive quantity, and a positive sale amount are required."}), 400

    db = get_db()
    item = db.execute("SELECT * FROM stock_items WHERE id = ? AND company_id = ?", (item_id, company_id)).fetchone()
    if item is None:
        return jsonify({"error": "Stock item not found."}), 404

    layers = db.execute(
        "SELECT id, quantity_remaining, unit_cost_pence FROM stock_layers "
        "WHERE company_id = ? AND stock_item_id = ? AND quantity_remaining > 0 ORDER BY date, id",
        (company_id, item_id),
    ).fetchall()
    available = sum(l["quantity_remaining"] for l in layers)
    if quantity > available:
        return jsonify({"error": f"Only {available} unit(s) on hand — can't sell {quantity}."}), 400

    # consume the oldest layers first (FIFO) until the sold quantity is covered
    remaining_to_consume = quantity
    cogs_pence = 0
    for layer in layers:
        if remaining_to_consume <= 0:
            break
        take = min(layer["quantity_remaining"], remaining_to_consume)
        cogs_pence += round(take * layer["unit_cost_pence"])
        db.execute(
            "UPDATE stock_layers SET quantity_remaining = quantity_remaining - ? WHERE id = ?",
            (take, layer["id"]),
        )
        remaining_to_consume -= take

    journal_id = uuid.uuid4().hex
    try:
        revenue_tx_id = post_ledger_transaction(
            db, company_id, date, f"Stock sale — {item['name']}", sale_amount, payment_account, revenue_account,
            journal_id=journal_id,
        )
        cogs_tx_id = post_ledger_transaction(
            db, company_id, date, f"Cost of stock sold — {item['name']}", from_pence(cogs_pence),
            item["cogs_account"], item["stock_account"], journal_id=journal_id,
        )
    except LedgerError as e:
        db.rollback()
        return jsonify({"error": e.message}), e.status

    db.execute(
        "INSERT INTO stock_sales (company_id, stock_item_id, date, quantity, cogs_pence, sale_amount_pence, revenue_transaction_id, cogs_transaction_id) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (company_id, item_id, date, quantity, cogs_pence, to_pence(sale_amount), revenue_tx_id, cogs_tx_id),
    )
    db.commit()
    return jsonify({"revenueTransactionId": revenue_tx_id, "cogsTransactionId": cogs_tx_id, "cogs": from_pence(cogs_pence)})


@app.route("/api/companies/<int:company_id>/sofa", methods=["GET"])
@login_required
@company_required
def statement_of_financial_activities(company_id):
    """Charity SORP-style Statement of Financial Activities: incoming resources and resources
    expended, segmented by fund type. Built from the same ledger as the standard P&L — a
    transaction's fund tag plus its account's revenue/expense classification is all this needs.
    Scoped to net movement in funds for the period; cumulative funds-carried-forward across
    periods isn't tracked yet (that would need fund-level opening balances, a further extension)."""
    db = get_db()
    rows = db.execute(
        "SELECT t.amount_pence, t.debit, t.credit, a_debit.type as debitType, a_credit.type as creditType, "
        "f.type as fundType, f.name as fundName "
        "FROM transactions t "
        "LEFT JOIN funds f ON f.id = t.fund_id "
        "LEFT JOIN accounts a_debit ON a_debit.company_id = t.company_id AND a_debit.name = t.debit COLLATE NOCASE "
        "LEFT JOIN accounts a_credit ON a_credit.company_id = t.company_id AND a_credit.name = t.credit COLLATE NOCASE "
        "WHERE t.company_id = ? AND t.voided_at IS NULL",
        (company_id,),
    ).fetchall()

    by_fund_type = {t: {"incoming": 0, "expended": 0} for t in VALID_FUND_TYPES}
    by_fund_type["unfunded"] = {"incoming": 0, "expended": 0}  # transactions with no fund tag at all
    fund_columns = VALID_FUND_TYPES + ("unfunded",)

    # Charity SORP presents the SOFA columnar — fund types across the top, income/expenditure
    # categories (accounts) down the side — rather than fund types as rows. income_by_account /
    # expenditure_by_account build that: {account_name: {fund_type: amount, ...}}.
    income_by_account = {}
    expenditure_by_account = {}

    for r in rows:
        amount = from_pence(r["amount_pence"])
        fund_type = r["fundType"] or "unfunded"
        if r["creditType"] in ("revenue", "cogs"):
            by_fund_type[fund_type]["incoming"] += amount
            bucket = income_by_account.setdefault(r["credit"], {ft: 0 for ft in fund_columns})
            bucket[fund_type] += amount
        if r["debitType"] == "expense":
            by_fund_type[fund_type]["expended"] += amount
            bucket = expenditure_by_account.setdefault(r["debit"], {ft: 0 for ft in fund_columns})
            bucket[fund_type] += amount

    for bucket in by_fund_type.values():
        bucket["net"] = bucket["incoming"] - bucket["expended"]

    total_incoming = sum(b["incoming"] for b in by_fund_type.values())
    total_expended = sum(b["expended"] for b in by_fund_type.values())

    return jsonify({
        "byFundType": by_fund_type,
        "totalIncoming": total_incoming,
        "totalExpended": total_expended,
        "netMovement": total_incoming - total_expended,
        "fundColumns": list(fund_columns),
        "incomeByAccount": income_by_account,
        "expenditureByAccount": expenditure_by_account,
    })


# ---------- opening balances ----------

@app.route("/api/companies/<int:company_id>/opening-balances", methods=["GET"])
@login_required
@company_required
def list_opening_balances(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT ob.id, a.name as account, a.type as accountType, ob.amount_pence as amountPence, "
        "ob.side, ob.as_of_date as asOfDate "
        "FROM opening_balances ob JOIN accounts a ON a.id = ob.account_id "
        "WHERE ob.company_id = ?",
        (company_id,),
    ).fetchall()
    result = [dict(r) for r in rows]
    for r in result:
        r["amount"] = from_pence(r.pop("amountPence"))
    return jsonify(result)


@app.route("/api/companies/<int:company_id>/opening-balances/bulk", methods=["POST"])
@login_required
@company_required
@write_required
def set_opening_balances(company_id):
    items = request.get_json(force=True) or []
    db = get_db()
    saved = 0
    for it in items:
        account_name, amount, side, as_of_date = (
            it.get("account"), it.get("amount"), it.get("side"), it.get("asOfDate")
        )
        if not all([account_name, side, as_of_date]) or not amount or float(amount) <= 0:
            continue
        if side not in ("debit", "credit"):
            continue
        canonical_name = resolve_account(db, company_id, account_name)
        account = get_account_by_name(db, company_id, canonical_name)
        db.execute(
            "INSERT INTO opening_balances (company_id, account_id, amount_pence, side, as_of_date) VALUES (?,?,?,?,?) "
            "ON CONFLICT(company_id, account_id) DO UPDATE SET amount_pence = excluded.amount_pence, "
            "side = excluded.side, as_of_date = excluded.as_of_date",
            (company_id, account["id"], to_pence(amount), side, as_of_date),
        )
        saved += 1
    db.commit()
    return jsonify({"saved": saved})


@app.route("/api/companies/<int:company_id>/opening-balances/<int:ob_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_opening_balance(company_id, ob_id):
    db = get_db()
    db.execute("DELETE FROM opening_balances WHERE id = ? AND company_id = ?", (ob_id, company_id))
    db.commit()
    return jsonify({"ok": True})


# ---------- transactions ----------

def _valid_vat_direction(v):
    return v in ("", "input", "output")


def _serialize_transaction(row):
    d = dict(row)
    d["amount"] = from_pence(d.pop("amountPence"))
    if "foreignAmountPence" in d:
        d["foreignAmount"] = from_pence(d.pop("foreignAmountPence")) if d["foreignAmountPence"] is not None else None
    return d


@app.route("/api/companies/<int:company_id>/transactions", methods=["GET"])
@login_required
@company_required
def list_transactions(company_id):
    db = get_db()
    include_voided = request.args.get("includeVoided") == "1"
    voided_clause = "" if include_voided else "AND voided_at IS NULL"
    rows = db.execute(
        f"SELECT t.id, t.date, t.desc, t.amount_pence as amountPence, t.debit, t.credit, t.tax_year as taxYear, "
        f"t.vat_rate as vatRate, t.vat_direction as vatDirection, t.confidence, t.journal_id as journalId, "
        f"t.voided_at as voidedAt, t.voided_by as voidedBy, t.reviewed_by as reviewedBy, t.reviewed_at as reviewedAt, "
        f"f.name as fund, d.name as department, t.currency, t.foreign_amount_pence as foreignAmountPence, t.exchange_rate as exchangeRate, "
        f"(SELECT COUNT(*) FROM attachments a WHERE a.transaction_id = t.id) as attachmentCount, "
        f"(SELECT COUNT(*) FROM transaction_comments c WHERE c.transaction_id = t.id) as commentCount "
        f"FROM transactions t LEFT JOIN funds f ON f.id = t.fund_id LEFT JOIN departments d ON d.id = t.department_id "
        f"WHERE t.company_id = ? {voided_clause} ORDER BY t.date",
        (company_id,),
    ).fetchall()
    return jsonify([_serialize_transaction(r) for r in rows])


@app.route("/api/companies/<int:company_id>/search", methods=["GET"])
@login_required
@company_required
def search(company_id):
    q = (request.args.get("q") or "").strip()
    if not q:
        return jsonify({"transactions": [], "accounts": [], "contacts": []})
    db = get_db()
    like = f"%{q}%"
    transactions_out = [
        _serialize_transaction(r) for r in db.execute(
            "SELECT t.id, t.date, t.desc, t.amount_pence as amountPence, t.debit, t.credit, t.tax_year as taxYear, "
            "t.vat_rate as vatRate, t.vat_direction as vatDirection, t.confidence, t.journal_id as journalId, "
            "t.voided_at as voidedAt, t.voided_by as voidedBy, t.reviewed_by as reviewedBy, t.reviewed_at as reviewedAt, "
            "NULL as fund, 0 as attachmentCount, 0 as commentCount "
            "FROM transactions t WHERE t.company_id = ? AND t.voided_at IS NULL AND t.desc LIKE ? "
            "ORDER BY t.date DESC LIMIT 50",
            (company_id, like),
        ).fetchall()
    ]
    accounts_out = [dict(r) for r in db.execute(
        "SELECT id, code, name, type FROM accounts WHERE company_id = ? AND name LIKE ? ORDER BY name LIMIT 50",
        (company_id, like),
    ).fetchall()]
    contacts_out = [dict(r) for r in db.execute(
        "SELECT id, name, type, email FROM contacts WHERE company_id = ? AND name LIKE ? ORDER BY name LIMIT 50",
        (company_id, like),
    ).fetchall()]
    return jsonify({"transactions": transactions_out, "accounts": accounts_out, "contacts": contacts_out})


class LedgerError(Exception):
    def __init__(self, message, status=400):
        self.message = message
        self.status = status


def post_ledger_transaction(db, company_id, date, desc, amount, debit, credit,
                             vat_rate=0, vat_direction="", confidence="high", journal_id=None, fund_id=None,
                             department_id=None, currency=None, exchange_rate=None):
    """Shared insert path for anything that writes to the ledger — manual entries, bulk
    imports, invoice/bill send-and-pay postings, and (Stage 2) compound journal legs — so
    they all get the same account resolution, locking check, preset learning, and audit trail.

    tax_year is NOT a caller-supplied parameter: a client (or a bulk-import row) could otherwise
    claim any tax year it likes. It's always derived here from the transaction date against the
    company's own fiscal-year anchor (companies.period_start_date)."""
    if not all([date, desc, debit, credit]) or not amount or float(amount) <= 0 or debit == credit:
        raise LedgerError("Invalid transaction.")
    if not _valid_vat_direction(vat_direction):
        raise LedgerError("Invalid VAT direction.")
    if is_locked(g.company, date):
        raise LedgerError(f"This period is locked until {g.company['locked_until']} — unlock it in settings first.", 423)

    debit = resolve_account(db, company_id, debit)
    credit = resolve_account(db, company_id, credit)

    if vat_direction:
        credit_type = get_account_by_name(db, company_id, credit)["type"]
        debit_type = get_account_by_name(db, company_id, debit)["type"]
        if credit_type == "revenue" and vat_direction != "output":
            raise LedgerError('VAT on a sale (credit to a revenue account) must use vatDirection "output".')
        if debit_type in ("expense", "cogs") and vat_direction != "input":
            raise LedgerError('VAT on a purchase (debit to an expense/COGS account) must use vatDirection "input".')

    tax_year = compute_tax_year(date, g.company["period_start_date"])

    # Multi-currency: `amount` is treated as the FOREIGN amount when currency+exchange_rate are
    # given, converted to the company's base currency here before anything downstream (VAT
    # split, account resolution, etc.) ever sees it — every other report in this app assumes
    # amount_pence is already in one currency and stays correct unmodified. foreign_amount_pence
    # and exchange_rate are stored on the main leg only, as the basis for a later FX revaluation.
    foreign_pence = None
    if currency and exchange_rate:
        foreign_pence = to_pence(amount)
        amount = amount * float(exchange_rate)

    # VAT is posted as a real second ledger row, not client-side display math: a "gross" amount
    # carrying VAT is split here into a net leg (the original debit/credit pair) and a VAT leg
    # against the VAT Control Account, sharing one journal_id. This is what makes consolidation
    # and the Statement of Financial Activities — which sum transactions.debit/credit directly —
    # see the VAT control balance at all; previously it only existed as client-side JS math that
    # those server-side reports never ran.
    gross_pence = to_pence(amount)
    vat_rate = float(vat_rate or 0)
    vat_pence = round(gross_pence * vat_rate / (100 + vat_rate)) if vat_rate > 0 and vat_direction else 0
    net_pence = gross_pence - vat_pence
    leg_journal_id = journal_id or (uuid.uuid4().hex if vat_pence else None)

    cur = db.execute(
        "INSERT INTO transactions (company_id, date, desc, amount_pence, debit, credit, tax_year, vat_rate, vat_direction, confidence, journal_id, fund_id, department_id, currency, foreign_amount_pence, exchange_rate) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (company_id, date, desc, net_pence, debit, credit, tax_year, vat_rate, vat_direction, confidence, leg_journal_id, fund_id, department_id, currency, foreign_pence, exchange_rate),
    )
    main_id = cur.lastrowid

    if vat_pence:
        vat_account = resolve_account(db, company_id, "VAT Control Account", "current_liability")
        if vat_direction == "input":  # purchase: VAT is reclaimable, sits as a debit
            vat_debit, vat_credit = vat_account, credit
        else:  # output: sale, VAT is owed to HMRC, sits as a credit
            vat_debit, vat_credit = debit, vat_account
        db.execute(
            "INSERT INTO transactions (company_id, date, desc, amount_pence, debit, credit, tax_year, vat_rate, vat_direction, confidence, journal_id, fund_id, department_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (company_id, date, f"{desc} (VAT)", vat_pence, vat_debit, vat_credit, tax_year, vat_rate, vat_direction, confidence, leg_journal_id, fund_id, department_id),
        )

    db.execute(
        "INSERT INTO presets (company_id, desc_key, debit, credit) VALUES (?,?,?,?) "
        "ON CONFLICT(company_id, desc_key) DO UPDATE SET debit = excluded.debit, credit = excluded.credit",
        (company_id, desc.strip().lower(), debit, credit),
    )
    log_audit(db, company_id, "create", "transaction", main_id, after={
        "date": date, "desc": desc, "amount": amount, "debit": debit, "credit": credit
    })
    return main_id


@app.route("/api/companies/<int:company_id>/transactions", methods=["POST"])
@login_required
@company_required
@write_required
def create_transaction(company_id):
    data = request.get_json(force=True) or {}
    db = get_db()
    try:
        fund_id = resolve_fund_id(db, company_id, data.get("fund"))
        department_id = resolve_department_id(db, company_id, data.get("department"))
        tx_id = post_ledger_transaction(
            db, company_id, data.get("date"), data.get("desc"), data.get("amount"),
            data.get("debit"), data.get("credit"),
            float(data.get("vatRate") or 0), data.get("vatDirection") or "",
            data.get("confidence") or "high", fund_id=fund_id, department_id=department_id,
            currency=data.get("currency") or None, exchange_rate=float(data["exchangeRate"]) if data.get("exchangeRate") else None,
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status
    db.commit()
    return jsonify({"id": tx_id})


@app.route("/api/companies/<int:company_id>/transactions/bulk", methods=["POST"])
@login_required
@company_required
@write_required
def bulk_create_transactions(company_id):
    payload = request.get_json(force=True) or []
    # Back-compat: callers that already worked send a bare array. CSV import sends an object with
    # reviewUnsure=true, which opts into routing incomplete/placeholder rows to the clarification
    # queue instead of silently posting them against an "Unknown"/"Uncategorized" account.
    if isinstance(payload, dict):
        items = payload.get("items") or []
        review_unsure = bool(payload.get("reviewUnsure"))
    else:
        items, review_unsure = payload, False

    PLACEHOLDER_ACCOUNTS = {"", "unknown", "uncategorized", "uncategorised"}

    def is_unsure(it):
        if not it.get("date") or not it.get("desc"):
            return True
        for side in (it.get("debit"), it.get("credit")):
            if (side or "").strip().lower() in PLACEHOLDER_ACCOUNTS:
                return True
        return False

    db = get_db()
    inserted = 0
    skipped_locked = 0
    queued = 0
    for it in items:
        if review_unsure and is_unsure(it):
            db.execute(
                "INSERT INTO clarification_queue (company_id, source, raw_line_json, suggested_debit, "
                "suggested_credit, suggested_amount_pence, confidence, reason) VALUES (?,?,?,?,?,?,?,?)",
                (
                    company_id, "csv", json.dumps({"date": it.get("date"), "desc": it.get("desc"), "amount": it.get("amount")}),
                    it.get("debit") or "", it.get("credit") or "",
                    to_pence(it.get("amount") or 0), 0.2,
                    "Imported CSV row with a missing field or an uncategorised debit/credit account.",
                ),
            )
            queued += 1
            continue
        try:
            fund_id = resolve_fund_id(db, company_id, it.get("fund"))
            post_ledger_transaction(
                db, company_id, it.get("date"), it.get("desc"), it.get("amount"),
                it.get("debit"), it.get("credit"),
                float(it.get("vatRate") or 0), it.get("vatDirection") or "",
                it.get("confidence") or "high", fund_id=fund_id,
            )
        except LedgerError as e:
            if e.status == 423:
                skipped_locked += 1
            continue
        inserted += 1
    db.commit()
    return jsonify({"inserted": inserted, "skippedLocked": skipped_locked, "queued": queued})


@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def void_transaction(company_id, tx_id):
    db = get_db()
    row = db.execute(
        "SELECT date, desc, amount_pence as amountPence, debit, credit, journal_id as journalId FROM transactions "
        "WHERE id = ? AND company_id = ? AND voided_at IS NULL",
        (tx_id, company_id),
    ).fetchone()
    if row is None:
        return jsonify({"ok": True})
    if is_locked(g.company, row["date"]):
        return jsonify({"error": f"This period is locked until {g.company['locked_until']} — unlock it in settings first."}), 423
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    # A transaction sharing a journal_id (a VAT leg, or a compound-journal leg) was never meant
    # to stand alone — voiding just one row would leave the books unbalanced. Void the whole
    # journal together.
    ids_to_void = [tx_id]
    if row["journalId"]:
        ids_to_void = [r["id"] for r in db.execute(
            "SELECT id FROM transactions WHERE company_id = ? AND journal_id = ? AND voided_at IS NULL",
            (company_id, row["journalId"]),
        ).fetchall()]
    db.executemany(
        "UPDATE transactions SET voided_at = ?, voided_by = ? WHERE id = ? AND company_id = ?",
        [(now, session.get("email", "unknown"), i, company_id) for i in ids_to_void],
    )
    log_audit(db, company_id, "void", "transaction", tx_id, before=_serialize_transaction(row))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>/review", methods=["POST"])
@login_required
@company_required
def review_transaction(company_id, tx_id):
    """Separate from who POSTED a transaction — a second pair of eyes (e.g. an invited
    accountant) marking it checked. Any access level can review; reviewing isn't a ledger
    mutation in the accounting sense, just an annotation, so it's not write_required-gated."""
    db = get_db()
    row = db.execute("SELECT id FROM transactions WHERE id = ? AND company_id = ?", (tx_id, company_id)).fetchone()
    if row is None:
        return jsonify({"error": "Not found."}), 404
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db.execute(
        "UPDATE transactions SET reviewed_by = ?, reviewed_at = ? WHERE id = ? AND company_id = ?",
        (session.get("email", "unknown"), now, tx_id, company_id),
    )
    log_audit(db, company_id, "review", "transaction", tx_id, after={"reviewedBy": session.get("email")})
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>/unreview", methods=["POST"])
@login_required
@company_required
def unreview_transaction(company_id, tx_id):
    db = get_db()
    db.execute(
        "UPDATE transactions SET reviewed_by = NULL, reviewed_at = NULL WHERE id = ? AND company_id = ?",
        (tx_id, company_id),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/transactions/clear", methods=["POST"])
@login_required
@company_required
@write_required
def clear_transactions(company_id):
    db = get_db()
    locked_until = g.company["locked_until"] or ""
    rows = db.execute(
        "SELECT id, date, desc, amount_pence as amountPence, debit, credit FROM transactions "
        "WHERE company_id = ? AND voided_at IS NULL",
        (company_id,),
    ).fetchall()
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    voided = 0
    for row in rows:
        if locked_until and row["date"] <= locked_until:
            continue
        db.execute(
            "UPDATE transactions SET voided_at = ?, voided_by = ? WHERE id = ?",
            (now, session.get("email", "unknown"), row["id"]),
        )
        log_audit(db, company_id, "void", "transaction", row["id"], before=_serialize_transaction(row))
        voided += 1
    db.commit()
    return jsonify({"ok": True, "deleted": voided, "skippedLocked": len(rows) - voided})


# ---------- compound journals ----------
#
# The ledger's core model is deliberately a single debit/credit pair per row — everything
# built on top of it (VAT splitting, the Cash Flow Statement, bank reconciliation, fixed
# asset depreciation) was built and tested against that shape. Rather than rip that out for
# a full N-line journal_lines table — the single highest-risk change available — a compound
# entry here is decomposed into one two-line transaction per non-pivot account, all sharing
# a journal_id. This is mathematically identical to one true multi-line posting whenever
# every line shares one common pivot account (the overwhelmingly common real case: one
# payment split across several expense categories, or one receipt split across several
# income categories) — double-entry is linear, so summing N two-line postings against the
# same pivot has the exact same net ledger effect as one N-line posting would.

@app.route("/api/companies/<int:company_id>/journals", methods=["POST"])
@login_required
@company_required
@write_required
def create_compound_journal(company_id):
    data = request.get_json(force=True) or {}
    date, desc, pivot_account, pivot_side, lines = (
        data.get("date"), data.get("desc"), data.get("pivotAccount"), data.get("pivotSide"), data.get("lines") or []
    )
    if not all([date, desc, pivot_account]) or pivot_side not in ("debit", "credit"):
        return jsonify({"error": "Date, description, a pivot account, and its side are required."}), 400
    valid_lines = [
        ln for ln in lines
        if ln.get("account") and ln.get("amount") and float(ln["amount"]) > 0 and ln["account"] != pivot_account
    ]
    if len(valid_lines) < 2:
        return jsonify({"error": "A compound journal needs at least 2 lines (besides the pivot account)."}), 400

    db = get_db()
    journal_id = uuid.uuid4().hex
    posted = []
    try:
        for ln in valid_lines:
            account = ln["account"]
            amount = float(ln["amount"])
            if pivot_side == "credit":
                # money is going OUT of the pivot (e.g. one bank payment split across several expenses)
                debit, credit = account, pivot_account
            else:
                # money is coming IN to the pivot (e.g. one receipt split across several income lines)
                debit, credit = pivot_account, account
            tx_id = post_ledger_transaction(
                db, company_id, date, f"{desc} ({account})", amount, debit, credit,
                journal_id=journal_id,
            )
            posted.append(tx_id)
    except LedgerError as e:
        db.rollback()
        return jsonify({"error": e.message}), e.status

    db.commit()
    total = sum(float(ln["amount"]) for ln in valid_lines)
    return jsonify({"journalId": journal_id, "transactionIds": posted, "total": total})


# ---------- AI categorization (Stage 5: server-side, key never reaches the browser) ----------
# ---------- + clarification queue (Stage 8): anything ingested that we can't confidently
# categorize gets parked here instead of silently posted or guessed, per the "unsure" rules below.

def score_candidate_confidence(db, company_id, candidate, seen_amount_dates):
    """Returns (score 0..1, reasons[]) for one AI-suggested line. Starts at 1.0 and subtracts for
    each red flag from the agreed "what counts as unsure" rules — account doesn't exist, the
    description is too thin to trust, the date is suspiciously old, the amount is a repeat within
    this same batch (possible duplicate), or the amount is a statistical outlier for that account's
    history (the same test the Anomaly detector uses, applied here before posting rather than
    after)."""
    score = 1.0
    reasons = []

    debit_acc = get_account_by_name(db, company_id, candidate.get("debit", ""))
    credit_acc = get_account_by_name(db, company_id, candidate.get("credit", ""))
    if debit_acc is None or credit_acc is None:
        score -= 0.35
        reasons.append("Suggested account doesn't exist in the chart of accounts yet")

    word_count = len((candidate.get("desc") or "").split())
    if word_count <= 3:
        score -= 0.2
        reasons.append("Description is too short to categorise confidently")

    try:
        candidate_date = datetime.date.fromisoformat(candidate.get("date", ""))
        if (datetime.date.today() - candidate_date).days > 90:
            score -= 0.15
            reasons.append("Date is more than 90 days old")
    except (ValueError, TypeError):
        score -= 0.3
        reasons.append("Date could not be parsed")

    amount = candidate.get("amount")
    key = (candidate.get("date"), round(float(amount), 2) if amount else None)
    if key in seen_amount_dates:
        score -= 0.2
        reasons.append("Same amount and date appears more than once in this import — possible duplicate")
    seen_amount_dates.add(key)

    if debit_acc is not None and amount:
        history = db.execute(
            "SELECT amount_pence FROM transactions WHERE company_id = ? AND debit = ? AND voided_at IS NULL",
            (company_id, debit_acc["name"]),
        ).fetchall()
        amounts = [from_pence(r["amount_pence"]) for r in history]
        if len(amounts) >= 4:
            mean = sum(amounts) / len(amounts)
            variance = sum((a - mean) ** 2 for a in amounts) / len(amounts)
            stddev = variance ** 0.5
            if stddev > 0.01 and abs(float(amount) - mean) / stddev > 3:
                score -= 0.25
                reasons.append(f'Amount is a statistical outlier for "{debit_acc["name"]}" — typically around {mean:.2f}')

    return max(0.0, min(1.0, score)), reasons


@app.route("/api/companies/<int:company_id>/ai-categorize", methods=["POST"])
@login_required
@company_required
@write_required
@rate_limit(max_attempts=20, window_seconds=3600)
def ai_categorize(company_id):
    data = request.get_json(force=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Nothing to analyze."}), 400
    api_key = decrypt_secret(g.company["ai_api_key"])
    if not api_key:
        return jsonify({"error": "No Claude API key set for this company — add one in settings."}), 400

    db = get_db()
    known_accounts = [r["name"] for r in db.execute(
        "SELECT name FROM accounts WHERE company_id = ? ORDER BY name", (company_id,)
    ).fetchall()]
    today = datetime.date.today().isoformat()

    prompt = f"""You are a bookkeeping assistant doing double-entry classification for a small UK business.
Known chart of accounts already in use (reuse these names exactly when they fit, only invent a new account name when nothing fits): {', '.join(known_accounts) or '(none yet — use sensible standard account names)'}

For each line below, identify it as one bank/cash movement and decide:
- date (YYYY-MM-DD; if no date is present, use {today})
- desc: a short clean description
- amount: a positive number
- debit: the account that receives value
- credit: the account value comes from

Money going OUT of the bank/cash account is typically Debit = expense/asset category, Credit = Cash.
Money coming IN is typically Debit = Cash, Credit = Sales/Trade Recievables/income category.
Skip lines that aren't real transactions (headers, balances, page numbers, etc).

Return ONLY a JSON array, no prose, no markdown fences:
[{{"date":"YYYY-MM-DD","desc":"...","amount":0.00,"debit":"...","credit":"..."}}]

Lines:
{text}"""

    try:
        raw_text = call_claude(api_key, [{"role": "user", "content": prompt}], max_tokens=4096)
    except urllib.error.HTTPError as e:
        return jsonify({"error": f"Anthropic API error {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"}), 502
    except urllib.error.URLError as e:
        return jsonify({"error": f"Could not reach Anthropic API: {e.reason}"}), 502

    match = re.search(r"\[[\s\S]*\]", raw_text)
    if not match:
        return jsonify({"error": "Claude did not return a parseable list."}), 502
    try:
        items = json.loads(match.group(0))
    except json.JSONDecodeError:
        return jsonify({"error": "Claude's response wasn't valid JSON."}), 502

    candidates = [
        it for it in items
        if it.get("date") and it.get("desc") and it.get("amount") and it.get("debit") and it.get("credit")
    ]

    threshold = g.company["confidence_threshold"]
    ready, queued, seen_amount_dates = [], [], set()
    for it in candidates:
        confidence, reasons = score_candidate_confidence(db, company_id, it, seen_amount_dates)
        if confidence < threshold:
            db.execute(
                "INSERT INTO clarification_queue (company_id, source, raw_line_json, suggested_debit, "
                "suggested_credit, suggested_amount_pence, confidence, reason) VALUES (?,?,?,?,?,?,?,?)",
                (
                    company_id, "ai", json.dumps(it), it["debit"], it["credit"],
                    to_pence(it["amount"]), confidence, "; ".join(reasons),
                ),
            )
            queued.append(it)
        else:
            ready.append(it)
    if queued:
        db.commit()
    return jsonify({"candidates": ready, "queuedCount": len(queued)})


def _serialize_clarification(row):
    d = dict(row)
    d["rawLine"] = json.loads(d.pop("raw_line_json"))
    d["suggestedDebit"] = d.pop("suggested_debit")
    d["suggestedCredit"] = d.pop("suggested_credit")
    d["suggestedAmount"] = from_pence(d.pop("suggested_amount_pence"))
    d["createdAt"] = d.pop("created_at")
    d["resolvedAt"] = d.pop("resolved_at")
    d["resolvedBy"] = d.pop("resolved_by")
    return d


@app.route("/api/companies/<int:company_id>/clarification-queue", methods=["GET"])
@login_required
@company_required
def list_clarification_queue(company_id):
    db = get_db()
    status = request.args.get("status", "pending")
    rows = db.execute(
        "SELECT * FROM clarification_queue WHERE company_id = ? AND status = ? ORDER BY created_at",
        (company_id, status),
    ).fetchall()
    return jsonify([_serialize_clarification(r) for r in rows])


@app.route("/api/companies/<int:company_id>/clarification-queue/<int:item_id>/resolve", methods=["POST"])
@login_required
@company_required
@write_required
def resolve_clarification(company_id, item_id):
    db = get_db()
    item = db.execute(
        "SELECT * FROM clarification_queue WHERE id = ? AND company_id = ? AND status = 'pending'",
        (item_id, company_id),
    ).fetchone()
    if item is None:
        return jsonify({"error": "Not found, or already resolved."}), 404

    data = request.get_json(force=True) or {}
    raw_line = json.loads(item["raw_line_json"])
    date = data.get("date") or raw_line.get("date")
    desc = data.get("desc") or raw_line.get("desc")
    amount = data.get("amount") or from_pence(item["suggested_amount_pence"])
    debit = data.get("debit") or item["suggested_debit"]
    credit = data.get("credit") or item["suggested_credit"]

    try:
        tx_id = post_ledger_transaction(db, company_id, date, desc, amount, debit, credit)
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status

    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db.execute(
        "UPDATE clarification_queue SET status = 'resolved', resolved_at = ?, resolved_by = ? WHERE id = ?",
        (now, session.get("email", "unknown"), item_id),
    )
    db.commit()
    return jsonify({"ok": True, "transactionId": tx_id})


@app.route("/api/companies/<int:company_id>/clarification-queue/<int:item_id>/skip", methods=["POST"])
@login_required
@company_required
@write_required
def skip_clarification(company_id, item_id):
    db = get_db()
    db.execute(
        "UPDATE clarification_queue SET status = 'skipped' WHERE id = ? AND company_id = ? AND status = 'pending'",
        (item_id, company_id),
    )
    db.commit()
    return jsonify({"ok": True})


def call_claude(api_key, messages, max_tokens=1024):
    payload = json.dumps({"model": "claude-sonnet-4-6", "max_tokens": max_tokens, "messages": messages}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=payload, method="POST",
        headers={"Content-Type": "application/json", "x-api-key": api_key, "anthropic-version": "2023-06-01"},
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    return "".join(block.get("text", "") for block in body.get("content", []))


PLAID_HOSTS = {
    "sandbox": "https://sandbox.plaid.com",
    "development": "https://development.plaid.com",
    "production": "https://production.plaid.com",
}


class PlaidError(Exception):
    def __init__(self, message, status=502):
        self.message = message
        self.status = status


def call_plaid(company, path, payload):
    client_id = (company["plaid_client_id"] or "").strip()
    secret = decrypt_secret(company["plaid_secret"])
    if not client_id or not secret:
        raise PlaidError("No Plaid credentials set for this company — add them in settings.", 400)
    env = company["plaid_env"] or "sandbox"
    host = PLAID_HOSTS.get(env, PLAID_HOSTS["sandbox"])

    body = json.dumps({**payload, "client_id": client_id, "secret": secret}).encode("utf-8")
    req = urllib.request.Request(
        f"{host}{path}", data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", "replace")
        try:
            err_json = json.loads(err_body)
            message = err_json.get("error_message", err_body[:300])
        except json.JSONDecodeError:
            message = err_body[:300]
        raise PlaidError(f"Plaid error: {message}", 502)
    except urllib.error.URLError as e:
        raise PlaidError(f"Could not reach Plaid: {e.reason}", 502)


@app.route("/api/companies/<int:company_id>/ask", methods=["POST"])
@login_required
@company_required
@write_required
@rate_limit(max_attempts=20, window_seconds=3600)
def ask_ledger(company_id):
    """Stage 5 flagship feature: natural-language Q&A over this company's actual ledger.
    The model only sees a compact CSV export built fresh per request — no separate index to
    keep in sync, and the same server-side-key pattern as the rest of Stage 5."""
    data = request.get_json(force=True) or {}
    question = (data.get("question") or "").strip()
    if not question:
        return jsonify({"error": "Ask a question first."}), 400
    api_key = decrypt_secret(g.company["ai_api_key"])
    if not api_key:
        return jsonify({"error": "No Claude API key set for this company — add one in settings."}), 400

    db = get_db()
    rows = db.execute(
        "SELECT date, desc, amount_pence, debit, credit, vat_rate, vat_direction FROM transactions "
        "WHERE company_id = ? AND voided_at IS NULL ORDER BY date",
        (company_id,),
    ).fetchall()

    MAX_ROWS = 3000
    truncated = len(rows) > MAX_ROWS
    csv_lines = ["date,description,amount,debit_account,credit_account,vat_rate,vat_direction"]
    for r in rows[-MAX_ROWS:]:
        amt = from_pence(r["amount_pence"])
        desc = r["desc"].replace(",", ";")
        csv_lines.append(f"{r['date']},{desc},{amt},{r['debit']},{r['credit']},{r['vat_rate']},{r['vat_direction']}")
    ledger_csv = "\n".join(csv_lines)

    today = datetime.date.today().isoformat()
    prompt = f"""You are a financial assistant answering a question about a small UK business's bookkeeping ledger.
Today's date is {today}. Below is the full transaction ledger as CSV (each row is one debit/credit posting).
{"Note: this is only the most recent " + str(MAX_ROWS) + " transactions, the ledger has more history than shown." if truncated else ""}

Answer the question concisely and specifically, citing actual figures computed from this data — don't guess or
estimate. If the data doesn't contain what's needed to answer, say so plainly rather than making something up.

Ledger CSV:
{ledger_csv}

Question: {question}"""

    try:
        answer = call_claude(api_key, [{"role": "user", "content": prompt}], max_tokens=1024)
    except urllib.error.HTTPError as e:
        return jsonify({"error": f"Anthropic API error {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"}), 502
    except urllib.error.URLError as e:
        return jsonify({"error": f"Could not reach Anthropic API: {e.reason}"}), 502

    return jsonify({"answer": answer.strip(), "transactionsConsidered": min(len(rows), MAX_ROWS), "truncated": truncated})


# ---------- attachments ----------

ALLOWED_ATTACHMENT_TYPES = {"application/pdf", "image/png", "image/jpeg", "image/heic", "image/webp"}


@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>/attachments", methods=["GET"])
@login_required
@company_required
def list_attachments(company_id, tx_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, filename, mime_type as mimeType, uploaded_by as uploadedBy, uploaded_at as uploadedAt "
        "FROM attachments WHERE company_id = ? AND transaction_id = ? ORDER BY uploaded_at",
        (company_id, tx_id),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>/attachments", methods=["POST"])
@login_required
@company_required
@write_required
def upload_attachment(company_id, tx_id):
    db = get_db()
    tx = db.execute("SELECT id FROM transactions WHERE id = ? AND company_id = ?", (tx_id, company_id)).fetchone()
    if tx is None:
        return jsonify({"error": "Transaction not found."}), 404

    file = request.files.get("file")
    if file is None or not file.filename:
        return jsonify({"error": "No file uploaded."}), 400
    mime_type = file.mimetype or mimetypes.guess_type(file.filename)[0] or "application/octet-stream"
    if mime_type not in ALLOWED_ATTACHMENT_TYPES:
        return jsonify({"error": f"Unsupported file type: {mime_type}. Allowed: PDF, PNG, JPEG, HEIC, WEBP."}), 400

    company_dir = UPLOADS_DIR / str(company_id)
    company_dir.mkdir(exist_ok=True)
    safe_name = secure_filename(file.filename) or "upload"
    stored_name = f"{uuid.uuid4().hex}_{safe_name}"
    file.save(str(company_dir / stored_name))

    cur = db.execute(
        "INSERT INTO attachments (company_id, transaction_id, filename, mime_type, stored_path, uploaded_by) "
        "VALUES (?,?,?,?,?,?)",
        (company_id, tx_id, safe_name, mime_type, f"{company_id}/{stored_name}", session.get("email", "unknown")),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid, "filename": safe_name, "mimeType": mime_type})


@app.route("/api/companies/<int:company_id>/attachments/<int:attachment_id>/download", methods=["GET"])
@login_required
@company_required
def download_attachment(company_id, attachment_id):
    db = get_db()
    row = db.execute(
        "SELECT filename, mime_type, stored_path FROM attachments WHERE id = ? AND company_id = ?",
        (attachment_id, company_id),
    ).fetchone()
    if row is None:
        return jsonify({"error": "Not found."}), 404
    directory, filename = row["stored_path"].rsplit("/", 1)
    return send_from_directory(
        str(UPLOADS_DIR / directory), filename, mimetype=row["mime_type"],
        as_attachment=True, download_name=row["filename"],
    )


def extract_receipt_fields(api_key, mime_type, file_bytes):
    """Shared receipt-OCR call: send file bytes to Claude (vision for images, native document
    support for PDFs) and ask it to read off date/description/amount. Used both by the
    post-hoc attachment extractor and the pre-transaction quick-scan endpoint, so there's one
    place that owns the prompt and the response parsing."""
    file_b64 = base64.b64encode(file_bytes).decode("ascii")
    block_type = "document" if mime_type == "application/pdf" else "image"
    prompt_text = (
        "This is a receipt or invoice. Read off the date (YYYY-MM-DD), a short description "
        "(vendor/item), and the total amount paid (a positive number, the gross/final total). "
        'Return ONLY JSON, no prose: {"date":"YYYY-MM-DD","desc":"...","amount":0.00}. '
        'If you genuinely cannot read a field, use null for it.'
    )
    messages = [{
        "role": "user",
        "content": [
            {"type": block_type, "source": {"type": "base64", "media_type": mime_type, "data": file_b64}},
            {"type": "text", "text": prompt_text},
        ],
    }]
    raw_text = call_claude(api_key, messages, max_tokens=1024)
    match = re.search(r"\{[\s\S]*\}", raw_text)
    if not match:
        raise ValueError("Claude did not return a parseable result.")
    return json.loads(match.group(0))


@app.route("/api/companies/<int:company_id>/attachments/<int:attachment_id>/extract", methods=["POST"])
@login_required
@company_required
@write_required
def extract_attachment(company_id, attachment_id):
    """Stage 5 receipt OCR on a file already attached to a transaction."""
    api_key = decrypt_secret(g.company["ai_api_key"])
    if not api_key:
        return jsonify({"error": "No Claude API key set for this company — add one in settings."}), 400

    db = get_db()
    row = db.execute(
        "SELECT filename, mime_type, stored_path FROM attachments WHERE id = ? AND company_id = ?",
        (attachment_id, company_id),
    ).fetchone()
    if row is None:
        return jsonify({"error": "Attachment not found."}), 404

    file_path = UPLOADS_DIR / row["stored_path"]
    if not file_path.exists():
        return jsonify({"error": "Stored file is missing."}), 404
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    try:
        extracted = extract_receipt_fields(api_key, row["mime_type"], file_bytes)
    except urllib.error.HTTPError as e:
        return jsonify({"error": f"Anthropic API error {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"}), 502
    except urllib.error.URLError as e:
        return jsonify({"error": f"Could not reach Anthropic API: {e.reason}"}), 502
    except (ValueError, json.JSONDecodeError) as e:
        return jsonify({"error": str(e) or "Claude's response wasn't valid JSON."}), 502
    return jsonify(extracted)


@app.route("/api/companies/<int:company_id>/scan-receipt", methods=["POST"])
@login_required
@company_required
@write_required
def scan_receipt(company_id):
    """Quick-entry receipt capture: OCR a photo BEFORE any transaction exists, so the
    new-transaction form can be pre-filled and posted in one step. Deliberately doesn't persist
    the file — attachments.transaction_id is NOT NULL (a file is always attached to a posted
    transaction), so a scan that's discarded or never posted leaves nothing orphaned. If the
    user wants the receipt kept, they attach it the normal way after posting."""
    api_key = decrypt_secret(g.company["ai_api_key"])
    if not api_key:
        return jsonify({"error": "No Claude API key set for this company — add one in settings."}), 400

    file = request.files.get("file")
    if file is None or not file.filename:
        return jsonify({"error": "No file uploaded."}), 400
    mime_type = file.mimetype or mimetypes.guess_type(file.filename)[0] or "application/octet-stream"
    if mime_type not in ALLOWED_ATTACHMENT_TYPES:
        return jsonify({"error": f"Unsupported file type: {mime_type}. Allowed: PDF, PNG, JPEG, HEIC, WEBP."}), 400

    try:
        extracted = extract_receipt_fields(api_key, mime_type, file.read())
    except urllib.error.HTTPError as e:
        return jsonify({"error": f"Anthropic API error {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"}), 502
    except urllib.error.URLError as e:
        return jsonify({"error": f"Could not reach Anthropic API: {e.reason}"}), 502
    except (ValueError, json.JSONDecodeError) as e:
        return jsonify({"error": str(e) or "Claude's response wasn't valid JSON."}), 502
    return jsonify(extracted)


@app.route("/api/companies/<int:company_id>/attachments/<int:attachment_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_attachment(company_id, attachment_id):
    db = get_db()
    row = db.execute(
        "SELECT stored_path FROM attachments WHERE id = ? AND company_id = ?", (attachment_id, company_id)
    ).fetchone()
    if row is None:
        return jsonify({"ok": True})
    file_path = UPLOADS_DIR / row["stored_path"]
    if file_path.exists():
        file_path.unlink()
    db.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
    db.commit()
    return jsonify({"ok": True})


# ---------- transaction comments (#14) ----------

@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>/comments", methods=["GET"])
@login_required
@company_required
def list_transaction_comments(company_id, tx_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, author, body, created_at as createdAt FROM transaction_comments "
        "WHERE company_id = ? AND transaction_id = ? ORDER BY created_at",
        (company_id, tx_id),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>/comments", methods=["POST"])
@login_required
@company_required
@comment_required
def add_transaction_comment(company_id, tx_id):
    db = get_db()
    tx = db.execute("SELECT id FROM transactions WHERE id = ? AND company_id = ?", (tx_id, company_id)).fetchone()
    if tx is None:
        return jsonify({"error": "Transaction not found."}), 404
    body = (request.get_json(force=True) or {}).get("body", "").strip()
    if not body:
        return jsonify({"error": "Comment can't be empty."}), 400
    cur = db.execute(
        "INSERT INTO transaction_comments (company_id, transaction_id, author, body) VALUES (?,?,?,?)",
        (company_id, tx_id, session.get("email", "unknown"), body),
    )
    db.commit()
    row = db.execute(
        "SELECT id, author, body, created_at as createdAt FROM transaction_comments WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(dict(row))


@app.route("/api/companies/<int:company_id>/comments/<int:comment_id>", methods=["DELETE"])
@login_required
@company_required
@comment_required
def delete_transaction_comment(company_id, comment_id):
    """Owners can clear up any comment; everyone else (post/comment-permission members,
    including an invited accountant) can only delete their own."""
    db = get_db()
    row = db.execute("SELECT author FROM transaction_comments WHERE id = ? AND company_id = ?", (comment_id, company_id)).fetchone()
    if row is not None and g.company_permission != "owner" and row["author"] != session.get("email"):
        return jsonify({"error": "You can only delete your own comments."}), 403
    db.execute("DELETE FROM transaction_comments WHERE id = ? AND company_id = ?", (comment_id, company_id))
    db.commit()
    return jsonify({"ok": True})


# ---------- presets ----------

@app.route("/api/companies/<int:company_id>/presets", methods=["GET"])
@login_required
@company_required
def list_presets(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT desc_key, debit, credit FROM presets WHERE company_id = ?", (company_id,)
    ).fetchall()
    return jsonify({r["desc_key"]: {"debit": r["debit"], "credit": r["credit"]} for r in rows})


# ---------- contacts ----------

@app.route("/api/companies/<int:company_id>/contacts", methods=["GET"])
@login_required
@company_required
def list_contacts(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, name, type, email, phone FROM contacts WHERE company_id = ? ORDER BY name",
        (company_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/contacts", methods=["POST"])
@login_required
@company_required
@write_required
def create_contact(company_id):
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Contact name is required."}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO contacts (company_id, name, type, email, phone) VALUES (?,?,?,?,?)",
        (company_id, name, data.get("type", "customer"), data.get("email", ""), data.get("phone", "")),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/contacts/<int:contact_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_contact(company_id, contact_id):
    db = get_db()
    in_use = db.execute(
        "SELECT COUNT(*) as n FROM invoices_bills WHERE company_id = ? AND contact_id = ?",
        (company_id, contact_id),
    ).fetchone()["n"]
    if in_use:
        return jsonify({"error": f"This contact has {in_use} invoice/bill record(s) and can't be deleted."}), 409
    db.execute("DELETE FROM contacts WHERE id = ? AND company_id = ?", (contact_id, company_id))
    db.commit()
    return jsonify({"ok": True})


# ---------- invoices & bills ----------

def _serialize_invoice_bill(row, today):
    d = dict(row)
    d["amount"] = from_pence(d.pop("amountPence"))
    display_status = d["status"]
    if d["status"] == "sent" and d["dueDate"] < today:
        display_status = "overdue"
    d["displayStatus"] = display_status
    return d


@app.route("/api/companies/<int:company_id>/invoices-bills", methods=["GET"])
@login_required
@company_required
def list_invoices_bills(company_id):
    db = get_db()
    today = datetime.date.today().isoformat()
    rows = db.execute(
        "SELECT ib.id, ib.kind, ib.contact_id as contactId, c.name as contactName, ib.date, "
        "ib.due_date as dueDate, ib.desc, ib.amount_pence as amountPence, ib.account, ib.vat_rate as vatRate, "
        "ib.status, ib.transaction_id as transactionId, ib.payment_transaction_id as paymentTransactionId, "
        "ib.linked_doc_id as linkedDocId "
        "FROM invoices_bills ib JOIN contacts c ON c.id = ib.contact_id "
        "WHERE ib.company_id = ? ORDER BY ib.due_date",
        (company_id,),
    ).fetchall()
    return jsonify([_serialize_invoice_bill(r, today) for r in rows])


@app.route("/api/companies/<int:company_id>/invoices-bills", methods=["POST"])
@login_required
@company_required
@write_required
def create_invoice_bill(company_id):
    data = request.get_json(force=True) or {}
    kind, contact_id, date, due_date, desc, amount, account = (
        data.get("kind"), data.get("contactId"), data.get("date"), data.get("dueDate"),
        data.get("desc"), data.get("amount"), data.get("account"),
    )
    if kind not in ("invoice", "bill", "credit_note"):
        return jsonify({"error": "kind must be 'invoice', 'bill', or 'credit_note'."}), 400
    if not all([contact_id, date, due_date, desc, account]) or not amount or float(amount) <= 0:
        return jsonify({"error": "Contact, dates, description, account, and a positive amount are all required."}), 400

    db = get_db()
    linked_doc_id = None
    effective_kind = kind
    if kind == "credit_note":
        linked_doc_id = data.get("linkedDocId")
        linked_doc = db.execute(
            "SELECT kind FROM invoices_bills WHERE id = ? AND company_id = ?", (linked_doc_id, company_id)
        ).fetchone()
        if linked_doc is None:
            return jsonify({"error": "A credit note must link to an existing invoice or bill."}), 400
        effective_kind = linked_doc["kind"]  # a credit note against an invoice behaves like a (reversed) invoice, etc.

    account = resolve_account(db, company_id, account, "revenue" if effective_kind == "invoice" else "expense")
    cur = db.execute(
        "INSERT INTO invoices_bills (company_id, kind, contact_id, date, due_date, desc, amount_pence, account, vat_rate, linked_doc_id) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (company_id, kind, contact_id, date, due_date, desc, to_pence(amount), account, float(data.get("vatRate") or 0), linked_doc_id),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/invoices-bills/<int:doc_id>/send", methods=["POST"])
@login_required
@company_required
@write_required
def send_invoice_bill(company_id, doc_id):
    db = get_db()
    doc = db.execute(
        "SELECT * FROM invoices_bills WHERE id = ? AND company_id = ?", (doc_id, company_id)
    ).fetchone()
    if doc is None:
        return jsonify({"error": "Not found."}), 404
    if doc["status"] != "draft":
        return jsonify({"error": "Only a draft can be sent."}), 400

    amount = from_pence(doc["amount_pence"])
    effective_kind = doc["kind"]
    if doc["kind"] == "credit_note":
        linked = db.execute("SELECT kind FROM invoices_bills WHERE id = ?", (doc["linked_doc_id"],)).fetchone()
        effective_kind = linked["kind"] if linked else "invoice"

    if effective_kind == "invoice":
        debtors_account = resolve_account(db, company_id, "Trade Receivables", "current_asset")
        if doc["kind"] == "credit_note":
            # reverses a normal invoice posting: reduces Sales (or whatever account), reduces
            # what the customer owes — same VAT direction (still an output-VAT adjustment)
            debit, credit, vat_direction = doc["account"], debtors_account, "output"
        else:
            debit, credit, vat_direction = debtors_account, doc["account"], "output"
    else:
        creditors_account = resolve_account(db, company_id, "Trade Payables", "current_liability")
        if doc["kind"] == "credit_note":
            debit, credit, vat_direction = creditors_account, doc["account"], "input"
        else:
            debit, credit, vat_direction = doc["account"], creditors_account, "input"

    label = {"invoice": "Invoice", "bill": "Bill", "credit_note": "Credit note"}[doc["kind"]]
    try:
        tx_id = post_ledger_transaction(
            db, company_id, doc["date"], f'{label}: {doc["desc"]}',
            amount, debit, credit, vat_rate=doc["vat_rate"], vat_direction=vat_direction if doc["vat_rate"] else "",
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status

    # A credit note's ledger effect is fully captured by this one posting — there's no separate
    # "paid" step the way a normal invoice/bill has, so it goes straight to a terminal 'applied'
    # status rather than 'sent' (which would otherwise make it show up as outstanding in the
    # Aging Report and as payable via the /pay endpoint, neither of which is correct for it).
    new_status = "applied" if doc["kind"] == "credit_note" else "sent"
    db.execute(
        "UPDATE invoices_bills SET status = ?, transaction_id = ? WHERE id = ?", (new_status, tx_id, doc_id)
    )
    db.commit()
    return jsonify({"ok": True, "transactionId": tx_id})


@app.route("/api/companies/<int:company_id>/invoices-bills/<int:doc_id>/pay", methods=["POST"])
@login_required
@company_required
@write_required
def pay_invoice_bill(company_id, doc_id):
    data = request.get_json(force=True) or {}
    payment_date = data.get("date") or datetime.date.today().isoformat()
    payment_account = data.get("account") or "Cash"
    cis_deduction = float(data.get("cisDeduction") or 0)

    db = get_db()
    doc = db.execute(
        "SELECT * FROM invoices_bills WHERE id = ? AND company_id = ?", (doc_id, company_id)
    ).fetchone()
    if doc is None:
        return jsonify({"error": "Not found."}), 404
    if doc["status"] != "sent":
        return jsonify({"error": "Only a sent invoice/bill can be marked paid."}), 400

    amount = from_pence(doc["amount_pence"])
    if cis_deduction < 0 or cis_deduction > amount:
        return jsonify({"error": "CIS deduction must be between 0 and the full amount."}), 400
    net_amount = round(amount - cis_deduction, 2)

    try:
        if not cis_deduction:
            if doc["kind"] == "invoice":
                debtors_account = resolve_account(db, company_id, "Trade Receivables", "current_asset")
                debit, credit = payment_account, debtors_account
            else:
                creditors_account = resolve_account(db, company_id, "Trade Payables", "current_liability")
                debit, credit = creditors_account, payment_account
            tx_id = post_ledger_transaction(
                db, company_id, payment_date, f'Payment: {doc["desc"]}', amount, debit, credit
            )
        else:
            # CIS (Construction Industry Scheme): the contractor paying a subcontractor withholds
            # CIS tax from the payment and owes it to HMRC; the subcontractor being paid has that
            # same amount withheld but it's recoverable against their own tax bill ("CIS suffered").
            # Either way the invoice/bill is still settled in FULL — it's just split across two
            # legs sharing one journal_id instead of one Cash leg for the whole amount.
            journal_id = uuid.uuid4().hex
            tx_id = None
            if doc["kind"] == "invoice":
                debtors_account = resolve_account(db, company_id, "Trade Receivables", "current_asset")
                cis_account = resolve_account(db, company_id, "CIS Suffered", "current_asset")
                if net_amount > 0:
                    tx_id = post_ledger_transaction(
                        db, company_id, payment_date, f'Payment: {doc["desc"]}', net_amount,
                        payment_account, debtors_account, journal_id=journal_id,
                    )
                cis_tx_id = post_ledger_transaction(
                    db, company_id, payment_date, f'CIS suffered: {doc["desc"]}', cis_deduction,
                    cis_account, debtors_account, journal_id=journal_id,
                )
            else:
                creditors_account = resolve_account(db, company_id, "Trade Payables", "current_liability")
                cis_account = resolve_account(db, company_id, "CIS Deductions Payable", "current_liability")
                if net_amount > 0:
                    tx_id = post_ledger_transaction(
                        db, company_id, payment_date, f'Payment: {doc["desc"]}', net_amount,
                        creditors_account, payment_account, journal_id=journal_id,
                    )
                cis_tx_id = post_ledger_transaction(
                    db, company_id, payment_date, f'CIS deducted: {doc["desc"]}', cis_deduction,
                    creditors_account, cis_account, journal_id=journal_id,
                )
            tx_id = tx_id or cis_tx_id
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status

    cis_rate = round(cis_deduction / amount * 100, 2) if cis_deduction else None
    db.execute(
        "UPDATE invoices_bills SET status = 'paid', payment_transaction_id = ?, cis_deduction_pence = ?, cis_rate = ? WHERE id = ?",
        (tx_id, to_pence(cis_deduction), cis_rate, doc_id),
    )
    db.commit()
    return jsonify({"ok": True, "transactionId": tx_id})


@app.route("/api/companies/<int:company_id>/invoices-bills/<int:doc_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_invoice_bill(company_id, doc_id):
    db = get_db()
    doc = db.execute(
        "SELECT * FROM invoices_bills WHERE id = ? AND company_id = ?", (doc_id, company_id)
    ).fetchone()
    if doc is None:
        return jsonify({"ok": True})
    # voiding the linked ledger postings keeps the books correct instead of leaving orphaned entries
    for tx_id in (doc["transaction_id"], doc["payment_transaction_id"]):
        if tx_id is None:
            continue
        tx = db.execute(
            "SELECT date, journal_id as journalId FROM transactions WHERE id = ? AND voided_at IS NULL", (tx_id,)
        ).fetchone()
        if tx and not is_locked(g.company, tx["date"]):
            now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
            # a VAT-bearing send/pay posting is two rows sharing a journal_id — void both
            ids_to_void = [tx_id]
            if tx["journalId"]:
                ids_to_void = [r["id"] for r in db.execute(
                    "SELECT id FROM transactions WHERE company_id = ? AND journal_id = ? AND voided_at IS NULL",
                    (company_id, tx["journalId"]),
                ).fetchall()]
            db.executemany(
                "UPDATE transactions SET voided_at = ?, voided_by = ? WHERE id = ?",
                [(now, session.get("email", "unknown"), i) for i in ids_to_void],
            )
            log_audit(db, company_id, "void", "transaction", tx_id, before={"reason": f"invoice/bill #{doc_id} deleted"})
    db.execute("DELETE FROM invoices_bills WHERE id = ?", (doc_id,))
    db.commit()
    return jsonify({"ok": True})


# ---------- purchase orders ----------

PO_STATUS_FLOW = {"draft": "approved", "approved": "received", "received": "billed"}


def _serialize_purchase_order(row):
    d = dict(row)
    d["amount"] = from_pence(d.pop("amountPence"))
    return d


@app.route("/api/companies/<int:company_id>/purchase-orders", methods=["GET"])
@login_required
@company_required
def list_purchase_orders(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT po.id, po.contact_id as contactId, c.name as contactName, po.date, po.desc, "
        "po.amount_pence as amountPence, po.account, po.status, po.bill_id as billId "
        "FROM purchase_orders po JOIN contacts c ON c.id = po.contact_id "
        "WHERE po.company_id = ? ORDER BY po.date DESC",
        (company_id,),
    ).fetchall()
    return jsonify([_serialize_purchase_order(r) for r in rows])


@app.route("/api/companies/<int:company_id>/purchase-orders", methods=["POST"])
@login_required
@company_required
@write_required
def create_purchase_order(company_id):
    data = request.get_json(force=True) or {}
    contact_id, date, desc, amount, account = (
        data.get("contactId"), data.get("date"), data.get("desc"), data.get("amount"), data.get("account"),
    )
    if not all([contact_id, date, desc, account]) or not amount or float(amount) <= 0:
        return jsonify({"error": "Contact, date, description, account, and a positive amount are all required."}), 400
    db = get_db()
    account = resolve_account(db, company_id, account, "expense")
    cur = db.execute(
        "INSERT INTO purchase_orders (company_id, contact_id, date, desc, amount_pence, account) VALUES (?,?,?,?,?,?)",
        (company_id, contact_id, date, desc, to_pence(amount), account),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/purchase-orders/<int:po_id>/advance", methods=["POST"])
@login_required
@company_required
@write_required
def advance_purchase_order(company_id, po_id):
    """Moves a PO forward one step: draft -> approved -> received. The final step, received ->
    billed, happens via /convert-to-bill instead, since that one also creates the bill."""
    db = get_db()
    po = db.execute(
        "SELECT * FROM purchase_orders WHERE id = ? AND company_id = ?", (po_id, company_id)
    ).fetchone()
    if po is None:
        return jsonify({"error": "Not found."}), 404
    next_status = PO_STATUS_FLOW.get(po["status"])
    if next_status is None or next_status == "billed":
        return jsonify({"error": f"Can't advance from '{po['status']}' — use /convert-to-bill once received."}), 400
    db.execute("UPDATE purchase_orders SET status = ? WHERE id = ?", (next_status, po_id))
    db.commit()
    return jsonify({"ok": True, "status": next_status})


@app.route("/api/companies/<int:company_id>/purchase-orders/<int:po_id>/convert-to-bill", methods=["POST"])
@login_required
@company_required
@write_required
def convert_purchase_order_to_bill(company_id, po_id):
    db = get_db()
    po = db.execute(
        "SELECT * FROM purchase_orders WHERE id = ? AND company_id = ?", (po_id, company_id)
    ).fetchone()
    if po is None:
        return jsonify({"error": "Not found."}), 404
    if po["status"] != "received":
        return jsonify({"error": "A purchase order can only become a bill once it's marked received."}), 400

    data = request.get_json(force=True) or {}
    due_date = data.get("dueDate") or po["date"]
    cur = db.execute(
        "INSERT INTO invoices_bills (company_id, kind, contact_id, date, due_date, desc, amount_pence, account, vat_rate) "
        "VALUES (?,'bill',?,?,?,?,?,?,?)",
        (company_id, po["contact_id"], po["date"], due_date, po["desc"], po["amount_pence"], po["account"], float(data.get("vatRate") or 0)),
    )
    bill_id = cur.lastrowid
    db.execute("UPDATE purchase_orders SET status = 'billed', bill_id = ? WHERE id = ?", (bill_id, po_id))
    db.commit()
    return jsonify({"billId": bill_id})


@app.route("/api/companies/<int:company_id>/purchase-orders/<int:po_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_purchase_order(company_id, po_id):
    db = get_db()
    db.execute("DELETE FROM purchase_orders WHERE id = ? AND company_id = ?", (po_id, company_id))
    db.commit()
    return jsonify({"ok": True})


# ---------- budgets ----------

@app.route("/api/companies/<int:company_id>/budgets", methods=["GET"])
@login_required
@company_required
def list_budgets(company_id):
    db = get_db()
    period = request.args.get("period")
    query = "SELECT b.id, b.account_id as accountId, a.name as account, a.type as accountType, b.period, b.amount_pence as amountPence FROM budgets b JOIN accounts a ON a.id = b.account_id WHERE b.company_id = ?"
    params = [company_id]
    if period:
        query += " AND b.period = ?"
        params.append(period)
    rows = db.execute(query + " ORDER BY b.period, a.code", params).fetchall()
    result = [dict(r) for r in rows]
    for r in result:
        r["amount"] = from_pence(r.pop("amountPence"))
    return jsonify(result)


@app.route("/api/companies/<int:company_id>/budgets", methods=["POST"])
@login_required
@company_required
@write_required
def set_budget(company_id):
    data = request.get_json(force=True) or {}
    account_name, period, amount = data.get("account"), data.get("period"), data.get("amount")
    if not all([account_name, period]) or amount is None or float(amount) < 0:
        return jsonify({"error": "Account, period (YYYY-MM), and a non-negative amount are required."}), 400
    if not re.match(r"^\d{4}-\d{2}$", period):
        return jsonify({"error": "Period must be in YYYY-MM format."}), 400
    db = get_db()
    account_name = resolve_account(db, company_id, account_name)
    account_row = get_account_by_name(db, company_id, account_name)
    db.execute(
        "INSERT INTO budgets (company_id, account_id, period, amount_pence) VALUES (?,?,?,?) "
        "ON CONFLICT(company_id, account_id, period) DO UPDATE SET amount_pence = excluded.amount_pence",
        (company_id, account_row["id"], period, to_pence(amount)),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/budgets/<int:budget_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_budget(company_id, budget_id):
    db = get_db()
    db.execute("DELETE FROM budgets WHERE id = ? AND company_id = ?", (budget_id, company_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/cis-statements", methods=["GET"])
@login_required
@company_required
def cis_statements(company_id):
    """#18: every paid invoice/bill that had a CIS deduction applied, grouped by contact —
    the data a CIS payment & deduction statement (which contractors must give subcontractors
    for every payment under the scheme) is built from. kind='bill' rows are payments this
    company made AS A CONTRACTOR to a subcontractor (CIS deducted, owed to HMRC); kind='invoice'
    rows are payments this company RECEIVED as a subcontractor (CIS suffered, recoverable)."""
    db = get_db()
    from_date = request.args.get("from") or ""
    to_date = request.args.get("to") or ""
    date_clause = ""
    params = [company_id]
    if from_date:
        date_clause += " AND ib.date >= ?"
        params.append(from_date)
    if to_date:
        date_clause += " AND ib.date <= ?"
        params.append(to_date)
    rows = db.execute(
        f"SELECT ib.id, ib.kind, ib.contact_id as contactId, c.name as contactName, ib.date, ib.desc, "
        f"ib.amount_pence as grossPence, ib.cis_deduction_pence as cisPence, ib.cis_rate as cisRate "
        f"FROM invoices_bills ib JOIN contacts c ON c.id = ib.contact_id "
        f"WHERE ib.company_id = ? AND ib.status = 'paid' AND ib.cis_deduction_pence > 0 {date_clause} "
        f"ORDER BY c.name, ib.date",
        params,
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        gross = from_pence(d.pop("grossPence"))
        cis = from_pence(d.pop("cisPence"))
        d["gross"] = gross
        d["cisDeducted"] = cis
        d["net"] = round(gross - cis, 2)
        out.append(d)
    return jsonify(out)


@app.route("/api/companies/<int:company_id>/aging-report", methods=["GET"])
@login_required
@company_required
def aging_report(company_id):
    db = get_db()
    today = datetime.date.today()
    rows = db.execute(
        "SELECT ib.id, ib.kind, ib.contact_id as contactId, c.name as contactName, ib.due_date as dueDate, "
        "ib.amount_pence as amountPence "
        "FROM invoices_bills ib JOIN contacts c ON c.id = ib.contact_id "
        "WHERE ib.company_id = ? AND ib.status = 'sent'",
        (company_id,),
    ).fetchall()
    # applied credit notes reduce what's actually still outstanding on the invoice/bill they're
    # linked to — without this, an invoice with a credit note against it would show as fully
    # outstanding here even though part (or all) of it has already been credited back
    credit_notes_by_doc = {}
    for cn in db.execute(
        "SELECT linked_doc_id, amount_pence FROM invoices_bills "
        "WHERE company_id = ? AND kind = 'credit_note' AND status = 'applied' AND linked_doc_id IS NOT NULL",
        (company_id,),
    ).fetchall():
        credit_notes_by_doc[cn["linked_doc_id"]] = credit_notes_by_doc.get(cn["linked_doc_id"], 0) + cn["amount_pence"]

    def bucket_for(days_overdue):
        if days_overdue <= 0:
            return "current"
        if days_overdue <= 30:
            return "1-30"
        if days_overdue <= 60:
            return "31-60"
        if days_overdue <= 90:
            return "61-90"
        return "90+"

    result = {"invoice": {}, "bill": {}}
    for r in rows:
        outstanding_pence = r["amountPence"] - credit_notes_by_doc.get(r["id"], 0)
        if outstanding_pence <= 0:
            continue  # fully credited — nothing left outstanding
        due = datetime.date.fromisoformat(r["dueDate"])
        days_overdue = (today - due).days
        bucket = bucket_for(days_overdue)
        contact_bucket = result[r["kind"]].setdefault(r["contactName"], {
            "current": 0, "1-30": 0, "31-60": 0, "61-90": 0, "90+": 0
        })
        contact_bucket[bucket] += from_pence(outstanding_pence)
    return jsonify(result)


# ---------- fixed assets ----------

@app.route("/api/companies/<int:company_id>/fixed-assets", methods=["GET"])
@login_required
@company_required
def list_fixed_assets(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, name, asset_account as assetAccount, cost_pence as costPence, purchase_date as purchaseDate, "
        "useful_life_years as usefulLifeYears, residual_value_pence as residualValuePence, method, "
        "depreciation_account as depreciationAccount, accum_account as accumAccount "
        "FROM fixed_assets WHERE company_id = ? ORDER BY purchase_date",
        (company_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["cost"] = from_pence(d.pop("costPence"))
        d["residualValue"] = from_pence(d.pop("residualValuePence"))
        result.append(d)
    return jsonify(result)


@app.route("/api/companies/<int:company_id>/fixed-assets", methods=["POST"])
@login_required
@company_required
@write_required
def create_fixed_asset(company_id):
    data = request.get_json(force=True) or {}
    name, asset_account, cost, purchase_date, useful_life = (
        data.get("name"), data.get("assetAccount"), data.get("cost"),
        data.get("purchaseDate"), data.get("usefulLifeYears")
    )
    if not all([name, asset_account, purchase_date]) or not cost or float(cost) <= 0 or not useful_life or float(useful_life) <= 0:
        return jsonify({"error": "Name, asset account, cost, purchase date, and useful life are all required."}), 400

    db = get_db()
    asset_account = resolve_account(db, company_id, asset_account)
    depreciation_account = resolve_account(db, company_id, data.get("depreciationAccount") or "Depreciation Expense", "expense")
    accum_account = resolve_account(
        db, company_id, data.get("accumAccount") or f"Accumulated Depreciation — {name}", "noncurrent_asset"
    )
    cur = db.execute(
        "INSERT INTO fixed_assets (company_id, name, asset_account, cost_pence, purchase_date, useful_life_years, "
        "residual_value_pence, method, depreciation_account, accum_account) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            company_id, name, asset_account, to_pence(cost), purchase_date, float(useful_life),
            to_pence(data.get("residualValue") or 0), data.get("method", "straight_line"),
            depreciation_account, accum_account,
        ),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/fixed-assets/<int:asset_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_fixed_asset(company_id, asset_id):
    db = get_db()
    db.execute("DELETE FROM fixed_assets WHERE id = ? AND company_id = ?", (asset_id, company_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/fixed-assets/<int:asset_id>/run-depreciation", methods=["POST"])
@login_required
@company_required
@write_required
def run_depreciation(company_id, asset_id):
    """Posts one straight-line monthly depreciation charge for a single asset: Dr depreciation
    account / Cr accumulated depreciation account, tagged with the given (or today's) date. Capped
    at the asset's remaining depreciable amount (cost - residual - depreciation already posted) so
    repeated runs can't depreciate an asset below its residual value."""
    db = get_db()
    asset = db.execute(
        "SELECT * FROM fixed_assets WHERE id = ? AND company_id = ?", (asset_id, company_id)
    ).fetchone()
    if asset is None:
        return jsonify({"error": "Not found."}), 404
    data = request.get_json(force=True) or {}
    run_date = data.get("date") or datetime.date.today().isoformat()

    depreciable_pence = asset["cost_pence"] - asset["residual_value_pence"]
    already_posted = db.execute(
        "SELECT COALESCE(SUM(amount_pence), 0) as total FROM transactions "
        "WHERE company_id = ? AND credit = ? AND voided_at IS NULL",
        (company_id, asset["accum_account"]),
    ).fetchone()["total"]
    remaining_pence = depreciable_pence - already_posted
    charge_pence = round(depreciable_pence / asset["useful_life_years"] / 12)
    charge_pence = max(0, min(charge_pence, remaining_pence))
    if charge_pence <= 0:
        return jsonify({"error": "This asset is already fully depreciated."}), 400

    try:
        tx_id = post_ledger_transaction(
            db, company_id, run_date, f"Depreciation — {asset['name']}", from_pence(charge_pence),
            asset["depreciation_account"], asset["accum_account"],
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status
    db.commit()
    return jsonify({"transactionId": tx_id, "amount": from_pence(charge_pence)})


# ---------- full data export ----------

@app.route("/api/companies/<int:company_id>/export", methods=["GET"])
@login_required
@company_required
def export_company_data(company_id):
    """Stage 7: a real backup, not just the transactions-only CSV — every table for this
    company in one JSON document. The AI key is deliberately excluded (Stage 5 made it
    write-only; an export is exactly the kind of file that ends up emailed or dropped in a
    shared folder, so it should never carry a credential)."""
    db = get_db()

    def all_rows(query, params=(company_id,)):
        return [dict(r) for r in db.execute(query, params).fetchall()]

    company = dict(db.execute(
        "SELECT name, default_credit_account, locked_until, period_start_date, created_at FROM companies WHERE id = ?",
        (company_id,),
    ).fetchone())

    export = {
        "exportedAt": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "company": company,
        "accounts": all_rows("SELECT code, name, type FROM accounts WHERE company_id = ?"),
        "transactions": [
            {**_serialize_transaction(r)} for r in db.execute(
                "SELECT id, date, desc, amount_pence as amountPence, debit, credit, tax_year as taxYear, "
                "vat_rate as vatRate, vat_direction as vatDirection, confidence, journal_id as journalId, "
                "voided_at as voidedAt, voided_by as voidedBy FROM transactions WHERE company_id = ? ORDER BY date",
                (company_id,),
            ).fetchall()
        ],
        "openingBalances": all_rows(
            "SELECT a.name as account, ob.amount_pence, ob.side, ob.as_of_date as asOfDate "
            "FROM opening_balances ob JOIN accounts a ON a.id = ob.account_id WHERE ob.company_id = ?"
        ),
        "contacts": all_rows("SELECT name, type, email, phone FROM contacts WHERE company_id = ?"),
        "invoicesBills": all_rows(
            "SELECT ib.kind, c.name as contact, ib.date, ib.due_date as dueDate, ib.desc, "
            "ib.amount_pence, ib.account, ib.vat_rate as vatRate, ib.status "
            "FROM invoices_bills ib JOIN contacts c ON c.id = ib.contact_id WHERE ib.company_id = ?"
        ),
        "fixedAssets": all_rows(
            "SELECT name, asset_account as assetAccount, cost_pence, purchase_date as purchaseDate, "
            "useful_life_years as usefulLifeYears, residual_value_pence, method, "
            "depreciation_account as depreciationAccount, accum_account as accumAccount FROM fixed_assets WHERE company_id = ?"
        ),
        "bankLines": all_rows(
            "SELECT cash_account as cashAccount, date, desc, amount_pence FROM bank_lines WHERE company_id = ?"
        ),
        "auditLog": all_rows(
            "SELECT user_email as userEmail, action, entity_type as entityType, entity_id as entityId, "
            "before_json as beforeJson, after_json as afterJson, created_at as createdAt FROM audit_log WHERE company_id = ?"
        ),
    }
    # pence -> pounds for the handful of tables not already routed through a serializer
    for row in export["openingBalances"]:
        row["amount"] = from_pence(row.pop("amount_pence"))
    for row in export["invoicesBills"]:
        row["amount"] = from_pence(row.pop("amount_pence"))
    for row in export["fixedAssets"]:
        row["cost"] = from_pence(row.pop("cost_pence"))
        row["residualValue"] = from_pence(row.pop("residual_value_pence"))
    for row in export["bankLines"]:
        row["amount"] = from_pence(row.pop("amount_pence"))

    return jsonify(export)


# ---------- audit log ----------

@app.route("/api/companies/<int:company_id>/audit-log", methods=["GET"])
@login_required
@company_required
def list_audit_log(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, user_email as userEmail, action, entity_type as entityType, entity_id as entityId, "
        "before_json as beforeJson, after_json as afterJson, created_at as createdAt "
        "FROM audit_log WHERE company_id = ? ORDER BY id DESC LIMIT 500",
        (company_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ---------- live bank feed (Plaid) ----------
#
# This is the "buy don't build" Open Banking piece: actual bank/card connections go through
# Plaid's regulated infrastructure, not anything custom. access_token is the live credential
# that reads someone's real transactions — encrypted at rest, never returned to the browser.
# Synced transactions land in the existing bank_lines table, so they flow straight into the
# Bank Reconciliation screen already built — nothing about that UI needed to change.

@app.route("/api/companies/<int:company_id>/plaid/link-token", methods=["POST"])
@login_required
@company_required
@write_required
def create_plaid_link_token(company_id):
    data = request.get_json(force=True) or {}
    try:
        result = call_plaid(g.company, "/link/token/create", {
            "client_name": "Bookkeeping Assistant",
            "language": "en",
            "country_codes": ["GB", "US"],
            "user": {"client_user_id": str(session["user_id"])},
            "products": ["transactions"],
        })
    except PlaidError as e:
        return jsonify({"error": e.message}), e.status
    return jsonify({"linkToken": result.get("link_token")})


@app.route("/api/companies/<int:company_id>/plaid/exchange", methods=["POST"])
@login_required
@company_required
@write_required
def exchange_plaid_public_token(company_id):
    data = request.get_json(force=True) or {}
    public_token = data.get("publicToken")
    institution_name = data.get("institutionName", "")
    cash_account = data.get("cashAccount") or "Cash"
    if not public_token:
        return jsonify({"error": "Missing public token."}), 400

    db = get_db()
    try:
        result = call_plaid(g.company, "/item/public_token/exchange", {"public_token": public_token})
    except PlaidError as e:
        return jsonify({"error": e.message}), e.status

    cash_account = resolve_account(db, company_id, cash_account, "cash")
    cur = db.execute(
        "INSERT INTO bank_connections (company_id, item_id, access_token, institution_name, cash_account) "
        "VALUES (?,?,?,?,?)",
        (company_id, result["item_id"], encrypt_secret(result["access_token"]), institution_name, cash_account),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/bank-connections", methods=["GET"])
@login_required
@company_required
def list_bank_connections(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, institution_name as institutionName, cash_account as cashAccount, created_at as createdAt "
        "FROM bank_connections WHERE company_id = ? ORDER BY created_at",
        (company_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/bank-connections/<int:connection_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_bank_connection(company_id, connection_id):
    db = get_db()
    conn = db.execute(
        "SELECT access_token FROM bank_connections WHERE id = ? AND company_id = ?", (connection_id, company_id)
    ).fetchone()
    if conn is None:
        return jsonify({"ok": True})
    try:
        call_plaid(g.company, "/item/remove", {"access_token": decrypt_secret(conn["access_token"])})
    except PlaidError:
        pass  # still remove our record even if Plaid's side errors (e.g. already revoked)
    db.execute("DELETE FROM bank_connections WHERE id = ?", (connection_id,))
    db.commit()
    return jsonify({"ok": True})


def queue_plaid_line_if_unsure(db, company_id, cash_account, date, desc, amount):
    """Plaid feed transactions never go through the AI suggester (that's a separate, paid call) —
    the only signal available is whether this description has been seen before as a preset. A
    new, never-seen description is exactly the case the clarification queue exists for: posting
    it automatically based on nothing but the sign of the amount would be a silent guess."""
    preset = db.execute(
        "SELECT debit, credit FROM presets WHERE company_id = ? AND desc_key = ?",
        (company_id, desc.strip().lower()),
    ).fetchone()
    if preset is not None:
        return  # a known description — confident enough to leave for normal bank-rec matching

    guessed_debit, guessed_credit = (cash_account, "Uncategorized") if amount > 0 else ("Uncategorized", cash_account)
    db.execute(
        "INSERT INTO clarification_queue (company_id, source, raw_line_json, suggested_debit, "
        "suggested_credit, suggested_amount_pence, confidence, reason) VALUES (?,?,?,?,?,?,?,?)",
        (
            company_id, "plaid", json.dumps({"date": date, "desc": desc, "amount": abs(amount)}),
            guessed_debit, guessed_credit, to_pence(abs(amount)), 0.2,
            "New bank feed transaction with no matching preset — description never seen before.",
        ),
    )


def sync_bank_connection(db, company, connection_id):
    """Pull new transactions since the last sync via Plaid's cursor-based /transactions/sync,
    inserting each as a bank_line keyed by Plaid's own transaction_id so re-syncing (including
    from the webhook) never creates duplicates."""
    conn = db.execute("SELECT * FROM bank_connections WHERE id = ?", (connection_id,)).fetchone()
    if conn is None:
        raise PlaidError("Connection not found.", 404)

    access_token = decrypt_secret(conn["access_token"])
    cursor = conn["sync_cursor"]
    inserted = 0
    has_more = True
    while has_more:
        payload = {"access_token": access_token}
        if cursor:
            payload["cursor"] = cursor
        result = call_plaid(company, "/transactions/sync", payload)
        for tx in result.get("added", []):
            amount = -float(tx["amount"])  # Plaid: positive = money out: flip sign to match this app's convention
            desc = tx.get("merchant_name") or tx.get("name") or "Bank transaction"
            db.execute(
                "INSERT INTO bank_lines (company_id, cash_account, date, desc, amount_pence, external_id) "
                "VALUES (?,?,?,?,?,?) ON CONFLICT(company_id, external_id) WHERE external_id IS NOT NULL DO NOTHING",
                (
                    conn["company_id"], conn["cash_account"], tx["date"], desc,
                    to_pence(amount), tx["transaction_id"],
                ),
            )
            inserted += 1
            queue_plaid_line_if_unsure(db, conn["company_id"], conn["cash_account"], tx["date"], desc, amount)
        cursor = result.get("next_cursor")
        has_more = result.get("has_more", False)
    db.execute("UPDATE bank_connections SET sync_cursor = ? WHERE id = ?", (cursor, connection_id))
    db.commit()
    return inserted


@app.route("/api/companies/<int:company_id>/bank-connections/<int:connection_id>/sync", methods=["POST"])
@login_required
@company_required
@write_required
def sync_bank_connection_route(company_id, connection_id):
    db = get_db()
    try:
        inserted = sync_bank_connection(db, g.company, connection_id)
    except PlaidError as e:
        return jsonify({"error": e.message}), e.status
    return jsonify({"inserted": inserted})


@app.route("/api/plaid/webhook", methods=["POST"])
def plaid_webhook():
    """Plaid calls this server-to-server the moment new transactions are ready — this is the
    actual "real-time" half of the feature; the manual Sync button above is the fallback for
    local/sandbox testing where Plaid's servers can't reach a localhost URL.
    NOTE: production use should verify the Plaid-Verification JWT header before trusting this
    payload — not implemented here, flagged as a known gap for a deployed instance."""
    data = request.get_json(force=True) or {}
    if data.get("webhook_type") != "TRANSACTIONS":
        return jsonify({"ok": True})  # ignore webhook types we don't act on (ITEM_ERROR, etc.)

    item_id = data.get("item_id")
    db = get_db()
    conn = db.execute("SELECT * FROM bank_connections WHERE item_id = ?", (item_id,)).fetchone()
    if conn is None:
        return jsonify({"ok": True})
    company = db.execute("SELECT * FROM companies WHERE id = ?", (conn["company_id"],)).fetchone()
    try:
        sync_bank_connection(db, company, conn["id"])
    except PlaidError:
        pass  # webhook delivery isn't the place to surface this to a user; next manual sync will retry
    return jsonify({"ok": True})


# ---------- bank reconciliation ----------

@app.route("/api/companies/<int:company_id>/bank-lines", methods=["GET"])
@login_required
@company_required
def list_bank_lines(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, cash_account as cashAccount, date, desc, amount_pence as amountPence, "
        "matched_transaction_id as matchedTransactionId "
        "FROM bank_lines WHERE company_id = ? ORDER BY date",
        (company_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["amount"] = from_pence(d.pop("amountPence"))
        result.append(d)
    return jsonify(result)


@app.route("/api/companies/<int:company_id>/bank-lines/bulk", methods=["POST"])
@login_required
@company_required
@write_required
def bulk_create_bank_lines(company_id):
    items = request.get_json(force=True) or []
    db = get_db()
    inserted = 0
    for it in items:
        cash_account, date, desc, amount = it.get("cashAccount"), it.get("date"), it.get("desc"), it.get("amount")
        if not all([cash_account, date, desc]) or amount is None or float(amount) == 0:
            continue
        cash_account = resolve_account(db, company_id, cash_account, "cash")
        db.execute(
            "INSERT INTO bank_lines (company_id, cash_account, date, desc, amount_pence) VALUES (?,?,?,?,?)",
            (company_id, cash_account, date, desc, to_pence(amount)),
        )
        inserted += 1
    db.commit()
    return jsonify({"inserted": inserted})


@app.route("/api/companies/<int:company_id>/bank-lines/<int:line_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_bank_line(company_id, line_id):
    db = get_db()
    db.execute("DELETE FROM bank_lines WHERE id = ? AND company_id = ?", (line_id, company_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/bank-lines/<int:line_id>/match", methods=["POST"])
@login_required
@company_required
@write_required
def match_bank_line(company_id, line_id):
    data = request.get_json(force=True) or {}
    tx_id = data.get("transactionId")
    db = get_db()
    if tx_id is not None:
        tx = db.execute(
            "SELECT id FROM transactions WHERE id = ? AND company_id = ?", (tx_id, company_id)
        ).fetchone()
        if tx is None:
            return jsonify({"error": "Transaction not found."}), 404
    db.execute(
        "UPDATE bank_lines SET matched_transaction_id = ? WHERE id = ? AND company_id = ?",
        (tx_id, line_id, company_id),
    )
    db.commit()
    return jsonify({"ok": True})


# ---------- bank reconciliations (formal open/close workflow, on top of bank_lines) ----------

def _serialize_reconciliation(row):
    d = dict(row)
    d["statementClosingBalance"] = from_pence(d.pop("statement_closing_balance_pence"))
    d["statementDate"] = d.pop("statement_date")
    return d


@app.route("/api/companies/<int:company_id>/reconciliations", methods=["GET"])
@login_required
@company_required
def list_reconciliations(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, account, statement_date, statement_closing_balance_pence, status, created_at "
        "FROM bank_reconciliations WHERE company_id = ? ORDER BY statement_date DESC",
        (company_id,),
    ).fetchall()
    return jsonify([_serialize_reconciliation(r) for r in rows])


@app.route("/api/companies/<int:company_id>/reconciliations", methods=["POST"])
@login_required
@company_required
@write_required
def create_reconciliation(company_id):
    data = request.get_json(force=True) or {}
    account = (data.get("account") or "").strip()
    statement_date = data.get("statementDate")
    statement_balance = data.get("statementClosingBalance")
    if not account or not statement_date or statement_balance is None:
        return jsonify({"error": "Account, statement date, and closing balance are required."}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO bank_reconciliations (company_id, account, statement_date, statement_closing_balance_pence) "
        "VALUES (?,?,?,?)",
        (company_id, account, statement_date, to_pence(statement_balance)),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/reconciliations/<int:rec_id>/clear-line", methods=["PUT"])
@login_required
@company_required
@write_required
def clear_reconciliation_line(company_id, rec_id):
    db = get_db()
    rec = db.execute(
        "SELECT id FROM bank_reconciliations WHERE id = ? AND company_id = ?", (rec_id, company_id)
    ).fetchone()
    if rec is None:
        return jsonify({"error": "Reconciliation not found."}), 404
    data = request.get_json(force=True) or {}
    line_id = data.get("lineId")
    tx_id = data.get("transactionId")
    if not line_id:
        return jsonify({"error": "lineId is required."}), 400
    if tx_id is not None:
        tx = db.execute(
            "SELECT id FROM transactions WHERE id = ? AND company_id = ?", (tx_id, company_id)
        ).fetchone()
        if tx is None:
            return jsonify({"error": "Transaction not found."}), 404
    db.execute(
        "UPDATE bank_lines SET matched_transaction_id = ? WHERE id = ? AND company_id = ?",
        (tx_id, line_id, company_id),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/reconciliations/<int:rec_id>/close", methods=["POST"])
@login_required
@company_required
@write_required
def close_reconciliation(company_id, rec_id):
    db = get_db()
    rec = db.execute(
        "SELECT * FROM bank_reconciliations WHERE id = ? AND company_id = ?", (rec_id, company_id)
    ).fetchone()
    if rec is None:
        return jsonify({"error": "Reconciliation not found."}), 404
    if rec["status"] == "closed":
        return jsonify({"error": "This reconciliation is already closed."}), 400

    cleared_pence = db.execute(
        "SELECT COALESCE(SUM(amount_pence), 0) as total FROM bank_lines "
        "WHERE company_id = ? AND cash_account = ? AND matched_transaction_id IS NOT NULL",
        (company_id, rec["account"]),
    ).fetchone()["total"]
    if cleared_pence != rec["statement_closing_balance_pence"]:
        return jsonify({
            "error": f"Cleared balance ({from_pence(cleared_pence)}) does not match the statement "
                     f"closing balance ({from_pence(rec['statement_closing_balance_pence'])}).",
            "clearedBalance": from_pence(cleared_pence),
        }), 400

    db.execute("UPDATE bank_reconciliations SET status = 'closed' WHERE id = ?", (rec_id,))
    db.commit()
    return jsonify({"ok": True})


# ---------- recurring journals + period close ----------

def _serialize_recurring_journal(row):
    d = dict(row)
    d["amount"] = from_pence(d.pop("amount_pence"))
    d["nextDue"] = d.pop("next_due")
    d["endDate"] = d.pop("end_date")
    return d


@app.route("/api/companies/<int:company_id>/recurring-journals", methods=["GET"])
@login_required
@company_required
def list_recurring_journals(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, label, frequency, next_due, debit, credit, amount_pence, end_date "
        "FROM recurring_journals WHERE company_id = ? ORDER BY next_due",
        (company_id,),
    ).fetchall()
    return jsonify([_serialize_recurring_journal(r) for r in rows])


@app.route("/api/companies/<int:company_id>/recurring-journals", methods=["POST"])
@login_required
@company_required
@write_required
def create_recurring_journal(company_id):
    data = request.get_json(force=True) or {}
    label, frequency, next_due, debit, credit, amount = (
        data.get("label"), data.get("frequency", "monthly"), data.get("nextDue"),
        data.get("debit"), data.get("credit"), data.get("amount"),
    )
    if not all([label, next_due, debit, credit]) or not amount or float(amount) <= 0:
        return jsonify({"error": "Label, next due date, debit, credit, and a positive amount are all required."}), 400
    if frequency not in ("weekly", "monthly", "quarterly", "annually"):
        return jsonify({"error": "Frequency must be weekly, monthly, quarterly, or annually."}), 400
    db = get_db()
    debit = resolve_account(db, company_id, debit)
    credit = resolve_account(db, company_id, credit)
    cur = db.execute(
        "INSERT INTO recurring_journals (company_id, label, frequency, next_due, debit, credit, amount_pence, end_date) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (company_id, label, frequency, next_due, debit, credit, to_pence(amount), data.get("endDate", "")),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/recurring-journals/<int:rj_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_recurring_journal(company_id, rj_id):
    db = get_db()
    db.execute("DELETE FROM recurring_journals WHERE id = ? AND company_id = ?", (rj_id, company_id))
    db.commit()
    return jsonify({"ok": True})


def _advance_next_due(date_str, frequency):
    d = datetime.date.fromisoformat(date_str)
    if frequency == "weekly":
        return (d + datetime.timedelta(days=7)).isoformat()
    if frequency == "quarterly":
        months_ahead = d.month - 1 + 3
    elif frequency == "annually":
        months_ahead = d.month - 1 + 12
    else:  # monthly
        months_ahead = d.month - 1 + 1
    year = d.year + months_ahead // 12
    month = months_ahead % 12 + 1
    day = min(d.day, [31, 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28,
                       31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1])
    return datetime.date(year, month, day).isoformat()


@app.route("/api/companies/<int:company_id>/period-close", methods=["POST"])
@login_required
@company_required
@write_required
def period_close(company_id):
    """Posts every recurring journal that's due (next_due <= today and not past its end_date),
    then advances next_due by one cadence step. Skips (and reports) anything that fails to post
    — e.g. a recurring journal whose date now falls in a locked period — rather than aborting
    the whole run."""
    db = get_db()
    today = datetime.date.today().isoformat()
    due = db.execute(
        "SELECT * FROM recurring_journals WHERE company_id = ? AND next_due <= ? "
        "AND (end_date = '' OR end_date >= next_due)",
        (company_id, today),
    ).fetchall()

    posted, skipped, queued = [], [], []
    for rj in due:
        # A recurring journal stores its debit/credit by account NAME. If one of those accounts
        # has been renamed or deleted since the template was set up, post_ledger_transaction's
        # resolve_account() would silently re-create it — masking a real problem. So we check
        # first: if either side no longer exists, route the due posting to the clarification
        # queue for the user to confirm/fix instead of guessing, and DON'T advance next_due
        # (so it's still pending once they sort it out).
        missing = [
            name for name in (rj["debit"], rj["credit"])
            if get_account_by_name(db, company_id, name) is None
        ]
        if missing:
            db.execute(
                "INSERT INTO clarification_queue (company_id, source, raw_line_json, suggested_debit, "
                "suggested_credit, suggested_amount_pence, confidence, reason) VALUES (?,?,?,?,?,?,?,?)",
                (
                    company_id, "recurring",
                    json.dumps({"date": rj["next_due"], "desc": rj["label"], "amount": from_pence(rj["amount_pence"])}),
                    rj["debit"], rj["credit"], rj["amount_pence"], 0.0,
                    f"Recurring journal \"{rj['label']}\" is due, but its account(s) no longer exist: "
                    f"{', '.join(missing)}. Renamed or deleted since the template was set up — confirm before posting.",
                ),
            )
            queued.append({"recurringJournalId": rj["id"], "missing": missing})
            continue
        try:
            tx_id = post_ledger_transaction(
                db, company_id, rj["next_due"], rj["label"], from_pence(rj["amount_pence"]),
                rj["debit"], rj["credit"],
            )
            posted.append({"recurringJournalId": rj["id"], "transactionId": tx_id, "date": rj["next_due"]})
        except LedgerError as e:
            skipped.append({"recurringJournalId": rj["id"], "reason": e.message})
            continue
        next_due = _advance_next_due(rj["next_due"], rj["frequency"])
        db.execute("UPDATE recurring_journals SET next_due = ? WHERE id = ?", (next_due, rj["id"]))

    db.commit()
    return jsonify({"posted": posted, "skipped": skipped, "queued": queued})


# ---------- payroll journal wizard ----------

def amap_rate_pence(vehicle_type):
    """HMRC Approved Mileage Allowance Payments rates (2024/25). Cars/vans taper from 45p to 25p
    after the first 10,000 business miles in a tax year; motorcycles and bicycles are flat."""
    return {"car": (45, 25, 10000), "van": (45, 25, 10000), "motorcycle": (24, 24, None), "bicycle": (20, 20, None)}.get(
        vehicle_type, (45, 25, 10000)
    )


def compute_mileage_amount_pence(miles_before_this_trip, miles_this_trip, vehicle_type):
    """Splits a trip's miles across the 10,000-mile-per-tax-year threshold if it straddles it —
    e.g. a 200-mile trip starting at mile 9,950 charges 50 miles at the higher rate and 150 at
    the lower one, rather than rounding the whole trip to one rate."""
    high_rate, low_rate, threshold = amap_rate_pence(vehicle_type)
    if threshold is None:
        return round(miles_this_trip * high_rate)
    miles_at_high = max(0, min(miles_this_trip, threshold - miles_before_this_trip))
    miles_at_low = miles_this_trip - miles_at_high
    return round(miles_at_high * high_rate + miles_at_low * low_rate)


@app.route("/api/companies/<int:company_id>/mileage-log", methods=["GET"])
@login_required
@company_required
def list_mileage_log(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, date, tax_year as taxYear, from_location as fromLocation, to_location as toLocation, "
        "miles, purpose, vehicle_type as vehicleType, amount_pence as amountPence, transaction_id as transactionId "
        "FROM mileage_log WHERE company_id = ? ORDER BY date DESC", (company_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["amount"] = from_pence(d.pop("amountPence"))
        out.append(d)
    return jsonify(out)


@app.route("/api/companies/<int:company_id>/mileage-log", methods=["POST"])
@login_required
@company_required
@write_required
def add_mileage_log(company_id):
    """Logs a business trip, computes the AMAP claim against miles already logged this tax
    year, and posts it straight to the ledger (DR Mileage Expense, CR the chosen liability/cash
    account — typically Director's Loan Account if the driver is reimbursed later, or Cash if
    paid immediately) so it shows up in expenses without a second manual entry."""
    data = request.get_json(force=True) or {}
    date = data.get("date")
    from_location = (data.get("fromLocation") or "").strip()
    to_location = (data.get("toLocation") or "").strip()
    purpose = (data.get("purpose") or "").strip()
    vehicle_type = data.get("vehicleType") or "car"
    credit_account = (data.get("creditAccount") or "Director's Loan Account").strip()
    try:
        miles = float(data.get("miles") or 0)
    except (TypeError, ValueError):
        miles = 0

    if not date or not from_location or not to_location or not purpose or miles <= 0:
        return jsonify({"error": "Date, from, to, purpose, and a positive mileage are required."}), 400
    if is_locked(g.company, date):
        return jsonify({"error": f"This period is locked until {g.company['locked_until']}."}), 423

    db = get_db()
    tax_year = compute_tax_year(date, g.company["period_start_date"])
    miles_before = db.execute(
        "SELECT COALESCE(SUM(miles), 0) as total FROM mileage_log WHERE company_id = ? AND tax_year = ? AND vehicle_type = ?",
        (company_id, tax_year, vehicle_type),
    ).fetchone()["total"]
    amount_pence = compute_mileage_amount_pence(miles_before, miles, vehicle_type)
    amount = from_pence(amount_pence)

    try:
        transaction_id = post_ledger_transaction(
            db, company_id, date, f"Mileage — {from_location} to {to_location} ({purpose})",
            amount, "Mileage Expense", credit_account,
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status

    cur = db.execute(
        "INSERT INTO mileage_log (company_id, date, tax_year, from_location, to_location, miles, purpose, vehicle_type, amount_pence, transaction_id) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (company_id, date, tax_year, from_location, to_location, miles, purpose, vehicle_type, amount_pence, transaction_id),
    )
    db.commit()
    return jsonify({
        "id": cur.lastrowid, "date": date, "taxYear": tax_year, "fromLocation": from_location, "toLocation": to_location,
        "miles": miles, "purpose": purpose, "vehicleType": vehicle_type, "amount": amount, "transactionId": transaction_id,
        "milesBeforeThisTrip": miles_before,
    })


@app.route("/api/companies/<int:company_id>/mileage-log/<int:entry_id>", methods=["DELETE"])
@login_required
@company_required
@write_required
def delete_mileage_log(company_id, entry_id):
    db = get_db()
    row = db.execute(
        "SELECT transaction_id FROM mileage_log WHERE id = ? AND company_id = ?", (entry_id, company_id)
    ).fetchone()
    if row is None:
        return jsonify({"ok": True})
    if row["transaction_id"]:
        tx = db.execute("SELECT * FROM transactions WHERE id = ?", (row["transaction_id"],)).fetchone()
        if tx is not None:
            db.execute("UPDATE transactions SET voided_at = ?, voided_by = ? WHERE id = ?",
                       (datetime.datetime.utcnow().isoformat(), session.get("email", "unknown"), tx["id"]))
    db.execute("DELETE FROM mileage_log WHERE id = ?", (entry_id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/payroll-journal", methods=["POST"])
@login_required
@company_required
@write_required
def post_payroll_journal(company_id):
    """The most common compound journal a small business runs: one gross pay figure splits into
    what's owed to HMRC (PAYE + both employee and employer NI), what's owed to the pension
    provider (both employee and employer contributions), and what actually hits the employee's
    bank account. Posted as DR Salary Expense (the full cost: gross + employer NI + employer
    pension) against four credit legs sharing one journal_id — mathematically the same shape as
    the existing compound-journal endpoint (one pivot, several lines), just with payroll-specific
    inputs and a server-computed net pay instead of requiring the caller to do the arithmetic."""
    data = request.get_json(force=True) or {}
    date = data.get("date")
    label = (data.get("label") or "Payroll").strip()
    gross_pay = float(data.get("grossPay") or 0)
    employer_ni = float(data.get("employerNi") or 0)
    employee_ni = float(data.get("employeeNi") or 0)
    paye = float(data.get("paye") or 0)
    employee_pension = float(data.get("employeePension") or 0)
    employer_pension = float(data.get("employerPension") or 0)

    if not date or gross_pay <= 0:
        return jsonify({"error": "Date and a positive gross pay are required."}), 400
    if any(v < 0 for v in (employer_ni, employee_ni, paye, employee_pension, employer_pension)):
        return jsonify({"error": "Deduction amounts can't be negative."}), 400

    net_pay = round(gross_pay - employee_ni - paye - employee_pension, 2)
    if net_pay <= 0:
        return jsonify({"error": "Net pay works out to zero or negative — check the deduction amounts against gross pay."}), 400

    db = get_db()
    salary_account = resolve_account(db, company_id, "Salary Expense", "expense")
    credit_legs = [
        (resolve_account(db, company_id, "NI Payable", "current_liability"), round(employee_ni + employer_ni, 2)),
        (resolve_account(db, company_id, "PAYE Payable", "current_liability"), round(paye, 2)),
        (resolve_account(db, company_id, "Pension Payable", "current_liability"), round(employee_pension + employer_pension, 2)),
        (resolve_account(db, company_id, "Net Pay Payable", "current_liability"), net_pay),
    ]
    credit_legs = [(acc, amt) for acc, amt in credit_legs if amt > 0]
    if not credit_legs:
        return jsonify({"error": "Nothing to post — all amounts are zero."}), 400

    journal_id = uuid.uuid4().hex
    posted = []
    try:
        for acc, amt in credit_legs:
            tx_id = post_ledger_transaction(
                db, company_id, date, f"{label} ({acc})", amt, salary_account, acc, journal_id=journal_id
            )
            posted.append(tx_id)
    except LedgerError as e:
        db.rollback()
        return jsonify({"error": e.message}), e.status

    db.commit()
    total_cost = sum(amt for _, amt in credit_legs)
    return jsonify({"journalId": journal_id, "transactionIds": posted, "netPay": net_pay, "totalCost": total_cost})


# ---------- dividend posting wizard ----------

def compute_cumulative_net_profit(db, company_id):
    """Revenue - COGS - expenses, all-time, ignoring opening balances on those account types
    (a real edge case but rare enough in practice that every other report in this app makes the
    same simplification)."""
    accounts = {r["name"]: r["type"] for r in db.execute(
        "SELECT name, type FROM accounts WHERE company_id = ?", (company_id,)
    ).fetchall()}
    rows = db.execute(
        "SELECT debit, credit, amount_pence FROM transactions WHERE company_id = ? AND voided_at IS NULL",
        (company_id,),
    ).fetchall()
    revenue = cogs = expense = 0
    for r in rows:
        amount = from_pence(r["amount_pence"])
        debit_type, credit_type = accounts.get(r["debit"]), accounts.get(r["credit"])
        if credit_type == "revenue":
            revenue += amount
        elif debit_type == "revenue":
            revenue -= amount
        if debit_type == "cogs":
            cogs += amount
        elif credit_type == "cogs":
            cogs -= amount
        if debit_type == "expense":
            expense += amount
        elif credit_type == "expense":
            expense -= amount
    return revenue - cogs - expense


@app.route("/api/companies/<int:company_id>/dividends", methods=["POST"])
@login_required
@company_required
@write_required
def post_dividend(company_id):
    """DR Retained Earnings / CR Dividends Payable (if declared but not yet paid) or CR a bank
    account (if paid immediately). Blocks the post if the amount exceeds distributable reserves
    (cumulative net profit, less any dividends already debited to Retained Earnings) unless the
    caller explicitly overrides — posting an unlawful dividend has real legal consequences for
    directors, so this should require a deliberate second step, not happen silently."""
    data = request.get_json(force=True) or {}
    date = data.get("date")
    amount = float(data.get("amount") or 0)
    paid_immediately = bool(data.get("paidImmediately"))
    bank_account = data.get("bankAccount") or "Cash"
    if not date or amount <= 0:
        return jsonify({"error": "Date and a positive amount are required."}), 400

    db = get_db()
    cumulative_net_profit = compute_cumulative_net_profit(db, company_id)
    re_account_row = get_account_by_name(db, company_id, "Retained Earnings")
    re_balance = 0.0
    if re_account_row:
        row = db.execute(
            "SELECT COALESCE(SUM(CASE WHEN credit = ? THEN amount_pence ELSE 0 END), 0) - "
            "COALESCE(SUM(CASE WHEN debit = ? THEN amount_pence ELSE 0 END), 0) as net "
            "FROM transactions WHERE company_id = ? AND voided_at IS NULL",
            (re_account_row["name"], re_account_row["name"], company_id),
        ).fetchone()
        re_balance = from_pence(row["net"])
    available_reserves = round(cumulative_net_profit + re_balance, 2)

    if amount > available_reserves and not data.get("force"):
        return jsonify({
            "error": f"This dividend ({amount:.2f}) exceeds distributable reserves ({available_reserves:.2f}). "
                     "Posting an unlawful dividend has its own legal consequences for directors — "
                     "resubmit with force=true to override if you're certain.",
            "availableReserves": available_reserves,
        }), 400

    retained_earnings_account = resolve_account(db, company_id, "Retained Earnings", "equity")
    credit_account = (
        resolve_account(db, company_id, bank_account, "cash") if paid_immediately
        else resolve_account(db, company_id, "Dividends Payable", "current_liability")
    )
    try:
        tx_id = post_ledger_transaction(
            db, company_id, date, "Dividend", amount, retained_earnings_account, credit_account
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status
    db.commit()
    return jsonify({"transactionId": tx_id, "availableReserves": available_reserves})


# ---------- multi-currency: FX revaluation ----------

@app.route("/api/companies/<int:company_id>/fx-revaluation", methods=["POST"])
@login_required
@company_required
@write_required
def fx_revaluation(company_id):
    """Revalues one account's foreign-currency-denominated transactions at a new exchange rate
    and posts the GBP difference to Unrealised FX Gain/Loss. Only transactions originally posted
    with a currency+exchangeRate (so a known foreign_amount_pence) are revalued — purely
    GBP-denominated postings on the same account are left untouched."""
    data = request.get_json(force=True) or {}
    account_name = (data.get("account") or "").strip()
    new_rate = float(data.get("newRate") or 0)
    date = data.get("date") or datetime.date.today().isoformat()
    if not account_name or new_rate <= 0:
        return jsonify({"error": "Account and a positive new exchange rate are required."}), 400

    db = get_db()
    account_row = get_account_by_name(db, company_id, account_name)
    if account_row is None:
        return jsonify({"error": "Account not found."}), 404
    debit_normal = account_row["type"] in ("cash", "cogs", "expense", "current_asset", "noncurrent_asset", "drawings")

    rows = db.execute(
        "SELECT debit, credit, foreign_amount_pence, amount_pence FROM transactions "
        "WHERE company_id = ? AND (debit = ? OR credit = ?) AND voided_at IS NULL AND foreign_amount_pence IS NOT NULL",
        (company_id, account_row["name"], account_row["name"]),
    ).fetchall()
    if not rows:
        return jsonify({"error": "No foreign-currency transactions found on this account to revalue."}), 400

    net_foreign_pence = 0
    net_gbp_pence = 0
    for r in rows:
        sign = 1 if r["debit"] == account_row["name"] else -1
        if not debit_normal:
            sign = -sign
        net_foreign_pence += sign * r["foreign_amount_pence"]
        net_gbp_pence += sign * r["amount_pence"]

    new_gbp_pence = round(net_foreign_pence * new_rate)
    diff_pence = new_gbp_pence - net_gbp_pence
    if diff_pence == 0:
        return jsonify({"ok": True, "adjustment": 0})

    # diff_pence moves the account by exactly that much in ITS OWN normal direction; the
    # offsetting leg always lands on the revenue-type FX account on the opposite normal side,
    # which is what makes the P&L effect come out as a gain when an asset's value rises (or a
    # liability's falls) and a loss the other way round, without needing separate gain/loss logic.
    fx_account = resolve_account(db, company_id, "Unrealised FX Gain/Loss", "revenue")
    amount = from_pence(abs(diff_pence))
    increases_account = diff_pence > 0
    if debit_normal:
        debit, credit = (account_row["name"], fx_account) if increases_account else (fx_account, account_row["name"])
    else:
        debit, credit = (fx_account, account_row["name"]) if increases_account else (account_row["name"], fx_account)

    try:
        tx_id = post_ledger_transaction(
            db, company_id, date, f"FX revaluation — {account_row['name']} @ {new_rate}", amount, debit, credit
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status
    db.commit()
    return jsonify({"ok": True, "transactionId": tx_id, "adjustment": from_pence(diff_pence)})


# ---------- Making Tax Digital (VAT) — HMRC OAuth + obligations + submission ----------
#
# Structurally complete, mirroring the existing Plaid integration's pattern (encrypted
# credentials, sandbox/production env switch, the same call/error-wrapping shape) — but this
# could NOT be exercised against HMRC's real sandbox in development, since that requires a real
# application registered on HMRC's Developer Hub (https://developer.service.hmrc.gov.uk) with
# its own client_id/secret and an approved redirect_uri. Anyone deploying this for real needs to
# register their own app there first and put its credentials into Settings.

HMRC_HOSTS = {
    "sandbox": "https://test-api.service.hmrc.gov.uk",
    "production": "https://api.service.hmrc.gov.uk",
}


class HmrcError(Exception):
    def __init__(self, message, status=502):
        self.message = message
        self.status = status


def hmrc_host(company):
    return HMRC_HOSTS.get(company["hmrc_env"] or "sandbox", HMRC_HOSTS["sandbox"])


def call_hmrc(company, method, path, headers=None, data=None, form=False):
    access_token = decrypt_secret(company["hmrc_access_token"])
    if not access_token:
        raise HmrcError("Not connected to HMRC for this company yet — connect it in Settings.", 400)
    req_headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/vnd.hmrc.1.0+json"}
    req_headers.update(headers or {})
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode("utf-8")
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{hmrc_host(company)}{path}", data=body, method=method, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8")) if resp.length != 0 else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", "replace")
        try:
            err_json = json.loads(err_body)
            message = err_json.get("message", err_body[:300])
        except json.JSONDecodeError:
            message = err_body[:300]
        raise HmrcError(f"HMRC error {e.code}: {message}", 502)
    except urllib.error.URLError as e:
        raise HmrcError(f"Could not reach HMRC: {e.reason}", 502)


@app.route("/api/companies/<int:company_id>/hmrc/auth-url", methods=["GET"])
@login_required
@company_required
def hmrc_auth_url(company_id):
    client_id = (g.company["hmrc_client_id"] or "").strip()
    if not client_id:
        return jsonify({"error": "No HMRC Client ID set for this company — add one in Settings first."}), 400
    redirect_uri = f"{request.host_url.rstrip('/')}/api/hmrc/callback"
    state = json.dumps({"companyId": company_id, "nonce": uuid.uuid4().hex})
    params = urllib.parse.urlencode({
        "response_type": "code", "client_id": client_id, "scope": "write:vat read:vat",
        "redirect_uri": redirect_uri, "state": state,
    })
    return jsonify({"authUrl": f"{hmrc_host(g.company)}/oauth/authorize?{params}", "redirectUri": redirect_uri})


@app.route("/api/hmrc/callback", methods=["GET"])
@login_required
def hmrc_callback():
    """HMRC redirects the user's browser here after they approve (or deny) access in their HMRC
    business tax account. Not under company_required since the company is identified from the
    `state` param we generated ourselves in hmrc_auth_url, not from the URL path."""
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    if error:
        return f"<p>HMRC authorization failed: {error}. Close this tab and try again.</p>"
    try:
        state_data = json.loads(state or "{}")
        company_id = int(state_data["companyId"])
    except (ValueError, KeyError, TypeError):
        return "<p>Invalid state parameter — close this tab and try again.</p>", 400

    db = get_db()
    company = db.execute(
        "SELECT * FROM companies WHERE id = ? AND user_id = ?", (company_id, session["user_id"])
    ).fetchone()
    if company is None:
        return "<p>Company not found.</p>", 404
    client_id = (company["hmrc_client_id"] or "").strip()
    client_secret = decrypt_secret(company["hmrc_client_secret"])
    redirect_uri = f"{request.host_url.rstrip('/')}/api/hmrc/callback"

    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "client_id": client_id, "client_secret": client_secret,
        "redirect_uri": redirect_uri, "code": code,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{hmrc_host(company)}/oauth/token", data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        return f"<p>Token exchange with HMRC failed: {e}. Close this tab and try again.</p>", 502

    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(seconds=token_data.get("expires_in", 14400))).isoformat()
    db.execute(
        "UPDATE companies SET hmrc_access_token = ?, hmrc_refresh_token = ?, hmrc_token_expires_at = ? WHERE id = ?",
        (encrypt_secret(token_data["access_token"]), encrypt_secret(token_data.get("refresh_token", "")), expires_at, company_id),
    )
    db.commit()
    return "<p>Connected to HMRC successfully. You can close this tab and return to the app.</p>"


@app.route("/api/companies/<int:company_id>/hmrc/obligations", methods=["GET"])
@login_required
@company_required
def hmrc_obligations(company_id):
    vrn = (g.company["hmrc_vrn"] or "").strip()
    if not vrn:
        return jsonify({"error": "No VAT registration number set for this company — add one in Settings."}), 400
    try:
        result = call_hmrc(g.company, "GET", f"/organisations/vat/{vrn}/obligations?status=O")
    except HmrcError as e:
        return jsonify({"error": e.message}), e.status
    return jsonify(result)


@app.route("/api/companies/<int:company_id>/hmrc/submit-vat-return", methods=["POST"])
@login_required
@company_required
@write_required
def hmrc_submit_vat_return(company_id):
    """Body carries the same Box 1-9 figures the existing (review-only) VAT Return already
    computes client-side — this endpoint just submits them to HMRC rather than recalculating,
    so what gets filed is exactly what the user saw on screen."""
    vrn = (g.company["hmrc_vrn"] or "").strip()
    if not vrn:
        return jsonify({"error": "No VAT registration number set for this company — add one in Settings."}), 400
    data = request.get_json(force=True) or {}
    required = ["periodKey", "vatDueSales", "vatDueAcquisitions", "totalVatDue", "vatReclaimedCurrPeriod",
                "netVatDue", "totalValueSalesExVAT", "totalValuePurchasesExVAT", "totalValueGoodsSuppliedExVAT",
                "totalAcquisitionsExVAT"]
    if any(k not in data for k in required):
        return jsonify({"error": f"Missing required fields: {', '.join(k for k in required if k not in data)}"}), 400
    payload = {k: data[k] for k in required}
    payload["finalised"] = bool(data.get("finalised"))
    try:
        result = call_hmrc(g.company, "POST", f"/organisations/vat/{vrn}/returns", data=payload)
    except HmrcError as e:
        return jsonify({"error": e.message}), e.status

    db = get_db()
    db.execute(
        "INSERT INTO vat_filings (company_id, period_key, net_vat_due_pence, payload_json, hmrc_response_json, submitted_by) "
        "VALUES (?,?,?,?,?,?)",
        (company_id, payload["periodKey"], to_pence(payload["netVatDue"]), json.dumps(payload), json.dumps(result),
         session.get("email", "unknown")),
    )
    db.commit()
    return jsonify(result)


@app.route("/api/companies/<int:company_id>/vat-filings", methods=["GET"])
@login_required
@company_required
def list_vat_filings(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, period_key as periodKey, net_vat_due_pence as netVatDuePence, payload_json as payloadJson, "
        "hmrc_response_json as hmrcResponseJson, submitted_by as submittedBy, submitted_at as submittedAt "
        "FROM vat_filings WHERE company_id = ? ORDER BY submitted_at DESC",
        (company_id,),
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["netVatDue"] = from_pence(d.pop("netVatDuePence"))
        d["payload"] = json.loads(d.pop("payloadJson"))
        d["hmrcResponse"] = json.loads(d.pop("hmrcResponseJson"))
        out.append(d)
    return jsonify(out)


init_db()  # runs on import too, not just `python3 server.py` directly — gunicorn imports this module without executing __main__

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"  # default on for local dev; set FLASK_DEBUG=0 to turn off
    # Local HTTPS dev only — set FLASK_HTTPS=1 to get a throwaway self-signed cert (Werkzeug's
    # "adhoc" mode, using the `cryptography` package already a dependency here) for testing
    # anything that requires a secure context (e.g. some browser APIs, OAuth redirect URIs).
    # A real deployment should NOT use this: terminate TLS at nginx (or another reverse proxy)
    # with a properly issued certificate, then run this app over plain HTTP behind it via gunicorn
    # — see the deploy notes in the README.
    use_https = os.environ.get("FLASK_HTTPS", "0") == "1"
    app.run(host="127.0.0.1", port=5050, debug=debug, ssl_context="adhoc" if use_https else None)
