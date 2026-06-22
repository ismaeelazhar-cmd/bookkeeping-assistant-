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


SCHEMA_VERSION = 3  # bumped for Stage 2: contacts + invoices/bills


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
    if "currency" not in company_cols:
        db.execute("ALTER TABLE companies ADD COLUMN currency TEXT NOT NULL DEFAULT 'GBP'")
    if "confidence_threshold" not in company_cols:
        db.execute("ALTER TABLE companies ADD COLUMN confidence_threshold REAL NOT NULL DEFAULT 0.7")
    contact_cols = {row[1] for row in db.execute("PRAGMA table_info(contacts)").fetchall()}
    if "address_line1" not in contact_cols:
        db.execute("ALTER TABLE contacts ADD COLUMN address_line1 TEXT DEFAULT ''")
        db.execute("ALTER TABLE contacts ADD COLUMN address_city TEXT DEFAULT ''")
        db.execute("ALTER TABLE contacts ADD COLUMN address_postcode TEXT DEFAULT ''")
        db.execute("ALTER TABLE contacts ADD COLUMN address_country TEXT DEFAULT ''")
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


def guess_account_type(name):
    n = name.lower()
    if n == "cash" or "bank" in n:
        return "cash"
    if "accumulated depreciation" in n:
        return "noncurrent_asset"
    if "depreciation" in n:
        return "expense"
    if "drawing" in n:
        return "drawings"
    if n == "capital" or "capital introduced" in n or "share capital" in n or "share premium" in n or "opening balance equity" in n:
        return "equity"
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


def seed_default_chart(db, company_id):
    for name, account_type in DEFAULT_CHART:
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
        "fund_accounting_enabled, plaid_client_id, plaid_secret, plaid_env, confidence_threshold, "
        "'owner' as permission "
        "FROM companies WHERE user_id = ? "
        "UNION ALL "
        "SELECT c.id, c.name, c.default_credit_account, c.ai_api_key, c.locked_until, c.period_start_date, "
        "c.fund_accounting_enabled, c.plaid_client_id, c.plaid_secret, c.plaid_env, c.confidence_threshold, "
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
        result.append(d)
    return jsonify(result)


@app.route("/api/companies", methods=["POST"])
@login_required
def create_company():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Company name is required."}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO companies (user_id, name) VALUES (?, ?)", (session["user_id"], name)
    )
    seed_default_chart(db, cur.lastrowid)
    db.commit()
    return jsonify({
        "id": cur.lastrowid, "name": name, "default_credit_account": "", "ai_api_key_set": False,
        "locked_until": "", "period_start_date": "", "fund_accounting_enabled": 0,
        "plaid_client_id": "", "plaid_secret_set": False, "plaid_env": "sandbox", "permission": "owner",
        "confidence_threshold": 0.7,
    })


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
        "fund_accounting_enabled = ?, plaid_client_id = ?, plaid_env = ?, confidence_threshold = ? WHERE id = ?",
        (
            data.get("defaultCreditAccount", ""), data.get("lockedUntil", ""), data.get("periodStartDate", ""),
            1 if data.get("fundAccountingEnabled") else 0,
            data.get("plaidClientId", ""), data.get("plaidEnv") or "sandbox", confidence_threshold, company_id,
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
    db.commit()
    return jsonify({"ok": True})


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

    return jsonify({
        "memberCount": len(member_ids),
        "accounts": sorted(accounts_out, key=lambda a: a["name"]),
        "summary": {
            "revenue": totals["revenue"], "cogs": totals["cogs"], "expenses": totals["expense"],
            "netProfit": net_profit, "totalAssets": total_assets, "totalLiabilities": total_liabilities,
            "totalEquity": total_equity,
        },
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

    for r in rows:
        amount = from_pence(r["amount_pence"])
        fund_type = r["fundType"] or "unfunded"
        if r["creditType"] in ("revenue", "cogs"):
            by_fund_type[fund_type]["incoming"] += amount
        if r["debitType"] == "expense":
            by_fund_type[fund_type]["expended"] += amount

    for bucket in by_fund_type.values():
        bucket["net"] = bucket["incoming"] - bucket["expended"]

    total_incoming = sum(b["incoming"] for b in by_fund_type.values())
    total_expended = sum(b["expended"] for b in by_fund_type.values())

    return jsonify({
        "byFundType": by_fund_type,
        "totalIncoming": total_incoming,
        "totalExpended": total_expended,
        "netMovement": total_incoming - total_expended,
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
        f"f.name as fund, "
        f"(SELECT COUNT(*) FROM attachments a WHERE a.transaction_id = t.id) as attachmentCount "
        f"FROM transactions t LEFT JOIN funds f ON f.id = t.fund_id "
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
            "NULL as fund, 0 as attachmentCount "
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
                             vat_rate=0, vat_direction="", confidence="high", journal_id=None, fund_id=None):
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
        "INSERT INTO transactions (company_id, date, desc, amount_pence, debit, credit, tax_year, vat_rate, vat_direction, confidence, journal_id, fund_id) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (company_id, date, desc, net_pence, debit, credit, tax_year, vat_rate, vat_direction, confidence, leg_journal_id, fund_id),
    )
    main_id = cur.lastrowid

    if vat_pence:
        vat_account = resolve_account(db, company_id, "VAT Control Account", "current_liability")
        if vat_direction == "input":  # purchase: VAT is reclaimable, sits as a debit
            vat_debit, vat_credit = vat_account, credit
        else:  # output: sale, VAT is owed to HMRC, sits as a credit
            vat_debit, vat_credit = debit, vat_account
        db.execute(
            "INSERT INTO transactions (company_id, date, desc, amount_pence, debit, credit, tax_year, vat_rate, vat_direction, confidence, journal_id, fund_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (company_id, date, f"{desc} (VAT)", vat_pence, vat_debit, vat_credit, tax_year, vat_rate, vat_direction, confidence, leg_journal_id, fund_id),
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
        tx_id = post_ledger_transaction(
            db, company_id, data.get("date"), data.get("desc"), data.get("amount"),
            data.get("debit"), data.get("credit"),
            float(data.get("vatRate") or 0), data.get("vatDirection") or "",
            data.get("confidence") or "high", fund_id=fund_id,
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
    items = request.get_json(force=True) or []
    db = get_db()
    inserted = 0
    skipped_locked = 0
    for it in items:
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
    return jsonify({"inserted": inserted, "skippedLocked": skipped_locked})


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


@app.route("/api/companies/<int:company_id>/attachments/<int:attachment_id>/extract", methods=["POST"])
@login_required
@company_required
@write_required
def extract_attachment(company_id, attachment_id):
    """Stage 5 receipt OCR: send the stored file to Claude (vision for images, native
    document support for PDFs) and ask it to read off date/description/amount/vendor —
    same server-side-key pattern as ai_categorize, nothing new exposed to the browser."""
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
        file_b64 = base64.b64encode(f.read()).decode("ascii")

    block_type = "document" if row["mime_type"] == "application/pdf" else "image"
    prompt_text = (
        "This is a receipt or invoice. Read off the date (YYYY-MM-DD), a short description "
        "(vendor/item), and the total amount paid (a positive number, the gross/final total). "
        'Return ONLY JSON, no prose: {"date":"YYYY-MM-DD","desc":"...","amount":0.00}. '
        'If you genuinely cannot read a field, use null for it.'
    )
    messages = [{
        "role": "user",
        "content": [
            {"type": block_type, "source": {"type": "base64", "media_type": row["mime_type"], "data": file_b64}},
            {"type": "text", "text": prompt_text},
        ],
    }]
    try:
        raw_text = call_claude(api_key, messages, max_tokens=1024)
    except urllib.error.HTTPError as e:
        return jsonify({"error": f"Anthropic API error {e.code}: {e.read().decode('utf-8', 'replace')[:300]}"}), 502
    except urllib.error.URLError as e:
        return jsonify({"error": f"Could not reach Anthropic API: {e.reason}"}), 502

    match = re.search(r"\{[\s\S]*\}", raw_text)
    if not match:
        return jsonify({"error": "Claude did not return a parseable result."}), 502
    try:
        extracted = json.loads(match.group(0))
    except json.JSONDecodeError:
        return jsonify({"error": "Claude's response wasn't valid JSON."}), 502
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
        "ib.status, ib.transaction_id as transactionId, ib.payment_transaction_id as paymentTransactionId "
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
    if kind not in ("invoice", "bill"):
        return jsonify({"error": "kind must be 'invoice' or 'bill'."}), 400
    if not all([contact_id, date, due_date, desc, account]) or not amount or float(amount) <= 0:
        return jsonify({"error": "Contact, dates, description, account, and a positive amount are all required."}), 400

    db = get_db()
    account = resolve_account(db, company_id, account, "revenue" if kind == "invoice" else "expense")
    cur = db.execute(
        "INSERT INTO invoices_bills (company_id, kind, contact_id, date, due_date, desc, amount_pence, account, vat_rate) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (company_id, kind, contact_id, date, due_date, desc, to_pence(amount), account, float(data.get("vatRate") or 0)),
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
    if doc["kind"] == "invoice":
        debtors_account = resolve_account(db, company_id, "Trade Receivables", "current_asset")
        debit, credit, vat_direction = debtors_account, doc["account"], "output"
    else:
        creditors_account = resolve_account(db, company_id, "Trade Payables", "current_liability")
        debit, credit, vat_direction = doc["account"], creditors_account, "input"

    try:
        tx_id = post_ledger_transaction(
            db, company_id, doc["date"], f'{"Invoice" if doc["kind"] == "invoice" else "Bill"}: {doc["desc"]}',
            amount, debit, credit, vat_rate=doc["vat_rate"], vat_direction=vat_direction if doc["vat_rate"] else "",
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status

    db.execute(
        "UPDATE invoices_bills SET status = 'sent', transaction_id = ? WHERE id = ?", (tx_id, doc_id)
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

    db = get_db()
    doc = db.execute(
        "SELECT * FROM invoices_bills WHERE id = ? AND company_id = ?", (doc_id, company_id)
    ).fetchone()
    if doc is None:
        return jsonify({"error": "Not found."}), 404
    if doc["status"] != "sent":
        return jsonify({"error": "Only a sent invoice/bill can be marked paid."}), 400

    amount = from_pence(doc["amount_pence"])
    if doc["kind"] == "invoice":
        debtors_account = resolve_account(db, company_id, "Trade Receivables", "current_asset")
        debit, credit = payment_account, debtors_account
    else:
        creditors_account = resolve_account(db, company_id, "Trade Payables", "current_liability")
        debit, credit = creditors_account, payment_account

    try:
        tx_id = post_ledger_transaction(
            db, company_id, payment_date, f'Payment: {doc["desc"]}', amount, debit, credit
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status

    db.execute(
        "UPDATE invoices_bills SET status = 'paid', payment_transaction_id = ? WHERE id = ?", (tx_id, doc_id)
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


@app.route("/api/companies/<int:company_id>/aging-report", methods=["GET"])
@login_required
@company_required
def aging_report(company_id):
    db = get_db()
    today = datetime.date.today()
    rows = db.execute(
        "SELECT ib.kind, ib.contact_id as contactId, c.name as contactName, ib.due_date as dueDate, "
        "ib.amount_pence as amountPence "
        "FROM invoices_bills ib JOIN contacts c ON c.id = ib.contact_id "
        "WHERE ib.company_id = ? AND ib.status = 'sent'",
        (company_id,),
    ).fetchall()

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
        due = datetime.date.fromisoformat(r["dueDate"])
        days_overdue = (today - due).days
        bucket = bucket_for(days_overdue)
        contact_bucket = result[r["kind"]].setdefault(r["contactName"], {
            "current": 0, "1-30": 0, "31-60": 0, "61-90": 0, "90+": 0
        })
        contact_bucket[bucket] += from_pence(r["amountPence"])
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
            db.execute(
                "INSERT INTO bank_lines (company_id, cash_account, date, desc, amount_pence, external_id) "
                "VALUES (?,?,?,?,?,?) ON CONFLICT(company_id, external_id) WHERE external_id IS NOT NULL DO NOTHING",
                (
                    conn["company_id"], conn["cash_account"], tx["date"],
                    tx.get("merchant_name") or tx.get("name") or "Bank transaction",
                    to_pence(amount), tx["transaction_id"],
                ),
            )
            inserted += 1
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

    posted, skipped = [], []
    for rj in due:
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
    return jsonify({"posted": posted, "skipped": skipped})


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
