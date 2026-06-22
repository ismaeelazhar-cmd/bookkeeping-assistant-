import sqlite3
import secrets
import json
import datetime
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, session, send_from_directory, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data.sqlite"

app = Flask(__name__, static_folder=str(BASE_DIR / "static"))
app.secret_key = secrets.token_hex(32)  # regenerates on restart -> logs everyone out on deploy; fine for now


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


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
        """
    )
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


def is_locked(company_row, date_str):
    locked_until = company_row["locked_until"] if company_row else ""
    return bool(locked_until) and date_str <= locked_until


# ---------- auth helpers ----------

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Not logged in"}), 401
        return fn(*args, **kwargs)
    return wrapper


def company_required(fn):
    @wraps(fn)
    def wrapper(company_id, *args, **kwargs):
        db = get_db()
        row = db.execute(
            "SELECT * FROM companies WHERE id = ? AND user_id = ?",
            (company_id, session["user_id"]),
        ).fetchone()
        if row is None:
            return jsonify({"error": "Company not found"}), 404
        g.company = row
        return fn(company_id, *args, **kwargs)
    return wrapper


# ---------- static / pages ----------

@app.route("/")
def index():
    return send_from_directory(str(BASE_DIR / "templates"), "index.html")


# ---------- auth endpoints ----------

@app.route("/api/signup", methods=["POST"])
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
def login():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Incorrect email or password."}), 401

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


# ---------- companies ----------

@app.route("/api/companies", methods=["GET"])
@login_required
def list_companies():
    db = get_db()
    rows = db.execute(
        "SELECT id, name, default_credit_account, ai_api_key, locked_until, period_start_date "
        "FROM companies WHERE user_id = ? ORDER BY name",
        (session["user_id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


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
        "id": cur.lastrowid, "name": name, "default_credit_account": "", "ai_api_key": "",
        "locked_until": "", "period_start_date": "",
    })


@app.route("/api/companies/<int:company_id>", methods=["DELETE"])
@login_required
@company_required
def delete_company(company_id):
    db = get_db()
    db.execute("DELETE FROM companies WHERE id = ?", (company_id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/settings", methods=["PUT"])
@login_required
@company_required
def update_settings(company_id):
    data = request.get_json(force=True) or {}
    db = get_db()
    db.execute(
        "UPDATE companies SET default_credit_account = ?, ai_api_key = ?, locked_until = ?, period_start_date = ? WHERE id = ?",
        (
            data.get("defaultCreditAccount", ""), data.get("aiApiKey", ""),
            data.get("lockedUntil", ""), data.get("periodStartDate", ""), company_id,
        ),
    )
    db.commit()
    return jsonify({"ok": True})


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
        f"SELECT id, date, desc, amount_pence as amountPence, debit, credit, tax_year as taxYear, "
        f"vat_rate as vatRate, vat_direction as vatDirection, confidence, voided_at as voidedAt, voided_by as voidedBy "
        f"FROM transactions WHERE company_id = ? {voided_clause} ORDER BY date",
        (company_id,),
    ).fetchall()
    return jsonify([_serialize_transaction(r) for r in rows])


class LedgerError(Exception):
    def __init__(self, message, status=400):
        self.message = message
        self.status = status


def post_ledger_transaction(db, company_id, date, desc, amount, debit, credit, tax_year="",
                             vat_rate=0, vat_direction="", confidence="high"):
    """Shared insert path for anything that writes to the ledger — manual entries, bulk
    imports, and (Stage 2) invoice/bill send-and-pay postings — so they all get the same
    account resolution, locking check, preset learning, and audit trail."""
    if not all([date, desc, debit, credit]) or not amount or float(amount) <= 0 or debit == credit:
        raise LedgerError("Invalid transaction.")
    if not _valid_vat_direction(vat_direction):
        raise LedgerError("Invalid VAT direction.")
    if is_locked(g.company, date):
        raise LedgerError(f"This period is locked until {g.company['locked_until']} — unlock it in settings first.", 423)

    debit = resolve_account(db, company_id, debit)
    credit = resolve_account(db, company_id, credit)
    cur = db.execute(
        "INSERT INTO transactions (company_id, date, desc, amount_pence, debit, credit, tax_year, vat_rate, vat_direction, confidence) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (company_id, date, desc, to_pence(amount), debit, credit, tax_year, vat_rate, vat_direction, confidence),
    )
    db.execute(
        "INSERT INTO presets (company_id, desc_key, debit, credit) VALUES (?,?,?,?) "
        "ON CONFLICT(company_id, desc_key) DO UPDATE SET debit = excluded.debit, credit = excluded.credit",
        (company_id, desc.strip().lower(), debit, credit),
    )
    log_audit(db, company_id, "create", "transaction", cur.lastrowid, after={
        "date": date, "desc": desc, "amount": amount, "debit": debit, "credit": credit
    })
    return cur.lastrowid


@app.route("/api/companies/<int:company_id>/transactions", methods=["POST"])
@login_required
@company_required
def create_transaction(company_id):
    data = request.get_json(force=True) or {}
    db = get_db()
    try:
        tx_id = post_ledger_transaction(
            db, company_id, data.get("date"), data.get("desc"), data.get("amount"),
            data.get("debit"), data.get("credit"), data.get("taxYear", ""),
            float(data.get("vatRate") or 0), data.get("vatDirection") or "",
            data.get("confidence") or "high",
        )
    except LedgerError as e:
        return jsonify({"error": e.message}), e.status
    db.commit()
    return jsonify({"id": tx_id})


@app.route("/api/companies/<int:company_id>/transactions/bulk", methods=["POST"])
@login_required
@company_required
def bulk_create_transactions(company_id):
    items = request.get_json(force=True) or []
    db = get_db()
    inserted = 0
    skipped_locked = 0
    for it in items:
        try:
            post_ledger_transaction(
                db, company_id, it.get("date"), it.get("desc"), it.get("amount"),
                it.get("debit"), it.get("credit"), it.get("taxYear", ""),
                float(it.get("vatRate") or 0), it.get("vatDirection") or "",
                it.get("confidence") or "high",
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
def void_transaction(company_id, tx_id):
    db = get_db()
    row = db.execute(
        "SELECT date, desc, amount_pence as amountPence, debit, credit FROM transactions "
        "WHERE id = ? AND company_id = ? AND voided_at IS NULL",
        (tx_id, company_id),
    ).fetchone()
    if row is None:
        return jsonify({"ok": True})
    if is_locked(g.company, row["date"]):
        return jsonify({"error": f"This period is locked until {g.company['locked_until']} — unlock it in settings first."}), 423
    now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
    db.execute(
        "UPDATE transactions SET voided_at = ?, voided_by = ? WHERE id = ? AND company_id = ?",
        (now, session.get("email", "unknown"), tx_id, company_id),
    )
    log_audit(db, company_id, "void", "transaction", tx_id, before=_serialize_transaction(row))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/transactions/clear", methods=["POST"])
@login_required
@company_required
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
            amount, debit, credit, "", doc["vat_rate"], vat_direction if doc["vat_rate"] else "",
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
        tx = db.execute("SELECT date FROM transactions WHERE id = ? AND voided_at IS NULL", (tx_id,)).fetchone()
        if tx and not is_locked(g.company, tx["date"]):
            now = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
            db.execute(
                "UPDATE transactions SET voided_at = ?, voided_by = ? WHERE id = ?",
                (now, session.get("email", "unknown"), tx_id),
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
def delete_fixed_asset(company_id, asset_id):
    db = get_db()
    db.execute("DELETE FROM fixed_assets WHERE id = ? AND company_id = ?", (asset_id, company_id))
    db.commit()
    return jsonify({"ok": True})


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
def delete_bank_line(company_id, line_id):
    db = get_db()
    db.execute("DELETE FROM bank_lines WHERE id = ? AND company_id = ?", (line_id, company_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/bank-lines/<int:line_id>/match", methods=["POST"])
@login_required
@company_required
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


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5050, debug=True)
