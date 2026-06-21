import sqlite3
import secrets
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


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            date TEXT NOT NULL,
            desc TEXT NOT NULL,
            amount REAL NOT NULL,
            debit TEXT NOT NULL,
            credit TEXT NOT NULL,
            tax_year TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS presets (
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            desc_key TEXT NOT NULL,
            debit TEXT NOT NULL,
            credit TEXT NOT NULL,
            PRIMARY KEY (company_id, desc_key)
        );

        CREATE TABLE IF NOT EXISTS account_types (
            company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
            account_name TEXT NOT NULL,
            type TEXT NOT NULL,
            PRIMARY KEY (company_id, account_name)
        );
        """
    )
    db.commit()
    db.close()


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
        "SELECT id, name, default_credit_account, ai_api_key FROM companies WHERE user_id = ? ORDER BY name",
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
    db.commit()
    return jsonify({"id": cur.lastrowid, "name": name, "default_credit_account": "", "ai_api_key": ""})


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
        "UPDATE companies SET default_credit_account = ?, ai_api_key = ? WHERE id = ?",
        (data.get("defaultCreditAccount", ""), data.get("aiApiKey", ""), company_id),
    )
    db.commit()
    return jsonify({"ok": True})


# ---------- transactions ----------

@app.route("/api/companies/<int:company_id>/transactions", methods=["GET"])
@login_required
@company_required
def list_transactions(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT id, date, desc, amount, debit, credit, tax_year as taxYear "
        "FROM transactions WHERE company_id = ? ORDER BY date",
        (company_id,),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/companies/<int:company_id>/transactions", methods=["POST"])
@login_required
@company_required
def create_transaction(company_id):
    data = request.get_json(force=True) or {}
    date, desc, amount, debit, credit = (
        data.get("date"), data.get("desc"), data.get("amount"), data.get("debit"), data.get("credit")
    )
    if not all([date, desc, debit, credit]) or not amount or float(amount) <= 0 or debit == credit:
        return jsonify({"error": "Invalid transaction."}), 400

    db = get_db()
    cur = db.execute(
        "INSERT INTO transactions (company_id, date, desc, amount, debit, credit, tax_year) VALUES (?,?,?,?,?,?,?)",
        (company_id, date, desc, float(amount), debit, credit, data.get("taxYear", "")),
    )
    db.execute(
        "INSERT INTO presets (company_id, desc_key, debit, credit) VALUES (?,?,?,?) "
        "ON CONFLICT(company_id, desc_key) DO UPDATE SET debit = excluded.debit, credit = excluded.credit",
        (company_id, desc.strip().lower(), debit, credit),
    )
    db.commit()
    return jsonify({"id": cur.lastrowid})


@app.route("/api/companies/<int:company_id>/transactions/bulk", methods=["POST"])
@login_required
@company_required
def bulk_create_transactions(company_id):
    items = request.get_json(force=True) or []
    db = get_db()
    inserted = 0
    for it in items:
        date, desc, amount, debit, credit = (
            it.get("date"), it.get("desc"), it.get("amount"), it.get("debit"), it.get("credit")
        )
        if not all([date, desc, debit, credit]) or not amount or float(amount) <= 0 or debit == credit:
            continue
        db.execute(
            "INSERT INTO transactions (company_id, date, desc, amount, debit, credit, tax_year) VALUES (?,?,?,?,?,?,?)",
            (company_id, date, desc, float(amount), debit, credit, it.get("taxYear", "")),
        )
        db.execute(
            "INSERT INTO presets (company_id, desc_key, debit, credit) VALUES (?,?,?,?) "
            "ON CONFLICT(company_id, desc_key) DO UPDATE SET debit = excluded.debit, credit = excluded.credit",
            (company_id, desc.strip().lower(), debit, credit),
        )
        inserted += 1
    db.commit()
    return jsonify({"inserted": inserted})


@app.route("/api/companies/<int:company_id>/transactions/<int:tx_id>", methods=["DELETE"])
@login_required
@company_required
def delete_transaction(company_id, tx_id):
    db = get_db()
    db.execute("DELETE FROM transactions WHERE id = ? AND company_id = ?", (tx_id, company_id))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/companies/<int:company_id>/transactions/clear", methods=["POST"])
@login_required
@company_required
def clear_transactions(company_id):
    db = get_db()
    db.execute("DELETE FROM transactions WHERE company_id = ?", (company_id,))
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


# ---------- account types ----------

@app.route("/api/companies/<int:company_id>/account-types", methods=["GET"])
@login_required
@company_required
def list_account_types(company_id):
    db = get_db()
    rows = db.execute(
        "SELECT account_name, type FROM account_types WHERE company_id = ?", (company_id,)
    ).fetchall()
    return jsonify({r["account_name"]: r["type"] for r in rows})


@app.route("/api/companies/<int:company_id>/account-types", methods=["PUT"])
@login_required
@company_required
def set_account_type(company_id):
    data = request.get_json(force=True) or {}
    name, type_ = data.get("name"), data.get("type")
    if not name or not type_:
        return jsonify({"error": "name and type are required."}), 400
    db = get_db()
    db.execute(
        "INSERT INTO account_types (company_id, account_name, type) VALUES (?,?,?) "
        "ON CONFLICT(company_id, account_name) DO UPDATE SET type = excluded.type",
        (company_id, name, type_),
    )
    db.commit()
    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5050, debug=True)
