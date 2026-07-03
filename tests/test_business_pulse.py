import datetime
import sqlite3

import server as server_module
from conftest import signup, create_company, post_transaction


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def _company_row(cid):
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    row = db.execute("SELECT * FROM companies WHERE id = ?", (cid,)).fetchone()
    db.close()
    return row


def make_sent_invoice(client, cid, amount=500, due_date="2020-01-31"):
    client.post(f"/api/companies/{cid}/contacts", json={"name": "J Smith", "type": "customer"})
    contact_id = client.get(f"/api/companies/{cid}/contacts").get_json()[0]["id"]
    doc = client.post(f"/api/companies/{cid}/invoices-bills", json={
        "kind": "invoice", "contactId": contact_id, "date": "2020-01-01", "dueDate": due_date,
        "desc": "Work done", "amount": amount, "account": "Sales",
    }).get_json()
    client.post(f"/api/companies/{cid}/invoices-bills/{doc['id']}/send")
    return doc["id"]


def test_pulse_endpoint_works_without_smtp_and_flags_overdue_invoice(client):
    cid = make_company(client)
    make_sent_invoice(client, cid, amount=750, due_date="2020-01-31")  # long overdue
    res = client.get(f"/api/companies/{cid}/business-pulse")
    assert res.status_code == 200
    lines = res.get_json()["lines"]
    warn_texts = " ".join(l["text"] for l in lines if l["kind"] == "warn")
    assert "overdue" in warn_texts
    assert "750" in warn_texts


def test_pulse_includes_wins_for_recently_paid_invoices(client):
    cid = make_company(client)
    inv = make_sent_invoice(client, cid, amount=300, due_date="2099-01-01")
    client.post(f"/api/companies/{cid}/invoices-bills/{inv}/pay", json={})
    lines = client.get(f"/api/companies/{cid}/business-pulse").get_json()["lines"]
    win_texts = " ".join(l["text"] for l in lines if l["kind"] == "win")
    assert "paid" in win_texts
    assert "300" in win_texts


def test_pulse_outlook_includes_projection_when_there_is_activity(client):
    cid = make_company(client)
    post_transaction(client, cid, amount=1000, debit="Cash", credit="Sales")
    lines = client.get(f"/api/companies/{cid}/business-pulse").get_json()["lines"]
    outlook = [l for l in lines if "30-day outlook" in l["text"]]
    assert len(outlook) == 1
    assert "1,000.00" in outlook[0]["text"]


def test_weekly_pulse_frequency_skips_email_on_non_matching_days(client, monkeypatch):
    cid = make_company(client)
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    # weekly_monday cadence; pretend today is not Monday unless it really is —
    # pick the frequency that does NOT match today's real weekday to test the skip.
    today = datetime.date.today()
    non_matching = "weekly_friday" if today.weekday() != 4 else "weekly_monday"
    db.execute("UPDATE companies SET pulse_frequency = ?, notifications_enabled = 1, notify_email = 'x@example.com' WHERE id = ?",
               (non_matching, cid))
    db.commit()
    company = _company_row(cid)
    result = server_module.run_notifications_for_company(db, company)
    assert result["sent"] is False
    assert "cadence" in result["reason"]
    db.close()


def test_daily_pulse_frequency_still_attempts_email(client):
    cid = make_company(client)
    make_sent_invoice(client, cid, amount=750, due_date="2020-01-31")
    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("UPDATE companies SET notifications_enabled = 1, notify_email = 'x@example.com' WHERE id = ?", (cid,))
    db.commit()
    company = _company_row(cid)
    result = server_module.run_notifications_for_company(db, company)
    # No SMTP configured in tests, so it fails AT the send step — proving it got past cadence gating.
    assert result["sent"] is False
    assert "SMTP" in result["reason"]
    db.close()


def test_rule_match_queues_instead_of_posting_when_auto_post_disabled(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/categorization-rules", json={"keyword": "eon", "debit": "Utilities", "credit": "Cash"})
    client.put(f"/api/companies/{cid}/settings", json={"autoPostRulesEnabled": False})

    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    server_module.queue_plaid_line_if_unsure(db, cid, "Cash", "2026-06-01", "EON ENERGY DD", -79.45)
    db.commit()
    db.close()

    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert len(queue) == 1
    assert queue[0]["suggestedDebit"] == "Utilities"
    assert "auto-posting is turned off" in queue[0]["reason"]
    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert txs == []  # nothing posted silently


def test_rule_match_still_auto_posts_by_default(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/categorization-rules", json={"keyword": "eon", "debit": "Utilities", "credit": "Cash"})

    db = sqlite3.connect(server_module.DB_PATH)
    db.row_factory = sqlite3.Row
    with server_module.app.app_context():
        server_module.queue_plaid_line_if_unsure(db, cid, "Cash", "2026-06-01", "EON ENERGY DD", -79.45)
    db.commit()
    db.close()

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert len(txs) == 1
    assert txs[0]["debit"] == "Utilities"
