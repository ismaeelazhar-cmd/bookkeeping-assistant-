import json

import server as server_module
from conftest import signup, create_company


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def enable_ai(client, cid):
    client.put(f"/api/companies/{cid}/settings", json={"aiApiKey": "sk-ant-test-key"})


def test_no_ai_provider_configured_falls_back_to_plain_guess(client, monkeypatch):
    cid = make_company(client)

    def boom(*a, **kw):
        raise AssertionError("call_ai should never be invoked when no provider is configured")
    monkeypatch.setattr(server_module, "call_ai", boom)

    import sqlite3
    conn = sqlite3.connect(server_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    server_module.queue_plaid_line_if_unsure(conn, cid, "Cash", "2026-06-01", "SOME UNKNOWN MERCHANT LTD", -45.00)
    conn.commit()
    conn.close()

    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert len(queue) == 1
    assert queue[0]["source"] == "plaid"
    assert queue[0]["suggestedDebit"] == "Uncategorized"


def test_ai_configured_and_no_rule_match_queues_ai_suggestion(client, monkeypatch):
    cid = make_company(client)
    enable_ai(client, cid)

    def fake_call_ai(company, messages, max_tokens=1024):
        return json.dumps([{"date": "2026-06-01", "desc": "Coffee shop supplies", "amount": 45.0, "debit": "Office Expenses", "credit": "Cash"}])
    monkeypatch.setattr(server_module, "call_ai", fake_call_ai)

    import sqlite3
    conn = sqlite3.connect(server_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    server_module.queue_plaid_line_if_unsure(conn, cid, "Cash", "2026-06-01", "COFFEE SHOP SUPPLIES LTD", -45.00)
    conn.commit()
    conn.close()

    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert len(queue) == 1
    assert queue[0]["source"] == "ai"
    assert queue[0]["suggestedDebit"] == "Office Expenses"
    assert queue[0]["suggestedCredit"] == "Cash"
    assert "AI-suggested" in queue[0]["reason"]
    # never silently posted, even though this is a clean, confident-looking suggestion
    assert client.get(f"/api/companies/{cid}/transactions").get_json() == []


def test_ai_call_failure_falls_back_to_plain_guess_gracefully(client, monkeypatch):
    cid = make_company(client)
    enable_ai(client, cid)

    def broken_call_ai(company, messages, max_tokens=1024):
        raise ValueError("boom")
    monkeypatch.setattr(server_module, "call_ai", broken_call_ai)

    import sqlite3
    conn = sqlite3.connect(server_module.DB_PATH)
    conn.row_factory = sqlite3.Row
    server_module.queue_plaid_line_if_unsure(conn, cid, "Cash", "2026-06-01", "MYSTERY MERCHANT", -20.00)
    conn.commit()
    conn.close()

    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert len(queue) == 1
    assert queue[0]["source"] == "plaid"
    assert queue[0]["suggestedDebit"] == "Uncategorized"


def test_bulk_import_also_gets_ai_fallback_when_no_rule_matches(client, monkeypatch):
    cid = make_company(client)
    enable_ai(client, cid)

    def fake_call_ai(company, messages, max_tokens=1024):
        return json.dumps([{"date": "2026-06-01", "desc": "Van repair", "amount": 300.0, "debit": "Motor Expenses", "credit": "Cash"}])
    monkeypatch.setattr(server_module, "call_ai", fake_call_ai)

    client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-01", "desc": "VAN REPAIR GARAGE LTD", "amount": -300.0},
    ])
    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert len(queue) == 1
    assert queue[0]["source"] == "ai"
    assert queue[0]["suggestedDebit"] == "Motor Expenses"
