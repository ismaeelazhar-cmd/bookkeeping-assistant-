from conftest import signup, create_company


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def test_plaid_credentials_persist_and_secret_is_write_only(client):
    cid = make_company(client)
    client.put(f"/api/companies/{cid}/settings", json={"plaidClientId": "abc123", "plaidSecret": "supersecret", "plaidEnv": "sandbox"})
    companies = client.get("/api/companies").get_json()
    assert companies[0]["plaid_client_id"] == "abc123"
    assert companies[0]["plaid_secret_set"] is True
    assert "supersecret" not in str(companies)


def test_link_token_without_credentials_fails_clearly(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/plaid/link-token", json={})
    assert res.status_code == 400
    assert "credentials" in res.get_json()["error"].lower()


def test_link_token_reaches_plaid_with_fake_credentials(client):
    """We don't have real Plaid credentials in CI/local tests, but a real network call to
    Plaid's sandbox with an invalid client_id proves the request is shaped correctly — Plaid's
    own format validator rejects it, rather than our code failing before the request is sent."""
    cid = make_company(client)
    client.put(f"/api/companies/{cid}/settings", json={"plaidClientId": "not-a-real-id", "plaidSecret": "not-a-real-secret"})
    res = client.post(f"/api/companies/{cid}/plaid/link-token", json={})
    assert res.status_code == 502
    assert "plaid" in res.get_json()["error"].lower()


def test_bank_connections_list_empty_initially(client):
    cid = make_company(client)
    assert client.get(f"/api/companies/{cid}/bank-connections").get_json() == []


def test_sync_dedup_via_partial_unique_index(client):
    """This is the thing that actually broke during development (SQLite's ON CONFLICT target
    didn't match a partial unique index without restating the WHERE clause) — lock it in by
    exercising the exact insert pattern sync_bank_connection() uses, twice."""
    import sqlite3
    import server as server_module

    cid = make_company(client)
    db = sqlite3.connect(server_module.DB_PATH)
    db.execute(
        "INSERT INTO bank_connections (company_id, item_id, access_token, institution_name, cash_account) "
        "VALUES (?,?,?,?,?)",
        (cid, "item_123", server_module.encrypt_secret("fake_token"), "Test Bank", "Cash"),
    )
    db.commit()

    insert_sql = (
        "INSERT INTO bank_lines (company_id, cash_account, date, desc, amount_pence, external_id) "
        "VALUES (?,?,?,?,?,?) ON CONFLICT(company_id, external_id) WHERE external_id IS NOT NULL DO NOTHING"
    )
    db.execute(insert_sql, (cid, "Cash", "2026-06-01", "Coffee shop", -500, "plaid_tx_1"))
    db.execute(insert_sql, (cid, "Cash", "2026-06-01", "Coffee shop", -500, "plaid_tx_1"))  # duplicate sync
    db.commit()

    rows = db.execute("SELECT COUNT(*) FROM bank_lines WHERE company_id = ?", (cid,)).fetchall()
    assert rows[0][0] == 1  # the duplicate was silently dropped, not double-counted
    db.close()


def test_webhook_ignores_non_transactions_types(client):
    res = client.post("/api/plaid/webhook", json={"webhook_type": "ITEM", "webhook_code": "ERROR"})
    assert res.status_code == 200


def test_webhook_ignores_unknown_item_id(client):
    res = client.post("/api/plaid/webhook", json={"webhook_type": "TRANSACTIONS", "item_id": "no_such_item"})
    assert res.status_code == 200
