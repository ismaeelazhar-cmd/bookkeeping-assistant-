from conftest import signup, create_company, post_transaction


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def test_company_seeds_default_chart(client):
    cid = make_company(client)
    names = {a["name"] for a in client.get(f"/api/companies/{cid}/accounts").get_json()}
    assert {"Cash", "Sales", "Opening Balance Equity", "VAT Control Account"} <= names


def test_account_case_insensitive_dedup(client):
    """The core Stage 1 bug fix: 'Cash' and 'cash' must resolve to the same account."""
    cid = make_company(client)
    post_transaction(client, cid, credit="cash")
    res = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert res[0]["credit"] == "Cash"  # snapped to the canonical casing, not a new "cash" row

    cash_accounts = [a for a in client.get(f"/api/companies/{cid}/accounts").get_json() if a["name"].lower() == "cash"]
    assert len(cash_accounts) == 1


def test_pence_precision_no_float_drift(client):
    cid = make_company(client)
    post_transaction(client, cid, amount=10.10)
    post_transaction(client, cid, amount=19.99)
    amounts = [t["amount"] for t in client.get(f"/api/companies/{cid}/transactions").get_json()]
    assert sorted(amounts) == [10.10, 19.99]


def test_duplicate_debit_credit_rejected(client):
    cid = make_company(client)
    res = post_transaction(client, cid, debit="Cash", credit="Cash")
    assert res.status_code == 400


def test_unknown_account_auto_created(client):
    cid = make_company(client)
    post_transaction(client, cid, debit="Brand New Expense Category")
    names = {a["name"] for a in client.get(f"/api/companies/{cid}/accounts").get_json()}
    assert "Brand New Expense Category" in names


def test_account_rename_cascades_to_transactions(client):
    cid = make_company(client)
    post_transaction(client, cid, debit="Office Expenses")
    accounts = client.get(f"/api/companies/{cid}/accounts").get_json()
    office = next(a for a in accounts if a["name"] == "Office Expenses")
    client.put(f"/api/companies/{cid}/accounts/{office['id']}", json={"name": "Stationery"})
    tx = client.get(f"/api/companies/{cid}/transactions").get_json()[0]
    assert tx["debit"] == "Stationery"


def test_account_delete_blocked_when_in_use(client):
    cid = make_company(client)
    post_transaction(client, cid, debit="Office Expenses")
    accounts = client.get(f"/api/companies/{cid}/accounts").get_json()
    office = next(a for a in accounts if a["name"] == "Office Expenses")
    res = client.delete(f"/api/companies/{cid}/accounts/{office['id']}")
    assert res.status_code == 409


def test_soft_delete_excludes_by_default_but_recoverable(client):
    cid = make_company(client)
    tx_id = post_transaction(client, cid).get_json()["id"]
    client.delete(f"/api/companies/{cid}/transactions/{tx_id}")

    assert client.get(f"/api/companies/{cid}/transactions").get_json() == []
    voided = client.get(f"/api/companies/{cid}/transactions?includeVoided=1").get_json()
    assert voided[0]["voidedAt"] is not None
    assert voided[0]["voidedBy"] == "owner@example.com"


def test_period_lock_blocks_postings_on_or_before(client):
    cid = make_company(client)
    client.put(f"/api/companies/{cid}/settings", json={"lockedUntil": "2026-06-15"})

    blocked = post_transaction(client, cid, date="2026-06-10")
    assert blocked.status_code == 423

    allowed = post_transaction(client, cid, date="2026-06-20")
    assert allowed.status_code == 200


def test_period_lock_blocks_delete_too(client):
    cid = make_company(client)
    tx_id = post_transaction(client, cid, date="2026-06-10").get_json()["id"]
    client.put(f"/api/companies/{cid}/settings", json={"lockedUntil": "2026-06-15"})
    res = client.delete(f"/api/companies/{cid}/transactions/{tx_id}")
    assert res.status_code == 423


def test_opening_balance_feeds_cash_position(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/opening-balances/bulk", json=[
        {"account": "Cash", "amount": 5000, "side": "debit", "asOfDate": "2026-01-01"}
    ])
    assert res.get_json()["saved"] == 1
    ob = client.get(f"/api/companies/{cid}/opening-balances").get_json()
    assert ob[0]["amount"] == 5000.0
    assert ob[0]["account"] == "Cash"


def test_export_never_contains_raw_ai_key(client):
    cid = make_company(client)
    client.put(f"/api/companies/{cid}/settings", json={"aiApiKey": "sk-ant-shouldnotleak"})
    post_transaction(client, cid)
    dump = client.get(f"/api/companies/{cid}/export").get_json()
    assert "sk-ant-shouldnotleak" not in str(dump)


def test_ai_key_never_returned_by_companies_endpoint(client):
    cid = make_company(client)
    client.put(f"/api/companies/{cid}/settings", json={"aiApiKey": "sk-ant-secret"})
    companies = client.get("/api/companies").get_json()
    assert "sk-ant-secret" not in str(companies)
    assert companies[0]["ai_api_key_set"] is True
