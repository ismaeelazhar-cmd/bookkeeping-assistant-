from conftest import signup, create_company, post_transaction


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def test_fund_accounting_off_by_default(client):
    cid = make_company(client)
    companies = client.get("/api/companies").get_json()
    assert companies[0].get("fund_accounting_enabled") in (0, False, None)


def test_enabling_fund_accounting_does_not_disturb_other_settings(client):
    cid = make_company(client)
    client.put(f"/api/companies/{cid}/settings", json={"defaultCreditAccount": "Cash", "lockedUntil": "2026-01-01"})
    client.put(f"/api/companies/{cid}/settings", json={
        "defaultCreditAccount": "Cash", "lockedUntil": "2026-01-01", "fundAccountingEnabled": True,
    })
    companies = client.get("/api/companies").get_json()
    assert companies[0]["locked_until"] == "2026-01-01"  # untouched by the fund toggle


def test_create_and_list_funds(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/funds", json={"name": "Building Appeal", "type": "restricted"})
    assert res.status_code == 200
    funds = client.get(f"/api/companies/{cid}/funds").get_json()
    assert funds[0]["name"] == "Building Appeal"
    assert funds[0]["type"] == "restricted"


def test_duplicate_fund_name_rejected(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/funds", json={"name": "General Fund", "type": "unrestricted"})
    res = client.post(f"/api/companies/{cid}/funds", json={"name": "general fund", "type": "unrestricted"})
    assert res.status_code == 409


def test_invalid_fund_type_rejected(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/funds", json={"name": "x", "type": "made up"})
    assert res.status_code == 400


def test_transaction_with_unknown_fund_rejected(client):
    cid = make_company(client)
    res = post_transaction(client, cid, fund="Nonexistent Fund")
    assert res.status_code == 400


def test_transaction_tagged_with_fund_appears_in_journal(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/funds", json={"name": "General Fund", "type": "unrestricted"})
    post_transaction(client, cid, fund="General Fund")
    tx = client.get(f"/api/companies/{cid}/transactions").get_json()[0]
    assert tx["fund"] == "General Fund"


def test_fund_delete_blocked_when_in_use(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/funds", json={"name": "General Fund", "type": "unrestricted"})
    post_transaction(client, cid, fund="General Fund")
    fund_id = client.get(f"/api/companies/{cid}/funds").get_json()[0]["id"]
    res = client.delete(f"/api/companies/{cid}/funds/{fund_id}")
    assert res.status_code == 409


def test_sofa_segments_by_fund_type(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/funds", json={"name": "General Fund", "type": "unrestricted"})
    client.post(f"/api/companies/{cid}/funds", json={"name": "Building Appeal", "type": "restricted"})

    post_transaction(client, cid, desc="Donation", amount=1000, debit="Cash", credit="Sales", fund="General Fund")
    post_transaction(client, cid, desc="Grant", amount=5000, debit="Cash", credit="Sales", fund="Building Appeal")
    post_transaction(client, cid, desc="Builders", amount=2000, debit="Office Expenses", credit="Cash", fund="Building Appeal")
    post_transaction(client, cid, desc="Supplies", amount=50, debit="Office Expenses", credit="Cash")  # no fund tag

    sofa = client.get(f"/api/companies/{cid}/sofa").get_json()
    assert sofa["byFundType"]["unrestricted"] == {"incoming": 1000.0, "expended": 0, "net": 1000.0}
    assert sofa["byFundType"]["restricted"] == {"incoming": 5000.0, "expended": 2000.0, "net": 3000.0}
    assert sofa["byFundType"]["unfunded"] == {"incoming": 0, "expended": 50.0, "net": -50.0}
    assert sofa["totalIncoming"] == 6000.0
    assert sofa["totalExpended"] == 2050.0
    assert sofa["netMovement"] == 3950.0
