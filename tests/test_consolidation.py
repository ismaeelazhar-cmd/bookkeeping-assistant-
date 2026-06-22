from conftest import signup, create_company, post_transaction


def make_two_companies(client):
    signup(client, "parent@example.com")
    cid1 = create_company(client, "Charity Parent").get_json()["id"]
    cid2 = create_company(client, "Trading Sub").get_json()["id"]
    return cid1, cid2


def test_create_group_requires_two_companies(client):
    make_two_companies(client)
    res = client.post("/api/consolidation-groups", json={"name": "Too Few", "companyIds": [1]})
    assert res.status_code == 400


def test_create_group_rejects_unowned_companies(client):
    cid1, cid2 = make_two_companies(client)
    client.post("/api/logout")
    signup(client, "other@example.com")
    res = client.post("/api/consolidation-groups", json={"name": "Stolen", "companyIds": [cid1, cid2]})
    assert res.status_code == 403


def test_create_and_list_group(client):
    cid1, cid2 = make_two_companies(client)
    res = client.post("/api/consolidation-groups", json={"name": "Whole Org", "companyIds": [cid1, cid2]})
    assert res.status_code == 200
    groups = client.get("/api/consolidation-groups").get_json()
    assert groups[0]["name"] == "Whole Org"
    assert {m["id"] for m in groups[0]["members"]} == {cid1, cid2}


def test_consolidated_report_sums_across_companies(client):
    cid1, cid2 = make_two_companies(client)
    post_transaction(client, cid1, desc="Donation", amount=1000, debit="Cash", credit="Sales")
    post_transaction(client, cid2, desc="Trading income", amount=2000, debit="Cash", credit="Sales")
    post_transaction(client, cid2, desc="Rent", amount=500, debit="Office Expenses", credit="Cash")

    group_id = client.post("/api/consolidation-groups", json={"name": "Whole Org", "companyIds": [cid1, cid2]}).get_json()["id"]
    report = client.get(f"/api/consolidation-groups/{group_id}/report").get_json()

    assert report["memberCount"] == 2
    assert report["summary"]["revenue"] == 3000.0
    assert report["summary"]["expenses"] == 500.0
    assert report["summary"]["netProfit"] == 2500.0
    assert report["summary"]["totalAssets"] == 2500.0
    assert report["summary"]["totalLiabilities"] == 0
    assert report["summary"]["totalEquity"] == 2500.0
    # the accounting equation must hold on the combined view too
    assert report["summary"]["totalAssets"] == report["summary"]["totalLiabilities"] + report["summary"]["totalEquity"]


def test_delete_group_leaves_companies_untouched(client):
    cid1, cid2 = make_two_companies(client)
    post_transaction(client, cid1)
    group_id = client.post("/api/consolidation-groups", json={"name": "x", "companyIds": [cid1, cid2]}).get_json()["id"]
    client.delete(f"/api/consolidation-groups/{group_id}")
    assert client.get("/api/consolidation-groups").get_json() == []
    assert len(client.get(f"/api/companies/{cid1}/transactions").get_json()) == 1
