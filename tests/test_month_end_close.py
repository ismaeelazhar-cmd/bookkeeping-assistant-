from conftest import signup, create_company


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def test_run_recurring_invoices_now_route_exists_and_returns_summary(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/recurring-invoices/run")
    assert res.status_code == 200
    assert res.get_json() == []  # nothing due yet, but the route itself works end-to-end


def test_run_depreciation_now_posts_for_every_asset(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Laptop", "assetAccount": "Fixed Assets", "cost": 1200,
        "purchaseDate": "2020-01-01", "usefulLifeYears": 3,
    })
    client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Van", "assetAccount": "Fixed Assets", "cost": 6000,
        "purchaseDate": "2020-01-01", "usefulLifeYears": 5,
    })
    res = client.post(f"/api/companies/{cid}/run-depreciation")
    assert res.status_code == 200
    body = res.get_json()
    assert len(body["posted"]) == 2
    names = {p["name"] for p in body["posted"]}
    assert names == {"Laptop", "Van"}


def test_run_depreciation_now_is_idempotent_same_day(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Laptop", "assetAccount": "Fixed Assets", "cost": 1200,
        "purchaseDate": "2020-01-01", "usefulLifeYears": 3,
    })
    client.post(f"/api/companies/{cid}/run-depreciation")
    second = client.post(f"/api/companies/{cid}/run-depreciation")
    body = second.get_json()
    assert body["posted"] == []
    assert len(body["skipped"]) == 1
