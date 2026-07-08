from conftest import signup, create_company


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def make_asset(client, cid, cost=1200, useful_life=3, purchase_date="2023-01-01"):
    return client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Laptop", "assetAccount": "Fixed Assets", "cost": cost,
        "purchaseDate": purchase_date, "usefulLifeYears": useful_life,
    }).get_json()["id"]


def test_dispose_with_no_depreciation_posted_is_pure_derecognition(client):
    cid = make_company(client)
    asset_id = make_asset(client, cid, cost=1000)
    res = client.post(f"/api/companies/{cid}/fixed-assets/{asset_id}/dispose", json={
        "date": "2026-01-01", "proceeds": 1000,
    })
    assert res.status_code == 200
    body = res.get_json()
    assert body["netBookValue"] == 1000.0
    assert body["gainOrLoss"] == 0.0
    # asset is gone from the register
    assert client.get(f"/api/companies/{cid}/fixed-assets").get_json() == []


def test_dispose_for_less_than_net_book_value_posts_a_loss(client):
    cid = make_company(client)
    asset_id = make_asset(client, cid, cost=1200, useful_life=3, purchase_date="2020-01-01")
    # run one month of depreciation so accumulated depreciation > 0
    client.post(f"/api/companies/{cid}/fixed-assets/{asset_id}/run-depreciation", json={"date": "2026-01-15"})

    res = client.post(f"/api/companies/{cid}/fixed-assets/{asset_id}/dispose", json={
        "date": "2026-02-01", "proceeds": 100,
    })
    assert res.status_code == 200
    body = res.get_json()
    assert body["gainOrLoss"] < 0  # sold for less than net book value

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    loss_tx = next((t for t in txs if t["debit"] == "Loss on Disposal"), None)
    assert loss_tx is not None
    assert loss_tx["credit"] == "Fixed Assets"


def test_dispose_for_more_than_net_book_value_posts_a_gain(client):
    cid = make_company(client)
    asset_id = make_asset(client, cid, cost=1000, useful_life=5, purchase_date="2020-01-01")

    res = client.post(f"/api/companies/{cid}/fixed-assets/{asset_id}/dispose", json={
        "date": "2026-02-01", "proceeds": 1500,
    })
    assert res.status_code == 200
    body = res.get_json()
    assert body["gainOrLoss"] == 500.0

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    gain_tx = next((t for t in txs if t["credit"] == "Gain on Disposal"), None)
    assert gain_tx is not None
    assert gain_tx["amount"] == 500.0


def test_delete_blocked_once_depreciation_posted_but_allowed_before(client):
    cid = make_company(client)
    asset_id = make_asset(client, cid)
    # no depreciation posted yet — hard delete should still work
    res = client.delete(f"/api/companies/{cid}/fixed-assets/{asset_id}")
    assert res.status_code == 200
    assert client.get(f"/api/companies/{cid}/fixed-assets").get_json() == []

    asset_id = make_asset(client, cid, purchase_date="2020-01-01")
    client.post(f"/api/companies/{cid}/fixed-assets/{asset_id}/run-depreciation", json={"date": "2026-01-15"})
    res = client.delete(f"/api/companies/{cid}/fixed-assets/{asset_id}")
    assert res.status_code == 400
    assert len(client.get(f"/api/companies/{cid}/fixed-assets").get_json()) == 1
