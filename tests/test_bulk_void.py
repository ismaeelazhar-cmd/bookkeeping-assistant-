from conftest import signup, create_company, post_transaction


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def test_bulk_void_deletes_only_selected_transactions(client):
    cid = make_company(client)
    id1 = post_transaction(client, cid, desc="A", amount=10).get_json()["id"]
    id2 = post_transaction(client, cid, desc="B", amount=20).get_json()["id"]
    id3 = post_transaction(client, cid, desc="C", amount=30).get_json()["id"]

    res = client.post(f"/api/companies/{cid}/transactions/bulk-void", json={"ids": [id1, id2]})
    assert res.status_code == 200
    assert res.get_json()["voided"] == 2

    remaining = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert len(remaining) == 1
    assert remaining[0]["id"] == id3

    all_txs = client.get(f"/api/companies/{cid}/transactions?includeVoided=1").get_json()
    assert len(all_txs) == 3
    assert next(t for t in all_txs if t["id"] == id1)["voidedAt"] is not None
    assert next(t for t in all_txs if t["id"] == id2)["voidedAt"] is not None


def test_bulk_void_skips_locked_period_transactions(client):
    cid = make_company(client)
    id1 = post_transaction(client, cid, desc="Old", date="2026-01-15", amount=10).get_json()["id"]
    id2 = post_transaction(client, cid, desc="New", date="2026-06-15", amount=20).get_json()["id"]

    client.put(f"/api/companies/{cid}/settings", json={"lockedUntil": "2026-03-01"})

    res = client.post(f"/api/companies/{cid}/transactions/bulk-void", json={"ids": [id1, id2]})
    assert res.status_code == 200
    body = res.get_json()
    assert body["voided"] == 1
    assert body["skippedLocked"] == 1

    remaining_ids = {t["id"] for t in client.get(f"/api/companies/{cid}/transactions").get_json()}
    assert id1 in remaining_ids  # locked, kept
    assert id2 not in remaining_ids  # voided
