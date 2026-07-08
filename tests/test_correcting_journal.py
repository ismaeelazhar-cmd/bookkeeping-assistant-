from conftest import signup, create_company, post_transaction


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def test_correct_transaction_voids_original_and_posts_new(client):
    cid = make_company(client)
    tx_id = post_transaction(client, cid, amount=100, debit="Office Expenses", credit="Cash").get_json()["id"]

    res = client.post(f"/api/companies/{cid}/transactions/{tx_id}/correct", json={
        "debit": "Travel Expense", "credit": "Cash", "amount": 100,
    })
    assert res.status_code == 200
    body = res.get_json()
    assert body["voidedTransactionId"] == tx_id
    new_id = body["newTransactionId"]

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert len(txs) == 1  # original voided, excluded by default
    assert txs[0]["id"] == new_id
    assert txs[0]["debit"] == "Travel Expense"
    assert f"Correction of #{tx_id}" in txs[0]["desc"]

    all_txs = client.get(f"/api/companies/{cid}/transactions?includeVoided=1").get_json()
    assert len(all_txs) == 2
    original = next(t for t in all_txs if t["id"] == tx_id)
    assert original["voidedAt"] is not None


def test_correct_transaction_can_park_in_suspense_account(client):
    cid = make_company(client)
    tx_id = post_transaction(client, cid, amount=250, debit="Office Expenses", credit="Cash").get_json()["id"]

    res = client.post(f"/api/companies/{cid}/transactions/{tx_id}/correct", json={
        "debit": "Suspense Account", "credit": "Cash",
    })
    assert res.status_code == 200
    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert txs[0]["debit"] == "Suspense Account"
    assert txs[0]["amount"] == 250.0  # amount/date/desc default to the original's when omitted


def test_correct_transaction_rejects_journal_leg_and_missing_id(client):
    cid = make_company(client)
    # a VAT-bearing transaction posts two legs sharing a journal_id
    post_transaction(client, cid, amount=1200, debit="Trade Receivables", credit="Sales", vatRate=20, vatDirection="output")
    tx_id = client.get(f"/api/companies/{cid}/transactions").get_json()[0]["id"]

    res = client.post(f"/api/companies/{cid}/transactions/{tx_id}/correct", json={"debit": "Sales", "credit": "Trade Receivables"})
    assert res.status_code == 400

    res = client.post(f"/api/companies/{cid}/transactions/999999/correct", json={"debit": "a", "credit": "b"})
    assert res.status_code == 404
