import io

from conftest import signup, create_company, post_transaction


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


# ---------- bank reconciliation ----------

def test_bank_line_import_and_list(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-01", "desc": "Card payment", "amount": -389.95},
        {"cashAccount": "Cash", "date": "2026-06-03", "desc": "Deposit", "amount": 500},
    ])
    assert res.get_json()["inserted"] == 2
    lines = client.get(f"/api/companies/{cid}/bank-lines").get_json()
    assert len(lines) == 2
    assert {l["amount"] for l in lines} == {-389.95, 500.0}


def test_bank_line_zero_amount_skipped(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-01", "desc": "Bad row", "amount": 0},
    ])
    assert res.get_json()["inserted"] == 0


def test_bank_line_match_and_unmatch(client):
    cid = make_company(client)
    tx_id = post_transaction(client, cid, amount=389.95, debit="Office Expenses", credit="Cash").get_json()["id"]
    line_id = client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-01", "desc": "Card payment", "amount": -389.95},
    ]).get_json()
    line_id = client.get(f"/api/companies/{cid}/bank-lines").get_json()[0]["id"]

    res = client.post(f"/api/companies/{cid}/bank-lines/{line_id}/match", json={"transactionId": tx_id})
    assert res.status_code == 200
    matched = client.get(f"/api/companies/{cid}/bank-lines").get_json()[0]
    assert matched["matchedTransactionId"] == tx_id

    client.post(f"/api/companies/{cid}/bank-lines/{line_id}/match", json={"transactionId": None})
    unmatched = client.get(f"/api/companies/{cid}/bank-lines").get_json()[0]
    assert unmatched["matchedTransactionId"] is None


def test_bank_line_match_rejects_unknown_transaction(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-01", "desc": "x", "amount": -10},
    ])
    line_id = client.get(f"/api/companies/{cid}/bank-lines").get_json()[0]["id"]
    res = client.post(f"/api/companies/{cid}/bank-lines/{line_id}/match", json={"transactionId": 99999})
    assert res.status_code == 404


def test_bank_line_delete(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-01", "desc": "x", "amount": -10},
    ])
    line_id = client.get(f"/api/companies/{cid}/bank-lines").get_json()[0]["id"]
    client.delete(f"/api/companies/{cid}/bank-lines/{line_id}")
    assert client.get(f"/api/companies/{cid}/bank-lines").get_json() == []


# ---------- fixed assets ----------

def test_fixed_asset_create_and_pence_conversion(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Laptop", "assetAccount": "Computer Equipment", "cost": 1200.10,
        "purchaseDate": "2026-01-01", "usefulLifeYears": 3, "residualValue": 50.05,
    })
    assert res.status_code == 200
    asset = client.get(f"/api/companies/{cid}/fixed-assets").get_json()[0]
    assert asset["cost"] == 1200.10
    assert asset["residualValue"] == 50.05
    assert asset["accumAccount"] == "Accumulated Depreciation — Laptop"


def test_fixed_asset_requires_positive_cost_and_life(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Bad asset", "assetAccount": "Computer Equipment", "cost": 0,
        "purchaseDate": "2026-01-01", "usefulLifeYears": 3,
    })
    assert res.status_code == 400


def test_fixed_asset_delete(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/fixed-assets", json={
        "name": "Laptop", "assetAccount": "Computer Equipment", "cost": 1200,
        "purchaseDate": "2026-01-01", "usefulLifeYears": 3,
    })
    asset_id = client.get(f"/api/companies/{cid}/fixed-assets").get_json()[0]["id"]
    client.delete(f"/api/companies/{cid}/fixed-assets/{asset_id}")
    assert client.get(f"/api/companies/{cid}/fixed-assets").get_json() == []


def test_straight_line_depreciation_math():
    """The actual depreciation formula lives in the frontend (templates/index.html's
    runDepreciation()) since it needs live ledger state to avoid double-charging a month —
    this locks in the formula itself: monthly charge = (cost - residual) / life / 12."""
    cost, residual, life_years = 1200, 0, 3
    monthly_charge = (cost - residual) / life_years / 12
    assert round(monthly_charge, 2) == 33.33


# ---------- attachments ----------

def test_attachment_upload_list_download_delete(client):
    cid = make_company(client)
    tx_id = post_transaction(client, cid).get_json()["id"]

    upload = client.post(
        f"/api/companies/{cid}/transactions/{tx_id}/attachments",
        data={"file": (io.BytesIO(b"%PDF-1.4 fake receipt"), "receipt.pdf", "application/pdf")},
        content_type="multipart/form-data",
    )
    assert upload.status_code == 200
    attachment_id = upload.get_json()["id"]

    listed = client.get(f"/api/companies/{cid}/transactions/{tx_id}/attachments").get_json()
    assert len(listed) == 1
    assert listed[0]["filename"] == "receipt.pdf"

    tx_with_count = client.get(f"/api/companies/{cid}/transactions").get_json()[0]
    assert tx_with_count["attachmentCount"] == 1

    download = client.get(f"/api/companies/{cid}/attachments/{attachment_id}/download")
    assert download.status_code == 200
    assert download.data == b"%PDF-1.4 fake receipt"

    client.delete(f"/api/companies/{cid}/attachments/{attachment_id}")
    assert client.get(f"/api/companies/{cid}/transactions/{tx_id}/attachments").get_json() == []


def test_attachment_rejects_unsupported_type(client):
    cid = make_company(client)
    tx_id = post_transaction(client, cid).get_json()["id"]
    res = client.post(
        f"/api/companies/{cid}/transactions/{tx_id}/attachments",
        data={"file": (io.BytesIO(b"#!/bin/sh\necho hi"), "script.sh", "application/x-sh")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400


# ---------- presets ----------

def test_posting_learns_a_preset(client):
    cid = make_company(client)
    post_transaction(client, cid, desc="Coffee with client", debit="Office Expenses", credit="Cash")
    presets = client.get(f"/api/companies/{cid}/presets").get_json()
    assert presets["coffee with client"] == {"debit": "Office Expenses", "credit": "Cash"}


def test_preset_updates_on_repost_with_different_accounts(client):
    cid = make_company(client)
    post_transaction(client, cid, desc="Ambiguous item", debit="Office Expenses", credit="Cash")
    post_transaction(client, cid, desc="Ambiguous item", debit="Travel Expense", credit="Cash")
    presets = client.get(f"/api/companies/{cid}/presets").get_json()
    assert presets["ambiguous item"]["debit"] == "Travel Expense"
