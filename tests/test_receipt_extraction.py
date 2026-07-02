import io

from conftest import signup, create_company


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def scan_extracted(client, cid, date="2026-06-01", desc="EON Energy", amount="79.45", filename="receipt.pdf"):
    return client.post(
        f"/api/companies/{cid}/scan-receipt-extracted",
        data={
            "date": date, "desc": desc, "amount": amount,
            "file": (io.BytesIO(b"%PDF-1.4 fake receipt bytes"), filename),
        },
        content_type="multipart/form-data",
    )


def test_scan_receipt_extracted_auto_posts_when_rule_matches(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/categorization-rules", json={"keyword": "eon", "debit": "Utilities", "credit": "Cash"})

    res = scan_extracted(client, cid)
    assert res.status_code == 200
    body = res.get_json()
    assert body["posted"] is True
    assert body["debit"] == "Utilities"
    assert body["credit"] == "Cash"
    assert "transactionId" in body

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert len(txs) == 1
    assert txs[0]["amount"] == 79.45


def test_scan_receipt_extracted_returns_fields_only_without_a_matching_rule(client):
    cid = make_company(client)
    res = scan_extracted(client, cid, desc="Some Unknown Vendor")
    assert res.status_code == 200
    body = res.get_json()
    assert body.get("posted") is not True
    assert body["date"] == "2026-06-01"
    assert body["amount"] == 79.45

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert len(txs) == 0  # nothing posted without a confident category match


def test_scan_receipt_extracted_stores_attachment_when_it_auto_posts(client):
    cid = make_company(client)
    client.post(f"/api/companies/{cid}/categorization-rules", json={"keyword": "eon", "debit": "Utilities", "credit": "Cash"})
    res = scan_extracted(client, cid)
    tx_id = res.get_json()["transactionId"]
    attachments = client.get(f"/api/companies/{cid}/transactions/{tx_id}/attachments").get_json()
    assert len(attachments) == 1
    assert attachments[0]["filename"] == "receipt.pdf"


def test_scan_receipt_extracted_rejects_missing_fields(client):
    cid = make_company(client)
    res = client.post(
        f"/api/companies/{cid}/scan-receipt-extracted",
        data={"file": (io.BytesIO(b"%PDF-1.4 fake"), "receipt.pdf")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400


def test_scan_receipt_extracted_rejects_unsupported_file_type(client):
    cid = make_company(client)
    res = client.post(
        f"/api/companies/{cid}/scan-receipt-extracted",
        data={
            "date": "2026-06-01", "desc": "Test", "amount": "10.00",
            "file": (io.BytesIO(b"not a real file"), "receipt.exe"),
        },
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
