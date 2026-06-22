from conftest import signup, create_company


def make_company(client):
    signup(client)
    return create_company(client).get_json()["id"]


def test_draft_invoice_has_no_ledger_effect(client):
    cid = make_company(client)
    contact_id = client.post(f"/api/companies/{cid}/contacts", json={"name": "Acme Ltd"}).get_json()["id"]
    client.post(f"/api/companies/{cid}/invoices-bills", json={
        "kind": "invoice", "contactId": contact_id, "date": "2026-05-01", "dueDate": "2026-05-15",
        "desc": "Consulting", "amount": 1200, "account": "Sales", "vatRate": 20,
    })
    assert client.get(f"/api/companies/{cid}/transactions").get_json() == []


def test_send_invoice_posts_vat_aware_transaction(client):
    cid = make_company(client)
    contact_id = client.post(f"/api/companies/{cid}/contacts", json={"name": "Acme Ltd"}).get_json()["id"]
    doc_id = client.post(f"/api/companies/{cid}/invoices-bills", json={
        "kind": "invoice", "contactId": contact_id, "date": "2026-05-01", "dueDate": "2026-05-15",
        "desc": "Consulting", "amount": 1200, "account": "Sales", "vatRate": 20,
    }).get_json()["id"]

    res = client.post(f"/api/companies/{cid}/invoices-bills/{doc_id}/send")
    assert res.status_code == 200

    # VAT is posted as a real second ledger row sharing a journal_id, not folded into one
    # gross-amount row: a net leg (Receivables/Sales) plus a VAT leg (Receivables/VAT Control).
    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    assert len(txs) == 2
    assert len({t["journalId"] for t in txs}) == 1

    main = next(t for t in txs if t["credit"] == "Sales")
    vat_leg = next(t for t in txs if t["credit"] == "VAT Control Account")
    assert main["debit"] == "Trade Receivables"
    assert main["amount"] == 1000.0
    assert main["vatDirection"] == "output"
    assert vat_leg["debit"] == "Trade Receivables"
    assert vat_leg["amount"] == 200.0
    assert vat_leg["vatDirection"] == "output"


def test_pay_invoice_settles_receivable(client):
    cid = make_company(client)
    contact_id = client.post(f"/api/companies/{cid}/contacts", json={"name": "Acme Ltd"}).get_json()["id"]
    doc_id = client.post(f"/api/companies/{cid}/invoices-bills", json={
        "kind": "invoice", "contactId": contact_id, "date": "2026-05-01", "dueDate": "2026-05-15",
        "desc": "Consulting", "amount": 1200, "account": "Sales",
    }).get_json()["id"]
    client.post(f"/api/companies/{cid}/invoices-bills/{doc_id}/send")
    res = client.post(f"/api/companies/{cid}/invoices-bills/{doc_id}/pay", json={"date": "2026-06-01", "account": "Cash"})
    assert res.status_code == 200

    doc = client.get(f"/api/companies/{cid}/invoices-bills").get_json()[0]
    assert doc["status"] == "paid"
    assert client.get(f"/api/companies/{cid}/aging-report").get_json()["invoice"] == {}


def test_delete_invoice_voids_linked_transactions(client):
    cid = make_company(client)
    contact_id = client.post(f"/api/companies/{cid}/contacts", json={"name": "Acme Ltd"}).get_json()["id"]
    doc_id = client.post(f"/api/companies/{cid}/invoices-bills", json={
        "kind": "invoice", "contactId": contact_id, "date": "2026-05-01", "dueDate": "2026-05-15",
        "desc": "Consulting", "amount": 1200, "account": "Sales",
    }).get_json()["id"]
    client.post(f"/api/companies/{cid}/invoices-bills/{doc_id}/send")
    client.delete(f"/api/companies/{cid}/invoices-bills/{doc_id}")

    voided = client.get(f"/api/companies/{cid}/transactions?includeVoided=1").get_json()
    assert all(t["voidedAt"] is not None for t in voided)


def test_compound_journal_splits_against_pivot(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/journals", json={
        "date": "2026-06-22", "desc": "BACS run", "pivotAccount": "Cash", "pivotSide": "credit",
        "lines": [{"account": "Rent Expenses", "amount": 700}, {"account": "Utilities", "amount": 300}],
    })
    assert res.status_code == 200
    data = res.get_json()
    assert data["total"] == 1000.0
    assert len(data["transactionIds"]) == 2

    txs = client.get(f"/api/companies/{cid}/transactions").get_json()
    journal_ids = {t["journalId"] for t in txs}
    assert len(journal_ids) == 1  # both legs share one journal_id
    assert sum(t["amount"] for t in txs) == 1000.0


def test_compound_journal_requires_at_least_two_lines(client):
    cid = make_company(client)
    res = client.post(f"/api/companies/{cid}/journals", json={
        "date": "2026-06-22", "desc": "x", "pivotAccount": "Cash", "pivotSide": "credit",
        "lines": [{"account": "Rent Expenses", "amount": 100}],
    })
    assert res.status_code == 400
