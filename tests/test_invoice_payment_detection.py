from conftest import signup, create_company


def make_company_with_sent_invoice(client, amount=500):
    signup(client)
    cid = create_company(client).get_json()["id"]
    client.post(f"/api/companies/{cid}/contacts", json={"name": "J Smith", "type": "customer"})
    contact_id = client.get(f"/api/companies/{cid}/contacts").get_json()[0]["id"]
    doc = client.post(f"/api/companies/{cid}/invoices-bills", json={
        "kind": "invoice", "contactId": contact_id, "date": "2026-06-01", "dueDate": "2026-06-30",
        "desc": "Consulting work", "amount": amount, "account": "Sales",
    }).get_json()
    client.post(f"/api/companies/{cid}/invoices-bills/{doc['id']}/send")
    return cid, doc["id"]


def test_bank_line_matching_one_open_invoice_queues_a_suggestion(client):
    cid, invoice_id = make_company_with_sent_invoice(client, amount=500)
    client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-15", "desc": "FP FROM J SMITH", "amount": 500},
    ])
    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    suggestions = [q for q in queue if q["source"] == "invoice_payment"]
    assert len(suggestions) == 1
    assert suggestions[0]["rawLine"]["invoiceId"] == invoice_id
    assert "Consulting work" in suggestions[0]["reason"]


def test_ambiguous_amount_two_open_invoices_does_not_suggest(client):
    cid, _ = make_company_with_sent_invoice(client, amount=500)
    contact_id = client.get(f"/api/companies/{cid}/contacts").get_json()[0]["id"]
    doc2 = client.post(f"/api/companies/{cid}/invoices-bills", json={
        "kind": "invoice", "contactId": contact_id, "date": "2026-06-02", "dueDate": "2026-06-30",
        "desc": "More consulting", "amount": 500, "account": "Sales",
    }).get_json()
    client.post(f"/api/companies/{cid}/invoices-bills/{doc2['id']}/send")

    client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-15", "desc": "FP 500", "amount": 500},
    ])
    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert [q for q in queue if q["source"] == "invoice_payment"] == []


def test_outgoing_bank_line_never_suggests_invoice_payment(client):
    cid, _ = make_company_with_sent_invoice(client, amount=500)
    client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-15", "desc": "PAYMENT OUT", "amount": -500},
    ])
    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert [q for q in queue if q["source"] == "invoice_payment"] == []


def test_duplicate_bank_line_does_not_double_suggest(client):
    cid, _ = make_company_with_sent_invoice(client, amount=500)
    for _ in range(2):
        client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
            {"cashAccount": "Cash", "date": "2026-06-15", "desc": "FP FROM J SMITH", "amount": 500},
        ])
    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    assert len([q for q in queue if q["source"] == "invoice_payment"]) == 1


def test_confirming_suggestion_marks_invoice_paid(client):
    cid, invoice_id = make_company_with_sent_invoice(client, amount=500)
    client.post(f"/api/companies/{cid}/bank-lines/bulk", json=[
        {"cashAccount": "Cash", "date": "2026-06-15", "desc": "FP FROM J SMITH", "amount": 500},
    ])
    queue = client.get(f"/api/companies/{cid}/clarification-queue").get_json()
    item = next(q for q in queue if q["source"] == "invoice_payment")

    # The frontend's confirm flow: pay the invoice, then dismiss the queue item.
    res = client.post(f"/api/companies/{cid}/invoices-bills/{invoice_id}/pay", json={"date": "2026-06-15"})
    assert res.status_code == 200
    client.post(f"/api/companies/{cid}/clarification-queue/{item['id']}/skip")

    docs = client.get(f"/api/companies/{cid}/invoices-bills").get_json()
    assert next(d for d in docs if d["id"] == invoice_id)["status"] == "paid"
    assert client.get(f"/api/companies/{cid}/clarification-queue").get_json() == []
