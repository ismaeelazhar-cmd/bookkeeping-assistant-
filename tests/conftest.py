import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import server as server_module


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Each test gets a fresh SQLite file and a clean rate-limit bucket, so tests
    can't bleed state into each other regardless of execution order."""
    db_path = tmp_path / "test.sqlite"
    monkeypatch.setattr(server_module, "DB_PATH", db_path)
    server_module._rate_limit_buckets.clear()
    server_module.init_db()
    server_module.app.config["TESTING"] = True
    with server_module.app.test_client() as c:
        yield c


def signup(client, email="owner@example.com", password="testpass123"):
    return client.post("/api/signup", json={"email": email, "password": password})


def login(client, email="owner@example.com", password="testpass123"):
    return client.post("/api/login", json={"email": email, "password": password})


def create_company(client, name="Test Co"):
    return client.post("/api/companies", json={"name": name})


def post_transaction(client, company_id, **kwargs):
    body = {
        "date": "2026-06-01", "desc": "Test entry", "amount": 100,
        "debit": "Office Expenses", "credit": "Cash",
    }
    body.update(kwargs)
    return client.post(f"/api/companies/{company_id}/transactions", json=body)
