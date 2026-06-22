from conftest import signup, login


def test_signup_creates_session(client):
    res = signup(client)
    assert res.status_code == 200
    assert client.get("/api/me").get_json()["user"]["email"] == "owner@example.com"


def test_signup_rejects_duplicate_email(client):
    signup(client)
    res = signup(client)
    assert res.status_code == 409


def test_signup_rejects_short_password(client):
    res = client.post("/api/signup", json={"email": "a@example.com", "password": "short"})
    assert res.status_code == 400


def test_login_wrong_password_rejected(client):
    signup(client)
    client.post("/api/logout")
    res = login(client, password="wrongpassword")
    assert res.status_code == 401


def test_login_unknown_email_rejected(client):
    res = login(client, email="nobody@example.com")
    assert res.status_code == 401


def test_logout_clears_session(client):
    signup(client)
    client.post("/api/logout")
    assert client.get("/api/me").get_json()["user"] is None


def test_unauthenticated_requests_rejected(client):
    res = client.get("/api/companies")
    assert res.status_code == 401


def test_rate_limit_blocks_after_threshold(client):
    for _ in range(15):
        login(client, password="wrong")
    res = login(client, password="wrong")
    assert res.status_code == 429
