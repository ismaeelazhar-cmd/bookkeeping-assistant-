import hmac
import hashlib
import base64
import struct
import time

from conftest import signup, login, create_company, post_transaction


def make_company_with_member(client, permission="view"):
    signup(client, "owner@example.com")
    cid = create_company(client).get_json()["id"]
    client.post("/api/logout")
    signup(client, "member@example.com")
    client.post("/api/logout")
    login(client, "owner@example.com")
    client.post(f"/api/companies/{cid}/members", json={"email": "member@example.com", "permission": permission})
    client.post("/api/logout")
    login(client, "member@example.com")
    return cid


def test_view_permission_blocks_writes(client):
    cid = make_company_with_member(client, "view")
    res = post_transaction(client, cid)
    assert res.status_code == 403


def test_view_permission_allows_reads(client):
    cid = make_company_with_member(client, "view")
    res = client.get(f"/api/companies/{cid}/transactions")
    assert res.status_code == 200


def test_post_permission_allows_writes(client):
    cid = make_company_with_member(client, "post")
    res = post_transaction(client, cid)
    assert res.status_code == 200


def test_member_cannot_delete_company(client):
    cid = make_company_with_member(client, "post")
    res = client.delete(f"/api/companies/{cid}")
    assert res.status_code == 403


def test_member_cannot_manage_team(client):
    cid = make_company_with_member(client, "post")
    res = client.post(f"/api/companies/{cid}/members", json={"email": "owner@example.com", "permission": "view"})
    assert res.status_code == 403


def test_view_permission_blocked_from_ai_endpoints(client):
    cid = make_company_with_member(client, "view")
    res = client.post(f"/api/companies/{cid}/ask", json={"question": "test"})
    assert res.status_code == 403


def test_invite_unknown_email_fails_clearly(client):
    signup(client)
    cid = create_company(client).get_json()["id"]
    res = client.post(f"/api/companies/{cid}/members", json={"email": "nobody@example.com", "permission": "view"})
    assert res.status_code == 404


def test_owner_sees_company_after_inviting(client):
    cid = make_company_with_member(client, "view")
    companies = client.get("/api/companies").get_json()
    assert companies[0]["id"] == cid
    assert companies[0]["permission"] == "view"


def totp_now(secret):
    counter = int(time.time() // 30)
    key = base64.b32decode(secret.upper())
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** 6)
    return str(code_int).zfill(6)


def test_2fa_full_cycle(client):
    signup(client)
    setup = client.post("/api/2fa/setup").get_json()
    secret = setup["secret"]

    code = totp_now(secret)
    confirm = client.post("/api/2fa/confirm", json={"code": code})
    assert confirm.status_code == 200
    assert client.get("/api/2fa/status").get_json()["enabled"] is True

    client.post("/api/logout")
    res = login(client)
    assert res.get_json()["requires2fa"] is True
    assert client.get("/api/me").get_json()["user"] is None

    code = totp_now(secret)
    res = client.post("/api/login/2fa", json={"code": code})
    assert res.status_code == 200
    assert client.get("/api/me").get_json()["user"]["email"] == "owner@example.com"


def test_2fa_wrong_code_rejected(client):
    signup(client)
    setup = client.post("/api/2fa/setup").get_json()
    client.post("/api/2fa/confirm", json={"code": totp_now(setup["secret"])})
    client.post("/api/logout")
    login(client)
    res = client.post("/api/login/2fa", json={"code": "000000"})
    assert res.status_code == 401


def test_2fa_disable(client):
    signup(client)
    setup = client.post("/api/2fa/setup").get_json()
    secret = setup["secret"]
    client.post("/api/2fa/confirm", json={"code": totp_now(secret)})
    res = client.post("/api/2fa/disable", json={"code": totp_now(secret)})
    assert res.status_code == 200
    assert client.get("/api/2fa/status").get_json()["enabled"] is False
