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


def test_2fa_backup_code_recovers_lost_authenticator(client):
    """The whole point: losing the authenticator device shouldn't mean losing account access."""
    signup(client)
    setup = client.post("/api/2fa/setup").get_json()
    secret = setup["secret"]
    confirm = client.post("/api/2fa/confirm", json={"code": totp_now(secret)})
    backup_codes = confirm.get_json()["backupCodes"]
    assert len(backup_codes) == 10
    assert client.get("/api/2fa/status").get_json()["backupCodesRemaining"] == 10

    client.post("/api/logout")
    login(client)
    # no access to the authenticator (secret) at all here — only a saved backup code
    res = client.post("/api/login/2fa", json={"code": backup_codes[0]})
    assert res.status_code == 200
    assert client.get("/api/me").get_json()["user"]["email"] == "owner@example.com"
    assert client.get("/api/2fa/status").get_json()["backupCodesRemaining"] == 9  # single-use


def test_2fa_backup_code_cannot_be_reused(client):
    signup(client)
    setup = client.post("/api/2fa/setup").get_json()
    secret = setup["secret"]
    confirm = client.post("/api/2fa/confirm", json={"code": totp_now(secret)})
    code = confirm.get_json()["backupCodes"][0]

    client.post("/api/logout")
    login(client)
    client.post("/api/login/2fa", json={"code": code})

    client.post("/api/logout")
    login(client)
    res = client.post("/api/login/2fa", json={"code": code})  # same code again
    assert res.status_code == 401


def test_2fa_backup_codes_regenerate_invalidates_old_set(client):
    signup(client)
    setup = client.post("/api/2fa/setup").get_json()
    secret = setup["secret"]
    confirm = client.post("/api/2fa/confirm", json={"code": totp_now(secret)})
    old_code = confirm.get_json()["backupCodes"][0]

    regen = client.post("/api/2fa/backup-codes/regenerate", json={"code": totp_now(secret)})
    assert regen.status_code == 200
    new_codes = regen.get_json()["backupCodes"]
    assert len(new_codes) == 10
    assert old_code not in new_codes

    client.post("/api/logout")
    login(client)
    res = client.post("/api/login/2fa", json={"code": old_code})
    assert res.status_code == 401  # the old set is gone entirely, not just the one code

    client.post("/api/logout")
    login(client)
    res2 = client.post("/api/login/2fa", json={"code": new_codes[0]})
    assert res2.status_code == 200
