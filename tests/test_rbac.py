"""JWT authentication + role-based access control through the public REST API only."""
import time, jwt, pytest
from fastapi.testclient import TestClient
from tracevault import crypto as C, package
from tracevault.api import create_app
from tracevault.keystore import KeyStore
from tracevault.release import decrypt_and_release

USERS = {"adm": {"password": "adminpass1", "role": "admin"},
         "sub1": {"password": "submitpass1", "role": "submitter"},
         "sub2": {"password": "submitpass2", "role": "submitter"},
         "aud": {"password": "auditpass1", "role": "auditor"}}

@pytest.fixture
def app(tmp_path):
    return create_app(str(tmp_path / "d"), USERS)

@pytest.fixture
def c(app):
    return TestClient(app)

def H(c, u):
    r = c.post("/auth/login", json={"username": u, "password": USERS[u]["password"]})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}

def upload(c, h, data, name="x.pdf"):
    return c.post("/submitter/evidence", headers=h, json={"filename": name, "content_b64": C.b64e(data)})

def test_login_returns_jwt_with_role(c):
    r = c.post("/auth/login", json={"username": "sub1", "password": "submitpass1"}).json()
    assert r["role"] == "submitter"
    claims = jwt.decode(r["token"], options={"verify_signature": False})
    assert claims["sub"] == "sub1" and claims["role"] == "submitter" and claims["exp"] > time.time()

def test_bad_credentials_and_lockout(c):
    for _ in range(5):
        assert c.post("/auth/login", json={"username": "aud", "password": "nope"}).status_code == 401
    assert c.post("/auth/login", json={"username": "aud", "password": "auditpass1"}).status_code == 429

def test_missing_forged_expired_tokens_rejected(c, app):
    assert c.get("/auth/me").status_code == 401
    assert c.get("/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401
    forged = jwt.encode({"sub": "adm", "role": "admin", "iat": 1, "exp": int(time.time()) + 999, "iss": "tracevault"},
                        "x" * 40, algorithm="HS256")
    assert c.get("/auth/me", headers={"Authorization": "Bearer " + forged}).status_code == 401
    none_alg = jwt.encode({"sub": "adm", "exp": int(time.time()) + 999}, None, algorithm="none")
    assert c.get("/auth/me", headers={"Authorization": "Bearer " + none_alg}).status_code == 401
    from tracevault.config import env
    expired = jwt.encode({"sub": "adm", "iat": 1, "exp": 2, "iss": "tracevault"}, env("TV_JWT_SECRET"), algorithm="HS256")
    assert c.get("/auth/me", headers={"Authorization": "Bearer " + expired}).status_code == 401

def test_token_role_claim_is_not_trusted(c):
    """Even a validly signed token claiming admin gets the role stored in the database."""
    from tracevault.config import env
    now = int(time.time())
    t = jwt.encode({"sub": "sub1", "role": "admin", "iat": now, "exp": now + 99, "iss": "tracevault"}, env("TV_JWT_SECRET"), algorithm="HS256")
    assert c.get("/admin/users", headers={"Authorization": "Bearer " + t}).status_code == 403

def test_role_matrix(c):
    adm, sub, aud = H(c, "adm"), H(c, "sub1"), H(c, "aud")
    # submitter: own area only
    assert c.get("/submitter/evidence", headers=sub).status_code == 200
    assert c.get("/auditor/evidence", headers=sub).status_code == 403
    assert c.get("/admin/users", headers=sub).status_code == 403
    assert c.get("/auditor/ledger", headers=sub).status_code == 403
    # auditor: read-only, cannot submit or administer
    assert c.get("/auditor/evidence", headers=aud).status_code == 200
    assert c.get("/auditor/ledger", headers=aud).status_code == 200
    assert upload(c, aud, b"%PDF-x").status_code == 403
    assert c.get("/admin/users", headers=aud).status_code == 403
    assert c.post("/admin/users", headers=aud, json={"username": "zzz", "password": "password12", "role": "admin"}).status_code == 403
    assert c.post("/admin/nodes/node-1/toggle", headers=aud).status_code == 403
    # admin: manages, reads, and may also run evidence checks (as in the original app)
    assert c.get("/admin/users", headers=adm).status_code == 200
    assert c.get("/admin/nodes", headers=adm).status_code == 200
    assert c.get("/admin/registry", headers=adm).status_code == 200
    assert c.get("/auditor/evidence", headers=adm).status_code == 200
    assert upload(c, adm, b"%PDF-x").status_code == 200
    # anonymous
    for path in ("/submitter/evidence", "/auditor/evidence", "/admin/users", "/auditor/ledger", "/admin/nodes"):
        assert c.get(path).status_code == 401

def test_legacy_endpoints_removed(c):
    adm = H(c, "adm")
    assert c.post("/demo/seed").status_code in (404, 405)
    assert c.get("/investigator/cases", headers=adm).status_code == 404

def test_submitter_history_is_private_and_reports_work(c, pdf):
    s1, s2, aud = H(c, "sub1"), H(c, "sub2"), H(c, "aud")
    r = upload(c, s1, pdf, "memo.pdf"); assert r.status_code == 200, r.text
    j = r.json(); assert j["verdict"] == "failed" and j["submitter"] == "sub1"   # unmarked file -> not a tracked copy
    cid = j["case_id"]
    assert [i["case_id"] for i in c.get("/submitter/evidence", headers=s1).json()["items"]] == [cid]
    assert c.get("/submitter/evidence", headers=s2).json()["items"] == []
    assert c.get(f"/submitter/evidence/{cid}", headers=s2).status_code == 404
    assert c.get(f"/submitter/evidence/{cid}/pdf", headers=s2).status_code == 404
    pdfr = c.get(f"/submitter/evidence/{cid}/pdf", headers=s1)
    assert pdfr.status_code == 200 and pdfr.content.startswith(b"%PDF-")
    assert [i["case_id"] for i in c.get("/auditor/evidence", headers=aud).json()["items"]] == [cid]
    js = c.get(f"/submitter/evidence/{cid}/json", headers=s1)
    assert js.status_code == 200 and js.json()["case_id"].startswith("C-") and c.get(f"/submitter/evidence/{cid}/json", headers=s2).status_code == 404
    # identical file from another submitter is a separate record and does not overwrite the first
    cid2 = upload(c, s2, pdf, "memo.pdf").json()["case_id"]
    assert cid2 != cid and len(c.get("/auditor/evidence", headers=aud).json()["items"]) == 2
    assert [i["submitter"] for i in c.get("/auditor/evidence", headers=aud).json()["items"] if i["case_id"] == cid] == ["sub1"]

def test_upload_validation(c):
    s = H(c, "sub1")
    assert c.post("/submitter/evidence", headers=s, json={"filename": "a", "content_b64": ""}).status_code == 400
    assert c.post("/submitter/evidence", headers=s, json={"filename": "a", "content_b64": "***"}).status_code == 400
    assert c.post("/submitter/evidence", headers=s, json={"filename": "a", "content_b64": "AA==", "role": "admin"}).status_code == 422
    # path traversal in filename is neutralised
    r = upload(c, s, b"hello world not a doc", "../../etc/passwd")
    assert r.status_code == 200 and r.json()["filename"] == "passwd"

def test_verified_flow_and_auditor_authenticity(app, c, pdf):
    reg, ledger = app.state.registry, app.state.ledger
    d = app.state.data_dir
    ks = KeyStore.create(f"{d}/k.keys", "pw").unlock("pw"); p = ks.public
    kid = reg.add_recipient("u", "Recipient", p["kem_pk"], p["dsa_pk"])
    did = reg.add_document("Sample", C.sha3(pdf), "admin")
    pkg = package.create_package(pdf, did, "Sample", {kid: C.b64d(p["kem_pk"])})
    rel = decrypt_and_release(package.for_recipient(pkg, kid), ks, ledger, reg)
    s, aud = H(c, "sub1"), H(c, "aud")
    j = upload(c, s, rel.protected_pdf, "leak.pdf").json()
    assert j["verdict"] == "verified", j
    a = c.get(f"/auditor/evidence/{j['case_id']}/authenticity", headers=aud).json()
    assert a["file_intact"] and a["verdict"] == "verified" and a["unchanged_since_submission"]
    lv = c.get("/auditor/ledger", headers=aud).json()
    assert lv["verified"] and lv["blocks"] == 1 and lv["nodes_valid"] == 4
    # tamper with the preserved original -> auditor re-check flags it
    import glob, os
    f = glob.glob(f"{d}/evidence/*leak.pdf")[0]; os.chmod(f, 0o644); open(f, "ab").write(b"tamper")
    a2 = c.get(f"/auditor/evidence/{j['case_id']}/authenticity", headers=aud).json()
    assert a2["file_intact"] is False and a2["verdict"] == "failed"

def test_admin_user_management(c):
    adm, sub = H(c, "adm"), H(c, "sub1")
    r = c.post("/admin/users", headers=adm, json={"username": "newbie", "password": "longpassword", "role": "auditor"})
    assert r.status_code == 200
    assert c.post("/admin/users", headers=adm, json={"username": "newbie", "password": "longpassword", "role": "auditor"}).status_code == 409
    assert c.post("/admin/users", headers=adm, json={"username": "x y", "password": "longpassword", "role": "auditor"}).status_code == 422
    assert c.post("/admin/users", headers=adm, json={"username": "okname", "password": "short", "role": "auditor"}).status_code == 422
    assert c.post("/admin/users", headers=adm, json={"username": "okname", "password": "longpassword", "role": "root"}).status_code == 422
    assert c.post("/auth/login", json={"username": "newbie", "password": "longpassword"}).json()["role"] == "auditor"
    # role change is immediate even for tokens already issued
    assert c.get("/auditor/ledger", headers=sub).status_code == 403
    assert c.post("/admin/users/sub1/role", headers=adm, json={"role": "auditor"}).status_code == 200
    assert c.get("/auditor/ledger", headers=sub).status_code == 200
    # deleting a user kills their live token
    assert c.delete("/admin/users/sub1", headers=adm).status_code == 200
    assert c.get("/auth/me", headers=sub).status_code == 401
    # guard rails
    assert c.delete("/admin/users/adm", headers=adm).status_code == 409
    assert c.post("/admin/users/adm/role", headers=adm, json={"role": "auditor"}).status_code == 409

def test_password_change(c):
    s = H(c, "sub2")
    assert c.post("/auth/password", headers=s, json={"current_password": "bad", "new_password": "brandnewpass"}).status_code == 401
    assert c.post("/auth/password", headers=s, json={"current_password": "submitpass2", "new_password": "brandnewpass"}).status_code == 200
    assert c.post("/auth/login", json={"username": "sub2", "password": "brandnewpass"}).status_code == 200

def test_node_toggle_and_resync(c, app):
    adm = H(c, "adm")
    assert c.post("/admin/nodes/node-4/toggle", headers=adm).json()["online"] is False
    assert c.post("/admin/nodes/node-4/toggle", headers=adm).json()["online"] is True
    assert c.post("/admin/nodes/node-9/toggle", headers=adm).status_code == 404

def test_audit_log_chain_intact_after_activity(c):
    H(c, "adm"); c.post("/auth/login", json={"username": "aud", "password": "bad"})
    assert c.get("/auditor/audit-log", headers=H(c, "aud")).json()["verified"] is True

def test_security_headers(c):
    r = c.get("/")
    assert r.headers["x-content-type-options"] == "nosniff" and "frame-ancestors 'none'" in r.headers["content-security-policy"]
