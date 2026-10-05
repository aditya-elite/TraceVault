"""Every original TraceVault workflow, now reachable through the role-based REST API."""
import base64, pytest
from fastapi.testclient import TestClient
from tracevault import crypto as C
from tracevault.api import create_app

USERS = {"adm": {"password": "adminpass1", "role": "admin"},
         "bob": {"password": "bobpass123", "role": "submitter"},
         "eve": {"password": "evepass123", "role": "submitter"},
         "aud": {"password": "auditpass1", "role": "auditor"}}

@pytest.fixture(scope="module")
def c(tmp_path_factory):
    return TestClient(create_app(str(tmp_path_factory.mktemp("d")), USERS))

def H(c, u):
    r = c.post("/auth/login", json={"username": u, "password": USERS[u]["password"]}); assert r.status_code == 200
    return {"Authorization": "Bearer " + r.json()["token"]}

class Ctx: pass
X = Ctx()

def test_admin_registers_document_enrols_recipient_and_shares(c, pdf):
    adm = H(c, "adm")
    d = c.post("/admin/documents", headers=adm, json={"title": "Op Plan", "content_b64": C.b64e(pdf)}); assert d.status_code == 200
    X.did = d.json()["document_id"]
    assert c.post("/admin/documents", headers=adm, json={"title": "bad", "content_b64": C.b64e(b"nope")}).status_code == 415
    # Bob enrols himself; Eve is enrolled by the admin; unknown user rejected; double enrolment rejected
    e = c.post("/recipient/enroll", headers=H(c, "bob"), json={"display_name": "Bob Rivera", "passphrase": "bob-keystore-pass"})
    assert e.status_code == 200, e.text; X.bob_kid = e.json()["recipient_key_id"]
    assert c.post("/recipient/enroll", headers=H(c, "bob"), json={"display_name": "Bob again", "passphrase": "another-pass-1"}).status_code == 409
    e2 = c.post("/admin/recipients/enroll", headers=adm, json={"user_id": "eve", "display_name": "Eve Adams", "passphrase": "eve-keystore-pass"}); assert e2.status_code == 200
    X.eve_kid = e2.json()["recipient_key_id"]
    assert c.post("/admin/recipients/enroll", headers=adm, json={"user_id": "ghost", "display_name": "Ghost", "passphrase": "ghost-pass-123"}).status_code == 404
    assert c.post("/recipient/enroll", headers=H(c, "aud"), json={"display_name": "Aud", "passphrase": "aud-keystore-pass"}).status_code == 403
    assert c.post("/recipient/enroll", headers=H(c, "bob"), json={"display_name": "x", "passphrase": "short"}).status_code == 422
    recs = c.get("/admin/recipients", headers=adm).json()["recipients"]
    assert {r["display_name"] for r in recs} == {"Bob Rivera", "Eve Adams"}
    # only active recipients can be targeted; private fields are never accepted
    r = c.post("/admin/distributions", headers=adm, json={"document_id": X.did, "recipient_key_ids": [X.bob_kid, X.eve_kid]})
    assert r.status_code == 200 and set(r.json()["packages"]) == {X.bob_kid, X.eve_kid}
    assert c.post("/admin/distributions", headers=adm, json={"document_id": X.did, "recipient_key_ids": ["K-nope"]}).status_code == 400

def test_inbox_is_private_and_lean(c):
    inbox = c.get("/recipient/packages", headers=H(c, "bob")).json()
    assert inbox["enrolled"] and inbox["display_name"] == "Bob Rivera" and len(inbox["packages"]) == 1
    assert "package" not in inbox["packages"][0] and inbox["packages"][0]["title"] == "Op Plan"
    assert c.get("/recipient/packages", headers=H(c, "aud")).status_code == 403
    assert c.get("/recipient/packages", headers=H(c, "adm")).json()["enrolled"] is False

def test_decrypt_release_timeline_viewer_and_leak_trace(c):
    bob = H(c, "bob")
    bad = c.post("/recipient/decrypt-and-release", headers=bob, json={"document_id": X.did, "keystore_passphrase": "wrong-passphrase"})
    assert bad.status_code == 401
    assert c.post("/recipient/decrypt-and-release", headers=H(c, "eve"), json={"document_id": "D-none", "keystore_passphrase": "eve-keystore-pass"}).status_code == 404
    r = c.post("/recipient/decrypt-and-release", headers=bob, json={"document_id": X.did, "keystore_passphrase": "bob-keystore-pass"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert [s["step"] for s in j["steps"] if s["status"] == "done"][-1] == "release"
    assert len(j["page_images"]) == 2 and len(j["record"]["attestations"]) == 4 and base64.b64decode(j["protected_pdf_b64"])[:5] == b"%PDF-"
    X.leak = j["protected_pdf_b64"]
    # that copy "leaks": Bob's colleague submits it and it is traced to Bob
    sub = c.post("/submitter/evidence", headers=H(c, "eve"), json={"filename": "leak.pdf", "content_b64": X.leak}).json()
    assert sub["verdict"] == "verified"
    d = c.get(f"/submitter/evidence/{sub['case_id']}", headers=H(c, "eve")).json()
    assert d["report"]["match"]["recipient"] == "Bob Rivera"
    X.case = sub["case_id"]

def test_ledger_blocks_and_export_for_verifier(c):
    aud = H(c, "aud")
    b = c.get("/auditor/ledger/blocks", headers=aud).json()["blocks"]
    assert len(b) == 1 and b[0]["recipient"] == "Bob Rivera" and b[0]["attestations"] == 4
    exp = c.get("/auditor/ledger/export", headers=aud).json()
    from tracevault.verify_ledger import verify_export
    assert verify_export(exp["ledger"], exp["registry"])["verified"]
    st = c.get("/auditor/ledger", headers=aud).json()
    assert all(n["online"] for n in st["nodes"].values())
    assert c.get("/ledger/status", headers=aud).json()["ok"]
    assert c.get("/auditor/ledger/blocks", headers=H(c, "bob")).status_code == 403

def test_json_report_exports(c):
    r = c.get(f"/auditor/evidence/{X.case}/json", headers=H(c, "aud"))
    assert r.status_code == 200 and r.json()["status"] == "VERIFIED" and "attachment" in r.headers["content-disposition"]

def test_fail_closed_when_quorum_lost(c):
    adm, bob = H(c, "adm"), H(c, "bob")
    # Eve opens the doc with 2 nodes offline -> release denied, nothing returned
    for n in ("node-1", "node-2"):
        assert c.post(f"/admin/nodes/{n}/toggle", headers=adm).json()["online"] is False
    r = c.post("/recipient/decrypt-and-release", headers=H(c, "eve"), json={"document_id": X.did, "keystore_passphrase": "eve-keystore-pass"})
    assert r.status_code == 409 and r.json()["step"] == "ledger" and "protected_pdf_b64" not in r.text
    for n in ("node-1", "node-2"):
        assert c.post(f"/admin/nodes/{n}/toggle", headers=adm).json()["online"] is True
    assert c.get("/auditor/ledger", headers=H(c, "aud")).json()["verified"]     # nodes caught up, ledger healthy
    ok = c.post("/recipient/decrypt-and-release", headers=H(c, "eve"), json={"document_id": X.did, "keystore_passphrase": "eve-keystore-pass"})
    assert ok.status_code == 200

@pytest.mark.parametrize("kind", ["tamper_ledger", "key_substitution", "quorum_loss"])
def test_attack_simulations_are_real_and_non_destructive(c, kind):
    before = c.get("/auditor/ledger/export", headers=H(c, "aud")).json()
    r = c.post(f"/simulate/{kind}", headers=H(c, "aud")); assert r.status_code == 200, r.text
    j = r.json(); assert j["defended"] is True and len(j["steps"]) >= 3
    assert c.get("/auditor/ledger/export", headers=H(c, "aud")).json() == before     # live data untouched
    assert c.post(f"/simulate/{kind}", headers=H(c, "bob")).status_code == 403

def test_simulation_on_empty_ledger_explains(tmp_path):
    cc = TestClient(create_app(str(tmp_path / "e"), USERS))
    assert cc.post("/simulate/tamper_ledger", headers=H(cc, "adm")).status_code == 409
    assert cc.post("/simulate/nonsense", headers=H(cc, "adm")).status_code == 404

def test_revoked_recipient_cannot_be_targeted(c):
    adm = H(c, "adm")
    assert c.post(f"/admin/recipients/{X.eve_kid}/revoke", headers=adm).status_code == 200
    assert c.post("/admin/distributions", headers=adm, json={"document_id": X.did, "recipient_key_ids": [X.eve_kid]}).status_code == 400
    assert c.post("/admin/recipients/K-unknown/revoke", headers=adm).status_code == 404

def test_golden_path_runs_for_real(c):
    adm = H(c, "adm")
    r = c.post("/admin/demo/golden-path", headers=adm); assert r.status_code == 200, r.text
    j = r.json()
    assert j["case"]["verdict"] == "verified" and j["traced_to"] == "Demo · Bob Rivera" and len(j["steps"]) >= 6
    assert c.post("/admin/demo/golden-path", headers=H(c, "bob")).status_code == 403
    assert c.get(f"/auditor/evidence/{j['case']['case_id']}", headers=H(c, "aud")).status_code == 200
    # demo recipients are closed after the run
    assert all(r["status"] == "revoked" for r in c.get("/admin/recipients", headers=adm).json()["recipients"] if r["display_name"].startswith("Demo"))
