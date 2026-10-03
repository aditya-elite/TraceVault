import io, json, cv2, numpy as np, pymupdf
from tracevault import evidence as E, watermark as W
from tracevault.release import decrypt_and_release
from tracevault.ledger import Ledger

def _release(w, i=1):
    return decrypt_and_release(w["pkg"], w["ks"][i], w["ledger"], w["reg"])

def _case(w, data, name="leak.pdf"):
    return E.process_case(data, name, w["reg"], w["ledger"], str(w["tmp"] / "ev"))

def _jpeg_pdf(w, rel, q, scale=1.0):
    imgs = W.PdfProtector().to_images(rel.protected_pdf); out = []
    for im in imgs:
        im = cv2.resize(im, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
        out.append(cv2.imdecode(cv2.imencode(".jpg", cv2.cvtColor(im, cv2.COLOR_RGB2BGR), [cv2.IMWRITE_JPEG_QUALITY, q])[1], 1))
    return out

def test_digital_leak_verified_and_names_recipient_2(world):
    w = world; rel = _release(w, 1)
    rep = _case(w, rel.protected_pdf)
    assert rep["status"] == E.VERIFIED and rep["match"]["recipient_key_id"] == w["kids"][1]
    assert rep["match"]["session_id"] == rel.event["session_id"]

def test_attribution_distinguishes_recipients(world):
    w = world; r0, r2 = _release(w, 0), _release(w, 2)
    assert _case(w, r0.protected_pdf)["match"]["recipient_key_id"] == w["kids"][0]
    assert _case(w, r2.protected_pdf)["match"]["recipient_key_id"] == w["kids"][2]

def test_resave_metadata_and_compression(world):
    w = world; rel = _release(w)
    doc = pymupdf.open(stream=rel.protected_pdf, filetype="pdf")
    doc.set_metadata({**doc.metadata, "author": "someone else"})
    b = io.BytesIO(doc.tobytes(deflate=True)); assert _case(w, b.getvalue())["status"] == E.VERIFIED
    jpg = cv2.imencode(".jpg", _jpeg_pdf(w, rel, 50, 0.8)[0])[1].tobytes()          # one page, rescaled, q50
    assert _case(w, jpg, "page.jpg")["status"] == E.VERIFIED

def test_no_watermark_and_corrupt(world):
    w = world
    assert _case(w, w["pdf"])["status"] == E.NO_WM
    assert _case(w, b"not a document at all")["status"] == E.LOW

def test_missing_ledger_proof(world, tmp_path):
    w = world; rel = _release(w)
    empty = Ledger(str(tmp_path / "other"))
    rep = E.process_case(rel.protected_pdf, "leak.pdf", w["reg"], empty, str(tmp_path / "ev2"))
    assert rep["status"] == E.PROOF_INCOMPLETE

def test_invalid_signature_wrong_registered_key(world):
    w = world; rel = _release(w, 1)
    r = w["reg"].d["recipients"]; k = w["kids"][1]; r[k] = {**r[k], "dsa_pk": r[w["kids"][0]]["dsa_pk"]}  # key substitution
    assert _case(w, rel.protected_pdf)["status"] == E.INVALID_SIG

def test_ledger_tamper_detected_and_single_node_cannot_rewrite(world):
    w = world; rel = _release(w, 1); _release(w, 0)
    n = w["ledger"].nodes[0]; n.records[0]["event"]["recipient_key_id"] = w["kids"][2]   # one node rewrites history
    v = w["ledger"].verify(w["reg"]); assert not v["nodes"]["node-1"]["ok"] and v["ok"]  # others still agree (3/4)
    assert _case(w, rel.protected_pdf)["match"]["recipient_key_id"] == w["kids"][1]
    for m in w["ledger"].nodes[:3]: m.records[0]["event"]["timestamp"] = "2000-01-01T00:00:00Z"  # majority tampered
    assert _case(w, rel.protected_pdf)["status"] != E.VERIFIED   # tampered majority never verifies

def test_evidence_preserved_read_only(world):
    w = world; rel = _release(w); rep = _case(w, rel.protected_pdf)
    import os, glob
    f = glob.glob(str(w["tmp"] / "ev" / "*"))[0]
    is_root = getattr(os, "geteuid", lambda: -1)() == 0
    assert open(f, "rb").read() == rel.protected_pdf and (not os.access(f, os.W_OK) or is_root)

def test_api_roles_and_no_private_keys(tmp_path, pdf):
    from fastapi.testclient import TestClient
    from tracevault.api import create_app
    from tracevault import crypto as C
    c = TestClient(create_app(str(tmp_path / "d"), {"adm": {"password": "a", "role": "admin"}, "inv": {"password": "i", "role": "investigator"}}))
    tok = lambda u, p: {"Authorization": "Bearer " + c.post("/auth/login", json={"username": u, "password": p}).json()["token"]}
    adm, inv = tok("adm", "a"), tok("inv", "i")
    assert c.post("/admin/documents", headers=inv, json={"title": "t", "content_b64": C.b64e(pdf)}).status_code == 403
    assert c.post("/admin/documents", json={"title": "t", "content_b64": C.b64e(pdf)}).status_code == 401
    assert c.post("/admin/documents", headers=adm, json={"title": "t", "content_b64": C.b64e(pdf)}).status_code == 200
    assert c.post("/admin/recipients", headers=adm, json={"user_id": "u", "display_name": "n", "kem_pk": "", "dsa_pk": "", "kem_sk": "x"}).status_code == 422
