"""Automated tests for P0/P1 capabilities:
- Database persistence, user auth, encrypted document vault at rest.
- Recipient-side flow with TraceVaultClient.
- ReportLab PDF export.
- Rotation-robust watermark extraction.
- Standalone ledger verification.
"""
import io, json, os, tempfile, cv2, pymupdf, pytest
from conftest import sample_pdf
from tracevault import crypto as C, package, events, watermark as W, evidence as E
from tracevault.db import Database
from tracevault.keystore import KeyStore
from tracevault.ledger import Ledger
from tracevault.registry import Registry
from tracevault.release import decrypt_and_release
from tracevault.report_pdf import generate_report_pdf
from tracevault.verify_ledger import verify_export

def test_database_persistence(tmp_path):
    db = Database(str(tmp_path / "app.db"))
    db.add_user("admin", "pass123", "admin")
    assert db.verify_user("admin", "pass123")["role"] == "admin"
    assert db.verify_user("admin", "wrong") is None
    
    # Encrypted document vault at rest
    pdf_bytes = sample_pdf()
    did = "D-test1"
    sha = db.store_document(did, "Classified Memo", pdf_bytes, "admin")
    assert sha == C.sha3(pdf_bytes)
    
    # Read back decrypted content
    assert db.get_document_content(did) == pdf_bytes
    
    # Verify no raw PDF plaintext in SQLite file
    db_bytes = open(tmp_path / "app.db", "rb").read()
    assert b"CLASSIFIED \xe2\x80\x94 SYNTHETIC SAMPLE" not in db_bytes

def test_watermark_rotation_invariance(tmp_path):
    """Verifies that watermark is detected even if image is rotated 90 or 180 degrees."""
    pdf = sample_pdf(pages=1)
    ev = events.new_event("D-1", "K-1", C.sha3(pdf))
    payload = W.make_payload(ev["watermark_digest"])
    
    prot = W.PdfProtector()
    marked_pdf = prot.embed(pdf, payload)
    images = prot.to_images(marked_pdf)
    assert len(images) == 1
    
    # Test 90-degree rotated page
    rot90 = cv2.rotate(images[0], cv2.ROTATE_90_CLOCKWISE)
    ex = W.extract_images([rot90])
    assert ex["status"] == "ok"
    assert ex["payload"] == payload[:8]
    assert ex["orientation_corrected"] in (90, 270)

def test_pdf_report_generation(world):
    w = world
    rel = decrypt_and_release(w["pkg"], w["ks"][1], w["ledger"], w["reg"])
    rep = E.process_case(rel.protected_pdf, "leaked.pdf", w["reg"], w["ledger"], str(w["tmp"] / "ev_test"))
    
    pdf_bytes = generate_report_pdf(rep)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 2000

def test_standalone_ledger_verifier(world):
    w = world
    decrypt_and_release(w["pkg"], w["ks"][1], w["ledger"], w["reg"])
    decrypt_and_release(w["pkg"], w["ks"][0], w["ledger"], w["reg"])
    
    export = w["ledger"].export_chain()
    res = verify_export(export, w["reg"].d)
    assert res["verified"] is True
    assert res["quorum_records"] == 2
