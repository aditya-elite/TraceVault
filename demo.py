"""SIH golden-path demo: admin -> 3 recipients -> Recipient 2 decrypts -> leak -> investigator -> report.
Run: python demo.py   (fully offline)"""
import io, os, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(__file__)); sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tests"))
import cv2, pymupdf
from tracevault.sample import sample_pdf
from tracevault import crypto as C, package, evidence as E, watermark as W
from tracevault.keystore import KeyStore
from tracevault.ledger import Ledger
from tracevault.registry import Registry
from tracevault.release import decrypt_and_release

d = tempfile.mkdtemp(prefix="tracevault_demo_"); reg, ledger = Registry(), Ledger(f"{d}/ledger")
pdf = sample_pdf(); did = reg.add_document("Classified Sample", C.sha3(pdf), "admin")
print(f"[admin] registered {did}, sha3={C.sha3(pdf)[:16]}…")
ks = []
for i in (1, 2, 3):
    k = KeyStore.create(f"{d}/r{i}.keys", f"pass{i}").unlock(f"pass{i}"); p = k.public; ks.append(k)
    print(f"[admin] registered Recipient {i} -> {reg.add_recipient(f'u{i}', f'Recipient {i}', p['kem_pk'], p['dsa_pk'])}")
pkg = package.create_package(pdf, did, "Classified Sample", {k.key_id: C.b64d(reg.recipient(k.key_id)["kem_pk"]) for k in ks})
print(f"[admin] one AES-256-GCM payload, {len(pkg['recipients'])} distinct ML-KEM-768 encapsulations")

print("\n[recipient 2] decrypting locally…")
rel = decrypt_and_release(pkg, ks[1], ledger, reg, lambda s, st: print(f"   {s:<12}{st}") if st == "done" else None)
print(f"   session={rel.event['session_id']} wm={rel.event['watermark_digest'][:16]}… ledger record #{rel.record['index']} "
      f"({len(rel.record['attestations'])}/4 node attestations)")

# controlled leak: re-save with changed metadata, then page re-encoded as a compressed image
p = pymupdf.open(stream=rel.protected_pdf, filetype="pdf"); p.set_metadata({**p.metadata, "author": "unknown"}); b = io.BytesIO(p.tobytes(deflate=True))
page = W.PdfProtector().to_images(b.getvalue())[0]
leak = cv2.imencode(".jpg", cv2.cvtColor(cv2.resize(page, None, fx=0.8, fy=0.8), cv2.COLOR_RGB2BGR), [cv2.IMWRITE_JPEG_QUALITY, 55])[1].tobytes()
for name, data in (("leaked_resaved.pdf", b.getvalue()), ("leaked_page_q55.jpg", leak), ("unrelated.pdf", pdf)):
    print("\n" + "=" * 70); print(E.render_text(E.process_case(data, name, reg, ledger, f"{d}/evidence")))

print("\n" + "=" * 70 + "\n[negative] tamper: 3 of 4 ledger nodes rewrite the record timestamp")
for n in ledger.nodes[:3]: n.records[0]["event"]["timestamp"] = "2000-01-01T00:00:00Z"
print("   status:", E.process_case(b.getvalue(), "leaked_resaved.pdf", reg, ledger, f"{d}/evidence")["status"])
for root, _, files in os.walk(d):
    for f in files: os.chmod(os.path.join(root, f), 0o777)
shutil.rmtree(d)
