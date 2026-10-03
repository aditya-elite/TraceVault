import io, os, sys, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from reportlab.pdfgen import canvas
from tracevault import crypto as C, package
from tracevault.keystore import KeyStore
from tracevault.ledger import Ledger
from tracevault.registry import Registry

def sample_pdf(pages=2):
    b = io.BytesIO(); c = canvas.Canvas(b, pagesize=(612, 792))
    for p in range(pages):
        c.setFont("Helvetica-Bold", 20); c.drawString(72, 720, f"CLASSIFIED — SYNTHETIC SAMPLE p{p+1}"); c.setFont("Helvetica", 11)
        for i in range(40): c.drawString(72, 690 - i * 14, f"Synthetic line {i}: operational planning text for demonstration only, lorem ipsum.")
        c.showPage()
    c.save(); return b.getvalue()

@pytest.fixture(scope="session")
def pdf(): return sample_pdf()

@pytest.fixture
def world(tmp_path, pdf):
    reg, ledger = Registry(), Ledger(str(tmp_path / "ledger"))
    ks, kids = [], []
    for i in range(3):
        k = KeyStore.create(str(tmp_path / f"r{i+1}.keys"), f"pw{i+1}").unlock(f"pw{i+1}"); p = k.public
        kids.append(reg.add_recipient(f"u{i+1}", f"Recipient {i+1}", p["kem_pk"], p["dsa_pk"])); ks.append(k)
    did = reg.add_document("Sample", C.sha3(pdf), "admin")
    pkg = package.create_package(pdf, did, "Sample", {k: C.b64d(reg.recipient(k)["kem_pk"]) for k in kids})
    return dict(reg=reg, ledger=ledger, ks=ks, kids=kids, did=did, pkg=pkg, pdf=pdf, tmp=tmp_path)
