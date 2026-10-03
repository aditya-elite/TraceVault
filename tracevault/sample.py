"""Sample classified PDF generator for TraceVault demo and testing."""
import io
from reportlab.pdfgen import canvas

def sample_pdf(pages: int = 2) -> bytes:
    b = io.BytesIO()
    c = canvas.Canvas(b, pagesize=(612, 792))
    for p in range(pages):
        c.setFont("Helvetica-Bold", 20)
        c.drawString(72, 720, f"CLASSIFIED — SYNTHETIC SAMPLE p{p+1}")
        c.setFont("Helvetica", 11)
        for i in range(40):
            c.drawString(72, 690 - i * 14, f"Synthetic line {i}: operational planning text for demonstration only, lorem ipsum.")
        c.showPage()
    c.save()
    return b.getvalue()
