"""PDF Evidence Report Generation using ReportLab.

Produces tamper-evident, court-ready cryptographic provenance reports
conforming to PRD §11-12 and §16.
Includes:
- Official Case ID, Timestamp, Investigator ID, and SHA3-256 evidence fingerprint.
- Visual cryptographic status banner (VERIFIED / INVALID SIGNATURE / etc.).
- Provenance attribution details (session, recipient, document ID, timestamp, block hash).
- Full forensic integrity checks table.
- PRD legal non-conclusion disclaimer.
"""
import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable

def generate_report_pdf(report: dict) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A')
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#64748B')
    )
    
    h2_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#1E293B'),
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    
    bold_body = ParagraphStyle(
        'BoldBody',
        parent=body_style,
        fontName='Helvetica-Bold'
    )
    
    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#475569')
    )
    
    story = []
    
    # 1. Header
    story.append(Paragraph("TRACEVAULT FORENSIC PROVENANCE REPORT", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("POST-QUANTUM CRYPTOGRAPHIC EVIDENCE & VERIFICATION AUDIT", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceAfter=14))
    
    # 2. Case Overview Table
    case_info = [
        [Paragraph("<b>Case ID:</b>", bold_body), Paragraph(report.get("case_id", "N/A"), body_style),
         Paragraph("<b>Submitted At:</b>", bold_body), Paragraph(report.get("submitted_at", "N/A"), body_style)],
        [Paragraph("<b>Submitted by:</b>", bold_body), Paragraph(report.get("investigator", "N/A"), body_style),
         Paragraph("<b>Evidence File:</b>", bold_body), Paragraph(report.get("evidence_file", "N/A"), body_style)],
        [Paragraph("<b>SHA3-256 Digest:</b>", bold_body), Paragraph(f"<font size='7'>{report.get('evidence_sha3_256', 'N/A')}</font>", body_style), "", ""]
    ]
    t_case = Table(case_info, colWidths=[100, 160, 100, 172])
    t_case.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('SPAN', (1, 2), (3, 2)),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
    ]))
    story.append(t_case)
    story.append(Spacer(1, 14))
    
    # 3. Status Banner
    status = report.get("status", "UNKNOWN")
    status_bg = colors.HexColor('#DCFCE7') if status == "VERIFIED" else colors.HexColor('#FEE2E2')
    status_fg = colors.HexColor('#166534') if status == "VERIFIED" else colors.HexColor('#991B1B')
    
    status_p = Paragraph(
        f"<b>VERIFICATION STATUS: {status}</b>",
        ParagraphStyle('StatusBanner', fontName='Helvetica-Bold', fontSize=12, leading=16, textColor=status_fg, alignment=1)
    )
    t_status = Table([[status_p]], colWidths=[532])
    t_status.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), status_bg),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('BOX', (0, 0), (-1, -1), 1, status_fg),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(t_status)
    story.append(Spacer(1, 16))
    
    # 4. Attribution Details (if matched)
    match = report.get("match")
    if match:
        story.append(Paragraph("Cryptographic Recipient Attribution", h2_style))
        attr_data = [
            [Paragraph("<b>Recipient Display Name:</b>", bold_body), Paragraph(str(match.get("recipient", "Unknown")), body_style)],
            [Paragraph("<b>Recipient Key ID:</b>", bold_body), Paragraph(str(match.get("recipient_key_id", "N/A")), body_style)],
            [Paragraph("<b>Session ID:</b>", bold_body), Paragraph(str(match.get("session_id", "N/A")), body_style)],
            [Paragraph("<b>Document ID:</b>", bold_body), Paragraph(str(match.get("document_id", "N/A")), body_style)],
            [Paragraph("<b>Decryption Timestamp:</b>", bold_body), Paragraph(str(match.get("decrypted_at", "N/A")), body_style)],
            [Paragraph("<b>Ledger Record Index:</b>", bold_body), Paragraph(f"#{match.get('record_index', 0)}", body_style)],
            [Paragraph("<b>Ledger Block Hash:</b>", bold_body), Paragraph(f"<font size='7'>{match.get('record_hash', 'N/A')}</font>", body_style)],
        ]
        t_attr = Table(attr_data, colWidths=[160, 372])
        t_attr.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ]))
        story.append(t_attr)
        story.append(Spacer(1, 16))
        
    # 5. Integrity Checks Table
    story.append(Paragraph("Forensic Verification Pipeline Checks", h2_style))
    checks = report.get("checks", [])
    chk_rows = [
        [Paragraph("<b>Status</b>", bold_body), Paragraph("<b>Verification Check</b>", bold_body), Paragraph("<b>Audit Details</b>", bold_body)]
    ]
    for c in checks:
        passed = c.get("passed", False)
        pass_txt = "<font color='#16A34A'><b>[PASS]</b></font>" if passed else "<font color='#DC2626'><b>[FAIL]</b></font>"
        chk_rows.append([
            Paragraph(pass_txt, body_style),
            Paragraph(c.get("name", ""), bold_body),
            Paragraph(str(c.get("detail", "")), body_style)
        ])
    t_chk = Table(chk_rows, colWidths=[65, 185, 282])
    t_chk.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_chk)
    story.append(Spacer(1, 18))
    
    # 6. Legal Non-Conclusion Disclaimer
    disclaimer_text = report.get("disclaimer", "")
    story.append(KeepTogether([
        Paragraph("<b>Notice & Legal Non-Conclusion:</b>", ParagraphStyle('DisclH', parent=disclaimer_style, fontName='Helvetica-Bold')),
        Spacer(1, 3),
        Paragraph(disclaimer_text, disclaimer_style),
        Spacer(1, 8),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#94A3B8'))
    ]))
    
    doc.build(story)
    return buffer.getvalue()
