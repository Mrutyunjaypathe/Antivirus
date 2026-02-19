from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from io import BytesIO

def create_pdf_bytes(report_data):
    """
    Generate a PDF scan report in-memory and return a BytesIO buffer.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor("#1e293b"),
        alignment=1,  # Center
        spaceAfter=20
    )
    
    subtitle_style = ParagraphStyle(
        'SubtitleStyle',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor("#64748b"),
        alignment=1,
        spaceAfter=30
    )
    
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor("#334155"),
        spaceBefore=15,
        spaceAfter=10
    )

    Story = []

    # ── Header ───────────────────────────────────────────────────────────────
    Story.append(Paragraph("🛡️ SHIELDX Security Report", title_style))
    Story.append(
        Paragraph(f"Scan ID: {report_data.get('report_id', 'N/A')} • Generated: {report_data.get('generated_at', 'N/A')}", subtitle_style)
    )
    Story.append(Spacer(1, 12))

    # ── Verdict Banner ───────────────────────────────────────────────────────
    verdict = report_data.get("summary", {}).get("verdict", "UNKNOWN")
    severity = report_data.get("summary", {}).get("severity", "N/A")
    
    is_threat = verdict == "THREAT DETECTED"
    bg_color = colors.HexColor("#fee2e2") if is_threat else colors.HexColor("#dcfce7")
    text_color = colors.HexColor("#991b1b") if is_threat else colors.HexColor("#166534")
    border_color = colors.HexColor("#f87171") if is_threat else colors.HexColor("#4ade80")
    
    banner_text = f"<b>SCAN VERDICT: {verdict}</b><br/><font size='10' color='black'>Severity: {severity}</font>"
    banner_style = ParagraphStyle(
        'Banner',
        parent=styles['Normal'],
        fontSize=18,
        textColor=text_color,
        alignment=1,
        backColor=bg_color,
        borderPadding=15,
        borderWidth=1,
        borderColor=border_color,
        spaceAfter=30
    )
    Story.append(Paragraph(banner_text, banner_style))

    # ── File Details Table ───────────────────────────────────────────────────
    Story.append(Paragraph("File Information", h2_style))
    
    file_info = [
        ["File Name", report_data.get("summary", {}).get("file_name", "N/A")],
        ["File Size", report_data.get("file_details", {}).get("size", "N/A")],
        ["File Type", report_data.get("file_details", {}).get("type", "N/A")],
        ["MD5 Hash", report_data.get("file_details", {}).get("md5", "N/A")],
        ["SHA256 Hash", report_data.get("file_details", {}).get("sha256", "N/A")[:32] + "..."],
    ]
    
    t = Table(file_info, colWidths=[1.5*inch, 4.5*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f1f5f9")),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor("#475569")),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    Story.append(t)
    Story.append(Spacer(1, 20))

    # ── Threat Details (if any) ──────────────────────────────────────────────
    if is_threat:
        Story.append(Paragraph("Threat Analysis", h2_style))
        threat_name = report_data.get("summary", {}).get("threat_name", "Unknown")
        
        details = [
            ["Threat Name", threat_name],
            ["Risk Level", severity],
            ["Action Taken", "Quarantined (Check Vault)" if "quarantine" in str(report_data).lower() else "Logged"],
        ]
        
        tt = Table(details, colWidths=[1.5*inch, 4.5*inch])
        tt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#fff1f2")),
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor("#be123c")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#fecdd3")),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica-Bold'),
            ('PADDING', (0,0), (-1,-1), 8),
        ]))
        Story.append(tt)
        Story.append(Spacer(1, 20))

    # ── Recommendations ──────────────────────────────────────────────────────
    Story.append(Paragraph("Security Recommendations", h2_style))
    recs = report_data.get("recommendations", [])
    if not recs:
        recs = ["No specific actions required."]
        
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        leftIndent=20,
        spaceAfter=5,
        bulletIndent=10,
        bulletFontName='Symbol'
    )
    
    for rec in recs:
        Story.append(Paragraph(f"• {rec}", bullet_style))

    # ── Footer ───────────────────────────────────────────────────────────────
    Story.append(Spacer(1, 50))
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.HexColor("#94a3b8"),
        alignment=1
    )
    Story.append(Paragraph("© 2026 SHIELDX Security Suite • Confidential Report", footer_style))

    doc.build(Story)
    buffer.seek(0)
    return buffer
