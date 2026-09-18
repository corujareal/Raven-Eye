from __future__ import annotations

"""Professional local PDF security-report renderer.

The renderer is deliberately self-contained: no external CDN, JavaScript, or
remote asset is required. Images are included only when they are already part
of the scan result (screenshots/evidence images) and point to existing local
files.
"""

from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
from xml.sax.saxutils import escape

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.pdfbase.pdfmetrics import stringWidth
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False
    colors = None

from .base import risk_score

if _REPORTLAB_AVAILABLE:
    BLACK = colors.HexColor("#08080B")
    PURPLE = colors.HexColor("#7B2CBF")
    PURPLE_DARK = colors.HexColor("#3C096C")
    RED = colors.HexColor("#D90429")
    RED_DARK = colors.HexColor("#8D001B")
    WHITE = colors.white
    GREY = colors.HexColor("#B8B8C2")
    GREY_DARK = colors.HexColor("#1A1720")
    BORDER = colors.HexColor("#33253F")
    SEV = {
        "CRITICAL": RED,
        "HIGH": colors.HexColor("#B5179E"),
        "MEDIUM": colors.HexColor("#F72585"),
        "LOW": PURPLE,
        "INFO": colors.HexColor("#77727F"),
    }



def _safe_text(value, limit=1000):
    text = str(value or "")
    return escape(text[:limit])


def _image_candidates(report: dict) -> list[Path]:
    candidates = []
    for key in ("screenshots", "images", "evidence_images", "screenshot_paths"):
        value = report.get(key, [])
        if isinstance(value, (str, Path)):
            value = [value]
        if isinstance(value, list):
            candidates.extend(value)
    # Also support images attached directly to findings.
    for finding in report.get("vulnerabilities", []) or []:
        if isinstance(finding, dict):
            value = finding.get("screenshot") or finding.get("image") or finding.get("images", [])
            if isinstance(value, (str, Path)):
                value = [value]
            if isinstance(value, list):
                candidates.extend(value)
    seen = set(); result = []
    for raw in candidates:
        try:
            p = Path(raw).expanduser().resolve()
        except (TypeError, OSError):
            continue
        if p in seen or not p.is_file() or p.stat().st_size > 12 * 1024 * 1024:
            continue
        if p.suffix.lower() not in {".png", ".jpg", ".jpeg", ".webp"}:
            continue
        seen.add(p); result.append(p)
    return result[:24]


def _draw_header(canvas, doc):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(BLACK); canvas.rect(0, height - 22 * mm, width, 22 * mm, stroke=0, fill=1)
    canvas.setFillColor(PURPLE); canvas.rect(0, height - 22 * mm, 7 * mm, 22 * mm, stroke=0, fill=1)
    canvas.setFillColor(RED); canvas.rect(width - 5 * mm, height - 22 * mm, 5 * mm, 22 * mm, stroke=0, fill=1)
    canvas.setFillColor(GREY)
    canvas.setFont("Helvetica", 7)
    canvas.drawString(18 * mm, 9 * mm, "RavenEye 6.6.6 · I see you")
    canvas.drawRightString(width - 18 * mm, 9 * mm, f"Página {doc.page}")
    canvas.restoreState()


def _severity_table(counts):
    data = [["SEVERIDADE", "QUANTIDADE", "PESO"]]
    weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        data.append([sev, str(counts[sev]), str(weights[sev])])
    table = Table(data, colWidths=[55 * mm, 35 * mm, 25 * mm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PURPLE_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 1), (-1, -1), GREY_DARK),
        ("TEXTCOLOR", (0, 1), (-1, -1), GREY),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [GREY_DARK, colors.HexColor("#211A29")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for idx, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), 1):
        style.append(("TEXTCOLOR", (0, idx), (0, idx), SEV[sev]))
    table.setStyle(TableStyle(style))
    return table


def _finding_card(finding, styles):
    sev = str(finding.get("severity", "INFO")).upper()
    title = _safe_text(finding.get("name") or finding.get("id") or "Finding")
    rows = [
        [Paragraph(f"<b>{title}</b>", styles["finding_title"]), Paragraph(sev, styles["severity"])],
        [Paragraph(f"<b>URL:</b> {_safe_text(finding.get('url'))}", styles["body"]),
         Paragraph(f"<b>Confidence:</b> {_safe_text(finding.get('confidence', 'MEDIUM'))}", styles["body"])],
    ]
    details = []
    for label, key in (("Descrição", "description"), ("Evidência", "evidence"), ("Impacto", "impact"), ("Remediação", "remediation")):
        if finding.get(key):
            details.append(Paragraph(f"<b>{label}</b>", styles["label"]))
            details.append(Paragraph(_safe_text(finding.get(key), 1200).replace("\n", "<br/>"), styles["body"]))
    cwe = finding.get("cwe"); cve = finding.get("cve")
    if cwe or cve:
        details.append(Paragraph(f"<b>Referências:</b> CWE={_safe_text(cwe)} · CVE={_safe_text(cve)}", styles["body"]))
    inner = Table([[rows[0][0], rows[0][1]], [rows[1][0], rows[1][1]]], colWidths=[125 * mm, 35 * mm])
    inner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17121D")),
        ("TEXTCOLOR", (1, 0), (1, 0), SEV.get(sev, PURPLE)),
        ("BOX", (0, 0), (-1, -1), 0.7, SEV.get(sev, PURPLE)),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    flow = [inner]
    if details:
        body = Table([[x] for x in details], colWidths=[160 * mm])
        body.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), GREY_DARK),
            ("BOX", (0, 0), (-1, -1), 0.7, BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        flow.append(body)
    return flow


def render_pdf(report: dict, filename: str) -> str:
    """Render a polished, self-contained PDF and return its path."""
    if not _REPORTLAB_AVAILABLE:
        raise RuntimeError(
            "PDF indisponível neste ambiente: instale a integração PDF opcional "
            "(reportlab + Pillow) usando o perfil de dependências compatível com seu sistema."
        )
    target = report.get("target", {}) if isinstance(report.get("target", {}), dict) else {}
    target_name = target.get("domain") or report.get("target") or "N/A"
    ip = target.get("ip") or report.get("ip") or "N/A"
    scan_time = report.get("timestamp") or report.get("started_at") or report.get("date") or datetime.now(timezone.utc).isoformat()
    findings = list(report.get("findings") or [])
    if not findings:
        scan = report.get("vulnerability_scan") or {}
        findings = list(scan.get("findings") or [])
    counts = Counter(str(f.get("severity", "INFO")).upper() for f in findings)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        counts.setdefault(sev, 0)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="cover", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=27, leading=32, textColor=WHITE, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="cover_sub", parent=styles["Normal"], fontSize=11, leading=16, textColor=GREY))
    styles.add(ParagraphStyle(name="h1r", parent=styles["Heading1"], fontSize=18, leading=22, textColor=PURPLE, spaceAfter=8))
    styles.add(ParagraphStyle(name="h2r", parent=styles["Heading2"], fontSize=12, leading=16, textColor=RED, spaceBefore=7, spaceAfter=5))
    styles.add(ParagraphStyle(name="body", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=GREY))
    styles.add(ParagraphStyle(name="label", parent=styles["BodyText"], fontSize=8, leading=10, textColor=PURPLE, spaceBefore=3))
    styles.add(ParagraphStyle(name="finding_title", parent=styles["BodyText"], fontSize=10, leading=12, textColor=WHITE))
    styles.add(ParagraphStyle(name="severity", parent=styles["BodyText"], fontSize=8, leading=10, textColor=WHITE, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="small", parent=styles["BodyText"], fontSize=7, leading=9, textColor=GREY))

    out = Path(filename); out.parent.mkdir(parents=True, exist_ok=True)
    frame = Frame(15 * mm, 15 * mm, A4[0] - 30 * mm, A4[1] - 40 * mm, id="normal", leftPadding=0, rightPadding=0, topPadding=4 * mm, bottomPadding=4 * mm)
    doc = BaseDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=22 * mm, bottomMargin=15 * mm, title=f"RavenEye 6.6.6 — {target_name}", author="RavenEye")
    doc.addPageTemplates([PageTemplate(id="raven", frames=frame, onPage=_draw_header)])

    story = []
    # Cover
    cover = Table([[Paragraph("RAVENEYE 6.6.6", styles["cover"])], [Paragraph("I see you", styles["cover_sub"])],
                   [Paragraph(f"<b>Alvo:</b> {_safe_text(target_name)}<br/><b>IP:</b> {_safe_text(ip)}<br/><b>Data:</b> {_safe_text(scan_time)}", styles["cover_sub"])],
                   [Paragraph(f"<b>RISK SCORE</b> &nbsp; {risk_score(findings):.1f}/10", ParagraphStyle(name="score", parent=styles["cover"], fontSize=19, textColor=RED))]],
                  colWidths=[160 * mm], rowHeights=[42 * mm, 22 * mm, 40 * mm, 35 * mm])
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BLACK), ("BOX", (0, 0), (-1, -1), 1.2, PURPLE),
        ("LEFTPADDING", (0, 0), (-1, -1), 14), ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 10), ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story += [Spacer(1, 20 * mm), cover, PageBreak()]

    story += [Paragraph("Resumo executivo", styles["h1r"]), Paragraph(
        f"O scan registrou <b>{len(findings)}</b> findings. A classificação é baseada na severidade e confiança armazenadas pelo RavenEye; resultados heurísticos não são apresentados como confirmação automática.", styles["body"]), Spacer(1, 5 * mm), _severity_table(counts), Spacer(1, 8 * mm)]
    surface = report.get("surface", {}) if isinstance(report.get("surface", {}), dict) else {}
    metrics = [["URLs", str(surface.get("urls", len(report.get("urls", []) or [])))], ["Endpoints", str(surface.get("endpoints", len(report.get("endpoints", []) or [])))], ["Subdomínios", str(surface.get("subdomains", len(report.get("subdomains", []) or [])))]]
    mt = Table(metrics, colWidths=[45 * mm, 35 * mm]); mt.setStyle(TableStyle([("BACKGROUND", (0,0),(-1,-1),GREY_DARK),("TEXTCOLOR",(0,0),(-1,-1),GREY),("GRID",(0,0),(-1,-1),0.4,BORDER)]))
    story += [mt, PageBreak(), Paragraph("Findings", styles["h1r"])]

    if findings:
        for idx, finding in enumerate(findings, 1):
            story.append(Paragraph(f"#{idx}", styles["h2r"]))
            story.extend(_finding_card(finding, styles))
            finding_images = []
            if isinstance(finding, dict):
                value = finding.get("screenshots") or finding.get("evidence_images") or finding.get("images") or finding.get("screenshot") or finding.get("image")
                if isinstance(value, (str, Path)):
                    value = [value]
                if isinstance(value, list):
                    for raw in value:
                        try:
                            fp = Path(raw).expanduser().resolve()
                            if fp.is_file() and fp.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"} and fp.stat().st_size <= 12 * 1024 * 1024:
                                finding_images.append(fp)
                        except (TypeError, OSError):
                            continue
            for fp in finding_images[:4]:
                try:
                    story.append(Paragraph(f"<b>Evidência visual:</b> {_safe_text(fp.name, 200)}", styles["label"]))
                    img = Image(str(fp)); img._restrictSize(150 * mm, 75 * mm); story.append(img)
                except Exception:
                    continue
            story.append(Spacer(1, 5 * mm))
    else:
        story.append(Paragraph("Nenhum finding registrado.", styles["body"]))

    images = _image_candidates(report)
    if images:
        story.append(PageBreak()); story.append(Paragraph("Evidências visuais", styles["h1r"]))
        story.append(Paragraph("Imagens existentes no resultado do scan foram incorporadas ao relatório. O PDF não busca imagens remotamente.", styles["body"]))
        for image_path in images:
            try:
                img = Image(str(image_path))
                img._restrictSize(155 * mm, 85 * mm)
                story += [Spacer(1, 4 * mm), Paragraph(_safe_text(image_path.name, 200), styles["label"]), img]
            except Exception:
                continue

    story += [PageBreak(), Paragraph("Anexos", styles["h1r"])]
    tech = report.get("tech") or report.get("technologies") or {}
    if tech:
        story.append(Paragraph("Tecnologias detectadas", styles["h2r"]))
        story.append(Paragraph(_safe_text(tech, 2500).replace("\n", "<br/>"), styles["body"]))
    endpoints = report.get("endpoints", []) or []
    if endpoints:
        story.append(Paragraph(f"Endpoints descobertos ({min(len(endpoints), 200)})", styles["h2r"]))
        story.append(Paragraph("<br/>".join(_safe_text(e, 300) for e in endpoints[:200]), styles["small"]))

    doc.build(story)
    return str(out)
