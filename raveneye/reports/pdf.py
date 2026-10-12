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
        PageBreak, Image, Flowable
    )
    from reportlab.pdfbase.pdfmetrics import stringWidth
    _REPORTLAB_AVAILABLE = True
except ImportError:
    _REPORTLAB_AVAILABLE = False
    colors = None

from .base import risk_score

if _REPORTLAB_AVAILABLE:
    BLACK = colors.HexColor("#07111F")
    NAVY = colors.HexColor("#0B1B2B")
    PANEL = colors.HexColor("#10263A")
    PURPLE = colors.HexColor("#44D7C8")
    PURPLE_DARK = colors.HexColor("#163F4A")
    RED = colors.HexColor("#FF657A")
    RED_DARK = colors.HexColor("#8D344A")
    WHITE = colors.white
    GREY = colors.HexColor("#C1D0DA")
    GREY_DARK = colors.HexColor("#122233")
    BORDER = colors.HexColor("#29475D")
    CYAN = colors.HexColor("#57B8FF")
    GREEN = colors.HexColor("#44D7C8")
    TEAL_INK = colors.HexColor("#167C78")
    BLUE_INK = colors.HexColor("#286A8E")
    TEXT_INK = colors.HexColor("#24394B")
    TEXT_MUTED = colors.HexColor("#526B7C")
    SEV = {
        "CRITICAL": RED,
        "HIGH": colors.HexColor("#FF9A62"),
        "MEDIUM": colors.HexColor("#F3CB69"),
        "LOW": CYAN,
        "INFO": colors.HexColor("#8DA9BA"),
    }



def _safe_text(value, limit=1000):
    from raveneye.core.logger import redact, redact_data

    safe = redact(value) if isinstance(value, str) else redact_data(value)
    text = str(safe or "")
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
    canvas.setFillColor(GREEN); canvas.rect(0, height - 22 * mm, 2 * mm, 22 * mm, stroke=0, fill=1)
    canvas.setStrokeColor(BORDER); canvas.setLineWidth(0.5)
    canvas.line(18 * mm, height - 18 * mm, width - 18 * mm, height - 18 * mm)
    canvas.setStrokeColor(GREEN); canvas.setLineWidth(1.2)
    route = canvas.beginPath()
    route.moveTo(width - 78 * mm, height - 11 * mm)
    route.curveTo(width - 66 * mm, height - 4 * mm, width - 57 * mm, height - 18 * mm, width - 45 * mm, height - 11 * mm)
    route.curveTo(width - 33 * mm, height - 4 * mm, width - 25 * mm, height - 18 * mm, width - 18 * mm, height - 11 * mm)
    canvas.drawPath(route, stroke=1, fill=0)
    for x in (width - 78 * mm, width - 45 * mm, width - 18 * mm):
        canvas.setFillColor(BLACK); canvas.setStrokeColor(CYAN); canvas.circle(x, height - 11 * mm, 1.6 * mm, stroke=1, fill=1)
    canvas.setFillColor(GREY)
    canvas.setFont("Helvetica", 7)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(18 * mm, height - 12 * mm, "RAVENEYE  //  TANDAI_SEC")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(18 * mm, 9 * mm, "Thiago · Tandai Sec  |  Relatório de segurança")
    canvas.drawRightString(width - 18 * mm, 9 * mm, f"PÁGINA {doc.page}")
    canvas.setStrokeColor(BORDER); canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
    canvas.restoreState()


if _REPORTLAB_AVAILABLE:
    class _TunnelDiagram(Flowable):
        """Small, locally drawn route diagram for the VPN inspired report cover."""

        def __init__(self, width: float, height: float) -> None:
            super().__init__()
            self.width = width
            self.height = height

        def draw(self) -> None:
            canvas = self.canv
            width, height = self.width, self.height
            canvas.setFillColor(NAVY)
            canvas.setStrokeColor(BORDER)
            canvas.roundRect(0, 0, width, height, 4 * mm, stroke=1, fill=1)
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#173149"))
            canvas.setLineWidth(0.35)
            for x in range(int(10 * mm), int(width), int(10 * mm)):
                canvas.line(x, 0, x, height)
            for y in range(int(10 * mm), int(height), int(10 * mm)):
                canvas.line(0, y, width, y)
            canvas.restoreState()

            center_y = height * 0.58
            left_x, gateway_x, target_x = 22 * mm, width * 0.51, width - 22 * mm
            canvas.setStrokeColor(GREEN)
            canvas.setLineWidth(1.8)
            tunnel = canvas.beginPath()
            tunnel.moveTo(left_x, center_y)
            tunnel.curveTo(width * 0.30, height * 0.96, width * 0.36, height * 0.20, gateway_x, center_y)
            tunnel.curveTo(width * 0.66, height * 0.94, width * 0.76, height * 0.24, target_x, center_y)
            canvas.drawPath(tunnel, stroke=1, fill=0)

            nodes = ((left_x, "OPERADOR"), (gateway_x, "TÚNEL SEGURO"), (target_x, "ALVO"))
            for index, (x, label) in enumerate(nodes):
                radius = 5 * mm if index == 1 else 3.3 * mm
                canvas.setFillColor(BLACK if index != 1 else PURPLE_DARK)
                canvas.setStrokeColor(CYAN if index != 1 else GREEN)
                canvas.setLineWidth(1.3)
                canvas.circle(x, center_y, radius, stroke=1, fill=1)
                canvas.setFillColor(GREY)
                canvas.setFont("Helvetica-Bold", 6.5)
                canvas.drawCentredString(x, 9 * mm, label)
            # A compact lock glyph identifies the protected middle hop.
            lock_w, lock_h = 5 * mm, 4 * mm
            canvas.setStrokeColor(GREEN); canvas.setFillColor(NAVY); canvas.setLineWidth(1)
            canvas.roundRect(gateway_x - lock_w / 2, center_y - 2 * mm, lock_w, lock_h, 0.8 * mm, stroke=1, fill=1)
            shackle = canvas.beginPath()
            shackle.moveTo(gateway_x - 1.6 * mm, center_y + 1 * mm)
            shackle.arcTo(gateway_x - 1.6 * mm, center_y + 1 * mm, gateway_x + 1.6 * mm, center_y + 5 * mm, 0, 180)
            canvas.drawPath(shackle, stroke=1, fill=0)
            canvas.setFillColor(CYAN)
            canvas.setFont("Helvetica", 6)
            canvas.drawString(8 * mm, height - 7 * mm, "RAVENEYE SECURE ROUTE  /  TELEMETRIA LOCAL")


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


def _normalize_severity(value) -> str:
    raw = str(value or "INFO").strip().upper()
    return {
        "CRITICO": "CRITICAL", "CRÍTICO": "CRITICAL", "ALTO": "HIGH",
        "MEDIO": "MEDIUM", "MÉDIO": "MEDIUM", "BAIXO": "LOW",
    }.get(raw, raw if raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "INFO")


def _normalize_stage(value) -> str:
    raw = str(value or "POSSIBLE").strip().upper()
    return raw if raw in {"CONFIRMED", "PROBABLE", "POSSIBLE"} else "POSSIBLE"


def _finding_card(finding, styles):
    sev = _normalize_severity(finding.get("severity", "INFO"))
    stage = _normalize_stage(finding.get("stage", "POSSIBLE"))
    title = _safe_text(finding.get("name") or finding.get("id") or "Finding")
    rows = [
        [Paragraph(f"<b>{title}</b>", styles["finding_title"]), Paragraph(sev, styles["severity"])],
        [Paragraph(f"<b>URL:</b> {_safe_text(finding.get('url'))}", styles["body_dark"]),
         Paragraph(f"<b>Stage:</b> {_safe_text(stage)} · <b>Evidence score:</b> {_safe_text(finding.get('confidence_score', 0))}/100 · <b>Confidence:</b> {_safe_text(finding.get('confidence', 'MEDIUM'))}", styles["body_dark"])],
    ]
    details = []
    recommendation = finding.get("remediation") or finding.get("recommendation")
    for label, value in (("Descrição", finding.get("description")), ("Evidência", finding.get("evidence")),
                         ("Impacto", finding.get("impact")), ("Remediação", recommendation)):
        if value:
            details.append(Paragraph(f"<b>{label}</b>", styles["label"]))
            details.append(Paragraph(_safe_text(value, 1200).replace("\n", "<br/>"), styles["body_dark"]))
    cwe = finding.get("cwe"); cve = finding.get("cve")
    if cwe or cve:
        details.append(Paragraph(f"<b>Referências:</b> CWE={_safe_text(cwe)} · CVE={_safe_text(cve)}", styles["body_dark"]))
    inner = Table([[rows[0][0], rows[0][1]], [rows[1][0], rows[1][1]]], colWidths=[125 * mm, 35 * mm])
    inner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17121D")),
        ("BACKGROUND", (0, 1), (-1, 1), NAVY),
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
            "PDF indisponível: o runtime RavenEye está incompleto. Execute installer/install.sh "
            "para instalar reportlab e Pillow junto às dependências obrigatórias."
        )
    from raveneye.core.logger import redact_data
    from .dork_results import sanitize_dork_results

    safe_report = dict(report)
    safe_dorks = sanitize_dork_results(report)
    safe_report.pop("google_dorks", None)
    if safe_dorks:
        safe_report["google_dorks_results"] = safe_dorks
    else:
        safe_report.pop("google_dorks_results", None)
    raw_js_secrets = safe_report.get("secrets_js", [])
    if isinstance(raw_js_secrets, list):
        safe_report["secrets_js"] = [
            {**item, "valor": "[REDACTED]"} if isinstance(item, dict) else item
            for item in raw_js_secrets
        ]
    report = redact_data(safe_report)

    target = report.get("target", {}) if isinstance(report.get("target", {}), dict) else {}
    target_name = target.get("domain") or report.get("target") or "N/A"
    ip = target.get("ip") or report.get("ip") or "N/A"
    scan_time = report.get("timestamp") or report.get("started_at") or report.get("date") or datetime.now(timezone.utc).isoformat()
    scan = report.get("vulnerability_scan") or {}
    findings = list(report.get("findings") or [])
    if not findings and isinstance(scan, dict):
        findings = list(scan.get("findings") or [])
    findings = [
        {**finding, "severity": _normalize_severity(finding.get("severity")),
         "stage": _normalize_stage(finding.get("stage"))}
        for finding in findings if isinstance(finding, dict)
    ]
    from raveneye.scanner.evidence import sanitize_url
    surface_hints = [
        {**item, "url": sanitize_url(str(item.get("url", "")))}
        for item in report.get("surface_hints", []) if isinstance(item, dict)
    ][:200]
    if not surface_hints and isinstance(report.get("vulnerabilities"), dict):
        for category, raw_urls in report["vulnerabilities"].items():
            urls = raw_urls if isinstance(raw_urls, (list, tuple, set)) else [raw_urls]
            for raw_url in urls:
                if isinstance(raw_url, str) and (safe_url := sanitize_url(raw_url)):
                    surface_hints.append({"category": str(category)[:80], "url": safe_url})
                    if len(surface_hints) >= 200:
                        break
            if len(surface_hints) >= 200:
                break
    javascript_secrets = report.get("javascript_secrets", report.get("secrets_js", []))
    javascript_secrets = [
        {**item, "url": sanitize_url(str(item.get("url", ""))), "value": "[REDACTED]", "valor": "[REDACTED]"}
        for item in javascript_secrets if isinstance(item, dict)
    ][:200] if isinstance(javascript_secrets, list) else []
    raw_route_templates = report.get("javascript_route_templates")
    if not isinstance(raw_route_templates, list):
        crawler_data = report.get("crawler", {})
        raw_route_templates = crawler_data.get("js_route_templates", []) if isinstance(crawler_data, dict) else []
    javascript_route_templates = list(dict.fromkeys(
        value for raw in raw_route_templates if isinstance(raw, str)
        if (value := sanitize_url(raw))
    ))[:200] if isinstance(raw_route_templates, list) else []
    stage_counts = Counter(finding["stage"] for finding in findings)
    counts = Counter(finding["severity"] for finding in findings)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        counts.setdefault(sev, 0)
    for stage in ("CONFIRMED", "PROBABLE", "POSSIBLE"):
        stage_counts.setdefault(stage, 0)

    try:
        from .dork_results import sanitize_dork_results
        dork_results = sanitize_dork_results(report)
    except (ImportError, TypeError, ValueError):
        dork_results = None
    api_results = report.get("asset_intelligence", {})
    if not isinstance(api_results, dict):
        api_results = {}

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="cover", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=27, leading=32, textColor=WHITE, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="cover_sub", parent=styles["Normal"], fontSize=11, leading=16, textColor=GREY))
    styles.add(ParagraphStyle(name="h1r", parent=styles["Heading1"], fontSize=18, leading=22, textColor=TEAL_INK, spaceAfter=8))
    styles.add(ParagraphStyle(name="h2r", parent=styles["Heading2"], fontSize=12, leading=16, textColor=BLUE_INK, spaceBefore=7, spaceAfter=5))
    styles.add(ParagraphStyle(name="body", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=TEXT_INK))
    styles.add(ParagraphStyle(name="body_dark", parent=styles["BodyText"], fontSize=8.5, leading=12, textColor=GREY))
    styles.add(ParagraphStyle(name="label", parent=styles["BodyText"], fontSize=8, leading=10, textColor=GREEN, spaceBefore=3))
    styles.add(ParagraphStyle(name="finding_title", parent=styles["BodyText"], fontSize=10, leading=12, textColor=WHITE))
    styles.add(ParagraphStyle(name="severity", parent=styles["BodyText"], fontSize=8, leading=10, textColor=WHITE, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="small", parent=styles["BodyText"], fontSize=7, leading=9, textColor=GREY))
    styles.add(ParagraphStyle(name="small_light", parent=styles["BodyText"], fontSize=7, leading=9, textColor=TEXT_MUTED))

    out = Path(filename); out.parent.mkdir(parents=True, exist_ok=True)
    frame = Frame(15 * mm, 15 * mm, A4[0] - 30 * mm, A4[1] - 40 * mm, id="normal", leftPadding=0, rightPadding=0, topPadding=4 * mm, bottomPadding=4 * mm)
    doc = BaseDocTemplate(str(out), pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=22 * mm, bottomMargin=15 * mm, title=f"RavenEye 6.6.6 — {target_name}", author="Thiago · Tandai Sec")
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
    story += [Spacer(1, 12 * mm), _TunnelDiagram(160 * mm, 47 * mm), Spacer(1, 4 * mm), cover, PageBreak()]

    story += [Paragraph("Resumo executivo", styles["h1r"]), Paragraph(
        f"O scan registrou <b>{len(findings)}</b> findings: <b>{stage_counts['CONFIRMED']}</b> confirmados, "
        f"<b>{stage_counts['PROBABLE']}</b> prováveis e <b>{stage_counts['POSSIBLE']}</b> possíveis. "
        "A etapa descreve a força da evidência observada; referências CVE e sinais heurísticos não elevam um finding a confirmado.", styles["body"]),
        Spacer(1, 5 * mm), _severity_table(counts), Spacer(1, 6 * mm)]
    surface = report.get("surface", {}) if isinstance(report.get("surface", {}), dict) else {}
    crawl = report.get("crawler", {}) if isinstance(report.get("crawler", {}), dict) else {}
    metrics = [
        ["PÁGINAS", "ENDPOINTS", "ARQUIVOS JS", "ERROS", "CONFIRMADOS", "PROVÁVEIS", "POSSÍVEIS"],
        [str(surface.get("urls", len(crawl.get("list", []) or report.get("urls", []) or []))),
         str(surface.get("endpoints", len(crawl.get("endpoints", []) or report.get("endpoints", []) or []))),
         str(surface.get("javascript_files", len(crawl.get("js_urls", []) or []))),
         str(surface.get("crawl_errors", crawl.get("metrics", {}).get("errors", 0) if isinstance(crawl.get("metrics", {}), dict) else 0)),
         str(stage_counts["CONFIRMED"]), str(stage_counts["PROBABLE"]), str(stage_counts["POSSIBLE"])],
    ]
    mt = Table(metrics, colWidths=[23 * mm] * 7)
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY), ("TEXTCOLOR", (0, 0), (-1, -1), GREY),
        ("TEXTCOLOR", (0, 0), (1, 0), CYAN), ("TEXTCOLOR", (2, 0), (2, 0), GREEN),
        ("TEXTCOLOR", (4, 0), (4, 0), RED), ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(mt)
    dork_count = dork_results.get("total_interessantes", 0) if dork_results else 0
    overview = [
        ["RESPOSTAS DE BUSCA", "ROTAS PARA REVISAR", "ROTAS JS DINÂMICAS", "CANDIDATOS JS", "INTEGRAÇÕES"],
        [str(dork_count), str(len(surface_hints)),
         str(surface.get("javascript_route_templates", len(javascript_route_templates))),
         str(len(javascript_secrets)), str(len(api_results))],
    ]
    overview_table = Table(overview, colWidths=[32 * mm] * 5)
    overview_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PURPLE_DARK), ("BACKGROUND", (0, 1), (-1, 1), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("TEXTCOLOR", (0, 1), (-1, 1), GREY),
        ("TEXTCOLOR", (0, 1), (0, 1), CYAN), ("TEXTCOLOR", (1, 1), (1, 1), GREEN),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [Spacer(1, 5 * mm), Paragraph("Sinais do scan", styles["h2r"]), overview_table]
    if api_results:
        api_rows = [["PROVEDOR", "ESTADO", "HTTP", "OBSERVAÇÃO"]]
        for provider, result in sorted(api_results.items(), key=lambda pair: str(pair[0]).lower()):
            if not isinstance(result, dict):
                continue
            api_rows.append([
                _safe_text(str(provider)[:60]),
                _safe_text(result.get("status", "unknown"), 60),
                _safe_text(result.get("http_status", "—"), 12),
                Paragraph(_safe_text(result.get("message", ""), 240), styles["small"]),
            ])
        if len(api_rows) > 1:
            api_table = Table(api_rows, colWidths=[32 * mm, 36 * mm, 18 * mm, 74 * mm], repeatRows=1)
            api_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), PURPLE_DARK), ("BACKGROUND", (0, 1), (-1, -1), GREY_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("TEXTCOLOR", (0, 1), (-1, -1), GREY),
                ("GRID", (0, 0), (-1, -1), 0.35, BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 7), ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story += [Spacer(1, 5 * mm), Paragraph("Integrações de inteligência", styles["h2r"]), api_table]
    story += [PageBreak(), Paragraph("Findings", styles["h1r"])]

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

    if surface_hints:
        story += [Spacer(1, 3 * mm), Paragraph("Indícios de rota — não verificados", styles["h2r"]), Paragraph(
            "Estes caminhos coincidem com padrões conhecidos, mas a resposta do endpoint não foi validada. Não são findings confirmados.",
            styles["body"],
        )]
        hint_rows = [[Paragraph("PADRÃO", styles["small"]), Paragraph("ROTA OBSERVADA", styles["small"]), Paragraph("VALIDAÇÃO", styles["small"])]]
        for item in surface_hints[:40]:
            hint_rows.append([
                Paragraph(_safe_text(item.get("category", "padrão de URL"), 100), styles["body_dark"]),
                Paragraph(_safe_text(item.get("url", ""), 400), styles["body_dark"]),
                Paragraph("Não verificado", styles["body_dark"]),
            ])
        hint_table = Table(hint_rows, colWidths=[35 * mm, 95 * mm, 30 * mm], repeatRows=1, hAlign="LEFT")
        hint_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PURPLE_DARK), ("BACKGROUND", (0, 1), (-1, -1), GREY_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(hint_table)

    if javascript_route_templates:
        story += [Spacer(1, 3 * mm), Paragraph("Rotas dinâmicas JavaScript — não requisitadas", styles["h2r"]), Paragraph(
            "Templates observados em chamadas JavaScript. Valores dinâmicos e query strings foram omitidos; os caminhos abaixo não foram requisitados pelo crawler.",
            styles["body"],
        )]
        route_rows = [[Paragraph("ROTA OBSERVADA", styles["small"]), Paragraph("ESTADO", styles["small"])]]
        route_rows.extend([
            [Paragraph(_safe_text(route, 400), styles["body_dark"]),
             Paragraph("Template · não requisitado", styles["body_dark"])]
            for route in javascript_route_templates[:40]
        ])
        route_table = Table(route_rows, colWidths=[115 * mm, 45 * mm], repeatRows=1, hAlign="LEFT")
        route_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PURPLE_DARK), ("BACKGROUND", (0, 1), (-1, -1), GREY_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(route_table)

    if javascript_secrets:
        story += [Spacer(1, 3 * mm), Paragraph("Candidatos a segredo em JavaScript — valores ocultos", styles["h2r"]), Paragraph(
            "Correspondências de padrões encontradas nos arquivos JS. O conteúdo do possível segredo foi removido do relatório.",
            styles["body"],
        )]
        js_rows = [[Paragraph("PADRÃO", styles["small"]), Paragraph("ARQUIVO", styles["small"]), Paragraph("SEVERIDADE", styles["small"])]]
        for item in javascript_secrets[:40]:
            js_rows.append([
                Paragraph(_safe_text(item.get("type", item.get("tipo", "secret pattern")), 120), styles["body_dark"]),
                Paragraph(_safe_text(item.get("url", ""), 400), styles["body_dark"]),
                Paragraph(_safe_text(item.get("severity", "ALTO"), 24), styles["body_dark"]),
            ])
        js_table = Table(js_rows, colWidths=[45 * mm, 85 * mm, 30 * mm], repeatRows=1, hAlign="LEFT")
        js_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PURPLE_DARK), ("BACKGROUND", (0, 1), (-1, -1), GREY_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(js_table)

    if dork_results:
        story += [Spacer(1, 5 * mm), Paragraph("Busca automatizada — respostas", styles["h1r"])]
        story.append(Paragraph(
            f"Fonte: <b>{_safe_text(dork_results.get('provider', 'N/A'), 120)}</b> · "
            f"consultas executadas: {dork_results.get('dorks_executados', 0)} · "
            f"respostas brutas: {dork_results.get('total_bruto', 0)} · "
            f"resultados únicos em escopo: {dork_results.get('total_interessantes', 0)}. "
            "O relatório contém somente respostas filtradas; os textos das consultas foram omitidos.",
            styles["body"],
        ))
        dork_rows = [[
            Paragraph("CLASSIFICAÇÃO", styles["small"]),
            Paragraph("RESPOSTA DO MOTOR", styles["small"]),
        ]]
        for item in dork_results.get("interessantes", [])[:40]:
            detail_text = f"<b>{_safe_text(item.get('titulo', 'Resultado sem título'), 240)}</b><br/>{_safe_text(item.get('link', ''), 500)}"
            if item.get("snippet"):
                detail_text += f"<br/>{_safe_text(item.get('snippet'), 500)}"
            if item.get("engines"):
                detail_text += f"<br/><font size='7'>Motores: {_safe_text(item.get('engines'), 160)}</font>"
            classification = (
                f"{_safe_text(item.get('confidence', 'baixa'))}<br/>"
                f"{_safe_text(item.get('motivo', 'resultado em escopo para revisão'), 160)}"
            )
            dork_rows.append([Paragraph(classification, styles["body_dark"]), Paragraph(detail_text, styles["body_dark"])])
        if len(dork_rows) > 1:
            dork_table = Table(dork_rows, colWidths=[42 * mm, 118 * mm], repeatRows=1, hAlign="LEFT")
            dork_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), PURPLE_DARK), ("BACKGROUND", (0, 1), (-1, -1), GREY_DARK),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE), ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
                ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(dork_table)
        else:
            story.append(Paragraph("A busca não retornou resposta em escopo que passasse pelos filtros.", styles["body"]))

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

    annex = []
    tech = report.get("tech") or report.get("technologies") or {}
    if tech:
        annex.append(Paragraph("Tecnologias detectadas", styles["h2r"]))
        annex.append(Paragraph(_safe_text(tech, 2500).replace("\n", "<br/>"), styles["body"]))
    endpoints = report.get("endpoints", []) or []
    if endpoints:
        annex.append(Paragraph(f"Endpoints descobertos ({min(len(endpoints), 200)})", styles["h2r"]))
        annex.append(Paragraph("<br/>".join(_safe_text(e, 300) for e in endpoints[:200]), styles["small_light"]))
    if annex:
        story += [PageBreak(), Paragraph("Anexos", styles["h1r"]), *annex]

    doc.build(story)
    return str(out)
