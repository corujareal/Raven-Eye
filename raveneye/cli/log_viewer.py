from __future__ import annotations
import asyncio, pathlib, shutil, time, json, csv
import unicodedata
from datetime import datetime, timezone
from uuid import uuid4
from raveneye.core.logger import redact_data, redact_text


def _safe_log_line(line: str) -> str:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return "".join(" " if unicodedata.category(char) == "Cc" else char for char in redact_text(line))
    value = redact_data(value)

    def terminal_safe(raw):
        if isinstance(raw, str):
            return "".join(" " if unicodedata.category(char) == "Cc" else char for char in raw)
        if isinstance(raw, list):
            return [terminal_safe(item) for item in raw]
        if isinstance(raw, dict):
            return {terminal_safe(str(key)): terminal_safe(item) for key, item in raw.items()}
        return raw

    value = terminal_safe(value)
    event = value.get("event") if isinstance(value, dict) else None
    data = value.get("data", {}) if isinstance(value, dict) else {}
    if isinstance(event, str) and isinstance(data, dict) and value.get("schema_version") == "1.0":
        timestamp = str(value.get("timestamp", ""))[:19].replace("T", " ")
        target = str(value.get("target", "[target omitted]"))

        def compact(raw, limit: int = 320) -> str:
            text = "".join(" " if unicodedata.category(char) == "Cc" else char for char in str(raw or ""))
            return " ".join(text.split())[:limit]

        if event == "scan.summary":
            vulnerability_counts = data.get("vulnerability_findings", {})
            by_stage = vulnerability_counts.get("by_stage", {}) if isinstance(vulnerability_counts, dict) else {}
            dorks = data.get("dork_search", {})
            if not isinstance(by_stage, dict):
                by_stage = {}
            if not isinstance(dorks, dict):
                dorks = {}
            pages = data.get("pages_crawled", 0)
            endpoints = data.get("endpoints", 0)
            message = (f"SCAN {compact(target, 260)} | {pages} páginas | {endpoints} endpoints | "
                       f"{by_stage.get('CONFIRMED', 0)} confirmados / {by_stage.get('PROBABLE', 0)} prováveis / "
                       f"{by_stage.get('POSSIBLE', 0)} possíveis | dorks {dorks.get('provider', 'off')}: "
                       f"{dorks.get('unique_results', 0)} respostas")
        elif event in {"vulnerability.confirmed", "vulnerability.candidate"}:
            message = (f"VULNERABILIDADE {data.get('stage', 'POSSIBLE')} [{data.get('severity', 'INFO')}] "
                       f"{compact(data.get('name'), 180)} | {compact(data.get('url'), 220)}")
        elif event == "search.summary":
            message = (f"BUSCA {compact(data.get('provider'), 80)} | {data.get('dorks_executados', 0)} consultas | "
                       f"{data.get('total_bruto', 0)} respostas brutas | {data.get('total_interessantes', 0)} resultados únicos")
        elif event == "search.response":
            message = (f"RESPOSTA {compact(data.get('provider'), 80)} [{data.get('confidence', 'baixa')}] "
                       f"{compact(data.get('titulo'), 180)} | {compact(data.get('link'), 220)} | "
                       f"{compact(data.get('snippet'), 320)}")
        elif event == "crawl.summary":
            js_urls = data.get("javascript_urls", [])
            endpoint_urls = data.get("endpoint_urls", [])
            route_templates = data.get("javascript_route_template_examples", [])
            js_count = len(js_urls) if isinstance(js_urls, list) else 0
            endpoint_count = len(endpoint_urls) if isinstance(endpoint_urls, list) else 0
            route_template_examples = len(route_templates) if isinstance(route_templates, list) else 0
            message = (f"CRAWL | {data.get('pages', 0)} páginas | {data.get('endpoints', 0)} endpoints | "
                       f"{data.get('javascript_files', 0)} arquivos JS | "
                       f"{data.get('javascript_route_templates', 0)} rotas JS dinâmicas | "
                       f"{data.get('javascript_secret_candidates', 0)} candidatos JS | {data.get('requests', 0)} requisições | "
                       f"{data.get('errors', 0)} erros | exemplos: {endpoint_count} endpoints / {js_count} JS / "
                       f"{route_template_examples} rotas dinâmicas")
        elif event == "surface.hint":
            message = (f"INDÍCIO DE ROTA [{compact(data.get('category'), 100)}] "
                       f"{compact(data.get('url'), 220)} | não verificado")
        elif event == "javascript.secret_hint":
            message = (f"CANDIDATO A SEGREDO EM JS [{compact(data.get('type'), 100)}] "
                       f"{compact(data.get('url'), 220)} | valor ocultado")
        elif event == "integration.status":
            status = f" HTTP {data['http_status']}" if isinstance(data.get("http_status"), int) else ""
            message = f"API {compact(data.get('provider'), 80)}: {compact(data.get('status'), 60)}{status} {compact(data.get('message'), 160)}"
        else:
            message = json.dumps(value, ensure_ascii=False)
        return f"{timestamp} | {message}\n"
    return json.dumps(value, ensure_ascii=False) + "\n"


def _matches_category(row: dict, category: str) -> bool:
    wanted = category.strip().casefold()
    if not wanted:
        return True
    event = str(row.get("event", "")).casefold()
    if wanted in {"scanner", "vulnerability", "vulnerabilities"}:
        return event.startswith("vulnerability.") or event == "surface.hint" or wanted in str(row.get("category", "")).casefold()
    if wanted in {"dork", "dorks", "search", "busca"}:
        return event.startswith("search.") or wanted in str(row.get("category", "")).casefold()
    if wanted in {"api", "apis", "integration", "integrations"}:
        return event == "integration.status" or wanted in str(row.get("category", "")).casefold()
    if wanted in {"crawl", "crawler"}:
        return event.startswith("crawl.") or event.startswith("javascript.") or wanted in str(row.get("category", "")).casefold()
    return any(wanted in str(row.get(key, "")).casefold() for key in ("category", "severity", "event", "logger"))


def _pdf_report_from_events(rows: list[dict], fallback_target: str) -> dict:
    """Keep scan/search/API telemetry out of the PDF's vulnerability findings."""
    structured = any(isinstance(row.get("event"), str) and isinstance(row.get("data"), dict) for row in rows)
    if not structured:
        findings = [{
            "name": row.get("event") or row.get("category") or "Log event",
            "severity": str(row.get("severity", "INFO")).upper(),
            "confidence": row.get("confidence", "INFO"),
            "stage": row.get("stage", "POSSIBLE"),
            "url": row.get("url", ""),
            "description": json.dumps(row, ensure_ascii=False)[:1200],
        } for row in rows]
        return {"target": {"domain": fallback_target}, "findings": findings}

    summary_row = next((row for row in rows if row.get("event") == "scan.summary"), {})
    summary = summary_row.get("data", {}) if isinstance(summary_row.get("data"), dict) else {}
    target = str(summary_row.get("target") or next((row.get("target") for row in rows if row.get("target")), fallback_target))
    findings = []
    for row in rows:
        event = row.get("event")
        data = row.get("data", {})
        if event not in {"vulnerability.confirmed", "vulnerability.candidate"} or not isinstance(data, dict):
            continue
        findings.append({
            "name": data.get("name", data.get("id", "Finding")),
            "severity": data.get("severity", "INFO"),
            "confidence": data.get("confidence", "LOW"),
            "stage": data.get("stage", "POSSIBLE"),
            "confidence_score": data.get("confidence_score", 0),
            "url": data.get("url", ""),
            "cwe": data.get("cwe", ""),
            "cve": data.get("cve", ""),
            "description": json.dumps(data.get("evidence", {}), ensure_ascii=False)[:1200],
        })

    search_summary = next((row.get("data", {}) for row in rows if row.get("event") == "search.summary"), {})
    search_responses = [row.get("data", {}) for row in rows if row.get("event") == "search.response" and isinstance(row.get("data"), dict)]
    report = {
        "target": {"domain": target},
        "findings": findings,
        "timestamp": summary_row.get("timestamp"),
        "surface": {
            "urls": summary.get("pages_crawled", 0),
            "endpoints": summary.get("endpoints", 0),
            "subdomains": 0,
        },
    }
    crawl_summary = next((row.get("data", {}) for row in rows if row.get("event") == "crawl.summary" and isinstance(row.get("data"), dict)), {})
    if crawl_summary:
        report["surface"] = {
            "urls": crawl_summary.get("pages", 0),
            "endpoints": crawl_summary.get("endpoints", 0),
            "javascript_files": crawl_summary.get("javascript_files", 0),
            "javascript_route_templates": crawl_summary.get("javascript_route_templates", 0),
            "crawl_errors": crawl_summary.get("errors", 0),
            "subdomains": 0,
        }
        raw_templates = crawl_summary.get("javascript_route_template_examples", [])
        report["javascript_route_templates"] = [
            value for value in raw_templates if isinstance(value, str)
        ][:50] if isinstance(raw_templates, list) else []
    report["surface_hints"] = [
        row.get("data", {}) for row in rows
        if row.get("event") == "surface.hint" and isinstance(row.get("data"), dict)
    ]
    report["javascript_secrets"] = [
        row.get("data", {}) for row in rows
        if row.get("event") == "javascript.secret_hint" and isinstance(row.get("data"), dict)
    ]
    if search_summary or search_responses:
        report["google_dorks_results"] = {
            "provider": search_summary.get("provider", "SearXNG local (Docker)"),
            "dorks_executados": search_summary.get("dorks_executados", 0),
            "total_bruto": search_summary.get("total_bruto", 0),
            "total_em_escopo": search_summary.get("total_em_escopo", 0),
            "total_interessantes": len(search_responses),
            "interessantes": search_responses,
        }
    api_results = {}
    for row in rows:
        if row.get("event") != "integration.status" or not isinstance(row.get("data"), dict):
            continue
        data = row["data"]
        api_results[str(data.get("provider", "unknown"))] = {
            "status": data.get("status", "unknown"),
            "http_status": data.get("http_status"),
            "message": data.get("message", ""),
        }
    if api_results:
        report["asset_intelligence"] = api_results
    return report


async def watch(path: str, interval: float = .5):
    """Tail a log safely, including truncation/rotation detection."""
    if interval <= 0:
        raise ValueError("interval must be > 0")
    p = pathlib.Path(path)
    pos = 0
    inode = None
    while True:
        try:
            stat = p.stat()
        except FileNotFoundError:
            await asyncio.sleep(interval)
            continue
        current_inode = getattr(stat, "st_ino", None)
        if inode is not None and (current_inode != inode or stat.st_size < pos):
            pos = 0
        inode = current_inode
        with p.open("r", encoding="utf-8", errors="replace") as f:
            f.seek(pos)
            data = f.read()
            pos = f.tell()
        if data:
            print("".join(_safe_log_line(line) for line in data.splitlines(keepends=True)), end="")
        await asyncio.sleep(interval)

def safe_delete(path: str, trash: str = '.raveneye_trash', confirmation: str = ''):
    """Move a confirmed regular file into a private, non-symlink trash folder."""
    if confirmation != 'SIM':
        raise PermissionError('Confirmation must be exactly SIM')
    src = pathlib.Path(path).expanduser()
    trash_dir = pathlib.Path(trash).expanduser()
    if not src.exists():
        raise FileNotFoundError(src)
    if src.is_symlink():
        raise PermissionError(f'Refusing to move a symbolic link: {src}')
    if not src.is_file():
        raise IsADirectoryError(src)
    if trash_dir.is_symlink():
        raise PermissionError(f'Refusing to use a symbolic link as trash: {trash_dir}')
    src_resolved = src.resolve()
    trash_resolved = trash_dir.resolve()
    if src_resolved == trash_resolved or trash_resolved in src_resolved.parents:
        raise PermissionError('Refusing to delete from the RavenEye trash directory')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    trash_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    dst = trash_dir / f'{stamp}_{uuid4().hex}_{src.name}'
    shutil.move(str(src), str(dst))
    return dst

EXPORT_FORMATS = {
    "1": ("csv", ".csv"),
    "2": ("jsonl", ".jsonl"),
    "3": ("pdf", ".pdf"),
}

def format_menu() -> None:
    print("Formatos disponiveis:")
    print("  1 - CSV   (.csv)")
    print("  2 - JSONL (.jsonl)")
    print("  3 - PDF   (.pdf)")


def export_category(path: str, category: str, output: str, fmt: str | None = None):
    """Export matching JSONL events to an explicitly selected format.

    The format is never guessed as a fallback. If *fmt* is omitted, the output
    extension is accepted only when it is one of the supported formats. When
    a supported extension is missing, ``.pdf`` is appended only if fmt=pdf.
    This prevents accidentally creating an extensionless text file when the
    user intended a PDF.
    """
    src = pathlib.Path(path)
    if not src.is_file():
        raise FileNotFoundError(src)
    rows = []
    with src.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if _matches_category(obj, category):
                rows.append(redact_data(obj))

    requested = (fmt or pathlib.Path(output).suffix.lstrip(".")).lower()
    aliases = {"md": "markdown", "json": "jsonl", "jsonlines": "jsonl"}
    requested = aliases.get(requested, requested)
    if requested not in {"csv", "jsonl", "pdf"}:
        raise ValueError("Formato invalido. Use CSV, JSONL ou PDF.")

    out = pathlib.Path(output)
    if not out.suffix:
        out = out.with_suffix("." + requested)
    elif out.suffix.lower() != "." + requested:
        # Never silently write PDF bytes into a .txt/.log file.
        out = out.with_suffix("." + requested)
    out.parent.mkdir(parents=True, exist_ok=True)

    if requested == "csv":
        keys = sorted({k for r in rows for k in r}) or ["category"]
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)
    elif requested == "pdf":
        from raveneye.reports.pdf import render_pdf
        report = _pdf_report_from_events(rows, src.name)
        report.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        render_pdf(report, str(out))
        if not out.is_file() or out.stat().st_size == 0 or out.read_bytes()[:4] != b"%PDF":
            raise IOError("O gerador nao produziu um PDF valido.")
        from raveneye_pkg.reports import _publish_pdf_for_easy_access
        _publish_pdf_for_easy_access(str(out))
    else:
        out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return out



def export_report_file(path: str, output: str, fmt: str):
    """Exporta um arquivo de relatorio existente para CSV, JSONL ou PDF.

    Diferente de ``export_category``, esta funcao trabalha sobre o arquivo
    selecionado pelo usuario e nao pressupoe que ele seja um log JSONL.
    """
    src = pathlib.Path(path)
    if not src.is_file():
        raise FileNotFoundError(src)
    requested = str(fmt).lower()
    if requested not in {"csv", "jsonl", "pdf"}:
        raise ValueError("Formato invalido. Use CSV, JSONL ou PDF.")
    suffix = "." + requested
    out = pathlib.Path(output)
    if out.suffix.lower() != suffix:
        out = out.with_suffix(suffix) if out.suffix else out.with_name(out.name + suffix)
    out.parent.mkdir(parents=True, exist_ok=True)

    if src.suffix.lower() == ".pdf":
        if requested == "pdf":
            shutil.copy2(src, out)
            if not out.is_file() or out.stat().st_size == 0 or out.read_bytes()[:4] != b"%PDF":
                raise IOError("O arquivo PDF de origem nao possui uma assinatura PDF valida.")
            return out
        raise ValueError("Conversao direta de PDF para CSV/JSONL nao e suportada; use o PDF como origem apenas para exportacao PDF.")

    raw = src.read_text(encoding="utf-8", errors="replace")
    rows = []
    full_scan_report = None
    if src.suffix.lower() == ".json":
        try:
            parsed_report = json.loads(raw)
        except json.JSONDecodeError:
            parsed_report = None
        report_markers = {"vulnerability_scan", "crawler", "google_dorks_results", "findings", "vulnerabilities", "asset_intelligence", "subdomains"}
        if isinstance(parsed_report, dict) and "event" not in parsed_report and report_markers.intersection(parsed_report):
            full_scan_report = parsed_report
    if src.suffix.lower() in {".json", ".jsonl"}:
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(redact_data(obj))
                else:
                    rows.append({"value": redact_data(obj)})
            except json.JSONDecodeError:
                continue
    if not rows:
        rows = [{"line": i, "content": redact_text(line)} for i, line in enumerate(raw.splitlines(), 1)]

    if requested == "csv":
        keys = sorted({k for row in rows for k in row}) or ["content"]
        with out.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
    elif requested == "jsonl":
        out.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    else:
        from raveneye.reports.pdf import render_pdf
        if full_scan_report is not None:
            from raveneye.reports.dork_results import sanitize_dork_results
            safe_report = dict(full_scan_report)
            safe_dorks = sanitize_dork_results(full_scan_report)
            safe_report.pop("google_dorks", None)
            safe_report.pop("dorks", None)
            raw_js_secrets = safe_report.get("secrets_js", [])
            if isinstance(raw_js_secrets, list):
                safe_report["secrets_js"] = [
                    {**item, "valor": "[REDACTED]"} if isinstance(item, dict) and "valor" in item else item
                    for item in raw_js_secrets
                ]
            if safe_dorks:
                safe_report["google_dorks_results"] = safe_dorks
            else:
                safe_report.pop("google_dorks_results", None)
            report = redact_data(safe_report)
        else:
            report = _pdf_report_from_events(rows[:1000], src.name)
        report.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        render_pdf(report, str(out))
        if not out.is_file() or out.stat().st_size == 0 or out.read_bytes()[:4] != b"%PDF":
            raise IOError("O gerador nao produziu um PDF valido.")
        from raveneye_pkg.reports import _publish_pdf_for_easy_access
        _publish_pdf_for_easy_access(str(out))
    return out
