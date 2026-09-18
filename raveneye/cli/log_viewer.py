from __future__ import annotations
import asyncio, pathlib, shutil, time, json, csv
from datetime import datetime, timezone
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
            print(data, end="")
        await asyncio.sleep(interval)

def safe_delete(path: str, trash: str = '.raveneye_trash', confirmation: str = ''):
    if confirmation != 'SIM':
        raise PermissionError('Confirmation must be exactly SIM')
    src = pathlib.Path(path).expanduser()
    trash_dir = pathlib.Path(trash).expanduser()
    if not src.exists() or src.is_symlink():
        raise FileNotFoundError(src)
    if not src.is_file():
        raise IsADirectoryError(src)
    src_resolved = src.resolve()
    trash_resolved = trash_dir.resolve()
    if src_resolved == trash_resolved or trash_resolved in src_resolved.parents:
        raise PermissionError('Refusing to delete from the RavenEye trash directory')
    trash_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    dst = trash_dir / f'{stamp}_{src.name}'
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
            if category.lower() in str(obj.get("category", obj.get("severity", ""))).lower():
                rows.append(obj)

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
        findings = []
        for r in rows:
            findings.append({
                "name": r.get("event") or r.get("category") or "Log event",
                "severity": str(r.get("severity", "INFO")).upper(),
                "confidence": r.get("confidence", "INFO"),
                "url": r.get("url", ""),
                "description": json.dumps(r, ensure_ascii=False)[:1200],
            })
        render_pdf({
            "target": {"domain": src.name},
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "surface": {"urls": 0, "endpoints": 0, "subdomains": 0},
        }, str(out))
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
    if src.suffix.lower() in {".json", ".jsonl"}:
        for line in raw.splitlines():
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
                else:
                    rows.append({"value": obj})
            except json.JSONDecodeError:
                continue
    if not rows:
        rows = [{"line": i, "content": line} for i, line in enumerate(raw.splitlines(), 1)]

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
        findings = []
        for row in rows[:1000]:
            findings.append({
                "name": row.get("event") or row.get("name") or row.get("category") or "Report entry",
                "severity": str(row.get("severity", "INFO")).upper(),
                "confidence": row.get("confidence", "INFO"),
                "url": row.get("url", ""),
                "description": str(row.get("content", row))[:1200],
            })
        render_pdf({
            "target": {"domain": src.name},
            "findings": findings,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "surface": {"urls": 0, "endpoints": 0, "subdomains": 0},
        }, str(out))
        if not out.is_file() or out.stat().st_size == 0 or out.read_bytes()[:4] != b"%PDF":
            raise IOError("O gerador nao produziu um PDF valido.")
        from raveneye_pkg.reports import _publish_pdf_for_easy_access
        _publish_pdf_for_easy_access(str(out))
    return out
