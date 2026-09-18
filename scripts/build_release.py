#!/usr/bin/env python3
"""Build a clean RavenEye release archive without runtime/cache artifacts."""
from pathlib import Path
import shutil
import argparse
import sys
import zipfile

parser = argparse.ArgumentParser(description="Build a clean RavenEye v6.6.6 release ZIP.")
parser.add_argument("name", nargs="?", default="RavenEye_v6_6_6_RELEASE", help="Nome base do ZIP (sem .zip)")
parser.add_argument("--output", "-o", help="Caminho completo do ZIP de saída")
args = parser.parse_args()

ROOT = Path(__file__).resolve().parents[1]
NAME = args.name
OUT = Path(args.output).expanduser().resolve() if args.output else ROOT.parent / f"{NAME}.zip"
TMP = ROOT.parent / f".{NAME}_build"

EXCLUDED_NAMES = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv", "venv"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
EXCLUDED_FILES = {"raveneye.db", ".coverage"}
DYNAMIC_REPORT_DIRS = {Path("reports"), Path("data"), Path("me")}
RUNTIME_FILES = {"raveneye.log", "raveneye_audit_log.txt"}

def excluded(p: Path) -> bool:
    rel = p.relative_to(ROOT)
    if any(part in EXCLUDED_NAMES for part in rel.parts):
        return True
    if p.suffix.lower() in EXCLUDED_SUFFIXES:
        return True
    if p.name in EXCLUDED_FILES or p.name in RUNTIME_FILES:
        return True
    if any(rel == d or d in rel.parents for d in DYNAMIC_REPORT_DIRS):
        # Runtime-generated reports/databases never belong in a source release.
        return True
    return False

if TMP.exists():
    shutil.rmtree(TMP)
if OUT.exists():
    OUT.unlink()
DEST = TMP
DEST.mkdir(parents=True)

for src in ROOT.rglob("*"):
    if excluded(src) or src == OUT or TMP in src.parents:
        continue
    rel = src.relative_to(ROOT)
    dst = DEST / rel
    if src.is_dir():
        dst.mkdir(parents=True, exist_ok=True)
    else:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    files = [p for p in DEST.rglob("*") if p.is_file()]
    for p in sorted(files, key=lambda item: item.relative_to(TMP).as_posix()):
        zf.write(p, p.relative_to(TMP).as_posix())

with zipfile.ZipFile(OUT) as zf:
    bad = [n for n in zf.namelist() if Path(n).name in EXCLUDED_FILES or any(x in Path(n).parts for x in EXCLUDED_NAMES) or Path(n).suffix.lower() in EXCLUDED_SUFFIXES]
    if bad:
        raise SystemExit(f"Release hygiene failure: {bad}")

shutil.rmtree(TMP)
print(OUT)
