#!/usr/bin/env python3
"""Static integrity audit for a RavenEye source tree or release ZIP."""
from __future__ import annotations

import ast
import re
import sys
import zipfile
from pathlib import Path

VERSION = "6.6.6"
FORBIDDEN = re.compile(r"\b(eval|exec|pickle)\s*\(|\bshell\s*=\s*True|\bos\.system\s*\(")
BAD_NAME = re.compile(r"(?i)(?:^|[_-])(stage|loop|part|audit_stage|test_stage|test_loop)(?:[_-]|\d|$)")


def scan_tree(root: Path) -> list[str]:
    errors: list[str] = []
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(root)
        parts = set(rel.parts)
        if "__pycache__" in parts or ".pytest_cache" in parts or p.suffix in {".pyc", ".pyo"}:
            errors.append(f"runtime cache in tree: {rel}")
        if p.name == "raveneye.db" or p.suffix.lower() in {".sqlite", ".sqlite3"}:
            errors.append(f"runtime database in tree: {rel}")
        if any(BAD_NAME.search(part) for part in rel.parts):
            errors.append(f"stage/loop/test-stage style path: {rel}")
        if p.suffix == ".py":
            text = p.read_text(encoding="utf-8", errors="replace")
            if FORBIDDEN.search(text):
                errors.append(f"forbidden primitive in {rel}")
            try:
                ast.parse(text, filename=str(rel))
            except SyntaxError as exc:
                errors.append(f"syntax error in {rel}: {exc}")
    version_hits = 0
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in {".py", ".md", ".txt", ".toml", ".yml", ".yaml"}:
            text = p.read_text(encoding="utf-8", errors="replace")
            if "tests" not in p.relative_to(root).parts and re.search(r"(?<![\d.])(?:v)?7\.0\.0(?![\d.])", text):
                errors.append(f"forbidden version reference in {p.relative_to(root)}")
            if VERSION in text:
                version_hits += 1
    if version_hits == 0:
        errors.append("no 6.6.6 version marker found")
    return errors


def scan_zip(path: Path) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        for name in names:
            p = Path(name)
            if any(part in {"__pycache__", ".pytest_cache", ".venv", "venv"} for part in p.parts):
                errors.append(f"forbidden directory in zip: {name}")
            if p.suffix.lower() in {".pyc", ".pyo", ".sqlite", ".sqlite3"} or p.name == "raveneye.db":
                errors.append(f"runtime artifact in zip: {name}")
        if "RavenEye.py" not in names:
            errors.append("RavenEye.py is not at ZIP root")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: audit_project.py <project-dir|release.zip>")
        return 2
    target = Path(argv[1]).resolve()
    if target.is_dir():
        errors = scan_tree(target)
    elif target.is_file() and target.suffix.lower() == ".zip":
        errors = scan_zip(target)
    else:
        print("target must be a project directory or .zip")
        return 2
    if errors:
        for item in errors:
            print(f"FAIL: {item}")
        return 1
    print("AUDIT_OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
