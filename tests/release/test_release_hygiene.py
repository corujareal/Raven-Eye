from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_release_builder_excludes_runtime_artifacts():
    builder = (ROOT / "scripts" / "build_release.py").read_text(encoding="utf-8")
    assert "raveneye.db" in builder
    assert ".pytest_cache" in builder
    assert "__pycache__" in builder
    assert ".pyc" in builder
