from pathlib import Path


def test_project_root_contains_expected_entrypoints():
    root = Path(__file__).resolve().parents[2]
    assert (root / "RavenEye.py").is_file()
    assert (root / "pyproject.toml").is_file()
    assert (root / "installer" / "install.sh").is_file()
    assert (root / "installer" / "uninstall.sh").is_file()
    assert (root / "raveneye").is_dir()
    assert (root / "raveneye_pkg").is_dir()


def test_legacy_layer_is_explicitly_present_for_backward_compatibility():
    root = Path(__file__).resolve().parents[2]
    assert (root / "raveneye_pkg" / "menus.py").is_file()


def test_release_builder_places_project_at_zip_root():
    import subprocess, sys, zipfile
    root = Path(__file__).resolve().parents[2]
    out = root.parent / "_release_layout_test.zip"
    subprocess.run([sys.executable, str(root / "scripts" / "build_release.py"), "_release_layout_test"], check=True)
    try:
        with zipfile.ZipFile(out) as zf:
            names = set(zf.namelist())
        assert "RavenEye.py" in names
        assert "pyproject.toml" in names
        assert not any(name.startswith(root.name + "/") for name in names)
        assert not any(name.endswith(".pyc") for name in names)
        assert not any(name.endswith("raveneye.db") for name in names)
    finally:
        out.unlink(missing_ok=True)
