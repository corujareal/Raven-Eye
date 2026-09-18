from pathlib import Path

def test_termux_requirements_split():
    text = Path("installer/install.sh").read_text()
    start = text.index("CORE_DEPS='") + len("CORE_DEPS='")
    end = text.index("'", start)
    core_block = text[start:end].lower()
    for name in ("pydantic", "pyyaml", "sqlalchemy", "lxml", "pillow", "reportlab"):
        assert name not in core_block
    assert "FULL_DEPS='" in text

def test_xml_detector():
    from raveneye_pkg.crawler import RavenCrawler
    assert RavenCrawler._looks_like_xml("https://example.test/sitemap.xml", "<urlset></urlset>")
    assert RavenCrawler._looks_like_xml("https://example.test/feed", '<?xml version="1.0"?><rss></rss>')
    assert not RavenCrawler._looks_like_xml("https://example.test/", "<html><body>x</body></html>")


def test_pdf_module_is_lazy_when_reportlab_unavailable():
    import importlib
    mod = importlib.import_module("raveneye.reports.pdf")
    assert hasattr(mod, "render_pdf")

def test_cli_does_not_import_reportlab_at_module_import():
    import importlib
    mod = importlib.import_module("raveneye.cli.main")
    assert hasattr(mod, "main")
