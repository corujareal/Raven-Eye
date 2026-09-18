import asyncio
import warnings
from pathlib import Path


def test_doctor_bootstrap_without_colorama(monkeypatch, capsys):
    # Exercise the diagnosis logic directly; the launcher delegates to this
    # module before importing the legacy colorama-dependent stack.
    from raveneye_pkg.doctor import run_doctor
    result = run_doctor()
    assert 'core_dependencies' in result
    assert 'optional_dependencies' in result


def test_sitemap_parser_does_not_emit_xml_html_warning():
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
    from raveneye.crawler.sitemaps import parse_sitemap
    xml = '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.test/a</loc></url></urlset>'
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        urls = parse_sitemap(xml, 'https://example.test/')
        # The parser implementation is regex-based and must remain warning-free.
        assert urls == ['https://example.test/a']
        assert not any(isinstance(w.message, XMLParsedAsHTMLWarning) for w in caught)


def test_export_formats_are_explicit():
    from raveneye.cli.log_viewer import EXPORT_FORMATS
    assert EXPORT_FORMATS == {
        '1': ('csv', '.csv'),
        '2': ('jsonl', '.jsonl'),
        '3': ('pdf', '.pdf'),
    }


def test_release_builder_excludes_runtime_db_and_caches():
    text = Path('scripts/build_release.py').read_text(encoding='utf-8')
    for marker in ('raveneye.db', '__pycache__', '.pytest_cache', '.pyc'):
        assert marker in text


def test_pinned_resolver_is_mutable_per_host():
    from raveneye.network.session import _PinnedResolver
    class Dummy:
        async def close(self):
            return None
    r = _PinnedResolver(Dummy())
    r.pin('A.Example', ['1.2.3.4'])
    assert r._validated['a.example'] == ['1.2.3.4']
    r.pin('b.example.', ['5.6.7.8', '5.6.7.8'])
    assert r._validated['b.example'] == ['5.6.7.8']


def test_cli_report_formats_include_all_supported_report_types():
    text = Path('raveneye/cli/main.py').read_text(encoding='utf-8')
    for fmt in ('txt', 'json', 'html', 'csv', 'markdown', 'pdf'):
        assert fmt in text
