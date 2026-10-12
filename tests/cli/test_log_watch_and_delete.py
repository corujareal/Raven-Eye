import asyncio
import json
from pathlib import Path
import pytest
from raveneye.cli.log_viewer import _safe_log_line, safe_delete, watch


def test_safe_delete_requires_file_and_uses_unique_trash(tmp_path):
    f = tmp_path / 'a.log'
    f.write_text('x')
    trash = tmp_path / '.trash'
    out = safe_delete(str(f), str(trash), 'SIM')
    assert not f.exists()
    assert out.exists()
    assert out.parent == trash
    assert out.name.endswith('_a.log')


def test_safe_delete_rejects_directory_and_wrong_confirmation(tmp_path):
    d = tmp_path / 'dir'
    d.mkdir()
    with pytest.raises(PermissionError):
        safe_delete(str(d), str(tmp_path / '.trash'), 'NAO')
    with pytest.raises(IsADirectoryError):
        safe_delete(str(d), str(tmp_path / '.trash'), 'SIM')


def test_watch_rejects_non_positive_interval(tmp_path):
    f = tmp_path / 'x.log'
    f.write_text('x')
    with pytest.raises(ValueError):
        asyncio.run(asyncio.wait_for(watch(str(f), 0), timeout=.1))


def test_crawl_log_summary_shows_dynamic_route_template_count_without_query_values():
    row = {
        "schema_version": "1.0",
        "timestamp": "2026-10-12T10:00:00Z",
        "event": "crawl.summary",
        "target": "example.test",
        "data": {
            "pages": 4,
            "javascript_route_templates": 1,
            "javascript_route_template_examples": ["https://example.test/api/users/{param}"],
        },
    }

    rendered = _safe_log_line(json.dumps(row))

    assert "1 rotas JS dinâmicas" in rendered
    assert "1 rotas dinâmicas" in rendered
    assert "{param}" not in rendered
